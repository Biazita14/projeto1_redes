import socket, os, json, time, re
from urllib.parse import unquote, unquote_plus

PORT = 8080
RATE_MAX, RATE_WINDOW = 10, 5          # máx. 10 requisições a cada 5 segundos por IP
ATTACK_LOGS, IP_REQUESTS = [], {}
REASONS = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 408: "Request Timeout", 429: "Too Many Requests"}
MIME = {"html": "text/html; charset=utf-8", "css": "text/css", "js": "application/javascript",
        "png": "image/png", "jpg": "image/jpeg", "json": "application/json"}

# Regras do WAF: procuram a ESTRUTURA do ataque (e não palavras soltas) para evitar falsos positivos
ATTACK_PATTERNS = {
    "Path Traversal": [r"\.\./|\.\.\\", r"/etc/passwd", r"boot\.ini"],
    "SQL Injection (SQLi)": [
        r"\bunion\b\s+(all\s+)?select\b",                           # UNION SELECT
        r"\bselect\b\s+(\*|[\w.]+\s*,).*\bfrom\b",                  # SELECT * FROM / SELECT a, b FROM
        r"\b(or|and)\b\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\2\b",      # tautologia: OR 1=1 / OR 'a'='a'
        r"'\s*(--|#)",                                              # admin'--
        r"\bdrop\s+table\b"],
    "Cross-Site Scripting (XSS)": [r"<\s*script", r"javascript\s*:", r"<[^>]*\son[a-z]{3,}\s*=", r"\balert\s*\("],
}


def normalize(text):
    """Decodifica %XX até 3 vezes (pega %252e) e remove comentários SQL (UNION/**/SELECT)."""
    for _ in range(3):
        text = unquote_plus(text)
    return re.sub(r"/\*.*?\*/", " ", text)


def inspect_request(target, body, ip):
    """WAF: inspeciona só a URL e o corpo (não os cabeçalhos, para evitar falsos positivos)."""
    text = normalize(target) + "\n" + normalize(body)
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                ATTACK_LOGS.append({"id": len(ATTACK_LOGS) + 1, "timestamp": time.strftime("%H:%M:%S"),
                                    "ip": ip, "type": attack_type, "payload": target})
                print(f"  [WAF] {attack_type} de {ip}")
                return attack_type
    return None


def check_rate_limit(ip):
    """Janela deslizante: guarda o horário das últimas requisições de cada IP."""
    now = time.time()
    IP_REQUESTS[ip] = [t for t in IP_REQUESTS.get(ip, []) if now - t < RATE_WINDOW]
    if len(IP_REQUESTS[ip]) >= RATE_MAX:
        return False
    IP_REQUESTS[ip].append(now)
    return True


def read_request(client):
    """TCP é um fluxo de bytes: lê até o fim dos cabeçalhos (CRLF CRLF) e depois o corpo (Content-Length)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = client.recv(4096)
        if not chunk or len(data) > 16384:
            raise ValueError("requisição incompleta ou grande demais")
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", errors="replace").split("\r\n")
    parts = lines[0].split(" ")                                     # MÉTODO ALVO VERSÃO
    if len(parts) != 3:
        raise ValueError("linha de requisição inválida")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))                # ValueError se não for número
    if length > 65536:
        raise ValueError("corpo grande demais")
    while len(body) < length:
        chunk = client.recv(4096)
        if not chunk:
            raise ValueError("corpo incompleto")
        body += chunk
    return parts[0], parts[1], body.decode("utf-8", errors="replace")


def send(client, status, body, content_type="application/json; charset=utf-8", extra=""):
    """Monta a resposta HTTP: linha de status + cabeçalhos + linha em branco + corpo."""
    if isinstance(body, (dict, list)):
        body = json.dumps(body, ensure_ascii=False)
    if isinstance(body, str):
        body = body.encode("utf-8")
    header = (f"HTTP/1.1 {status} {REASONS[status]}\r\nContent-Type: {content_type}\r\n"
              f"Content-Length: {len(body)}\r\nConnection: close\r\n{extra}\r\n")
    client.sendall(header.encode() + body)


def handle(client, ip):
    if not check_rate_limit(ip):
        return send(client, 429, {"error": "Too Many Requests", "reason": "Rate limit excedido",
                                  "status": 429}, extra="Retry-After: 5\r\n")
    method, target, body = read_request(client)
    path = target.split("?")[0]
    print(f"[+] {method} {target} - {ip}")

    attack = inspect_request(target, body, ip)
    if attack:
        return send(client, 403, {"error": "Access Denied", "reason": f"WAF Blocked: {attack}",
                                  "attack_type": attack, "status": 403})

    if method == "GET" and path == "/api/logs":
        send(client, 200, ATTACK_LOGS)
    elif method == "POST" and path == "/api/login":
        send(client, 200, {"status": "sucesso", "mensagem": "Dados processados pelo servidor WAF.",
                           "recebido": body})
    elif method == "GET":
        # basename() descarta qualquer diretório do caminho; só extensões da lista MIME são servidas
        filename = "index.html" if path == "/" else os.path.basename(unquote(path))
        ext = filename.rsplit(".", 1)[-1].lower()
        if ext in MIME and os.path.isfile(filename):
            with open(filename, "rb") as f:
                send(client, 200, f.read(), MIME[ext])
        else:
            send(client, 404, {"error": "Not Found", "reason": "Arquivo não encontrado", "status": 404})
    else:
        send(client, 405, {"error": "Method Not Allowed", "reason": method, "status": 405})


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # permite reiniciar sem esperar o TIME_WAIT
    server.bind(("", PORT))
    server.listen(5)
    server.settimeout(1)                                           # permite o Ctrl+C funcionar no accept()
    print(f"[*] Servidor WAF em http://localhost:{PORT}")
    try:
        while True:
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            client.settimeout(5)                                   # cliente lento não trava o servidor
            try:
                handle(client, addr[0])
            except socket.timeout:
                send(client, 408, {"error": "Request Timeout", "status": 408})
            except ValueError as e:
                send(client, 400, {"error": "Bad Request", "reason": str(e), "status": 400})
            except OSError:
                pass                                               # cliente desconectou
            finally:
                try:
                    client.shutdown(socket.SHUT_WR)                # avisa (FIN) que terminamos de enviar
                except OSError:
                    pass
                client.close()
    except KeyboardInterrupt:
        print("\n[*] Servidor encerrado.")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()