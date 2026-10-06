import socket, os, json, time, re
from urllib.parse import unquote_plus

# --- CONFIGURAÇÕES GLOBAIS DE REDE E LIMITES ---
PORT = 8080
RATE_MAX, RATE_WINDOW = 10, 5  # Proteção Anti-DoS: máx. 10 requisições a cada 5 segundos por IP
ATTACK_LOGS, IP_REQUESTS = [], {}  # Estruturas em memória para armazenar logs e o histórico de IPs

# Mapeamento de extensões para cabeçalhos Content-Type do protocolo HTTP
MIME = {
    "html": "text/html; charset=utf-8", 
    "css": "text/css", 
    "js": "application/javascript",
    "png": "image/png", 
    "jpg": "image/jpeg", 
    "json": "application/json"
}

# Regras do WAF: Expressões Regulares (Regex) para detecção de ameaças na camada de aplicação
ATTACK_PATTERNS = {
    "Path Traversal": [
        r"\.\.",            # Captura a tentativa de subir diretórios (ex: ../)
        r"\/etc\/passwd",   # Captura tentativa de ler arquivos do sistema Linux
        r"boot\.ini"        # Captura tentativa de ler arquivos do sistema Windows
    ],
    "SQL Injection (SQLi)": [
        r"(?i)\bOR\b.*=",   # Captura cláusula OR com igualdade (ex: OR 1=1)
        r"(?i)\bUNION\b",   # Captura o comando UNION usado para extrair dados
        r"(?i)\bSELECT\b",  # Captura o comando SELECT
        r"(?i)1\s*=\s*1",   # Captura tautologias clássicas
        r"'"                # Captura tentativa de quebra de aspa simples em queries
    ],
    "Cross-Site Scripting (XSS)": [
        r"(?i)<script",     # Captura abertura de tags de script
        r"(?i)%3Cscript",   # Captura a tag <script> codificada em URL
        r"(?i)alert\(",     # Captura chamadas de funções JavaScript de alerta
        r"(?i)javascript:" # Captura URIs maliciosas executando JS
    ]
}

def inspect_request(target, body, ip):
    """ MOTOR WAF: Inspeciona a URL e o corpo (body) da requisição em busca de padrões maliciosos. """
    # Descodifica a URL/body (ex: transforma %20 em espaço) para analisar o texto real
    full_text = unquote_plus(target) + "\n" + unquote_plus(body)
    
    # Percorre as regras e aplica os padrões regex sobre o texto recebido
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, full_text):
                # Registra a ocorrência na memória caso encontre um ataque
                ATTACK_LOGS.append({
                    "id": len(ATTACK_LOGS) + 1, 
                    "timestamp": time.strftime("%H:%M:%S"),
                    "ip": ip, 
                    "type": attack_type, 
                    "payload": target
                })
                print(f"  [WAF ALERTA] {attack_type} detectado de {ip}")
                return attack_type
    return None

def check_rate_limit(ip):
    """ PROTEÇÃO RATE LIMITING: Controla rajadas de requisições por IP na camada de transporte/sessão. """
    now = time.time()
    # Remove timestamps de requisições que já saíram da janela de 5 segundos
    IP_REQUESTS[ip] = [t for t in IP_REQUESTS.get(ip, []) if now - t < RATE_WINDOW]
    
    # Se o IP ultrapassou 10 requisições recentes, bloqueia
    if len(IP_REQUESTS[ip]) >= RATE_MAX:
        return False
        
    IP_REQUESTS[ip].append(now)
    return True

def send_response(client, status_code, status_msg, body_bytes, content_type="application/json; charset=utf-8"):
    """ CAMADA DE APLICAÇÃO: Monta a resposta HTTP válida (cabeçalho + corpo) e envia pelo socket TCP. """
    header = (
        f"HTTP/1.1 {status_code} {status_msg}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n\r\n"
    )
    # Transmite o texto do cabeçalho concatenado aos bytes do corpo através do socket
    client.sendall(header.encode('utf-8') + body_bytes)

def start_server():
    """ CAMADA DE TRANSPORTE: Inicializa o socket TCP, faz o bind na porta e lida com as conexões. """
    # Criando socket IPv4 (AF_INET) e TCP (SOCK_STREAM)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Permite reutilizar a porta 8080 imediatamente ao reiniciar o script sem erro de porta ocupada
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Faz o bind em todas as interfaces de rede na porta 8080
    server.bind(('', PORT))
    
    # Coloca o socket em modo de escuta (queue de até 5 conexões pendentes)
    server.listen(5)
    print(f"[*] Servidor WAF & HTTP rodando em http://localhost:{PORT}")

    try:
        while True:
            # Aguarda e aceita o Three-Way Handshake TCP do cliente
            client, addr = server.accept()
            ip = addr[0]

            # 1. Aplica verificação de Rate Limiting antes de processar
            if not check_rate_limit(ip):
                body = json.dumps({"error": "Too Many Requests", "status": 429}).encode('utf-8')
                send_response(client, 429, "Too Many Requests", body)
                client.close()
                continue

            # 2. Recebe até 4096 bytes contínuos do fluxo TCP
            raw_data = client.recv(4096).decode('utf-8', errors='ignore')
            if not raw_data:
                client.close()
                continue

            # 3. Delimitação do HTTP: Separa os cabeçalhos do corpo pelo delimitador \r\n\r\n
            parts = raw_data.split('\r\n\r\n')
            first_line = parts[0].split('\r\n')[0].split(' ')
            if len(first_line) < 2:
                client.close()
                continue

            # Extrai o método HTTP (GET/POST) e o caminho/alvo da requisição
            method, target = first_line[0], first_line[1]
            body_text = parts[1] if len(parts) > 1 else ""
            path = target.split('?')[0]

            print(f"[+] Requisicao: {method} {target} - IP: {ip}")

            # 4. Inspeção do WAF na camada de aplicação
            detected_attack = inspect_request(target, body_text, ip)
            if detected_attack:
                body = json.dumps({"error": "Access Denied", "reason": f"WAF Blocked: {detected_attack}", "status": 403}).encode('utf-8')
                send_response(client, 403, "Forbidden", body)
                client.close()
                continue

            # 5. Roteamento das URLs
            # Rota de API: Devolve os logs de ataques para o painel em formato JSON
            if method == 'GET' and path == '/api/logs':
                send_response(client, 200, "OK", json.dumps(ATTACK_LOGS).encode('utf-8'))

            # Rota de API: Processa requisições de teste enviadas por formulário POST
            elif method == 'POST' and path == '/api/login':
                res = json.dumps({"status": "sucesso", "recebido": body_text}).encode('utf-8')
                send_response(client, 200, "OK", res)

            # Rota para entrega de arquivos estáticos (HTML/CSS/JS)
            elif method == 'GET':
                filename = 'index.html' if path in ['/', '/index.html'] else os.path.basename(unquote_plus(path))
                ext = filename.split('.')[-1].lower() if '.' in filename else ''

                # Se o arquivo existe na pasta e tem extensão permitida, lê e envia em bytes
                if ext in MIME and os.path.isfile(filename):
                    with open(filename, 'rb') as f:
                        send_response(client, 200, "OK", f.read(), MIME[ext])
                else:
                    body = json.dumps({"error": "Not Found", "status": 404}).encode('utf-8')
                    send_response(client, 404, "Not Found", body)
            else:
                body = json.dumps({"error": "Method Not Allowed", "status": 405}).encode('utf-8')
                send_response(client, 405, "Method Not Allowed", body)

            # Fecha a conexão TCP do cliente após responder
            client.close()

    except KeyboardInterrupt:
        print("\n[*] Servidor encerrado pelo usuario.")
    finally:
        # Garante o fechamento do socket principal do servidor ao encerrar
        server.close()

if __name__ == '__main__':
    start_server()