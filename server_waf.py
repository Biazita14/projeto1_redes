import socket
import os
import json
import time
import re

PORT = 8080
HOST = ''

# ESTRUTURAS DE DADOS DO WAF / HONEYPOT

# Regras de inspeção WAF (Expressões Regulares)
# Regras de inspeção WAF atualizadas e flexíveis
ATTACK_PATTERNS = {
    "Path Traversal": [
        r"\.\.",
        r"\/etc\/passwd",
        r"boot\.ini"
    ],
    "SQL Injection (SQLi)": [
        r"(?i)\bOR\b.*=",
        r"(?i)\bUNION\b",
        r"(?i)\bSELECT\b",
        r"(?i)1\s*=\s*1",
        r"'"
    ],
    "Cross-Site Scripting (XSS)": [
        r"(?i)<script",
        r"(?i)%3Cscript",
        r"(?i)alert\(",
        r"(?i)javascript:"
    ]
}

# Logs de incidentes gravados pelo WAF
ATTACK_LOGS = []

# Controle de Rate Limiting por IP: { ip: [timestamp_req1, timestamp_req2, ...] }
IP_REQUESTS = {}
RATE_LIMIT_MAX = 10     # Máximo de requisições
RATE_LIMIT_WINDOW = 5   # Janela de tempo em segundos

# FUNÇÕES DE SEGURANÇA E AUXILIARES

def check_rate_limit(ip):
    """
    Mecanismo de Rate Limiting: Bloqueia IPs que realizam muitas requisições
    em um curto intervalo de tempo (Mitigação de DoS / Brute Force).
    """
    now = time.time()
    if ip not in IP_REQUESTS:
        IP_REQUESTS[ip] = []
    
    # Remove timestamps fora da janela de tempo
    IP_REQUESTS[ip] = [t for t in IP_REQUESTS[ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(IP_REQUESTS[ip]) >= RATE_LIMIT_MAX:
        return False  # Limite excedido
    
    IP_REQUESTS[ip].append(now)
    return True

def inspect_request(request_str, client_ip):
    """
    Motor de Inspeção WAF: Inspeciona apenas a linha de requisição (URL/método) e o corpo (body),
    evitando falsos positivos nos cabeçalhos HTTP do navegador (como cookies e referers).
    """
    parts = request_str.split('\r\n\r\n')
    headers_part = parts[0]
    first_line = headers_part.split('\r\n')[0] if headers_part else ""
    body_part = parts[1] if len(parts) > 1 else ""

    # Analisamos apenas a linha da URL e o corpo da requisição (POST)
    text_to_inspect = first_line + "\n" + body_part

    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_to_inspect):
                # Log do incidente
                log_entry = {
                    "id": len(ATTACK_LOGS) + 1,
                    "timestamp": time.strftime("%H:%M:%S"),
                    "ip": client_ip,
                    "type": attack_type,
                    "payload": first_line  # Registra a linha da requisição
                }
                ATTACK_LOGS.append(log_entry)
                print(f"  [WAF ALERTA] ATAQUE DETECTADO [{attack_type}] de {client_ip}")
                return attack_type
    return None

def get_mime_type(filename):
    """ Mapeia extensões para Content-Type HTTP """
    ext = filename.split('.')[-1].lower()
    types = {
        'html': 'text/html; charset=utf-8',
        'css': 'text/css',
        'js': 'application/javascript',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'json': 'application/json'
    }
    return types.get(ext, 'text/plain')


# LOOP PRINCIPAL DO SERVIDOR

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    print(f"[*] WAF & HTTP Server iniciado na porta {PORT}...")
    print(f"[*] Dashboard de Segurança acessível em: http://localhost:{PORT}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_ip = addr[0]
            
            try:
                # 1. Verificação de Rate Limiting (Camada de Proteção Brute-Force)
                if not check_rate_limit(client_ip):
                    print(f"  [RATE LIMIT] IP Bloqueado por excesso de requisições: {client_ip}")
                    res = (
                        "HTTP/1.1 429 Too Many Requests\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n"
                        "Retry-After: 5\r\n"
                        "Connection: close\r\n\r\n"
                        "<h1>429 - Bloqueado por Rate Limiting (Muitas Requisicoes)</h1>"
                    )
                    client_socket.sendall(res.encode())
                    client_socket.close()
                    continue

                request_data = client_socket.recv(4096)
                if not request_data:
                    client_socket.close()
                    continue

                request_text = request_data.decode('utf-8', errors='ignore')
                lines = request_text.split('\r\n')
                first_line = lines[0].split(' ')

                if len(first_line) < 2:
                    client_socket.close()
                    continue

                method = first_line[0]
                path = first_line[1]

                print(f"[+] Requisicao: {method} {path} - IP: {client_ip}")

                # 2. Inspeção Ativa de Segurança (WAF)
                detected_attack = inspect_request(request_text, client_ip)
                if detected_attack:
                    body = json.dumps({
                        "error": "Access Denied",
                        "reason": f"WAF Blocked: {detected_attack}",
                        "status": 403
                    }).encode('utf-8')
                    
                    header = (
                        "HTTP/1.1 403 Forbidden\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    client_socket.sendall(header.encode() + body)
                    client_socket.close()
                    continue

                # 3. Roteamento e Respostas HTTP Válidas

                # ROTA: Dashboard Principal (HTML)
                if method == 'GET' and (path == '/' or path == '/index.html'):
                    filepath = 'index.html'
                    if os.path.exists(filepath):
                        with open(filepath, 'rb') as f:
                            body = f.read()
                        header = (
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html; charset=utf-8\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            "Connection: close\r\n\r\n"
                        )
                        client_socket.sendall(header.encode() + body)
                    else:
                        res = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 - index.html nao encontrado"
                        client_socket.sendall(res.encode())

                # ROTA: API para busca dos logs de ataques em tempo real (GET)
                elif method == 'GET' and path == '/api/logs':
                    body = json.dumps(ATTACK_LOGS).encode('utf-8')
                    header = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    client_socket.sendall(header.encode() + body)

                # ROTA: API para simular envio de dados / login (POST)
                elif method == 'POST' and path == '/api/login':
                    parts = request_text.split('\r\n\r\n')
                    post_body = parts[1] if len(parts) > 1 else ""
                    
                    body = json.dumps({
                        "status": "sucesso",
                        "mensagem": "Dados processados com sucesso pelo servidor WAF.",
                        "recebido": post_body
                    }).encode('utf-8')
                    
                    header = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    client_socket.sendall(header.encode() + body)

                # ROTA: Arquivos Estáticos ou 404
                elif method == 'GET':
                    filename = path.lstrip('/')
                    if os.path.exists(filename) and os.path.isfile(filename):
                        mime_type = get_mime_type(filename)
                        with open(filename, 'rb') as f:
                            body = f.read()
                        header = (
                            "HTTP/1.1 200 OK\r\n"
                            f"Content-Type: {mime_type}\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            "Connection: close\r\n\r\n"
                        )
                        client_socket.sendall(header.encode() + body)
                    else:
                        res = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 - Arquivo Nao Encontrado</h1>"
                        client_socket.sendall(res.encode())

                else:
                    res = "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\n405 Method Not Allowed"
                    client_socket.sendall(res.encode())

            except Exception as e:
                print(f"[-] Erro ao processar requisição: {e}")
            finally:
                client_socket.close()

    except KeyboardInterrupt:
        print("\n[*] Servidor encerrado.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()