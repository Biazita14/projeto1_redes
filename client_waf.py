import socket
import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

# --- CONFIGURAÇÕES GLOBAIS DE REDE E PORTAS ---
WAF_HOST = '127.0.0.1'   # Endereço IP do Servidor WAF alvo
WAF_PORT = 8080          # Porta TCP onde o Servidor WAF está escutando
CLIENT_UI_PORT = 9090    # Porta local da interface visual de controle do cliente

def send_raw_tcp_http(method, path, body="", content_type="application/x-www-form-urlencoded"):
    """ CAMADA DE TRANSPORTE & APLICAÇÃO: Abre socket TCP puro, monta o pacote HTTP/1.1 e lê a resposta. """
    # Codifica espaços em branco na URL (%20) para não quebrar a primeira linha do protocolo HTTP/1.1
    path = path.replace(" ", "%20")

    # Criando socket IPv4 (AF_INET) e TCP (SOCK_STREAM) com timeout de 5 segundos
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(5)

    # Converte o corpo (body) para bytes e monta os cabeçalhos obrigatórios do HTTP/1.1
    body_bytes = body.encode('utf-8')
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {WAF_HOST}:{WAF_PORT}\r\n"
        f"User-Agent: Python-Raw-Socket-Client/2.0\r\n"
        f"Connection: close\r\n"
    )

    # Se for requisição POST, inclui o tipo e o tamanho exato do payload em bytes
    if method == "POST":
        headers += (
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
        )

    # Concatena cabeçalhos + delimitador obrigatório (\r\n\r\n) + corpo da mensagem em bytes
    raw_request_bytes = headers.encode('utf-8') + b"\r\n" + body_bytes
    raw_request_str = raw_request_bytes.decode('utf-8', errors='replace')

    try:
        # 1. Estabelece a conexão TCP (Three-Way Handshake) com o servidor WAF
        client.connect((WAF_HOST, WAF_PORT))

        # 2. Transmite todos os bytes da requisição HTTP pelo canal TCP
        client.sendall(raw_request_bytes)

        # 3. Recebe a resposta do servidor em blocos (chunks) de até 4096 bytes até o fim do fluxo
        chunks = []
        while True:
            try:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except ConnectionAbortedError:
                # Se o servidor encerrar abruptamente após responder (TCP RST), aproveita o que já foi lido
                if chunks:
                    break
                raise

        # Decodifica a resposta completa e separa a linha de status (ex: HTTP/1.1 200 OK)
        full_response = b"".join(chunks).decode('utf-8', errors='replace')
        parts = full_response.split('\r\n\r\n', 1)
        status_line = parts[0].split('\r\n')[0] if parts[0] else "Sem resposta"

        return {
            "ok": True,
            "status_line": status_line,
            "raw_request": raw_request_str,
            "raw_response": full_response
        }

    except ConnectionRefusedError:
        # Trata o erro caso o server_waf.py ainda não esteja rodando na porta 8080
        return {
            "ok": False,
            "status_line": "ERRO DE CONEXÃO (Connection Refused)",
            "raw_request": raw_request_str,
            "raw_response": f"Não foi possível conectar em {WAF_HOST}:{WAF_PORT}.\nVerifique se o server_waf.py está rodando!"
        }
    except Exception as e:
        # Captura falhas gerais de timeout ou rede no socket
        return {
            "ok": False,
            "status_line": "ERRO NO SOCKET",
            "raw_request": raw_request_str,
            "raw_response": str(e)
        }
    finally:
        # Garante o fechamento do socket TCP e a liberação da porta efêmera no sistema operacional
        client.close()


# --- INTERFACE WEB DE CONTROLE E INSPEÇÃO DE PACOTES (WIRE VIEW) ---
HTML_UI = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Cliente TCP/HTTP Nativo - Painel de Ataque</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e2f; color: #fff; margin: 0; padding: 20px; }
        h1 { color: #00d2ff; margin-bottom: 5px; }
        .subtitle { color: #a9b7c6; margin-top: 0; margin-bottom: 20px; }
        .container { display: flex; gap: 20px; flex-wrap: wrap; }
        .card { background: #27293d; padding: 20px; border-radius: 8px; flex: 1; min-width: 340px; box-shadow: 0 4px 8px rgba(0,0,0,0.3); }
        .card h2 { margin-top: 0; color: #ff3366; }
        .card h2.green { color: #00e676; }
        label { display: block; margin-top: 10px; font-size: 13px; color: #a9b7c6; }
        input[type="text"], select { width: 100%; padding: 10px; margin: 6px 0 12px 0; border-radius: 4px; border: 1px solid #444; background: #1e1e2f; color: #fff; box-sizing: border-box; }
        button { background: #00d2ff; color: #1e1e2f; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; width: 100%; margin-top: 8px; transition: 0.2s; }
        button:hover { background: #0099cc; }
        button.attack { background: #ff3366; color: #fff; }
        button.attack:hover { background: #d62854; }
        button.safe { background: #00e676; color: #1e1e2f; }
        button.safe:hover { background: #00c853; }
        pre { background: #1e1e2f; padding: 12px; border-radius: 4px; overflow-x: auto; color: #a9b7c6; border: 1px solid #333; font-size: 13px; white-space: pre-wrap; word-wrap: break-word; }
        .status-badge { display: inline-block; padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; background: #333; margin-bottom: 10px; }
        .status-200 { background: #00e676; color: #1e1e2f; }
        .status-403, .status-429, .status-err { background: #ff3366; color: #fff; }
    </style>
</head>
<body>

    <h1>Cliente TCP/HTTP Nativo (Python Raw Socket)</h1>
    <p class="subtitle">Interface de Controle para Disparo de Pacotes TCP Brutos contra o Servidor WAF (127.0.0.1:8080)</p>

    <div class="container">
        <!-- Coluna 1: Controles de Disparo -->
        <div class="card">
            <h2 class="green">1. Tráfego Legítimo (Camada 7)</h2>
            <button class="safe" onclick="disparar('GET', '/api/logs', '')">Consultar Logs do SOC (GET /api/logs)</button>
            <button class="safe" onclick="disparar('POST', '/api/login', 'user=beatriz&pass=senha123')">Enviar Login Válido (POST /api/login)</button>

            <hr style="border-color: #444; margin: 20px 0;">

            <h2>2. Simulação de Ataques (Testar WAF)</h2>
            <button class="attack" onclick="disparar('POST', '/api/login', 'user=admin\\' OR 1=1--&pass=123')">Simular SQL Injection (OR 1=1)</button>
            <button class="attack" onclick="disparar('GET', '/?busca=%3Cscript%3Ealert(1)%3C/script%3E', '')">Simular Cross-Site Scripting (XSS)</button>
            <button class="attack" onclick="disparar('GET', '/../../etc/passwd', '')">Simular Path Traversal (/etc/passwd)</button>
            <button class="attack" onclick="dispararRajada()">Simular Rajada Anti-DoS (12 reqs seguidas)</button>

            <hr style="border-color: #444; margin: 20px 0;">

            <h2 style="color: #00d2ff;">3. Requisição Manual Customizada</h2>
            <label>Método HTTP:</label>
            <select id="customMethod">
                <option value="GET">GET</option>
                <option value="POST">POST</option>
            </select>
            <label>Caminho / URL:</label>
            <input type="text" id="customPath" value="/api/login">
            <label>Corpo (Body - apenas para POST):</label>
            <input type="text" id="customBody" value="username=admin' UNION SELECT * FROM users--">
            <button onclick="dispararCustom()">Disparar Pacote via Socket TCP</button>
        </div>

        <!-- Coluna 2: Inspeção de Pacotes TCP/HTTP -->
        <div class="card">
            <h2 style="color: #00d2ff;">Inspeção de Pacotes (Wire View)</h2>
            <div id="statusBadge" class="status-badge">Aguardando disparo...</div>

            <label>Pacote HTTP Bruto Enviado pelo Socket Python (Request):</label>
            <pre id="rawRequestBox">Nenhum pacote enviado ainda.</pre>

            <label>Resposta Bruta Recebida do Servidor WAF (Response):</label>
            <pre id="rawResponseBox">Aguardando resposta...</pre>
        </div>
    </div>

    <script>
        // Envia comando para o backend Python disparar a requisição via socket TCP nativo
        async function disparar(method, path, body) {
            document.getElementById('statusBadge').className = 'status-badge';
            document.getElementById('statusBadge').innerText = 'Abrindo socket TCP...';

            const res = await fetch('/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ method, path, body })
            });
            const data = await res.json();

            const badge = document.getElementById('statusBadge');
            badge.innerText = data.status_line;

            // Aplica a cor semântica de acordo com o código de status HTTP retornado
            if (data.status_line.includes('200')) {
                badge.className = 'status-badge status-200';
            } else if (data.status_line.includes('429')) {
                badge.className = 'status-badge status-429';
            } else if (data.status_line.includes('403')) {
                badge.className = 'status-badge status-403';
            } else {
                badge.className = 'status-badge status-err';
            }

            document.getElementById('rawRequestBox').innerText = data.raw_request;
            document.getElementById('rawResponseBox').innerText = data.raw_response;
        }

        // Lê os campos do formulário customizado e dispara o pacote
        function dispararCustom() {
            const method = document.getElementById('customMethod').value;
            const path = document.getElementById('customPath').value;
            const body = method === 'POST' ? document.getElementById('customBody').value : '';
            disparar(method, path, body);
        }

        // Dispara até 12 requisições em sequência para testar o limite de Rate Limiting (429)
        async function dispararRajada() {
            const badge = document.getElementById('statusBadge');
            for (let i = 1; i <= 12; i++) {
                badge.className = 'status-badge';
                badge.innerText = `Rajada Anti-DoS: enviando pacote ${i}/12...`;

                const res = await fetch('/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ method: 'GET', path: '/api/logs', body: '' })
                });
                const data = await res.json();

                document.getElementById('rawRequestBox').innerText = data.raw_request;
                document.getElementById('rawResponseBox').innerText = data.raw_response;

                if (data.status_line.includes('429')) {
                    badge.innerText = `Bloqueado na req ${i}/12: ${data.status_line}`;
                    badge.className = 'status-badge status-429';
                    break;
                } else if (data.status_line.includes('200')) {
                    badge.innerText = `Req ${i}/12: ${data.status_line}`;
                    badge.className = 'status-badge status-200';
                } else {
                    badge.innerText = `Req ${i}/12: ${data.status_line}`;
                    badge.className = 'status-badge status-err';
                    break;
                }

                await new Promise(r => setTimeout(r, 120));
            }
        }
    </script>
</body>
</html>
"""


class ClientUIHandler(BaseHTTPRequestHandler):
    """ SERVIDOR LOCAL DE CONTROLE: Serve a página HTML do cliente e recebe os comandos dos botões. """
    def log_message(self, format, *args):
        pass  # Suprime logs de acesso da UI para manter o terminal limpo

    # Rota GET: Entrega a interface web do cliente para o navegador
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(HTML_UI.encode('utf-8'))

    # Rota POST /send: Aciona a função de socket TCP nativo e devolve o resultado em JSON
    def do_POST(self):
        if self.path == '/send':
            length = int(self.headers.get('Content-Length', 0))
            payload = json.loads(self.rfile.read(length).decode('utf-8'))
            result = send_raw_tcp_http(
                payload.get('method', 'GET'),
                payload.get('path', '/'),
                payload.get('body', '')
            )
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))


def start_client():
    """ INICIALIZAÇÃO DO CLIENTE: Sobe a interface visual na porta 9090 e abre no navegador. """
    server_ui = HTTPServer(('127.0.0.1', CLIENT_UI_PORT), ClientUIHandler)
    url = f"http://127.0.0.1:{CLIENT_UI_PORT}"
    print(f"[*] Interface Visual do Cliente TCP rodando em: {url}")
    print(f"[*] Alvo configurado: Socket TCP {WAF_HOST}:{WAF_PORT}")
    webbrowser.open(url)
    try:
        server_ui.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Cliente encerrado pelo usuario.")
    finally:
        server_ui.server_close()

if __name__ == '__main__':
    start_client()