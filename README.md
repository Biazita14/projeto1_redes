# Web Application Firewall (WAF), Cliente TCP Nativo & SOC Dashboard 

Uma arquitetura completa **Cliente-Servidor** de segurança web desenvolvida em Python utilizando **Sockets TCP nativos** (`AF_INET`, `SOCK_STREAM`), sem o uso de frameworks externos (como Flask, Django ou `requests`). O projeto integra um Servidor HTTP/WAF (`server_waf.py`) com Dashboard SOC e um Cliente TCP/HTTP Nativo (`client_waf.py`) com interface visual para disparo e inspeção de pacotes brutos.

---

##  Funcionalidades

###  Servidor HTTP & Motor WAF (`server_waf.py` — Porta `8080`)
- **Servidor HTTP/1.1 Nativo:** Parsing manual de cabeçalhos, métodos (`GET`/`POST`), rotas e delimitação por `\r\n\r\n` diretamente sobre sockets TCP.
- **Inspeção na Camada de Aplicação (Camada 7):** Filtragem de URLs e corpos de requisição (*body*) via Expressões Regulares (Regex) após decodificação URL (`unquote_plus`).
- **Detecção de Ameaças:**
  - **SQL Injection (SQLi):** Bloqueio de comandos como `UNION`, `SELECT`, `OR 1=1`, aspas simples e tautologias.
  - **Cross-Site Scripting (XSS):** Filtro contra tags `<script>`, payloads ofuscados em URL (`%3Cscript`), chamadas `alert(` e URIs `javascript:`.
  - **Path Traversal:** Bloqueio de navegação não autorizada no sistema de arquivos (`../`, `/etc/passwd`, `boot.ini`).
- **Proteção Anti-DoS (Rate Limiting):** Mecanismo de janela deslizante (*sliding window*) que limita a 10 requisições a cada 5 segundos por endereço IP (`HTTP 429 Too Many Requests`).
- **Painel SOC / Dashboard (`index.html`):** Interface web em tempo real para visualização dos incidentes bloqueados (`HTTP 403 Forbidden`).

###  Cliente TCP/HTTP Nativo (`client_waf.py` — Porta `9090`)
- **Construção Manual de Pacotes HTTP/1.1:** Abre conexões TCP puras (`socket.connect`) e monta manualmente os cabeçalhos (`Host`, `User-Agent`, `Content-Length`, `Connection: close`) e o corpo da requisição.
- **Interface Visual de Controle:** Painel web integrado para disparo de tráfego legítimo, simulações automatizadas de ataques (SQLi, XSS, Path Traversal, rajadas Anti-DoS) e requisições customizadas (`GET` e `POST`).
- **Inspeção de Pacotes (*Wire View*):** Exibe em tempo real tanto o pacote HTTP bruto enviado pelo socket Python quanto a resposta bruta recebida do servidor.

---

##  Tecnologias Utilizadas

- **Linguagem:** Python 3 (Bibliotecas nativas: `socket`, `os`, `json`, `time`, `re`, `urllib.parse`, `http.server`, `webbrowser`)
- **Frontend:** HTML5, CSS3, JavaScript (Fetch API)
- **Versionamento:** Git & GitHub

---

##  Estrutura do Projeto

```text
projeto1_redes/
├── server_waf.py   # Servidor HTTP/1.1 + Motor WAF + Rate Limiting (Porta 8080)
├── client_waf.py   # Cliente TCP/HTTP Nativo + Interface Wire View (Porta 9090)
├── index.html      # Dashboard do SOC (Logs de incidentes em tempo real)
└── README.md       # Documentação do projeto

```

##  Como Executar o Projeto

### Pré-requisitos
- **Python 3.x** instalado no computador.
- **Navegador Web** (Chrome, Edge, Firefox, etc.).

### Passo a Passo

1. **Clonar o Repositório**
   ```bash
   git clone [https://github.com/Biazita14/projeto1_redes.git](https://github.com/Biazita14/projeto1_redes.git)
   cd projeto1_redes
   python server_waf.py -> para ligar servidor
   http://localhost:8080 -> coloca no seu navegador para entrar na página

2. **Iniciar servidor WAF (terminal 1)**
   ```
   python server_waf.py
   ```
3. **Iniciar o Cliente TCP/HTTP Nativo (Terminal 2)**
   ```
   python client_waf.py
   ```
   
## Testar os Ataques e a Segurança

-Deixe as abas do Cliente (127.0.0.1:9090) e do Servidor (localhost:8080) abertas lado a lado:

-Tráfego Legítimo: No painel do Cliente, clique em "Enviar Login Válido (POST /api/login)". Observe o status verde HTTP/1.1 200 OK e o pacote bruto montado na coluna Wire View.

-Bloqueio de Ataques (WAF): Clique nos botões de simulação (SQL Injection, XSS ou Path Traversal) ou monte um payload na seção Requisição Manual Customizada. O cliente receberá HTTP/1.1 403 Forbidden e o incidente aparecerá automaticamente na tabela do SOC Dashboard (localhost:8080).

-Proteção Anti-DoS: Clique em "Simular Rajada Anti-DoS (12 reqs seguidas)" para validar o bloqueio por excesso de requisições (HTTP/1.1 429 Too Many Requests).
