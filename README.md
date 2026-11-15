# Web Application Firewall (WAF) & SOC Dashboard 🛡️

Um servidor HTTP e Web Application Firewall (WAF) desenvolvido  em Python utilizando **Sockets TCP nativos** (sem frameworks externos como Flask ou Django). O projeto inclui um painel SOC em tempo real para monitorização e simulação de ataques cibernéticos.

---

## 📌 Funcionalidades

- **Servidor HTTP/1.1 Nativo:** Construído diretamente sobre a API de Sockets TCP (`AF_INET`, `SOCK_STREAM`).
- **Web Application Firewall (WAF):** Inspeção de requisições na Camada de Aplicação (Camada 7) utilizando Expressões Regulares (Regex).
- **Proteção contra Ameaças:**
  - **SQL Injection (SQLi):** Detecção de comandos como `UNION SELECT`, `OR 1=1`, aspas e tautologias.
  - **Cross-Site Scripting (XSS):** Filtro contra tags `<script>`, funções de alerta e payloads em codificação URL.
  - **Path Traversal:** Bloqueio de navegação não autorizada no sistema de ficheiros (ex: `../`, `/etc/passwd`).
- **Proteção Anti-DoS (Rate Limiting):** Mecanismo de janela deslizante (*sliding window*) que limita a 10 requisições a cada 5 segundos por IP.
- **Painel SOC / Dashboard:** Interface web responsiva para simulação de ataques e visualização dos incidentes de segurança em tempo real.

---

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3 (Bibliotecas nativas: `socket`, `os`, `json`, `time`, `re`, `urllib.parse`)
- **Frontend:** HTML5, CSS3, JavaScript (Fetch API para consumo assíncrono do Dashboard)
- **Versionamento:** Git & GitHub

---

## 🚀 Como Executar o Projeto

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
## Testar os Ataques e a Segurança

- Clica nos botões de simulação (SQL Injection, XSS, Path Traversal) para testar os bloqueios do WAF.

- Observa a resposta 403 Forbidden no painel e a atualização automática da tabela de Logs de Incidentes Detectados.

- Testa disparar vários cliques seguidos num botão para validar o bloqueio por Rate Limiting (429 Too Many Requests).
