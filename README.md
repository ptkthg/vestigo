# Vestigo — SOC Intelligence Platform

Plataforma de análise de logs e payloads para times de SOC.
Interpreta logs brutos de segurança e entrega ao analista: o que aconteceu, o quanto é crítico e o que fazer agora.

**Diferencial:** privacidade by design — o log bruto **nunca** chega à IA. Apenas um JSON de contexto mascarado e enriquecido é enviado ao modelo.

---

## Arquitetura

```
Browser → Gateway (8000)
             ├── POST /parse  → parser-service  (8001)
             ├── POST /enrich → enricher-service (8002)
             └── POST /analyze → ai-service     (8003)
                                    └── Groq / OpenAI API
```

### Módulos

| Serviço | Responsabilidade |
|---------|-----------------|
| `gateway` | Orquestração, rate limiting, servir frontend |
| `parser-service` | Detectar formato, extrair campos, mascarar PII |
| `enricher-service` | AbuseIPDB, VirusTotal, MITRE mapping, severidade |
| `ai-service` | Prompt estruturado por perfil → LLM → resposta |
| `postgres` | Persistência (fase futura) |

### Formatos de log suportados

- Windows Event Log (XML e JSON)
- Syslog RFC 3164 e RFC 5424
- JSON genérico de segurança (Defender, Sentinel, CloudTrail, etc.)
- CEF / LEEF (detecção de formato, parse básico)
- Texto livre (fallback)

---

## Como rodar

### Pré-requisitos

- Docker Desktop (ou Docker + docker-compose)
- Chaves de API (mínimo: Groq ou OpenAI para o módulo de IA)

### 1. Configurar variáveis de ambiente

```bash
cp .env.example .env
```

Edite `.env` e preencha:

```env
INTERNAL_API_SECRET=<gere com: python -c "import secrets; print(secrets.token_hex(32))">
POSTGRES_PASSWORD=<senha forte>

# Escolha pelo menos uma:
GROQ_API_KEY=<sua chave Groq>      # recomendado (LLaMA 3.3 70B, gratuito)
OPENAI_API_KEY=<sua chave OpenAI>  # alternativa (GPT-4o)
LLM_PROVIDER=groq                   # ou "openai"

# Enriquecimento (opcional no MVP, mas recomendado):
ABUSEIPDB_API_KEY=<sua chave>
VIRUSTOTAL_API_KEY=<sua chave>
```

### 2. Subir os containers

```bash
docker-compose up --build
```

### 3. Acessar

Abra **http://localhost:8000** no navegador.

Para verificar saúde dos serviços:
```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/analyze  # 405 Method Not Allowed = serviço ok
```

---

## Exemplos de log para teste

### Windows Event — Logon Failure (Event ID 4625)

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
    <Computer>WORKSTATION-01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrador</Data>
    <Data Name="IpAddress">203.0.113.45</Data>
    <Data Name="IpPort">52341</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="Status">0xC000006D</Data>
  </EventData>
</Event>
```

### Syslog RFC 3164 — SSH brute force

```
Jan 15 10:30:00 server01 sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 22 ssh2
```

### Syslog RFC 5424

```
<34>1 2024-01-15T10:30:00Z web-server nginx 1234 - - Failed password for user admin from 198.51.100.10 port 443
```

### JSON genérico

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event": "Authentication failure",
  "src_ip": "203.0.113.45",
  "user": "root",
  "status": "failed",
  "source": "auth.log"
}
```

---

## Segurança do MVP

- Secrets exclusivamente via variáveis de ambiente (nunca hardcoded)
- Input sanitizado: null bytes, tentativas de injection bloqueadas
- Rate limiting: 10 req/min por IP (configurável via `RATE_LIMIT_PER_MINUTE`)
- Logs de aplicação não registram conteúdo do log do usuário
- `INTERNAL_API_SECRET` protege comunicação entre containers
- Usuário não-root em todos os containers
- Rede Docker interna isola os serviços (apenas gateway exposto)

## Privacidade by design

```
Log bruto → [parser] → Mascaramento PII → JSON limpo
                         ↓
                    IPs internos     → [IP_INTERNO]
                    Emails           → [EMAIL]
                    Tokens/segredos  → [TOKEN]
                    CPF/PII          → [PII]
                    Senhas           → [CREDENTIAL]
                         ↓
               JSON enriquecido → [ai-service] → LLM
               (sem dado bruto do log original)
```

---

## Estrutura de pastas

```
vestigo/
├── docker-compose.yml
├── .env.example
├── gateway/                  # Orquestrador + frontend estático
│   └── app/
│       ├── main.py
│       └── static/           # index.html, style.css, app.js
├── parser-service/           # Módulo 1: Parse + Mascaramento
│   └── app/
│       ├── detector.py       # Detecção de formato
│       ├── masker.py         # PII masking
│       ├── ioc_extractor.py  # Extração de IoCs
│       └── parsers/          # Parsers por formato
├── enricher-service/         # Módulo 2: Enriquecimento
│   └── app/
│       ├── enrichers/        # AbuseIPDB, VirusTotal, MITRE
│       └── severity.py       # Cálculo de severidade
└── ai-service/               # Módulo 3: IA
    └── app/
        ├── llm_client.py     # Cliente Groq/OpenAI
        └── prompts/          # Prompts por perfil (N1, N2/N3)
```

---

## Roadmap (pós-MVP)

- [ ] Autenticação de usuários (JWT)
- [ ] Histórico de análises (PostgreSQL)
- [ ] Exportação PDF de relatórios
- [ ] Correlação de múltiplos logs
- [ ] Integração com SIEM (webhooks)
- [ ] Suporte a LEEF completo, CloudTrail, CEF
- [ ] Perfil Gestor (impacto de negócio)
- [ ] URLhaus e OTX AlienVault no enricher
