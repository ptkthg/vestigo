<![CDATA[<div align="center">

<br/>

```
██╗   ██╗███████╗███████╗████████╗██╗ ██████╗  ██████╗
██║   ██║██╔════╝██╔════╝╚══██╔══╝██║██╔════╝ ██╔═══██╗
██║   ██║█████╗  ███████╗   ██║   ██║██║  ███╗██║   ██║
╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██║██║   ██║██║   ██║
 ╚████╔╝ ███████╗███████║   ██║   ██║╚██████╔╝╚██████╔╝
  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝  ╚═════╝
```

**SOC Intelligence Platform**

*Análise de logs de segurança com IA — privacidade by design*

<br/>

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-Groq%20%2F%20OpenAI-FF6B35?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)

</div>

---

## O que é o Vestigo?

O Vestigo é uma plataforma de análise de logs de segurança para times de SOC. Você cola um log bruto — Windows Event XML, Syslog, JSON, CEF — e a plataforma entrega em segundos:

- **O que aconteceu** em linguagem clara
- **Qual a severidade real** (low / medium / high / critical)
- **O que fazer agora** — ações imediatas por perfil de analista
- **Mapeamento MITRE ATT&CK** com técnica e tática
- **Queries prontas** para KQL (Sentinel/Defender) e SPL (Splunk)
- **IoCs extraídos** — IPs, hashes, domínios, URLs

> **Diferencial:** privacidade by design — o log bruto **nunca** chega à IA. Apenas um JSON de contexto estruturado e mascarado é enviado ao modelo.

---

## Funcionalidades

### Análise

| Recurso | Descrição |
|---|---|
| 🔍 **Análise individual** | Streaming SSE com indicador de progresso por etapa |
| 🔗 **Correlação de logs** | Analisa 2–10 logs juntos e detecta ataques coordenados |
| 📊 **Perfil N1** | Linguagem simples, ações imediatas, indicação de escalonamento |
| 🎯 **Perfil N2/N3** | Análise forense, cadeia de ataque, pivôs de investigação, containment |
| 📦 **Batch** | Análise em lote de até 20 logs via API |

### Enriquecimento

| Recurso | Descrição |
|---|---|
| 🌐 **AbuseIPDB** | Reputação de IPs com cache TTL para não esgotar cota |
| 🦠 **VirusTotal** | Reputação de hashes e domínios |
| 🛡️ **MITRE ATT&CK** | Mapeamento automático de técnica e tática |
| ⚖️ **Score de severidade** | Cálculo próprio com contexto organizacional |

### Operacional

| Recurso | Descrição |
|---|---|
| 📝 **Diagnóstico do analista** | Registre FP / VP / Inconclusivo com nota — alimenta o contexto histórico |
| 🏢 **Contexto organizacional** | Configure CIDRs internos, IPs confiáveis e ferramentas autorizadas para reduzir falsos positivos |
| 🔔 **Webhooks** | Alertas automáticos para Slack e Teams por severidade mínima configurável |
| 📈 **Dashboard** | Métricas de volume, distribuição de severidade e top técnicas MITRE |
| 🔎 **Histórico com busca** | Filtre por IoC, MITRE, severidade e diagnóstico |
| 💾 **Exportação** | JSON e PDF de qualquer análise |

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                         Browser                             │
│              http://localhost:8000                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │    Gateway      │  FastAPI · Rate limiting · SSE
              │    :8000        │  PostgreSQL · Webhooks
              └──┬──────┬──┬───┘
                 │      │  │
        ┌────────▼──┐   │  └────────────────┐
        │  Parser   │   │                   │
        │  :8001    │   │            ┌──────▼──────┐
        │           │   │            │  AI Service  │
        │ • Detecta │   │            │  :8003       │
        │   formato │   │            │              │
        │ • Mascara │   │            │ • Groq LLaMA │
        │   PII     │   │            │   3.3 70B    │
        │ • Extrai  │   │            │ • OpenAI     │
        │   IoCs    │   │            │   GPT-4o     │
        └────────┬──┘   │            └─────────────┘
                 │      │
          ┌──────▼──────▼─┐
          │   Enricher    │
          │   :8002       │
          │               │
          │ • AbuseIPDB   │
          │ • VirusTotal  │
          │ • MITRE map   │
          │ • Severidade  │
          └───────────────┘
```

### Fluxo de privacidade

```
Log bruto → [Parser] ──────────────────────────────────────────┐
                                                                │
             Mascaramento PII                                   │
             ├── IPs internos    →  [IP_INTERNO]               │
             ├── Emails          →  [EMAIL]                    │
             ├── Tokens/senhas   →  [CREDENTIAL]               │
             └── CPF / dados PII →  [PII]                      │
                                                                │
             JSON estruturado → [Enricher] → [AI Service] ─────┘
             (log bruto NUNCA enviado à IA)
```

---

## Formatos de log suportados

| Formato | Exemplos |
|---|---|
| Windows Event Log | XML (4625, 4688, 4720…), JSON do Defender |
| Syslog | RFC 3164, RFC 5424 |
| JSON genérico | Microsoft Sentinel, AWS CloudTrail, Elastic |
| CEF / LEEF | ArcSight, QRadar |
| Texto livre | Qualquer log não estruturado (fallback) |

---

## Início rápido

### Pré-requisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (ou Docker + Compose)
- Chave de API: [Groq](https://console.groq.com) *(gratuito, recomendado)* ou [OpenAI](https://platform.openai.com)
- Opcional: [AbuseIPDB](https://www.abuseipdb.com/api) e [VirusTotal](https://developers.virustotal.com)

### 1. Configurar variáveis de ambiente

```bash
cp .env.example .env
```

Edite `.env`:

```env
# Segurança interna
INTERNAL_API_SECRET=<gere com: python -c "import secrets; print(secrets.token_hex(32))">
POSTGRES_PASSWORD=<senha forte>

# LLM — escolha pelo menos um
GROQ_API_KEY=gsk_...          # LLaMA 3.3 70B, plano gratuito disponível
OPENAI_API_KEY=sk-...         # GPT-4o, alternativa
LLM_PROVIDER=groq             # ou "openai"

# Enriquecimento (opcional, mas recomendado)
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...

# Webhooks (opcional)
WEBHOOK_URL=https://hooks.slack.com/services/...
WEBHOOK_MIN_SEVERITY=high     # low | medium | high | critical
```

### 2. Subir

```bash
docker-compose up --build
```

### 3. Acessar

| URL | Descrição |
|---|---|
| http://localhost:8000 | Interface principal — Analisar |
| http://localhost:8000/history.html | Histórico de análises |
| http://localhost:8000/dashboard.html | Dashboard de métricas |
| http://localhost:8000/settings.html | Contexto organizacional |

---

## Exemplos de log para teste

<details>
<summary>Windows Event — Logon failure (Event ID 4625)</summary>

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
</details>

<details>
<summary>Syslog — SSH brute force</summary>

```
Jan 15 10:30:00 server01 sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 22 ssh2
Jan 15 10:30:01 server01 sshd[12346]: Failed password for invalid user root from 203.0.113.45 port 22 ssh2
Jan 15 10:30:02 server01 sshd[12347]: Failed password for invalid user admin from 203.0.113.45 port 22 ssh2
```
</details>

<details>
<summary>JSON genérico — Autenticação suspeita</summary>

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event": "Authentication failure",
  "src_ip": "203.0.113.45",
  "user": "root",
  "status": "failed",
  "source": "auth.log",
  "geo": { "country": "CN", "city": "Shanghai" }
}
```
</details>

<details>
<summary>Correlação — Múltiplos eventos para análise encadeada</summary>

Cole no modo **Correlação de Logs** (toggle na página principal):

**Evento 1 — Reconhecimento:**
```
Jan 15 10:00:00 fw01 kernel: DROP IN=eth0 SRC=203.0.113.45 DST=10.0.0.1 PROTO=TCP DPT=22
```

**Evento 2 — Acesso inicial:**
```
Jan 15 10:05:00 server01 sshd[1234]: Accepted password for deploy from 203.0.113.45 port 49201 ssh2
```

**Evento 3 — Exfiltração:**
```
Jan 15 10:12:00 server01 kernel: OUT=eth0 SRC=10.0.0.5 DST=203.0.113.45 PROTO=TCP DPT=443 LEN=65535
```
</details>

---

## API Reference

| Endpoint | Método | Descrição |
|---|---|---|
| `/api/analyze` | POST | Análise individual (síncrona) |
| `/api/analyze/stream` | POST | Análise com streaming SSE |
| `/api/analyze/batch` | POST | Lote de até 20 logs |
| `/api/analyze/correlate` | POST | Correlação de 2–10 logs |
| `/api/history` | GET | Histórico com filtros |
| `/api/analyses/{id}/diagnosis` | PATCH | Registrar FP/VP/Inconclusivo |
| `/api/org-config` | GET/PUT | Contexto organizacional |
| `/api/stats` | GET | Métricas do dashboard |
| `/health` | GET | Health check |

---

## Segurança

- Secrets exclusivamente via variáveis de ambiente — nunca hardcoded
- Input sanitizado: null bytes e tentativas de injection bloqueadas
- Rate limiting: 10 req/min por IP (configurável via `RATE_LIMIT_PER_MINUTE`)
- Logs de aplicação não registram conteúdo dos logs do usuário
- `INTERNAL_API_SECRET` autentica comunicação entre containers
- Usuário não-root em todos os containers Docker
- Rede interna Docker isola os serviços — apenas o gateway é exposto

---

## Estrutura do projeto

```
vestigo/
├── docker-compose.yml
├── .env.example
│
├── gateway/                    # Orquestrador + frontend estático
│   └── app/
│       ├── main.py             # Endpoints, SSE, rate limit
│       ├── database.py         # PostgreSQL (análises, diagnósticos, config)
│       ├── webhook.py          # Alertas Slack/Teams
│       └── static/             # Frontend SPA
│           ├── index.html      # Análise + Correlação
│           ├── history.html    # Histórico com busca
│           ├── dashboard.html  # Métricas Chart.js
│           ├── settings.html   # Contexto organizacional
│           ├── app.js          # Lógica frontend
│           └── style.css       # Design system dark SOC
│
├── parser-service/             # Módulo 1: Parse + mascaramento
│   └── app/
│       ├── detector.py         # Detecção de formato de log
│       ├── masker.py           # PII masking
│       ├── ioc_extractor.py    # Extração de IPs, hashes, domínios
│       └── parsers/            # Windows Event, Syslog, JSON, CEF
│
├── enricher-service/           # Módulo 2: Enriquecimento
│   └── app/
│       ├── cache.py            # Cache TTL em memória
│       ├── severity.py         # Scoring de severidade
│       └── enrichers/
│           ├── abuseipdb.py    # Reputação de IPs
│           ├── virustotal.py   # Reputação de hashes/domínios
│           └── mitre_mapper.py # Mapeamento ATT&CK
│
└── ai-service/                 # Módulo 3: IA
    └── app/
        ├── llm_client.py       # Cliente Groq / OpenAI
        └── prompts/
            ├── n1.py           # Prompt analista júnior
            ├── n2n3.py         # Prompt analista sênior
            └── correlate.py    # Prompt correlação de eventos
```

---

## Stack

| Camada | Tecnologia |
|---|---|
| Backend | Python 3.12, FastAPI, asyncpg |
| Banco de dados | PostgreSQL 16 |
| LLM | Groq (LLaMA 3.3 70B) / OpenAI (GPT-4o) |
| Frontend | HTML/CSS/JS vanilla, Chart.js |
| Infra | Docker Compose, slowapi, httpx |
| Fontes | Inter + JetBrains Mono (Google Fonts) |

---

## Licença

MIT — veja [LICENSE](LICENSE) para detalhes.

---

<div align="center">

*Vestigo · privacidade by design · o log bruto nunca chega à IA*

</div>
]]>