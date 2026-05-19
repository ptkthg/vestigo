<div align="center">

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
![LLM](https://img.shields.io/badge/LLM-Groq%20%7C%20OpenAI%20%7C%20Ollama-FF6B35?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)

</div>

---

## O que é o Vestigo?

Plataforma de análise de logs de segurança para times de SOC. Cole um log bruto — Windows Event XML, Syslog, JSON, CEF — e receba em segundos:

- **O que aconteceu** em linguagem clara
- **Qual a severidade real** — low / medium / high / critical
- **O que fazer agora** — ações imediatas por perfil de analista
- **Mapeamento MITRE ATT&CK** com técnica e tática
- **Queries prontas** para KQL (Sentinel/Defender) e SPL (Splunk)
- **IoCs extraídos** — IPs, hashes, domínios, URLs

> **Privacidade by design** — o log bruto **nunca** chega à IA. Apenas um JSON de contexto estruturado e mascarado é enviado ao modelo. Com Ollama, nenhum dado sai da rede.

---

## Funcionalidades

### Análise

| Recurso | Descrição |
|---|---|
| **Análise individual** | Streaming SSE com indicador de progresso por etapa |
| **Correlação de logs** | Analisa 2–10 logs juntos e detecta ataques coordenados |
| **Perfil N1** | Linguagem simples, ações imediatas, indicação de escalonamento |
| **Perfil N2/N3** | Análise forense, cadeia de ataque, pivôs de investigação, containment |
| **Batch** | Análise em lote de até 20 logs via API |

### Enriquecimento

| Recurso | Descrição |
|---|---|
| **AbuseIPDB** | Reputação de IPs com cache TTL para não esgotar a cota |
| **VirusTotal** | Reputação de hashes e domínios |
| **MITRE ATT&CK** | Mapeamento automático de técnica e tática |
| **Score de severidade** | Cálculo próprio calibrado pelo contexto organizacional |

### Operacional

| Recurso | Descrição |
|---|---|
| **Diagnóstico do analista** | Registre FP / VP / Inconclusivo com nota — alimenta o histórico |
| **Contexto organizacional** | Configure CIDRs internos, IPs confiáveis e ferramentas autorizadas |
| **Webhooks** | Alertas automáticos para Slack e Teams por severidade mínima |
| **Dashboard** | Métricas de volume, distribuição de severidade e top técnicas MITRE |
| **Histórico com busca** | Filtre por IoC, MITRE, severidade e diagnóstico |
| **Exportação** | JSON e PDF de qualquer análise |

---

## Arquitetura

```
┌──────────────────────────────────────────────────────┐
│                      Browser                         │
│                 http://localhost:8000                 │
└─────────────────────┬────────────────────────────────┘
                      │
             ┌────────▼────────┐
             │    Gateway      │  FastAPI · SSE · Rate limit
             │    :8000        │  PostgreSQL · Webhooks
             └──┬───────┬──┬───┘
                │       │  │
       ┌────────▼─┐     │  └──────────────────┐
       │  Parser  │     │                     │
       │  :8001   │     │              ┌───────▼──────┐
       │          │     │              │  AI Service  │
       │ • Formato│     │              │  :8003       │
       │ • PII    │     │              │              │
       │ • IoCs   │     │              │ • Groq       │
       └────────┬─┘     │              │ • OpenAI     │
                │       │              │ • Ollama     │
         ┌──────▼───────▼─┐            │  (local)     │
         │   Enricher     │            └──────────────┘
         │   :8002        │
         │                │
         │ • AbuseIPDB    │
         │ • VirusTotal   │
         │ • MITRE ATT&CK │
         │ • Severidade   │
         └────────────────┘
```

### Fluxo de privacidade

```
Log bruto → [Parser] → Mascaramento PII → JSON limpo
                         ├── IPs internos  →  [IP_INTERNO]
                         ├── Emails        →  [EMAIL]
                         ├── Tokens/senhas →  [CREDENTIAL]
                         └── CPF / PII     →  [PII]
                                ↓
              [Enricher] → [AI Service] → LLM
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

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- Chave de API: [Groq](https://console.groq.com) *(gratuito, recomendado)* ou [OpenAI](https://platform.openai.com) — ou nenhuma, se usar Ollama
- Opcional: [AbuseIPDB](https://www.abuseipdb.com/api) e [VirusTotal](https://developers.virustotal.com)

### 1. Configurar variáveis de ambiente

```bash
cp .env.example .env
```

Edite `.env` com as chaves desejadas:

```env
INTERNAL_API_SECRET=   # gere com: python -c "import secrets; print(secrets.token_hex(32))"
POSTGRES_PASSWORD=     # senha forte

LLM_PROVIDER=groq      # groq | openai | ollama
GROQ_API_KEY=gsk_...   # se LLM_PROVIDER=groq
OPENAI_API_KEY=sk-...  # se LLM_PROVIDER=openai

ABUSEIPDB_API_KEY=     # opcional
VIRUSTOTAL_API_KEY=    # opcional
```

### 2. Subir

```bash
docker-compose up --build
```

### 3. Acessar

| URL | Descrição |
|---|---|
| `http://localhost:8000` | Analisar logs |
| `http://localhost:8000/history.html` | Histórico de análises |
| `http://localhost:8000/dashboard.html` | Dashboard de métricas |
| `http://localhost:8000/settings.html` | Contexto organizacional |

---

## Modo 100% offline com Ollama

Rode a IA localmente — sem Groq, sem OpenAI, nenhum dado sai da rede.

**1.** No `.env`, defina:

```env
LLM_PROVIDER=ollama
OLLAMA_MODEL=qwen2.5:7b   # recomendado para JSON estruturado
```

**2.** Suba com o profile Ollama:

```bash
docker-compose --profile ollama up
```

O modelo é baixado automaticamente na primeira execução e fica em cache no volume `ollama_data`. Reinicializações seguintes são instantâneas.

### Modelos disponíveis

| Modelo | Tamanho | RAM mínima | Indicado para |
|---|---|---|---|
| `qwen2.5:7b` | 4.4 GB | 16 GB | **Padrão — melhor JSON estruturado** |
| `llama3.2:3b` | 2.0 GB | 8 GB | Máquinas com menos recursos |
| `llama3.1:8b` | 4.7 GB | 16 GB | Alternativa Llama |
| `mistral:7b` | 4.1 GB | 16 GB | Alternativa sólida |

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

Use o modo **Correlação de Logs** (toggle na página principal).

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
| `/api/analyze` | `POST` | Análise individual (síncrona) |
| `/api/analyze/stream` | `POST` | Análise com streaming SSE |
| `/api/analyze/batch` | `POST` | Lote de até 20 logs |
| `/api/analyze/correlate` | `POST` | Correlação de 2–10 logs |
| `/api/history` | `GET` | Histórico com filtros |
| `/api/analyses/{id}/diagnosis` | `PATCH` | Registrar FP / VP / Inconclusivo |
| `/api/org-config` | `GET` / `PUT` | Contexto organizacional |
| `/api/stats` | `GET` | Métricas do dashboard |
| `/health` | `GET` | Health check |

---

## Segurança

- Secrets via variáveis de ambiente — nunca hardcoded
- Input sanitizado: null bytes e tentativas de injection bloqueadas
- Rate limiting: 10 req/min por IP (configurável via `RATE_LIMIT_PER_MINUTE`)
- Logs de aplicação não registram o conteúdo dos logs do usuário
- `INTERNAL_API_SECRET` autentica comunicação entre containers
- Usuário não-root em todos os containers
- Rede Docker interna isola os serviços — apenas o gateway é exposto

---

## Estrutura do projeto

```
vestigo/
├── docker-compose.yml
├── .env.example
│
├── gateway/                     # Orquestrador + frontend
│   └── app/
│       ├── main.py              # Endpoints, SSE, rate limit
│       ├── database.py          # PostgreSQL — análises, diagnósticos, config
│       ├── webhook.py           # Alertas Slack / Teams
│       └── static/
│           ├── index.html       # Análise individual + Correlação
│           ├── history.html     # Histórico com busca e filtros
│           ├── dashboard.html   # Métricas com Chart.js
│           ├── settings.html    # Contexto organizacional
│           ├── app.js           # Lógica frontend
│           └── style.css        # Design system dark SOC
│
├── parser-service/              # Módulo 1 — Parse e mascaramento
│   └── app/
│       ├── detector.py          # Detecção de formato
│       ├── masker.py            # PII masking
│       ├── ioc_extractor.py     # Extração de IPs, hashes, domínios
│       └── parsers/             # Windows Event, Syslog, JSON, CEF
│
├── enricher-service/            # Módulo 2 — Enriquecimento
│   └── app/
│       ├── cache.py             # Cache TTL em memória
│       ├── severity.py          # Scoring de severidade
│       └── enrichers/
│           ├── abuseipdb.py     # Reputação de IPs
│           ├── virustotal.py    # Reputação de hashes e domínios
│           └── mitre_mapper.py  # Mapeamento ATT&CK
│
└── ai-service/                  # Módulo 3 — IA
    └── app/
        ├── llm_client.py        # Cliente Groq / OpenAI / Ollama
        └── prompts/
            ├── n1.py            # Prompt analista júnior (N1)
            ├── n2n3.py          # Prompt analista sênior (N2/N3)
            └── correlate.py     # Prompt correlação de eventos
```

---

## Stack

| Camada | Tecnologia |
|---|---|
| Backend | Python 3.12, FastAPI, asyncpg |
| Banco de dados | PostgreSQL 16 |
| LLM | Groq (LLaMA 3.3 70B) / OpenAI (GPT-4o) / Ollama (local) |
| Frontend | HTML, CSS, JavaScript vanilla, Chart.js |
| Infra | Docker Compose, slowapi, httpx |

---

## Licença

MIT — veja [LICENSE](LICENSE) para detalhes.

---

<div align="center">

*Vestigo · privacidade by design · o log bruto nunca chega à IA*

</div>
