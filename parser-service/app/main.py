import logging
import os
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse

from .schemas import ParseRequest, EventoContext
from .detector import detect_format, LogFormat
from .masker import mask_pii
from .ioc_extractor import extract_iocs
from .parsers import (
    WindowsEventXMLParser,
    WindowsEventJSONParser,
    SyslogRFC3164Parser,
    SyslogRFC5424Parser,
    JSONGenericParser,
)

logger = logging.getLogger("parser-service")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

app = FastAPI(title="Vestigo Parser Service", version="1.0.0", docs_url=None, redoc_url=None)

INTERNAL_SECRET = os.getenv("INTERNAL_API_SECRET", "")

_PARSERS = {
    LogFormat.WINDOWS_EVENT_XML: WindowsEventXMLParser(),
    LogFormat.WINDOWS_EVENT_JSON: WindowsEventJSONParser(),
    LogFormat.SYSLOG_RFC3164: SyslogRFC3164Parser(),
    LogFormat.SYSLOG_RFC5424: SyslogRFC5424Parser(),
    LogFormat.JSON_GENERIC: JSONGenericParser(),
}


def _verify_internal(x_internal_secret: str = Header(default="")):
    if INTERNAL_SECRET and x_internal_secret != INTERNAL_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/health")
def health():
    return {"status": "ok", "service": "parser-service"}


@app.post("/parse", response_model=EventoContext)
def parse_log(
    body: ParseRequest,
    _: None = Depends(_verify_internal),
):
    raw = body.log_raw

    # Extrai IoCs do texto bruto ANTES do mascaramento
    iocs_raw = extract_iocs(raw)

    # Detecta formato
    fmt = detect_format(raw)
    logger.info("Format detected: %s (length=%d)", fmt, len(raw))

    # Mascarar PII antes de passar ao parser específico para formatos text-like
    # Para XML e JSON estruturado, o parser acessa os campos diretamente.
    # O mascaramento do texto bruto garante que nenhum trecho literal vaze no evento.
    masked_raw = mask_pii(raw)

    # Parse
    parser = _PARSERS.get(fmt)
    if parser:
        ctx = parser.parse(masked_raw if fmt in (
            LogFormat.SYSLOG_RFC3164, LogFormat.SYSLOG_RFC5424, LogFormat.FREE_TEXT
        ) else raw)
    else:
        # FREE_TEXT: parse mínimo
        ctx = EventoContext()
        ctx.formato = "free_text"
        ctx.fonte = "desconhecido"
        ctx.evento = masked_raw[:200]
        ctx.acao = "unknown"
        ctx.enriquecimento.score_confianca = "low"
        ctx.enriquecimento.justificativa_confianca = "Texto livre sem formato reconhecido"

    ctx.formato = fmt.value

    # Merge IoCs: IPs já foram inseridos pelo parser com contexto de interno/externo.
    # Os demais vêm do extrator de texto bruto.
    for h in iocs_raw["hashes"]:
        if h not in ctx.iocs.hashes:
            ctx.iocs.hashes.append(h)
    for d in iocs_raw["dominios"]:
        if d not in ctx.iocs.dominios:
            ctx.iocs.dominios.append(d)
    for u in iocs_raw["urls"]:
        if u not in ctx.iocs.urls:
            ctx.iocs.urls.append(u)
    if iocs_raw["emails"] and not ctx.iocs.emails:
        ctx.iocs.emails = iocs_raw["emails"]

    # IPs públicos do texto que o parser pode ter perdido
    for ip in iocs_raw["ips"]:
        if ip not in ctx.iocs.ips:
            ctx.iocs.ips.append(ip)
            if ctx.origem.tipo == "desconhecido":
                ctx.origem.tipo = "ip_externo"

    return ctx
