import asyncio
import logging
import os

from fastapi import FastAPI, HTTPException, Header, Depends

from .schemas import EventoContext
from .enrichers import check_ip, check_hash, check_domain, map_mitre
from .severity import calculate_severity, calculate_confidence

logger = logging.getLogger("enricher-service")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

app = FastAPI(title="Vestigo Enricher Service", version="1.0.0", docs_url=None, redoc_url=None)

INTERNAL_SECRET = os.getenv("INTERNAL_API_SECRET", "")

# Limites de IoCs consultados para não estourar rate limits de API gratuita
_MAX_IPS = 3
_MAX_HASHES = 2
_MAX_DOMAINS = 2


def _verify_internal(x_internal_secret: str = Header(default="")):
    if INTERNAL_SECRET and x_internal_secret != INTERNAL_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/health")
def health():
    return {"status": "ok", "service": "enricher-service"}


@app.post("/enrich", response_model=EventoContext)
async def enrich(
    ctx: EventoContext,
    _: None = Depends(_verify_internal),
):
    external_data: dict = {}
    external_enriched = False

    # ── Enriquecimento de IPs (apenas externos, máx _MAX_IPS) ──────────────────
    external_ips = [ip for ip in ctx.iocs.ips if ip and "[" not in ip][:_MAX_IPS]
    if external_ips:
        ip_results = await asyncio.gather(
            *[check_ip(ip) for ip in external_ips],
            return_exceptions=True,
        )
        external_data["ips"] = []
        for ip, result in zip(external_ips, ip_results):
            if isinstance(result, Exception):
                logger.warning("IP enrichment failed for redacted IP: %s", type(result).__name__)
                continue
            external_data["ips"].append(result)
            external_enriched = True

        # Atualiza reputação de origem com o primeiro IP
        if external_data["ips"]:
            first = external_data["ips"][0]
            ctx.origem.reputacao = first.get("reputacao", "desconhecida")
            ctx.origem.pais = first.get("pais")
            ctx.origem.asn = first.get("asn")

    # ── Enriquecimento de hashes ───────────────────────────────────────────────
    hashes_to_check = [h for h in ctx.iocs.hashes if h and "[" not in h][:_MAX_HASHES]
    if hashes_to_check:
        hash_results = await asyncio.gather(
            *[check_hash(h) for h in hashes_to_check],
            return_exceptions=True,
        )
        external_data["hashes"] = [
            r for r in hash_results if not isinstance(r, Exception)
        ]
        if external_data["hashes"]:
            external_enriched = True

    # ── Enriquecimento de domínios ─────────────────────────────────────────────
    domains_to_check = [d for d in ctx.iocs.dominios if d and "[" not in d][:_MAX_DOMAINS]
    if domains_to_check:
        domain_results = await asyncio.gather(
            *[check_domain(d) for d in domains_to_check],
            return_exceptions=True,
        )
        external_data["dominios"] = [
            r for r in domain_results if not isinstance(r, Exception)
        ]
        if external_data["dominios"]:
            external_enriched = True

    # ── MITRE mapping ──────────────────────────────────────────────────────────
    mitre_id, mitre_tecnica = map_mitre(
        ctx.evento,
        ctx.acao,
        contexto=str(external_data),
    )
    if mitre_id:
        ctx.enriquecimento.mitre_id = mitre_id
        ctx.enriquecimento.mitre_tecnica = mitre_tecnica

    # ── CVE detection ─────────────────────────────────────────────────────────
    import re
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", ctx.evento + " " + ctx.acao, re.IGNORECASE)
    if cve_match:
        ctx.enriquecimento.cve = cve_match.group(0).upper()

    # ── Severidade e confiança ─────────────────────────────────────────────────
    ctx.enriquecimento.severidade = calculate_severity(ctx, external_data)
    score, justif = calculate_confidence(ctx, external_enriched)
    ctx.enriquecimento.score_confianca = score
    ctx.enriquecimento.justificativa_confianca = justif

    ctx.contexto_externo = external_data
    logger.info(
        "Enrichment complete: severity=%s confidence=%s mitre=%s",
        ctx.enriquecimento.severidade,
        ctx.enriquecimento.score_confianca,
        ctx.enriquecimento.mitre_id,
    )
    return ctx
