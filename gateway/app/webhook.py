import logging
import os
import httpx

logger = logging.getLogger("gateway.webhook")

WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_MIN_SEV = os.getenv("WEBHOOK_MIN_SEVERITY", "high").lower()


def _should_fire(severidade: str | None) -> bool:
    if not WEBHOOK_URL or not severidade:
        return False
    return _SEV_ORDER.get(severidade.lower(), -1) >= _SEV_ORDER.get(_MIN_SEV, 2)


def _build_payload(analysis: dict, analysis_id: int | None) -> dict:
    res = analysis.get("resultado", {})
    severidade = analysis.get("severidade", "unknown").upper()
    mitre_id = analysis.get("mitre_id", "")
    mitre_tecnica = analysis.get("mitre_tecnica", "")
    resumo = res.get("resumo") or res.get("resumo_executivo", "")
    iocs = analysis.get("iocs", {})
    ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))

    sev_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(severidade, "⚪")

    text = (
        f"{sev_emoji} *Vestigo — Alerta {severidade}*\n"
        f"*MITRE:* {mitre_id} — {mitre_tecnica}\n"
        f"*Resumo:* {resumo[:300]}\n"
        f"*IoCs:* {ioc_count} indicadores identificados"
    )
    if analysis_id:
        text += f"\n*ID da análise:* #{analysis_id}"

    # Formato compatível com Slack (text) e Teams (text simples)
    return {
        "text": text,
        "username": "Vestigo SOC",
        "icon_emoji": ":mag:",
        # Teams / adaptive card fallback
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"Vestigo — Alerta {severidade}",
        "themeColor": {"CRITICAL": "FF0000", "HIGH": "FF8C00", "MEDIUM": "FFD700", "LOW": "00C853"}.get(severidade, "0078D7"),
        "sections": [{"text": text.replace("*", "**")}],
    }


async def fire_webhook(analysis: dict, analysis_id: int | None) -> None:
    severidade = analysis.get("severidade")
    if not _should_fire(severidade):
        return

    payload = _build_payload(analysis, analysis_id)
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(WEBHOOK_URL, json=payload)
            if resp.status_code >= 400:
                logger.warning("Webhook returned %s", resp.status_code)
            else:
                logger.info("Webhook fired for severity=%s", severidade)
    except Exception as e:
        logger.warning("Webhook failed: %s", type(e).__name__)
