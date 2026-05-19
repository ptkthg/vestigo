import logging
import os
import httpx

from ..cache import get as cache_get, set as cache_set

logger = logging.getLogger("enricher.abuseipdb")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

_REPUTATION_MAP = {
    (0, 10): "limpa",
    (10, 50): "suspeita",
    (50, 101): "maliciosa",
}


def _score_to_reputation(score: int) -> str:
    for (low, high), label in _REPUTATION_MAP.items():
        if low <= score < high:
            return label
    return "desconhecida"


async def check_ip(ip: str) -> dict:
    """
    Consulta AbuseIPDB para o IP fornecido.
    Retorna apenas: reputacao, pais, asn, score — nunca o IP bruto.
    """
    if not _API_KEY:
        logger.warning("ABUSEIPDB_API_KEY não configurada, pulando enriquecimento de IP")
        return {"reputacao": "desconhecida", "pais": None, "asn": None, "score": 0}

    cached = cache_get(f"abuseipdb:{ip}")
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                ABUSEIPDB_URL,
                headers={"Key": _API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            result = {
                "reputacao": _score_to_reputation(score),
                "pais": data.get("countryCode"),
                "asn": data.get("isp"),
                "score": score,
            }
            cache_set(f"abuseipdb:{ip}", result)
            return result
    except httpx.HTTPStatusError as e:
        logger.warning("AbuseIPDB HTTP error: %s", e.response.status_code)
    except Exception as e:
        logger.warning("AbuseIPDB error: %s", type(e).__name__)

    return {"reputacao": "desconhecida", "pais": None, "asn": None, "score": 0}
