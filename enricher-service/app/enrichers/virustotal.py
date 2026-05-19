import logging
import os
import httpx

from ..cache import get as cache_get, set as cache_set

logger = logging.getLogger("enricher.virustotal")

VT_BASE = "https://www.virustotal.com/api/v3"
_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


def _headers() -> dict:
    return {"x-apikey": _API_KEY}


def _malicious_summary(stats: dict) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "veredicto": (
            "malicioso" if malicious > 3
            else "suspeito" if malicious > 0 or suspicious > 3
            else "limpo"
        ),
    }


async def check_hash(file_hash: str) -> dict:
    """Consulta VirusTotal para um hash de arquivo."""
    if not _API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY não configurada")
        return {"hash": file_hash, "veredicto": "desconhecido"}

    cached = cache_get(f"vt:hash:{file_hash}")
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{VT_BASE}/files/{file_hash}",
                headers=_headers(),
            )
            if resp.status_code == 404:
                return {"hash": file_hash, "veredicto": "não encontrado"}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            summary = _malicious_summary(stats)
            result = {
                "hash": file_hash,
                "nome": data.get("meaningful_name") or data.get("name", ""),
                **summary,
            }
            cache_set(f"vt:hash:{file_hash}", result)
            return result
    except httpx.HTTPStatusError as e:
        logger.warning("VirusTotal hash HTTP error: %s", e.response.status_code)
    except Exception as e:
        logger.warning("VirusTotal hash error: %s", type(e).__name__)

    return {"hash": file_hash, "veredicto": "erro"}


async def check_domain(domain: str) -> dict:
    """Consulta VirusTotal para um domínio."""
    if not _API_KEY:
        return {"domain": domain, "veredicto": "desconhecido"}

    cached = cache_get(f"vt:domain:{domain}")
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{VT_BASE}/domains/{domain}",
                headers=_headers(),
            )
            if resp.status_code == 404:
                return {"domain": domain, "veredicto": "não encontrado"}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            summary = _malicious_summary(stats)
            result = {
                "domain": domain,
                "categorias": data.get("categories", {}),
                **summary,
            }
            cache_set(f"vt:domain:{domain}", result)
            return result
    except httpx.HTTPStatusError as e:
        logger.warning("VirusTotal domain HTTP error: %s", e.response.status_code)
    except Exception as e:
        logger.warning("VirusTotal domain error: %s", type(e).__name__)

    return {"domain": domain, "veredicto": "erro"}
