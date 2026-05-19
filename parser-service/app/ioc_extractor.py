import re

# IPs públicos (exclui RFC-1918, loopback, link-local)
_PUBLIC_IP = re.compile(
    r"(?<!\d)"
    r"(?!"
    r"(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|0\.0\.0\.0"
    r"|255\.255\.255\.255"
    r")"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?!\d)"
)

# Domínios (TLDs comuns — lista intencionalmnete restrita para reduzir falsos positivos)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|edu|gov|io|cc|biz|info|co|uk|de|br|ru|cn|xyz|top"
    r"|site|online|club|tk|ml|ga|cf|gq|pw|icu|vip|win|bid|loan"
    r"|stream|download|click|link|app|dev|tech)\b",
    re.IGNORECASE,
)

_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

_URL = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]{4,2048}", re.IGNORECASE)

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        low = item.lower()
        if low not in seen:
            seen.add(low)
            result.append(item)
    return result


def extract_iocs(text: str) -> dict:
    """Extrai IoCs do texto RAW antes do mascaramento de PII."""
    hashes = _dedupe(_SHA256.findall(text) + _SHA1.findall(text) + _MD5.findall(text))

    # Evita falsos positivos: ignora hashes que parecem UUIDs ou IDs comuns
    hashes = [h for h in hashes if len(set(h)) > 4]

    # Emails encontrados são listados como "[EMAIL]" — valor real não sai do parser
    emails_found = _EMAIL.findall(text)

    return {
        "ips": _dedupe(_PUBLIC_IP.findall(text)),
        "dominios": _dedupe(_DOMAIN.findall(text)),
        "hashes": hashes,
        "urls": _dedupe(_URL.findall(text)),
        "emails": ["[EMAIL]"] * len(emails_found) if emails_found else [],
    }
