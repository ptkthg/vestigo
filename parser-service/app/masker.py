import re

# ─── Padrões de PII ───────────────────────────────────────────────────────────

_PRIVATE_IP = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# password=VALUE  /  passwd: VALUE  /  senha=VALUE  etc.
_PASSWORD = re.compile(
    r"((?:password|passwd|pwd|senha|pass)\s*[=:]\s*)(\S+)",
    re.IGNORECASE,
)

# token=VALUE  /  api_key=VALUE  /  Bearer VALUE  etc.
_TOKEN_KV = re.compile(
    r"((?:token|api[_-]?key|apikey|secret|auth_token|access_token|x-api-key)\s*[=:]\s*)([A-Za-z0-9\-_\.+/]{8,})",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(Bearer\s+)([A-Za-z0-9\-_\.+/]{8,})", re.IGNORECASE)

# CPF: 000.000.000-00 ou 00000000000
_CPF = re.compile(r"\b\d{3}[\.\s]?\d{3}[\.\s]?\d{3}[\-\.]?\d{2}\b")

# Email
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def mask_pii(text: str) -> str:
    """
    Aplica mascaramento de PII em ordem de precedência.
    Senhas → Tokens → CPF → Emails → IPs internos.
    Hashes (hex 32/40/64 chars) são preservados intencionalmente como IoCs.
    """
    text = _PASSWORD.sub(lambda m: m.group(1) + "[CREDENTIAL]", text)
    text = _TOKEN_KV.sub(lambda m: m.group(1) + "[TOKEN]", text)
    text = _BEARER.sub(lambda m: m.group(1) + "[TOKEN]", text)
    text = _CPF.sub("[PII]", text)
    text = _EMAIL.sub("[EMAIL]", text)
    text = _PRIVATE_IP.sub("[IP_INTERNO]", text)
    return text


def is_internal_ip(ip: str) -> bool:
    return bool(_PRIVATE_IP.fullmatch(ip.strip()))
