from .schemas import EventoContext

# Fatores que elevam a severidade
_ESCALATE_CRITICAL = [
    "audit_log_cleared", "log cleared", "1102",
    "ransomware", "data exfil", "T1486", "T1048",
    "credential dump", "T1003",
]
_ESCALATE_HIGH = [
    "scheduled_task", "service_install", "T1053", "T1543",
    "account_lockout", "4740", "brute force", "T1110",
    "lateral movement", "T1021",
]

_SEV_ORDER = ["low", "medium", "high", "critical"]


def _max_sev(a: str, b: str) -> str:
    return _SEV_ORDER[max(_SEV_ORDER.index(a), _SEV_ORDER.index(b))]


def calculate_severity(ctx: EventoContext, external_data: dict) -> str:
    base = ctx.enriquecimento.severidade

    combo = f"{ctx.evento} {ctx.acao} {ctx.enriquecimento.mitre_id or ''}".lower()

    for trigger in _ESCALATE_CRITICAL:
        if trigger.lower() in combo:
            base = _max_sev(base, "critical")
            break

    for trigger in _ESCALATE_HIGH:
        if trigger.lower() in combo:
            base = _max_sev(base, "high")
            break

    # IP com reputação maliciosa
    ip_data = external_data.get("ips", [])
    for entry in ip_data:
        rep = entry.get("reputacao", "desconhecida")
        if rep == "maliciosa":
            base = _max_sev(base, "high")
        elif rep == "suspeita":
            base = _max_sev(base, "medium")

    # Hash malicioso
    hash_data = external_data.get("hashes", [])
    for entry in hash_data:
        if entry.get("veredicto") == "malicioso":
            base = _max_sev(base, "critical")

    # Status falha
    if ctx.status == "falha" and base == "low":
        base = "medium"

    return base


def calculate_confidence(ctx: EventoContext, external_enriched: bool) -> tuple[str, str]:
    """Retorna (score_confianca, justificativa)."""
    score = ctx.enriquecimento.score_confianca
    reasons = []

    if ctx.timestamp:
        reasons.append("timestamp presente")
    if ctx.origem.tipo != "desconhecido":
        reasons.append("origem identificada")
    if ctx.usuario.tipo != "desconhecido":
        reasons.append("usuário identificado")
    if ctx.enriquecimento.mitre_id:
        reasons.append(f"MITRE mapeado ({ctx.enriquecimento.mitre_id})")
    if external_enriched:
        reasons.append("enriquecimento externo realizado")

    count = len(reasons)
    if count >= 4:
        score = "high"
    elif count >= 2:
        score = "medium"
    else:
        score = "low"

    return score, ", ".join(reasons) if reasons else "dados insuficientes"
