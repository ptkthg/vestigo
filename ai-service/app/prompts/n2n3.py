SYSTEM_N2N3 = """Você é um analista sênior de ameaças (Threat Intelligence / DFIR) respondendo a um incidente.
Analise o contexto de segurança fornecido com profundidade técnica.

REGRAS ABSOLUTAS:
- Responda APENAS com JSON válido, sem texto fora do JSON
- Não invente TTPs ou IoCs que não possam ser inferidos do contexto
- Seja específico e acionável, não genérico
- As queries devem ser funcionais e baseadas nos dados do contexto

Retorne EXATAMENTE este JSON:
{
  "resumo_executivo": "2 frases para gestão: impacto de negócio e risco",
  "severidade_confirmada": "low|medium|high|critical",
  "cadeia_ataque": "Descrição da cadeia de ataque inferida (Kill Chain / ATT&CK)",
  "hipoteses": [
    "Hipótese 1 com base nas evidências",
    "Hipótese 2 alternativa"
  ],
  "mitre_analise": {
    "tecnica_principal": "Nome da técnica",
    "id": "T1XXX",
    "sub_tecnicas_possiveis": ["T1XXX.001"],
    "tatica": "Tática MITRE correspondente",
    "justificativa": "Por que esta técnica foi identificada"
  },
  "pivos": [
    "Próximo passo de investigação 1",
    "Próximo passo de investigação 2",
    "Próximo passo de investigação 3"
  ],
  "iocs_prioritarios": [
    "IoC 1 para bloquear/monitorar",
    "IoC 2"
  ],
  "recomendacoes_tecnicas": [
    "Ação técnica detalhada 1",
    "Ação técnica detalhada 2",
    "Ação técnica detalhada 3"
  ],
  "queries": {
    "kql_detection": "KQL para detecção no Sentinel/Defender",
    "kql_hunting": "KQL de threat hunting relacionado",
    "spl_detection": "SPL para detecção no Splunk",
    "spl_hunting": "SPL de threat hunting relacionado"
  },
  "containment": "Ação de contenção imediata recomendada",
  "false_positive_chance": "alta|media|baixa",
  "false_positive_reasoning": "Por que pode ou não ser falso positivo"
}"""


def build_prompt_n2n3(context: dict, org_context: dict | None = None) -> str:
    org_section = _format_org_context(org_context) if org_context else ""
    return f"""Realize análise forense/threat intelligence do seguinte evento de segurança:
{org_section}
CONTEXTO COMPLETO:
{_format_context_technical(context)}

Responda com o JSON especificado."""


def _format_org_context(org: dict) -> str:
    if not org:
        return ""
    lines = ["\nCONTEXTO ORGANIZACIONAL (use para calibrar severidade e falsos positivos):"]
    if org.get("org_name"):
        lines.append(f"Organização: {org['org_name']}")
    if org.get("internal_cidrs"):
        lines.append(f"CIDRs internos: {', '.join(org['internal_cidrs'])}")
    if org.get("trusted_ips"):
        lines.append(f"IPs confiáveis: {', '.join(org['trusted_ips'])}")
    if org.get("authorized_tools"):
        lines.append(f"Ferramentas autorizadas: {', '.join(org['authorized_tools'])}")
    if org.get("privileged_users"):
        lines.append(f"Contas privilegiadas conhecidas: {', '.join(org['privileged_users'])}")
    if org.get("custom_context"):
        lines.append(f"Contexto adicional: {org['custom_context']}")
    lines.append("")
    return "\n".join(lines)


def _format_context_technical(ctx: dict) -> str:
    import json
    # Para N2/N3, entregamos o contexto mais completo possível
    # mas ainda sem dados brutos do log original
    safe_ctx = {
        "evento": ctx.get("evento"),
        "fonte": ctx.get("fonte"),
        "formato": ctx.get("formato"),
        "timestamp": ctx.get("timestamp"),
        "acao": ctx.get("acao"),
        "status": ctx.get("status"),
        "origem": ctx.get("origem"),
        "destino": ctx.get("destino"),
        "usuario": ctx.get("usuario"),
        "iocs": ctx.get("iocs"),
        "enriquecimento": ctx.get("enriquecimento"),
        "contexto_externo": ctx.get("contexto_externo"),
    }
    return json.dumps(safe_ctx, ensure_ascii=False, indent=2)
