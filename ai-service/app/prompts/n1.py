SYSTEM_N1 = """Você é um assistente de segurança que ajuda analistas de nível 1 (N1) do SOC.
Sua missão: explicar o que aconteceu em linguagem simples e dizer o que fazer agora.

REGRAS ABSOLUTAS:
- Responda APENAS com JSON válido, sem texto fora do JSON
- Não invente informações que não estejam no contexto fornecido
- Use linguagem simples, sem jargão técnico excessivo
- Foque em ações práticas e imediatas

Retorne EXATAMENTE este JSON (sem campos extras, sem markdown):
{
  "resumo": "Explicação do que aconteceu em 2-3 frases simples",
  "o_que_significa": "O que isso pode indicar para a organização (1-2 frases)",
  "severidade_confirmada": "low|medium|high|critical",
  "urgencia": "imediata|alta|media|baixa",
  "acoes_imediatas": [
    "Ação clara e objetiva 1",
    "Ação clara e objetiva 2",
    "Ação clara e objetiva 3"
  ],
  "nao_faca": "O que NÃO fazer (1 frase)",
  "escalar": true,
  "motivo_escalonamento": "Por que escalar ou null se não precisa",
  "queries": {
    "kql": "Consulta KQL para buscar no Microsoft Sentinel/Defender",
    "spl": "Consulta SPL para buscar no Splunk"
  }
}"""


def build_prompt_n1(context: dict, org_context: dict | None = None) -> str:
    org_section = _format_org_context(org_context) if org_context else ""
    return f"""Analise este evento de segurança e responda em português:
{org_section}
CONTEXTO DO EVENTO:
{_format_context(context)}

Responda com o JSON especificado."""


def _format_org_context(org: dict) -> str:
    if not org:
        return ""
    lines = ["\nCONTEXTO ORGANIZACIONAL (use para reduzir falsos positivos):"]
    if org.get("org_name"):
        lines.append(f"Organização: {org['org_name']}")
    if org.get("internal_cidrs"):
        lines.append(f"CIDRs internos: {', '.join(org['internal_cidrs'])}")
    if org.get("trusted_ips"):
        lines.append(f"IPs confiáveis/autorizados: {', '.join(org['trusted_ips'])}")
    if org.get("authorized_tools"):
        lines.append(f"Ferramentas autorizadas: {', '.join(org['authorized_tools'])}")
    if org.get("privileged_users"):
        lines.append(f"Usuários/contas privilegiadas conhecidas: {', '.join(org['privileged_users'])}")
    if org.get("custom_context"):
        lines.append(f"Contexto adicional: {org['custom_context']}")
    lines.append("")
    return "\n".join(lines)


def _format_context(ctx: dict) -> str:
    lines = [
        f"Evento: {ctx.get('evento', 'desconhecido')}",
        f"Fonte: {ctx.get('fonte', 'desconhecida')}",
        f"Timestamp: {ctx.get('timestamp', 'desconhecido')}",
        f"Ação: {ctx.get('acao', 'desconhecida')}",
        f"Status: {ctx.get('status', 'desconhecido')}",
    ]
    origem = ctx.get("origem", {})
    if origem.get("tipo") != "desconhecido":
        lines.append(f"Origem: {origem.get('tipo')} | Reputação: {origem.get('reputacao')}")
        if origem.get("pais"):
            lines.append(f"País de origem: {origem.get('pais')}")

    destino = ctx.get("destino", {})
    if destino.get("servico"):
        porta = destino.get("porta")
        lines.append(f"Destino: {destino.get('servico')}" + (f" porta {porta}" if porta else ""))

    usuario = ctx.get("usuario", {})
    if usuario.get("tipo") != "desconhecido":
        lines.append(f"Usuário: tipo={usuario.get('tipo')} privilégio={usuario.get('privilegio')}")

    enr = ctx.get("enriquecimento", {})
    if enr.get("mitre_tecnica"):
        lines.append(f"Técnica MITRE: {enr.get('mitre_tecnica')} ({enr.get('mitre_id')})")
    if enr.get("cve"):
        lines.append(f"CVE identificado: {enr.get('cve')}")
    lines.append(f"Severidade calculada: {enr.get('severidade', 'medium')}")
    lines.append(f"Score de confiança: {enr.get('score_confianca', 'low')} — {enr.get('justificativa_confianca', '')}")

    iocs = ctx.get("iocs", {})
    if iocs.get("ips"):
        lines.append(f"IPs externos: {', '.join(iocs['ips'][:3])}")
    if iocs.get("hashes"):
        lines.append(f"Hashes: {', '.join(iocs['hashes'][:2])}")
    if iocs.get("dominios"):
        lines.append(f"Domínios: {', '.join(iocs['dominios'][:3])}")

    ext = ctx.get("contexto_externo", {})
    if ext.get("ips"):
        for ip_data in ext["ips"][:2]:
            rep = ip_data.get("reputacao", "desconhecida")
            score = ip_data.get("score", 0)
            lines.append(f"Reputação IP (AbuseIPDB): {rep} (score: {score}/100)")
    if ext.get("hashes"):
        for h in ext["hashes"][:1]:
            lines.append(f"Hash (VirusTotal): {h.get('veredicto', 'desconhecido')} — {h.get('malicious', 0)} detecções")

    return "\n".join(lines)
