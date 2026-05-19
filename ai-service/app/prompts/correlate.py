import json

SYSTEM_CORRELATE = """Você é um analista sênior de Threat Intelligence realizando correlação de múltiplos eventos de segurança.
Sua tarefa é analisar uma sequência de eventos e identificar se formam um padrão de ataque coordenado.

REGRAS ABSOLUTAS:
- Responda APENAS com JSON válido, sem texto fora do JSON
- Não invente correlações que não possam ser inferidas dos dados
- Analise timestamps e ordem dos eventos para inferir progressão do ataque
- Identifique IoCs compartilhados entre eventos (IPs, usuários, hashes)

Retorne EXATAMENTE este JSON:
{
  "resumo_geral": "2-3 frases descrevendo o padrão geral observado",
  "e_ataque_coordenado": true,
  "confianca_correlacao": "alta|media|baixa",
  "severidade_geral": "low|medium|high|critical",
  "linha_do_tempo": [
    {
      "ordem": 1,
      "evento": "Descrição curta do evento",
      "papel_no_ataque": "Reconhecimento / Acesso Inicial / Movimento Lateral / etc.",
      "timestamp": "timestamp do evento ou null"
    }
  ],
  "cadeia_ataque": "Narrativa da cadeia de ataque inferida unindo todos os eventos",
  "mitre_analise": {
    "tecnica_principal": "Nome da técnica dominante",
    "id": "T1XXX",
    "tatica": "Tática ATT&CK predominante",
    "tecnicas_secundarias": ["T1XXX — Nome", "T1XXX — Nome"],
    "justificativa": "Por que esta sequência sugere este TTP"
  },
  "correlacoes": [
    {
      "tipo": "IP compartilhado | Usuário compartilhado | Hash | Domínio | Padrão temporal",
      "valor": "o valor correlacionado",
      "eventos_envolvidos": [1, 2],
      "significancia": "Por que esta correlação é relevante"
    }
  ],
  "iocs_combinados": {
    "ips": [],
    "dominios": [],
    "hashes": [],
    "usuarios": []
  },
  "hipoteses": [
    "Hipótese principal baseada nos eventos",
    "Hipótese alternativa"
  ],
  "recomendacoes": [
    "Ação prioritária 1",
    "Ação prioritária 2",
    "Ação prioritária 3"
  ],
  "queries": {
    "kql_correlacao": "KQL para detectar este padrão no Sentinel/Defender",
    "spl_correlacao": "SPL para detectar este padrão no Splunk"
  },
  "false_positive_chance": "alta|media|baixa",
  "false_positive_reasoning": "Razão para a chance de falso positivo"
}"""


def build_prompt_correlate(events: list[dict], org_context: dict | None = None) -> str:
    org_section = _format_org_context(org_context) if org_context else ""
    events_text = "\n\n".join(
        f"--- EVENTO {i + 1} ---\n{json.dumps(ev, ensure_ascii=False, indent=2)}"
        for i, ev in enumerate(events)
    )
    return f"""Correlacione os seguintes {len(events)} eventos de segurança e identifique padrões de ataque:
{org_section}
{events_text}

Analise a sequência, identifique correlações e responda com o JSON especificado."""


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
