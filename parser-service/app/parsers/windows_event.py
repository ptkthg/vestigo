import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from ..schemas import (
    EventoContext, OrigemContext, DestinoContext,
    UsuarioContext, Enriquecimento,
)
from .base import BaseParser

# Mapeamento de EventID → descrição e severidade
_EVENT_MAP: dict[int, tuple[str, str, str]] = {
    # (evento, acao, severidade)
    4624: ("Logon bem-sucedido", "logon", "low"),
    4625: ("Falha de logon", "logon_failure", "medium"),
    4648: ("Logon com credenciais explícitas", "logon_explicit", "medium"),
    4672: ("Privilégios especiais atribuídos", "privilege_assigned", "medium"),
    4688: ("Processo criado", "process_creation", "low"),
    4698: ("Tarefa agendada criada", "scheduled_task_create", "high"),
    4699: ("Tarefa agendada deletada", "scheduled_task_delete", "medium"),
    4700: ("Tarefa agendada habilitada", "scheduled_task_enable", "high"),
    4702: ("Tarefa agendada modificada", "scheduled_task_modify", "high"),
    4720: ("Conta de usuário criada", "account_create", "medium"),
    4726: ("Conta de usuário deletada", "account_delete", "medium"),
    4732: ("Membro adicionado ao grupo", "group_membership_change", "medium"),
    4740: ("Conta bloqueada", "account_lockout", "high"),
    4756: ("Membro adicionado a grupo universal", "group_membership_change", "medium"),
    4776: ("Validação NTLM", "ntlm_auth", "medium"),
    7045: ("Serviço instalado", "service_install", "high"),
    1102: ("Log de auditoria limpo", "audit_log_cleared", "critical"),
    4657: ("Valor de registro modificado", "registry_modify", "medium"),
    4663: ("Acesso a objeto", "object_access", "low"),
    4768: ("Solicitação de TGT Kerberos", "kerberos_tgt", "low"),
    4769: ("Solicitação de ticket de serviço Kerberos", "kerberos_service", "low"),
    4771: ("Pré-autenticação Kerberos falhou", "kerberos_preauth_fail", "medium"),
}

_LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

_NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _find_ns(elem: ET.Element, tag: str) -> ET.Element | None:
    result = elem.find(f"w:{tag}", _NS)
    if result is None:
        result = elem.find(tag)
    return result


def _findall_data(system_data: ET.Element) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in system_data:
        name = item.get("Name") or item.tag.split("}")[-1]
        result[name] = (item.text or "").strip()
    return result


class WindowsEventXMLParser(BaseParser):
    def parse(self, raw: str) -> EventoContext:
        ctx = EventoContext()
        ctx.formato = "windows_event_xml"
        ctx.fonte = "Windows Security"

        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            ctx.evento = "Windows Event (XML inválido)"
            return ctx

        system = _find_ns(root, "System")
        event_data = _find_ns(root, "EventData")

        if system is None:
            ctx.evento = "Windows Event (System ausente)"
            return ctx

        # EventID
        event_id_elem = _find_ns(system, "EventID")
        event_id = int(event_id_elem.text or 0) if event_id_elem is not None else 0

        # Timestamp
        time_created = _find_ns(system, "TimeCreated")
        if time_created is not None:
            ctx.timestamp = time_created.get("SystemTime", "")

        # Computer
        computer = _find_ns(system, "Computer")
        if computer is not None and computer.text:
            ctx.destino.tipo = "servidor_windows"
            ctx.destino.servico = computer.text.strip()

        # Channel
        channel = _find_ns(system, "Channel")
        if channel is not None and channel.text:
            ctx.fonte = channel.text.strip()

        # EventData fields
        edata: dict[str, str] = {}
        if event_data is not None:
            edata = _findall_data(event_data)

        # IP de origem
        src_ip = edata.get("IpAddress") or edata.get("SourceAddress") or ""
        if src_ip and src_ip not in ("-", "::1", "127.0.0.1"):
            from ..masker import is_internal_ip
            if is_internal_ip(src_ip):
                ctx.origem.tipo = "ip_interno"
            else:
                ctx.origem.tipo = "ip_externo"
                if src_ip not in ctx.iocs.ips:
                    ctx.iocs.ips.append(src_ip)

        src_port = edata.get("IpPort") or edata.get("SourcePort") or ""
        if src_port and src_port.isdigit():
            ctx.destino.porta = int(src_port)

        # Usuário
        subject_user = edata.get("SubjectUserName") or edata.get("TargetUserName") or ""
        subject_logon = edata.get("SubjectLogonId") or ""
        if subject_user and subject_user not in ("-", "SYSTEM"):
            privs = edata.get("PrivilegeList") or ""
            ctx.usuario.tipo = "humano" if "@" not in subject_user else "conta_servico"
            if "SeDebugPrivilege" in privs or "SeTcbPrivilege" in privs:
                ctx.usuario.privilegio = "admin"
            elif subject_user.endswith("$"):
                ctx.usuario.tipo = "conta_servico"
            else:
                ctx.usuario.privilegio = "usuario"

        # Descrição por EventID
        meta = _EVENT_MAP.get(event_id)
        if meta:
            ctx.evento = meta[0]
            ctx.acao = meta[1]
            ctx.enriquecimento.severidade = meta[2]
        else:
            ctx.evento = f"Windows Event ID {event_id}"
            ctx.acao = "unknown"

        # Status: logon failures
        status_code = edata.get("Status") or edata.get("FailureReason") or ""
        if event_id == 4625 or "fail" in ctx.acao.lower():
            ctx.status = "falha"
        elif event_id in (4624, 4672):
            ctx.status = "sucesso"
        elif event_id in (1102, 7045, 4698, 4700):
            ctx.status = "sucesso"
        else:
            ctx.status = "desconhecido"

        # Logon type
        logon_type = edata.get("LogonType", "")
        if logon_type:
            logon_desc = _LOGON_TYPES.get(logon_type, logon_type)
            ctx.evento += f" ({logon_desc})"

        # Process info
        proc_name = edata.get("NewProcessName") or edata.get("ProcessName") or ""
        if proc_name:
            ctx.acao = f"process_creation:{proc_name.split('\\')[-1]}"

        ctx.enriquecimento.score_confianca = "high"
        ctx.enriquecimento.justificativa_confianca = f"Formato estruturado Windows Event ID {event_id}"
        return ctx


class WindowsEventJSONParser(BaseParser):
    def parse(self, raw: str) -> EventoContext:
        ctx = EventoContext()
        ctx.formato = "windows_event_json"
        ctx.fonte = "Windows Security"

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            ctx.evento = "Windows Event JSON (inválido)"
            return ctx

        event_id = int(data.get("EventID", 0))
        ctx.timestamp = data.get("TimeCreated", "")
        ctx.destino.tipo = "servidor_windows"
        ctx.destino.servico = data.get("Computer", "")

        meta = _EVENT_MAP.get(event_id)
        if meta:
            ctx.evento = meta[0]
            ctx.acao = meta[1]
            ctx.enriquecimento.severidade = meta[2]
        else:
            ctx.evento = f"Windows Event ID {event_id}"
            ctx.acao = "unknown"

        ctx.enriquecimento.score_confianca = "medium"
        ctx.enriquecimento.justificativa_confianca = f"Windows Event JSON ID {event_id}"
        return ctx
