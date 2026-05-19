import json
from ..schemas import EventoContext, OrigemContext, DestinoContext, UsuarioContext
from .base import BaseParser
from ..masker import is_internal_ip

# Mapeamento de chaves comuns → campos do schema
_TIMESTAMP_KEYS = ["timestamp", "time", "datetime", "@timestamp", "event_time", "eventTime", "created_at"]
_EVENT_KEYS = ["event", "event_type", "eventType", "action", "type", "message", "msg", "description"]
_SRC_IP_KEYS = ["src_ip", "srcip", "source_ip", "sourceIp", "src", "client_ip", "clientIp", "remote_addr"]
_DST_IP_KEYS = ["dst_ip", "dstip", "dest_ip", "destIp", "destination_ip", "server_ip"]
_SRC_PORT_KEYS = ["src_port", "srcport", "source_port", "sourcePort"]
_DST_PORT_KEYS = ["dst_port", "dstport", "dest_port", "destPort", "port"]
_USER_KEYS = ["user", "username", "user_name", "userName", "account", "subject_user", "actor"]
_STATUS_KEYS = ["status", "result", "outcome", "action_result"]
_HASH_KEYS = ["hash", "md5", "sha1", "sha256", "sha2", "file_hash", "fileHash"]
_SEVERITY_KEYS = ["severity", "level", "priority", "risk"]

_STATUS_MAP = {
    "success": "sucesso", "succeeded": "sucesso", "allowed": "sucesso",
    "accept": "sucesso", "ok": "sucesso", "200": "sucesso",
    "fail": "falha", "failed": "falha", "failure": "falha",
    "denied": "falha", "reject": "falha", "error": "falha",
    "blocked": "bloqueado", "block": "bloqueado", "drop": "bloqueado",
}

_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "low", "informational": "low",
    "warning": "medium", "warn": "medium", "error": "high",
    "emergency": "critical", "alert": "critical",
}


def _get_first(data: dict, keys: list[str], default=None):
    for k in keys:
        if k in data:
            return data[k]
        # case-insensitive fallback
        for dk in data:
            if dk.lower() == k.lower():
                return data[dk]
    return default


class JSONGenericParser(BaseParser):
    def parse(self, raw: str) -> EventoContext:
        ctx = EventoContext()
        ctx.formato = "json_generic"

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            ctx.evento = "JSON (inválido)"
            return ctx

        if not isinstance(data, dict):
            ctx.evento = "JSON (estrutura não mapeável)"
            return ctx

        # Timestamp
        ts = _get_first(data, _TIMESTAMP_KEYS)
        if ts:
            ctx.timestamp = str(ts)

        # Evento
        event_val = _get_first(data, _EVENT_KEYS)
        if event_val:
            ctx.evento = str(event_val)[:200]
            ctx.acao = str(event_val)[:50].lower().replace(" ", "_")

        # Fonte
        fonte = data.get("source") or data.get("product") or data.get("vendor") or ""
        ctx.fonte = str(fonte)[:50] if fonte else "json_generico"

        # IP de origem
        src_ip = _get_first(data, _SRC_IP_KEYS)
        if src_ip and isinstance(src_ip, str):
            if is_internal_ip(src_ip):
                ctx.origem.tipo = "ip_interno"
            else:
                ctx.origem.tipo = "ip_externo"
                ctx.iocs.ips.append(src_ip)

        # IP de destino
        dst_ip = _get_first(data, _DST_IP_KEYS)
        if dst_ip and isinstance(dst_ip, str):
            ctx.destino.tipo = "ip_externo" if not is_internal_ip(dst_ip) else "ip_interno"

        # Porta
        dst_port = _get_first(data, _DST_PORT_KEYS)
        if dst_port and str(dst_port).isdigit():
            ctx.destino.porta = int(dst_port)

        # Usuário
        user = _get_first(data, _USER_KEYS)
        if user:
            ctx.usuario.tipo = "humano"

        # Status
        status_raw = _get_first(data, _STATUS_KEYS)
        if status_raw:
            ctx.status = _STATUS_MAP.get(str(status_raw).lower(), "desconhecido")

        # Hashes
        for key in _HASH_KEYS:
            val = data.get(key)
            if val and isinstance(val, str) and len(val) in (32, 40, 64):
                ctx.iocs.hashes.append(val)

        # Severidade
        sev_raw = _get_first(data, _SEVERITY_KEYS)
        if sev_raw:
            ctx.enriquecimento.severidade = _SEVERITY_MAP.get(
                str(sev_raw).lower(), "medium"
            )

        ctx.enriquecimento.score_confianca = "medium"
        ctx.enriquecimento.justificativa_confianca = (
            f"JSON genérico — {len(data)} campos detectados"
        )
        return ctx
