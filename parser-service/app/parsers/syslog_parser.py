import re
from datetime import datetime

from ..schemas import EventoContext, OrigemContext, DestinoContext, UsuarioContext
from .base import BaseParser

# RFC 3164: <PRI>Month DD HH:MM:SS hostname process[pid]: message
_RFC3164 = re.compile(
    r"^(?:<(?P<priority>\d{1,3})>)?"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?\s*:\s*"
    r"(?P<message>.+)$",
    re.IGNORECASE | re.DOTALL,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID [SD] MSG
_RFC5424 = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<rest>.+)$",
    re.DOTALL,
)

# Padrões comuns em mensagens syslog
_AUTH_FAIL = re.compile(
    r"(?:authentication failure|invalid user|failed password|"
    r"invalid password|login incorrect|logon failure)",
    re.IGNORECASE,
)
_AUTH_SUCCESS = re.compile(
    r"(?:accepted password|accepted publickey|session opened|logged in successfully)",
    re.IGNORECASE,
)
_SRC_IP = re.compile(r"(?:from|src|source)\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
_SRC_PORT = re.compile(r"port\s+(\d+)", re.IGNORECASE)
_USER_MATCH = re.compile(
    r"(?:user|invalid user|for user|for)\s+([A-Za-z0-9_\-\.@]+)", re.IGNORECASE
)

# Detecção de fonte por processo/appname
_SOURCE_MAP = {
    re.compile(r"sshd", re.I): ("auth.log", "SSH"),
    re.compile(r"sudo|su\b", re.I): ("auth.log", "sudo"),
    re.compile(r"nginx|apache|httpd", re.I): ("web", "HTTP"),
    re.compile(r"postfix|sendmail|dovecot", re.I): ("mail", "SMTP/IMAP"),
    re.compile(r"kernel|kern", re.I): ("kern.log", "Kernel"),
    re.compile(r"cron", re.I): ("cron", "Cron"),
    re.compile(r"systemd", re.I): ("systemd", "systemd"),
    re.compile(r"firewall|iptables|ufw|pf\b", re.I): ("firewall", "Firewall"),
    re.compile(r"snort|suricata", re.I): ("ids", "IDS/IPS"),
}


def _priority_to_severity(priority: int | None) -> str:
    if priority is None:
        return "medium"
    severity_num = priority & 0x7
    # syslog severity: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice, 6=info, 7=debug
    if severity_num <= 2:
        return "critical"
    if severity_num == 3:
        return "high"
    if severity_num == 4:
        return "medium"
    return "low"


def _detect_source(process: str) -> tuple[str, str]:
    for pattern, (fonte, servico) in _SOURCE_MAP.items():
        if pattern.search(process):
            return fonte, servico
    return "syslog", process


class SyslogRFC3164Parser(BaseParser):
    def parse(self, raw: str) -> EventoContext:
        ctx = EventoContext()
        ctx.formato = "syslog_rfc3164"

        m = _RFC3164.match(raw.strip())
        if not m:
            ctx.evento = "Syslog RFC 3164 (parse parcial)"
            ctx.enriquecimento.score_confianca = "low"
            ctx.enriquecimento.justificativa_confianca = "Formato detectado mas parse incompleto"
            return ctx

        priority = int(m.group("priority")) if m.group("priority") else None
        process = m.group("process") or ""
        message = m.group("message") or ""
        hostname = m.group("host") or ""

        # Timestamp parcial (sem ano)
        year = datetime.now().year
        ctx.timestamp = f"{year} {m.group('month')} {m.group('day')} {m.group('time')}"

        fonte, servico = _detect_source(process)
        ctx.fonte = fonte
        ctx.destino.tipo = "servidor"
        ctx.destino.servico = servico

        if hostname and hostname != "-":
            ctx.destino.tipo = "servidor"

        # IP de origem na mensagem
        ip_m = _SRC_IP.search(message)
        if ip_m:
            src_ip = ip_m.group(1)
            from ..masker import is_internal_ip
            if is_internal_ip(src_ip):
                ctx.origem.tipo = "ip_interno"
            else:
                ctx.origem.tipo = "ip_externo"
                ctx.iocs.ips.append(src_ip)

        port_m = _SRC_PORT.search(message)
        if port_m:
            ctx.destino.porta = int(port_m.group(1))

        # Usuário
        user_m = _USER_MATCH.search(message)
        if user_m:
            ctx.usuario.tipo = "humano"

        # Evento e status
        if _AUTH_FAIL.search(message):
            ctx.evento = f"Falha de autenticação ({servico})"
            ctx.acao = "auth_failure"
            ctx.status = "falha"
            ctx.enriquecimento.severidade = "medium"
        elif _AUTH_SUCCESS.search(message):
            ctx.evento = f"Autenticação bem-sucedida ({servico})"
            ctx.acao = "auth_success"
            ctx.status = "sucesso"
            ctx.enriquecimento.severidade = "low"
        else:
            ctx.evento = f"Evento {servico}: {message[:80]}"
            ctx.acao = "syslog_event"
            ctx.status = "desconhecido"
            ctx.enriquecimento.severidade = _priority_to_severity(priority)

        ctx.enriquecimento.score_confianca = "medium"
        ctx.enriquecimento.justificativa_confianca = f"Syslog RFC 3164 — processo: {process}"
        return ctx


class SyslogRFC5424Parser(BaseParser):
    def parse(self, raw: str) -> EventoContext:
        ctx = EventoContext()
        ctx.formato = "syslog_rfc5424"

        m = _RFC5424.match(raw.strip())
        if not m:
            ctx.evento = "Syslog RFC 5424 (parse parcial)"
            ctx.enriquecimento.score_confianca = "low"
            ctx.enriquecimento.justificativa_confianca = "Formato detectado mas parse incompleto"
            return ctx

        priority = int(m.group("priority"))
        appname = m.group("appname") or "-"
        hostname = m.group("hostname") or "-"
        ctx.timestamp = m.group("timestamp") or ""

        rest = m.group("rest") or ""
        # Structured data + message
        message = rest
        if rest.startswith("["):
            sd_end = rest.find("] ")
            if sd_end != -1:
                message = rest[sd_end + 2:]

        fonte, servico = _detect_source(appname)
        ctx.fonte = fonte
        ctx.destino.tipo = "servidor"
        ctx.destino.servico = servico if appname == "-" else appname

        ip_m = _SRC_IP.search(message)
        if ip_m:
            src_ip = ip_m.group(1)
            from ..masker import is_internal_ip
            if is_internal_ip(src_ip):
                ctx.origem.tipo = "ip_interno"
            else:
                ctx.origem.tipo = "ip_externo"
                ctx.iocs.ips.append(src_ip)

        if _AUTH_FAIL.search(message):
            ctx.evento = f"Falha de autenticação ({servico})"
            ctx.acao = "auth_failure"
            ctx.status = "falha"
        elif _AUTH_SUCCESS.search(message):
            ctx.evento = f"Autenticação bem-sucedida ({servico})"
            ctx.acao = "auth_success"
            ctx.status = "sucesso"
        else:
            ctx.evento = f"Evento {servico}: {message[:80]}"
            ctx.acao = "syslog_event"
            ctx.status = "desconhecido"

        ctx.enriquecimento.severidade = _priority_to_severity(priority)
        ctx.enriquecimento.score_confianca = "medium"
        ctx.enriquecimento.justificativa_confianca = f"Syslog RFC 5424 — app: {appname}"
        return ctx
