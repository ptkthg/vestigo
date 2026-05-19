import re
from typing import Optional

# (mitre_id, mitre_tecnica, peso_severidade) ordenados do mais específico para o mais genérico
_RULES: list[tuple[str, str, int, list[str]]] = [
    # id, tecnica, peso (+1 por match), keywords
    ("T1003", "OS Credential Dumping", 3, [
        "lsass", "mimikatz", "credential dump", "ntds.dit", "secretsdump",
        "sam database", "wce.exe", "procdump",
    ]),
    ("T1110", "Brute Force", 2, [
        "brute force", "multiple failed", "repeated failed login",
        "too many authentication failures", "invalid user",
        "authentication failure", "logon failure",
    ]),
    ("T1059", "Command and Scripting Interpreter", 2, [
        "powershell", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "bash -c", "sh -c", "python -c",
    ]),
    ("T1053", "Scheduled Task/Job", 3, [
        "scheduled task", "schtasks", "at command", "cron job", "crontab",
        "task scheduler",
    ]),
    ("T1543", "Create or Modify System Process", 3, [
        "service installed", "new service", "sc create", "service creation",
        "service start", "7045",
    ]),
    ("T1021", "Remote Services", 2, [
        "rdp", "remote desktop", "psexec", "winrm", "wmi remote",
        "lateral movement", "ssh from", "smb login",
    ]),
    ("T1070", "Indicator Removal", 3, [
        "log cleared", "event log cleared", "audit log cleared",
        "wevtutil cl", "1102", "clear-eventlog",
    ]),
    ("T1566", "Phishing", 2, [
        "phishing", "malicious attachment", "macro enabled",
        "office macro", "suspicious email", "urlzone",
    ]),
    ("T1046", "Network Service Discovery", 1, [
        "port scan", "network scan", "nmap", "masscan",
        "service discovery", "sweep",
    ]),
    ("T1048", "Exfiltration Over Alternative Protocol", 3, [
        "data exfil", "large outbound transfer", "dns exfiltration",
        "data exfiltration", "unusual outbound",
    ]),
    ("T1190", "Exploit Public-Facing Application", 3, [
        "sql injection", "rce", "remote code execution",
        "exploit", "buffer overflow", "cve-",
    ]),
    ("T1078", "Valid Accounts", 2, [
        "compromised account", "stolen credential", "account takeover",
        "logon with explicit credentials", "4648",
    ]),
    ("T1562", "Impair Defenses", 2, [
        "antivirus disabled", "firewall disabled", "defender disabled",
        "tamper protection", "security tool disabled",
    ]),
    ("T1486", "Data Encrypted for Impact", 3, [
        "ransomware", "encrypted files", "file encryption",
        "wannacry", "lockbit", "ransom note",
    ]),
    ("T1496", "Resource Hijacking", 2, [
        "cryptomining", "coin miner", "xmrig", "cpu usage",
        "high cpu", "monero",
    ]),
    ("T1136", "Create Account", 2, [
        "account created", "new account", "net user /add",
        "useradd", "account creation", "4720",
    ]),
]


def map_mitre(evento: str, acao: str, contexto: str = "") -> tuple[Optional[str], Optional[str]]:
    """Retorna (mitre_id, mitre_tecnica) ou (None, None)."""
    texto = f"{evento} {acao} {contexto}".lower()

    best_id: Optional[str] = None
    best_tecnica: Optional[str] = None
    best_score = 0

    for mitre_id, tecnica, peso, keywords in _RULES:
        score = sum(peso for kw in keywords if kw in texto)
        if score > best_score:
            best_score = score
            best_id = mitre_id
            best_tecnica = tecnica

    if best_score >= 2:
        return best_id, best_tecnica
    return None, None
