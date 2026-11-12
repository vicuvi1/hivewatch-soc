"""Map honeypot observations to MITRE ATT&CK (Enterprise) techniques.

The mapping is deliberately rule-based and transparent: every regex below is
something an analyst can read, review and tune.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Event


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


# Tactic order as it appears in the ATT&CK matrix (subset relevant to a honeypot)
TACTICS = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Command and Control",
    "Impact",
]

TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in [
        Technique("T1595", "Active Scanning", "Reconnaissance"),
        Technique("T1595.003", "Wordlist Scanning", "Reconnaissance"),
        Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
        Technique("T1078", "Valid Accounts", "Initial Access"),
        Technique("T1059.004", "Unix Shell", "Execution"),
        Technique("T1053.003", "Cron", "Persistence"),
        Technique("T1098", "Account Manipulation", "Persistence"),
        Technique("T1098.004", "SSH Authorized Keys", "Persistence"),
        Technique("T1070.003", "Clear Command History", "Defense Evasion"),
        Technique("T1070.002", "Clear Linux or Mac System Logs", "Defense Evasion"),
        Technique("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
        Technique("T1222.002", "Linux File Permissions Modification", "Defense Evasion"),
        Technique("T1110", "Brute Force", "Credential Access"),
        Technique("T1110.001", "Password Guessing", "Credential Access"),
        Technique("T1110.004", "Credential Stuffing", "Credential Access"),
        Technique("T1003.008", "/etc/passwd and /etc/shadow", "Credential Access"),
        Technique("T1082", "System Information Discovery", "Discovery"),
        Technique("T1033", "System Owner/User Discovery", "Discovery"),
        Technique("T1057", "Process Discovery", "Discovery"),
        Technique("T1016", "System Network Configuration Discovery", "Discovery"),
        Technique("T1049", "System Network Connections Discovery", "Discovery"),
        Technique("T1083", "File and Directory Discovery", "Discovery"),
        Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
        Technique("T1496", "Resource Hijacking", "Impact"),
        Technique("T1489", "Service Stop", "Impact"),
    ]
}

# (regex, technique) pairs applied to shell commands
COMMAND_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(wget|curl|tftp|ftpget)\b"), "T1105"),
    (re.compile(r"\b(xmrig|minerd|cpuminer|stratum\+tcp|kdevtmpfsi|kinsing|c3pool|nanopool)\b"), "T1496"),
    (re.compile(r"crontab|/etc/cron"), "T1053.003"),
    (re.compile(r"authorized_keys"), "T1098.004"),
    (re.compile(r"\b(passwd|chpasswd|useradd|usermod)\b"), "T1098"),
    (re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|\.bash_history"), "T1070.003"),
    (re.compile(r"rm\s+-[rf]+\s+/var/log|>\s*/var/log/"), "T1070.002"),
    (re.compile(r"base64\s+(-d|--decode)"), "T1140"),
    (re.compile(r"chmod\s+(\+x|7[0-7][0-7])"), "T1222.002"),
    (re.compile(r"\b(sh|bash)\s+\S+|\./\S+|\|\s*(sh|bash)\b"), "T1059.004"),
    (re.compile(r"/etc/(shadow|passwd)"), "T1003.008"),
    (re.compile(r"\b(uname|lscpu|nproc|free|/proc/cpuinfo|/proc/meminfo|cat /etc/\S*release|df\b|lspci)"), "T1082"),
    (re.compile(r"\b(whoami|id|w|who|last)\b"), "T1033"),
    (re.compile(r"\b(ps|top|pgrep)\b"), "T1057"),
    (re.compile(r"\b(ifconfig|ip a(ddr)?|ip route|route|arp|cat /etc/resolv\.conf)"), "T1016"),
    (re.compile(r"\b(netstat|ss -\w+|lsof -i)"), "T1049"),
    (re.compile(r"\b(ls|find|locate)\b"), "T1083"),
    (re.compile(r"\b(pkill|killall|kill -9|systemctl stop|service \S+ stop)"), "T1489"),
]

WEB_EXPLOIT = re.compile(
    r"(\.\./|%2e%2e|/etc/passwd|union\s+select|'\s*or\s*'1'\s*=\s*'1|<script|\$\{jndi:|"
    r"\$\(|;\s*(id|wget|curl)|eval-stdin|/cgi-bin/|/boaform/|shell\?|/actuator/|\bcmd=)",
    re.IGNORECASE,
)
WEB_WORDLIST = re.compile(
    r"(\.env|\.git/|wp-login|wp-admin|xmlrpc|phpmyadmin|/admin|\.aws/|config\.json|"
    r"\.DS_Store|server-status|backup|\.sql)",
    re.IGNORECASE,
)


def techniques_for_command(command: str) -> list[str]:
    found: list[str] = []
    for pattern, tid in COMMAND_RULES:
        if pattern.search(command) and tid not in found:
            found.append(tid)
    return found


def map_event(event: Event) -> list[str]:
    """Return the ATT&CK technique IDs an event provides evidence for."""
    et = event.event_type
    if et in ("connection", "port_probe"):
        return ["T1595"]
    if et == "login_failed":
        return ["T1110.001"] if event.sensor in ("ssh", "telnet") else ["T1110"]
    if et == "login_success":
        return ["T1078"]
    if et == "command" and event.command:
        return techniques_for_command(event.command)
    if et == "http_request":
        target = f"{event.path or ''} {event.user_agent or ''}"
        if WEB_EXPLOIT.search(target):
            return ["T1190"]
        if WEB_WORDLIST.search(target):
            return ["T1595.003"]
        return ["T1595"]
    return []


def describe(tid: str) -> dict[str, str]:
    t = TECHNIQUES.get(tid)
    if not t:
        return {"id": tid, "name": tid, "tactic": "Unknown", "url": ""}
    return {"id": t.id, "name": t.name, "tactic": t.tactic, "url": t.url}
