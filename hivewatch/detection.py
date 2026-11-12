"""Streaming detection engine.

Each rule looks at the incoming event plus a small amount of sliding-window
state, and may raise an Alert. Windows use the *event* timestamp, so the same
engine works for live traffic, replayed logs and the demo backfill.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .mitre import WEB_EXPLOIT
from .models import Alert, Event


@dataclass
class Window:
    """Timestamped values kept for `span` seconds."""

    span: float
    items: deque = field(default_factory=deque)

    def add(self, ts: float, value: object) -> None:
        self.items.append((ts, value))
        self.prune(ts)

    def prune(self, now: float) -> None:
        while self.items and self.items[0][0] < now - self.span:
            self.items.popleft()

    def count(self) -> int:
        return len(self.items)

    def distinct(self) -> int:
        return len({v for _, v in self.items})


URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s'\";|)]+")
MINER_RE = re.compile(r"xmrig|minerd|cpuminer|stratum\+tcp|kdevtmpfsi|kinsing|c3pool|nanopool", re.I)
DOWNLOAD_RE = re.compile(r"\b(wget|curl|tftp|ftpget)\b")
PERSIST_RE = re.compile(r"authorized_keys|crontab|/etc/cron|useradd|chpasswd")
WIPE_RE = re.compile(r"history\s+-c|unset\s+HISTFILE|rm\s+-[rf]+\s+/var/log|HISTFILE=/dev/null")
SHADOW_RE = re.compile(r"/etc/shadow")


class DetectionEngine:
    # Tunable thresholds
    BRUTE_FORCE_ATTEMPTS = 10
    BRUTE_FORCE_WINDOW = 60
    SPRAY_USERS = 5
    SPRAY_WINDOW = 300
    STUFFING_IPS = 4
    STUFFING_WINDOW = 600
    SCAN_PORTS = 4
    SCAN_WINDOW = 120
    COOLDOWN = 300  # seconds before the same rule may fire again for the same key
    RULE_COOLDOWN = {"distributed_stuffing": 1800, "username_enumeration": 900}

    def __init__(self) -> None:
        self.failed = defaultdict(lambda: Window(self.BRUTE_FORCE_WINDOW))
        self.users = defaultdict(lambda: Window(self.SPRAY_WINDOW))
        self.cred_sources = defaultdict(lambda: Window(self.STUFFING_WINDOW))
        self.ports = defaultdict(lambda: Window(self.SCAN_WINDOW))
        self._last_fired: dict[tuple[str, str], float] = {}

    # ------------------------------------------------------------------ api
    def process(self, ev: Event) -> list[Alert]:
        alerts: list[Alert] = []
        handler = getattr(self, f"_on_{ev.event_type}", None)
        if handler:
            alerts.extend(handler(ev))
        alerts.extend(self._port_scan(ev))
        out = []
        for a in alerts:
            a.ts = ev.ts
            a.country, a.country_code = ev.country, ev.country_code
            a.simulated = ev.simulated
            key = (a.rule, a.evidence.get("dedup", a.src_ip))
            cooldown = self.RULE_COOLDOWN.get(a.rule, self.COOLDOWN)
            if ev.ts - self._last_fired.get(key, -1e18) >= cooldown:
                self._last_fired[key] = ev.ts
                a.evidence.pop("dedup", None)
                out.append(a)
        return out

    # ------------------------------------------------------------------ rules
    def _on_login_failed(self, ev: Event) -> list[Alert]:
        alerts = []
        w = self.failed[ev.src_ip]
        w.add(ev.ts, ev.password)
        if w.count() >= self.BRUTE_FORCE_ATTEMPTS:
            alerts.append(Alert(
                rule="brute_force",
                title=f"{ev.sensor.upper()} brute force",
                severity="high",
                src_ip=ev.src_ip,
                technique="T1110.001",
                description=f"{w.count()} failed logins in {self.BRUTE_FORCE_WINDOW}s on {ev.sensor}",
                evidence={"attempts": w.count(), "sensor": ev.sensor},
            ))

        if ev.username:
            u = self.users[ev.src_ip]
            u.add(ev.ts, ev.username)
            if u.distinct() >= self.SPRAY_USERS:
                alerts.append(Alert(
                    rule="username_enumeration",
                    title="Username enumeration / spraying",
                    severity="medium",
                    src_ip=ev.src_ip,
                    technique="T1110",
                    description=f"{u.distinct()} distinct usernames tried within {self.SPRAY_WINDOW // 60} min",
                    evidence={"usernames": sorted({v for _, v in u.items})[:10]},
                ))

        if ev.username and ev.password:
            pair = f"{ev.username}:{ev.password}"
            c = self.cred_sources[pair]
            c.add(ev.ts, ev.src_ip)
            if c.distinct() >= self.STUFFING_IPS:
                alerts.append(Alert(
                    rule="distributed_stuffing",
                    title="Distributed credential stuffing (botnet)",
                    severity="high",
                    src_ip=ev.src_ip,
                    technique="T1110.004",
                    description=f"Credential '{pair}' tried from {c.distinct()} different IPs — coordinated botnet",
                    evidence={"credential": pair, "sources": sorted({v for _, v in c.items})[:10], "dedup": pair},
                ))
        return alerts

    def _on_login_success(self, ev: Event) -> list[Alert]:
        return [Alert(
            rule="honeypot_login",
            title="Attacker obtained a shell",
            severity="high",
            src_ip=ev.src_ip,
            technique="T1078",
            description=f"Logged in to {ev.sensor} honeypot as '{ev.username}' with password '{ev.password}'",
            evidence={"username": ev.username, "password": ev.password, "session": ev.session_id,
                      "dedup": ev.session_id or ev.src_ip},
        )]

    def _on_command(self, ev: Event) -> list[Alert]:
        cmd = ev.command or ""
        alerts = []
        if MINER_RE.search(cmd):
            alerts.append(Alert(
                rule="cryptominer",
                title="Cryptominer deployment",
                severity="critical",
                src_ip=ev.src_ip,
                technique="T1496",
                description="Command references a known cryptocurrency miner / mining pool",
                evidence={"command": cmd[:300]},
            ))
        if DOWNLOAD_RE.search(cmd):
            urls = URL_RE.findall(cmd)
            alerts.append(Alert(
                rule="malware_download",
                title="Malware download attempt",
                severity="critical",
                src_ip=ev.src_ip,
                technique="T1105",
                description="Attacker tried to pull a remote payload" + (f": {urls[0]}" if urls else ""),
                evidence={"command": cmd[:300], "urls": urls},
            ))
        if PERSIST_RE.search(cmd):
            alerts.append(Alert(
                rule="persistence",
                title="Persistence mechanism installed",
                severity="high",
                src_ip=ev.src_ip,
                technique="T1098.004" if "authorized_keys" in cmd else "T1053.003",
                description="Attacker attempted to keep access (SSH keys / cron / accounts)",
                evidence={"command": cmd[:300]},
            ))
        if WIPE_RE.search(cmd):
            alerts.append(Alert(
                rule="anti_forensics",
                title="Anti-forensics: log / history wiping",
                severity="high",
                src_ip=ev.src_ip,
                technique="T1070.003",
                description="Attacker tried to erase evidence of their activity",
                evidence={"command": cmd[:300]},
            ))
        if SHADOW_RE.search(cmd):
            alerts.append(Alert(
                rule="credential_dump",
                title="Credential file access",
                severity="medium",
                src_ip=ev.src_ip,
                technique="T1003.008",
                description="Attacker read /etc/shadow",
                evidence={"command": cmd[:300]},
            ))
        return alerts

    def _on_http_request(self, ev: Event) -> list[Alert]:
        target = f"{ev.path or ''} {ev.user_agent or ''}"
        if WEB_EXPLOIT.search(target):
            return [Alert(
                rule="web_exploit",
                title="Web exploitation attempt",
                severity="high",
                src_ip=ev.src_ip,
                technique="T1190",
                description=f"Exploit payload in {ev.http_method} {ev.path[:120] if ev.path else ''}",
                evidence={"path": (ev.path or "")[:300], "user_agent": ev.user_agent},
            )]
        return []

    def _port_scan(self, ev: Event) -> list[Alert]:
        w = self.ports[ev.src_ip]
        w.add(ev.ts, ev.dst_port)
        if w.distinct() >= self.SCAN_PORTS:
            return [Alert(
                rule="port_scan",
                title="Port scan",
                severity="medium",
                src_ip=ev.src_ip,
                technique="T1595",
                description=f"{w.distinct()} distinct ports probed in {self.SCAN_WINDOW}s",
                evidence={"ports": sorted({v for _, v in w.items})},
            )]
        return []
