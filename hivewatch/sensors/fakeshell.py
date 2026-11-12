"""A tiny, convincing-enough fake Linux shell.

It never executes anything: it only returns canned output so that bots keep
talking and reveal their full playbook (recon -> download -> persistence).
"""

from __future__ import annotations

import random
import shlex

FAKE_FILES = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false\n"
    ),
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\n'
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz\n"
        "cpu cores\t: 8\n"
    ) * 2,
}


class FakeShell:
    def __init__(self, hostname: str = "srv-prod-01", user: str = "root") -> None:
        self.hostname = hostname
        self.user = user
        self.cwd = "/root" if user == "root" else f"/home/{user}"

    @property
    def prompt(self) -> str:
        home = "/root" if self.user == "root" else f"/home/{self.user}"
        path = "~" if self.cwd == home else self.cwd
        sign = "#" if self.user == "root" else "$"
        return f"{self.user}@{self.hostname}:{path}{sign} "

    def run(self, line: str) -> str:
        """Return fake output for a full command line (supports ; && | chains)."""
        out = []
        for part in _split_chain(line):
            res = self._run_one(part.strip())
            if res:
                out.append(res)
        return "\n".join(out)

    def _run_one(self, cmd: str) -> str:
        if not cmd:
            return ""
        try:
            argv = shlex.split(cmd)
        except ValueError:
            argv = cmd.split()
        if not argv:
            return ""
        name, args = argv[0], argv[1:]
        name = name.rsplit("/", 1)[-1]

        if name in ("whoami",):
            return self.user
        if name == "id":
            return "uid=0(root) gid=0(root) groups=0(root)" if self.user == "root" else \
                f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),27(sudo)"
        if name == "hostname":
            return self.hostname
        if name == "pwd":
            return self.cwd
        if name == "cd":
            self.cwd = args[0] if args and args[0].startswith("/") else (
                f"{self.cwd.rstrip('/')}/{args[0]}" if args else "/root")
            return ""
        if name == "uname":
            if "-a" in args:
                return (f"Linux {self.hostname} 5.15.0-105-generic #115-Ubuntu SMP "
                        "Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux")
            if "-m" in args:
                return "x86_64"
            return "Linux"
        if name == "nproc":
            return "8"
        if name == "free":
            return ("               total        used        free      shared  buff/cache   available\n"
                    "Mem:        16365492     2210436    11020584        1660     3134472    13812352\n"
                    "Swap:        2097148           0     2097148")
        if name == "uptime":
            return " 14:02:11 up 41 days,  3:17,  1 user,  load average: 0.08, 0.11, 0.09"
        if name in ("cat", "head", "tail", "more", "less"):
            for a in args:
                if a in FAKE_FILES:
                    return FAKE_FILES[a].rstrip("\n")
                if a == "/etc/shadow":
                    return "root:$6$Vx3n9P2q$Jm1...:19740:0:99999:7:::"
            return f"{name}: {args[-1] if args else ''}: No such file or directory"
        if name == "ls":
            return "backup.tar.gz  deploy.sh  .ssh  notes.txt" if "-a" not in " ".join(args) else \
                ".  ..  .bash_history  .bashrc  .profile  .ssh  backup.tar.gz  deploy.sh  notes.txt"
        if name == "ps":
            return ("  PID TTY          TIME CMD\n    1 ?        00:00:12 systemd\n"
                    "  812 ?        00:01:03 sshd\n  944 ?        00:04:51 mysqld\n"
                    " 1201 ?        00:00:30 nginx\n 2210 pts/0    00:00:00 bash")
        if name in ("ifconfig", "ip"):
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                    "        inet 10.0.4.17  netmask 255.255.255.0  broadcast 10.0.4.255")
        if name in ("wget", "curl"):
            url = next((a for a in args if "://" in a), "")
            host = url.split("/")[2] if url.count("/") >= 2 else url
            if random.random() < 0.5:
                return f"{name}: unable to resolve host address '{host}'"
            return f"Connecting to {host}... connected.\nHTTP request sent, awaiting response... 200 OK\nSaving to: '{url.rsplit('/', 1)[-1] or 'index.html'}'"
        if name in ("chmod", "echo", "export", "unset", "history", "rm", "mkdir", "touch",
                    "crontab", "kill", "pkill", "killall", "cp", "mv", "sh", "bash", "nohup"):
            if name == "echo":
                return " ".join(a for a in args if not a.startswith(">"))[:200]
            return ""
        if name == "exit" or name == "logout":
            return ""
        if name.startswith("./"):
            return "Segmentation fault (core dumped)"
        return f"-bash: {name}: command not found"


def _split_chain(line: str) -> list[str]:
    parts, cur, i = [], "", 0
    while i < len(line):
        two = line[i:i + 2]
        if two in ("&&", "||"):
            parts.append(cur)
            cur = ""
            i += 2
            continue
        if line[i] in ";|":
            parts.append(cur)
            cur = ""
            i += 1
            continue
        cur += line[i]
        i += 1
    parts.append(cur)
    return parts
