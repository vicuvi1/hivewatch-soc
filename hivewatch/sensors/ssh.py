"""Medium-interaction SSH honeypot built on paramiko.

* Records every username/password attempt.
* Accepts a small set of "weak" credentials (and, like real bots expect, a
  random lucky guess after many failures) to drop the attacker into a fake
  shell where every command is recorded — nothing is ever executed.
"""

from __future__ import annotations

import logging
import random
import socket
import threading
from pathlib import Path
from typing import Callable

import paramiko

from ..models import Event, new_id
from .fakeshell import FakeShell

log = logging.getLogger("hivewatch.ssh")
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

WEAK_CREDENTIALS = {
    ("root", "root"), ("root", "123456"), ("root", "password"), ("root", "admin"),
    ("admin", "admin"), ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("root", "toor"),
    ("user", "user"), ("test", "test"),
}
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
MAX_SESSION_SECONDS = 180


class _Server(paramiko.ServerInterface):
    def __init__(self, sensor: "SSHHoneypot", ip: str, port: int, session: str):
        self.sensor, self.ip, self.port, self.session = sensor, ip, port, session
        self.shell_ready = threading.Event()
        self.username = "root"
        self.attempts = 0
        self.exec_command: str | None = None

    def _emit(self, **kw) -> None:
        self.sensor.emit(Event(sensor="ssh", src_ip=self.ip, src_port=self.port,
                               dst_port=self.sensor.port, session_id=self.session, **kw))

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        self.attempts += 1
        ok = (username, password) in WEAK_CREDENTIALS or (self.attempts > 3 and random.random() < 0.05)
        self._emit(event_type="login_success" if ok else "login_failed",
                   username=username[:64], password=password[:128])
        if ok:
            self.username = username[:32] or "root"
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key) -> int:
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.shell_ready.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        self.exec_command = command.decode("utf-8", "replace")[:2000]
        self.shell_ready.set()
        return True


class SSHHoneypot:
    def __init__(self, host: str, port: int, data_dir: Path, hostname: str,
                 emit: Callable[[Event], None]):
        self.host, self.port, self.hostname, self.emit = host, port, hostname, emit
        key_path = data_dir / "ssh_host_rsa.key"
        data_dir.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            self.host_key = paramiko.RSAKey(filename=str(key_path))
        else:
            self.host_key = paramiko.RSAKey.generate(2048)
            self.host_key.write_private_key_file(str(key_path))
        self._sock: socket.socket | None = None

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(100)
        threading.Thread(target=self._accept_loop, name="ssh-honeypot", daemon=True).start()
        log.info("SSH honeypot listening on %s:%s", self.host, self.port)

    def _accept_loop(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while True:
            try:
                client, (ip, port) = sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client, ip, port), daemon=True).start()

    def _handle(self, client: socket.socket, ip: str, port: int) -> None:
        session = new_id()
        self.emit(Event(sensor="ssh", event_type="connection", src_ip=ip, src_port=port,
                        dst_port=self.port, session_id=session))
        transport = None
        try:
            client.settimeout(MAX_SESSION_SECONDS)
            transport = paramiko.Transport(client)
            transport.local_version = BANNER
            transport.add_server_key(self.host_key)
            server = _Server(self, ip, port, session)
            transport.start_server(server=server)
            chan = transport.accept(30)
            if chan is None:
                return
            server.shell_ready.wait(10)
            shell = FakeShell(self.hostname, server.username)
            if server.exec_command:
                self._record(server, server.exec_command)
                chan.sendall((shell.run(server.exec_command) + "\r\n").encode())
                chan.send_exit_status(0)
                return
            chan.sendall(b"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n")
            chan.sendall(shell.prompt.encode())
            self._interactive(chan, shell, server)
        except Exception as exc:  # malformed handshakes from scanners are normal
            log.debug("ssh session %s ended: %s", session, exc)
        finally:
            if transport:
                transport.close()
            client.close()

    def _record(self, server: _Server, command: str) -> None:
        self.emit(Event(sensor="ssh", event_type="command", src_ip=server.ip, src_port=server.port,
                        dst_port=self.port, session_id=server.session, username=server.username,
                        command=command.strip()[:2000]))

    def _interactive(self, chan: paramiko.Channel, shell: FakeShell, server: _Server) -> None:
        buf = ""
        while True:
            data = chan.recv(1024)
            if not data:
                return
            for ch in data.decode("utf-8", "replace"):
                if ch in ("\r", "\n"):
                    chan.sendall(b"\r\n")
                    line = buf.strip()
                    buf = ""
                    if line:
                        self._record(server, line)
                        if line in ("exit", "logout"):
                            return
                        out = shell.run(line)
                        if out:
                            chan.sendall(out.replace("\n", "\r\n").encode() + b"\r\n")
                    chan.sendall(shell.prompt.encode())
                elif ch in ("\x7f", "\x08"):
                    if buf:
                        buf = buf[:-1]
                        chan.sendall(b"\x08 \x08")
                elif ch == "\x03":
                    buf = ""
                    chan.sendall(b"^C\r\n" + shell.prompt.encode())
                elif ch == "\x04":
                    return
                elif ch.isprintable():
                    buf += ch
                    chan.sendall(ch.encode())
                if len(buf) > 4096:
                    buf = buf[:4096]
