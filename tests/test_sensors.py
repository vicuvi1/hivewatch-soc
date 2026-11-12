"""Integration tests: real sensors bound to 127.0.0.1 on ephemeral ports."""

import asyncio
import time

import paramiko
import pytest

from hivewatch.sensors.network import TelnetHoneypot
from hivewatch.sensors.ssh import SSHHoneypot


def test_ssh_honeypot_captures_credentials_and_commands(tmp_path):
    events = []
    pot = SSHHoneypot("127.0.0.1", 0, tmp_path, "srv-test", events.append)
    pot.start()
    port = pot._sock.getsockname()[1]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 - connecting to our own test honeypot
    with pytest.raises(paramiko.AuthenticationException):
        client.connect("127.0.0.1", port=port, username="oracle", password="nope",
                       look_for_keys=False, allow_agent=False, timeout=5)
    client.close()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507
    client.connect("127.0.0.1", port=port, username="root", password="123456",
                   look_for_keys=False, allow_agent=False, timeout=5)
    _, stdout, _ = client.exec_command("whoami; uname -m")
    output = stdout.read().decode()
    client.close()

    deadline = time.time() + 5
    while time.time() < deadline and not any(e.event_type == "command" for e in events):
        time.sleep(0.05)

    types = [e.event_type for e in events]
    assert "login_failed" in types and "login_success" in types
    failed = next(e for e in events if e.event_type == "login_failed")
    assert (failed.username, failed.password) == ("oracle", "nope")
    cmd = next(e for e in events if e.event_type == "command")
    assert cmd.command == "whoami; uname -m"
    assert "root" in output and "x86_64" in output


def test_telnet_honeypot_captures_login():
    async def scenario():
        events = []

        async def emit(e):
            events.append(e)

        pot = TelnetHoneypot("127.0.0.1", 0, emit)
        server = await asyncio.start_server(pot._handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"login: ")
        writer.write(b"root\r\n")
        await reader.readuntil(b"Password: ")
        writer.write(b"xc3511\r\n")
        await writer.drain()
        await reader.readuntil(b"Login incorrect")
        writer.close()
        server.close()
        return events

    events = asyncio.run(scenario())
    login = next(e for e in events if e.event_type == "login_failed")
    assert (login.sensor, login.username, login.password) == ("telnet", "root", "xc3511")
