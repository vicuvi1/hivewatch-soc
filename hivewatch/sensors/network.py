"""Asyncio sensors: a fake Telnet login (IoT botnet bait) and TCP tripwire ports."""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from ..models import Event, new_id

log = logging.getLogger("hivewatch.network")

Emit = Callable[[Event], Awaitable[object]]

# Short, protocol-plausible greetings so scanners fingerprint something real-looking
TRIPWIRE_BANNERS = {
    3306: b"J\x00\x00\x00\n8.0.36-0ubuntu0.22.04.1\x00",
    6379: b"-NOAUTH Authentication required.\r\n",
    5900: b"RFB 003.008\n",
    9200: b"",
    3389: b"",
}


async def _readline(reader: asyncio.StreamReader, limit: int = 256) -> str:
    raw = await asyncio.wait_for(reader.readline(), timeout=30)
    # strip telnet IAC negotiation bytes
    cleaned = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == 0xFF and i + 2 < len(raw):
            i += 3
            continue
        cleaned.append(raw[i])
        i += 1
    return cleaned.decode("utf-8", "replace").strip()[:limit]


class TelnetHoneypot:
    def __init__(self, host: str, port: int, emit: Emit):
        self.host, self.port, self.emit = host, port, emit

    async def start(self) -> None:
        await asyncio.start_server(self._handle, self.host, self.port)
        log.info("Telnet honeypot listening on %s:%s", self.host, self.port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, port = writer.get_extra_info("peername")[:2]
        session = new_id()
        base = dict(sensor="telnet", src_ip=ip, src_port=port, dst_port=self.port, session_id=session)
        await self.emit(Event(event_type="connection", **base))
        try:
            for _ in range(3):
                writer.write(b"\r\nBusyBox v1.31.1 () built-in shell\r\nlogin: ")
                await writer.drain()
                user = await _readline(reader)
                writer.write(b"Password: ")
                await writer.drain()
                password = await _readline(reader)
                await self.emit(Event(event_type="login_failed", username=user, password=password, **base))
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()


class TripwirePorts:
    """Listen on ports with no legitimate service. Any touch is suspicious."""

    def __init__(self, host: str, ports: list[int], emit: Emit):
        self.host, self.ports, self.emit = host, ports, emit

    async def start(self) -> None:
        for p in self.ports:
            try:
                await asyncio.start_server(lambda r, w, p=p: self._handle(r, w, p), self.host, p)
                log.info("Tripwire listening on %s:%s", self.host, p)
            except OSError as exc:
                log.warning("cannot bind tripwire port %s: %s", p, exc)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> None:
        ip, sport = writer.get_extra_info("peername")[:2]
        payload = ""
        try:
            banner = TRIPWIRE_BANNERS.get(port, b"")
            if banner:
                writer.write(banner)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=5)
            payload = data.decode("utf-8", "replace")[:200]
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
        await self.emit(Event(sensor="tcp", event_type="port_probe", src_ip=ip, src_port=sport,
                              dst_port=port, command=payload or None))
