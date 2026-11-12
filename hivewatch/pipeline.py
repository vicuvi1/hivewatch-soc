"""Ingestion pipeline: enrich -> tag (MITRE) -> store -> detect -> broadcast -> notify."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

from .detection import DetectionEngine
from .enrichment import Enricher
from .mitre import map_event
from .models import Alert, Event
from .notifier import TelegramNotifier
from .store import Store

log = logging.getLogger("hivewatch.pipeline")

Subscriber = Callable[[dict[str, Any]], Awaitable[None]]


class Pipeline:
    def __init__(self, store: Store, enricher: Enricher, notifier: TelegramNotifier | None = None):
        self.store = store
        self.enricher = enricher
        self.notifier = notifier
        self.engine = DetectionEngine()
        self._subscribers: set[asyncio.Queue] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------- pub/sub
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def _broadcast(self, message: dict[str, Any]) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass  # slow client: drop rather than block the pipeline

    # ------------------------------------------------------------- ingest
    async def ingest(self, ev: Event, broadcast: bool = True) -> list[Alert]:
        try:
            await self.enricher.enrich(ev)
        except Exception:
            log.exception("enrichment crashed")
        ev.techniques = map_event(ev)
        self.store.add_event(ev)
        alerts = self.engine.process(ev)
        for a in alerts:
            self.store.add_alert(a)
        if broadcast:
            self._broadcast({"type": "event", "data": ev.to_dict()})
            for a in alerts:
                self._broadcast({"type": "alert", "data": a.to_dict()})
        if self.notifier:
            for a in alerts:
                asyncio.create_task(self.notifier.send(a))
        return alerts

    def submit_threadsafe(self, ev: Event) -> None:
        """Called from sensor threads (e.g. paramiko) to hand events to the asyncio loop."""
        if self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self.ingest(ev), self.loop)
