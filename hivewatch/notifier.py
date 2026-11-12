"""Push high-severity alerts to a Telegram chat."""

from __future__ import annotations

import logging
import time

import httpx

from .models import SEVERITY_ORDER, Alert

log = logging.getLogger("hivewatch.notifier")

EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, min_severity: str = "high") -> None:
        self.token = token
        self.chat_id = chat_id
        self.min_level = SEVERITY_ORDER.get(min_severity, 3)
        self._sent: list[float] = []

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def format(self, alert: Alert) -> str:
        flag = alert.country_code or "??"
        return (
            f"{EMOJI.get(alert.severity, '⚪')} *{alert.severity.upper()}* — {alert.title}\n"
            f"`{alert.src_ip}` ({alert.country or 'unknown'} {flag})\n"
            f"{alert.description}\n"
            f"MITRE: `{alert.technique or '-'}`"
        )

    async def send(self, alert: Alert) -> None:
        if not self.enabled or alert.simulated:
            return
        if SEVERITY_ORDER.get(alert.severity, 0) < self.min_level:
            return
        now = time.time()
        self._sent = [t for t in self._sent if t > now - 60]
        if len(self._sent) >= 15:  # stay well below Telegram's flood limits
            return
        self._sent.append(now)
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(
                    f"https://api.telegram.org/bot{self.token}/sendMessage",
                    json={"chat_id": self.chat_id, "text": self.format(alert), "parse_mode": "Markdown"},
                )
        except Exception as exc:
            log.warning("telegram notification failed: %s", exc)
