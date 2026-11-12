"""Runtime configuration, read from environment variables (12-factor style)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _env_ports(name: str, default: str) -> list[int]:
    ports = []
    for chunk in _env(name, default).split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            ports.append(int(chunk))
    return ports


@dataclass
class Settings:
    # demo  = synthetic attack traffic only (great for showcasing)
    # live  = real honeypot sensors only
    # hybrid = both at the same time
    mode: str = field(default_factory=lambda: _env("HW_MODE", "demo").lower())

    data_dir: Path = field(default_factory=lambda: Path(_env("HW_DATA_DIR", "data")))

    dashboard_host: str = field(default_factory=lambda: _env("HW_DASH_HOST", "127.0.0.1"))
    dashboard_port: int = field(default_factory=lambda: _env_int("HW_DASH_PORT", 8000))
    # Optional shared secret protecting the dashboard + API (?token=... or X-HiveWatch-Token)
    dashboard_token: str = field(default_factory=lambda: _env("HW_DASH_TOKEN", ""))

    sensor_host: str = field(default_factory=lambda: _env("HW_SENSOR_HOST", "0.0.0.0"))
    ssh_port: int = field(default_factory=lambda: _env_int("HW_SSH_PORT", 2222))
    http_port: int = field(default_factory=lambda: _env_int("HW_HTTP_PORT", 8080))
    telnet_port: int = field(default_factory=lambda: _env_int("HW_TELNET_PORT", 2323))
    # Bare TCP "tripwire" ports: any connection is logged as a probe
    tcp_ports: list[int] = field(
        default_factory=lambda: _env_ports("HW_TCP_PORTS", "3389,5900,3306,6379,9200")
    )
    hostname: str = field(default_factory=lambda: _env("HW_FAKE_HOSTNAME", "srv-prod-01"))

    # Where the honeypot lives (drawn as the target on the globe)
    sensor_label: str = field(default_factory=lambda: _env("HW_SENSOR_LABEL", "Frankfurt, DE"))
    sensor_lat: float = field(default_factory=lambda: _env_float("HW_SENSOR_LAT", 50.11))
    sensor_lon: float = field(default_factory=lambda: _env_float("HW_SENSOR_LON", 8.68))

    # Demo simulator
    demo_rate: float = field(default_factory=lambda: _env_float("HW_DEMO_RATE", 1.0))
    demo_backfill_minutes: int = field(default_factory=lambda: _env_int("HW_DEMO_BACKFILL", 60))

    # Threat-intel enrichment
    geoip_enabled: bool = field(default_factory=lambda: _env("HW_GEOIP", "1") == "1")
    abuseipdb_key: str = field(default_factory=lambda: _env("ABUSEIPDB_API_KEY", ""))

    # Telegram alerting
    telegram_token: str = field(default_factory=lambda: _env("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id: str = field(default_factory=lambda: _env("TELEGRAM_CHAT_ID", ""))
    telegram_min_severity: str = field(
        default_factory=lambda: _env("TELEGRAM_MIN_SEVERITY", "high").lower()
    )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "hivewatch.db"

    @property
    def run_simulator(self) -> bool:
        return self.mode in ("demo", "hybrid")

    @property
    def run_sensors(self) -> bool:
        return self.mode in ("live", "hybrid")


settings = Settings()
