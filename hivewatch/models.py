"""Core data models shared by sensors, the pipeline, the detection engine and the API."""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def new_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class Event:
    """A single observation from a honeypot sensor."""

    sensor: str  # ssh | telnet | http | tcp
    event_type: str  # connection | login_failed | login_success | command | http_request | port_probe
    src_ip: str
    dst_port: int
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=new_id)
    src_port: int = 0
    session_id: str = ""
    username: str | None = None
    password: str | None = None
    command: str | None = None
    http_method: str | None = None
    path: str | None = None
    user_agent: str | None = None
    # enrichment
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    org: str | None = None
    abuse_score: int | None = None
    # ATT&CK technique IDs, filled by hivewatch.mitre
    techniques: list[str] = field(default_factory=list)
    simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    """A detection produced by a rule in hivewatch.detection."""

    rule: str
    title: str
    severity: str
    src_ip: str
    description: str
    technique: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=new_id)
    country: str | None = None
    country_code: str | None = None
    simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
