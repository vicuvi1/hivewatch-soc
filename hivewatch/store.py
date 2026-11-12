"""SQLite persistence + the aggregate queries that power the dashboard."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .mitre import TACTICS, TECHNIQUES, describe
from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    sensor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    session_id TEXT,
    username TEXT,
    password TEXT,
    command TEXT,
    http_method TEXT,
    path TEXT,
    user_agent TEXT,
    country TEXT,
    country_code TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    org TEXT,
    abuse_score INTEGER,
    techniques TEXT,
    simulated INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    rule TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    description TEXT,
    technique TEXT,
    evidence TEXT,
    country TEXT,
    country_code TEXT,
    simulated INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""

EVENT_COLUMNS = [
    "id", "ts", "sensor", "event_type", "src_ip", "src_port", "dst_port", "session_id",
    "username", "password", "command", "http_method", "path", "user_agent", "country",
    "country_code", "city", "lat", "lon", "org", "abuse_score", "techniques", "simulated",
]
ALERT_COLUMNS = [
    "id", "ts", "rule", "title", "severity", "src_ip", "description", "technique",
    "evidence", "country", "country_code", "simulated",
]


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ writes
    def add_event(self, ev: Event) -> None:
        row = ev.to_dict()
        row["techniques"] = json.dumps(ev.techniques)
        row["simulated"] = int(ev.simulated)
        self._insert("events", EVENT_COLUMNS, row)

    def add_alert(self, al: Alert) -> None:
        row = al.to_dict()
        row["evidence"] = json.dumps(al.evidence)
        row["simulated"] = int(al.simulated)
        self._insert("alerts", ALERT_COLUMNS, row)

    def _insert(self, table: str, cols: list[str], row: dict[str, Any]) -> None:
        sql = f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        with self._lock:
            self._conn.execute(sql, [row.get(c) for c in cols])
            self._conn.commit()

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM alerts")
            self._conn.commit()

    # ------------------------------------------------------------------ reads
    def _q(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def _one(self, sql: str, params: tuple | list = ()) -> Any:
        rows = self._q(sql, params)
        return next(iter(rows[0].values())) if rows else None

    @staticmethod
    def _decode_event(row: dict[str, Any]) -> dict[str, Any]:
        row["techniques"] = json.loads(row.get("techniques") or "[]")
        row["simulated"] = bool(row.get("simulated"))
        return row

    @staticmethod
    def _decode_alert(row: dict[str, Any]) -> dict[str, Any]:
        row["evidence"] = json.loads(row.get("evidence") or "{}")
        row["simulated"] = bool(row.get("simulated"))
        return row

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._q("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
        return [self._decode_event(r) for r in rows]

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._q("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
        return [self._decode_alert(r) for r in rows]

    def top(self, column: str, where: str = "1=1", limit: int = 10) -> list[dict[str, Any]]:
        if column not in EVENT_COLUMNS:  # column names can't be bound parameters -> allow-list
            raise ValueError(f"unknown column {column!r}")
        return self._q(
            f"SELECT {column} AS label, COUNT(*) AS count FROM events "
            f"WHERE {column} IS NOT NULL AND {column} != '' AND {where} "
            f"GROUP BY {column} ORDER BY count DESC LIMIT ?",
            (limit,),
        )

    def kpis(self) -> dict[str, Any]:
        now = time.time()
        return {
            "events": self._one("SELECT COUNT(*) FROM events") or 0,
            "attackers": self._one("SELECT COUNT(DISTINCT src_ip) FROM events") or 0,
            "countries": self._one("SELECT COUNT(DISTINCT country_code) FROM events") or 0,
            "credentials": self._one(
                "SELECT COUNT(*) FROM events WHERE event_type IN ('login_failed','login_success')"
            ) or 0,
            "sessions": self._one("SELECT COUNT(*) FROM events WHERE event_type='login_success'") or 0,
            "commands": self._one("SELECT COUNT(*) FROM events WHERE event_type='command'") or 0,
            "alerts": self._one("SELECT COUNT(*) FROM alerts") or 0,
            "critical": self._one("SELECT COUNT(*) FROM alerts WHERE severity='critical'") or 0,
            "epm": self._one("SELECT COUNT(*) FROM events WHERE ts > ?", (now - 60,)) or 0,
        }

    def timeline(self, minutes: int = 60) -> dict[str, Any]:
        now = time.time()
        start = int((now - minutes * 60) // 60) * 60
        rows = self._q(
            "SELECT CAST(ts/60 AS INTEGER)*60 AS bucket, sensor, COUNT(*) AS count "
            "FROM events WHERE ts >= ? GROUP BY bucket, sensor",
            (start,),
        )
        buckets = [start + i * 60 for i in range(minutes + 1)]
        series: dict[str, list[int]] = {}
        index = {b: i for i, b in enumerate(buckets)}
        for r in rows:
            s = series.setdefault(r["sensor"], [0] * len(buckets))
            if r["bucket"] in index:
                s[index[r["bucket"]]] = r["count"]
        return {"buckets": buckets, "series": series}

    def mitre_matrix(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for r in self._q("SELECT techniques FROM events WHERE techniques != '[]'"):
            for tid in json.loads(r["techniques"]):
                counts[tid] = counts.get(tid, 0) + 1
        columns = []
        for tactic in TACTICS:
            techs = [
                {**describe(t.id), "count": counts.get(t.id, 0)}
                for t in TECHNIQUES.values()
                if t.tactic == tactic
            ]
            columns.append({"tactic": tactic, "techniques": techs})
        return {"columns": columns, "max": max(counts.values(), default=0)}

    def attackers(self, limit: int = 15) -> list[dict[str, Any]]:
        rows = self._q(
            """
            SELECT src_ip,
                   MAX(country) AS country, MAX(country_code) AS country_code,
                   MAX(city) AS city, MAX(org) AS org, MAX(abuse_score) AS abuse_score,
                   COUNT(*) AS events,
                   SUM(event_type='login_failed') AS failed,
                   SUM(event_type='login_success') AS success,
                   SUM(event_type='command') AS commands,
                   GROUP_CONCAT(DISTINCT sensor) AS sensors,
                   MIN(ts) AS first_seen, MAX(ts) AS last_seen
            FROM events GROUP BY src_ip
            ORDER BY (SUM(event_type='login_success')*40 + SUM(event_type='command')*6 + COUNT(*)) DESC
            LIMIT ?
            """,
            (limit,),
        )
        alert_weight = {
            r["src_ip"]: r["w"]
            for r in self._q(
                "SELECT src_ip, SUM(CASE severity WHEN 'critical' THEN 25 WHEN 'high' THEN 15 "
                "WHEN 'medium' THEN 8 WHEN 'low' THEN 3 ELSE 0 END) AS w FROM alerts GROUP BY src_ip"
            )
        }
        for r in rows:
            # Weighted risk model: volume < access < post-exploitation < confirmed detections
            score = (
                min(r["failed"], 40) * 0.4
                + min(r["success"], 2) * 10
                + min(r["commands"], 15) * 1.5
                + min(alert_weight.get(r["src_ip"], 0), 45) * 0.8
                + (r["abuse_score"] or 0) * 0.15
            )
            r["risk"] = int(min(100, round(score)))
            r["sensors"] = (r["sensors"] or "").split(",")
        rows.sort(key=lambda r: r["risk"], reverse=True)
        return rows

    def attacker_profile(self, ip: str) -> dict[str, Any]:
        events = [
            self._decode_event(r)
            for r in self._q("SELECT * FROM events WHERE src_ip=? ORDER BY ts ASC LIMIT 1000", (ip,))
        ]
        alerts = [
            self._decode_alert(r)
            for r in self._q("SELECT * FROM alerts WHERE src_ip=? ORDER BY ts ASC", (ip,))
        ]
        techniques = sorted({t for e in events for t in e["techniques"]})
        return {
            "ip": ip,
            "events": events,
            "alerts": alerts,
            "techniques": [describe(t) for t in techniques],
            "credentials": [
                {"username": e["username"], "password": e["password"], "ok": e["event_type"] == "login_success"}
                for e in events
                if e["event_type"] in ("login_failed", "login_success")
            ][-50:],
            "commands": [
                {"ts": e["ts"], "command": e["command"], "session": e["session_id"]}
                for e in events
                if e["event_type"] == "command"
            ],
        }

    def iocs(self) -> dict[str, Any]:
        ips = self._q(
            "SELECT src_ip, MAX(simulated) AS simulated, COUNT(*) AS hits FROM events "
            "GROUP BY src_ip ORDER BY hits DESC"
        )
        urls: dict[str, int] = {}
        url_re = re.compile(r"(?:https?|ftp|tftp)://[^\s'\";|)]+")
        for r in self._q("SELECT command FROM events WHERE event_type='command'"):
            for u in url_re.findall(r["command"] or ""):
                urls[u] = urls.get(u, 0) + 1
        return {
            "ips": ips,
            "urls": [{"url": u, "hits": n} for u, n in sorted(urls.items(), key=lambda x: -x[1])],
            "passwords": self.top("password", limit=50),
        }

    def geo_points(self, since_seconds: int = 3600) -> list[dict[str, Any]]:
        return self._q(
            "SELECT src_ip, MAX(lat) AS lat, MAX(lon) AS lon, MAX(country_code) AS country_code, "
            "MAX(city) AS city, COUNT(*) AS count FROM events WHERE ts > ? AND lat IS NOT NULL "
            "GROUP BY src_ip ORDER BY count DESC LIMIT 400",
            (time.time() - since_seconds,),
        )
