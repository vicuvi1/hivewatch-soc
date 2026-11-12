import pytest
from fastapi.testclient import TestClient

from hivewatch.app import create_app
from hivewatch.config import Settings


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HW_MODE", "demo")
    monkeypatch.setenv("HW_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HW_DEMO_BACKFILL", "15")
    monkeypatch.setenv("HW_GEOIP", "0")
    with TestClient(create_app(Settings())) as c:
        yield c


def test_health_and_security_headers(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    r = client.get("/")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_stats_shape(client):
    s = client.get("/api/stats").json()
    assert s["kpis"]["events"] > 0
    assert s["kpis"]["attackers"] > 0
    assert len(s["mitre"]["columns"]) == 9
    assert all(0 <= a["risk"] <= 100 for a in s["attackers"])


def test_attacker_profile_and_iocs(client):
    ip = client.get("/api/stats").json()["attackers"][0]["src_ip"]
    p = client.get(f"/api/attacker/{ip}").json()
    assert p["ip"] == ip and p["events"]
    assert client.get("/api/iocs?fmt=txt").text.startswith("# HiveWatch blocklist")
    assert client.get("/api/iocs?fmt=csv").text.startswith("type,value,hits,simulated")


def test_websocket_streams_live_events(client):
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] in ("event", "alert")


def test_token_protection(tmp_path, monkeypatch):
    monkeypatch.setenv("HW_MODE", "live")
    monkeypatch.setenv("HW_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HW_DASH_TOKEN", "s3cret")
    cfg = Settings()
    cfg.mode = "none"  # no sensors / simulator, API only
    with TestClient(create_app(cfg)) as c:
        assert c.get("/api/stats").status_code == 401
        assert c.get("/api/stats", headers={"X-HiveWatch-Token": "s3cret"}).status_code == 200
        assert c.get("/healthz").status_code == 200
