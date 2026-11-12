"""Dashboard API + WebSocket live feed, and orchestration of sensors/simulator."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Settings
from .config import settings as default_settings
from .enrichment import Enricher
from .notifier import TelegramNotifier
from .pipeline import Pipeline
from .simulator import AttackSimulator
from .store import Store

log = logging.getLogger("hivewatch")
STATIC = Path(__file__).parent / "static"


def create_app(cfg: Settings | None = None) -> FastAPI:
    cfg = cfg or default_settings
    store = Store(cfg.db_path)
    enricher = Enricher(geoip=cfg.geoip_enabled, abuseipdb_key=cfg.abuseipdb_key)
    notifier = TelegramNotifier(cfg.telegram_token, cfg.telegram_chat_id, cfg.telegram_min_severity)
    pipeline = Pipeline(store, enricher, notifier)
    tasks: list[asyncio.Task] = []
    sensors_status: dict[str, str] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        pipeline.loop = asyncio.get_running_loop()
        if cfg.run_simulator:
            store.clear()  # demo data is regenerated on every start
            n = await AttackSimulator(pipeline.ingest, cfg.demo_rate, seed=None).backfill(cfg.demo_backfill_minutes)
            log.info("demo backfill: %s events", n)
            for i in range(3):  # several concurrent campaigns, like the real internet
                sim = AttackSimulator(pipeline.ingest, cfg.demo_rate)
                tasks.append(asyncio.create_task(sim.run_forever(), name=f"simulator-{i}"))
            sensors_status["simulator"] = "running"
        if cfg.run_sensors:
            await _start_sensors(cfg, pipeline, tasks, sensors_status)
        yield
        for t in tasks:
            t.cancel()
        await enricher.close()

    app = FastAPI(title="HiveWatch SOC", version=__version__, lifespan=lifespan)
    app.state.store, app.state.pipeline, app.state.cfg = store, pipeline, cfg

    # ------------------------------------------------------------ auth
    @app.middleware("http")
    async def auth_and_headers(request: Request, call_next):
        if cfg.dashboard_token and request.url.path != "/healthz":
            token = request.headers.get("x-hivewatch-token") or request.query_params.get("token") \
                or request.cookies.get("hw_token")
            if not (token and secrets.compare_digest(token, cfg.dashboard_token)):
                return JSONResponse({"detail": "invalid or missing token"}, status_code=401)
        response = await call_next(request)
        # The dashboard of a security tool should not itself be an easy target
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path in ("/docs", "/redoc", "/openapi.json"):
            return response  # Swagger UI ships its own inline scripts
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://unpkg.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data: blob: https://unpkg.com https://flagcdn.com; "
            "connect-src 'self' ws: wss: https://unpkg.com; worker-src blob:"
        )
        token = request.query_params.get("token")
        if cfg.dashboard_token and token:
            response.set_cookie("hw_token", token, httponly=True, samesite="strict")
        return response

    # ------------------------------------------------------------ routes
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/meta")
    async def meta():
        return {
            "version": __version__, "mode": cfg.mode,
            "sensor": {"label": cfg.sensor_label, "lat": cfg.sensor_lat, "lon": cfg.sensor_lon},
            "sensors": sensors_status, "telegram": notifier.enabled,
            "abuseipdb": bool(cfg.abuseipdb_key),
        }

    @app.get("/api/stats")
    async def stats():
        return {
            "kpis": store.kpis(),
            "timeline": store.timeline(60),
            "top_countries": store.top("country", limit=10),
            "top_usernames": store.top("username", limit=10),
            "top_passwords": store.top("password", limit=10),
            "top_commands": store.top("command", "event_type='command'", limit=10),
            "top_paths": store.top("path", "event_type='http_request'", limit=8),
            "sensors": store.top("sensor", limit=10),
            "ports": store.top("dst_port", limit=12),
            "attackers": store.attackers(15),
            "mitre": store.mitre_matrix(),
            "geo": store.geo_points(3600),
        }

    @app.get("/api/events")
    async def events(limit: int = Query(100, le=1000)):
        return store.recent_events(limit)

    @app.get("/api/alerts")
    async def alerts(limit: int = Query(50, le=500)):
        return store.recent_alerts(limit)

    @app.get("/api/attacker/{ip}")
    async def attacker(ip: str):
        return store.attacker_profile(ip)

    @app.get("/api/iocs")
    async def iocs(fmt: str = Query("json", pattern="^(json|csv|txt)$")):
        data = store.iocs()
        if fmt == "txt":  # plain blocklist, e.g. for ipset / firewall import
            lines = [f"# HiveWatch blocklist ({'DEMO DATA - do not deploy' if cfg.run_simulator else 'live'})"]
            lines += [r["src_ip"] for r in data["ips"] if cfg.run_simulator or not r["simulated"]]
            return PlainTextResponse("\n".join(lines) + "\n")
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["type", "value", "hits", "simulated"])
            for r in data["ips"]:
                w.writerow(["ipv4", r["src_ip"], r["hits"], bool(r["simulated"])])
            for u in data["urls"]:
                w.writerow(["url", u["url"], u["hits"], cfg.run_simulator])
            return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                                     headers={"Content-Disposition": "attachment; filename=hivewatch_iocs.csv"})
        return data

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        if cfg.dashboard_token:
            token = websocket.query_params.get("token") or websocket.cookies.get("hw_token")
            if not (token and secrets.compare_digest(token, cfg.dashboard_token)):
                await websocket.close(code=4401)
                return
        await websocket.accept()
        q = pipeline.subscribe()
        try:
            while True:
                msg = await q.get()
                await websocket.send_json(msg)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            pipeline.unsubscribe(q)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


async def _start_sensors(cfg: Settings, pipeline: Pipeline, tasks: list, status: dict) -> None:
    from .sensors.network import TelnetHoneypot, TripwirePorts
    from .sensors.ssh import SSHHoneypot
    from .sensors.web import build_http_honeypot

    try:
        SSHHoneypot(cfg.sensor_host, cfg.ssh_port, cfg.data_dir, cfg.hostname,
                    pipeline.submit_threadsafe).start()
        status["ssh"] = f"listening :{cfg.ssh_port}"
    except OSError as exc:
        status["ssh"] = f"error: {exc}"
    try:
        await TelnetHoneypot(cfg.sensor_host, cfg.telnet_port, pipeline.ingest).start()
        status["telnet"] = f"listening :{cfg.telnet_port}"
    except OSError as exc:
        status["telnet"] = f"error: {exc}"
    await TripwirePorts(cfg.sensor_host, cfg.tcp_ports, pipeline.ingest).start()
    status["tcp"] = "listening :" + ",".join(map(str, cfg.tcp_ports))

    http_app = build_http_honeypot(pipeline.ingest, cfg.http_port)
    server = uvicorn.Server(uvicorn.Config(http_app, host=cfg.sensor_host, port=cfg.http_port,
                                           log_level="warning", access_log=False,
                                           proxy_headers=False, server_header=False))
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    tasks.append(asyncio.create_task(server.serve(), name="http-honeypot"))
    status["http"] = f"listening :{cfg.http_port}"
