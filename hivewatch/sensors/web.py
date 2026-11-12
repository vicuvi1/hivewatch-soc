"""HTTP honeypot: a fake router/admin login page that logs every request."""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from ..models import Event

log = logging.getLogger("hivewatch.http")

Emit = Callable[[Event], Awaitable[object]]

LOGIN_PAGE = """<!doctype html><html><head><title>NetGate Pro AX3000 — Admin</title>
<style>body{font-family:Arial;background:#eef1f5;display:flex;justify-content:center;padding-top:10vh}
form{background:#fff;padding:32px;border-radius:6px;box-shadow:0 2px 12px #0002;width:300px}
input{width:100%;padding:8px;margin:6px 0 14px;box-sizing:border-box}button{width:100%;padding:10px;
background:#1565c0;color:#fff;border:0;border-radius:4px}</style></head><body>
<form method="post" action="/login"><h3>NetGate Pro — Router Login</h3>
<label>Username</label><input name="username"><label>Password</label>
<input name="password" type="password"><button>Log in</button>
<p style="font-size:11px;color:#888">Firmware v2.0.4.118</p></form></body></html>"""


def build_http_honeypot(emit: Emit, dst_port: int) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
    async def catch_all(request: Request, path: str):
        ip = request.client.host if request.client else "0.0.0.0"
        port = request.client.port if request.client else 0
        full_path = str(request.url.path) + (f"?{request.url.query}" if request.url.query else "")
        ua = request.headers.get("user-agent", "")[:300]
        username = password = None
        if request.method == "POST":
            try:
                form = await request.form()
                username = str(form.get("username") or form.get("log") or form.get("user") or "")[:64] or None
                password = str(form.get("password") or form.get("pwd") or form.get("pass") or "")[:128] or None
            except Exception as exc:  # malformed bodies are expected from scanners
                log.debug("could not parse form body from %s: %s", ip, exc)
        await emit(Event(sensor="http", event_type="http_request", src_ip=ip, src_port=port,
                         dst_port=dst_port, http_method=request.method, path=full_path[:500],
                         user_agent=ua))
        if username or password:
            await emit(Event(sensor="http", event_type="login_failed", src_ip=ip, src_port=port,
                             dst_port=dst_port, username=username, password=password,
                             http_method=request.method, path=full_path[:500], user_agent=ua))
            return HTMLResponse(LOGIN_PAGE.replace("<h3>", "<p style='color:red'>Invalid credentials</p><h3>"),
                                status_code=401)
        headers = {"Server": "lighttpd/1.4.59"}
        return HTMLResponse(LOGIN_PAGE, headers=headers)

    return app
