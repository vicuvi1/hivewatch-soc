"""CLI entry point:  python -m hivewatch [--mode demo|live|hybrid] [--port 8000]"""

from __future__ import annotations

import argparse
import logging
import os

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(prog="hivewatch", description="HiveWatch honeypot SOC dashboard")
    parser.add_argument("--mode", choices=["demo", "live", "hybrid"], help="override HW_MODE")
    parser.add_argument("--host", help="dashboard bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="dashboard port (default 8000)")
    args = parser.parse_args()

    if args.mode:
        os.environ["HW_MODE"] = args.mode
    if args.host:
        os.environ["HW_DASH_HOST"] = args.host
    if args.port:
        os.environ["HW_DASH_PORT"] = str(args.port)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    from .app import create_app
    from .config import Settings

    cfg = Settings()
    print(BANNER.format(mode=cfg.mode.upper(), host=cfg.dashboard_host, port=cfg.dashboard_port))
    uvicorn.run(create_app(cfg), host=cfg.dashboard_host, port=cfg.dashboard_port, log_level="warning")


BANNER = r"""
  _   _ _          __        __    _       _
 | | | (_)_   _____\ \      / /_ _| |_ ___| |__
 | |_| | \ \ / / _ \\ \ /\ / / _` | __/ __| '_ \
 |  _  | |\ V /  __/ \ V  V / (_| | || (__| | | |
 |_| |_|_| \_/ \___|  \_/\_/ \__,_|\__\___|_| |_|   honeypot SOC

  mode: {mode}    dashboard: http://{host}:{port}
"""

if __name__ == "__main__":
    main()
