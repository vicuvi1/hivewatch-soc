"""Threat-intel enrichment: GeoIP / ASN (ip-api.com) and reputation (AbuseIPDB).

Both lookups are cached per IP, rate-limit friendly and fail open: if an
external service is down, the event is still recorded without enrichment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time

import httpx

from .models import Event

log = logging.getLogger("hivewatch.enrichment")


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


class Enricher:
    GEO_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,org"
    ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, geoip: bool = True, abuseipdb_key: str = "") -> None:
        self.geoip = geoip
        self.abuseipdb_key = abuseipdb_key
        self._geo_cache: dict[str, dict | None] = {}
        self._abuse_cache: dict[str, int | None] = {}
        self._geo_lock = asyncio.Lock()
        self._last_geo_call = 0.0
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=4.0, headers={"User-Agent": "hivewatch-soc"})
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    async def enrich(self, ev: Event) -> Event:
        if ev.lat is not None or not is_public(ev.src_ip):
            if ev.country is None and not is_public(ev.src_ip):
                ev.country, ev.country_code, ev.city = "Private network", "LAN", "Local"
            return ev
        if self.geoip:
            geo = await self._geo(ev.src_ip)
            if geo:
                ev.country = geo.get("country")
                ev.country_code = geo.get("countryCode")
                ev.city = geo.get("city")
                ev.lat = geo.get("lat")
                ev.lon = geo.get("lon")
                ev.org = geo.get("as") or geo.get("org")
        if self.abuseipdb_key:
            ev.abuse_score = await self._abuse(ev.src_ip)
        return ev

    async def _geo(self, ip: str) -> dict | None:
        if ip in self._geo_cache:
            return self._geo_cache[ip]
        async with self._geo_lock:
            if ip in self._geo_cache:
                return self._geo_cache[ip]
            # ip-api free tier: 45 req/min -> keep >= 1.4 s between calls
            wait = 1.4 - (time.monotonic() - self._last_geo_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_geo_call = time.monotonic()
            try:
                client = await self._http()
                r = await client.get(self.GEO_URL.format(ip=ip))
                data = r.json()
                result = data if data.get("status") == "success" else None
            except Exception as exc:  # network errors must never break ingestion
                log.debug("geoip lookup failed for %s: %s", ip, exc)
                return None
            self._geo_cache[ip] = result
            return result

    async def _abuse(self, ip: str) -> int | None:
        if ip in self._abuse_cache:
            return self._abuse_cache[ip]
        try:
            client = await self._http()
            r = await client.get(
                self.ABUSE_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
            )
            score = int(r.json()["data"]["abuseConfidenceScore"])
        except Exception as exc:
            log.debug("abuseipdb lookup failed for %s: %s", ip, exc)
            score = None
        self._abuse_cache[ip] = score
        return score
