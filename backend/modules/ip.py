import asyncio
import ipaddress
import os
import socket
from typing import Any, Dict, List, Optional

import httpx

try:
    from ipgeolocateio import Client as IpGeoClient
    HAS_IPGEO = True
except ImportError:
    HAS_IPGEO = False

from .base import BaseModule, ModuleResult, ModuleStatus, TargetType


USER_AGENT = "Sent Eye/0.1 (https://github.com/muneercybrid/sent-eye)"


class IPModule(BaseModule):
    name = "ip_intel"
    description = "Resolves geolocation, ASN, reverse DNS, and threat signals for an IP address."
    target_types = {TargetType.IP}

    def __init__(self):
        try:
            self.timeout = float(os.environ.get("SENT_EYE_IP_TIMEOUT", "10"))
        except ValueError:
            self.timeout = 10.0
        self.client = IpGeoClient() if HAS_IPGEO else None

    async def run(self, target: str) -> ModuleResult:
        raw = target.strip()

        try:
            ip_obj = ipaddress.ip_address(raw)
        except ValueError:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Invalid IP address: {target!r}"],
            )

        is_private = ip_obj.is_private
        is_reserved = ip_obj.is_reserved
        is_loopback = ip_obj.is_loopback
        version = ip_obj.version

        findings: List[Dict[str, Any]] = []
        warnings: List[str] = []

        # Core identity finding
        identity = {
            "check": "identity",
            "category": "identity",
            "status": "ok",
            "ip": str(ip_obj),
            "version": version,
            "is_private": is_private,
            "is_reserved": is_reserved,
            "is_loopback": is_loopback,
        }
        findings.append(identity)

        if is_private or is_reserved or is_loopback:
            warnings.append(
                "This IP is private/reserved/loopback — public geolocation APIs will not return data."
            )
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=findings,
                metadata={"ip": str(ip_obj), "version": version},
                warnings=warnings,
            )

        # Reverse DNS (local, no external API)
        rev_dns = await self._reverse_dns(str(ip_obj))
        if rev_dns:
            findings.append({
                "check": "reverse_dns",
                "category": "network",
                "status": "ok",
                "detail": rev_dns,
            })

        # Primary: ipgeolocationapi.io (keyless, 5k/day)
        geo_finding = await self._ipgeo_lookup(str(ip_obj))
        if geo_finding:
            findings.append(geo_finding)
        else:
            warnings.append("Primary IP API (ipgeolocationapi.io) failed or returned no data.")

        # Fallback: ipdata.info (keyless, 50/min)
        if not geo_finding or geo_finding.get("status") != "ok":
            fallback = await self._ipdata_lookup(str(ip_obj))
            if fallback:
                findings.append(fallback)
            else:
                warnings.append("Fallback IP API (ipdata.info) also failed.")

        # Additional: ipinfo.io (tokenless, 1k/day shared)
        if not any(f.get("status") == "ok" for f in findings if f.get("category") == "geo"):
            ipinfo = await self._ipinfo_lookup(str(ip_obj))
            if ipinfo:
                findings.append(ipinfo)

        geo_ok = any(f.get("status") == "ok" for f in findings if f.get("category") == "geo")
        status = ModuleStatus.SUCCESS if geo_ok else ModuleStatus.PARTIAL

        metadata = {
            "ip": str(ip_obj),
            "version": version,
            "is_private": is_private,
            "is_reserved": is_reserved,
            "reverse_dns": rev_dns,
            "primary_source": "ipgeolocationapi.io",
            "fallback_used": not geo_ok,
        }

        return ModuleResult(
            status=status,
            findings=findings,
            metadata=metadata,
            warnings=warnings,
        )

    async def _reverse_dns(self, ip: str) -> Optional[str]:
        try:
            return await asyncio.get_running_loop().run_in_executor(
                None, lambda: socket.gethostbyaddr(ip)[0]
            )
        except Exception:
            return None

    async def _ipgeo_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.client:
            return None
        try:
            data = await asyncio.get_running_loop().run_in_executor(
                None, lambda: self.client.lookup(ip)
            )
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        country = data.get("country") or {}
        connection = data.get("connection") or {}
        tz = data.get("timezone") or {}
        location = data.get("location") or {}

        return {
            "check": "ipgeolocationapi",
            "category": "geo",
            "status": "ok",
            "detail": "Geolocation resolved via ipgeolocationapi.io.",
            "source": "ipgeolocationapi.io",
            "country": country.get("name"),
            "country_code": country.get("code"),
            "region": location.get("region") or location.get("region_name"),
            "city": location.get("city"),
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
            "timezone": tz.get("id"),
            "asn": connection.get("asn"),
            "org": connection.get("organization") or connection.get("isp"),
            "isp": connection.get("isp"),
        }

    async def _ipdata_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"https://ipdata.info/{ip}"
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
        except Exception:
            return None

        if resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        return {
            "check": "ipdata",
            "category": "geo",
            "status": "ok",
            "detail": "Geolocation resolved via ipdata.info (fallback).",
            "source": "ipdata.info",
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("time_zone", {}).get("name"),
            "asn": data.get("asn", {}).get("asn"),
            "org": data.get("asn", {}).get("name"),
            "isp": data.get("asn", {}).get("route"),
        }

    async def _ipinfo_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"https://ipinfo.io/{ip}/json"
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
        except Exception:
            return None

        if resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        if "bogon" in data or "error" in data:
            return None

        loc = data.get("loc", "")
        lat, lon = (loc.split(",") + [None, None])[:2] if loc else (None, None)

        return {
            "check": "ipinfo",
            "category": "geo",
            "status": "ok",
            "detail": "Geolocation resolved via ipinfo.io (tertiary fallback).",
            "source": "ipinfo.io",
            "country": data.get("country"),
            "country_code": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": lat,
            "longitude": lon,
            "timezone": data.get("timezone"),
            "asn": data.get("org"),
            "org": data.get("org"),
            "isp": data.get("org"),
        }
