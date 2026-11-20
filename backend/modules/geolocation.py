import asyncio
import json
import subprocess
from typing import Any, Dict, List, Optional

import httpx

from .base import BaseModule, ModuleResult, ModuleStatus


NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"
# Nominatim's usage policy requires a descriptive User-Agent.
# For personal/dev use this is fine; for public deployment, add contact info.
USER_AGENT = "Sent-Eye/0.1 (https://github.com/muneercybrid/Sent-Eye)"


def _extract_coord(raw_value: Any, ref: Optional[str]) -> Optional[float]:
    """Normalize a GPS coordinate to signed decimal degrees.

    Handles decimal numbers (from exiftool -n), DMS lists, and DMS strings.
    """
    value: Optional[float] = None

    if isinstance(raw_value, (int, float)):
        value = float(raw_value)
    elif isinstance(raw_value, list) and len(raw_value) >= 3:
        try:
            value = (
                float(raw_value[0])
                + float(raw_value[1]) / 60.0
                + float(raw_value[2]) / 3600.0
            )
        except (TypeError, ValueError):
            return None
    elif isinstance(raw_value, str):
        try:
            value = float(raw_value)
        except ValueError:
            return None

    if value is None:
        return None

    if ref and ref.strip().upper() in ("S", "W"):
        value = -abs(value)
    else:
        value = abs(value)

    return round(value, 7)


class GeolocationModule(BaseModule):
    name = "geolocation"
    description = "Extracts GPS, builds map links, and reverse-geocodes the location."

    async def run(self, image_path: str) -> ModuleResult:
        # 1. Pull GPS tags from the image via exiftool
        try:
            process = await asyncio.create_subprocess_exec(
                "exiftool", "-json", "-n", "-GPS:all", image_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
        except FileNotFoundError:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=["ExifTool is not installed (sudo apt install libimage-exiftool-perl)."],
            )

        if process.returncode != 0:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[stderr.decode().strip() or "exiftool failed."],
            )

        try:
            records: List[Dict[str, Any]] = json.loads(stdout.decode() or "[]")
        except json.JSONDecodeError as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Could not parse exiftool output: {exc}"],
            )

        if not records:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["No GPS metadata returned by exiftool."],
            )

        gps = records[0]

        # 2. Extract coordinates
        lat = _extract_coord(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
        lon = _extract_coord(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))

        if lat is None or lon is None:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                metadata={"gps_tags_present": bool(gps)},
                errors=["Image does not contain usable GPS coordinates."],
            )

        # 3. Build the finding with map links
        finding: Dict[str, Any] = {
            "source": "exiftool",
            "type": "gps_coordinates",
            "latitude": lat,
            "longitude": lon,
            "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
            "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
            "raw_gps_tags": {k: v for k, v in gps.items() if k.startswith("GPS")},
        }

        # 4. Reverse geocode (optional — graceful failure)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    NOMINATIM_URL,
                    params={"lat": lat, "lon": lon, "format": "json", "zoom": 18},
                    headers={"User-Agent": USER_AGENT},
                )
                if resp.status_code == 200:
                    geo = resp.json()
                    finding["address"] = geo.get("display_name")
                    finding["address_components"] = geo.get("address", {})
                else:
                    finding["geocoding_error"] = f"Nominatim HTTP {resp.status_code}"
        except Exception as exc:
            finding["geocoding_error"] = f"{type(exc).__name__}: {exc}"

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[finding],
            metadata={"tools": ["exiftool", "nominatim"]},
        )
