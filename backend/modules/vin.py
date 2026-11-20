import asyncio
import os
import re
from typing import Any, Dict, List

import httpx

from .base import BaseModule, ModuleResult, ModuleStatus, TargetType


USER_AGENT = "Sent Eye/0.1 (https://github.com/muneercybrid/sent-eye)"

VPIC_URL = "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json"
RECALLS_URL = "https://api.nhtsa.gov/recalls/recallsByVehicle"

VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")

# Fields we surface prominently in the report (order matters — reading order).
HIGHLIGHT_FIELDS = [
    ("Make", "Make"),
    ("Model", "Model"),
    ("ModelYear", "Year"),
    ("Series", "Series"),
    ("Trim", "Trim"),
    ("BodyClass", "Body class"),
    ("VehicleType", "Vehicle type"),
    ("Doors", "Doors"),
    ("DriveType", "Drive type"),
    ("EngineCylinders", "Cylinders"),
    ("DisplacementL", "Displacement (L)"),
    ("EngineHP", "Horsepower"),
    ("FuelTypePrimary", "Fuel (primary)"),
    ("TransmissionStyle", "Transmission"),
    ("TransmissionSpeeds", "Speeds"),
    ("GVWR", "GVWR"),
    ("SeatBeltsAll", "Seat belts"),
    ("BrakeSystemType", "Brake system"),
    ("AirBagLocFront", "Front airbags"),
    ("AirBagLocSide", "Side airbags"),
    ("PlantCity", "Plant city"),
    ("PlantState", "Plant state"),
    ("PlantCountry", "Plant country"),
    ("PlantCompanyName", "Plant company"),
    ("Manufacturer", "Manufacturer"),
]


class VINModule(BaseModule):
    name = "vin_decode"
    description = "Decodes a VIN via NHTSA vPIC and retrieves official recall data."
    target_types = {TargetType.VIN}

    def __init__(self):
        try:
            self.timeout = float(os.environ.get("SENT_EYE_VIN_TIMEOUT", "15"))
        except ValueError:
            self.timeout = 15.0
        self.fetch_recalls = os.environ.get("SENT_EYE_VIN_RECALLS", "1") != "0"

    async def run(self, target: str) -> ModuleResult:
        vin = target.strip().upper()

        if not VIN_RE.match(vin):
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[
                    f"Invalid VIN: {target!r}. "
                    f"VINs are exactly 17 characters, alphanumeric, "
                    f"and never contain the letters I, O, or Q."
                ],
            )

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        warnings: List[str] = []

        async with httpx.AsyncClient(
            headers=headers, timeout=self.timeout, follow_redirects=True
        ) as client:
            decode = await self._decode(client, vin)
            if decode.get("status") == "error":
                return ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=[decode.get("detail", "NHTSA vPIC decode failed.")],
                )

            finding = decode["finding"]
            findings = [finding]

            recalls_finding = None
            if self.fetch_recalls:
                make = finding.get("decoded", {}).get("Make")
                model = finding.get("decoded", {}).get("Model")
                year = finding.get("decoded", {}).get("ModelYear")
                if make and model and year and year.isdigit():
                    recalls_finding = await self._recalls(client, make, model, year)
                    if recalls_finding:
                        findings.append(recalls_finding)
                else:
                    warnings.append("Skipped recall lookup: make/model/year incomplete.")

        decode_ok = finding.get("status") == "ok"
        if decode_ok:
            status = ModuleStatus.SUCCESS
        else:
            status = ModuleStatus.PARTIAL

        metadata = {
            "vin": vin,
            "wmi": vin[:3],
            "vis": vin[9:],
            "checks_run": len(findings),
            "recalls_fetched": bool(recalls_finding),
        }

        return ModuleResult(
            status=status,
            findings=findings,
            metadata=metadata,
            warnings=warnings,
        )

    async def _decode(self, client, vin: str) -> Dict[str, Any]:
        url = VPIC_URL.format(vin=vin)
        try:
            resp = await client.get(url)
        except httpx.TimeoutException:
            return {"status": "error", "detail": "NHTSA vPIC timed out."}
        except Exception as exc:
            return {"status": "error", "detail": f"{type(exc).__name__}: {exc}"}

        if resp.status_code != 200:
            return {
                "status": "error",
                "detail": f"NHTSA vPIC returned HTTP {resp.status_code}.",
            }

        try:
            payload = resp.json()
        except Exception:
            return {"status": "error", "detail": "NHTSA vPIC returned non-JSON."}

        results = payload.get("Results") or []
        if not results:
            return {"status": "error", "detail": "NHTSA vPIC returned no results."}

        record = results[0]
        error_code = (record.get("ErrorCode") or "").strip()
        error_text = (record.get("ErrorText") or "").strip()

        decoded = {}
        for source_key, _ in HIGHLIGHT_FIELDS:
            value = record.get(source_key)
            if value is None:
                continue
            value_str = str(value).strip()
            if value_str and value_str not in ("Not Applicable", "0", "null"):
                decoded[source_key] = value_str

        # Vehicle photo / brochure URLs are sometimes present.
        photo_url = record.get("VehiclePicture") or record.get("ImageURL") or ""
        if photo_url and photo_url != "Not Applicable":
            decoded["VehiclePicture"] = photo_url

        all_fields = {
            k: v for k, v in record.items()
            if isinstance(v, (str, int, float)) and str(v).strip() not in ("", "Not Applicable")
        }

        status = "ok" if error_code in ("", "0") else "warning"

        return {
            "status": status,
            "finding": {
                "check": "vpic_decode",
                "category": "decode",
                "status": status,
                "detail": (
                    "VIN decoded successfully via NHTSA vPIC."
                    if status == "ok"
                    else f"Partial decode — vPIC error code {error_code}: {error_text}"
                ),
                "decoded": decoded,
                "all_fields": all_fields,
                "error_code": error_code,
                "error_text": error_text,
            },
        }

    async def _recalls(self, client, make: str, model: str, year: str):
        params = {"make": make, "model": model, "modelYear": year}
        try:
            resp = await client.get(RECALLS_URL, params=params)
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except Exception:
            return None

        rows = data.get("results") or data.get("Results") or []
        if not rows:
            return {
                "check": "recalls",
                "category": "recalls",
                "status": "ok",
                "detail": "No open recalls on file with NHTSA.",
                "recalls": [],
            }

        compact = []
        for r in rows[:30]:
            compact.append({
                "campaign": r.get("NHTSACampaignNumber", ""),
                "component": r.get("Component", ""),
                "summary": (r.get("Summary") or "")[:500],
                "consequence": (r.get("Consequence") or "")[:300],
                "remedy": (r.get("Remedy") or "")[:300],
                "report_date": r.get("ReportReceivedDate", ""),
            })

        return {
            "check": "recalls",
            "category": "recalls",
            "status": "open" if compact else "ok",
            "detail": f"{len(compact)} recall(s) on file with NHTSA.",
            "recalls": compact,
        }
