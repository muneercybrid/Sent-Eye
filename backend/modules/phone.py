import os
from typing import Any, Dict, List

import httpx

try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import timezone as pn_timezone
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False

from .base import BaseModule, ModuleResult, ModuleStatus, TargetType


USER_AGENT = "Sent Eye/0.1 (https://github.com/muneercybrid/sent-eye)"
ABSTRACTAPI_URL = "https://phoneintelligence.abstractapi.com/v1/"


def _line_type_label(parsed):
    if not HAS_PHONENUMBERS:
        return "Unknown"
    nt = phonenumbers.number_type(parsed)
    labels = {
        phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed line",
        phonenumbers.PhoneNumberType.MOBILE: "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "Shared cost",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
        phonenumbers.PhoneNumberType.PAGER: "Pager",
        phonenumbers.PhoneNumberType.UAN: "Universal access number",
        phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
        phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
    }
    return labels.get(nt, "Unknown")


class PhoneModule(BaseModule):
    name = "phone_intel"
    description = "Parses a phone number; resolves region, line type, carrier, and timezones."
    target_types = {TargetType.PHONE}

    def __init__(self):
        self.abstract_key = os.environ.get("ABSTRACTAPI_KEY", "").strip()
        self.default_region = os.environ.get("SENT_EYE_PHONE_REGION", "US").strip() or "US"
        try:
            self.timeout = float(os.environ.get("SENT_EYE_PHONE_TIMEOUT", "10"))
        except ValueError:
            self.timeout = 10.0

    async def run(self, target: str) -> ModuleResult:
        if not HAS_PHONENUMBERS:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[
                    "phonenumbers library not installed. "
                    "Install with: pip install phonenumbers"
                ],
            )

        raw = target.strip()
        if not raw:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=["Empty phone number."],
            )

        parse_region = None if raw.startswith("+") else self.default_region
        try:
            parsed = phonenumbers.parse(raw, parse_region)
        except phonenumbers.NumberParseException as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Could not parse phone number: {exc}"],
            )

        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)
        region = phonenumbers.region_code_for_number(parsed) or ""

        line_type = _line_type_label(parsed)
        carrier_name = ""
        location = ""
        timezones: List[str] = []
        try:
            carrier_name = pn_carrier.name_for_number(parsed, "en") or ""
        except Exception:
            pass
        try:
            location = pn_geocoder.description_for_number(parsed, "en") or ""
        except Exception:
            pass
        try:
            timezones = sorted(pn_timezone.time_zones_for_number(parsed) or [])
        except Exception:
            pass

        identity_finding: Dict[str, Any] = {
            "check": "phonenumbers",
            "category": "identity",
            "status": "ok" if valid else "warning",
            "detail": (
                "Valid phone number for its region."
                if valid
                else (
                    "Number is possible but not valid for its region."
                    if possible
                    else "Number is not valid for its region."
                )
            ),
            "valid": valid,
            "possible": possible,
            "region": region,
            "country_code": parsed.country_code,
            "national_number": str(parsed.national_number),
            "international": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "national": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            ),
            "e164": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            ),
            "line_type": line_type,
            "carrier": carrier_name or None,
            "location": location or None,
            "timezones": timezones,
        }

        findings: List[Dict[str, Any]] = [identity_finding]
        warnings: List[str] = []

        if self.abstract_key:
            abs_finding = await self._abstractapi_lookup(
                identity_finding["e164"], identity_finding
            )
            if abs_finding:
                findings.append(abs_finding)
        else:
            warnings.append(
                "AbstractAPI key not set — using offline phonenumbers data only. "
                "Set ABSTRACTAPI_KEY env var for live carrier confirmation."
            )

        if valid:
            status = ModuleStatus.SUCCESS
        elif possible:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.FAILED

        metadata = {
            "input": raw,
            "e164": identity_finding["e164"],
            "region": region,
            "valid": valid,
            "line_type": line_type,
            "carrier": carrier_name or None,
            "abstractapi_used": bool(self.abstract_key),
            "default_region": self.default_region,
        }

        return ModuleResult(
            status=status,
            findings=findings,
            metadata=metadata,
            warnings=warnings,
        )

    async def _abstractapi_lookup(
        self, e164: str, identity: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(
                    ABSTRACTAPI_URL,
                    params={"api_key": self.abstract_key, "phone": e164},
                )
        except Exception as exc:
            return {
                "check": "abstractapi",
                "category": "verification",
                "status": "error",
                "detail": f"AbstractAPI lookup failed: {type(exc).__name__}",
            }

        if resp.status_code == 401:
            return {
                "check": "abstractapi",
                "category": "verification",
                "status": "error",
                "detail": "AbstractAPI key rejected (401). Verify the key is for Phone Intelligence.",
            }
        if resp.status_code == 429:
            return {
                "check": "abstractapi",
                "category": "verification",
                "status": "warning",
                "detail": "AbstractAPI rate-limited (429) — free tier quota may be exhausted.",
            }
        if resp.status_code != 200:
            return {
                "check": "abstractapi",
                "category": "verification",
                "status": "error",
                "detail": f"AbstractAPI returned HTTP {resp.status_code}.",
            }

        try:
            data = resp.json()
        except Exception:
            return {
                "check": "abstractapi",
                "category": "verification",
                "status": "error",
                "detail": "AbstractAPI returned non-JSON.",
            }

        if data.get("error"):
            err = data["error"]
            return {
                "check": "abstractapi",
                "category": "verification",
                "status": "error",
                "detail": f"AbstractAPI error: {err.get('message', err)}",
            }

        # Phone Intelligence response structure (nested objects)
        pv = data.get("phone_validation") or {}
        pc = data.get("phone_carrier") or {}
        pl = data.get("phone_location") or {}
        pm = data.get("phone_messaging") or {}
        pr = data.get("phone_registration") or {}
        prisk = data.get("phone_risk") or {}
        pbreach = data.get("phone_breaches") or {}
        pf = data.get("phone_format") or {}

        is_valid = bool(pv.get("is_valid"))
        line_status = pv.get("line_status") or ""
        is_voip = bool(pv.get("is_voip"))
        line_type_live = pc.get("line_type") or ""
        carrier_live = pc.get("name") or ""
        location_parts = [pl.get("city"), pl.get("region"), pl.get("country_name")]
        location_live = ", ".join(p for p in location_parts if p)
        country_name = pl.get("country_name") or ""
        risk_level = prisk.get("risk_level") or ""
        is_disposable = bool(prisk.get("is_disposable"))
        is_abuse = bool(prisk.get("is_abuse_detected"))
        registration_name = pr.get("name") or ""
        registration_type = pr.get("type") or ""
        total_breaches = pbreach.get("total_breaches")
        breached_domains = pbreach.get("breached_domains") or []

        if is_valid:
            status = "ok"
            detail = "Confirmed valid and active by AbstractAPI Phone Intelligence."
        elif line_status == "disconnected":
            status = "warning"
            detail = "AbstractAPI reports this number as disconnected."
        else:
            status = "warning"
            detail = "AbstractAPI reports this number as invalid."

        return {
            "check": "abstractapi",
            "category": "verification",
            "status": status,
            "detail": detail,
            "valid_live": is_valid,
            "line_status_live": line_status,
            "is_voip": is_voip,
            "carrier_live": carrier_live or None,
            "location_live": location_live or None,
            "line_type_live": line_type_live or None,
            "country_name": country_name or None,
            "international_format": pf.get("international"),
            "national_format": pf.get("national"),
            "mcc": pc.get("mcc"),
            "mnc": pc.get("mnc"),
            "sms_domain": pm.get("sms_domain") if pm.get("sms_domain") not in (None, "", "unknown") else None,
            "sms_email": pm.get("sms_email") if pm.get("sms_email") not in (None, "", "unknown") else None,
            "registration_name": registration_name or None,
            "registration_type": registration_type or None,
            "risk_level": risk_level or None,
            "is_disposable": is_disposable,
            "is_abuse_detected": is_abuse,
            "total_breaches": total_breaches,
            "breached_domains": breached_domains,
        }
