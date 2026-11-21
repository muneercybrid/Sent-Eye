import asyncio
import hashlib
import os
import re
from typing import Any, Dict, List

import httpx

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from .base import BaseModule, ModuleResult, ModuleStatus, TargetType


USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

ROLE_LOCAL_PARTS = {
    "admin", "administrator", "webmaster", "hostmaster", "postmaster",
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "support", "info", "sales", "contact", "hello", "team", "help",
    "billing", "abuse", "security", "privacy", "legal", "marketing",
    "office", "jobs", "careers", "hr", "newsletter", "notifications",
    "mailer-daemon", "root", "ftp", "www", "api", "dev", "developers",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "spam4.me", "trashmail.com", "maildrop.cc", "getnada.com",
    "mintemail.com", "tempinbox.com", "mytemp.email", "fakeinbox.com",
    "mailnesia.com", "temp-mail.org", "tempmailo.com", "dispostable.com",
    "mailcatch.com", "spambox.us", "spamgourmet.com", "throwaway.email",
    "emailondeck.com", "burnermail.io", "mail-temp.com", "moakt.com",
    "inboxkitten.com", "mailsac.com", "tempr.email", "discard.email",
}


class EmailModule(BaseModule):
    name = "email_intel"
    description = "Validates an email; checks MX, Gravatar, breaches, and role/disposable status."
    target_types = {TargetType.EMAIL}

    def __init__(self):
        try:
            self.timeout = float(os.environ.get("SENT_EYE_EMAIL_TIMEOUT", "10"))
        except ValueError:
            self.timeout = 10.0

    async def run(self, target: str) -> ModuleResult:
        email = target.strip().lower()
        findings: List[Dict[str, Any]] = []
        warnings: List[str] = []

        if not EMAIL_RE.match(email):
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Invalid email format: {target!r}"],
            )

        local, _, domain = email.rpartition("@")

        findings.append({
            "check": "format",
            "category": "validation",
            "status": "ok",
            "detail": "Email format is valid.",
        })

        is_role = local in ROLE_LOCAL_PARTS
        is_disposable = domain in DISPOSABLE_DOMAINS
        if is_role:
            findings.append({
                "check": "role_account",
                "category": "validation",
                "status": "detected",
                "detail": f"'{local}' is a role-based local part (shared inbox).",
            })
        if is_disposable:
            findings.append({
                "check": "disposable",
                "category": "validation",
                "status": "detected",
                "detail": f"'{domain}' is a known disposable email provider.",
            })

        headers = {"User-Agent": USER_AGENT}
        async with httpx.AsyncClient(
            headers=headers, timeout=self.timeout, follow_redirects=True
        ) as client:
            mx_result, gravatar_result, xon_result = await asyncio.gather(
                self._mx_lookup(domain),
                self._check_gravatar(client, email),
                self._check_xposedornot(client, email),
            )

        findings.extend(mx_result)
        findings.extend(gravatar_result)
        findings.extend(xon_result)

        if not HAS_DNS:
            warnings.append(
                "dnspython not installed — MX checks skipped. "
                "Install with: pip install dnspython"
            )

        has_errors = any(f.get("status") == "error" for f in findings)
        if has_errors and len(findings) > 1:
            status = ModuleStatus.PARTIAL
        elif len(findings) > 1:
            status = ModuleStatus.SUCCESS
        else:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "email": email,
                "local": local,
                "domain": domain,
                "checks_run": len(findings),
                "is_role_account": is_role,
                "is_disposable": is_disposable,
                "breach_intel_provider": "XposedOrNot",
            },
            warnings=warnings,
        )

    async def _mx_lookup(self, domain: str) -> List[Dict[str, Any]]:
        if not HAS_DNS:
            return []

        loop = asyncio.get_running_loop()

        def do_lookup():
            try:
                answers = dns.resolver.resolve(domain, "MX", lifetime=5)
                mx = sorted(
                    [(int(r.preference), str(r.exchange).rstrip(".")) for r in answers],
                    key=lambda x: x[0],
                )
                return ("ok", mx)
            except dns.resolver.NXDOMAIN:
                return ("nxdomain", None)
            except dns.resolver.NoAnswer:
                return ("no_mx", None)
            except Exception as exc:
                return ("error", f"{type(exc).__name__}: {exc}")

        kind, data = await loop.run_in_executor(None, do_lookup)

        if kind == "ok" and data:
            return [{
                "check": "mx",
                "category": "domain",
                "status": "ok",
                "detail": f"{len(data)} MX record(s) — domain accepts mail.",
                "records": [{"priority": p, "host": h} for p, h in data],
            }]
        if kind == "no_mx":
            return [{
                "check": "mx",
                "category": "domain",
                "status": "warning",
                "detail": "No MX records — domain likely does not accept mail.",
            }]
        if kind == "nxdomain":
            return [{
                "check": "mx",
                "category": "domain",
                "status": "error",
                "detail": "Domain does not exist (NXDOMAIN).",
            }]
        return [{
            "check": "mx",
            "category": "domain",
            "status": "error",
            "detail": f"MX lookup failed: {data}",
        }]

    async def _check_gravatar(self, client, email: str) -> List[Dict[str, Any]]:
        md5 = hashlib.md5(email.encode()).hexdigest()
        avatar_url = f"https://www.gravatar.com/avatar/{md5}?d=404&s=200"
        profile_url = f"https://www.gravatar.com/{md5}.json"

        try:
            resp = await client.get(avatar_url)
            if resp.status_code == 404:
                return [{
                    "check": "gravatar",
                    "category": "profile",
                    "status": "none",
                    "detail": "No Gravatar profile for this email.",
                    "url": avatar_url,
                }]
            if resp.status_code != 200:
                return [{
                    "check": "gravatar",
                    "category": "profile",
                    "status": "error",
                    "detail": f"Gravatar returned HTTP {resp.status_code}.",
                }]

            finding: Dict[str, Any] = {
                "check": "gravatar",
                "category": "profile",
                "status": "ok",
                "detail": "Gravatar profile exists.",
                "url": avatar_url,
                "profile_json": profile_url,
            }

            try:
                prof_resp = await client.get(profile_url)
                if prof_resp.status_code == 200:
                    data = prof_resp.json()
                    entry = (data.get("entry") or [{}])[0]
                    display = entry.get("displayName") or entry.get("preferredUsername")
                    name_block = entry.get("name") or {}
                    full_name = name_block.get("formatted") if isinstance(name_block, dict) else None
                    if display:
                        finding["display_name"] = display
                    if full_name:
                        finding["full_name"] = full_name
                    urls = entry.get("urls") or []
                    if urls:
                        finding["urls"] = [u.get("value") for u in urls if isinstance(u, dict)]
                    about = entry.get("aboutMe")
                    if about:
                        finding["about"] = about[:500]
            except Exception:
                pass

            return [finding]

        except Exception as exc:
            return [{
                "check": "gravatar",
                "category": "profile",
                "status": "error",
                "detail": f"Gravatar lookup failed: {type(exc).__name__}",
            }]

    async def _check_xposedornot(
        self, client, email: str
    ) -> List[Dict[str, Any]]:
        """Retrieve email breach analytics from XposedOrNot."""

        url = "https://api.xposedornot.com/v1/breach-analytics"

        try:
            resp = await client.get(url, params={"email": email})

            if resp.status_code == 404:
                return [{
                    "check": "xposedornot",
                    "category": "breaches",
                    "status": "ok",
                    "detail": "No matching breach records were found.",
                    "provider": "XposedOrNot",
                    "breach_count": 0,
                }]

            if resp.status_code == 429:
                return [{
                    "check": "xposedornot",
                    "category": "breaches",
                    "status": "warning",
                    "detail": (
                        "XposedOrNot rate limit reached. "
                        "Retry after the provider's limit resets."
                    ),
                    "provider": "XposedOrNot",
                }]

            if resp.status_code in (502, 503, 504):
                return [{
                    "check": "xposedornot",
                    "category": "breaches",
                    "status": "warning",
                    "detail": (
                        f"XposedOrNot is temporarily unavailable "
                        f"(HTTP {resp.status_code})."
                    ),
                    "provider": "XposedOrNot",
                }]

            if resp.status_code != 200:
                return [{
                    "check": "xposedornot",
                    "category": "breaches",
                    "status": "error",
                    "detail": (
                        f"XposedOrNot returned HTTP {resp.status_code}."
                    ),
                    "provider": "XposedOrNot",
                }]

            payload = resp.json()
            if not isinstance(payload, dict):
                raise ValueError("Unexpected API response format")

            exposed = payload.get("ExposedBreaches") or {}
            if not isinstance(exposed, dict):
                exposed = {}

            raw_breaches = exposed.get("breaches_details") or []
            if not isinstance(raw_breaches, list):
                raw_breaches = []

            breaches = []
            for item in raw_breaches[:100]:
                if not isinstance(item, dict):
                    continue

                raw_data = item.get("xposed_data") or ""
                if isinstance(raw_data, str):
                    data_classes = [
                        value.strip()
                        for value in raw_data.split(";")
                        if value.strip()
                    ]
                elif isinstance(raw_data, list):
                    data_classes = [
                        str(value) for value in raw_data if value
                    ]
                else:
                    data_classes = []

                breaches.append({
                    "name": item.get("breach"),
                    "title": item.get("breach"),
                    "date": item.get("xposed_date"),
                    "domain": item.get("domain"),
                    "industry": item.get("industry"),
                    "pwn_count": item.get("xposed_records"),
                    "data_classes": data_classes,
                    "description": item.get("details"),
                    "password_risk": item.get("password_risk"),
                    "verified": item.get("verified"),
                    "searchable": item.get("searchable"),
                    "reference_url": item.get("references"),
                    "logo": item.get("logo"),
                })

            summary = payload.get("BreachesSummary") or {}
            if not isinstance(summary, dict):
                summary = {}

            metrics = payload.get("BreachMetrics") or {}
            if not isinstance(metrics, dict):
                metrics = {}

            risk_items = metrics.get("risk") or []
            risk = risk_items[0] if (
                isinstance(risk_items, list) and risk_items
                and isinstance(risk_items[0], dict)
            ) else {}

            password_items = metrics.get("passwords_strength") or []
            password_strength = password_items[0] if (
                isinstance(password_items, list) and password_items
                and isinstance(password_items[0], dict)
            ) else {}

            paste_summary = payload.get("PastesSummary") or {}
            if not isinstance(paste_summary, dict):
                paste_summary = {}

            paste_count = paste_summary.get("cnt", 0)
            try:
                paste_count = int(paste_count or 0)
            except (TypeError, ValueError):
                paste_count = 0

            summary_site = summary.get("site")
            has_breach_data = bool(
                breaches or summary_site or metrics
            )
            has_paste_data = paste_count > 0

            if not has_breach_data and not has_paste_data:
                return [{
                    "check": "xposedornot",
                    "category": "breaches",
                    "status": "ok",
                    "detail": (
                        "No matching email breaches or paste exposures "
                        "were found in XposedOrNot."
                    ),
                    "provider": "XposedOrNot",
                    "breach_count": 0,
                    "paste_count": 0,
                }]

            detail_parts = []
            if breaches:
                detail_parts.append(
                    f"Found {len(breaches)} breach record(s)."
                )
            if has_paste_data:
                detail_parts.append(
                    f"Found {paste_count} paste exposure(s)."
                )

            finding = {
                "check": "xposedornot",
                "category": "breaches",
                "status": "breached",
                "detail": " ".join(detail_parts),
                "provider": "XposedOrNot",
                "breach_count": len(breaches),
                "breaches": breaches,
                "risk": {
                    "label": risk.get("risk_label"),
                    "score": risk.get("risk_score"),
                },
                "password_strength": password_strength,
                "paste_count": paste_count,
                "paste_summary": {
                    "domain": paste_summary.get("domain"),
                    "latest": paste_summary.get("tmpstmp"),
                },
                "attribution": "Breach intelligence provided by XposedOrNot.",
            }

            return [finding]

        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            return [{
                "check": "xposedornot",
                "category": "breaches",
                "status": "warning",
                "detail": (
                    f"XposedOrNot network request failed: "
                    f"{type(exc).__name__}."
                ),
                "provider": "XposedOrNot",
            }]
        except (ValueError, TypeError) as exc:
            return [{
                "check": "xposedornot",
                "category": "breaches",
                "status": "warning",
                "detail": (
                    "XposedOrNot returned an unexpected response: "
                    f"{type(exc).__name__}."
                ),
                "provider": "XposedOrNot",
            }]
        except Exception as exc:
            return [{
                "check": "xposedornot",
                "category": "breaches",
                "status": "error",
                "detail": (
                    f"XposedOrNot lookup failed: {type(exc).__name__}."
                ),
                "provider": "XposedOrNot",
            }]
