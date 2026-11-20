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
        self.hibp_key = os.environ.get("HIBP_API_KEY", "").strip()
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
            mx_result, gravatar_result, hibp_result = await asyncio.gather(
                self._mx_lookup(domain),
                self._check_gravatar(client, email),
                self._check_hibp(client, email),
            )

        findings.extend(mx_result)
        findings.extend(gravatar_result)
        findings.extend(hibp_result)

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
                "hibp_key_present": bool(self.hibp_key),
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

    async def _check_hibp(self, client, email: str) -> List[Dict[str, Any]]:
        if not self.hibp_key:
            return [{
                "check": "hibp",
                "category": "breaches",
                "status": "skipped",
                "detail": "Set HIBP_API_KEY env var to enable breach checks.",
            }]

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        try:
            resp = await client.get(
                url,
                headers={"hibp-api-key": self.hibp_key, "User-Agent": "Sent-Eye"},
                params={"truncateResponse": "false"},
            )
            if resp.status_code == 404:
                return [{
                    "check": "hibp",
                    "category": "breaches",
                    "status": "ok",
                    "detail": "No breaches found in Have I Been Pwned.",
                }]
            if resp.status_code == 401:
                return [{
                    "check": "hibp",
                    "category": "breaches",
                    "status": "error",
                    "detail": "HIBP API key rejected.",
                }]
            if resp.status_code == 429:
                return [{
                    "check": "hibp",
                    "category": "breaches",
                    "status": "warning",
                    "detail": "HIBP rate-limited — try again later.",
                }]
            if resp.status_code != 200:
                return [{
                    "check": "hibp",
                    "category": "breaches",
                    "status": "error",
                    "detail": f"HIBP returned HTTP {resp.status_code}.",
                }]

            breaches = resp.json()
            return [{
                "check": "hibp",
                "category": "breaches",
                "status": "breached",
                "detail": f"Found in {len(breaches)} known breach(es).",
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "title": b.get("Title"),
                        "date": b.get("BreachDate"),
                        "pwn_count": b.get("PwnCount"),
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in breaches[:20]
                ],
            }]
        except Exception as exc:
            return [{
                "check": "hibp",
                "category": "breaches",
                "status": "error",
                "detail": f"HIBP lookup failed: {type(exc).__name__}",
            }]
