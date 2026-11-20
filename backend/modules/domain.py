import asyncio
import os
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx
import dns.resolver

from .base import BaseModule, ModuleResult, ModuleStatus, TargetType


USER_AGENT = "Sent Eye/0.1 (https://github.com/muneercybrid/sent-eye)"
RDAP_URL = "https://rdap.org/domain/{domain}"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
)


def _clean_domain(raw: str) -> str:
    """Extract apex domain from a URL or domain string."""
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc
    else:
        # Handle cases like "example.com/path"
        raw = raw.split("/")[0]
    
    # Strip port if present
    if ":" in raw:
        raw = raw.split(":")[0]
        
    return raw


class DomainModule(BaseModule):
    name = "domain_intel"
    description = "Retrieves WHOIS/RDAP records, DNS entries, and subdomains from Certificate Transparency logs."
    target_types = {TargetType.DOMAIN}

    def __init__(self):
        try:
            self.timeout = float(os.environ.get("SENT_EYE_DOMAIN_TIMEOUT", "15"))
        except ValueError:
            self.timeout = 15.0

    async def run(self, target: str) -> ModuleResult:
        domain = _clean_domain(target)

        if not DOMAIN_RE.match(domain):
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Invalid domain name: {target!r}"],
            )

        findings: List[Dict[str, Any]] = []
        warnings: List[str] = []

        findings.append({
            "check": "identity",
            "category": "identity",
            "status": "ok",
            "domain": domain,
        })

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

        async with httpx.AsyncClient(
            headers=headers, timeout=self.timeout, follow_redirects=True
        ) as client:
            # 1. RDAP Lookup (WHOIS)
            rdap_finding = await self._rdap_lookup(client, domain)
            if rdap_finding:
                findings.append(rdap_finding)
                if rdap_finding["status"] == "error":
                    warnings.append(f"RDAP failed: {rdap_finding.get('detail')}")
            else:
                warnings.append("RDAP lookup returned no data.")

            # 2. DNS Lookup
            dns_finding = await self._dns_lookup(domain)
            if dns_finding:
                findings.append(dns_finding)

            # 3. Subdomains (Cert Spotter)
            ct_finding = await self._certspotter_lookup(client, domain)
            if ct_finding:
                findings.append(ct_finding)

        has_core = any(f.get("status") == "ok" and f.get("category") in ("rdap", "dns") for f in findings)
        status = ModuleStatus.SUCCESS if has_core else ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "checks_run": len(findings),
            },
            warnings=warnings,
        )

    async def _rdap_lookup(self, client, domain: str) -> Dict[str, Any]:
        url = RDAP_URL.format(domain=domain)
        try:
            resp = await client.get(url)
        except Exception as exc:
            return {
                "check": "rdap",
                "category": "rdap",
                "status": "error",
                "detail": f"RDAP request failed: {type(exc).__name__}",
            }

        if resp.status_code == 404:
            return {
                "check": "rdap",
                "category": "rdap",
                "status": "warning",
                "detail": "Domain not found in RDAP.",
            }
        if resp.status_code != 200:
            return {
                "check": "rdap",
                "category": "rdap",
                "status": "error",
                "detail": f"RDAP returned HTTP {resp.status_code}.",
            }

        try:
            data = resp.json()
        except Exception:
            return {
                "check": "rdap",
                "category": "rdap",
                "status": "error",
                "detail": "RDAP returned non-JSON.",
            }

        registrar = "Unknown"
        entities = data.get("entities") or []
        for ent in entities:
            if "registrar" in (ent.get("roles") or []):
                vcard = ent.get("vcardArray") or []
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if prop[0] == "fn":
                            registrar = prop[3]
                            break
                break

        events = {}
        for ev in data.get("events") or []:
            action = ev.get("eventAction")
            date = ev.get("eventDate")
            if action and date:
                events[action] = date

        nameservers = [
            ns.get("ldhName")
            for ns in data.get("nameservers") or []
            if ns.get("ldhName")
        ]

        return {
            "check": "rdap",
            "category": "rdap",
            "status": "ok",
            "detail": "RDAP lookup successful.",
            "registrar": registrar,
            "registered": events.get("registration"),
            "expires": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "status": data.get("status") or [],
            "nameservers": nameservers,
        }

    async def _dns_lookup(self, domain: str) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()

        def do_lookup():
            records = {}
            for rtype in ["A", "AAAA", "MX", "TXT", "NS"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    vals = []
                    for r in answers:
                        if rtype == "MX":
                            vals.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
                        else:
                            vals.append(str(r).strip('"'))
                    if vals:
                        records[rtype] = vals
                except Exception:
                    pass
            return records

        try:
            records = await loop.run_in_executor(None, do_lookup)
        except Exception as exc:
            return {
                "check": "dns",
                "category": "dns",
                "status": "error",
                "detail": f"DNS lookup failed: {type(exc).__name__}",
            }

        if not records:
            return {
                "check": "dns",
                "category": "dns",
                "status": "warning",
                "detail": "No DNS records found.",
            }

        return {
            "check": "dns",
            "category": "dns",
            "status": "ok",
            "detail": "DNS records resolved.",
            "records": records,
        }

    async def _certspotter_lookup(self, client, domain: str) -> Dict[str, Any]:
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        try:
            resp = await client.get(CERTSPOTTER_URL, params=params)
        except Exception as exc:
            return {
                "check": "certspotter",
                "category": "subdomains",
                "status": "error",
                "detail": f"Cert Spotter failed: {type(exc).__name__}",
            }

        if resp.status_code == 429:
            return {
                "check": "certspotter",
                "category": "subdomains",
                "status": "warning",
                "detail": "Cert Spotter rate-limited (429) — try again later.",
            }
        if resp.status_code != 200:
            return {
                "check": "certspotter",
                "category": "subdomains",
                "status": "error",
                "detail": f"Cert Spotter returned HTTP {resp.status_code}.",
            }

        try:
            data = resp.json()
        except Exception:
            return {
                "check": "certspotter",
                "category": "subdomains",
                "status": "error",
                "detail": "Cert Spotter returned non-JSON.",
            }

        subdomains = set()
        for cert in data:
            for name in cert.get("dns_names") or []:
                # Only keep names that actually end with our target domain
                if name.endswith(domain):
                    subdomains.add(name)

        sorted_subs = sorted(list(subdomains))

        return {
            "check": "certspotter",
            "category": "subdomains",
            "status": "ok",
            "detail": f"{len(sorted_subs)} unique subdomain(s) found in Certificate Transparency logs.",
            "subdomains": sorted_subs,
        }
