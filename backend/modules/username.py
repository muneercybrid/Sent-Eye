import asyncio
import os
import re
from typing import Any, Dict, List

import httpx

from .base import BaseModule, ModuleResult, ModuleStatus, TargetType


USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# Each site is a dict:
#   name        - display name
#   category    - group for the report
#   profile     - user-facing profile URL (what we show in the report)
#   check       - URL we actually fetch (may be a JSON API)
#   kind        - "api" | "html"
#   not_found   - substrings in the response body that prove "not registered"
#   confidence  - "high" (reliable: API or real 404) | "low" (SPA, 200 for any handle)
SITES: List[Dict[str, Any]] = [
    # --- High confidence: JSON APIs ---
    {"name": "GitHub", "category": "code",
     "profile": "https://github.com/{u}",
     "check": "https://api.github.com/users/{u}",
     "kind": "api", "not_found": ["Not Found"], "confidence": "high"},

    {"name": "GitLab", "category": "code",
     "profile": "https://gitlab.com/{u}",
     "check": "https://gitlab.com/api/v4/users?username={u}",
     "kind": "api", "not_found": ["[]"], "confidence": "high"},

    {"name": "Reddit", "category": "social",
     "profile": "https://www.reddit.com/user/{u}/",
     "check": "https://www.reddit.com/user/{u}/about.json",
     "kind": "api", "not_found": [], "confidence": "high"},

    {"name": "HackerNews", "category": "tech",
     "profile": "https://news.ycombinator.com/user?id={u}",
     "check": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
     "kind": "api", "not_found": ["null"], "confidence": "high"},

    {"name": "Keybase", "category": "tech",
     "profile": "https://keybase.io/{u}",
     "check": "https://keybase.io/{u}",
     "kind": "html",
     "not_found": ["user not found", "couldn't find", "not found", "404"],
     "confidence": "high"},

    # --- High confidence: HTML with real 404 or clear not-found markers ---
    # PyPI serves HTTP 200 for unknown users with no reliable HTML marker,
    # so we cannot confirm claims via scraping. Demoted to low confidence:
    # shows up under "Unverified" and the user must click to check.
    {"name": "PyPI", "category": "code",
     "profile": "https://pypi.org/user/{u}/",
     "check": "https://pypi.org/user/{u}/",
     "kind": "html", "not_found": [], "confidence": "low"},

    {"name": "Dev.to", "category": "writing",
     "profile": "https://dev.to/{u}",
     "check": "https://dev.to/{u}",
     "kind": "html", "not_found": ["page not found", "does not exist"], "confidence": "high"},

    {"name": "BitBucket", "category": "code",
     "profile": "https://bitbucket.org/{u}",
     "check": "https://bitbucket.org/{u}",
     "kind": "html", "not_found": ["page not found"], "confidence": "high"},

    {"name": "Vimeo", "category": "social",
     "profile": "https://vimeo.com/{u}",
     "check": "https://vimeo.com/{u}",
     "kind": "html", "not_found": ["page not found", "we couldn't find"], "confidence": "high"},

    {"name": "Dribbble", "category": "creative",
     "profile": "https://dribbble.com/{u}",
     "check": "https://dribbble.com/{u}",
     "kind": "html", "not_found": ["page not found", "we couldn't find"], "confidence": "high"},

    {"name": "Bugcrowd", "category": "security",
     "profile": "https://bugcrowd.com/{u}",
     "check": "https://bugcrowd.com/{u}",
     "kind": "html", "not_found": ["page not found"], "confidence": "high"},

    {"name": "LeetCode", "category": "code",
     "profile": "https://leetcode.com/{u}/",
     "check": "https://leetcode.com/{u}/",
     "kind": "html", "not_found": ["not found", "does not exist"], "confidence": "high"},

    {"name": "Imgur", "category": "social",
     "profile": "https://imgur.com/user/{u}",
     "check": "https://imgur.com/user/{u}",
     "kind": "html", "not_found": ["page not found"], "confidence": "high"},

    {"name": "HackerOne", "category": "security",
     "profile": "https://hackerone.com/{u}",
     "check": "https://hackerone.com/{u}",
     "kind": "html", "not_found": ["page not found"], "confidence": "high"},

    {"name": "Behance", "category": "creative",
     "profile": "https://www.behance.net/{u}",
     "check": "https://www.behance.net/{u}",
     "kind": "html", "not_found": ["page not found", "not found"], "confidence": "high"},

    {"name": "DeviantArt", "category": "creative",
     "profile": "https://www.deviantart.com/{u}",
     "check": "https://www.deviantart.com/{u}",
     "kind": "html", "not_found": ["page not found", "not found"], "confidence": "high"},

    {"name": "Flickr", "category": "creative",
     "profile": "https://www.flickr.com/people/{u}/",
     "check": "https://www.flickr.com/people/{u}/",
     "kind": "html", "not_found": ["page not found", "not found"], "confidence": "high"},

    {"name": "Patreon", "category": "creative",
     "profile": "https://www.patreon.com/{u}",
     "check": "https://www.patreon.com/{u}",
     "kind": "html", "not_found": ["page not found"], "confidence": "high"},

    # --- Low confidence: SPA sites (200 for any handle, unreliable) ---
    {"name": "YouTube", "category": "social",
     "profile": "https://www.youtube.com/@{u}",
     "check": "https://www.youtube.com/@{u}",
     "kind": "html", "not_found": [], "confidence": "low"},

    {"name": "Twitch", "category": "social",
     "profile": "https://www.twitch.tv/{u}",
     "check": "https://www.twitch.tv/{u}",
     "kind": "html", "not_found": [], "confidence": "low"},

    {"name": "SoundCloud", "category": "social",
     "profile": "https://soundcloud.com/{u}",
     "check": "https://soundcloud.com/{u}",
     "kind": "html", "not_found": [], "confidence": "low"},

    {"name": "Spotify", "category": "social",
     "profile": "https://open.spotify.com/user/{u}",
     "check": "https://open.spotify.com/user/{u}",
     "kind": "html", "not_found": [], "confidence": "low"},

    {"name": "Replit", "category": "code",
     "profile": "https://replit.com/@{u}",
     "check": "https://replit.com/@{u}",
     "kind": "html", "not_found": [], "confidence": "low"},

    {"name": "Kaggle", "category": "tech",
     "profile": "https://www.kaggle.com/{u}",
     "check": "https://www.kaggle.com/{u}",
     "kind": "html", "not_found": [], "confidence": "low"},

    {"name": "AboutMe", "category": "profile",
     "profile": "https://about.me/{u}",
     "check": "https://about.me/{u}",
     "kind": "html", "not_found": [], "confidence": "low"},
]


USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _load_sites() -> List[Dict[str, Any]]:
    raw = os.environ.get("SENT_EYE_USERNAME_SITES", "").strip()
    if not raw:
        return SITES
    wanted = {s.strip().lower() for s in raw.split(",") if s.strip()}
    filtered = [s for s in SITES if s["name"].lower() in wanted]
    return filtered or SITES


class UsernameModule(BaseModule):
    name = "username_enumeration"
    description = "Checks whether a username is claimed on popular public sites."
    target_types = {TargetType.USERNAME}

    def __init__(self):
        try:
            self.concurrency = int(os.environ.get("SENT_EYE_USERNAME_CONCURRENCY", "10"))
        except ValueError:
            self.concurrency = 10
        try:
            self.timeout = float(os.environ.get("SENT_EYE_USERNAME_TIMEOUT", "10"))
        except ValueError:
            self.timeout = 10.0
        self.sites = _load_sites()

    async def run(self, target: str) -> ModuleResult:
        username = target.lstrip("@").strip()
        if not USERNAME_RE.match(username):
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[
                    f"Invalid username: {target!r}. "
                    f"Allowed characters: A-Z, a-z, 0-9, '.', '_', '-'. Max 64 chars."
                ],
            )

        sem = asyncio.Semaphore(self.concurrency)
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            tasks = [self._check(client, sem, site, username) for site in self.sites]
            results = await asyncio.gather(*tasks)

        claimed_high = [r for r in results if r["status"] == "claimed" and r["confidence"] == "high"]
        claimed_low = [r for r in results if r["status"] == "claimed" and r["confidence"] == "low"]
        available = [r for r in results if r["status"] == "available"]
        ambiguous = [r for r in results if r["status"] in ("ambiguous", "error")]
        blocked = [r for r in ambiguous if r.get("http_code") in (403, 429)]

        if claimed_high or claimed_low:
            status = ModuleStatus.SUCCESS
        elif available:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.FAILED

        warnings: List[str] = []
        if blocked:
            warnings.append(
                f"{len(blocked)} site(s) returned 403/429 — likely cloud IP blocking "
                f"(AWS/GCP ranges are blocked by Cloudflare/Akamai). "
                f"Run locally for full accuracy."
            )
        for r in ambiguous:
            detail = r.get("error") or f"HTTP {r.get('http_code')}"
            warnings.append(f"{r['name']}: {detail}")

        return ModuleResult(
            status=status,
            findings=results,
            metadata={
                "username": username,
                "sites_checked": len(self.sites),
                "claimed_high": len(claimed_high),
                "claimed_low": len(claimed_low),
                "available": len(available),
                "ambiguous": len(ambiguous),
                "blocked": len(blocked),
            },
            warnings=warnings,
        )

    async def _check(self, client, sem, site, username):
        url = site["check"].format(u=username)
        profile_url = site["profile"].format(u=username)
        result = {
            "name": site["name"],
            "category": site["category"],
            "url": profile_url,
            "status": "unknown",
            "http_code": None,
            "error": None,
            "confidence": site["confidence"],
            "kind": site["kind"],
        }

        async with sem:
            try:
                resp = await client.get(url)
            except httpx.TimeoutException:
                result["status"] = "error"
                result["error"] = "timeout"
                return result
            except Exception as exc:
                result["status"] = "error"
                result["error"] = type(exc).__name__
                return result

        result["http_code"] = resp.status_code

        if resp.status_code == 404:
            result["status"] = "available"
            return result

        if resp.status_code == 200:
            body_lower = resp.text.lower()
            if any(marker.lower() in body_lower for marker in site["not_found"]):
                result["status"] = "available"
                return result
            final_path = str(resp.url).lower()
            if "/login" in final_path or "/signin" in final_path or "/sign-in" in final_path:
                result["status"] = "ambiguous"
                result["error"] = "redirected to login"
                return result
            result["status"] = "claimed"
            return result

        if resp.status_code in (401, 403, 429, 503):
            result["status"] = "ambiguous"
            result["error"] = f"blocked (HTTP {resp.status_code})"
            return result

        result["status"] = "ambiguous"
        result["error"] = f"HTTP {resp.status_code}"
        return result
