import asyncio
import os
import re
from typing import Any, Dict, List, Tuple

import httpx

from .base import BaseModule, ModuleResult, ModuleStatus, TargetType


USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# (name, category, url_template, not_found_markers)
# not_found_markers: substrings in body that prove the user is NOT registered.
#   Empty list = rely on HTTP status code (404 = not claimed, 200 = claimed).
SITES: List[Tuple[str, str, str, List[str]]] = [
    # Code / developer
    ("GitHub", "code", "https://github.com/{u}", []),
    ("GitLab", "code", "https://gitlab.com/{u}", []),
    ("BitBucket", "code", "https://bitbucket.org/{u}", []),
    ("PyPI", "code", "https://pypi.org/user/{u}/", []),
    ("Replit", "code", "https://replit.com/@{u}", []),
    ("LeetCode", "code", "https://leetcode.com/{u}/", ["not found", "does not exist"]),

    # Social / streaming
    ("Reddit", "social", "https://www.reddit.com/user/{u}/about.json", []),
    ("Twitch", "social", "https://www.twitch.tv/{u}", []),
    ("YouTube", "social", "https://www.youtube.com/@{u}", []),
    ("SoundCloud", "social", "https://soundcloud.com/{u}", []),
    ("Spotify", "social", "https://open.spotify.com/user/{u}", []),
    ("Vimeo", "social", "https://vimeo.com/{u}", []),
    ("Imgur", "social", "https://imgur.com/user/{u}", []),

    # Writing
    ("Dev.to", "writing", "https://dev.to/{u}", []),
    ("HackerNews", "tech", "https://news.ycombinator.com/user?id={u}", ["No such user"]),

    # Tech / profiles
    ("Keybase", "tech", "https://keybase.io/{u}", []),
    ("Kaggle", "tech", "https://www.kaggle.com/{u}", []),
    ("AboutMe", "profile", "https://about.me/{u}", []),

    # Security / bug bounty
    ("HackerOne", "security", "https://hackerone.com/{u}", []),
    ("Bugcrowd", "security", "https://bugcrowd.com/{u}", []),

    # Creative
    ("Behance", "creative", "https://www.behance.net/{u}", []),
    ("Dribbble", "creative", "https://dribbble.com/{u}", []),
    ("DeviantArt", "creative", "https://www.deviantart.com/{u}", []),
    ("Flickr", "creative", "https://www.flickr.com/people/{u}/", []),
    ("Patreon", "creative", "https://www.patreon.com/{u}", ["page not found"]),
]

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _load_sites() -> List[Tuple[str, str, str, List[str]]]:
    raw = os.environ.get("SENT_EYE_USERNAME_SITES", "").strip()
    if not raw:
        return SITES
    wanted = {s.strip().lower() for s in raw.split(",") if s.strip()}
    filtered = [s for s in SITES if s[0].lower() in wanted]
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
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            tasks = [self._check(client, sem, site, username) for site in self.sites]
            results = await asyncio.gather(*tasks)

        claimed = [r for r in results if r["status"] == "claimed"]
        available = [r for r in results if r["status"] == "available"]
        ambiguous = [r for r in results if r["status"] in ("ambiguous", "error")]

        if claimed:
            status = ModuleStatus.SUCCESS
        elif available:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.FAILED

        warnings = [
            f"{r['name']}: {r['status']}"
            + (f" ({r.get('error')})" if r.get("error") else f" (HTTP {r.get('http_code')})")
            for r in ambiguous
        ]

        return ModuleResult(
            status=status,
            findings=results,
            metadata={
                "username": username,
                "sites_checked": len(self.sites),
                "claimed": len(claimed),
                "available": len(available),
                "ambiguous": len(ambiguous),
            },
            warnings=warnings,
        )

    async def _check(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        site: Tuple[str, str, str, List[str]],
        username: str,
    ) -> Dict[str, Any]:
        name, category, url_tpl, not_found_markers = site
        url = url_tpl.format(u=username)
        result: Dict[str, Any] = {
            "name": name,
            "category": category,
            "url": url,
            "status": "unknown",
            "http_code": None,
            "error": None,
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
            if any(marker.lower() in body_lower for marker in not_found_markers):
                result["status"] = "available"
                return result
            # Login redirect? Not reliable.
            final_path = str(resp.url).lower()
            if "/login" in final_path or "/signin" in final_path or "/sign-in" in final_path:
                result["status"] = "ambiguous"
                result["error"] = "redirected to login"
                return result
            result["status"] = "claimed"
            return result

        if resp.status_code in (401, 403, 429):
            result["status"] = "ambiguous"
            result["error"] = f"blocked (HTTP {resp.status_code})"
            return result

        result["status"] = "ambiguous"
        result["error"] = f"HTTP {resp.status_code}"
        return result
