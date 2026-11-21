import asyncio
import os
from typing import Any, Dict, List

from PicImageSearch import Network, GoogleLens, Yandex, Tineye

from .base import BaseModule, ModuleResult, ModuleStatus


# Every engine we support, keyed by the CLI-friendly name.
ENGINE_FACTORIES = {
    "yandex": lambda client: Yandex(client=client),
    "tineye": lambda client: Tineye(client=client),
    "google_lens": lambda client: GoogleLens(client=client),
}

# Yandex is the only one that has proven reliable on the free tier.
DEFAULT_ENGINES = ["yandex"]


def _parse_engines(raw):
    """Parse comma-separated engine names, validate, and dedupe."""
    if not raw:
        return list(DEFAULT_ENGINES)
    if raw.strip().lower() == "all":
        return list(ENGINE_FACTORIES.keys())

    names = [n.strip().lower() for n in raw.split(",") if n.strip()]
    unknown = [n for n in names if n not in ENGINE_FACTORIES]
    if unknown:
        raise ValueError(
            f"Unknown engine(s): {', '.join(unknown)}. "
            f"Available: {', '.join(ENGINE_FACTORIES.keys())}"
        )

    seen = set()
    deduped = []
    for n in names:
        if n not in seen:
            seen.add(n)
            deduped.append(n)
    return deduped or list(DEFAULT_ENGINES)


class ReverseSearchModule(BaseModule):
    name = "reverse_image_search"
    description = "Searches the configured reverse-image engines for visually similar images."

    def __init__(self, engines=None):
        raw_engines = (
            os.environ.get("SENT_EYE_ENGINES")
            if engines is None
            else engines
        )
        self.engines = _parse_engines(raw_engines)

    async def run(self, image_path: str) -> ModuleResult:
        findings = []
        per_engine = {}
        warnings = []
        errors = []

        async with Network() as client:
            async def query(engine_name):
                info = {"findings": 0, "error": None, "empty": False}
                try:
                    engine = ENGINE_FACTORIES[engine_name](client)
                    response = await engine.search(file=image_path)
                    if not response.raw:
                        info["empty"] = True
                        return
                    for item in response.raw:
                        finding = {
                            "source": engine_name,
                            "title": getattr(item, "title", None),
                            "url": getattr(item, "url", None),
                            "thumbnail": getattr(item, "thumbnail", None),
                            "similarity": getattr(item, "similarity", None),
                        }
                        findings.append(
                            {k: v for k, v in finding.items() if v is not None}
                        )
                        info["findings"] += 1
                except Exception as exc:
                    info["error"] = f"{engine_name}: {type(exc).__name__}: {exc}"
                finally:
                    per_engine[engine_name] = info

            await asyncio.gather(*(query(n) for n in self.engines))

        # Classify: any engine success => SUCCESS with per-engine failures as warnings.
        any_success = any(info["findings"] > 0 for info in per_engine.values())
        all_engines_failed = (
            per_engine
            and not any_success
            and all(info["error"] for info in per_engine.values())
        )

        for name, info in per_engine.items():
            if info["error"] and not info["findings"]:
                warnings.append(info["error"])
            elif info["empty"]:
                warnings.append(f"{name}: returned no results.")

        if all_engines_failed:
            errors = list(warnings)
            warnings = []
            status = ModuleStatus.FAILED
        elif any_success:
            status = ModuleStatus.SUCCESS
        elif per_engine:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.PARTIAL
            errors.append("No engines configured.")

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "engines_configured": self.engines,
                "per_engine": per_engine,
            },
            errors=errors,
            warnings=warnings,
        )
