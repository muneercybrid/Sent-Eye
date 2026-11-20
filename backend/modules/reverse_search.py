import asyncio
from typing import List, Dict, Any

from PicImageSearch import Network, GoogleLens, Yandex, Tineye

from .base import BaseModule, ModuleResult, ModuleStatus


class ReverseSearchModule(BaseModule):
    name = "reverse_image_search"
    description = "Searches Google Lens, Yandex, and TinEye for visually similar images."

    async def run(self, image_path: str) -> ModuleResult:
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        async with Network() as client:
            # Each engine is queried independently so one failure
            # does not prevent the others from returning results.
            engines = [
                ("google_lens", GoogleLens(client=client)),
                ("yandex", Yandex(client=client)),
                ("tineye", Tineye(client=client)),
            ]

            async def query_engine(engine_name: str, engine) -> None:
                try:
                    response = await engine.search(file=image_path)
                    if not response.raw:
                        errors.append(f"{engine_name}: returned no results.")
                        return

                    for item in response.raw:
                        finding = {
                            "source": engine_name,
                            "title": getattr(item, "title", None),
                            "url": getattr(item, "url", None),
                            "thumbnail": getattr(item, "thumbnail", None),
                            "similarity": getattr(item, "similarity", None),
                        }
                        # Remove keys with None values to keep output clean.
                        findings.append({k: v for k, v in finding.items() if v is not None})
                except Exception as exc:
                    errors.append(f"{engine_name}: {type(exc).__name__}: {exc}")

            # Run all engine queries concurrently.
            await asyncio.gather(*(query_engine(name, eng) for name, eng in engines))

        if findings:
            status = ModuleStatus.SUCCESS
        elif errors:
            status = ModuleStatus.FAILED
        else:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"engines_used": [name for name, _ in engines]},
            errors=errors,
        )
