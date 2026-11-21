import asyncio
import os
from typing import Callable, Dict, List, Optional, Set, Type

from backend.modules.base import (
    BaseModule,
    ModuleResult,
    ModuleStatus,
    TargetType,
)
from backend.modules.metadata import MetadataModule
from backend.modules.reverse_search import ReverseSearchModule
from backend.modules.geolocation import GeolocationModule
from backend.modules.face_analysis import FaceAnalysisModule
from backend.modules.username import UsernameModule
from backend.modules.email import EmailModule
from backend.modules.vin import VINModule
from backend.modules.phone import PhoneModule
from backend.modules.ip import IPModule
from backend.modules.domain import DomainModule


MODULE_REGISTRY: List[Type[BaseModule]] = [
    MetadataModule,
    GeolocationModule,
    ReverseSearchModule,
    FaceAnalysisModule,
    UsernameModule,
    EmailModule,
    VINModule,
    PhoneModule,
    IPModule,
    DomainModule,
]

ModuleStartCallback = Callable[[str], str]
ModuleFinishCallback = Callable[[str, str], None]


class SentEyeRunner:
    """Runs only the modules authorized for this investigation."""

    def __init__(
        self,
        target_path: str,
        target_type: TargetType = TargetType.IMAGE,
        allowed_modules: Optional[Set[str]] = None,
        engines: Optional[str] = None,
        analyze_faces: Optional[bool] = None,
    ):
        self.target_path = target_path
        self.target_type = target_type
        self.modules: List[BaseModule] = []

        for cls in MODULE_REGISTRY:
            if target_type not in getattr(
                cls, "target_types", {TargetType.IMAGE}
            ):
                continue

            if allowed_modules is not None and cls.name not in allowed_modules:
                continue

            if cls is FaceAnalysisModule and analyze_faces is False:
                continue

            if cls is ReverseSearchModule:
                instance = cls(engines=engines)
            elif cls is FaceAnalysisModule:
                instance = cls(enabled=analyze_faces)
            else:
                instance = cls()

            self.modules.append(instance)

    async def run_all(
        self,
        on_progress=None,
        on_module_start: Optional[ModuleStartCallback] = None,
        on_module_finish: Optional[ModuleFinishCallback] = None,
    ) -> Dict:
        if self.target_type == TargetType.IMAGE and not os.path.exists(
            self.target_path
        ):
            raise FileNotFoundError(
                f"Image not found: {self.target_path}"
            )

        if not self.modules:
            raise ValueError(
                f"No authorized modules are registered for target type "
                f"'{self.target_type.value}'."
            )

        results = {}
        executed_count = 0
        total = len(self.modules)

        for idx, module in enumerate(self.modules, 1):
            if on_progress is not None:
                try:
                    on_progress(idx, total, module.name)
                except Exception:
                    pass

            usage_id = None

            # The authorization/quota reservation happens immediately before
            # the module executes. A denied attempt is not charged.
            try:
                if on_module_start is not None:
                    usage_id = on_module_start(module.name)
            except Exception as exc:
                results[module.name] = {
                    "description": module.description,
                    "status": ModuleStatus.SKIPPED.value,
                    "findings": [],
                    "metadata": {},
                    "errors": [str(exc)],
                    "warnings": [],
                }
                continue

            try:
                result = await module.run(self.target_path)
                executed_count += 1
            except Exception as exc:
                result = ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=[
                        f"Module execution failed: {type(exc).__name__}: {exc}"
                    ],
                )
                executed_count += 1

            if usage_id and on_module_finish is not None:
                try:
                    on_module_finish(usage_id, result.status.value)
                except Exception as exc:
                    result.warnings.append(
                        "Could not finalize module usage audit record: "
                        f"{type(exc).__name__}"
                    )

            results[module.name] = {
                "description": module.description,
                "status": result.status.value,
                "findings": result.findings,
                "metadata": result.metadata,
                "errors": result.errors,
                "warnings": getattr(result, "warnings", []),
            }

        return {
            "tool": "Sent Eye",
            "target": self.target_path,
            "target_type": self.target_type.value,
            "modules_run": executed_count,
            "results": results,
        }
