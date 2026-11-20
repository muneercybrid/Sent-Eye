import asyncio
import os
from typing import Dict, List, Type

from backend.modules.base import BaseModule, TargetType
from backend.modules.metadata import MetadataModule
from backend.modules.reverse_search import ReverseSearchModule
from backend.modules.geolocation import GeolocationModule
from backend.modules.face_analysis import FaceAnalysisModule
from backend.modules.username import UsernameModule
from backend.modules.email import EmailModule
from backend.modules.vin import VINModule
from backend.modules.phone import PhoneModule
from backend.modules.ip import IPModule

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
]


class SentEyeRunner:
    """Orchestrates all modules that support a given target type."""

    def __init__(self, target_path: str, target_type: TargetType = TargetType.IMAGE):
        self.target_path = target_path
        self.target_type = target_type
        self.modules: List[BaseModule] = [
            cls() for cls in MODULE_REGISTRY
            if target_type in getattr(cls, "target_types", {TargetType.IMAGE})
        ]

    async def run_all(self) -> Dict:
        if self.target_type == TargetType.IMAGE and not os.path.exists(self.target_path):
            raise FileNotFoundError(f"Image not found: {self.target_path}")

        if not self.modules:
            raise ValueError(
                f"No modules registered for target type '{self.target_type.value}'."
            )

        results = {}
        for module in self.modules:
            result = await module.run(self.target_path)
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
            "modules_run": len(self.modules),
            "results": results,
        }
