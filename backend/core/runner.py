import asyncio
import os
from typing import Dict, List, Type

from backend.modules.base import BaseModule
from backend.modules.metadata import MetadataModule
from backend.modules.reverse_search import ReverseSearchModule
from backend.modules.geolocation import GeolocationModule
from backend.modules.face_analysis import FaceAnalysisModule

MODULE_REGISTRY: List[Type[BaseModule]] = [
    MetadataModule,
    GeolocationModule,
    ReverseSearchModule,
    FaceAnalysisModule,
]

class SentEyeRunner:
    """Orchestrates all registered modules against a single image."""

    def __init__(self, image_path: str):
        self.image_path = image_path
        self.modules: List[BaseModule] = [cls() for cls in MODULE_REGISTRY]

    async def run_all(self) -> Dict:
        if not os.path.exists(self.image_path):
            raise FileNotFoundError(f"Image not found: {self.image_path}")

        results = {}
        for module in self.modules:
            result = await module.run(self.image_path)
            results[module.name] = {
                "description": module.description,
                "status": result.status.value,
                "findings": result.findings,
                "metadata": result.metadata,
                "errors": result.errors,
            }

        return {
            "tool": "Sent Eye",
            "target": os.path.abspath(self.image_path),
            "modules_run": len(self.modules),
            "results": results,
        }
