from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

class TargetType(str, Enum):
    IMAGE = "image"
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    IP = "ip"
    DOMAIN = "domain"
    VIN = "vin"
    MAC = "mac"
    PLATE = "plate"
    COORDS = "coords"


class ModuleStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class ModuleResult:
    status: ModuleStatus
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

class BaseModule(ABC):
    """
    The contract every Sent Eye module must follow.
    Each module should implement the 'run' method.
    """
    name: str = "base_module"
    description: str = "Base module contract."
    requires_key: bool = False
    # Which target types this module handles. Defaults to image-only so
    # existing modules need zero changes to keep working.
    target_types: Set["TargetType"] = {TargetType.IMAGE}

    @abstractmethod
    async def run(self, image_path: str) -> ModuleResult:
        """
        Execute the module against a given image file path.
        Must return a ModuleResult, never raise an exception.
        """
        pass
