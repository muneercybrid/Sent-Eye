"""Bridge from the web layer to the existing Sent Eye engine."""
from typing import Any, Callable, Dict, Optional, Set

from backend.core.runner import SentEyeRunner
from backend.modules.base import TargetType

ProgressCallback = Callable[[int, int, str], None]
ModuleStartCallback = Callable[[str], str]
ModuleFinishCallback = Callable[[str, str], None]


async def run_single(
    target: str,
    target_type: TargetType,
    on_progress: Optional[ProgressCallback] = None,
    allowed_modules: Optional[Set[str]] = None,
    engines: Optional[str] = None,
    analyze_faces: Optional[bool] = None,
    on_module_start: Optional[ModuleStartCallback] = None,
    on_module_finish: Optional[ModuleFinishCallback] = None,
) -> Dict[str, Any]:
    """Delegate to the existing engine with request-scoped authorization."""
    runner = SentEyeRunner(
        target,
        target_type=target_type,
        allowed_modules=allowed_modules,
        engines=engines,
        analyze_faces=analyze_faces,
    )
    return await runner.run_all(
        on_progress=on_progress,
        on_module_start=on_module_start,
        on_module_finish=on_module_finish,
    )
