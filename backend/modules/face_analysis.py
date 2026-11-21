import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseModule, ModuleResult, ModuleStatus
from backend.compat import install_pkg_resources_shim

install_pkg_resources_shim()

# face_recognition is imported lazily inside run() so the rest of Sent Eye
# works even if it isn't installed yet.
_SUPPORTED_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}


class FaceAnalysisModule(BaseModule):
    name = "face_analysis"
    description = "Detects faces and (optionally) matches them against a reference directory."

    def __init__(self, enabled=None):
        self.enabled = (
            os.environ.get("SENT_EYE_ENABLE_FACES") == "1"
            if enabled is None
            else bool(enabled)
        )
        self.reference_dir = os.environ.get("SENT_EYE_FACE_DB")
        try:
            self.tolerance = float(os.environ.get("SENT_EYE_FACE_TOLERANCE", "0.6"))
        except ValueError:
            self.tolerance = 0.6

    async def run(self, image_path: str) -> ModuleResult:
        if not self.enabled:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Face analysis disabled (pass --analyze-faces to enable)."],
            )

        try:
            import face_recognition  # noqa: F401
        except ImportError:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[
                    "face_recognition is not installed. "
                    "Install with: pip install dlib face_recognition"
                ],
            )

        # Face detection is CPU-heavy; run it in a thread pool so the
        # asyncio event loop keeps running other module coroutines.
        loop = asyncio.get_running_loop()
        try:
            findings = await loop.run_in_executor(None, self._analyze, image_path)
        except FileNotFoundError as exc:
            return ModuleResult(status=ModuleStatus.FAILED, errors=[str(exc)])
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        if not findings:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["No faces detected in the image."],
            )

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "tolerance": self.tolerance,
                "reference_dir": self.reference_dir or None,
            },
        )

    def _analyze(self, image_path: str) -> List[Dict[str, Any]]:
        import face_recognition

        image = face_recognition.load_image_file(image_path)
        locations = face_recognition.face_locations(image, model="hog")
        encodings = face_recognition.face_encodings(
            image, known_face_locations=locations
        )

        if not locations:
            return []

        reference: Optional[List[Dict[str, Any]]] = None
        if self.reference_dir:
            reference = self._load_reference_db()

        findings: List[Dict[str, Any]] = []
        for idx, (loc, enc) in enumerate(zip(locations, encodings)):
            top, right, bottom, left = loc
            finding: Dict[str, Any] = {
                "source": "face_recognition",
                "type": "face",
                "face_index": idx,
                "location": {
                    "top": top,
                    "right": right,
                    "bottom": bottom,
                    "left": left,
                },
                "box_width": right - left,
                "box_height": bottom - top,
            }

            if reference:
                matches = self._match(enc, reference)
                finding["matches"] = matches
                finding["has_match"] = any(m["is_match"] for m in matches)

            findings.append(finding)

        return findings

    def _load_reference_db(self) -> List[Dict[str, Any]]:
        """Encode every face in every image under self.reference_dir."""
        import face_recognition

        ref_dir = Path(self.reference_dir)
        if not ref_dir.is_dir():
            raise FileNotFoundError(
                f"Reference directory not found: {self.reference_dir}"
            )

        references: List[Dict[str, Any]] = []
        for path in ref_dir.iterdir():
            if path.suffix.lower() not in _SUPPORTED_EXT or not path.is_file():
                continue
            try:
                img = face_recognition.load_image_file(str(path))
                encs = face_recognition.face_encodings(img)
                for enc in encs:
                    references.append({"file": path.name, "encoding": enc})
            except Exception:
                continue  # skip unreadable reference images
        return references

    def _match(
        self,
        encoding: "Any",
        references: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        import face_recognition

        results: List[Dict[str, Any]] = []
        for ref in references:
            distance = float(
                face_recognition.face_distance([ref["encoding"]], encoding)[0]
            )
            results.append(
                {
                    "file": ref["file"],
                    "distance": round(distance, 4),
                    "is_match": distance <= self.tolerance,
                }
            )
        results.sort(key=lambda r: r["distance"])
        return results[:5]  # top 5 closest matches
