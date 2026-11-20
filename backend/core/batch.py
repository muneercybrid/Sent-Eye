"""Batch orchestration for Sent-Eye."""
import asyncio
import os
from pathlib import Path
from typing import Dict, List

from backend.core.runner import SentEyeRunner

SUPPORTED_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff", ".tif"}


def collect_images(directory: str, recursive: bool = False) -> List[str]:
    """Return a sorted list of image paths under `directory`."""
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")
    iterator = root.rglob("*") if recursive else root.glob("*")
    return sorted(
        str(p) for p in iterator
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXT
    )


class SentEyeBatchRunner:
    """Runs the full Sent-Eye pipeline against every image in a directory."""

    def __init__(self, directory: str, recursive: bool = False):
        self.directory = directory
        self.recursive = recursive
        self.images = collect_images(directory, recursive=recursive)

    async def run_all(self, on_progress=None) -> Dict:
        reports = []
        errors = []
        total = len(self.images)
        for idx, image_path in enumerate(self.images, 1):
            if on_progress:
                on_progress(idx, total, image_path)
            try:
                report = await SentEyeRunner(image_path).run_all()
                reports.append(report)
            except Exception as exc:
                errors.append(
                    {"image": image_path, "error": f"{type(exc).__name__}: {exc}"}
                )
        return {
            "tool": "Sent-Eye",
            "mode": "batch",
            "directory": os.path.abspath(self.directory),
            "recursive": self.recursive,
            "images_found": total,
            "images_analyzed": len(reports),
            "batch_errors": errors,
            "reports": reports,
        }
