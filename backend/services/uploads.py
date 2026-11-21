import io
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Tuple

from PIL import Image

ALLOWED_FORMATS = {"JPEG", "PNG", "BMP", "WEBP", "TIFF"}
FORMAT_TO_EXT = {
    "JPEG": ".jpg",
    "PNG": ".png",
    "BMP": ".bmp",
    "WEBP": ".webp",
    "TIFF": ".tiff",
}
MAX_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def create_workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="sent_eye_job_"))


def cleanup_workspace(path: Path) -> None:
    shutil.rmtree(str(path), ignore_errors=True)


def save_upload(data: bytes, original_filename: str) -> Tuple[Path, Path]:
    """Validate and persist an uploaded image to a fresh temp workspace.

    Returns (workspace_dir, image_path). Raises ValueError on invalid input.
    The original_filename is accepted only for logging; it is never used in
    the on-disk path.
    """
    if not data:
        raise ValueError("Empty file")

    if len(data) > MAX_SIZE_BYTES:
        mb = MAX_SIZE_BYTES // (1024 * 1024)
        raise ValueError(f"File too large (max {mb} MB)")

    # Magic-byte validation, not extension-based
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
    except Exception:
        raise ValueError("File is not a valid image")

    try:
        img2 = Image.open(io.BytesIO(data))
        fmt = img2.format
    except Exception:
        raise ValueError("File is not a valid image")

    if fmt not in ALLOWED_FORMATS:
        raise ValueError(f"Unsupported image format: {fmt}")

    workspace = create_workspace()
    ext = FORMAT_TO_EXT[fmt]
    # Server-controlled filename — original filename never touches the path
    safe_name = f"upload_{uuid.uuid4().hex}{ext}"
    file_path = workspace / safe_name
    file_path.write_bytes(data)
    return workspace, file_path
