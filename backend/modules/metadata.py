import subprocess
import json
import asyncio
from .base import BaseModule, ModuleResult, ModuleStatus

class MetadataModule(BaseModule):
    name = "metadata_extraction"
    description = "Extracts EXIF, GPS, and file metadata using ExifTool."

    async def run(self, image_path: str) -> ModuleResult:
        try:
            # We call exiftool with -json for structured, parsable output.
            # Running it in a thread prevents blocking the event loop.
            process = await asyncio.create_subprocess_exec(
                'exiftool', '-json', '-n', image_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                return ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=[f"ExifTool error: {error_msg}"]
                )

            # ExifTool outputs a JSON array; we want the first element.
            metadata_list = json.loads(stdout.decode())
            if not metadata_list:
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    errors=["ExifTool returned no metadata."]
                )

            raw_metadata = metadata_list[0]
            
            # We'll treat the entire dictionary as a finding for now.
            # Later, you could parse GPS specifically into lat/lon fields.
            finding = {
                "source": "exiftool",
                "type": "metadata_dump",
                "metadata": raw_metadata
            }

            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[finding],
                metadata={"tool": "exiftool"}
            )

        except FileNotFoundError:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=["ExifTool is not installed. Install it via: sudo apt install libimage-exiftool-perl"]
            )
        except Exception as e:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[str(e)]
            )
