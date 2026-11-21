import json
import os
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import JSONResponse, Response

from backend.core.runner import MODULE_REGISTRY
from backend.modules.base import TargetType
from backend.services.auth_store import (
    AccessDenied,
    QuotaExceeded,
    auth_store,
)
from backend.services.security import (
    get_current_user,
    require_csrf,
)
from backend.services.job_manager import job_manager
from backend.services.engine_bridge import run_single
from backend.services.uploads import save_upload

from .schemas import (
    HealthResponse,
    InvestigateResponse,
    JobStatus,
    ModuleInfo,
)

router = APIRouter()

SENSITIVE_MODULES = {
    "face_analysis",
    "geolocation",
    "reverse_image_search",
}


def _module_available(cls) -> bool:
    """Best-effort check that the module's runtime dependencies are importable."""
    name = cls.name
    try:
        if name == "face_analysis":
            import face_recognition  # noqa: F401
        elif name == "phone_intel":
            import phonenumbers  # noqa: F401
        elif name == "ip_intel":
            import ipgeolocateio  # noqa: F401
        elif name in ("email_intel", "domain_intel"):
            import dns.resolver  # noqa: F401
    except Exception:
        return False
    return True


def _job_to_status(
    job,
    report_available: Optional[bool] = None,
) -> JobStatus:
    return JobStatus(
        job_id=job.job_id,
        target_type=job.target_type,
        target_display=job.target_display,
        status=job.status,
        progress_current=job.progress_current,
        progress_total=job.progress_total,
        progress_module=job.progress_module,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        error=job.error,
        report_available=(
            job.report is not None
            if report_available is None
            else bool(report_available)
        ),
    )


def _record_to_status(record: Dict[str, Any]) -> JobStatus:
    return JobStatus(
        job_id=record["job_id"],
        target_type=record["target_type"],
        target_display=record["target_display"],
        status=record["status"],
        created_at=record["created_at"],
        finished_at=record.get("finished_at"),
        report_available=bool(record.get("report_available")),
    )


def _get_accessible_job(job_id: str, user: Dict[str, Any]):
    job = job_manager.get_job(job_id)

    if job is not None:
        if (
            user["role"] != "admin"
            and job.owner_user_id != user["user_id"]
        ):
            raise HTTPException(404, "Job not found.")
        return job

    record = auth_store.get_investigation(job_id)
    if record is None:
        raise HTTPException(404, "Job not found.")

    if (
        user["role"] != "admin"
        and record["user_id"] != user["user_id"]
    ):
        raise HTTPException(404, "Job not found.")

    return record


def _get_accessible_report(
    job_id: str,
    user: Dict[str, Any],
) -> Dict[str, Any]:
    item = _get_accessible_job(job_id, user)

    if isinstance(item, dict):
        status = item.get("status")
        report = item.get("report")
    else:
        status = item.status
        report = item.report

        # Recover an archived body if the in-memory job has no report.
        record = auth_store.get_investigation(job_id)
        if record is not None and report is None:
            report = record.get("report")
            if status != "completed":
                status = record.get("status")

    if status != "completed":
        raise HTTPException(
            409,
            f"Investigation is not complete (status: {status}).",
        )

    if not isinstance(report, dict):
        raise HTTPException(
            410,
            "This investigation has no archived report body. "
            "Import its previously downloaded JSON report from History.",
        )

    # Archive reports that are still available only in the old job manager.
    auth_store.save_investigation_report(job_id, report)
    return report


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    types = sorted(
        {tt.value for cls in MODULE_REGISTRY for tt in cls.target_types}
    )
    return HealthResponse(
        status="ok",
        version="0.2.0",
        modules_available=len(MODULE_REGISTRY),
        target_types=types,
    )


@router.get("/api/modules", response_model=List[ModuleInfo])
async def list_modules(
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[ModuleInfo]:
    permissions = {
        item["module_name"]: item
        for item in auth_store.get_module_permissions(user["user_id"])
    }

    out: List[ModuleInfo] = []
    for cls in MODULE_REGISTRY:
        inst = cls()
        grant = permissions.get(inst.name)
        authorized = (
            user["role"] == "admin"
            or bool(grant and grant["enabled"])
        )

        out.append(
            ModuleInfo(
                name=inst.name,
                description=inst.description,
                target_types=sorted(tt.value for tt in cls.target_types),
                requires_key=bool(getattr(inst, "requires_key", False)),
                available=_module_available(cls),
                authorized=authorized,
                sensitive=inst.name in SENSITIVE_MODULES
                or "track" in inst.name.lower(),
                daily_limit=(
                    None if user["role"] == "admin"
                    else grant["daily_limit"] if grant else None
                ),
                monthly_limit=(
                    None if user["role"] == "admin"
                    else grant["monthly_limit"] if grant else None
                ),
            )
        )

    return sorted(out, key=lambda module: module.name)


@router.post("/api/investigate", response_model=InvestigateResponse)
async def investigate(
    request: Request,
    target_type: str = Form(...),
    target: str = Form(""),
    file: Optional[UploadFile] = File(None),
    acknowledge_consent: bool = Form(False),
    analyze_faces: bool = Form(False),
    engines: str = Form(""),
    user: Dict[str, Any] = Depends(get_current_user),
) -> InvestigateResponse:
    require_csrf(request, user)

    try:
        tt = TargetType(target_type.strip().lower())
    except ValueError:
        raise HTTPException(400, f"Unknown target type: {target_type!r}")

    if not acknowledge_consent:
        raise HTTPException(
            400,
            "You must confirm you have permission to investigate this target.",
        )

    if analyze_faces and tt != TargetType.IMAGE:
        raise HTTPException(
            400,
            "Facial analysis is only available for image targets.",
        )

    compatible = [
        cls.name for cls in MODULE_REGISTRY
        if tt in getattr(cls, "target_types", {TargetType.IMAGE})
    ]

    permissions = {
        item["module_name"]: item
        for item in auth_store.get_module_permissions(user["user_id"])
    }

    if user["role"] == "admin":
        allowed_modules = set(compatible)
    else:
        allowed_modules = {
            name for name in compatible
            if permissions.get(name, {}).get("enabled", False)
        }

    if analyze_faces and "face_analysis" not in allowed_modules:
        raise HTTPException(
            403,
            "Facial analysis requires an explicit administrator grant.",
        )

    if engines.strip() and "reverse_image_search" not in allowed_modules:
        raise HTTPException(
            403,
            "Reverse-image search is not enabled for your account.",
        )

    # Face analysis runs only when the user explicitly opts in.
    selected_modules = {
        name for name in allowed_modules
        if name != "face_analysis" or analyze_faces
    }

    if not selected_modules:
        raise HTTPException(
            403,
            "No modules are authorized for this target type. "
            "Contact the administrator to request module access.",
        )

    workspace = None
    if tt == TargetType.IMAGE:
        if file is None:
            raise HTTPException(
                400,
                "Image file is required for image analysis.",
            )

        data = await file.read()
        try:
            workspace, image_path = save_upload(
                data, file.filename or "upload"
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))

        target_value = str(image_path)
        display_name = (
            (file.filename or "upload").rsplit("/", 1)[-1][:80]
        )
        target_display = f"uploaded image ({display_name})"
    else:
        target_value = (target or "").strip()
        if not target_value:
            raise HTTPException(400, "Target value is required.")
        if len(target_value) > 512:
            raise HTTPException(400, "Target value is too long (max 512 chars).")
        if "\x00" in target_value:
            raise HTTPException(400, "Target contains invalid characters.")
        target_display = target_value

    job = job_manager.create_job(
        target_type=tt.value,
        target_display=target_display,
        target_value=target_value,
        workspace=workspace,
        owner_user_id=user["user_id"],
    )

    try:
        auth_store.record_investigation(
            job.job_id,
            user["user_id"],
            tt.value,
            target_display,
        )
    except Exception:
        if workspace is not None:
            from backend.services.uploads import cleanup_workspace
            cleanup_workspace(workspace)
        raise HTTPException(
            500,
            "Could not record this investigation. No modules were started.",
        )

    def on_module_start(module_name: str) -> str:
        try:
            return auth_store.reserve_module_use(
                user_id=user["user_id"],
                role=user["role"],
                module_name=module_name,
                job_id=job.job_id,
                target_type=tt.value,
            )
        except (AccessDenied, QuotaExceeded) as exc:
            auth_store.record_audit_event(
                actor_user_id=user["user_id"],
                subject_user_id=user["user_id"],
                job_id=job.job_id,
                module_name=module_name,
                event_type="module.denied",
                details={"reason": str(exc)},
            )
            raise

    def on_module_finish(usage_id: str, status: str) -> None:
        auth_store.finish_module_use(usage_id, status)

    async def _run(on_progress):
        try:
            report = await run_single(
                target_value,
                tt,
                on_progress=on_progress,
                allowed_modules=selected_modules,
                engines=engines or None,
                analyze_faces=analyze_faces,
                on_module_start=on_module_start,
                on_module_finish=on_module_finish,
            )
        except Exception:
            auth_store.finish_investigation(job.job_id, "failed")
            raise

        try:
            auth_store.save_investigation_report(job.job_id, report)
        except Exception:
            auth_store.finish_investigation(job.job_id, "failed")
            raise

        auth_store.finish_investigation(job.job_id, "completed")
        return report

    try:
        job_manager.submit(job, _run)
    except Exception:
        auth_store.finish_investigation(job.job_id, "failed")
        raise HTTPException(500, "Could not schedule the investigation.")

    return InvestigateResponse(
        job_id=job.job_id,
        status="pending",
    )


@router.get("/api/jobs", response_model=List[JobStatus])
async def list_jobs(
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[JobStatus]:
    owner_id = None if user["role"] == "admin" else user["user_id"]
    records = auth_store.list_investigations(
        limit=100,
        owner_user_id=owner_id,
    )

    results = []
    for record in records:
        live_job = job_manager.get_job(record["job_id"])

        if live_job is not None:
            results.append(
                _job_to_status(
                    live_job,
                    report_available=(
                        record["report_available"]
                        or live_job.report is not None
                    ),
                )
            )
        else:
            results.append(_record_to_status(record))

    return results


@router.get("/api/jobs/{job_id}", response_model=JobStatus)
async def get_job(
    job_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JobStatus:
    item = _get_accessible_job(job_id, user)

    if isinstance(item, dict):
        return _record_to_status(item)

    record = auth_store.get_investigation(job_id) or {}
    return _job_to_status(
        item,
        report_available=(
            bool(record.get("report_available"))
            or item.report is not None
        ),
    )


@router.get("/api/jobs/{job_id}/report.json")
async def get_job_json(
    job_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
):
    report = _get_accessible_report(job_id, user)
    return JSONResponse(content=report)


@router.get("/api/jobs/{job_id}/report.html")
async def get_job_html(
    job_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Response:
    report = _get_accessible_report(job_id, user)

    from backend.exporters.html_report import HTMLReporter
    html = HTMLReporter(report).render()
    return Response(content=html, media_type="text/html")


@router.post("/api/jobs/{job_id}/report.json")
async def import_job_report(
    job_id: str,
    request: Request,
    file: UploadFile = File(...),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """Import a previously exported report into its original investigation."""
    require_csrf(request, user)
    _get_accessible_job(job_id, user)

    record = auth_store.get_investigation(job_id)
    if record is None:
        raise HTTPException(404, "Investigation not found.")

    if record["status"] != "completed":
        raise HTTPException(
            409,
            "A report can only be imported into a completed investigation.",
        )

    raw = await file.read(5 * 1024 * 1024 + 1)
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(413, "Report file exceeds the 5 MB limit.")

    try:
        report = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(400, "The selected file is not valid JSON.")

    if not isinstance(report, dict) or not isinstance(
        report.get("results"), dict
    ):
        raise HTTPException(
            400,
            "The file is not a valid Sent Eye investigation report.",
        )

    report_type = str(report.get("target_type") or "").strip().lower()
    if report_type and report_type != record["target_type"].lower():
        raise HTTPException(
            400,
            "The report target type does not match this investigation.",
        )

    auth_store.save_investigation_report(job_id, report)

    live_job = job_manager.get_job(job_id)
    if live_job is not None:
        live_job.report = report

    return {
        "job_id": job_id,
        "report_available": True,
        "message": "Report imported and archived successfully.",
    }
