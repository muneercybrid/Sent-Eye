"""In-memory async job manager for Sent Eye web investigations.

Limitations (documented for production planning):
- Jobs are lost on process restart.
- Not shared across multiple worker processes.
- TTL-based pruning (1 hour by default) keeps memory bounded.
"""
import asyncio
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .uploads import cleanup_workspace

MAX_CONCURRENT_JOBS = 2
JOB_TTL_SECONDS = 3600
CLEANUP_INTERVAL_SECONDS = 300


@dataclass
class Job:
    job_id: str
    target_type: str
    target_display: str
    target_value: str
    workspace: Optional[Path] = None
    owner_user_id: Optional[str] = None
    status: str = "pending"
    progress_current: int = 0
    progress_total: int = 0
    progress_module: Optional[str] = None
    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None


RunFn = Callable[[Callable[[int, int, str], None]], Awaitable[Dict[str, Any]]]


class JobManager:
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_JOBS)
        self._cleanup_task: Optional[asyncio.Task] = None

    def start_cleanup(self) -> None:
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            self._prune()

    def _prune(self) -> None:
        now = time.time()
        to_remove: List[str] = []
        for jid, job in self._jobs.items():
            if job.status not in ("completed", "failed", "cancelled"):
                continue
            if now - job.created_at > JOB_TTL_SECONDS:
                if job.workspace is not None:
                    cleanup_workspace(job.workspace)
                to_remove.append(jid)
        for jid in to_remove:
            self._jobs.pop(jid, None)

    def create_job(
        self,
        target_type: str,
        target_display: str,
        target_value: str,
        workspace: Optional[Path] = None,
        owner_user_id: Optional[str] = None,
    ) -> Job:
        job = Job(
            job_id=uuid.uuid4().hex,
            target_type=target_type,
            target_display=target_display,
            target_value=target_value,
            workspace=workspace,
            owner_user_id=owner_user_id,
        )
        self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list_jobs(
        self,
        limit: int = 50,
        owner_user_id: Optional[str] = None,
    ) -> List[Job]:
        jobs = self._jobs.values()
        if owner_user_id is not None:
            jobs = [
                job for job in jobs
                if job.owner_user_id == owner_user_id
            ]

        ordered = sorted(
            jobs, key=lambda j: j.created_at, reverse=True
        )
        return ordered[:limit]

    def submit(self, job: Job, run_fn: RunFn) -> None:
        """Schedule a job. Returns immediately; polls read state as it updates."""
        asyncio.create_task(self._run_job(job.job_id, run_fn))

    async def _run_job(self, job_id: str, run_fn: RunFn) -> None:
        async with self._semaphore:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = "running"
            job.started_at = time.time()

            def on_progress(current: int, total: int, module_name: str) -> None:
                job.progress_current = current
                job.progress_total = total
                job.progress_module = module_name

            try:
                report = await run_fn(on_progress)
                job.report = report
                job.status = "completed"
            except FileNotFoundError as exc:
                job.status = "failed"
                job.error = f"Target not found: {exc}"
            except ValueError as exc:
                job.status = "failed"
                job.error = str(exc)
            except Exception as exc:
                job.status = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
            finally:
                job.finished_at = time.time()
                if job.workspace is not None:
                    cleanup_workspace(job.workspace)
                    job.workspace = None


job_manager = JobManager()
