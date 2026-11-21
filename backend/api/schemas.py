from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel


class ModuleInfo(BaseModel):
    name: str
    description: str
    target_types: List[str]
    requires_key: bool
    available: bool
    authorized: bool = False
    sensitive: bool = False
    daily_limit: Optional[int] = None
    monthly_limit: Optional[int] = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    modules_available: int
    target_types: List[str]


class JobStatus(BaseModel):
    job_id: str
    target_type: str
    target_display: str
    status: Literal["pending", "running", "completed", "failed", "cancelled"]
    progress_current: int = 0
    progress_total: int = 0
    progress_module: Optional[str] = None
    created_at: float
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    report_available: bool = False


class InvestigateResponse(BaseModel):
    job_id: str
    status: str
