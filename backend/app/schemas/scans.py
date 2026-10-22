"""NetScope — Pydantic schemas for scan endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

from app.models.scan import ScanProfile, ScanStatus


def _validate_target(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("Target must not be empty.")
    if len(v) > 253:
        raise ValueError("Target exceeds maximum length.")
    return v


# ── Scan request ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, examples=["127.0.0.1"])
    profile: ScanProfile = Field(default=ScanProfile.QUICK)
    authorized: bool = Field(
        ...,
        description="User explicitly confirms they are authorised to scan this target.",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("authorized")
    @classmethod
    def require_authorization(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm authorisation to scan the target before proceeding."
            )
        return v


# ── Finding ──────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    scan_id: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    state: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    nse_output: Optional[str] = None
    cve_refs: Optional[List[str]] = None
    evidence: Optional[str] = None
    recorded_at: datetime

    model_config = {"from_attributes": True}


# ── Scan out ─────────────────────────────────────────────────────────────────

class ScanOut(BaseModel):
    id: str
    target: str
    profile: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    exit_code: Optional[int] = None
    findings: List[FindingOut] = []

    model_config = {"from_attributes": True}


class ScanSummaryOut(BaseModel):
    id: str
    target: str
    profile: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    finding_count: int = 0

    model_config = {"from_attributes": True}


# ── Paginated list ────────────────────────────────────────────────────────────

class PaginatedScans(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[ScanSummaryOut]


# ── Comparison ───────────────────────────────────────────────────────────────

class PortChange(BaseModel):
    port: int
    protocol: str
    change_type: str  # "new_open", "now_closed", "version_changed"
    baseline_value: Optional[str] = None
    current_value: Optional[str] = None


class ComparisonResult(BaseModel):
    baseline_scan_id: str
    current_scan_id: str
    target: str
    comparable: bool
    reason: Optional[str] = None
    new_open_ports: List[PortChange] = []
    closed_ports: List[PortChange] = []
    version_changes: List[PortChange] = []
    note: str = (
        "Changes are based on what was observed in each scan at its specific "
        "time. A port classified as newly open was not observed open in the "
        "baseline scan — this may reflect actual changes or scan coverage differences."
    )
