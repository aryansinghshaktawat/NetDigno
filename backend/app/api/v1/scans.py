"""NetDigno — scans API endpoints."""

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select

from app.core.config import settings
from app.models.base import get_db
from app.models.scan import Scan, ScanStatus
from app.repositories.scan_repository import (
    complete_scan, create_scan, get_scan_by_id, list_scans, update_scan_running
)
from app.schemas.scans import (
    ComparisonResult, FindingOut, PaginatedScans, ScanOut, ScanRequest, ScanSummaryOut
)
from app.security.allowlist import AllowlistError, validate_target_allowed
from app.services.nmap_service import nmap_available, run_nmap_scan
from app.services.scan_comparison import compare_scans

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# Semaphore to cap concurrent scans
_scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)


def _serialise_scan_summary(scan: Scan, finding_count: int = 0) -> ScanSummaryOut:
    return ScanSummaryOut(
        id=scan.id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        finding_count=finding_count,
    )


def _serialise_finding(f) -> FindingOut:
    cve_list = None
    if f.cve_refs:
        try:
            cve_list = json.loads(f.cve_refs)
        except (json.JSONDecodeError, TypeError):
            cve_list = [f.cve_refs]
    return FindingOut(
        id=f.id,
        scan_id=f.scan_id,
        port=f.port,
        protocol=f.protocol,
        state=f.state,
        service=f.service,
        version=f.version,
        cpe=f.cpe,
        nse_output=f.nse_output,
        cve_refs=cve_list,
        evidence=f.evidence,
        recorded_at=f.recorded_at,
    )


def _serialise_scan(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        error_message=scan.error_message,
        exit_code=scan.exit_code,
        findings=[_serialise_finding(f) for f in (scan.findings or [])],
    )


# ── POST /scans — start a new scan ───────────────────────────────────────────

@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.scan_rate_limit)
async def start_scan(
    request: Request,
    body: ScanRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Start a new Nmap-based port and service scan.

    Requires explicit authorisation confirmation in the request body.
    Target must be in the configured allowlist.
    Profile determines the scan depth and timeout.
    """
    # ── Allowlist check ───────────────────────────────────────────────────
    try:
        target = validate_target_allowed(body.target)
    except AllowlistError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    # ── Nmap availability ─────────────────────────────────────────────────
    if not nmap_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nmap is not available on this system. Scanning is disabled.",
        )

    # ── Concurrency limit ─────────────────────────────────────────────────
    if _scan_semaphore.locked() and _scan_semaphore._value == 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached. Retry shortly.",
        )

    # ── Create scan record ────────────────────────────────────────────────
    scan = await create_scan(db, target=target, profile=body.profile)
    logger.info("Scan %s started: target=%s profile=%s", scan.id, target, body.profile)

    # ── Execute scan (synchronous in executor to avoid blocking event loop)
    async with _scan_semaphore:
        scan = await update_scan_running(db, scan)
        loop = asyncio.get_event_loop()
        nmap_result = await loop.run_in_executor(
            None, run_nmap_scan, target, body.profile
        )

    # ── Determine final status ────────────────────────────────────────────
    if nmap_result.timed_out:
        final_status = ScanStatus.TIMEOUT
    elif nmap_result.exit_code not in (0, 1) or nmap_result.error_message:
        final_status = ScanStatus.FAILED
    else:
        final_status = ScanStatus.COMPLETED

    command_str = " ".join(nmap_result.command) if nmap_result.command else None

    scan = await complete_scan(
        db, scan,
        status=final_status,
        findings_data=nmap_result.findings,
        duration_seconds=nmap_result.duration_seconds,
        nmap_command=command_str,
        exit_code=nmap_result.exit_code,
        error_message=nmap_result.error_message,
        raw_output=nmap_result.stdout,
    )

    # Reload with findings
    scan = await get_scan_by_id(db, scan.id)
    return _serialise_scan(scan)


# ── GET /scans — paginated list ───────────────────────────────────────────────

@router.get("", response_model=PaginatedScans)
async def list_scans_endpoint(
    target: Optional[str] = Query(None, max_length=253),
    profile: Optional[str] = Query(None),
    scan_status: Optional[str] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List scan history with optional filters and pagination."""
    total, items = await list_scans(
        db, target=target, profile=profile, status=scan_status,
        page=page, page_size=page_size,
    )
    summaries = []
    for scan in items:
        # Eager-load finding count without loading all finding data
        stmt = select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan.id)
        result = await db.execute(stmt)
        loaded = result.scalar_one_or_none()
        count = len(loaded.findings) if loaded else 0
        summaries.append(_serialise_scan_summary(scan, finding_count=count))

    return PaginatedScans(total=total, page=page, page_size=page_size, items=summaries)


# ── GET /scans/compare ────────────────────────────────────────────────────────

@router.get("/compare", response_model=ComparisonResult)
async def compare_scans_endpoint(
    baseline_id: str = Query(..., min_length=1),
    current_id: str = Query(..., min_length=1),
    db: AsyncSession = Depends(get_db),
):
    """
    Compare two scan snapshots and identify port/service changes.

    Both scans must cover the same target. Incomplete baseline scans
    are explicitly flagged as non-comparable.
    """
    baseline = await get_scan_by_id(db, baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"Scan '{baseline_id}' not found.")

    current = await get_scan_by_id(db, current_id)
    if not current:
        raise HTTPException(status_code=404, detail=f"Scan '{current_id}' not found.")

    return compare_scans(baseline, current)


# ── GET /scans/{scan_id} ──────────────────────────────────────────────────────

@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve a single scan record with all findings."""
    scan = await get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return _serialise_scan(scan)


# ── GET /scans/{scan_id}/findings ────────────────────────────────────────────

@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def get_scan_findings(
    scan_id: str,
    state: Optional[str] = Query(None, description="Filter by port state (e.g. 'open')"),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve all findings for a scan, optionally filtered by port state."""
    scan = await get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    findings = scan.findings
    if state:
        findings = [f for f in findings if f.state == state]

    return [_serialise_finding(f) for f in findings]
