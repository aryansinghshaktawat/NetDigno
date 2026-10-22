"""NetScope — scan and finding database repositories."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus

logger = logging.getLogger(__name__)


# ── Scan repository ──────────────────────────────────────────────────────────

async def create_scan(
    db: AsyncSession,
    target: str,
    profile: str,
) -> Scan:
    scan = Scan(target=target, profile=profile, status=ScanStatus.PENDING)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def update_scan_running(db: AsyncSession, scan: Scan) -> Scan:
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    await db.commit()
    await db.refresh(scan)
    return scan


async def complete_scan(
    db: AsyncSession,
    scan: Scan,
    *,
    status: str,
    findings_data: List[dict],
    duration_seconds: float,
    nmap_command: Optional[str] = None,
    exit_code: Optional[int] = None,
    error_message: Optional[str] = None,
    raw_output: Optional[str] = None,
) -> Scan:
    scan.status = status
    scan.completed_at = datetime.utcnow()
    scan.duration_seconds = duration_seconds
    scan.nmap_command = nmap_command
    scan.exit_code = exit_code
    scan.error_message = error_message
    scan.raw_output = (raw_output or "")[:8192]  # cap stored output size

    for f_data in findings_data:
        cve_refs = f_data.get("cve_refs")
        finding = Finding(
            scan_id=scan.id,
            port=f_data.get("port"),
            protocol=f_data.get("protocol"),
            state=f_data.get("state"),
            service=f_data.get("service"),
            version=f_data.get("version"),
            cpe=f_data.get("cpe"),
            nse_output=f_data.get("nse_output"),
            cve_refs=json.dumps(cve_refs) if cve_refs else None,
            evidence=f_data.get("evidence"),
        )
        db.add(finding)

    await db.commit()
    await db.refresh(scan)
    return scan


async def get_scan_by_id(db: AsyncSession, scan_id: str) -> Optional[Scan]:
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.findings))
        .where(Scan.id == scan_id)
    )
    return result.scalar_one_or_none()


async def list_scans(
    db: AsyncSession,
    *,
    target: Optional[str] = None,
    profile: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
) -> tuple[int, List[Scan]]:
    """Return (total_count, page_items) with optional filters."""
    stmt = select(Scan)
    if target:
        stmt = stmt.where(Scan.target.ilike(f"%{target}%"))
    if profile:
        stmt = stmt.where(Scan.profile == profile)
    if status:
        stmt = stmt.where(Scan.status == status)
    stmt = stmt.order_by(Scan.started_at.desc())

    # Total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    # Paginated results
    offset = (page - 1) * page_size
    stmt = stmt.offset(offset).limit(page_size)
    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return total, items
