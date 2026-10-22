"""NetDigno — Scan ORM model."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ScanProfile(str, enum.Enum):
    QUICK = "quick"
    SERVICE = "service"
    VULN = "vuln"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    profile: Mapped[str] = mapped_column(String(32), nullable=False, default=ScanProfile.QUICK)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ScanStatus.PENDING
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    nmap_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(  # type: ignore[name-defined]
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
