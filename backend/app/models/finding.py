"""NetDigno — Finding ORM model."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(8), nullable=True)
    state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)
    nse_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_refs: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list stored as text
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")  # type: ignore[name-defined]
