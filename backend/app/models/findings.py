"""Findings, evidence artefacts, generated reports, and the audit trail."""

from __future__ import annotations

import enum

from sqlalchemy import Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

from .base import TimestampMixin, UUIDMixin


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> float:
        return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}[self.value]


class Finding(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), index=True, nullable=True
    )
    engagement_id: Mapped[str | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True, nullable=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True, nullable=True
    )

    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(64), index=True)  # firmware, network, bluetooth, hardware
    domain: Mapped[str] = mapped_column(String(32), index=True)    # bluetooth | wifi | hardware
    severity: Mapped[str] = mapped_column(String(16), default=Severity.INFO.value, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)

    # Stable identity for de-duplication across repeated scans / audit drift.
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)


class Evidence(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidence"

    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), index=True, nullable=True
    )
    kind: Mapped[str] = mapped_column(String(32))          # bootlog, pcap, firmware, screenshot, glitch-log
    filename: Mapped[str] = mapped_column(String(300))
    path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(default=0)
    note: Mapped[str | None] = mapped_column(String(400), nullable=True)


class Report(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "reports"

    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(20))          # html | pdf | json | sarif
    path: Mapped[str] = mapped_column(String(500))
    generated_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditLog(UUIDMixin, TimestampMixin, Base):
    """Record of security-relevant actions (who did what, when, and outcome)."""

    __tablename__ = "audit_logs"

    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="ok")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
