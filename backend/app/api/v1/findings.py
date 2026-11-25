"""Findings endpoints (filter, inspect, and per-engagement roll-up)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import current_user
from app.core.database import get_db
from app.core.errors import NotFound
from app.models import Finding, User
from app.schemas import FindingOut
from app.services.risk import engagement_risk_score, summary_counts

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(
    engagement_id: str | None = None,
    severity: str | None = None,
    domain: str | None = None,
    category: str | None = None,
    limit: int = Query(default=500, le=2000),
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    stmt = select(Finding).order_by(Finding.created_at.desc()).limit(limit)
    if engagement_id:
        stmt = stmt.where(Finding.engagement_id == engagement_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if domain:
        stmt = stmt.where(Finding.domain == domain)
    if category:
        stmt = stmt.where(Finding.category == category)
    return db.execute(stmt).scalars().all()


@router.get("/summary")
def findings_summary(
    engagement_id: str | None = None,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    stmt = select(Finding)
    if engagement_id:
        stmt = stmt.where(Finding.engagement_id == engagement_id)
    rows = db.execute(stmt).scalars().all()
    dicts = [{"severity": f.severity, "domain": f.domain, "category": f.category} for f in rows]
    by_domain: dict[str, int] = {}
    for d in dicts:
        by_domain[d["domain"]] = by_domain.get(d["domain"], 0) + 1
    return {
        "counts": summary_counts(dicts),
        "risk_score": engagement_risk_score(dicts),
        "by_domain": by_domain,
        "total": len(dicts),
    }


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise NotFound("Finding not found.")
    return finding
