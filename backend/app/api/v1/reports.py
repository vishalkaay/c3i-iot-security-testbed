"""Report generation and download endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import audit, current_user, require_role
from app.core.database import get_db
from app.core.errors import NotFound, ValidationError
from app.models import Asset, Engagement, Finding, Job, Report, Role, User
from app.schemas import ReportOut, ReportRequest
from app.services import reporting

router = APIRouter(tags=["reports"])


@router.post("/engagements/{engagement_id}/reports", response_model=ReportOut)
def create_report(
    engagement_id: str,
    payload: ReportRequest,
    user: User = Depends(require_role(Role.AUDITOR)),
    db: Session = Depends(get_db),
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise NotFound("Engagement not found.")
    if payload.kind not in reporting.RENDERERS:
        raise ValidationError(f"Unsupported report kind '{payload.kind}'.")

    assets = db.execute(select(Asset).where(Asset.engagement_id == engagement_id)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.engagement_id == engagement_id)).scalars().all()
    jobs = db.execute(select(Job).where(Job.engagement_id == engagement_id)).scalars().all()

    dataset = reporting.build_dataset(eng, assets, findings, jobs)
    if payload.title:
        dataset["engagement"]["name"] = payload.title
    path, _ext = reporting.generate(dataset, payload.kind, engagement_id)

    report = Report(engagement_id=engagement_id, kind=payload.kind, path=str(path),
                    generated_by=user.id, summary=dataset["summary"])
    db.add(report)
    audit(db, actor=user.username, action="report.create", engagement_id=engagement_id,
          detail={"kind": payload.kind})
    db.commit()
    db.refresh(report)
    return ReportOut(id=report.id, engagement_id=report.engagement_id, kind=report.kind,
                     path=report.path, summary=report.summary, created_at=report.created_at)


@router.get("/engagements/{engagement_id}/reports", response_model=list[ReportOut])
def list_reports(
    engagement_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)
):
    rows = db.execute(
        select(Report).where(Report.engagement_id == engagement_id).order_by(Report.created_at.desc())
    ).scalars().all()
    return [
        ReportOut(id=r.id, engagement_id=r.engagement_id, kind=r.kind, path=r.path,
                  summary=r.summary, created_at=r.created_at)
        for r in rows
    ]


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise NotFound("Report not found.")
    path = Path(report.path)
    if not path.exists():
        raise NotFound("Report file is missing on disk.")
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


@router.get("/reports/{report_id}/view")
def view_report(report_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise NotFound("Report not found.")
    path = Path(report.path)
    if not path.exists():
        raise NotFound("Report file is missing on disk.")
    if path.suffix == ".html":
        return FileResponse(path, media_type="text/html")
    if path.suffix == ".json" or path.name.endswith(".sarif.json"):
        return FileResponse(path, media_type="application/json")
    return FileResponse(path, media_type="application/pdf")
