"""Job endpoints: launch modules, stream progress, inspect results.

The authorization gate lives in ``app.core.authorization``; this layer's
critical responsibility is **target derivation**: every active/invasive module
must present a target (MAC, IP, serial device, file, or the explicit ``local``
pseudo-target) so the signed RoE scope actually decides what runs. Deriving no
target would make the scope check vacuous - the bug class the legacy tooling
allowed ("it ran, but nobody knew what it touched").
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import audit, current_user, require_role
from app.core.authorization import Safety, Target, assert_authorized
from app.core.database import get_db
from app.core.errors import AuthorizationRequired, NotFound, ValidationError
from app.jobs.runner import runner
from app.models import ROLE_RANK, Evidence, Engagement, Job, JobLog, JobStatus, Role, User
from app.plugins.hardware import support as hw_support
from app.plugins.registry import registry
from app.plugins.tools import validate_input_path, validate_mac
from app.schemas import JobCreate, JobLogOut, JobOut

router = APIRouter(prefix="/jobs", tags=["jobs"])

MIN_ROLE = {Safety.PASSIVE: Role.AUDITOR, Safety.ACTIVE: Role.OPERATOR, Safety.INVASIVE: Role.OPERATOR}

_SECRET_KEYS = ("password", "passwd", "secret", "token", "credential", "apikey", "api_key")


def _redact(params: dict) -> dict:
    """Audit logs must not store credential material."""
    out = {}
    for k, v in params.items():
        if any(s in k.lower() for s in _SECRET_KEYS):
            out[k] = "***"
        else:
            out[k] = v
    return out


def _contains_path_param(params: dict) -> str | None:
    for key in ("path", "capture_path"):
        if params.get(key):
            return str(params[key])
    return None


def _derive_target(plugin: str, action: str, params: dict) -> Target:
    """Map (plugin, action, params) onto a scope-checkable target.

    Falls back to the ``local`` pseudo-target for actions that touch the rig
    itself (local adapter re-identification, wireless survey, GPIO without a
    serial mapping). For those, the RoE scope must explicitly contain e.g.
    ``local`` (or the specific device path such as ``/dev/ttyUSB0``) - which is
    exactly the intent an operator should have to sign.
    """
    params = params or {}
    if plugin == "bluetooth":
        address = str(params.get("address") or "").strip()
        if address:
            try:
                validate_mac(address)
            except ValidationError as exc:
                raise ValidationError(f"Invalid Bluetooth address: {exc}") from exc
            return Target("bluetooth", address.upper())
        return Target("local", f"bluetooth:{action}")
    if plugin == "wifi":
        host = str(params.get("host") or "").strip()
        if host:
            return Target("wifi", host)
        bssid = str(params.get("bssid") or "").strip()
        if bssid:
            try:
                validate_mac(bssid)
            except ValidationError as exc:
                raise ValidationError(f"Invalid BSSID: {exc}") from exc
            return Target("wifi", bssid.lower())
        subnet = str(params.get("subnet") or "").strip()
        if subnet:
            return Target("wifi", subnet)
        return Target("local", f"wifi:{action}")
    if plugin == "hardware":
        if action == "spi_dump":
            return Target("hardware", "spi")
        port = str(params.get("port") or hw_support.resolve_serial_port() or "")
        if port:
            return Target("hardware", port)
        return Target("local", f"hardware:{action}")
    if plugin == "firmware":
        path = _contains_path_param(params)
        if path:
            return Target("firmware", path)
        return Target("local", f"firmware:{action}")
    return Target("local", plugin)


@router.post("", response_model=JobOut, status_code=status.HTTP_201_CREATED)
def create_job(
    payload: JobCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    spec = registry.get_module(payload.plugin, payload.action)
    if spec is None:
        raise NotFound(f"Module '{payload.plugin}.{payload.action}' not found.")

    # --- role check ---
    min_role = MIN_ROLE[spec.safety]
    if ROLE_RANK[Role(user.role)] < ROLE_RANK[min_role]:
        raise ValidationError(
            f"Module '{payload.plugin}.{payload.action}' is {spec.safety.value} and requires "
            f"role '{min_role.value}' or higher."
        )

    # --- engagement + authorization gate ---
    engagement = None
    if payload.engagement_id:
        engagement = db.get(Engagement, payload.engagement_id)
        if not engagement:
            raise NotFound("Engagement not found.")

    params = dict(payload.params or {})

    # Contain file-typed params BEFORE scope matching so the effective path is
    # the one that will actually be read - and it cannot be /etc/shadow.
    contained = _contains_path_param(params)
    if contained and payload.plugin in ("firmware", "bluetooth"):
        resolved = validate_input_path(contained)
        if "path" in params:
            params["path"] = resolved
        if "capture_path" in params:
            params["capture_path"] = resolved

    if spec.safety is not Safety.PASSIVE and engagement is None:
        raise AuthorizationRequired(
            "Active/invasive modules run only under an engagement with a signed "
            "Rules-of-Engagement.",
            details={"gate": "engagement_required"},
        )

    target = _derive_target(payload.plugin, payload.action, params)
    assert_authorized(engagement, spec.safety, target)

    # --- missing capability guard (fail fast with a clear message) ---
    from app.plugins.capabilities import missing

    miss = missing(spec.capabilities)
    # We allow launch anyway for passive read-only modules that can degrade;
    # but we surface the warning in the job message.
    warn = f"missing capabilities: {[c.id for c in miss]}" if miss else ""

    if target:
        params["_target_kind"] = target.kind
        params["_target_id"] = target.identifier

    job = Job(
        engagement_id=payload.engagement_id, asset_id=payload.asset_id,
        plugin=payload.plugin, action=payload.action, safety=spec.safety.value,
        params=params, status=JobStatus.QUEUED.value, created_by=user.id,
        message=warn or "queued",
    )
    db.add(job)
    audit(db, actor=user.username, action="job.create", engagement_id=payload.engagement_id,
          target=f"{payload.plugin}.{payload.action}",
          detail={"safety": spec.safety.value,
                  "params": _redact({k: v for k, v in payload.params.items()})})
    db.commit()
    db.refresh(job)

    runner.submit(job.id)
    return job


@router.get("", response_model=list[JobOut])
def list_jobs(
    engagement_id: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, le=500),
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    stmt = select(Job).order_by(Job.created_at.desc()).limit(limit)
    if engagement_id:
        stmt = stmt.where(Job.engagement_id == engagement_id)
    if status_filter:
        stmt = stmt.where(Job.status == status_filter)
    return db.execute(stmt).scalars().all()


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if not job:
        raise NotFound("Job not found.")
    return job


@router.get("/{job_id}/logs", response_model=list[JobLogOut])
def get_logs(job_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.execute(
        select(JobLog).where(JobLog.job_id == job_id).order_by(JobLog.ts.asc()).limit(2000)
    ).scalars().all()


@router.get("/{job_id}/evidence")
def get_evidence(job_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(Evidence).where(Evidence.job_id == job_id)).scalars().all()
    return [
        {"id": e.id, "kind": e.kind, "filename": e.filename, "sha256": e.sha256,
         "size": e.size, "note": e.note}
        for e in rows
    ]


@router.get("/{job_id}/evidence/{evidence_id}/download")
def download_evidence(
    job_id: str, evidence_id: str,
    _: User = Depends(current_user), db: Session = Depends(get_db),
):
    """Download a captured artefact (boot log, pcap, firmware dump, report, ...)."""
    from fastapi.responses import FileResponse

    ev = db.get(Evidence, evidence_id)
    if not ev or ev.job_id != job_id:
        raise NotFound("Evidence not found.")
    path = Path(ev.path)
    if not path.exists():
        raise NotFound(f"Evidence file is missing on disk: {ev.path}")
    return FileResponse(
        path, filename=ev.filename or path.name,
        media_type="application/octet-stream",
    )


@router.post("/{job_id}/cancel", response_model=JobOut)
def cancel_job(
    job_id: str, user: User = Depends(require_role(Role.OPERATOR)), db: Session = Depends(get_db)
):
    job = db.get(Job, job_id)
    if not job:
        raise NotFound("Job not found.")
    if job.status not in (JobStatus.QUEUED.value, JobStatus.RUNNING.value):
        raise ValidationError(
            f"Job already finished ({job.status}); nothing to cancel."
        )
    runner.cancel(job_id)
    job.status = JobStatus.CANCELLED.value
    job.message = "cancelled by operator"
    audit(db, actor=user.username, action="job.cancel", target=job_id)
    db.commit()
    db.refresh(job)
    return job
