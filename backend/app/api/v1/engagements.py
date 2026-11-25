"""Engagement + Rules-of-Engagement endpoints."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import audit, current_user, require_role
from app.core.authorization import compute_roe_signature
from app.core.database import get_db
from app.core.errors import NotFound, ValidationError
from app.models import Asset, Engagement, EngagementStatus, Role, User
from app.schemas import AssetOut, EngagementCreate, EngagementOut, RoeSignRequest

router = APIRouter(prefix="/engagements", tags=["engagements"])


@router.get("", response_model=list[EngagementOut])
def list_engagements(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.execute(select(Engagement).order_by(Engagement.created_at.desc())).scalars().all()


@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
def create_engagement(
    payload: EngagementCreate,
    user: User = Depends(require_role(Role.OPERATOR)),
    db: Session = Depends(get_db),
):
    eng = Engagement(
        name=payload.name, client=payload.client, description=payload.description,
        status=EngagementStatus.DRAFT.value, created_by=user.id,
    )
    db.add(eng)
    audit(db, actor=user.username, action="engagement.create", target=payload.name)
    db.commit()
    db.refresh(eng)
    return eng


@router.get("/{engagement_id}", response_model=EngagementOut)
def get_engagement(
    engagement_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise NotFound("Engagement not found.")
    return eng


@router.post("/{engagement_id}/authorize", response_model=EngagementOut)
def authorize_engagement(
    engagement_id: str,
    payload: RoeSignRequest,
    user: User = Depends(require_role(Role.ADMIN)),
    db: Session = Depends(get_db),
):
    """Sign the Rules of Engagement, cryptographically binding the scope.

    Only an ADMIN can authorize an engagement; the resulting signature is over
    the exact target scope, so silently widening the scope later invalidates it
    (the runner will refuse to launch invasive modules).
    """
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise NotFound("Engagement not found.")
    if not payload.authorized_targets:
        raise ValidationError("At least one authorized target is required.")

    expires_at = (
        dt.datetime.now(dt.UTC) + dt.timedelta(days=payload.expires_in_days)
        if payload.expires_in_days
        else None
    )
    scope = [t.strip() for t in payload.authorized_targets if t.strip()]
    signature = compute_roe_signature(
        engagement_id=eng.id, signed_by=payload.signed_by, scope=scope,
        expires_at=expires_at,
    )
    eng.authorized_targets = scope
    eng.roe_signed_by = payload.signed_by
    eng.roe_reference = payload.reference
    eng.roe_accepted_at = dt.datetime.now(dt.UTC)
    eng.roe_expires_at = expires_at
    eng.roe_signature = signature
    if payload.activate:
        eng.status = EngagementStatus.AUTHORIZED.value
    audit(db, actor=user.username, action="engagement.authorize",
          engagement_id=eng.id, target=payload.reference, detail={"scope": scope})
    db.commit()
    db.refresh(eng)
    return eng


@router.post("/{engagement_id}/status", response_model=EngagementOut)
def set_status(
    engagement_id: str, status_value: str,
    user: User = Depends(require_role(Role.OPERATOR)),
    db: Session = Depends(get_db),
):
    """Update engagement workflow status.

    Flipping to ``authorized`` without re-signing the RoE is restricted to
    admins: the signed scope is the safety control, and an operator moving the
    state machine around it deserves an SPA prompt, not a silent pass.
    """
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise NotFound("Engagement not found.")
    if status_value not in {s.value for s in EngagementStatus}:
        raise ValidationError(f"Unknown status '{status_value}'.")
    if status_value == EngagementStatus.AUTHORIZED.value and user.role != Role.ADMIN.value:
        raise ValidationError(
            "Only admins may set status 'authorized'; use the RoE sign-off flow."
        )
    eng.status = status_value
    audit(db, actor=user.username, action="engagement.status", engagement_id=eng.id,
          detail={"status": status_value})
    db.commit()
    db.refresh(eng)
    return eng


@router.get("/{engagement_id}/assets", response_model=list[AssetOut])
def list_assets(
    engagement_id: str, _: User = Depends(current_user), db: Session = Depends(get_db)
):
    return db.execute(
        select(Asset).where(Asset.engagement_id == engagement_id).order_by(Asset.created_at.desc())
    ).scalars().all()
