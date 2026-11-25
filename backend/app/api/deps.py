"""FastAPI dependencies: authentication, RBAC, and audit logging."""

from __future__ import annotations

import datetime as dt

from fastapi import Depends, Header
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.errors import AuthError, Forbidden
from app.core.security import decode_token, verify_api_key
from app.models import ROLE_RANK, ApiKey, AuditLog, Role, User


def _load_by_token(token: str, db: Session) -> User:
    try:
        payload = decode_token(token)
    except Exception as exc:  # noqa: BLE001
        raise AuthError(f"Invalid or expired token: {exc}") from exc
    user = db.get(User, payload.get("sub"))
    if not user or not user.is_active:
        raise AuthError("User not found or inactive.")
    return user


def _load_by_api_key(raw_key: str, db: Session) -> User:
    prefix = raw_key[:8]
    candidates = db.execute(
        select(ApiKey).where(ApiKey.prefix == prefix, ApiKey.revoked.is_(False))
    ).scalars().all()
    for key in candidates:
        if verify_api_key(raw_key, key.hashed_key):
            key.last_used = dt.datetime.now(dt.UTC)
            db.commit()
            user = db.get(User, key.user_id)
            if user and user.is_active:
                return user
    raise AuthError("Invalid API key.")


def _dev_user(db: Session) -> User:
    """Return the first admin user (or create a dev one) for no-auth mode."""
    user = db.execute(select(User).where(User.role == "admin")).scalars().first()
    if user:
        return user
    # create a throwaway dev user
    from app.core.security import hash_password
    user = User(
        username="dev", full_name="Dev User", hashed_password=hash_password("dev"),
        role="admin", is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def current_user(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    # DEV MODE: bypass all auth
    if settings.dev_no_auth:
        return _dev_user(db)

    if x_api_key:
        return _load_by_api_key(x_api_key, db)
    if authorization and authorization.lower().startswith("bearer "):
        return _load_by_token(authorization.split(" ", 1)[1], db)
    raise AuthError("Authentication required (Bearer token or X-API-Key).")


def require_role(minimum: Role):
    def checker(user: User = Depends(current_user)) -> User:
        try:
            role = Role(user.role)
        except ValueError:
            role = Role.VIEWER
        if ROLE_RANK[role] < ROLE_RANK[minimum]:
            raise Forbidden(f"Requires role '{minimum.value}' or higher.")
        return user

    return checker


def audit(db: Session, *, actor: str | None, action: str, target: str | None = None,
          engagement_id: str | None = None, outcome: str = "ok", detail: dict | None = None) -> None:
    db.add(
        AuditLog(actor=actor, action=action, target=target, engagement_id=engagement_id,
                 outcome=outcome, detail=detail or {})
    )
