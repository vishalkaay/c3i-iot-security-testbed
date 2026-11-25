"""Authentication, user, and API-key endpoints."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import audit, current_user, require_role
from app.core.database import get_db
from app.core.errors import AuthError, Conflict, NotFound
from app.core.security import create_access_token, hash_password, new_api_key, verify_password
from app.models import ApiKey, Role, User
from app.schemas import (
    AdminPasswordSet,
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    LoginRequest,
    PasswordChange,
    TokenResponse,
    UserCreate,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.username == payload.username)).scalars().first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise AuthError("Invalid username or password.")
    if not user.is_active:
        raise AuthError("Account is disabled.")
    user.last_login = dt.datetime.now(dt.UTC)
    audit(db, actor=user.username, action="login", outcome="ok")
    db.commit()
    token = create_access_token(user.id, user.role)
    return TokenResponse(access_token=token, role=user.role, username=user.username)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/password", response_model=UserOut)
def change_password(
    payload: PasswordChange,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Change the calling user's password (re-verified against the current one)."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise AuthError("Current password is incorrect.")
    user.hashed_password = hash_password(payload.new_password)
    audit(db, actor=user.username, action="user.change_password", target=user.username)
    db.commit()
    db.refresh(user)
    return user


@users_router.post("/{user_id}/password", response_model=UserOut)
def admin_set_password(
    user_id: str,
    payload: AdminPasswordSet,
    admin: User = Depends(require_role(Role.ADMIN)),
    db: Session = Depends(get_db),
):
    """Admin password reset (e.g. for a locked-out auditor)."""
    user = db.get(User, user_id)
    if not user:
        raise NotFound("User not found.")
    user.hashed_password = hash_password(payload.new_password)
    audit(db, actor=admin.username, action="user.admin_password_set", target=user.username)
    db.commit()
    db.refresh(user)
    return user


@router.post("/apikeys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: ApiKeyCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    raw, prefix, hashed = new_api_key()
    key = ApiKey(user_id=user.id, name=payload.name, prefix=prefix, hashed_key=hashed)
    db.add(key)
    audit(db, actor=user.username, action="apikey.create", target=payload.name)
    db.commit()
    db.refresh(key)
    return ApiKeyCreated(
        id=key.id, name=key.name, prefix=key.prefix, revoked=key.revoked,
        created_at=key.created_at, key=raw,
    )


@router.get("/apikeys", response_model=list[ApiKeyOut])
def list_api_keys(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.execute(select(ApiKey).where(ApiKey.user_id == user.id)).scalars().all()


@router.delete("/apikeys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(key_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    key = db.get(ApiKey, key_id)
    if not key or key.user_id != user.id:
        raise NotFound("API key not found.")
    key.revoked = True
    audit(db, actor=user.username, action="apikey.revoke", target=key.name)
    db.commit()


# --------------------------------------------------------------------------- #
# user administration
# --------------------------------------------------------------------------- #
@users_router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(require_role(Role.ADMIN)), db: Session = Depends(get_db)):
    return db.execute(select(User)).scalars().all()


@users_router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    admin: User = Depends(require_role(Role.ADMIN)),
    db: Session = Depends(get_db),
):
    if db.execute(select(User).where(User.username == payload.username)).scalars().first():
        raise Conflict("Username already exists.")
    if payload.role not in {r.value for r in Role}:
        raise Conflict(f"Unknown role '{payload.role}'.")
    user = User(
        username=payload.username, email=payload.email, full_name=payload.full_name,
        hashed_password=hash_password(payload.password), role=payload.role,
    )
    db.add(user)
    audit(db, actor=admin.username, action="user.create", target=payload.username)
    db.commit()
    db.refresh(user)
    return user


@users_router.patch("/{user_id}/role", response_model=UserOut)
def set_role(
    user_id: str, role: str,
    admin: User = Depends(require_role(Role.ADMIN)),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if not user:
        raise NotFound("User not found.")
    if role not in {r.value for r in Role}:
        raise Conflict(f"Unknown role '{role}'.")
    user.role = role
    audit(db, actor=admin.username, action="user.set_role", target=user.username, detail={"role": role})
    db.commit()
    db.refresh(user)
    return user
