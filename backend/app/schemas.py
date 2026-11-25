"""Pydantic request/response schemas for the API."""

from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    username: str
    email: str | None = None
    full_name: str | None = None
    role: str
    is_active: bool
    created_at: dt.datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=200)
    email: str | None = None
    full_name: str | None = None
    role: str = "viewer"


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=200)


class AdminPasswordSet(BaseModel):
    new_password: str = Field(min_length=8, max_length=200)


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    revoked: bool
    created_at: dt.datetime


class ApiKeyCreated(ApiKeyOut):
    key: str  # plaintext, shown once


class ApiKeyCreate(BaseModel):
    name: str = "default"


# --------------------------------------------------------------------------- #
# engagements
# --------------------------------------------------------------------------- #
class EngagementCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    client: str | None = None
    description: str | None = None


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    client: str | None
    description: str | None
    status: str
    authorized_targets: list[str]
    roe_reference: str | None
    roe_signed_by: str | None
    roe_accepted_at: dt.datetime | None
    roe_expires_at: dt.datetime | None
    created_at: dt.datetime


class RoeSignRequest(BaseModel):
    signed_by: str = Field(description="Name/role of the person authorizing the engagement")
    reference: str = Field(description="Contract / ticket / authorization reference")
    authorized_targets: list[str] = Field(description="Scope: MACs, IPs, CIDRs, globs")
    expires_in_days: int | None = Field(default=30, ge=1, le=365)
    activate: bool = True


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    kind: str
    identifier: str
    name: str | None
    vendor: str | None
    model: str | None
    firmware: str | None
    attributes: dict[str, Any]
    created_at: dt.datetime


# --------------------------------------------------------------------------- #
# jobs
# --------------------------------------------------------------------------- #
class JobCreate(BaseModel):
    engagement_id: str | None = None
    asset_id: str | None = None
    plugin: str
    action: str
    params: dict[str, Any] = Field(default_factory=dict)


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str | None
    asset_id: str | None
    plugin: str
    action: str
    safety: str
    params: dict[str, Any]
    status: str
    progress: int
    message: str | None
    error: str | None
    result: dict[str, Any] | None
    created_at: dt.datetime
    started_at: dt.datetime | None
    finished_at: dt.datetime | None


class JobLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    ts: dt.datetime
    level: str
    message: str


# --------------------------------------------------------------------------- #
# findings / reports
# --------------------------------------------------------------------------- #
class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    job_id: str | None
    engagement_id: str | None
    asset_id: str | None
    title: str
    category: str
    domain: str
    severity: str
    cvss_score: float | None
    epss_score: float | None
    cve_ids: list[str]
    cwe_ids: list[str]
    description: str | None
    evidence: str | None
    remediation: str | None
    references: list[str]
    extra: dict[str, Any]
    created_at: dt.datetime


class ReportRequest(BaseModel):
    kind: str = Field(default="html", description="html | json | sarif | pdf")
    title: str | None = None


class ReportOut(BaseModel):
    id: str
    engagement_id: str
    kind: str
    path: str
    summary: dict[str, Any]
    created_at: dt.datetime
