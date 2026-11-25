"""Engagements (assessments) and the assets discovered/attached to them."""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

from .base import TimestampMixin, UUIDMixin


class EngagementStatus(str, enum.Enum):
    DRAFT = "draft"
    AUTHORIZED = "authorized"
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class AssetKind(str, enum.Enum):
    BLUETOOTH = "bluetooth"
    WIFI = "wifi"
    HARDWARE = "hardware"
    FIRMWARE = "firmware"
    UNKNOWN = "unknown"


class Engagement(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "engagements"

    name: Mapped[str] = mapped_column(String(200))
    client: Mapped[str | None] = mapped_column(String(200), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=EngagementStatus.DRAFT.value)

    # --- Rules of Engagement ------------------------------------------------
    authorized_targets: Mapped[list] = mapped_column(JSON, default=list)
    roe_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    roe_signed_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    roe_accepted_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    roe_expires_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    roe_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    assets: Mapped[list["Asset"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class Asset(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(20), default=AssetKind.UNKNOWN.value)
    identifier: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    firmware: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Arbitrary structured attributes: RSSI history, open ports, services, etc.
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    engagement: Mapped[Engagement] = relationship(back_populates="assets")
