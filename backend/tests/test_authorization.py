"""Rules-of-Engagement gate tests - the most safety-critical behaviour."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import pytest

from app.core.authorization import (
    Safety,
    Target,
    assert_authorized,
    compute_roe_signature,
    verify_roe_signature,
)
from app.core.errors import AuthorizationRequired, Forbidden


@dataclass
class FakeEngagement:
    id: str = "eng-1"
    status: str = "authorized"
    authorized_targets: list = field(default_factory=lambda: ["AA:BB:CC:*", "192.168.1.0/24"])
    roe_signed_by: str = "Vishal"
    roe_accepted_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.UTC))
    roe_expires_at: dt.datetime | None = field(
        default_factory=lambda: dt.datetime.now(dt.UTC) + dt.timedelta(days=30)
    )
    roe_signature: str = ""

    def sign(self) -> "FakeEngagement":
        self.roe_signature = compute_roe_signature(
            engagement_id=self.id,
            signed_by=self.roe_signed_by,
            scope=self.authorized_targets,
            expires_at=self.roe_expires_at,
        )
        return self


def test_safety_ranking():
    assert Safety.PASSIVE.rank < Safety.ACTIVE.rank < Safety.INVASIVE.rank


def test_passive_always_allowed():
    assert_authorized(None, Safety.PASSIVE, None)  # no engagement needed


def test_signature_round_trip():
    sig = compute_roe_signature(
        engagement_id="e1", signed_by="A", scope=["x"], expires_at=None
    )
    assert verify_roe_signature(
        engagement_id="e1", signed_by="A", scope=["x"], expires_at=None, signature=sig
    )


def test_active_requires_roe():
    eng = FakeEngagement(roe_accepted_at=None, roe_signature="")
    with pytest.raises(AuthorizationRequired):
        assert_authorized(eng, Safety.ACTIVE, Target("bluetooth", "AA:BB:CC:11:22:33"))


def test_in_scope_glob_and_cidr():
    eng = FakeEngagement().sign()
    # glob match
    assert_authorized(eng, Safety.INVASIVE, Target("bluetooth", "AA:BB:CC:DE:AD:BE"))
    # cidr match
    assert_authorized(eng, Safety.ACTIVE, Target("wifi", "192.168.1.55"))


def test_out_of_scope_rejected():
    eng = FakeEngagement().sign()
    with pytest.raises(Forbidden):
        assert_authorized(eng, Safety.INVASIVE, Target("bluetooth", "11:22:33:44:55:66"))


def test_scope_tampering_invalidates_signature():
    eng = FakeEngagement().sign()
    # Widen the scope WITHOUT re-signing.
    eng.authorized_targets = ["*"]
    with pytest.raises(Forbidden):
        assert_authorized(eng, Safety.INVASIVE, Target("bluetooth", "DE:AD:BE:EF:00:01"))


def test_expired_roe_rejected():
    eng = FakeEngagement(
        roe_expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    ).sign()
    with pytest.raises(AuthorizationRequired):
        assert_authorized(eng, Safety.ACTIVE, Target("wifi", "192.168.1.1"))


def test_naive_datetime_roundtrip(tmp_path):
    """A datetime that loses tzinfo through the DB must still verify."""
    aware = dt.datetime(2030, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    sig = compute_roe_signature(
        engagement_id="e2", signed_by="A", scope=["x"], expires_at=aware
    )
    naive = aware.replace(tzinfo=None)  # simulates SQLite
    assert verify_roe_signature(
        engagement_id="e2", signed_by="A", scope=["x"], expires_at=naive, signature=sig
    )
