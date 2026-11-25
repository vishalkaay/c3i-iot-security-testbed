"""Rules-of-Engagement (RoE) authorization gate.

This is the single most important safety control in the testbed. Every module
declares an *intrusiveness* level. Passive modules may run freely; active and
invasive modules are refused unless **all** of the following hold:

1. ``C3I_ENABLE_INVASIVE`` is true on the host.
2. The engagement is in the ``authorized`` state.
3. A Rules-of-Engagement document was accepted and has not expired.
4. The stored RoE signature still matches a fresh HMAC over the engagement's
   scope (so nobody can quietly widen the target list after signing).
5. The requested target falls inside the signed scope.

The last two points are what elevate this from a checkbox to a real control:
the authorization is cryptographically bound to the *scope*, not just to a
boolean.
"""

from __future__ import annotations

import datetime as dt
import enum
import fnmatch
import hashlib
import hmac
import ipaddress
from dataclasses import dataclass

from .config import settings
from .errors import AuthorizationRequired, Forbidden


class Safety(str, enum.Enum):
    """How disruptive a module is to the device under test."""

    PASSIVE = "passive"      # read-only: scan, capture, analyse
    ACTIVE = "active"        # sends probes / authenticates / writes
    INVASIVE = "invasive"    # may reboot, brick, or degrade the device

    @property
    def rank(self) -> int:
        return {"passive": 0, "active": 1, "invasive": 2}[self.value]


@dataclass(frozen=True)
class Target:
    """Normalised target descriptor used for scope matching."""

    kind: str          # bluetooth | wifi | ip | hardware | firmware | local
    identifier: str    # MAC, IP, serial, hostname, file path


def _canon_dt(value: dt.datetime | None) -> str | None:
    """Canonical UTC, second-resolution string (SQLite drops tzinfo).

    Both signing and verification go through this so a value that round-trips
    through the database yields an identical signature component.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC).replace(microsecond=0).isoformat()


def _as_utc(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value.astimezone(dt.UTC)


def compute_roe_signature(
    *,
    engagement_id: str,
    signed_by: str,
    scope: list[str],
    expires_at: dt.datetime | None,
) -> str:
    """Deterministic HMAC binding an authorization to its exact scope."""
    material = "|".join(
        [
            engagement_id,
            signed_by.strip().lower(),
            ",".join(sorted(s.strip().lower() for s in scope)),
            _canon_dt(expires_at) or "no-expiry",
        ]
    )
    return hmac.new(settings.secret_key.encode(), material.encode(), hashlib.sha256).hexdigest()


def verify_roe_signature(
    *,
    engagement_id: str,
    signed_by: str,
    scope: list[str],
    expires_at: dt.datetime | None,
    signature: str,
) -> bool:
    expected = compute_roe_signature(
        engagement_id=engagement_id, signed_by=signed_by, scope=scope, expires_at=expires_at
    )
    return hmac.compare_digest(expected, signature or "")


def _in_scope(target: Target, scope: list[str]) -> bool:
    ident = target.identifier.strip().lower()
    for entry in scope:
        entry = entry.strip().lower()
        if not entry:
            continue
        # The pseudo-target "local" means "the test rig itself" (adapter mode
        # changes, GPIO, power). A scope entry of exactly "local" authorises it.
        if target.kind == "local" and entry == "local":
            return True
        # Exact match or shell-style glob (e.g. AA:BB:CC:*).
        if ident == entry or fnmatch.fnmatch(ident, entry):
            return True
        # CIDR / IP membership.
        try:
            if "/" in entry and ipaddress.ip_address(ident) in ipaddress.ip_network(
                entry, strict=False
            ):
                return True
        except ValueError:
            pass
    return False


def assert_authorized(engagement, safety: Safety, target: Target | None) -> None:
    """Raise unless the request is permitted. ``engagement`` is ORM object-like."""
    if safety is Safety.PASSIVE:
        return

    if not settings.enable_invasive:
        raise AuthorizationRequired(
            "Invasive modules are disabled on this host. Set C3I_ENABLE_INVASIVE=true "
            "and provide a signed Rules of Engagement to proceed.",
            details={"safety": safety.value, "gate": "host_disabled"},
        )

    status = getattr(engagement, "status", None)
    if status not in ("authorized", "active"):
        raise AuthorizationRequired(
            "Engagement is not authorized. Accept and sign the Rules of Engagement first.",
            details={"safety": safety.value, "gate": "engagement_status", "status": status},
        )

    if not getattr(engagement, "roe_accepted_at", None):
        raise AuthorizationRequired("No accepted Rules of Engagement on file.",
                                    details={"gate": "roe_missing"})

    expires_at = _as_utc(getattr(engagement, "roe_expires_at", None))
    if expires_at and expires_at <= dt.datetime.now(dt.UTC):
        raise AuthorizationRequired("Rules of Engagement have expired.",
                                    details={"gate": "roe_expired", "expires_at": expires_at.isoformat()})

    scope = list(getattr(engagement, "authorized_targets", []) or [])
    signed_by = getattr(engagement, "roe_signed_by", "") or ""
    signature = getattr(engagement, "roe_signature", "") or ""

    if not verify_roe_signature(
        engagement_id=str(engagement.id),
        signed_by=signed_by,
        scope=scope,
        expires_at=expires_at,
        signature=signature,
    ):
        raise Forbidden(
            "Rules-of-Engagement signature does not match the current scope. "
            "Re-sign the RoE after any change to authorized targets.",
            details={"gate": "roe_tampered"},
        )

    if target is not None and not _in_scope(target, scope):
        raise Forbidden(
            f"Target '{target.identifier}' is outside the authorized scope.",
            details={"gate": "out_of_scope", "scope": scope},
        )
