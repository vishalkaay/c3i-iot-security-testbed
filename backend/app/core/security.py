"""Password hashing, JWT issuance, and API-key handling."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
from typing import Any

import jwt

from .config import settings

ALGORITHM = "HS256"

# --- password hashing (stdlib PBKDF2-HMAC-SHA256, no native build deps) --- #
_PBKDF2_ITERATIONS = 240_000
_PBKDF2_PREFIX = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_PREFIX}${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        prefix, iterations, salt_hex, digest_hex = hashed.split("$")
        if prefix != _PBKDF2_PREFIX:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, AttributeError):
        return False


# ---- JWT --------------------------------------------------------------- #
def create_access_token(subject: str, role: str, extra: dict[str, Any] | None = None) -> str:
    now = dt.datetime.now(dt.UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + dt.timedelta(minutes=settings.access_token_ttl_min),
        "iss": "c3i-iot-testbed",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM], issuer="c3i-iot-testbed")


# ---- API keys ---------------------------------------------------------- #
def new_api_key() -> tuple[str, str, str]:
    """Return ``(plaintext, prefix, sha256_hash)``. Plaintext is shown once."""
    raw = secrets.token_urlsafe(32)
    prefix = raw[:8]
    return raw, prefix, hash_api_key(raw)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_api_key(raw: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw), hashed)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
