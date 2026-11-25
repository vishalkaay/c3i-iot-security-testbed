"""Test configuration.

Environment is set *before* any application import so the settings singleton
picks up an isolated data directory and deterministic secrets.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

TEST_DATA = Path("/tmp/opencode/c3i-test-data")
if TEST_DATA.exists():
    shutil.rmtree(TEST_DATA, ignore_errors=True)
TEST_DATA.mkdir(parents=True, exist_ok=True)

os.environ.update(
    C3I_ENV="test",
    C3I_DATA_DIR=str(TEST_DATA),
    C3I_SECRET_KEY="test-secret-key-deterministic-0000000000000000",
    C3I_ADMIN_PASSWORD="test-admin-pass",
    C3I_ENABLE_INVASIVE="true",
    # The suite asserts real auth behaviour (401s, gate flows); the developer's
    # repo .env may disable auth, so pin it OFF here. Env vars beat dotenv.
    C3I_DEV_NO_AUTH="false",
    C3I_CVE_ONLINE="false",
    C3I_LOG_LEVEL="WARNING",
)

# Make `app` importable when running pytest from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402


def _register_fixture_plugin() -> None:
    """Register the test-only plugin used by runner/WS regression tests."""
    try:
        from app.plugins.registry import registry

        from tests.helpers import FixturePlugin

        registry.register(FixturePlugin())
    except Exception as exc:  # pragma: no cover - loud if the harness breaks
        raise AssertionError(f"could not register fixture plugin: {exc}") from exc


_register_fixture_plugin()


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def token(client) -> str:
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-admin-pass"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def auth_headers(token) -> dict:
    return {"Authorization": f"Bearer {token}"}
