"""Central configuration.

All runtime configuration is sourced from environment variables / ``.env``.
Nothing security-relevant is hard-coded; the legacy tools embedded a root
password and hard-coded paths, which this module deliberately avoids.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository root (backend/app/core/config.py -> parents[3] = repo root).
# Relative paths in the environment are resolved against this so that running
# uvicorn from ``backend/`` or from the repo root yields the *same* data dir.
_REPO_ROOT = Path(__file__).resolve().parents[3]

_DEFAULT_SECRET = "change-me-in-production-please-32-bytes-min"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # Anchored to the repo root (NOT the CWD) so `make api` (uvicorn from
        # backend/) and a launch from the repo root read the same .env. Real
        # environment variables still take precedence over the file.
        env_file=str(_REPO_ROOT / ".env"),
        env_prefix="C3I_",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- core ----
    env: str = Field(default="development")
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"
    data_dir: Path = Path("./data")

    # ---- security ----
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    access_token_ttl_min: int = 480
    allowed_origins: str = "http://localhost:5173,http://localhost:8080"
    # Upload size ceiling (MB) for /system/uploads.
    max_upload_mb: int = Field(default=512, ge=1, le=65536)

    admin_user: str = "admin"
    admin_password: str = "change-me-on-first-login"
    dev_no_auth: bool = False

    # ---- safety gate ----
    enable_invasive: bool = False

    # ---- vulnerability intelligence ----
    nvd_api_key: str | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    osv_base_url: str = "https://api.osv.dev/v1"
    epss_base_url: str = "https://api.first.org/data/v1/epss"
    cve_online: bool = True
    cve_db_path: Path = Path("./data/cve/cve.db")

    # ---- assistant ----
    assistant_enabled: bool = False
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:3b"
    embed_model: str = "nomic-embed-text"

    # ------------------------------------------------------------------ #
    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("data_dir", "cve_db_path", mode="before")
    @classmethod
    def _resolve_against_repo_root(cls, v):
        """Anchor relative paths to the repo root, not the process CWD.

        README/Makefile tell users to run uvicorn from ``backend/``; without
        this, ``./data`` resolves to ``backend/data`` and two different
        databases get created depending on where the server was launched.
        """
        p = Path(str(v)).expanduser()
        if not p.is_absolute():
            p = _REPO_ROOT / p
        return p

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # convenience paths -------------------------------------------------- #
    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def firmware_dir(self) -> Path:
        return self.data_dir / "firmware"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "c3i_iot.db"

    def ensure_dirs(self) -> None:
        for p in (
            self.data_dir,
            self.uploads_dir,
            self.evidence_dir,
            self.reports_dir,
            self.firmware_dir,
            self.cve_db_path.parent,
        ):
            p.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.is_production:
        if len(s.secret_key) < 32 or s.secret_key == _DEFAULT_SECRET:
            raise RuntimeError(
                "C3I_SECRET_KEY must be overridden with a long random value in production."
            )
        if s.dev_no_auth:
            raise RuntimeError(
                "C3I_DEV_NO_AUTH disables authentication and cannot be combined with "
                "C3I_ENV=production. Switch to real login/API-key authentication."
            )
    s.ensure_dirs()
    return s


settings = get_settings()
