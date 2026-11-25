"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from app import __version__
from app.api import api_router, ws_router
from app.core.config import settings
from app.core.database import SessionLocal, init_db
from app.core.errors import C3iError, c3i_error_handler
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.jobs.runner import runner
from app.models import Role, User
from app.plugins.registry import load_plugins, registry

log = get_logger("main")


def bootstrap() -> None:
    """Create tables, register plugins, and seed the bootstrap admin."""
    configure_logging()
    settings.ensure_dirs()
    init_db()
    load_plugins()
    log.info("plugins: %s", [p.name for p in registry.all()])

    db = SessionLocal()
    try:
        existing = db.execute(select(User)).scalars().first()
        if existing is None:
            admin = User(
                username=settings.admin_user,
                full_name="Bootstrap Administrator",
                hashed_password=hash_password(settings.admin_password),
                role=Role.ADMIN.value,
            )
            db.add(admin)
            db.commit()
            log.warning(
                "bootstrap admin created (%s) - change the password immediately",
                settings.admin_user,
            )
    finally:
        db.close()

    # Jobs from a previous process never ran here; mark them failed instead of
    # letting the UI show them as queued/running forever.
    recovered = runner.recover_interrupted()
    if recovered:
        log.warning("marked %d interrupted job(s) as failed after restart", recovered)

    if settings.dev_no_auth:
        log.warning(
            "authentication DISABLED via C3I_DEV_NO_AUTH - every request runs as the "
            "bootstrap admin. Use only for local development."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap()
    runner.bind_loop(asyncio.get_running_loop())
    log.info("C3i IoT testbed v%s ready on %s:%s", __version__, settings.host, settings.port)
    yield
    log.info("shutting down")


app = FastAPI(
    title="C3i Hub IoT Security Testbed",
    version=__version__,
    description=(
        "Unified Bluetooth / Wi-Fi / hardware-firmware IoT security auditing platform. "
        "Passive analysis is open to auditors; active and invasive modules require a signed, "
        "in-scope Rules of Engagement."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(C3iError, c3i_error_handler)

# WebSocket routes at the root (browsers hit /ws/...).
app.include_router(ws_router)
# Versioned REST API.
app.include_router(api_router, prefix="/api/v1")


@app.get("/api/v1/health", include_in_schema=False)
async def root_health():
    return {"status": "ok", "version": __version__}


# --- Serve the built web console with SPA fallback (/login, /runner, ... all
# resolve to index.html; unknown API paths still 404 as JSON) --- #
_WEB_DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
if _WEB_DIST.exists():
    _ASSETS = _WEB_DIST / "assets"
    if _ASSETS.exists():
        app.mount("/assets", StaticFiles(directory=str(_ASSETS)), name="web-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        # Unknown API paths must stay JSON 404s - the catch-all must not serve
        # index.html for /api/v1/<typo> (the SPA fallback previously masked
        # client bugs with a 200 HTML response).
        if full_path == "api" or full_path.startswith("api/"):
            return JSONResponse(
                {"error": "not_found", "detail": "No such API route.",
                 "path": f"/{full_path}"},
                status_code=404,
            )
        candidate = (_WEB_DIST / full_path) if full_path else _WEB_DIST
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_WEB_DIST / "index.html")
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return JSONResponse(
            {
                "service": "C3i Hub IoT Security Testbed",
                "version": __version__,
                "docs": "/docs",
                "api": "/api/v1",
                "console": "Run `npm run dev` in ./web, or build it to serve here.",
            }
        )
