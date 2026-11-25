"""API v1 router aggregation."""

from fastapi import APIRouter

from . import auth, engagements, findings, jobs, plugins, reports, system, ws

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(auth.users_router)
api_router.include_router(engagements.router)
api_router.include_router(plugins.router)
api_router.include_router(jobs.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
api_router.include_router(system.router)

ws_router = ws.router

__all__ = ["api_router", "ws_router"]
