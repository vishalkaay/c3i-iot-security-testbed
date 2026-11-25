"""WebSocket endpoints for live job streaming.

Browsers cannot set an Authorization header on a WebSocket handshake, so the
access token is passed as a query parameter and validated here - including a
DB lookup so a token belonging to a user that was disabled (or deleted) stops
working immediately. Note the tradeoff: the same JWT remains valid until
expiry, so treat the ws URL like a bearer secret (do not log it).
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.core.config import settings
from app.core.database import session_scope
from app.core.events import bus
from app.core.logging import get_logger
from app.core.security import decode_token
from app.models import User

log = get_logger("api.ws")
router = APIRouter()


def _authorize(token: str | None) -> bool:
    """True when a valid bearer token belongs to an active user (or dev mode)."""
    if settings.dev_no_auth:
        return True
    if not token:
        return False
    try:
        payload = decode_token(token)
    except Exception:  # noqa: BLE001
        return False
    with session_scope() as db:
        user = db.execute(
            select(User).where(User.id == payload.get("sub"))
        ).scalars().first()
        return bool(user and user.is_active)


async def _pump(ws: WebSocket, channel: str) -> None:
    await ws.accept()
    try:
        async for event in bus.subscribe(channel):
            await ws.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        log.debug("ws closed on %s: %s", channel, exc)


@router.websocket("/ws/jobs")
async def ws_all_jobs(ws: WebSocket, token: str | None = Query(default=None)):
    if not _authorize(token):
        await ws.close(code=4401)
        return
    await _pump(ws, "jobs")


@router.websocket("/ws/jobs/{job_id}")
async def ws_job(ws: WebSocket, job_id: str, token: str | None = Query(default=None)):
    if not _authorize(token):
        await ws.close(code=4401)
        return
    await _pump(ws, f"job:{job_id}")


@router.websocket("/ws/system")
async def ws_system(ws: WebSocket, token: str | None = Query(default=None)):
    """Heartbeat channel for the console (keeps the connection warm)."""
    if not _authorize(token):
        await ws.close(code=4401)
        return
    await ws.accept()
    try:
        while True:
            await ws.send_json({"type": "heartbeat"})
            await asyncio.sleep(20)
    except WebSocketDisconnect:
        pass
