"""Domain-specific exception hierarchy and FastAPI handlers."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class C3iError(Exception):
    """Base class for all application errors."""

    status_code = 400
    code = "c3i_error"

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFound(C3iError):
    status_code = 404
    code = "not_found"


class Conflict(C3iError):
    status_code = 409
    code = "conflict"


class ValidationError(C3iError):
    status_code = 422
    code = "validation_error"


class AuthError(C3iError):
    status_code = 401
    code = "unauthorized"


class Forbidden(C3iError):
    status_code = 403
    code = "forbidden"


class AuthorizationRequired(Forbidden):
    """Raised when an invasive module is requested without a valid RoE."""

    code = "authorization_required"


class PluginError(C3iError):
    status_code = 400
    code = "plugin_error"


class CapabilityUnavailable(PluginError):
    """The host lacks a required tool, adapter, or hardware."""

    code = "capability_unavailable"


async def c3i_error_handler(_: Request, exc: C3iError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )
