"""Plugin + capability discovery endpoints (drives the dynamic console UI)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import current_user
from app.core.errors import NotFound
from app.models import User
from app.plugins.capabilities import CAPABILITIES, describe_all
from app.plugins.registry import registry

router = APIRouter(prefix="/plugins", tags=["plugins"])


@router.get("")
def list_plugins(_: User = Depends(current_user)):
    return registry.manifest()


@router.get("/capabilities")
def list_capabilities(_: User = Depends(current_user)):
    return describe_all(list(CAPABILITIES.keys()))


@router.get("/{name}")
def get_plugin(name: str, _: User = Depends(current_user)):
    plugin = registry.get(name)
    if not plugin:
        raise NotFound(f"Plugin '{name}' not found.")
    return plugin.manifest()
