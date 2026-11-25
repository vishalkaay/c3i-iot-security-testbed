"""System info, health, uploads, and ad-hoc CVE lookup."""

from __future__ import annotations

import datetime as dt
import re
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from app import __version__
from app.api.deps import audit, current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.models import User
from app.plugins.capabilities import CAPABILITIES, describe_all
from app.plugins.registry import registry
from app.services.vuln import vuln_intel

log = get_logger("api.system")
router = APIRouter(prefix="/system", tags=["system"])

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\- ]+")


@router.get("/health")
def health():
    return {"status": "ok", "version": __version__, "time": dt.datetime.now(dt.UTC).isoformat()}


@router.get("/info")
def info(_: User = Depends(current_user)):
    return {
        "version": __version__,
        "environment": settings.env,
        "dev_no_auth": settings.dev_no_auth,
        "invasive_enabled": settings.enable_invasive,
        "assistant_enabled": settings.assistant_enabled,
        "plugins": [
            {"name": p.name, "domain": p.domain, "title": p.title,
             "modules": len(p.iter_modules())}
            for p in registry.all()
        ],
        "capabilities": describe_all(list(CAPABILITIES.keys())),
        "vulnerability_intel": vuln_intel.stats(),
        "data_dir": str(settings.data_dir),
    }


class CveQuery(BaseModel):
    keywords: list[str] = Field(min_length=1)
    limit: int = Field(default=25, ge=1, le=100)


@router.post("/cve/lookup")
def cve_lookup(payload: CveQuery, _: User = Depends(current_user)):
    hits = vuln_intel.search_keywords(payload.keywords, limit=payload.limit)
    return {"query": payload.keywords, "count": len(hits),
            "results": [h.to_dict() for h in hits]}


@router.get("/hardware")
def hardware_status(_: User = Depends(current_user)):
    """Live hardware-rig status (GPIO backend, serial ports, wiring map).

    Powers the Hardware page: shows whether the testbed is connected to a real
    rig or running with the mock backend, and which pins are wired where.
    """
    from app.plugins.hardware import support

    _gpio, backend = support.get_gpio()
    ports = support.list_serial_ports()
    probes = support.usb_debug_probes()
    i2c_buses = support.bus_nodes("/dev/i2c-*")
    spi_buses = support.bus_nodes("/dev/spidev*")
    readiness = {
        "uart": bool(ports),
        "gpio_automation": backend != "mock",
        "spi": support.has_tool("flashrom") and bool(spi_buses or probes),
        "i2c": support.has_tool("i2cdetect") and bool(i2c_buses),
        "logic_decode": support.has_tool("sigrok-cli"),
    }
    return {
        "gpio_backend": backend,
        "gpio_is_mock": backend == "mock",
        "serial_ports": ports,
        "uart_port": support.resolve_serial_port() or None,
        "debug_probes": probes,
        "storage_devices": support.storage_devices(),
        "i2c_buses": i2c_buses,
        "spi_buses": spi_buses,
        "logic_analyzer_available": support.has_tool("sigrok-cli"),
        "readiness": readiness,
        "ready_for_physical_tests": any(readiness.values()),
        "pins": {
            "uart_tx_bcm": 14, "uart_tx_pin": 8,
            "uart_rx_bcm": 15, "uart_rx_pin": 10,
            "relay_power_bcm": support.PowerController("relay").relay_pin,
            "relay_power_pin": _bcm_to_header(support.PowerController("relay").relay_pin),
            "optocoupler_power_bcm": support.PowerController("optocoupler").octo_pin,
            "optocoupler_power_pin": _bcm_to_header(support.PowerController("optocoupler").octo_pin),
            "glitch_channel_bcm": support._glitch_pin_default(),
            "glitch_channel_pin": _bcm_to_header(support._glitch_pin_default()),
            "glitch_trigger_bcm": 20, "glitch_trigger_pin": 38,
            "spi_mosi_pin": 19, "spi_miso_pin": 21, "spi_sclk_pin": 23, "spi_ce0_pin": 24,
        },
        "power_polarity": {
            "optocoupler": {"power_on": "GPIO LOW", "power_off": "GPIO HIGH"},
            "relay": {"power_on": "GPIO HIGH", "power_off": "GPIO LOW"},
        },
    }


def _bcm_to_header(bcm: int) -> str | None:
    """BCM numbering to physical header pin on the Pi 40-pin connector (best effort)."""
    table = {
        2: 3, 3: 5, 4: 7, 5: 29, 6: 31, 7: 26, 8: 24, 9: 21, 10: 19, 11: 23,
        12: 32, 13: 33, 14: 8, 15: 10, 16: 36, 17: 11, 18: 12, 19: 35, 20: 38,
        21: 40, 22: 15, 23: 16, 24: 18, 25: 22, 26: 37, 27: 13,
    }
    s = table.get(bcm)
    return str(s) if s else None


@router.post("/uploads", status_code=status.HTTP_201_CREATED)
async def upload(
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db=Depends(get_db),
):
    """Store an uploaded artefact (firmware image, pcap, boot log) for analysis.

    Returns a server-side path that can be passed to the `firmware` or `bluetooth`
    plugins. Filenames are sanitised and de-duplicated; size is capped by
    ``C3I_MAX_UPLOAD_MB`` so a rogue analyst cannot fill the disk.
    """
    limit = settings.max_upload_mb * 1024 * 1024
    dest = settings.uploads_dir / f"{uuid.uuid4().hex[:8]}_{_SAFE_NAME.sub('_', file.filename or 'upload.bin').strip() or 'upload.bin'}"
    size = 0
    with dest.open("wb") as fh:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                fh.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Upload exceeds the {settings.max_upload_mb} MB limit.",
                )
            fh.write(chunk)
    audit(db, actor=user.username, action="upload.create", target=dest.name,
          detail={"size": size})
    db.commit()
    log.info("stored upload %s (%d bytes)", dest.name, size)
    return {"filename": dest.name, "path": str(dest), "size": size}


# --------------------------------------------------------------------------- #
# Uploads browser + download (so users can get files in and out easily)
# --------------------------------------------------------------------------- #
@router.get("/uploads")
def list_uploads(_: User = Depends(current_user)):
    """List files that have been uploaded for analysis (newest first).

    ``path`` is included so the console can hand the *server-side* path to
    analysis modules instead of guessing a relative location client-side.
    """
    files = []
    for p in sorted(settings.uploads_dir.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            st = p.stat()
            files.append({"filename": p.name, "size": st.st_size,
                          "path": str(p.resolve()),
                          "modified": dt.datetime.fromtimestamp(st.st_mtime, dt.UTC).isoformat()})
    return files


@router.get("/uploads/{filename}/download")
def download_upload(filename: str, _: User = Depends(current_user)):
    from pathlib import Path

    from fastapi.responses import FileResponse

    safe = Path(filename).name  # prevent traversal
    path = settings.uploads_dir / safe
    if not path.exists():
        raise HTTPException(status_code=404, detail="Upload not found.")
    return FileResponse(path, filename=safe, media_type="application/octet-stream")


@router.get("/exports")
def list_exports(
    engagement_id: str | None = None,
    _: User = Depends(current_user),
    db=Depends(get_db),
):
    """Every captured artefact across all/one engagement, for bulk export."""
    from sqlalchemy import select

    from app.models import Evidence, Job

    stmt = select(Evidence, Job).join(Job, Evidence.job_id == Job.id, isouter=True)
    if engagement_id:
        stmt = stmt.where(Job.engagement_id == engagement_id)
    rows = db.execute(stmt).all()
    out = []
    for ev, job in rows:
        out.append({
            "id": ev.id, "kind": ev.kind, "filename": ev.filename, "size": ev.size,
            "sha256": ev.sha256, "note": ev.note,
            "job_id": ev.job_id, "plugin": job.plugin if job else None,
            "action": job.action if job else None, "engagement_id": job.engagement_id if job else None,
            "created_at": ev.created_at.isoformat(),
            "download_url": f"/api/v1/jobs/{ev.job_id}/evidence/{ev.id}/download",
        })
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return out
