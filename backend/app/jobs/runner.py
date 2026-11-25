"""Async job orchestration.

Modules are synchronous (they shell out to tools), so each runs in a worker
thread. Progress and log lines are persisted and fanned out over the event bus
so the console can stream them live.

Design notes
------------
* ``_cancelled`` holds jobs the API asked to stop. Modules get a
  ``ctx.cancelled()`` callback for cooperative cancellation (serial reads, pulse
  trains, scan loops); after normal completion the runner still flips the status
  to ``cancelled`` if the flag was raised, so a cancelled job never reports
  ``succeeded``.
* Radio (bluetooth/wifi), firmware IO and hardware GPIO jobs are serialised per
  domain with a lock - a deauth flood and a port scan on the same radio must not
  interleave, and two flashrom/GPIO jobs must not fight over the rig.
* Status changes are published on **both** the global ``jobs`` channel and the
  per-job ``job:<id>`` channel - the frontend listens on the per-job channel and
  would otherwise hang waiting for a final status.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from app.core.database import session_scope
from app.core.events import bus
from app.core.logging import get_logger
from app.models import Asset, Evidence, Finding, Job, JobLog, JobStatus
from app.plugins.base import ModuleResult, PluginContext, Target, parse_target
from app.plugins.registry import registry

log = get_logger("jobs.runner")

# Backend domains that touch shared hardware/radio state: run at most one job
# per domain at a time. Everything else runs fully in parallel.
SerializedDomains = {"bluetooth", "wifi", "hardware", "firmware"}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class JobRunner:
    def __init__(self, max_workers: int = 4) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="c3i-job")
        self._loop: asyncio.AbstractEventLoop | None = None
        self._cancelled: set[str] = set()
        self._cancel_guard = threading.Lock()
        self._domain_locks: dict[str, threading.Lock] = {
            d: threading.Lock() for d in SerializedDomains
        }

    # ------------------------------------------------------------------ #
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def submit(self, job_id: str) -> None:
        self._pool.submit(self._run, job_id)

    def cancel(self, job_id: str) -> bool:
        """Ask a running/queued job to stop.

        Returns True when the job was cancellable (i.e. currently tracked).
        Cancellation is cooperative: modules that poll ``ctx.cancelled()`` stop
        promptly and retain the evidence produced so far.
        """
        with self._cancel_guard:
            self._cancelled.add(job_id)
        return self.status(job_id) in ("queued", "running")

    def status(self, job_id: str) -> str | None:
        with session_scope() as db:
            job = db.get(Job, job_id)
            return job.status if job else None

    def is_cancelled(self, job_id: str) -> bool:
        with self._cancel_guard:
            return job_id in self._cancelled

    # ------------------------------------------------------------------ #
    def recover_interrupted(self) -> int:
        """Mark jobs from a previous process as failed (they never ran here).

        Called once from bootstrap. Queued jobs were never picked up; running
        jobs were killed with the process. Re-running them silently would be
        dishonest - and invasive actions must never execute unattended.
        """
        recovered = 0
        with session_scope() as db:
            stuck = db.execute(
                select(Job).where(Job.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]))
            ).scalars().all()
            for job in stuck:
                job.status = JobStatus.FAILED.value
                job.error = "server restarted before this job completed; re-run it"
                job.finished_at = _now()
                recovered += 1
        if recovered:
            log.warning("recovered %d stale job(s) from previous run", recovered)
        return recovered

    # ------------------------------------------------------------------ #
    def _publish(self, channel: str, event: dict) -> None:
        if self._loop is None:
            return
        try:
            self._loop.call_soon_threadsafe(
                lambda: asyncio.create_task(bus.publish(channel, event))
            )
        except RuntimeError:
            pass  # loop already closed during shutdown

    def _status_event(self, job_id: str, status: str, progress: int | None = None) -> dict:
        return {
            "type": "status", "job_id": job_id, "status": status,
            "progress": progress, "ts": _now().isoformat(),
        }

    def _publish_status(self, job_id: str, status: str, progress: int | None = None) -> None:
        event = self._status_event(job_id, status, progress)
        self._publish("jobs", event)
        self._publish(f"job:{job_id}", event)

    def _emit(self, job_id: str, *, level: str, message: str, progress: int | None = None) -> None:
        with session_scope() as db:
            if level == "progress":
                db.add(JobLog(job_id=job_id, level="info", message=message or "progress"))
                job = db.get(Job, job_id)
                if job and progress is not None:
                    job.progress = progress
                    if message:
                        job.message = message
            else:
                db.add(JobLog(job_id=job_id, level=level, message=message))
        self._publish(
            f"job:{job_id}",
            {"type": "log", "job_id": job_id, "level": level, "message": message,
             "progress": progress, "ts": _now().isoformat()},
        )

    # ------------------------------------------------------------------ #
    def _run(self, job_id: str) -> None:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job is None:
                return
            job.status = JobStatus.RUNNING.value
            job.started_at = _now()
            plugin_name, action = job.plugin, job.action
            params = dict(job.params or {})
            engagement_id, asset_id = job.engagement_id, job.asset_id
            target_kind, target_id = (
                (job.params or {}).get("_target_kind"), (job.params or {}).get("_target_id")
            )

        self._publish_status(job_id, "running", progress=1)
        self._emit(job_id, level="info", message=f"starting {plugin_name}.{action}", progress=1)

        spec = registry.get_module(plugin_name, action)
        if spec is None:
            self._fail(job_id, f"unknown module {plugin_name}.{action}")
            return

        target: Target | None = None
        if target_kind and target_id:
            try:
                target = parse_target(target_kind, target_id)
            except Exception:  # noqa: BLE001
                target = Target(target_kind, target_id)

        def emit(*, level: str, message: str, progress: int | None = None) -> None:
            self._emit(job_id, level=level, message=message, progress=progress)

        domain = spec.fn.__self__.domain
        ctx = PluginContext(
            job_id=job_id, domain=domain, target=target,
            engagement_id=engagement_id, asset_id=asset_id, emit=emit,
            should_cancel=lambda: self.is_cancelled(job_id),
        )

        # Serialize hardware/radio domains so two jobs cannot fight over the
        # same radio, serial port or GPIO bus.
        lock = self._domain_locks.get(domain)
        try:
            if lock is not None:
                if not lock.acquire(timeout=180):
                    self._fail(
                        job_id,
                        f"another {domain} job is still using the hardware; wait for it to finish",
                    )
                    return
            try:
                clean = {k: v for k, v in params.items() if not k.startswith("_")}
                validated = spec.params_model(**clean)
                result: ModuleResult = spec.fn(ctx, validated)
            finally:
                if lock is not None:
                    lock.release()
            if self.is_cancelled(job_id):
                self._persist_partial(job_id, result, engagement_id, cancelled=True)
            else:
                self._persist_success(job_id, result, engagement_id)
        except Exception as exc:  # noqa: BLE001
            if self.is_cancelled(job_id):
                self._cancel_now(job_id, note=f"stopped during run: {type(exc).__name__}: {exc}")
            else:
                log.exception("job %s failed", job_id)
                self._fail(job_id, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-2000:]}")
        finally:
            with self._cancel_guard:
                self._cancelled.discard(job_id)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _finding_evidence(value) -> str | None:
        """Finding.evidence is a Text column; dicts must become JSON strings."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(value)

    def _persist_success(self, job_id: str, result: ModuleResult, engagement_id: str | None) -> None:
        self._store_result(job_id, result, engagement_id)
        self._emit(job_id, level="info",
                   message=f"completed: {result.summary}", progress=100)
        self._publish_status(job_id, "succeeded", progress=100)

    def _persist_partial(self, job_id: str, result: ModuleResult,
                         engagement_id: str | None, *, cancelled: bool) -> None:
        """Store output of a run interrupted by an operator cancel.

        Work already done stays as evidence/findings; the job ends CANCELLED
        rather than succeeded so the UI is honest about what happened.
        """
        self._store_result(job_id, result, engagement_id)
        self._cancel_now(job_id, note=f"cancelled by operator after partial run ({result.summary})")

    def _cancel_now(self, job_id: str, *, note: str) -> None:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job:
                job.status = JobStatus.CANCELLED.value
                job.error = None
                job.message = (note or "cancelled by operator")[:400]
                if job.finished_at is None:
                    job.finished_at = _now()
                db.add(JobLog(job_id=job_id, level="warn", message=note))
        self._emit(job_id, level="warn", message=note)
        self._publish_status(job_id, "cancelled")

    def _store_result(self, job_id: str, result: ModuleResult, engagement_id: str | None) -> None:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job is None:
                return
            asset_id = job.asset_id
            domain = job.plugin

            # --- assets upsert ---
            for draft in result.data.get("assets", []) or []:
                self._upsert_asset(db, engagement_id, draft)

            # --- findings ---
            for f in result.findings:
                fp = f.fingerprint(domain)
                existing = db.execute(
                    select(Finding).where(
                        Finding.engagement_id == engagement_id, Finding.fingerprint == fp
                    )
                ).scalars().first()
                if existing:
                    existing.severity = f.severity
                    existing.cvss_score = f.cvss_score or existing.cvss_score
                    existing.epss_score = f.epss_score or existing.epss_score
                    existing.updated_at = _now()
                    continue
                db.add(
                    Finding(
                        job_id=job_id, engagement_id=engagement_id, asset_id=asset_id,
                        title=f.title[:300], category=f.category, domain=domain,
                        severity=f.severity, cvss_score=f.cvss_score, epss_score=f.epss_score,
                        cve_ids=f.cve_ids, cwe_ids=f.cwe_ids, description=f.description,
                        evidence=self._finding_evidence(f.evidence),
                        remediation=f.remediation, references=f.references,
                        extra=f.extra, fingerprint=fp,
                    )
                )

            # --- evidence ---
            for ev in result.evidence:
                if ev.path:
                    db.add(
                        Evidence(
                            job_id=job_id, kind=ev.kind, filename=ev.filename, path=ev.path,
                            sha256=ev.sha256 or "", size=ev.size, note=ev.note,
                        )
                    )

            job.status = JobStatus.SUCCEEDED.value
            job.progress = 100
            job.result = result.data
            job.message = result.summary[:400] if result.summary else "completed"
            job.finished_at = _now()

    def _upsert_asset(self, db, engagement_id: str | None, draft: dict) -> Asset | None:
        if not engagement_id:
            return None
        kind = draft.get("kind") or "unknown"
        identifier = draft.get("identifier")
        if not identifier:
            return None
        asset = db.execute(
            select(Asset).where(
                Asset.engagement_id == engagement_id,
                Asset.kind == kind,
                Asset.identifier == identifier,
            )
        ).scalars().first()
        if asset is None:
            asset = Asset(
                engagement_id=engagement_id, kind=kind, identifier=identifier,
                name=draft.get("name"), vendor=draft.get("vendor"),
                model=draft.get("model"), firmware=draft.get("firmware"),
                attributes=draft.get("attributes") or {},
            )
            db.add(asset)
            db.flush()
        else:
            asset.name = draft.get("name") or asset.name
            asset.vendor = draft.get("vendor") or asset.vendor
            asset.model = draft.get("model") or asset.model
            asset.firmware = draft.get("firmware") or asset.firmware
            merged = {**(asset.attributes or {}), **(draft.get("attributes") or {})}
            asset.attributes = merged
            asset.updated_at = _now()
        return asset

    def _fail(self, job_id: str, error: str) -> None:
        with session_scope() as db:
            job = db.get(Job, job_id)
            if job:
                job.status = JobStatus.FAILED.value
                job.error = error[-8000:]
                job.finished_at = _now()
        self._emit(job_id, level="error", message=f"failed: {error[:300]}")
        self._publish_status(job_id, "failed")


runner = JobRunner()
