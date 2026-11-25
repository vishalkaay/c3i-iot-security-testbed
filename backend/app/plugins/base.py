"""Plugin base classes, the module registry, and execution context."""

from __future__ import annotations

import hashlib
import inspect
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import BaseModel

from app.core.authorization import Safety, Target
from app.core.config import settings
from app.core.errors import PluginError
from app.core.logging import get_logger

from .capabilities import describe_all, missing
from .tools import validate_host, validate_mac


# --------------------------------------------------------------------------- #
# Results a module can return
# --------------------------------------------------------------------------- #
@dataclass
class FindingDraft:
    title: str
    category: str
    severity: str = "info"
    description: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    epss_score: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Finding.evidence is persisted into a Text column: coerce structured
        # evidence (dict/list) to JSON so a whole job's results never die on a
        # sqlite binding error.
        if self.evidence is not None and not isinstance(self.evidence, str):
            try:
                self.evidence = json.dumps(self.evidence, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                self.evidence = str(self.evidence)

    def fingerprint(self, domain: str) -> str:
        key = f"{domain}|{self.category}|{self.title.strip().lower()}"
        return hashlib.sha256(key.encode()).hexdigest()[:32]


@dataclass
class EvidenceDraft:
    kind: str
    filename: str
    content: bytes
    note: str = ""
    # filled in by the context when persisted
    path: str | None = None
    sha256: str | None = None
    size: int = 0


@dataclass
class ModuleResult:
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[FindingDraft] = field(default_factory=list)
    evidence: list[EvidenceDraft] = field(default_factory=list)
    summary: str = ""
    artifacts: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Execution context passed to every module
# --------------------------------------------------------------------------- #
class PluginContext:
    def __init__(
        self,
        *,
        job_id: str,
        domain: str,
        target: Target | None,
        engagement_id: str | None = None,
        asset_id: str | None = None,
        emit: Callable[..., None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> None:
        self.job_id = job_id
        self.domain = domain
        self.target = target
        self.engagement_id = engagement_id
        self.asset_id = asset_id
        self.logger = get_logger(f"plugin.{domain}")
        self._emit = emit or (lambda *a, **k: None)
        self._should_cancel = should_cancel or (lambda: False)
        self.workdir = settings.evidence_dir / job_id
        self.workdir.mkdir(parents=True, exist_ok=True)

    # cooperative cancellation ------------------------------------------- #
    def cancelled(self) -> bool:
        """Poll by long-running loops (serial read, glitch train, port scan)."""
        try:
            return bool(self._should_cancel())
        except Exception:  # noqa: BLE001 - never let a cancel check crash a job
            return False

    # progress / log streaming ------------------------------------------- #
    def log(self, message: str, *, level: str = "info") -> None:
        self.logger.info(message)
        self._emit(level=level, message=message)

    def progress(self, percent: int, message: str | None = None) -> None:
        self._emit(level="progress", message=message or "", progress=max(0, min(100, percent)))

    # evidence persistence ----------------------------------------------- #
    def save_evidence(self, draft: EvidenceDraft) -> EvidenceDraft:
        safe = draft.filename.replace("/", "_")
        path = self.workdir / safe
        path.write_bytes(draft.content)
        digest = hashlib.sha256(draft.content).hexdigest()
        draft.path = str(path)
        draft.sha256 = digest
        draft.size = len(draft.content)
        self.log(f"saved evidence {draft.kind}: {safe} ({draft.size} bytes)")
        return draft


# --------------------------------------------------------------------------- #
# Module declaration + decorator
# --------------------------------------------------------------------------- #
@dataclass
class ModuleSpec:
    name: str
    title: str
    description: str
    safety: Safety
    params_model: type[BaseModel]
    capabilities: list[str]
    fn: Callable[..., ModuleResult]
    tags: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)  # e.g. TTP / ATT&CK-style ids


def module(
    *,
    name: str,
    title: str,
    description: str = "",
    safety: Safety = Safety.PASSIVE,
    params_model: type[BaseModel] | None = None,
    capabilities: list[str] | None = None,
    tags: list[str] | None = None,
    mitre: list[str] | None = None,
):
    """Declare a module on a plugin class."""

    class _NoParams(BaseModel):
        pass

    def deco(fn: Callable[..., ModuleResult]) -> Callable[..., ModuleResult]:
        # Capabilities may be passed as Capability objects or plain id strings.
        cap_ids = [getattr(c, "id", c) for c in (capabilities or [])]
        fn.__c3i_module__ = ModuleSpec(  # type: ignore[attr-defined]
            name=name,
            title=title,
            description=description or (fn.__doc__ or "").strip(),
            safety=safety,
            params_model=params_model or _NoParams,
            capabilities=cap_ids,
            fn=fn,
            tags=tags or [],
            mitre=mitre or [],
        )
        return fn

    return deco


# --------------------------------------------------------------------------- #
# Base plugin
# --------------------------------------------------------------------------- #
class BasePlugin:
    name: ClassVar[str] = "base"
    domain: ClassVar[str] = "base"
    title: ClassVar[str] = "Base plugin"
    description: ClassVar[str] = ""

    def iter_modules(self) -> list[ModuleSpec]:
        specs: list[ModuleSpec] = []
        for _attr, member in inspect.getmembers(type(self)):
            spec = getattr(member, "__c3i_module__", None)
            if spec is None:
                continue
            # Bind the method to this plugin instance.
            bound = getattr(self, _attr)
            specs.append(
                ModuleSpec(
                    name=spec.name,
                    title=spec.title,
                    description=spec.description,
                    safety=spec.safety,
                    params_model=spec.params_model,
                    capabilities=spec.capabilities,
                    fn=bound,
                    tags=spec.tags,
                    mitre=spec.mitre,
                )
            )
        # Deterministic order.
        specs.sort(key=lambda s: (s.safety.rank, s.name))
        return specs

    def all_capabilities(self) -> list[str]:
        caps: set[str] = set()
        for spec in self.iter_modules():
            caps.update(spec.capabilities)
        return sorted(caps)

    def manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "domain": self.domain,
            "title": self.title,
            "description": self.description,
            "capabilities": describe_all(self.all_capabilities()),
            "modules": [
                {
                    "name": s.name,
                    "title": s.title,
                    "description": s.description,
                    "safety": s.safety.value,
                    "tags": s.tags,
                    "mitre": s.mitre,
                    "capabilities": s.capabilities,
                    "missing_capabilities": [c.id for c in missing(s.capabilities)],
                    "params_schema": s.params_model.model_json_schema(),
                }
                for s in self.iter_modules()
            ],
        }

    # helpers ------------------------------------------------------------ #
    @staticmethod
    def new_job_id() -> str:
        return uuid.uuid4().hex


def parse_target(kind: str, identifier: str) -> Target:
    """Normalise/validate a target identifier for the given domain."""
    if kind == "bluetooth":
        return Target(kind, validate_mac(identifier))
    if kind in ("wifi", "ip"):
        return Target("wifi", validate_host(identifier))
    return Target(kind, identifier.strip())


__all__ = [
    "Safety",
    "Target",
    "PluginContext",
    "PluginError",
    "FindingDraft",
    "EvidenceDraft",
    "ModuleResult",
    "ModuleSpec",
    "BasePlugin",
    "module",
    "parse_target",
]
