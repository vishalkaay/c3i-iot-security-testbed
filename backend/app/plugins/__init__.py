"""Plugin framework for the C3i Hub IoT testbed."""

from .base import (
    BasePlugin,
    EvidenceDraft,
    FindingDraft,
    ModuleResult,
    ModuleSpec,
    PluginContext,
    Safety,
    Target,
    module,
    parse_target,
)
from .registry import load_plugins, registry

__all__ = [
    "BasePlugin",
    "ModuleSpec",
    "ModuleResult",
    "FindingDraft",
    "EvidenceDraft",
    "PluginContext",
    "Safety",
    "Target",
    "module",
    "parse_target",
    "registry",
    "load_plugins",
]
