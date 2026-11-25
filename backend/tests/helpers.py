"""Test fixture plugin: a cancellable loop for runner/WS regression tests.

Registered once at conftest import time (before TestClient lifespan runs), so
``registry.get_module("fixture", "cancel_probe")`` resolves inside job tests.
The module is PASSIVE: it needs no engagement/authorization.
"""

from __future__ import annotations

import time

from pydantic import BaseModel

from app.core.authorization import Safety
from app.plugins.base import (
    BasePlugin,
    ModuleResult,
    PluginContext,
    module,
)


class WaitParams(BaseModel):
    seconds: float = 3.0
    steps: int = 50


class FixturePlugin(BasePlugin):
    name = "fixture"
    domain = "fixture"
    title = "Test Fixture"

    @module(
        name="cancel_probe",
        title="Cancellation probe",
        description="Loops for `seconds`, checking ctx.cancelled() every step.",
        safety=Safety.PASSIVE,
        params_model=WaitParams,
    )
    def cancel_probe(self, ctx: PluginContext, params: WaitParams) -> ModuleResult:
        deadline = time.monotonic() + params.seconds
        steps = 0
        while time.monotonic() < deadline and steps < params.steps:
            if ctx.cancelled():
                return ModuleResult(
                    data={"cancelled_seen": True, "steps": steps},
                    summary=f"stopped after {steps} step(s) on cancel flag",
                )
            steps += 1
            ctx.progress(min(90, int(steps / max(1, params.steps) * 90)), f"step {steps}")
            time.sleep(0.05)
        return ModuleResult(
            data={"cancelled_seen": False, "steps": steps},
            summary=f"ran to completion ({steps} steps)",
        )
