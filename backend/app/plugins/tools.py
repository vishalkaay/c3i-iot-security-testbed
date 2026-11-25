"""Safe subprocess helpers + input validation.

The legacy tools passed user input straight into ``shell=True`` command strings
(command injection). Every external tool here is invoked with an argument
*vector*, and hosts/ports/identifiers are validated before use. File paths that
reach modules (e.g. ``firmware.secrets``) are additionally restricted to the
testbed's own data directories so an analyst token cannot be used to read
arbitrary files on the server.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.core.errors import CapabilityUnavailable, Forbidden, ValidationError

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]{0,253}[A-Za-z0-9])?$")


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


def _as_text(value) -> str:
    """subprocess.TimeoutExpired carries ``bytes`` even with ``text=True``; cope."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise CapabilityUnavailable(f"Required tool '{name}' is not installed on this host.")
    return path


def run(
    argv: list[str],
    *,
    timeout: int = 60,
    input_text: str | None = None,
    env: dict | None = None,
    check: bool = False,
) -> CommandResult:
    import time

    if not argv:
        raise ValidationError("Empty command")
    # No shell, ever.
    if not shutil.which(argv[0]) and "/" not in argv[0]:
        raise CapabilityUnavailable(f"Tool '{argv[0]}' not found on PATH.")

    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - argv form, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # stdout/stderr arrive as bytes here even when text=True.
        stdout = _as_text(getattr(exc, "stdout", None))
        stderr = _as_text(getattr(exc, "stderr", None)) or f"timeout after {timeout}s"
        return CommandResult(
            argv, 124, stdout, stderr,
            time.monotonic() - start,
        )
    result = CommandResult(argv, proc.returncode, proc.stdout, proc.stderr,
                           time.monotonic() - start)
    if check and not result.ok:
        raise CapabilityUnavailable(
            f"Command {' '.join(argv)} failed ({result.returncode}): {result.stderr.strip()[:300]}"
        )
    return result


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


# --------------------------------------------------------------------------- #
# Validators - raise ValidationError on bad input (defence in depth).
# --------------------------------------------------------------------------- #
def validate_mac(value: str) -> str:
    value = (value or "").strip()
    if not _MAC_RE.match(value):
        raise ValidationError(f"'{value}' is not a valid Bluetooth MAC address.")
    return value.upper()


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValidationError(f"'{value}' is not a valid IP address.") from exc


def validate_host(value: str) -> str:
    value = (value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(value):
        raise ValidationError(f"'{value}' is not a valid host or IP.")
    return value


def validate_port(value: int | str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"'{value}' is not a valid port.") from exc
    if not 1 <= port <= 65535:
        raise ValidationError(f"Port {port} out of range (1-65535).")
    return port


def validate_interface(value: str) -> str:
    if not re.match(r"^[A-Za-z0-9._:-]{1,32}$", value or ""):
        raise ValidationError(f"'{value}' is not a valid interface name.")
    return value


# --------------------------------------------------------------------------- #
# File-path containment
# --------------------------------------------------------------------------- #
def _allowed_roots() -> list[Path]:
    roots = [settings.uploads_dir, settings.evidence_dir, settings.firmware_dir]
    legacy = settings.data_dir.parent / "backend" / "data" / "uploads"
    if legacy.is_dir():
        roots.append(legacy)
    return [r.resolve() for r in roots if r.is_dir()]


def validate_input_path(value: str) -> str:
    """Restrict module ``path`` params to the testbed's own data directories.

    Prevents an authenticated analyst from running ``strings``/``binwalk``
    against, say, ``/etc/shadow`` through the jobs API.
    """
    candidate = Path(str(value or "")).expanduser()
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate).resolve()
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise ValidationError(f"Unusable path '{value}': {exc}") from exc

    if resolved == settings.data_dir.resolve():
        raise ValidationError("Data directory itself is not analysable; pass a file.")

    # A module could otherwise walk *out* through a symlink inside uploads.
    for root in _allowed_roots():
        if resolved == root or root in resolved.parents:
            return str(resolved)

    raise Forbidden(
        "Path must live inside the testbed's uploads/evidence/firmware directories. "
        "Use POST /system/uploads to bring files in.",
        details={"path": str(resolved)},
    )


SAFE_CHARS = re.compile(r"[^A-Za-z0-9._:\- ]+")
