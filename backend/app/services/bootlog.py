"""Boot-log analysis.

Turns a captured UART boot log into structured security findings: kernel and
bootloader versions, exposed consoles, default-account prompt patterns,
hard-coded secrets, and network services that announce themselves during boot.
Those versions/tokens then feed the CVE engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

VERSION_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{2,40}")

# (pattern, label, capture-group, severity, category, description, remediation)
RULES: list[tuple] = [
    (re.compile(r"Linux version (\S+)"), "linux-kernel", 1, "medium", "firmware-version",
     "The kernel version is disclosed on the console.",
     "Disable verbose kernel logging on the production console (quiet/loglevel)."),
    (re.compile(r"(U-Boot \d[\w.\-]*)", re.IGNORECASE), "u-boot", 1, "high", "bootloader",
     "The U-Boot bootloader versions itself; a reached U-Boot prompt can allow "
     "boot-argument tampering (init=/bin/sh, single-user mode).",
     "Set bootdelay=0 and password-protect the bootloader; disable the UART console "
     "in the final product."),
    (re.compile(r"(Booting Linux|Starting kernel|Uncompressing Linux)", re.IGNORECASE),
     "boot-marker", 1, "info", "boot", "Kernel hand-off marker observed.", ""),
    (re.compile(r"(OpenWrt|Buildroot|Yocto|BusyBox v[\d.\-]+)", re.IGNORECASE),
     "os-distro", 1, "info", "firmware-version", "Distribution/build system identified.", ""),
    (re.compile(r"(dropbear|dropbearmulti)[^\n]{0,40}", re.IGNORECASE), "ssh-server", 1,
     "low", "service", "An SSH server (dropbear) starts during boot.",
     "Confirm SSH is disabled in production or restricted to authenticated, encrypted access."),
    (re.compile(r"(telnetd|/usr/sbin/telnetd)", re.IGNORECASE), "telnet-server", 1, "high",
     "service", "Telnet is started during boot (cleartext remote access).",
     "Remove telnetd; use SSH with key authentication."),
    (re.compile(r"(login:\s*$)", re.MULTILINE), "console-login", 1, "medium", "console",
     "An interactive login prompt is exposed on the serial console.",
     "Disable the login shell on the production UART, or set a strong unique password."),
    (re.compile(r"(root:[^:\s]{6,})"), "shadow-like", 1, "critical", "hardcoded-secret",
     "A root credential-looking string was printed to the console.",
     "Never print credentials; rotate immediately and remove hard-coded secrets."),
    (re.compile(r"""(?i)(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["']?([^\s"']{4,})"""),
     "inline-secret", 0, "critical", "hardcoded-secret",
     "A secret-like assignment appears in the boot log.",
     "Remove hard-coded secrets; provision secrets at runtime via a secure element."),
    (re.compile(r"(listening on|bind\(\)|started server|httpd|telnetd|mqtt|coap)[^\n]{0,60}",
                re.IGNORECASE), "service-start", 0, "info", "service",
     "A service announces itself during boot.", ""),
    (re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"), "ip-address", 1, "info", "network",
     "A device IP address is printed at boot.", ""),
    (re.compile(r"(?:serial|sn|s/n)[:=]\s*([A-Za-z0-9\-]{6,})", re.IGNORECASE), "serial-number",
     1, "info", "identity", "A device serial number is exposed.", ""),
]

SECRET_KEYWORDS = ("password", "passwd", "secret", "api_key", "apikey", "token", "private_key")

# Labels whose captured value is itself a secret: they are masked before being
# placed in descriptions/evidence/extra so a finding never re-leaks the secret
# it reports.
_SECRET_LABELS = {"inline-secret", "shadow-like"}

_SECRET_ASSIGNMENT = re.compile(
    r"""((?i:password|passwd|secret|api[_-]?key|token|private[_-]?key)\s*[=:]\s*["']?)([^\s"']{4,})"""
)

_SHADOW_LIKE = re.compile(r"\b(root|admin):([^\s:]{6,})")


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "***"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _mask_secret_value(value: str) -> str:
    m = re.match(r"^(root:)(.*)$", value)
    if m:
        return m.group(1) + _mask(m.group(2))
    return _mask(value)


def _redact_secret_line(line: str) -> str:
    def _sub(m: re.Match) -> str:
        return f"{m.group(1)}{_mask(m.group(2))}"

    out = _SECRET_ASSIGNMENT.sub(_sub, line)
    out = _SHADOW_LIKE.sub(_sub, out)
    return out


@dataclass
class BootLogFinding:
    title: str
    category: str
    severity: str
    description: str = ""
    remediation: str = ""
    evidence: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class BootLogReport:
    findings: list[BootLogFinding] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    lines: int = 0

    def to_dict(self) -> dict:
        return {
            "versions": self.versions[:50],
            "tokens": self.tokens[:60],
            "lines": self.lines,
            "finding_count": len(self.findings),
        }


def analyse_bootlog(text: str) -> BootLogReport:
    report = BootLogReport(lines=len(text.splitlines()))
    seen: set[str] = set()
    for pattern, label, group, severity, category, desc, fix in RULES:
        for match in pattern.finditer(text):
            try:
                value = match.group(group).strip()
            except (IndexError, AttributeError):
                value = match.group(0).strip()
            value = value[:200]
            display = value
            evidence = _context(text, match.start())
            if label in _SECRET_LABELS:
                display = _mask_secret_value(value)
                evidence = _redact_secret_line(evidence)
            key = f"{label}:{display[:40]}"
            if key in seen:
                continue
            seen.add(key)
            title = f"{label.replace('-', ' ').title()} exposed in boot log"
            report.findings.append(
                BootLogFinding(
                    title=title, category=category, severity=severity,
                    description=f"{desc} Observed: `{display}`",
                    remediation=fix, evidence=evidence,
                    extra={"rule": label, "value": display},
                )
            )
    # Version-like tokens for CVE keyword search.
    report.versions = sorted(set(re.findall(r"\d+\.\d+(?:\.\d+){0,3}", text)))[:50]
    from collections import Counter

    words = Counter(
        w.lower() for w in VERSION_TOKEN.findall(text)
        if not w.isdigit() and len(w) > 3
    )
    stop = {"linux", "version", "kernel", "booting", "starting", "rootfs", "console", "command"}
    report.tokens = [w for w, _ in words.most_common(50) if w not in stop][:40]
    return report


def _context(text: str, index: int, width: int = 120) -> str:
    start = max(0, index - width // 2)
    end = min(len(text), index + width // 2)
    return text[start:end].replace("\r", "").strip()
