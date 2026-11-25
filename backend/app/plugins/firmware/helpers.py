"""Firmware static-analysis helpers: binwalk, entropy, strings, secrets, SBOM."""

from __future__ import annotations

import math
import re
import tarfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.plugins.tools import has_tool, run


# --------------------------------------------------------------------------- #
# binwalk
# --------------------------------------------------------------------------- #
@dataclass
class Signature:
    offset: int
    description: str

    def to_dict(self) -> dict:
        return {"offset": self.offset, "description": self.description}


def binwalk_scan(path: str, timeout: int = 600) -> list[Signature]:
    """Scan for embedded signatures.

    binwalk 2.x prints "decimal  hex  description" rows; binwalk 3.x prints
    only "0xHEX  description". Both shapes are parsed here - the original
    version only matched the decimal form and therefore reported zero
    signatures from hex-only output.
    """
    if not has_tool("binwalk"):
        return []
    res = run(["binwalk", path], timeout=timeout)
    sigs: list[Signature] = []
    for line in res.lines():
        m = re.match(r"\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.*)", line)
        if m:
            sigs.append(Signature(offset=int(m.group(1)), description=m.group(2).strip()))
            continue
        m = re.match(r"\s*0x([0-9A-Fa-f]+)\s+(.*)", line)
        if m:
            sigs.append(Signature(offset=int(m.group(1), 16), description=m.group(2).strip()))
    return sigs


def binwalk_extract(path: str, outdir: str, timeout: int = 900) -> dict:
    if not has_tool("binwalk"):
        return {"ok": False, "error": "binwalk not installed"}
    Path(outdir).mkdir(parents=True, exist_ok=True)
    res = run(["binwalk", "-e", "--directory", outdir, path], timeout=timeout)
    extracted = list(Path(outdir).iterdir()) if Path(outdir).exists() else []
    return {"ok": res.returncode == 0, "output": res.stdout[-4000:],
            "extracted": [p.name for p in extracted][:200], "outdir": outdir}


# --------------------------------------------------------------------------- #
# Pure-python carving (binwalk-free fallback)
# --------------------------------------------------------------------------- #
# (magic bytes, description, extractor) — extractor: None = report only,
# "gzip"/"bz2"/"xz"/"lzma_candidates"/"tar"/"cpio"/"zip"/"squashfs".
CARVE_MAGICS: list[tuple[bytes, str, str | None]] = [
    (b"\x1f\x8b\x08", "gzip compressed data", "gzip"),
    (b"BZh", "bzip2 compressed data", "bzip2"),
    (b"\xfd7zXZ\x00", "XZ compressed data", "xz"),
    (b"]\x00\x00", "LZMA stream (candidate)", "lzma"),
    (b"\x28\xb5\x2f\xfd", "Zstandard compressed data", None),
    (b"hsqs", "SquashFS filesystem (little-endian)", "squashfs"),
    (b"sqsh", "SquashFS filesystem (big-endian)", "squashfs"),
    (b"UBI#", "UBI erase-count block header", None),
    (b"\x85\x19", "JFFS2 node (candidate)", None),
    (b"070701", "cpio archive (newc)", "cpio"),
    (b"ustar", "tar archive (ustar header)", "tar"),
    (b"PK\x03\x04", "Zip archive data", "zip"),
    (b"\x27\x05\x19\x56", "U-Boot uImage legacy header", None),
    (b"ANDROID!", "Android boot image", None),
    (b"\x45\x3d\xcd\x28", "cramfs filesystem (candidate)", None),
]

_MAX_PAYLOAD = 256 * 1024 * 1024


def _pad4(n: int) -> int:
    return n + (4 - n % 4) % 4


def _newc_cpio_entries(data: bytes) -> dict:
    """Parse a newc (SVR4) cpio archive. Returns files/links/dirs (bounded)."""
    files: dict[str, bytes] = {}
    links: dict[str, str] = {}
    dirs: list[str] = []
    pos = 0
    while pos + 110 <= len(data) and data[pos:pos + 6] == b"070701" and len(files) < 4000:
        try:
            values = [int(data[pos + 6 + i * 8: pos + 14 + i * 8], 16)
                      for i in range(13)]
        except ValueError:
            break
        filesize, namesize, mode = values[6], values[11], values[1]
        if not 1 <= namesize <= 4096 or pos + 110 + namesize > len(data):
            raise ValueError("invalid cpio filename size")
        if data[pos + 110 + namesize - 1] != 0:
            raise ValueError("unterminated cpio filename")
        name = data[pos + 110: pos + 110 + namesize - 1].decode("latin-1")
        if name == "TRAILER!!!":
            pos = _pad4(pos + 110 + namesize)
            break
        data_start = _pad4(pos + 110 + namesize)
        if data_start + filesize > len(data):
            raise ValueError("truncated cpio file")
        payload = data[data_start: data_start + filesize]
        kind = mode & 0o170000
        if kind == 0o040000:
            dirs.append(name)
        elif kind == 0o120000:
            links[name] = payload.decode("latin-1", errors="replace")
        elif kind == 0o100000:
            files[name] = payload
        pos = _pad4(data_start + filesize)
    return {"files": files, "links": links, "dirs": dirs, "consumed": pos}


def carve(path: str, outdir: str | None = None, *,
          max_scan: int = 256 * 1024 * 1024, timeout: int = 600) -> dict:
    """binwalk-free signature carving + selective extraction.

    Scans the image for filesystem/compressor/embedded-header magic numbers
    (offsets become ``Signature`` rows identical in shape to binwalk's) and,
    where a stdlib decompressor can validate the stream, extracts the payload,
    recursing into ``cpio.gz`` archives. Notes stay honest: a carved SquashFS
    with no ``unsquashfs`` binary available is *reported*, never faked.
    """
    import bz2
    import io
    import lzma
    import time as _time
    import zlib

    deadline = _time.time() + timeout
    with open(path, "rb") as fh:
        data = fh.read(max_scan)

    signatures: list[Signature] = []
    extracted: list[str] = []
    notes: list[str] = []
    out_root = Path(outdir) if outdir else None
    if out_root:
        out_root.mkdir(parents=True, exist_ok=True)
    sig_cap = False
    written = 0

    def _write(directory: Path, name: str, content: bytes) -> None:
        nonlocal written
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or not relative.name:
            raise ValueError("unsafe archive path")
        target = directory.joinpath(*relative.parts)
        if not target.resolve().is_relative_to(out_root.resolve()):
            raise ValueError("archive path escapes output directory")
        if written + len(content) > _MAX_PAYLOAD or len(extracted) >= 4000:
            raise ValueError("extraction byte/file budget exceeded")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(content)
        written += len(content)
        extracted.append(str(target.relative_to(out_root)))

    def _cpio(directory: Path, content: bytes) -> dict:
        entries = _newc_cpio_entries(content)
        for name, payload in entries["files"].items():
            _write(directory, name, payload)
        if entries["links"]:
            notes.append(f"{len(entries['links'])} cpio symlinks recorded in archive, not materialised")
        return entries

    def _store(off: int, tag: str, payload: bytes) -> None:
        if out_root is None:
            return
        ext = "img" if tag == "squashfs" else "bin"
        target = out_root / f"off_{off:08x}_{tag}.{ext}"
        _write(out_root, target.name, payload)
        if payload.startswith(b"070701"):
            subdir = out_root / f"off_{off:08x}_{tag}_cpio"
            _cpio(subdir, payload)

    for magic, desc, kind in CARVE_MAGICS:
        start = 0
        while not sig_cap:
            if _time.time() > deadline:
                notes.append("scan stopped at time budget; remaining magics skipped")
                break
            off = data.find(magic, start)
            if off < 0:
                break
            start = off + 1
            if kind == "tar":
                off -= 257  # ustar is inside the header, not the archive start
                if off < 0:
                    continue
            signatures.append(Signature(offset=off, description=desc))
            if len(signatures) >= 4000:
                sig_cap = True
                notes.append("signature cap (4000) reached; further offsets ignored")
                break
            if kind is None or out_root is None:
                continue

            if kind in ("gzip", "bzip2", "xz", "lzma"):
                try:
                    blob = data[off: min(len(data), off + _MAX_PAYLOAD)]
                    # Single-stream decompressors: the image continues past the
                    # compressed payload, so multi-member helpers (gzip.decompress,
                    # which reads trailing bytes as another member) must not be used.
                    if kind == "gzip":
                        decoder = zlib.decompressobj(31)
                    elif kind == "bzip2":
                        decoder = bz2.BZ2Decompressor()
                    elif kind == "xz":
                        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=_MAX_PAYLOAD)
                    else:
                        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=_MAX_PAYLOAD)
                    payload = decoder.decompress(blob, max_length=_MAX_PAYLOAD - written + 1)
                    if len(payload) > _MAX_PAYLOAD - written or not decoder.eof:
                        raise ValueError("truncated stream or decompression limit reached")
                    if payload:
                        _store(off, kind, payload[:_MAX_PAYLOAD])
                except Exception as exc:  # magic match that isn't a valid stream
                    notes.append(f"stream at 0x{off:x} ({desc}) rejected: "
                                 f"{type(exc).__name__}")
            elif kind == "tar":
                try:
                    with tarfile.open(fileobj=io.BytesIO(data[off:]), mode="r:") as tf:
                        for member in tf:
                            if _time.time() > deadline:
                                raise TimeoutError("extraction time budget")
                            if not member.isfile():
                                continue
                            if member.size > _MAX_PAYLOAD - written:
                                raise ValueError("tar size budget exceeded")
                            src = tf.extractfile(member)
                            if src is None:
                                continue
                            _write(out_root / f"off_{off:08x}_tar", member.name, src.read())
                        start = max(start, off + tf.offset)
                except Exception as exc:
                    notes.append(f"tar cursor at 0x{off:x} unreadable: {type(exc).__name__}")
            elif kind == "cpio":
                try:
                    entries = _cpio(out_root / f"off_{off:08x}_cpio", data[off: off + _MAX_PAYLOAD])
                    start = max(start, off + entries["consumed"])
                except Exception as exc:
                    notes.append(f"cpio at 0x{off:x} unparsable: {type(exc).__name__}")
            elif kind == "zip":
                try:
                    if out_root is None:
                        continue
                    with zipfile.ZipFile(str(path)) as zf:
                        for member in zf.infolist():
                            if member.is_dir():
                                continue
                            if member.file_size > _MAX_PAYLOAD - written:
                                raise ValueError("zip size budget exceeded")
                            _write(out_root / f"off_{off:08x}_zip", member.filename, zf.read(member))
                    start = len(data)
                except Exception as exc:
                    notes.append(f"zip at 0x{off:x} not extractable: {type(exc).__name__}")
            elif kind == "squashfs":
                if out_root is None:
                    continue
                seg = out_root / f"off_{off:08x}_squashfs.img"
                _write(out_root, seg.name, data[off:])
                if has_tool("unsquashfs"):
                    res = run(["unsquashfs", "-d", str(out_root / f"off_{off:08x}_squashfs"),
                               str(seg)], timeout=timeout)
                    if res.returncode == 0:
                        extracted.append(f"off_{off:08x}_squashfs/")
                    else:
                        notes.append("unsquashfs failed; carved segment kept for manual analysis")
                else:
                    notes.append("SquashFS carved but unsquashfs is not installed; "
                                 "segment saved for manual unpacking")

    return {"engine": "carve", "signatures": signatures,
            "extracted": extracted[:4000], "notes": notes, "scanned": len(data),
            "truncated_scan": Path(path).stat().st_size > len(data)}


# --------------------------------------------------------------------------- #
# entropy
# --------------------------------------------------------------------------- #
def entropy_profile(path: str, block_size: int = 1024, max_blocks: int = 8192) -> dict:
    """Per-block Shannon entropy; high flat entropy suggests encryption/compression."""
    data = Path(path).read_bytes()
    blocks: list[float] = []
    for i in range(0, min(len(data), block_size * max_blocks), block_size):
        chunk = data[i : i + block_size]
        if not chunk:
            break
        freq = Counter(chunk)
        n = len(chunk)
        ent = -sum((c / n) * math.log2(c / n) for c in freq.values())
        blocks.append(round(ent, 3))
    overall = round(sum(blocks) / len(blocks), 3) if blocks else 0.0
    high = sum(1 for b in blocks if b > 7.5)
    return {
        "block_size": block_size,
        "blocks": blocks[:max_blocks],
        "overall_entropy": overall,
        "high_entropy_blocks": high,
        "encrypted_or_compressed": bool(blocks) and (high / len(blocks)) > 0.3,
    }


# --------------------------------------------------------------------------- #
# strings + secrets + components
# --------------------------------------------------------------------------- #
@dataclass
class Secret:
    kind: str
    value: str
    severity: str
    offset_hint: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity,
                "value": _mask(self.value), "context": self.offset_hint}


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def redact_context(line: str, *, keep: int = 160) -> str:
    """Mask secret *values* inside a raw context/preview line.

    Secret rules with a capture group isolate the secret value; rules without
    one (e.g. the ``-----BEGIN ... PRIVATE KEY-----`` header) are structural and
    left intact. This is what keeps finding descriptions/evidence useful for
    triage without re-leaking the secret they report.
    """
    out = line
    for _kind, pattern, _sev in SECRET_RULES:
        if pattern.groups == 0:
            continue

        def _sub(m: re.Match) -> str:
            value = m.group(m.lastindex)
            try:
                return m.group(0).replace(value, _mask(value), 1)
            except ValueError:
                return m.group(0)

        out = pattern.sub(_sub, out)
    return out[:keep]


SECRET_RULES = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("aws-secret", re.compile(r"(?i)aws.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"), "critical"),
    ("generic-password", re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,64})"), "high"),
    ("api-key", re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{8,64})"), "high"),
    ("shadow-hash", re.compile(r"\b(root|admin):\$[0-9][a-z]?\$[^\s:]{10,}\b"), "critical"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "high"),
    ("pem-blob", re.compile(r"MII[A-Za-z0-9+/]{40,}"), "medium"),
]

# Known components worth version-mapping (name -> regex on short strings).
COMPONENT_RULES = [
    ("busybox", re.compile(r"BusyBox v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("openssl", re.compile(r"OpenSSL[ /]([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", re.I)),
    ("openssh", re.compile(r"OpenSSH[ _]([0-9]+\.[0-9]+(?:p[0-9]+)?)", re.I)),
    ("dropbear", re.compile(r"dropbear[ _]?v?([0-9]+\.[0-9]+)", re.I)),
    ("libcurl", re.compile(r"libcurl/([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("mbedtls", re.compile(r"mbed ?tls[ /]([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("wolfssl", re.compile(r"wolfSSL/([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("lighttpd", re.compile(r"lighttpd/([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("dnsmasq", re.compile(r"dnsmasq-([0-9]+\.[0-9]+)", re.I)),
    ("mosquitto", re.compile(r"mosquitto[ /]([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("u-boot", re.compile(r"U-Boot ([0-9]{4}\.[0-9]{2})", re.I)),
    ("zlib", re.compile(r"zlib[ /]([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
]

# Credential pairs commonly left in firmware.
DEFAULT_CRED_PAIRS = [
    ("root", "root"), ("admin", "admin"), ("admin", "password"), ("root", "toor"),
    ("support", "support"), ("user", "user"), ("admin", "1234"), ("root", "123456"),
    ("ubnt", "ubnt"), ("admin", ""), ("root", "vizxv"), ("root", "xc3511"),
]


def extract_strings(path: str, *, min_len: int = 5, limit: int = 200_000) -> list[str]:
    """Use the `strings` tool when available, else a pure-Python fallback."""
    if has_tool("strings"):
        res = run(["strings", "-n", str(min_len), path], timeout=300)
        return res.stdout.splitlines()[:limit]
    data = Path(path).read_bytes()
    out: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("latin-1"))
        if len(out) >= limit:
            break
    return out


def find_secrets(strings: list[str]) -> list[Secret]:
    findings: list[Secret] = []
    seen: set[str] = set()
    for s in strings:
        for kind, pattern, severity in SECRET_RULES:
            for m in pattern.finditer(s):
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                if value in seen:
                    continue
                seen.add(value)
                findings.append(Secret(
                    kind=kind, value=value, severity=severity,
                    # Stored redacted so every consumer (descriptions, evidence,
                    # JSON reports) stays safe by construction.
                    offset_hint=redact_context(s.strip()),
                ))
    return findings


@dataclass
class Component:
    name: str
    version: str | None
    keyword: str

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "keyword": self.keyword}


def find_components(strings: list[str]) -> list[Component]:
    blob = "\n".join(strings)
    found: dict[str, Component] = {}
    for rule in COMPONENT_RULES:
        name, pattern = rule[0], rule[1]
        m = pattern.search(blob)
        if m:
            version = m.group(1) if m.groups() else None
            found[name] = Component(name=name, version=version,
                                    keyword=f"{name} {version}" if version else name)
    return list(found.values())


def find_default_credentials(strings: list[str]) -> list[tuple[str, str]]:
    blob = "\n".join(strings).lower()
    hits: list[tuple[str, str]] = []
    for user, pw in DEFAULT_CRED_PAIRS:
        if pw and f"{user}" in blob and pw in blob:
            # Coarse co-occurrence; the UI labels this as a candidate.
            hits.append((user, pw))
    return hits


# --------------------------------------------------------------------------- #
# Hardware-rooted boot-chain audit (static strings)
# --------------------------------------------------------------------------- #
# These rules look for *evidence* of boot-chain controls and for risky
# debug/unlocked-boot indicators. A string match is not proof that a control is
# active, and absence is not proof that it is missing; the result says which it
# is. This is the static half of a secure-boot assessment; confirm the final
# state on the hardware (fuses, boot ROM, signed image verification).
BOOT_CHAIN_RULES: list[tuple[str, str, re.Pattern, str, str]] = [
    ("signed-image", "Signed boot image / FIT signature",
     re.compile(r"(?i)fit[_ -]?signature|CONFIG_FIT_SIGNATURE|verify=required|"
                r"image signature|signed image|sha256[, ]+rsa|rsa2048"), "positive", "info"),
    ("verified-boot", "Verified boot / AVB / dm-verity",
     re.compile(r"(?i)verified[_ -]?boot|secure[_ -]?boot|androidboot\.verifiedbootstate|"
                r"vbmeta|avb_|dm[-_]verity|ima_policy|boot_state"), "positive", "info"),
    ("root-of-trust", "Root of trust / fuse / OTP",
     re.compile(r"(?i)root of trust|rotpk|\bsrk\b|pk_hash|otp|efuse|e-fuse|bootrom|romcode"),
     "positive", "info"),
    ("rollback", "Anti-rollback / version counter",
     re.compile(r"(?i)anti[-_ ]?rollback|rollback[_ -]?index|version[_ -]?counter|monotonic"),
     "positive", "info"),
    ("debug-lock", "Debug-port lock / production mode",
     re.compile(r"(?i)jtag[_ -]?disable|swd[_ -]?disable|debug[_ -]?lock|secure[_ -]?debug|"
                r"disable_jtag|production mode"), "positive", "info"),
    ("measured-boot", "Measured boot / TPM",
     re.compile(r"(?i)measured[_ -]?boot|\btpm2?\b|pcr\[|tpm_eventlog"), "positive", "info"),
    ("update-signature", "Signed firmware update verification",
     re.compile(r"(?i)verify_signature|rsa_verify|firmware[_ -]?signature|ota signature|"
                r"update signature|signature check|secure update"), "positive", "info"),
    ("debug-console", "Debug shell / unlocked bootloader indicator",
     re.compile(r"(?i)init=/bin/sh|rdinit=/bin/sh|bootdelay=[1-9]|telnetd|debugfs|"
                r"root shell|single[-_ ]user|unlocked bootloader"), "risk", "medium"),
    ("encrypted-firmware", "Encrypted firmware / filesystem",
     re.compile(r"(?i)encrypted firmware|firmware encryption|aes[-_]gcm|dm[-_]crypt|fscrypt"),
     "positive", "info"),
]

BOOT_CHAIN_GAPS = {
    "signed-image": "signed boot image verification not evidenced",
    "verified-boot": "verified boot / dm-verity not evidenced",
    "root-of-trust": "hardware root-of-trust/fuse references not evidenced",
    "rollback": "anti-rollback/version-counter references not evidenced",
    "debug-lock": "debug-port lock/production-mode references not evidenced",
    "update-signature": "signed update verification not evidenced",
}


def audit_boot_chain(strings: list[str]) -> dict:
    """Static boot-chain evidence and gaps from firmware strings.

    Returns a JSON-safe dict with indicators, gaps, a coarse evidence score and
    finding drafts (as plain dicts) so both the full analysis and the standalone
    module share exactly the same interpretation.
    """
    indicators: list[dict] = []
    matched_rules: set[str] = set()
    for rule, label, pattern, kind, severity in BOOT_CHAIN_RULES:
        matches: list[str] = []
        seen: set[str] = set()
        for line in strings:
            if not pattern.search(line):
                continue
            clean = line.strip()[:220]
            if clean and clean not in seen:
                seen.add(clean)
                matches.append(clean)
            if len(matches) >= 5:
                break
        if not matches:
            continue
        matched_rules.add(rule)
        indicators.append({
            "rule": rule,
            "label": label,
            "kind": kind,
            "severity": severity,
            "evidence": matches,
        })

    gaps = [
        label for rule, label in BOOT_CHAIN_GAPS.items()
        if rule not in matched_rules
    ]
    findings: list[dict] = []
    for indicator in indicators:
        if indicator["kind"] != "risk":
            continue
        findings.append({
            "title": f"Boot-chain risk indicator: {indicator['label']}",
            "category": "boot-chain",
            "severity": indicator["severity"],
            "description": (
                "Static strings contain an indicator associated with an interactive "
                "debug shell, unlocked bootloader, or weakened boot policy. This is "
                "evidence to verify on the hardware, not proof of reachability."
            ),
            "remediation": (
                "Disable the production console/debug shell, set a zero boot delay, "
                "lock the bootloader and debug port, and require signed boot images."
            ),
            "evidence": "; ".join(indicator["evidence"])[:1200],
            "extra": {"rule": indicator["rule"], "kind": "risk"},
        })

    signed = "signed-image" in matched_rules or "verified-boot" in matched_rules
    if not signed:
        findings.append({
            "title": "No signed-boot evidence found in firmware strings",
            "category": "boot-chain",
            "severity": "low",
            "description": (
                "Static analysis found no signed FIT/verified-boot/AVB/dm-verity "
                "markers. This may be because the bootloader is stripped, compressed "
                "or absent from the image; it is not proof that secure boot is off. "
                "Confirm the fuse/boot-ROM policy on the device."
            ),
            "remediation": (
                "Enable verified boot with a hardware root of trust, sign every "
                "boot stage and update package, and document the key lifecycle."
            ),
            "evidence": "no signature-verification strings matched",
            "extra": {"rule": "signed-image", "kind": "gap"},
        })
    if "rollback" not in matched_rules:
        findings.append({
            "title": "No anti-rollback evidence found in firmware strings",
            "category": "boot-chain",
            "severity": "info",
            "description": (
                "No version-counter/anti-rollback strings were found. If the device "
                "accepts older signed firmware, an attacker can reintroduce a known "
                "vulnerable release even with signature checks enabled."
            ),
            "remediation": "Enforce a monotonic version counter and reject downgrades.",
            "evidence": "no rollback-counter strings matched",
            "extra": {"rule": "rollback", "kind": "gap"},
        })

    positive = sum(1 for i in indicators if i["kind"] == "positive")
    score = positive
    confidence = "low"  # string evidence only; hardware confirmation required
    summary = (
        f"{positive} boot-chain control indicator(s), {len(gaps)} gap(s) in static "
        f"strings; {len([i for i in indicators if i['kind'] == 'risk'])} risk "
        f"indicator(s). Confidence: {confidence} (confirm on hardware)."
    )
    return {
        "indicators": indicators,
        "gaps": gaps,
        "score": score,
        "confidence": confidence,
        "summary": summary,
        "findings": findings,
        "note": (
            "String matches are evidence, not proof. Compressed/stripped bootloaders "
            "may hide controls; confirm the fuse, boot-ROM and update policy on the "
            "hardware."
        ),
    }


@dataclass
class FirmwareReport:
    size: int = 0
    signatures: list[Signature] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    entropy: dict = field(default_factory=dict)
    default_creds: list[tuple[str, str]] = field(default_factory=list)
    carve_engine: str | None = None
    boot_chain: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "size": self.size,
            "signatures": [s.to_dict() for s in self.signatures][:100],
            "secrets": [s.to_dict() for s in self.secrets][:100],
            "components": [c.to_dict() for c in self.components],
            "entropy": {k: v for k, v in self.entropy.items() if k != "blocks"},
            "default_credential_candidates": self.default_creds,
            "boot_chain": self.boot_chain,
        }
        if self.carve_engine:
            d["carve_engine"] = self.carve_engine
        return d
