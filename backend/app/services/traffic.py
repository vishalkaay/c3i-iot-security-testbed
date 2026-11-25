"""Packet-capture analysis.

Replaces the legacy "firmware extraction" that was really just string-mining a
pcap. Here we provide honest, well-defined primitives:

* :func:`classify_encryption` - per-payload entropy/printability scoring to say
  whether application data looks encrypted, compressed, or plaintext.
* :func:`extract_strings` - printable-string extraction with filtering.
* :func:`extract_version_hints` - pull product/version-looking tokens out of a
  capture (used to seed CVE lookups when no firmware image is available).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_VERSION = re.compile(
    r"(?i)(?:firmware|fw|version|ver|build|model|sw|hw)[^A-Za-z0-9]{0,4}"
    r"([A-Za-z]?[0-9]+(?:\.[0-9]+){1,4})"
)
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{2,30}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(data)


@dataclass
class EncryptionVerdict:
    encrypted: bool
    confidence: float
    entropy: float
    printable_ratio: float
    samples: int
    reasoning: str

    def to_dict(self) -> dict:
        return {
            "encrypted": self.encrypted,
            "confidence": round(self.confidence, 3),
            "entropy_bits_per_byte": round(self.entropy, 2),
            "printable_ratio": round(self.printable_ratio, 3),
            "samples_analysed": self.samples,
            "reasoning": self.reasoning,
        }


def classify_encryption(payloads: list[bytes]) -> EncryptionVerdict:
    """Heuristic verdict over a set of application-layer payloads."""
    payloads = [p for p in payloads if p]
    if not payloads:
        return EncryptionVerdict(False, 0.0, 0.0, 0.0, 0, "no payloads to analyse")

    entropies = [shannon_entropy(p) for p in payloads]
    printables = [printable_ratio(p) for p in payloads]
    avg_ent = sum(entropies) / len(entropies)
    avg_pr = sum(printables) / len(printables)

    # Plaintext text ~4.5 bits/byte & high printability. Ciphertext ~7.8-8.0.
    if avg_pr > 0.85 and avg_ent < 5.2:
        return EncryptionVerdict(False, 0.85, avg_ent, avg_pr, len(payloads),
                                 "high printable ratio and low entropy -> plaintext")
    if avg_ent > 7.2 and avg_pr < 0.55:
        return EncryptionVerdict(True, 0.9, avg_ent, avg_pr, len(payloads),
                                 "near-uniform byte distribution -> encrypted/compressed")
    if avg_ent > 6.3:
        return EncryptionVerdict(True, 0.6, avg_ent, avg_pr, len(payloads),
                                 "elevated entropy -> likely encrypted")
    return EncryptionVerdict(False, 0.4, avg_ent, avg_pr, len(payloads),
                             "mixed/ambiguous; manual review recommended")


def extract_strings(data: bytes, *, min_len: int = 4, limit: int = 2000) -> list[str]:
    out: list[str] = []
    for match in _PRINTABLE.finditer(data):
        if len(match.group()) >= min_len:
            out.append(match.group().decode("latin-1"))
        if len(out) >= limit:
            break
    return out


@dataclass
class VersionHints:
    versions: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"versions": self.versions, "tokens": self.tokens}


def extract_version_hints(data: bytes) -> VersionHints:
    text = "\n".join(extract_strings(data, min_len=4, limit=20000))
    versions = sorted(set(_VERSION.findall(text)))[:50]
    # Harvest vendor/product-looking tokens to feed the CVE keyword search.
    stop = {
        "the", "and", "for", "with", "http", "https", "true", "false", "null",
        "error", "warning", "debug", "info", "log", "device", "root", "admin",
    }
    counts = Counter(t.lower() for t in _TOKEN.findall(text) if t.lower() not in stop)
    tokens = [tok for tok, _ in counts.most_common(40)]
    return VersionHints(versions=versions, tokens=tokens)


def read_pcap_payloads(path: str, *, max_packets: int = 5000) -> list[bytes]:
    """Extract payloads using tshark if present; otherwise parse raw pcap.

    We deliberately avoid a heavy pcap-parsing dependency; tshark is already a
    declared capability for the network modules. The manual fallback understands
    the classic libpcap format (global header + per-packet records), which is
    what tcpdump writes; empty captures then yield *no* payloads instead of a
    bogus 24-byte "payload" made of the pcap file header.
    """
    from app.plugins.tools import has_tool, run

    data = Path(path).read_bytes() if Path(path).exists() else b""
    if not data:
        return []

    if not has_tool("tshark"):
        return _parse_pcap_fallback(data, max_packets=max_packets)

    result = run(
        [
            "tshark", "-r", path, "-T", "fields", "-e", "data.data",
            "-c", str(max_packets),
        ],
        timeout=120,
    )
    payloads: list[bytes] = []
    for line in result.lines():
        token = line.strip().replace(":", "")
        if token:
            try:
                payloads.append(bytes.fromhex(token))
            except ValueError:
                continue
    return payloads


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",   # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4": ">",   # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1": "<",   # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d": ">",
}


def _parse_pcap_fallback(data: bytes, max_packets: int) -> list[bytes]:
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic not in _PCAP_MAGICS:
        # pcapng or unknown: fall back to treating everything as one blob.
        return [data[:2_000_000]]
    import struct

    endian = _PCAP_MAGICS[magic]
    payloads: list[bytes] = []
    offset = 24
    while offset + 16 <= len(data) and len(payloads) < max_packets:
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", data[offset:offset + 16])
        if incl_len > 262_144 or incl_len == 0:  # sanity bound (256 KiB)
            break
        start = offset + 16
        payloads.append(data[start:start + incl_len])
        offset = start + incl_len
    return payloads
