"""Unit tests for the analysis engines (traffic, bootlog, firmware secrets)."""

from __future__ import annotations

import os

from app.plugins.firmware import helpers as fw
from app.services.bootlog import analyse_bootlog
from app.services.traffic import classify_encryption, extract_version_hints, shannon_entropy


def test_entropy_bounds():
    assert shannon_entropy(b"\x00" * 100) < 0.1
    assert shannon_entropy(bytes(range(256)) * 4) > 7.9


def test_plaintext_detected():
    text = [b"GET /index.html HTTP/1.1\r\nHost: router.local\r\n" * 3] * 5
    verdict = classify_encryption(text)
    assert verdict.encrypted is False
    assert verdict.printable_ratio > 0.8


def test_ciphertext_detected():
    blobs = [os.urandom(512) for _ in range(6)]
    verdict = classify_encryption(blobs)
    assert verdict.encrypted is True
    assert verdict.confidence >= 0.6


def test_bootlog_finds_bootloader_and_telnet():
    log = """
    U-Boot 2021.10 (Jan 01 2023 - 00:00:00)
    Starting kernel ...
    Linux version 5.4.0 (gcc 10.2.0)
    telnetd starting on port 23
    login:
    admin_password="hunter2"
    """
    report = analyse_bootlog(log)
    rules = {f.extra.get("rule") for f in report.findings}
    assert "u-boot" in rules
    assert "linux-kernel" in rules
    assert "telnet-server" in rules
    assert "5.4.0" in report.versions


def test_firmware_secret_detection():
    strings = [
        'password="supersecret123"',
        "root:$1$abc$0123456789abcdefghijklmnop:19000:0:99999:7:::",
        "AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN RSA PRIVATE KEY-----",
    ]
    secrets = fw.find_secrets(strings)
    kinds = {s.kind for s in secrets}
    assert "generic-password" in kinds
    assert "shadow-hash" in kinds
    assert "aws-access-key" in kinds
    assert "private-key" in kinds


def test_firmware_component_detection():
    strings = ["BusyBox v1.35.0", "OpenSSL 1.1.1f", "dropbear_2020.81"]
    comps = {c.name: c.version for c in fw.find_components(strings)}
    assert comps["busybox"] == "1.35.0"
    assert comps["openssl"] == "1.1.1f"
    assert comps["dropbear"] == "2020.81"


def test_version_hints_from_blob():
    blob = b"device model firmware_version=2.1.4 build 99\n" * 3
    hints = extract_version_hints(blob)
    assert "2.1.4" in hints.versions
