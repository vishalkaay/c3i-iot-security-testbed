"""Bluetooth fingerprint-parsing regressions.

Fixtures mirror *real* ``bluetoothctl`` transcripts captured on the reference
host (Apple MacBook advertising ManufacturerData, Windows OOBE hostnames,
multi-line hex dumps with BlueZ's ASCII gutter) so the parsers cannot silently
drift away from reality again.
"""
from __future__ import annotations

import pytest

from app.plugins.bluetooth import helpers as bh


class _FakeResult:
    def __init__(self, text: str) -> None:
        self._text = text
        self.stdout = text
        self.stderr = ""
        self.returncode = 0

    def lines(self) -> list[str]:
        return self._text.splitlines()


def _patch_bluetoothctl(monkeypatch: pytest.MonkeyPatch, scan: str, info: str) -> None:
    def fake_run(argv: list, **_kw):
        if argv[:2] == ["bluetoothctl", "--timeout"]:
            return _FakeResult(scan)
        if argv[:2] == ["bluetoothctl", "show"]:
            return _FakeResult("Controller 00:11:22:33:44:55 (public)\n\tPowered: yes\n")
        if argv[:2] == ["bluetoothctl", "info"]:
            address = argv[2].upper()
            # info text embeds the queried device's record; tests use two devices
            if address == "CC:08:FA:71:79:91":
                return _FakeResult(info)
            return _FakeResult(info.replace("CC:08:FA:71:79:91", address))
        return _FakeResult("")

    monkeypatch.setattr(bh, "run", fake_run)
    monkeypatch.setattr(bh, "has_tool", lambda _name: True)
    # Never touch the host's real BlueZ from a regression test.
    monkeypatch.setattr(bh, "_scan_dbus", lambda _duration: None)


# --------------------------------------------------------------------------- #
# Real scan transcript (ANSI colours stripped by the parser, kept here raw)
# --------------------------------------------------------------------------- #
SCAN_TRANSCRIPT = (
    "SetDiscoveryFilter success\n"
    "Discovery started\n"
    "[\x1b[0;93mCHG\x1b[0m] Controller AC:19:8E:27:6E:91 Discovering: yes\n"
    "[\x1b[0;92mNEW\x1b[0m] Device CC:08:FA:71:79:91 Abhiveer\u2019s MacBook Air\n"
    "[\x1b[0;92mNEW\x1b[0m] Device F4:6D:3F:20:3B:C1 LAPTOP-H041SFCK\n"
    "[\x1b[0;92mNEW\x1b[0m] Device B0:3C:DC:82:DD:3A DESKTOP-Q3UQ4IM\n"
    "[\x1b[0;92mNEW\x1b[0m] Device 4C:AC:0C:C6:CA:D9 CHAITANYA\n"
    "[\x1b[0;93mCHG\x1b[0m] Device F4:6D:3F:20:3B:C1 TxPower: 0x000c (12)\n"
    "[\x1b[0;93mCHG\x1b[0m] Device F4:6D:3F:20:3B:C1 UUIDs: 0000110b-0000-1000-8000-00805f9b34fb\n"
    "[\x1b[0;93mCHG\x1b[0m] Device F4:6D:3F:20:3B:C1 RSSI: -52\n"
)

# --------------------------------------------------------------------------- #
# Real `bluetoothctl info` record for the Apple LE device, incl. the
# ManufacturerData multi-line hex dump with ASCII gutter columns.
# --------------------------------------------------------------------------- #
INFO_TRANSCRIPT = (
    "Device CC:08:FA:71:79:91 (public)\n"
    "\tName: Abhiveer\u2019s MacBook Air\n"
    "\tAlias: Abhiveer\u2019s MacBook Air\n"
    "\tClass: 0x0038010c (3670284)\n"
    "\tIcon: computer\n"
    "\tPaired: no\n"
    "\tBonded: no\n"
    "\tTrusted: no\n"
    "\tBlocked: no\n"
    "\tConnected: no\n"
    "\tLegacyPairing: no\n"
    "\tRSSI: -58\n"
    "\tTxPower: 0x000c (12)\n"
    "\tModalias: usb:v004Cp0126d0041\n"
    "\tManufacturerData.Key: 0x4c00 (19456)\n"
    "\tManufacturerData.Value:\n"
    "  02 24 02 00 00 00 00 00 00 00 00 00 00 00 00 00  .$..............\n"
    "\tUUID: PnP Information           (00001200-0000-1000-8000-00805f9b34fb)\n"
    "\tUUID: A/V Remote Control Target (0000110c-0000-1000-8000-00805f9b34fb)\n"
)


def test_scan_captures_names_rssi_txpower_uuids(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_bluetoothctl(monkeypatch, SCAN_TRANSCRIPT, INFO_TRANSCRIPT)
    devices = {d.address: d for d in bh.scan(6)}

    assert set(devices) >= {
        "CC:08:FA:71:79:91", "F4:6D:3F:20:3B:C1", "B0:3C:DC:82:DD:3A",
    }
    apple = devices["CC:08:FA:71:79:91"]
    assert apple.name == "Abhiveer\u2019s MacBook Air"
    win = devices["F4:6D:3F:20:3B:C1"]
    assert win.name == "LAPTOP-H041SFCK"
    assert win.tx_power == 12
    assert win.rssi == -52
    assert "0000110b-0000-1000-8000-00805f9b34fb" in win.uuids


def test_device_info_parses_manufacturer_data_hexdump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_bluetoothctl(monkeypatch, SCAN_TRANSCRIPT, INFO_TRANSCRIPT)
    dev = bh.device_info("CC:08:FA:71:79:91")

    assert dev.name == "Abhiveer\u2019s MacBook Air"
    assert dev.icon == "computer"
    assert dev.device_class == "0x0038010c (3670284)"
    assert dev.rssi == -58
    assert dev.tx_power == 12
    # BlueZ prints the 16-bit company id in little-endian display order;
    # the parser must recognise 0x4c00 as Apple's 0x004C.
    assert "4c00" in dev.manufacturer_data
    summary = dev.manufacturer_data["4c00"]
    assert "Apple" in summary
    assert "0224" in summary.replace(" ", "")
    # Class decode must not crash on the "(decimal)" suffix.
    assert "cod-major:computer" in dev.uuids


def test_distance_model_is_calibrated_and_reports_uncertainty() -> None:
    at_one_metre = bh.estimate_distance(-59, reference_rssi_dbm=-59,
                                        path_loss_exponent=2.0)
    assert at_one_metre["available"] is True
    assert at_one_metre["estimated_m"] == 1.0
    assert at_one_metre["range_m"] == [1.0, 1.0]

    ten_metres = bh.estimate_distance(-79, reference_rssi_dbm=-59,
                                      path_loss_exponent=2.0)
    assert ten_metres["estimated_m"] == 10.0
    assert ten_metres["range_m"][0] < ten_metres["estimated_m"] < ten_metres["range_m"][1]
    assert ten_metres["confidence"] == "low"
    assert "RTT is not used" in ten_metres["caveat"]


def test_distance_model_refuses_sentinel_rssi() -> None:
    unknown = bh.estimate_distance(0)
    assert unknown["available"] is False
    assert unknown["estimated_m"] is None
    assert "sentinel" in unknown["caveat"]


def test_l2ping_uses_bluez_rssi_for_distance(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_bluetoothctl(monkeypatch, SCAN_TRANSCRIPT, INFO_TRANSCRIPT)

    def fake_run(argv: list, **_kw):
        if argv[:2] == ["bluetoothctl", "info"]:
            return _FakeResult(INFO_TRANSCRIPT)
        if argv[0] == "l2ping":
            return _FakeResult(
                "Ping: CC:08:FA:71:79:91 from AC:19:8E:27:6E:91 (data size 44) ...\n"
                "44 bytes from CC:08:FA:71:79:91 id 0 time 12.4ms\n"
                "44 bytes from CC:08:FA:71:79:91 id 1 time 13.1ms\n"
                "2 sent, 2 received, 0% loss\n"
            )
        return _FakeResult("")

    monkeypatch.setattr(bh, "run", fake_run)
    monkeypatch.setattr(bh, "has_tool", lambda _name: True)

    stats = bh.l2ping("CC:08:FA:71:79:91", count=2)
    assert not isinstance(stats, str)
    estimate = stats.distance
    assert estimate["available"] is True
    assert estimate["rssi_dbm"] == -58
    assert 0.8 <= estimate["estimated_m"] <= 1.5
    assert stats.to_dict()["estimated_distance_m"] == estimate["estimated_m"]


def test_l2ping_without_rssi_says_distance_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bh, "has_tool", lambda _name: True)
    monkeypatch.setattr(bh, "device_info", lambda _address: bh.BtDevice(address="AA:BB:CC:DD:EE:FF"))

    def fake_run(argv: list, **_kw):
        if argv[0] == "l2ping":
            return _FakeResult("44 bytes from AA:BB:CC:DD:EE:FF id 0 time 8.0ms\n")
        return _FakeResult("")

    monkeypatch.setattr(bh, "run", fake_run)
    stats = bh.l2ping("AA:BB:CC:DD:EE:FF", count=1)
    assert not isinstance(stats, str)
    assert stats.distance["available"] is False
    assert "No RSSI" in stats.distance["caveat"]


def test_infer_os_apple_manufacturer_data(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_bluetoothctl(monkeypatch, SCAN_TRANSCRIPT, INFO_TRANSCRIPT)
    dev = bh.device_info("CC:08:FA:71:79:91")
    infer = bh.infer_os(dev)
    assert infer.os_family == "Apple (iOS/macOS family)"
    assert infer.confidence == "high"
    assert any("company ID" in r for r in infer.reasons)


def test_infer_os_windows_default_hostname() -> None:
    dev = bh.BtDevice(address="B0:3C:DC:82:DD:3A", name="DESKTOP-Q3UQ4IM")
    infer = bh.infer_os(dev)
    assert infer.os_family == "Windows"
    assert infer.confidence == "high"


def test_infer_os_class_only_stays_low_confidence() -> None:
    dev = bh.BtDevice(address="00:11:22:33:44:55", icon="computer")
    infer = bh.infer_os(dev)
    assert infer.confidence == "low"
    assert "Windows/Linux/macOS" in infer.os_family


def test_infer_os_dis_read_upgrades_to_version_claim() -> None:
    dev = bh.BtDevice(address="00:11:22:33:44:55", name="DESKTOP-Q3UQ4IM")
    infer = bh.infer_os(dev, {"firmware_revision": "1.2.3"})
    assert infer.os_family == "Windows"
    assert infer.os_version == "1.2.3"


def test_company_id_endianness() -> None:
    # Apple airs 0x004C; BlueZ displays 0x4c00.
    assert bh._company_name("4c00") == "Apple"
    assert bh._company_name("004c") == "Apple"
    assert bh._company_name("00e0") == "Google"
    assert bh._company_name("ffff") is None


def test_scan_job_surfaces_os_hints_and_fingerprint_finding(
    monkeypatch: pytest.MonkeyPatch, client, auth_headers,
) -> None:
    """End-to-end: scan via the API records per-device OS hints + aggregate finding."""
    import time

    _patch_bluetoothctl(monkeypatch, SCAN_TRANSCRIPT, INFO_TRANSCRIPT)

    r = client.post("/api/v1/engagements", headers=auth_headers,
                    json={"name": "bt-print", "client": "ci", "targets": ["local"]})
    assert r.status_code == 201, r.text
    eng = r.json()

    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "bluetooth", "action": "scan",
              "params": {"duration": 6}},
    )
    assert r.status_code == 201, r.text
    job_id = r.json()["id"]

    deadline = time.time() + 20
    job = None
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            break
        time.sleep(0.1)
    assert job is not None and job["status"] == "succeeded", job

    result = job["result"]
    families = {h["os_family"] for h in result["os_hints"]}
    assert any("Windows" in f for f in families)
    assert any("Apple" in f for f in families)

    findings = client.get(
        "/api/v1/findings", headers=auth_headers,
        params={"engagement_id": eng["id"]},
    ).json()
    assert any(f["category"] == "bluetooth-fingerprinting" for f in findings), findings[:5]
