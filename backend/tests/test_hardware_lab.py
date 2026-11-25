"""Offline regression tests for the hardware-lab additions.

No programmer, I2C bus, logic analyzer, or target is touched: each test feeds
realistic tool output through the same parser/validator used in production.
"""

from __future__ import annotations

import pytest

from app.plugins.hardware import support


class _Result:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]


def test_spi_identify_parses_identity_and_write_protection(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list, **_kw):
        if "--flash-name" in argv:
            return _Result('vendor="Winbond" name="W25Q128.V"\n')
        if "--flash-size" in argv:
            return _Result("16777216\n")
        if "--wp-status" in argv:
            return _Result(
                "Protection range: start=0x00000000 length=0x00000000 (none)\n"
                "Protection mode: disabled\n"
            )
        return _Result()

    monkeypatch.setattr(support, "has_tool", lambda name: name == "flashrom")
    monkeypatch.setattr(support, "run", fake_run)

    result = support.spi_identify(programmer="ch341a_spi")

    assert result["ok"] is True
    assert result["vendor"] == "Winbond"
    assert result["chip"] == "W25Q128.V"
    assert result["size_bytes"] == 16 * 1024 * 1024
    assert result["write_protection"]["mode"] == "disabled"
    assert "ch341a_spi" in result["programmer"]


def test_spi_identify_rejects_unknown_programmer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(support, "has_tool", lambda _name: True)
    result = support.spi_identify(programmer="shell-injection")
    assert result["ok"] is False
    assert "unknown programmer" in result["error"]


def test_i2c_scan_decodes_addresses_and_in_use(monkeypatch: pytest.MonkeyPatch) -> None:
    output = (
        "     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n"
        "00:                         -- -- -- -- -- -- -- --\n"
        "10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --\n"
        "20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --\n"
        "30: -- -- -- -- 34 -- -- -- -- -- -- -- -- -- -- --\n"
        "40: -- -- -- -- -- -- -- -- UU -- -- -- -- -- -- --\n"
        "50: 50 -- -- -- -- -- -- -- -- -- -- -- -- -- -- --\n"
    )
    monkeypatch.setattr(support, "has_tool", lambda name: name == "i2cdetect")
    monkeypatch.setattr(support, "run", lambda *_a, **_k: _Result(output))

    result = support.i2c_scan(1)

    assert result["ok"] is True
    addresses = {d["address"]: d["status"] for d in result["devices"]}
    assert addresses["0x34"] == "present"
    assert addresses["0x48"] == "in-use"
    assert addresses["0x50"] == "present"
    assert result["count"] == 3


def test_i2c_dump_detects_no_response(monkeypatch: pytest.MonkeyPatch) -> None:
    output = (
        "     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n"
        "00: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX\n"
        "10: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX\n"
    )
    monkeypatch.setattr(support, "has_tool", lambda name: name == "i2cdump")
    monkeypatch.setattr(support, "run", lambda *_a, **_k: _Result(output))

    result = support.i2c_dump(1, 0x50)
    assert result["ok"] is True
    assert result["responded"] is False
    assert result["address"] == "0x50"


def test_logic_capture_builds_safe_sigrok_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []

    def fake_run(argv: list, **_kw):
        captured.append(argv)
        return _Result("uart: 48 65 6c 6c 6f\n")

    monkeypatch.setattr(support, "has_tool", lambda name: name == "sigrok-cli")
    monkeypatch.setattr(support, "run", fake_run)

    result = support.logic_capture(
        driver="fx2lafw", channels="D0,D1", protocol="uart",
        sample_rate=1_000_000, duration_s=2,
        decoder_options={"baudrate": "115200", "rx": "D0"},
    )

    assert result["ok"] is True
    assert result["decoder"] == "uart:baudrate=115200:rx=D0"
    assert captured[0][:2] == ["sigrok-cli", "-d"]
    assert "-P" in captured[0]
    assert "uart:baudrate=115200:rx=D0" in captured[0]


def test_logic_capture_rejects_decoder_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(support, "has_tool", lambda _name: True)
    result = support.logic_capture(
        driver="fx2lafw", channels="D0", protocol="uart",
        sample_rate=1_000_000, duration_s=1,
        decoder_options={"rx": "D0:evil=1"},
    )
    assert result["ok"] is False
    assert "invalid channel" in result["error"]


def test_usb_debug_probe_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    output = (
        "Bus 001 Device 003: ID 0403:6010 Future Technology Devices International, Ltd FT2232C/D/H\n"
        "Bus 001 Device 004: ID 1a86:7523 QinHeng Electronics CH340 serial converter\n"
        "Bus 001 Device 005: ID 1234:5678 Unknown Gadget\n"
    )
    monkeypatch.setattr(support, "has_tool", lambda name: name == "lsusb")
    monkeypatch.setattr(support, "run", lambda *_a, **_k: _Result(output))

    probes = support.usb_debug_probes()
    assert {p["vid_pid"] for p in probes} == {"0403:6010", "1a86:7523"}
    assert any("JTAG" in p["transports"] for p in probes)


def test_storage_inventory_parses_lsblk_json(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = (
        '{"blockdevices":[{"name":"mmcblk0","size":"29.1G","type":"disk",'
        '"tran":"mmc","model":null,"serial":null,"ro":false,'
        '"children":[{"name":"mmcblk0p1","size":"29G","type":"part",'
        '"tran":null,"model":null,"serial":null,"ro":false}]}]}'
    )
    monkeypatch.setattr(support, "has_tool", lambda name: name == "lsblk")
    monkeypatch.setattr(support, "run", lambda *_a, **_k: _Result(payload))

    devices = support.storage_devices()
    assert [d["name"] for d in devices] == ["mmcblk0", "mmcblk0p1"]
    assert devices[0]["transport"] == "mmc"
