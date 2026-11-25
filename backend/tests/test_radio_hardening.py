"""Regressions for defects found by running the Wi-Fi/Bluetooth modules against
the loopback simulator and real radios (BlueZ 5.87, iw 6.x)."""

from __future__ import annotations

import socket
import threading

import pytest

from app.core.errors import CapabilityUnavailable
from app.plugins.bluetooth import helpers as bh
from app.plugins.wifi import helpers as wh

IW_SCAN = """\
BSS aa:bb:cc:00:00:01(on wlan0) -- associated
\tfreq: 5540.0
\tcapability: ESS Privacy SpectrumMgmt (0x1111)
\tsignal: -52.00 dBm
\tSSID: corp-ent
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: IEEE 802.1X IEEE 802.1X/SHA-256
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC MFP-capable (0x008c)
BSS aa:bb:cc:00:00:02(on wlan0)
\tfreq: 2437
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -70.00 dBm
\tSSID: home-psk
\tDS Parameter set: channel 6
\tWPA:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP CCMP
\t\t * Authentication suites: PSK
\tRSN:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: CCMP TKIP
\t\t * Authentication suites: PSK
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
\tWPS:\t * Version: 1.0
\t\t * Wi-Fi Protected Setup State: 2 (Configured)
BSS aa:bb:cc:00:00:03(on wlan0)
\tfreq: 2412
\tcapability: ESS Privacy (0x0011)
\tsignal: -80.00 dBm
\tSSID: old-wep
BSS aa:bb:cc:00:00:04(on wlan0)
\tfreq: 2462
\tcapability: ESS (0x0001)
\tsignal: -60.00 dBm
\tSSID: cafe-open
BSS aa:bb:cc:00:00:05(on wlan0)
\tfreq: 5180
\tcapability: ESS Privacy (0x0011)
\tsignal: -61.00 dBm
\tSSID: \\x00\\x00\\x00
\tRSN:\t * Version: 1
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC MFP-required MFP-capable (0x00cc)
"""


def test_iw_scan_parser_derives_real_security_attributes() -> None:
    aps = {a.bssid[-2:]: a for a in wh.parse_iw_scan(IW_SCAN)}
    assert aps["01"].encryption == "WPA2/3-Enterprise" and aps["01"].pmf == "capable"
    assert aps["01"].channel == 108
    assert aps["02"].encryption == "WPA/WPA2-mixed" and "TKIP" in aps["02"].ciphers
    assert aps["02"].wps and aps["02"].pmf == "disabled" and aps["02"].channel == 6
    assert aps["03"].encryption == "WEP"
    assert aps["04"].encryption == "open" and not aps["04"].wps
    assert aps["05"].encryption == "WPA3-SAE" and aps["05"].pmf == "required"
    assert aps["05"].hidden and aps["05"].ssid == "<hidden>"


class _Res:
    def __init__(self, rc: int, out: str = "", err: str = "") -> None:
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_survey_without_privilege_is_never_a_clean_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wh, "has_tool", lambda _n: True)
    monkeypatch.setattr(wh, "run", lambda argv, **_k: _Res(255, "", "Operation not permitted (-1)"))
    with pytest.raises(CapabilityUnavailable):
        wh.wireless_survey("wlan0")

    def cached(argv, **_k):
        return _Res(0, IW_SCAN) if argv[-1] == "dump" else _Res(255, "", "Operation not permitted")

    monkeypatch.setattr(wh, "run", cached)
    aps, meta = wh.wireless_survey("wlan0")
    assert len(aps) == 5 and meta["complete"] is False and "cached" in meta["source"]


def test_tls11_is_classified_weak() -> None:
    # tls_probe() emits "tls1.1"; the weak set used to say "tls1_1" (never matched).
    assert {"tls1", "tls1.1"} <= wh.WEAK_PROTOCOLS


def _serve_once(payload: bytes, *, expect: bytes | None = None, reply: bytes = b"") -> int:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def loop() -> None:
        srv.settimeout(5)
        try:
            while True:
                conn, _ = srv.accept()
                with conn:
                    conn.settimeout(1)
                    if payload:
                        conn.sendall(payload)
                    try:
                        data = conn.recv(256)
                    except OSError:
                        data = b""
                    if expect and data.startswith(expect):
                        conn.sendall(reply)
        except OSError:
            srv.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


def test_identify_service_classifies_unlabelled_ports() -> None:
    telnet = _serve_once(b"\r\ncamera console\r\nlogin: ")
    assert wh.identify_service("127.0.0.1", telnet, timeout=1)["service"] == "telnet"
    ssh = _serve_once(b"SSH-2.0-dropbear_2019.78\r\n")
    assert wh.identify_service("127.0.0.1", ssh, timeout=1)["service"] == "ssh"
    mqtt = _serve_once(b"", expect=b"\x10", reply=b"\x20\x02\x00\x00")
    assert wh.identify_service("127.0.0.1", mqtt, timeout=1)["service"] == "mqtt"
    silent = _serve_once(b"")
    assert wh.identify_service("127.0.0.1", silent, timeout=1) == {}


def test_mqtt_probe_distinguishes_refused_from_anonymous() -> None:
    refused = _serve_once(b"", expect=b"\x10", reply=b"\x20\x02\x00\x05")
    out = wh.mqtt_anonymous_probe("127.0.0.1", refused, seconds=1, timeout=2)
    assert out["reachable"] and out["connack"] == 5 and not out["anonymous"]
    topics: list[str] = []
    pub = b"\x30\x0a\x00\x03a/bhello"
    assert wh._mqtt_drain(b"\x90\x03\x00\x01\x00" + pub + pub[:4], topics) == pub[:4]
    assert topics == ["a/b"]


# ------------------------------- Bluetooth -------------------------------- #
BT_SCAN = """\
SetDiscoveryFilter success
Discovery started
[CHG] Controller 00:11:22:33:44:55 Discovering: yes
[NEW] Device 11:22:33:44:55:66 11-22-33-44-55-66
[CHG] Device 11:22:33:44:55:66 RSSI: 0xffffffd8 (-40)
[CHG] Device 11:22:33:44:55:66 ManufacturerData.Key: 0x004c (76)
[CHG] Device 11:22:33:44:55:66 ManufacturerData.Value:
  10 06 4c 1d 15 44 78 68                          ..L..Dxh
[NEW] Device AA:AA:AA:AA:AA:01 LAPTOP-H041SFCK
[CHG] Device AA:AA:AA:AA:AA:02 RSSI: 0xffffffa6 (-90)
[CHG] Device AA:AA:AA:AA:AA:02 TxPower: 0x000c (12)
[CHG] Device AA:AA:AA:AA:AA:02 Name: Sensor-7
[CHG] Device AA:AA:AA:AA:AA:02 Alias: Sensor-7
"""


def test_scan_parser_handles_placeholder_names_and_attribute_lines() -> None:
    devs = {d.address: d for d in bh.parse_scan_output(BT_SCAN.splitlines())}
    anon = devs["11:22:33:44:55:66"]
    assert anon.name == "" and anon.rssi == -40          # dashed MAC is not a name
    assert anon.manufacturer == "Apple" and "004c" in anon.manufacturer_data
    assert devs["AA:AA:AA:AA:AA:01"].name == "LAPTOP-H041SFCK"
    s7 = devs["AA:AA:AA:AA:AA:02"]
    assert s7.name == "Sensor-7" and s7.rssi == -90 and s7.tx_power == 12
    assert "00:11:22:33:44:55" not in devs               # the controller is not a device


def test_scan_fails_loudly_without_a_powered_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bh, "has_tool", lambda _n: True)
    monkeypatch.setattr(bh, "run", lambda argv, **_k: _Res(0, "No default controller available\n"))
    with pytest.raises(CapabilityUnavailable):
        bh.scan(5)
