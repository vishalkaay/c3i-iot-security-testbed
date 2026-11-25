"""GATT enumeration + LE security-posture tests.

The flag classifier and UUID labelling are pure and tested directly; the two
modules are exercised through the API with the D-Bus layer monkeypatched to a
canned GATT map, so the finding logic (OPEN read/write, public-address privacy,
services-without-pairing) is verified offline with no adapter.
"""
from __future__ import annotations

import time

from app.plugins.bluetooth import helpers as bh


# --------------------------------------------------------------------------- #
# Pure logic
# --------------------------------------------------------------------------- #
def test_classify_flags_open_vs_protected() -> None:
    assert bh._classify_flags(["read"])["open_read"] is True
    assert bh._classify_flags(["write-without-response"])["open_write"] is True
    enc = bh._classify_flags(["encrypt-authenticated-read"])
    assert enc["open_read"] is False and enc["protected"] is True and enc["readable"] is True
    sw = bh._classify_flags(["secure-write"])
    assert sw["open_write"] is False and sw["writable"] is True and sw["protected"] is True
    # A char that is both open-readable and protected-writable is NOT open-write.
    mix = bh._classify_flags(["read", "encrypt-write"])
    assert mix["open_read"] is True and mix["open_write"] is False


def test_gatt_label_known_and_unknown() -> None:
    assert bh.gatt_label("0000180a-0000-1000-8000-00805f9b34fb") == "Device Information"
    assert bh.gatt_label("00002a19-0000-1000-8000-00805f9b34fb") == "Battery Level"
    assert bh.gatt_label("0000abcd-0000-1000-8000-00805f9b34fb") == ""  # unknown → verbatim


def test_enumerate_gatt_honest_without_dbus() -> None:
    # python-dbus is absent in CI → the helper must report that, not fake a map.
    res = bh.enumerate_gatt("AA:BB:CC:DD:EE:FF")
    assert "_error" in res


def test_read_security_posture_shape() -> None:
    # No adapter/dbus: still returns a well-formed dict (fields may be None).
    sec = bh.read_security_posture("AA:BB:CC:DD:EE:FF")
    assert sec["address"] == "AA:BB:CC:DD:EE:FF"
    assert "privacy" in sec and "paired" in sec


# --------------------------------------------------------------------------- #
# Modules via API (D-Bus layer monkeypatched)
# --------------------------------------------------------------------------- #
def _run(client, auth_headers, action, params, timeout=30):
    r = client.post("/api/v1/jobs", headers=auth_headers,
                    json={"plugin": "bluetooth", "action": action, "params": params})
    assert r.status_code == 201, r.text
    jid = r.json()["id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{jid}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed"):
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_gatt_enum_flags_open_write(monkeypatch, client, auth_headers) -> None:
    canned = {
        "address": "AA:BB:CC:DD:EE:FF",
        "services": [{"path": "/x/s1", "uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                      "label": "Battery Service", "primary": True}],
        "characteristics": [
            {"uuid": "00002a19-0000-1000-8000-00805f9b34fb", "label": "Battery Level",
             "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
             "flags": ["read"], "readable": True, "writable": False, "notify": False,
             "open_read": True, "open_write": False, "protected": False,
             "value_hex": "64", "value_text": "d"},
            {"uuid": "0000ff01-0000-1000-8000-00805f9b34fb", "label": "",
             "service_uuid": "0000ff00-0000-1000-8000-00805f9b34fb",
             "flags": ["write-without-response"], "readable": False, "writable": True,
             "notify": False, "open_read": False, "open_write": True, "protected": False},
        ],
        "stats": {"services": 1, "characteristics": 2, "open_readable": 1, "open_writable": 1},
        "open_reads": [{"uuid": "00002a19-0000-1000-8000-00805f9b34fb", "label": "Battery Level"}],
        "open_writes": [{"uuid": "0000ff01-0000-1000-8000-00805f9b34fb", "label": ""}],
    }
    monkeypatch.setattr(bh, "enumerate_gatt", lambda *a, **k: canned)
    job = _run(client, auth_headers, "gatt_enum", {"address": "AA:BB:CC:DD:EE:FF"})
    assert job["status"] == "succeeded", job
    assert job["result"]["gatt"]["stats"]["open_writable"] == 1
    # a high-severity open-write finding must be raised
    fids = client.get("/api/v1/findings", headers=auth_headers).json()
    assert any(f["category"] == "ble-gatt" and f["severity"] == "high"
               and "offer writes to an unpaired link" in f["title"] for f in fids), fids[:3]


def test_read_rejection_is_classified_as_protected() -> None:
    # BlueZ shows only "read" for a remote characteristic even when the device
    # requires encryption; the failed read is what proves it is protected.
    class _DBusErr(Exception):
        def __init__(self, name: str, msg: str) -> None:
            super().__init__(msg)
            self._name = name

        def get_dbus_name(self) -> str:
            return self._name

    sec = bh.classify_read_failure(_DBusErr("org.bluez.Error.NotAuthorized", "Read not authorized"))
    assert sec == {"read_error": "NotAuthorized", "rejected_for_security": True}
    enc = bh.classify_read_failure(_DBusErr("org.bluez.Error.Failed",
                                            "ATT error: 0x0f Insufficient Encryption"))
    assert enc["rejected_for_security"] is True
    gone = bh.classify_read_failure(_DBusErr("org.freedesktop.DBus.Error.NoReply", "timed out"))
    assert gone["rejected_for_security"] is False


def test_le_security_public_address_flagged(monkeypatch, client, auth_headers) -> None:
    posture = {"address": "AA:BB:CC:DD:EE:FF", "name": "Cam", "paired": False,
               "trusted": False, "connected": False, "address_type": "public",
               "bonded": False, "services_resolved": True, "advertised_services": 3,
               "privacy": "trackable"}
    monkeypatch.setattr(bh, "read_security_posture", lambda *a, **k: posture)
    job = _run(client, auth_headers, "le_security", {"address": "AA:BB:CC:DD:EE:FF"})
    assert job["status"] == "succeeded", job
    assert job["result"]["security_posture"]["privacy"] == "trackable"
    fids = client.get("/api/v1/findings", headers=auth_headers).json()
    cats = {f["category"] for f in fids}
    assert "ble-privacy" in cats  # fixed public address
    assert "ble-pairing" in cats  # services exposed without pairing
