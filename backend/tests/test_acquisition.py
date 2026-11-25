"""Acquisition tests: complete UART dump-all, live-rootfs tar, host-USB block
imaging, netcat exfil, and adb — the 'complete filesystem extraction' paths.

Everything runs offline: serial consoles are emulated finite-state shells, the
host block device is a monkeypatched ``dd``, and the netcat path uses a real
loopback socket. No radio, no copper, no attached hardware.
"""
from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import io
import re
import socket
import tarfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.plugins.hardware import support

MARK_B = b"C3I_B7F0\n"
MARK_E = b"\nC3I_E243\n"


def _b64_lines(blob: bytes) -> bytes:
    b64 = base64.b64encode(blob)
    return b"".join(b64[i:i + 76] + b"\n" for i in range(0, len(b64), 76))


# --------------------------------------------------------------------------- #
# Emulated consoles
# --------------------------------------------------------------------------- #
class FakeMultiPartCam:
    """busybox console exposing several /proc/mtd partitions, each dd-able."""

    def __init__(self, parts: list[tuple[str, bytes]]) -> None:
        self.parts = parts
        self._out = bytearray()

    def write(self, data: bytes) -> int:
        line = data.decode("latin-1")
        if "C3I_B7F0" not in line:
            return len(data)
        self._out += MARK_B
        if "cat /proc/mtd" in line:
            self._out += b"dev:    size   erasesize  name\n"
            for i, (name, blob) in enumerate(self.parts):
                self._out += f'mtd{i}: {len(blob):08x} 00010000 "{name}"\n'.encode()
        elif "dd if=" in line:
            m = re.search(r"if=/dev/mtd(\d+)", line)
            if m and int(m.group(1)) < len(self.parts):
                self._out += _b64_lines(self.parts[int(m.group(1))][1])
        self._out += MARK_E
        return len(data)

    def read(self, n: int = 4096) -> bytes:
        chunk = bytes(self._out[:n])
        del self._out[:n]
        return chunk

    def flush(self) -> None:  # pragma: no cover - trivial
        pass

    def close(self) -> None:  # pragma: no cover - trivial
        pass


class ScriptedShell(FakeMultiPartCam):
    """Shell that answers a wrapped command containing ``key`` with ``payload``."""

    def __init__(self, responses: dict[str, bytes]) -> None:
        super().__init__([])
        self.responses = responses

    def write(self, data: bytes) -> int:
        line = data.decode("latin-1")
        if "C3I_B7F0" not in line:
            return len(data)
        self._out += MARK_B
        for key, payload in self.responses.items():
            if key in line:
                self._out += payload
                break
        self._out += MARK_E
        return len(data)


def _install(monkeypatch, device) -> str:
    monkeypatch.setattr(support, "open_serial",
                        lambda port, baud: contextlib.nullcontext(device))
    monkeypatch.setattr(support, "resolve_serial_port", lambda: "/dev/fakecam")
    return "/dev/fakecam"


def _make_engagement(client, auth_headers, targets):
    r = client.post("/api/v1/engagements", headers=auth_headers,
                    json={"name": "acq", "client": "ci"})
    assert r.status_code == 201, r.text
    eng = r.json()
    r = client.post(f"/api/v1/engagements/{eng['id']}/authorize", headers=auth_headers,
                    json={"signed_by": "Acq Test", "reference": "ACQ-1",
                          "authorized_targets": targets, "expires_in_days": 3})
    assert r.status_code == 200, r.text
    return eng


def _run(client, auth_headers, eng, action, params, timeout=60):
    r = client.post("/api/v1/jobs", headers=auth_headers,
                    json={"engagement_id": eng["id"], "plugin": "hardware",
                          "action": action, "params": params})
    assert r.status_code == 201, r.text
    job_id = r.json()["id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed"):
            return job
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} did not finish")


# --------------------------------------------------------------------------- #
# A. Complete UART dump-all
# --------------------------------------------------------------------------- #
def test_filesystem_dump_all_partitions(monkeypatch, client, auth_headers) -> None:
    parts = [("u-boot", bytes(range(256)) * 4),
             ("u-boot-env", b"\x00\xff" * 256),
             ("rootfs", bytes(range(256)) * 16)]
    _install(monkeypatch, FakeMultiPartCam(parts))
    eng = _make_engagement(client, auth_headers, ["/dev/fakecam"])
    job = _run(client, auth_headers, eng, "filesystem_dump", {"all_partitions": True})
    assert job["status"] == "succeeded", job
    res = job["result"]
    assert res["mode"] == "all_partitions"
    assert res["partitions_total"] == 3
    assert res["partitions_ok"] == 3, res["manifest"]
    sizes = {m["name"]: m["recovered"] for m in res["manifest"]}
    assert sizes == {"u-boot": 1024, "u-boot-env": 512, "rootfs": 4096}
    # every partition produced a distinct evidence file with a hash
    assert all(m["sha256"] for m in res["manifest"])
    findings = client.get("/api/v1/findings", headers=auth_headers,
                          params={"engagement_id": eng["id"]}).json()
    assert any(f["category"] == "uart-fs" and "Complete flash acquisition" in f["title"]
               for f in findings), findings[:3]


# --------------------------------------------------------------------------- #
# B. Live-rootfs tar (serial transport) + the support roundtrip
# --------------------------------------------------------------------------- #
def _make_targz(members: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue())


def test_serial_tar_archive_roundtrip() -> None:
    targz = _make_targz({"etc/passwd": b"root:x:0:0:root:/root:/bin/sh\n",
                         "etc/shadow": b"root:!::0:::::\n"})
    shell = ScriptedShell({"tar cf -": _b64_lines(targz)})
    res = support.serial_tar_archive(shell, ["/etc"], compression="gzip",
                                     max_bytes=1 << 20, timeout_s=5)
    assert res["ok"], res
    tar_bytes = gzip.decompress(res["payload"])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        names = tf.getnames()
    assert "etc/passwd" in names and "etc/shadow" in names


def test_rootfs_archive_module(monkeypatch, client, auth_headers) -> None:
    targz = _make_targz({"etc/config": b"user=admin\npass=admin\n"})
    _install(monkeypatch, ScriptedShell({"tar cf -": _b64_lines(targz)}))
    eng = _make_engagement(client, auth_headers, ["/dev/fakecam"])
    job = _run(client, auth_headers, eng, "rootfs_archive",
               {"transport": "serial", "compression": "gzip"})
    assert job["status"] == "succeeded", job
    assert job["result"]["size"] == len(targz)
    assert job["result"]["sha256"]
    findings = client.get("/api/v1/findings", headers=auth_headers,
                          params={"engagement_id": eng["id"]}).json()
    assert any(f["category"] == "uart-fs" and "Live filesystem archived" in f["title"]
               for f in findings), findings[:3]


# --------------------------------------------------------------------------- #
# Netcat exfil (real loopback socket)
# --------------------------------------------------------------------------- #
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_net_exfil_receive_roundtrip(tmp_path) -> None:
    payload = bytes(range(256)) * 200  # ~51 KiB
    port = _free_port()
    out = tmp_path / "exfil.bin"

    def trigger() -> None:
        def push() -> None:
            with contextlib.suppress(Exception):
                c = socket.create_connection(("127.0.0.1", port), timeout=5)
                c.sendall(payload)
                c.close()
        threading.Thread(target=push, daemon=True).start()

    res = support.net_exfil_receive(str(out), port=port, timeout_s=10, trigger_cb=trigger)
    assert res["ok"], res
    assert res["bytes"] == len(payload)
    assert out.read_bytes() == payload
    assert res["sha256"] == hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------- #
# C. Host-USB block acquisition
# --------------------------------------------------------------------------- #
def test_host_block_acquire_reads_and_hashes(monkeypatch, tmp_path) -> None:
    content = bytes(range(256)) * 40  # ~10 KiB

    def fake_run(argv, *, timeout=60, **kw):
        of = next(a.split("=", 1)[1] for a in argv if a.startswith("of="))
        Path(of).write_bytes(content)
        return SimpleNamespace(stderr="", returncode=0)

    monkeypatch.setattr(support, "is_block_device", lambda p: True)
    monkeypatch.setattr(support, "host_system_disks", lambda: set())
    monkeypatch.setattr(support, "run", fake_run)
    out = tmp_path / "img.bin"
    res = support.host_block_acquire("/dev/sdz", str(out))
    assert res["ok"]
    assert res["bytes"] == len(content)
    assert res["sha256"] == hashlib.sha256(content).hexdigest()


def test_host_block_acquire_refuses_system_disk(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(support, "is_block_device", lambda p: True)
    monkeypatch.setattr(support, "host_system_disks", lambda: {"/dev/sdz"})
    res = support.host_block_acquire("/dev/sdz", str(tmp_path / "img.bin"))
    assert not res["ok"]
    assert "refusing" in res["error"]


def test_host_block_acquire_rejects_non_block(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(support, "is_block_device", lambda p: False)
    res = support.host_block_acquire("/dev/sdz", str(tmp_path / "img.bin"))
    assert not res["ok"]
    assert "not a block device" in res["error"]


def test_host_block_params_bad_device_rejected() -> None:
    with pytest.raises(ValueError):
        support.host_block_acquire("/etc/passwd", "/tmp/x")  # noqa: S108 - not written


# --------------------------------------------------------------------------- #
# D. ADB
# --------------------------------------------------------------------------- #
def test_adb_archive_success(monkeypatch, tmp_path) -> None:
    tar_bytes = b"ustar-ish-payload" * 64
    monkeypatch.setattr(support, "has_tool", lambda n: True)

    def fake_spawn(argv, out_path, *, timeout_s):
        Path(out_path).write_bytes(tar_bytes)
        return {"ok": True, "returncode": 0, "stderr": ""}

    monkeypatch.setattr(support, "_spawn_to_file", fake_spawn)
    res = support.adb_archive("EMU-1", ["/system"], str(tmp_path / "a.tar"))
    assert res["ok"]
    assert res["bytes"] == len(tar_bytes)
    assert res["sha256"] == hashlib.sha256(tar_bytes).hexdigest()


def test_adb_archive_no_adb(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(support, "has_tool", lambda n: False)
    res = support.adb_archive(None, ["/system"], str(tmp_path / "a.tar"))
    assert not res["ok"]
    assert "not installed" in res["error"]


def test_adb_devices_parsing(monkeypatch) -> None:
    monkeypatch.setattr(support, "has_tool", lambda n: True)
    out = ("List of devices attached\n"
           "EMU-1\tdevice\n"
           "BADCAFE\tunauthorized\n")
    monkeypatch.setattr(support, "run",
                        lambda argv, **kw: SimpleNamespace(stdout=out, stderr="", returncode=0))
    devs = support.adb_devices()
    assert {"serial": "EMU-1", "state": "device"} in devs
    assert {"serial": "BADCAFE", "state": "unauthorized"} in devs
