"""End-to-end camera pipeline tests: UART shell -> filesystem extraction.

The ``FakeCamDevice`` emulates a busybox-based IP camera's serial console
(login prompt, /proc/mtd, dd|base64 streaming) well enough to exercise the
whole ``filesystem_dump``/``serial_exec`` path offline — no radio, no copper.
"""
from __future__ import annotations

import base64
import contextlib
import gzip

import pytest


# --------------------------------------------------------------------------- #
# Fake serial device: a tiny finite-state chatbot speaking busybox dialect
# --------------------------------------------------------------------------- #
class FakeCamDevice:
    """Answers what a shell on a camera answers. Echos are suppressed."""

    def __init__(self, rootfs: bytes, *, creds: tuple[str, str] | None = None) -> None:
        self.rootfs = rootfs
        self.creds = creds
        self.login_state = "idle" if creds else "shell"
        self._out = bytearray()

    # --- pyserial-compatible plumbing --- #
    def write(self, data: bytes) -> int:
        parts = data.split(b"\n")
        if data.endswith(b"\n"):
            # A trailing newline is the Enter keystroke: one line, not two.
            parts = parts[:-1]
        for part in parts:
            self._handle(part.rstrip(b"\r").decode("latin-1", errors="replace"))
        return len(data)

    def read(self, n: int = 4096) -> bytes:
        chunk = bytes(self._out[:n])
        del self._out[:n]
        return chunk

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass

    # --- console behaviour --- #
    def _handle(self, line: str) -> None:
        if self.login_state == "shell":
            pass  # fall through to command parsing below
        elif self.login_state == "idle":
            # A getty consumes whatever you type while waiting; but a
            # marker-wrapped shell command must never *leak* /proc/mtd here.
            if "echo C3I_B7F0" in line:
                self._out += b"\nC3I_B7F0\n\nC3I_E243\n"
                return
            self._out += b"\nc3icam login: "
            self.login_state = "user"
            return
        elif self.login_state == "user":
            self._out += b"\nPassword: "
            self.login_state = "pass"
            self._user = line.strip()
            return
        elif self.login_state == "pass":
            pw = line.strip()
            creds = self.creds or ("", "")
            if pw == "" and creds[1] == "" or (self._user, pw) == creds:
                self._out += b"\nroot@c3icam:~# "
                self.login_state = "shell"
            else:
                self._out += b"\nLogin incorrect\nc3icam login: "
                self.login_state = "user"
            return
        if line.startswith("echo C3I_B7F0"):
            self._out += b"\nC3I_B7F0\n"
            if "cat /proc/mtd" in line:
                self._out += (
                    b"dev:    size   erasesize  name\n"
                    b"mtd0: 00040000 00010000 \"u-boot\"\n"
                    b"mtd1: 00020000 00010000 \"u-boot-env\"\n"
                    + f'mtd5: {len(self.rootfs):08x} 00020000 "rootfs"\n'.encode()
                )
            elif "dd if=" in line:
                blob = self.rootfs
                b64 = base64.b64encode(blob).decode()
                for i in range(0, len(b64), 76):
                    self._out += b64[i:i + 76].encode() + b"\n"
            elif "cat /etc" in line:
                self._out += b"C3iCam firmware 2.1.3, reachable only locally\n"
            else:
                self._out += f"sh: {line[:40]}: not found\n".encode()
            self._out += b"C3I_E243\n"
            return
        # unwrapped input on the shell: busybox noise
        self._out += f"sh: {line.strip()[:32]}: not found\n".encode()


def _install(monkeypatch: pytest.MonkeyPatch, device: FakeCamDevice) -> str:
    from app.plugins.hardware import support

    monkeypatch.setattr(support, "open_serial",
                        lambda port, baud: contextlib.nullcontext(device))
    monkeypatch.setattr(support, "resolve_serial_port", lambda: "/dev/fakecam")
    return "/dev/fakecam"


# --------------------------------------------------------------------------- #
# filesystem_dump
# --------------------------------------------------------------------------- #


def _make_engagement(client, auth_headers, targets):
    """Create + authorize an engagement (RoE signed) like the regression suite."""
    r = client.post(
        "/api/v1/engagements", headers=auth_headers,
        json={"name": "cam-uart", "client": "ci"},
    )
    assert r.status_code == 201, r.text
    eng = r.json()
    r = client.post(
        f"/api/v1/engagements/{eng['id']}/authorize", headers=auth_headers,
        json={"signed_by": "Camera Test", "reference": "CAM-1",
              "authorized_targets": targets, "expires_in_days": 3},
    )
    assert r.status_code == 200, r.text
    return eng


ROOTFS = (b"#!/bin/sh\nexport PATH=/bin:/sbin\nBusyBox v1.31.0\n"
          + bytes(range(256)) * 8)  # ~2 KiB with binary texture


def test_filesystem_dump_list_only(monkeypatch, client, auth_headers) -> None:
    dev = FakeCamDevice(ROOTFS, creds=("root", ""))
    _install(monkeypatch, dev)
    eng = _make_engagement(client, auth_headers, ["/dev/fakecam"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "hardware",
              "action": "filesystem_dump", "params": {"list_only": True,
                                                      "username": "root", "password": ""}},
    )
    assert r.status_code == 201, r.text
    job_id = r.json()["id"]
    import time
    deadline = time.time() + 30
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "succeeded", job
    parts = {p["name"] for p in job["result"]["partitions"]}
    assert parts == {"u-boot", "u-boot-env", "rootfs"}


def test_filesystem_dump_recovered_rootfs_matches(monkeypatch, client, auth_headers) -> None:
    dev = FakeCamDevice(ROOTFS, creds=("root", ""))
    _install(monkeypatch, dev)
    eng = _make_engagement(client, auth_headers, ["/dev/fakecam"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "hardware",
              "action": "filesystem_dump", "params": {"partition": "rootfs",
                                                      "username": "root", "password": ""}},
    )
    job_id = r.json()["id"]
    assert r.status_code == 201, r.text
    import time
    deadline = time.time() + 60
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "succeeded", job
    assert job["result"]["outcome"]["ok"] is True
    assert job["result"]["size"] == len(ROOTFS)
    assert job["result"]["sha256"]

    # the runner stores findings in the findings table; this one is critical
    findings = client.get("/api/v1/findings", headers=auth_headers,
                          params={"engagement_id": eng["id"]}).json()
    assert any(f["category"] == "uart-fs" and f["severity"] == "info"
               for f in findings), findings[:3]


def test_serial_exec_version_banner(monkeypatch, client, auth_headers) -> None:
    dev = FakeCamDevice(ROOTFS)  # shell already live, no login
    _install(monkeypatch, dev)
    eng = _make_engagement(client, auth_headers, ["/dev/fakecam"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "hardware",
              "action": "serial_exec",
              "params": {"command": "cat /etc/openwrt_release"}},
    )
    assert r.status_code == 201, r.text
    import time
    job_id = r.json()["id"]
    deadline = time.time() + 30
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "succeeded", job
    assert "C3iCam firmware 2.1.3" in job["result"]["output"]


def test_login_failure_reported_honestly(monkeypatch, client, auth_headers) -> None:
    dev = FakeCamDevice(ROOTFS, creds=("root", "vizxv"))  # real password unknown
    _install(monkeypatch, dev)
    eng = _make_engagement(client, auth_headers, ["/dev/fakecam"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "hardware",
              "action": "filesystem_dump", "params": {"username": "root",
                                                      "password": "wrongpw"}},
    )
    import time
    job_id = r.json()["id"]
    deadline = time.time() + 30
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "succeeded"
    assert "Login failed" in job["message"]


# --------------------------------------------------------------------------- #
# firmware carve: binwalk-free recovery of an unpacked rootfs
# --------------------------------------------------------------------------- #
def _newc_entry(name: str, payload: bytes) -> bytes:
    """Standard SVR4 (newc) cpio record."""
    # Field order: ino, mode, uid, gid, nlink, mtime, filesize,
    # devmajor, devminor, rdevmajor, rdevminor, namesize, check.
    fields = [0, 0o100644, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name) + 1, 0]
    hdr = b"070701" + b"".join(b"%08X" % v for v in fields)
    body = name.encode() + b"\x00"
    body += b"\x00" * ((4 - (len(hdr) + len(body)) % 4) % 4)
    body += payload
    body += b"\x00" * ((4 - (len(hdr) + len(body)) % 4) % 4)
    return hdr + body


def _newc_trailer() -> bytes:
    """Terminating record: namesize field (index 11) = len('TRAILER!!!') + 1."""
    fields = [0] * 11 + [len(b"TRAILER!!!") + 1, 0]
    return b"070701" + b"".join(b"%08X" % v for v in fields) + b"TRAILER!!!\x00"


def test_firmware_carve_recovers_rootfs_and_squashfs(monkeypatch, tmp_path) -> None:
    import lzma

    from app.plugins.firmware import helpers as fh

    rootfs_cpio = (_newc_entry("etc/version", b"C3iCam firmware 2.1.3\n")
                   + _newc_entry("etc/shadow", b"root:$6$rounds$hashhashhash\n")
                   + _newc_trailer()
                   + b"\x00" * 12)
    img = bytearray()
    img += b"\x27\x05\x19\x56" + b"\x00" * 60          # uImage header at 0
    img += gzip.compress(rootfs_cpio, mtime=0)         # cpio.gz rootfs
    off_squash = len(img)
    img += b"hsqs" + b"\x00" * 100                     # squashfs superblock
    img += lzma.compress(b"watchdog module payload " * 40, format=lzma.FORMAT_XZ)
    image = tmp_path / "camera_flash.bin"
    image.write_bytes(bytes(img))

    import app.plugins.tools as tools
    monkeypatch.setattr(tools, "has_tool", lambda n: False)
    monkeypatch.setattr(fh, "has_tool", lambda n: False)

    outdir = tmp_path / "carved"
    result = fh.carve(str(image), str(outdir))

    kinds = [s.description for s in result["signatures"]]
    assert any("uImage" in k for k in kinds)
    assert any("SquashFS" in k for k in kinds)
    assert any(s.offset == off_squash for s in result["signatures"])
    gz_payload = [n for n in result["extracted"] if "gzip" in n and n.endswith(".bin")]
    assert gz_payload
    assert b"C3iCam firmware 2.1.3" in (outdir / gz_payload[0]).read_bytes()
    # the cpio layer inside the gzip must have been recursed into
    carved_files = [n for n in result["extracted"] if "gzip_cpio/" in n]
    assert any(n.endswith("version") for n in carved_files), result["extracted"]
