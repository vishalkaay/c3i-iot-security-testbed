"""Acquisition integrity, real archive formats, and loopback lab regression checks."""
import base64
import gzip
import hashlib
import io
from pathlib import Path
import runpy
import socket
import tarfile
import threading
import time
import zipfile

import pytest

from app.plugins.firmware import helpers as firmware
from app.plugins.hardware import support

ROOT = Path(__file__).resolve().parents[2]


def wait_job(client, auth_headers, job_id):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            assert job["status"] == "succeeded", job
            return job
        time.sleep(0.05)
    pytest.fail("job did not finish")


@pytest.mark.parametrize("payload", [b"a", b"ab", bytes(range(256))])
def test_uart_echo_and_base64_padding(monkeypatch, payload):
    # Shell echo contains both markers before any output, and arrives separately.
    reads = iter([b"", b"echo C3I_B7F0; dd if=/dev/mtd0 | base64; echo C3I_E243\r\n",
                  b"C3I_B7F0\r\n", base64.b64encode(payload) + b"\r\nC3I_E243\r\n"])
    monkeypatch.setattr(support, "read_serial_from", lambda *a, **k: next(reads, b""))
    monkeypatch.setattr(support, "write_serial_to", lambda *a: True)
    result = support.serial_dump_mtd(object(), "/dev/mtd0", len(payload), timeout_s=1)
    assert result["ok"] and result["payload"] == payload


@pytest.mark.parametrize("output,expected_size", [(b"YWJj\n", 4), (b"YWJj\nkernel: log noise!\n", 3)])
def test_uart_corruption_never_reports_complete(monkeypatch, output, expected_size):
    reads = iter([b"", b"C3I_B7F0\n" + output + b"C3I_E243\n"])
    monkeypatch.setattr(support, "read_serial_from", lambda *a, **k: next(reads, b""))
    monkeypatch.setattr(support, "write_serial_to", lambda *a: True)
    result = support.serial_dump_mtd(object(), "/dev/mtd0", expected_size, timeout_s=1)
    assert result["ok"] is False and result["error"]


def test_uart_cancel_retains_partial_bytes(monkeypatch):
    reads = iter([b"", b"C3I_B7F0\nYWJj\n"])
    read_count = 0
    def read(*args, **kwargs):
        nonlocal read_count
        read_count += 1
        return next(reads, b"")
    monkeypatch.setattr(support, "read_serial_from", read)
    monkeypatch.setattr(support, "write_serial_to", lambda *a: True)
    result = support.serial_dump_mtd(object(), "/dev/mtd0", 6, cancel_cb=lambda: read_count >= 2)
    assert not result["ok"] and result["partial"] and result["payload"] == b"abc"


def test_explicit_uart_port_is_scoped(monkeypatch, client, auth_headers):
    monkeypatch.setattr(support, "resolve_serial_port", lambda: "/dev/allowed")
    eng = client.post("/api/v1/engagements", headers=auth_headers, json={"name": "UART gate"}).json()
    auth = client.post(f"/api/v1/engagements/{eng['id']}/authorize", headers=auth_headers,
                       json={"signed_by": "Test", "reference": "LAB", "authorized_targets": ["/dev/allowed"]})
    assert auth.status_code == 200
    response = client.post("/api/v1/jobs", headers=auth_headers, json={
        "engagement_id": eng["id"], "plugin": "hardware", "action": "filesystem_dump",
        "params": {"port": "/dev/out-of-scope", "list_only": True}})
    assert response.status_code == 403


def test_lab_image_roundtrip_and_api_evidence(monkeypatch, tmp_path, client, auth_headers):
    kit = runpy.run_path(str(ROOT / "lab/make_firmware.py"))
    manifest = kit["build"](tmp_path)
    image = tmp_path / "c3i-camera-lab.bin"
    assert hashlib.sha256(image.read_bytes()).hexdigest() == manifest["files"][image.name]["sha256"]
    monkeypatch.setattr(firmware, "has_tool", lambda name: False)
    monkeypatch.setattr("app.plugins.firmware.plugin.has_tool", lambda name: False)
    carved = firmware.carve(str(image), str(tmp_path / "out"))
    assert not carved["notes"], carved["notes"]
    for name, digest in manifest["rootfs_files"].items():
        recovered = tmp_path / "out/off_00000040_gzip_cpio" / name
        assert hashlib.sha256(recovered.read_bytes()).hexdigest() == digest
    assert any(s.offset == 262144 and "tar" in s.description for s in carved["signatures"])
    strings = firmware.extract_strings(str(image))
    assert {c.name for c in firmware.find_components(strings)} == set(manifest["expected_components"])
    assert set(manifest["expected_secret_rules"]) <= {s.kind for s in firmware.find_secrets(strings)}

    up = client.post("/api/v1/system/uploads", headers=auth_headers,
                     files={"file": (image.name, image.read_bytes(), "application/octet-stream")})
    assert up.status_code in (200, 201), up.text
    job = client.post("/api/v1/jobs", headers=auth_headers, json={
        "plugin": "firmware", "action": "extract", "params": {"path": up.json()["path"]}})
    assert job.status_code == 201, job.text
    job_id = job.json()["id"]
    result = wait_job(client, auth_headers, job_id)["result"]
    assert result["ok"] and result["signatures"][0]["offset"] == 64
    evidence = client.get(f"/api/v1/jobs/{job_id}/evidence", headers=auth_headers).json()
    download = client.get(f"/api/v1/jobs/{job_id}/evidence/{evidence[0]['id']}/download", headers=auth_headers)
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        assert archive.read("off_00000040_gzip_cpio/etc/camera.conf") == kit["FILES"]["etc/camera.conf"]


def test_carve_preserves_paths_and_rejects_traversal(tmp_path):
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in [("etc/config", b"one"), ("usr/config", b"two"), ("../../escape", b"bad")]:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    image = tmp_path / "test.tar"
    image.write_bytes(blob.getvalue())
    result = firmware.carve(str(image), str(tmp_path / "out"))
    assert (tmp_path / "out/off_00000000_tar/etc/config").read_bytes() == b"one"
    assert (tmp_path / "out/off_00000000_tar/usr/config").read_bytes() == b"two"
    assert not (tmp_path / "escape").exists()
    assert result["notes"]


def test_carve_rejects_truncated_and_expanding_streams(monkeypatch, tmp_path):
    monkeypatch.setattr(firmware, "_MAX_PAYLOAD", 1024)
    image = tmp_path / "test.bin"
    for payload in [gzip.compress(b"hello")[:-8], gzip.compress(b"a" * 10000)]:
        image.write_bytes(payload)
        result = firmware.carve(str(image), str(tmp_path / "out"))
        assert not result["extracted"] and result["notes"]


def test_loopback_simulator_auth_boundary():
    from app.plugins.wifi.helpers import http_basic_probe
    simulator = runpy.run_path(str(ROOT / "lab/network_simulator.py"))
    server = simulator["ThreadingHTTPServer"](("127.0.0.1", 0), simulator["CameraHandler"])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        hit = http_basic_probe("127.0.0.1", server.server_port, "admin", "admin")
        miss = http_basic_probe("127.0.0.1", server.server_port, "admin", "wrong")
        assert hit["ok"] and hit["baseline_status"] == 401
        assert not miss["ok"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def test_loopback_banner_and_mqtt_services():
    simulator = runpy.run_path(str(ROOT / "lab/network_simulator.py"))
    banner_server = simulator["BannerServer"](
        ("127.0.0.1", 0), simulator["BannerHandler"],
        banner=b"SSH-2.0-C3iLabTest\r\n", kind="ssh")
    thread = _serve(banner_server)
    try:
        with socket.create_connection(banner_server.server_address, timeout=2) as client:
            client.settimeout(2)
            assert client.recv(64) == b"SSH-2.0-C3iLabTest\r\n"
    finally:
        banner_server.shutdown()
        banner_server.server_close()
        thread.join(2)

    mqtt_server = simulator["BannerServer"](
        ("127.0.0.1", 0), simulator["BannerHandler"], kind="mqtt")
    thread = _serve(mqtt_server)
    try:
        with socket.create_connection(mqtt_server.server_address, timeout=2) as client:
            client.settimeout(2)
            client.sendall(b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00")
            assert client.recv(4) == b"\x20\x02\x00\x00"
            client.sendall(b"\x82\x06\x00\x01\x00\x01#\x00")
            received = b""
            while b"camera/telemetry" not in received:
                received += client.recv(256)
            assert b"lab" in received
            client.sendall(b"\xe0\x00")
    finally:
        mqtt_server.shutdown()
        mqtt_server.server_close()
        thread.join(2)


def test_loopback_ftp_and_telnet_services():
    simulator = runpy.run_path(str(ROOT / "lab/network_simulator.py"))

    def read_until(stream, marker):
        data = b""
        while marker not in data:
            chunk = stream.read(1)
            if not chunk:
                break
            data += chunk
        return data

    ftp_server = simulator["BannerServer"](
        ("127.0.0.1", 0), simulator["BannerHandler"],
        banner=b"220 (vsFTPd 3.0.3)\r\n", kind="ftp")
    telnet_server = simulator["BannerServer"](
        ("127.0.0.1", 0), simulator["BannerHandler"],
        banner=b"\r\nC3i camera lab console\r\n", kind="telnet")
    ftp_thread = _serve(ftp_server)
    telnet_thread = _serve(telnet_server)
    try:
        with socket.create_connection(ftp_server.server_address, timeout=2) as client:
            client.settimeout(2)
            stream = client.makefile("rwb")
            assert stream.readline().startswith(b"220 ")
            stream.write(b"USER lab\r\n")
            stream.flush()
            assert stream.readline().startswith(b"331 ")
            stream.write(b"PASS lab\r\n")
            stream.flush()
            assert stream.readline().startswith(b"230 ")
            stream.write(b"QUIT\r\n")
            stream.flush()
            assert stream.readline().startswith(b"221 ")
            stream.close()

        with socket.create_connection(telnet_server.server_address, timeout=2) as client:
            client.settimeout(2)
            stream = client.makefile("rwb")
            assert stream.readline() == b"\r\n"
            assert b"C3i camera lab console" in stream.readline()
            assert read_until(stream, b"login: ").endswith(b"login: ")
            stream.write(b"root\r\n")
            stream.flush()
            assert read_until(stream, b"Password: ").endswith(b"Password: ")
            stream.write(b"lab\r\n")
            stream.flush()
            assert b"BusyBox" in read_until(stream, b"BusyBox")
            stream.close()
    finally:
        for server, thread in ((ftp_server, ftp_thread), (telnet_server, telnet_thread)):
            server.shutdown()
            server.server_close()
            thread.join(2)
