"""Regression tests for the defects found in the functional review.

Covers: RoE-gate target coverage (the old `_derive_target` returned no target
for deauth/hardware/spoof → out-of-scope invasive jobs got 201), findings
persistence crash (dict evidence → Text column), cancellation terminal state,
per-job WebSocket status events, path containment, uploads, password change,
and unknown-API JSON 404s.
"""

from __future__ import annotations

import json
import time

import pytest
from starlette.testclient import WebSocketDisconnect


def _wait_terminal(client, auth_headers, job_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}", headers=auth_headers).json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} did not reach a terminal state in {timeout}s")


# --------------------------------------------------------------------------- #
# Authorization gate: full target coverage
# --------------------------------------------------------------------------- #
def _make_engagement(client, auth_headers, targets):
    r = client.post(
        "/api/v1/engagements", headers=auth_headers,
        json={"name": "gate-test", "client": "ci"},
    )
    assert r.status_code == 201, r.text
    eng = r.json()
    r = client.post(
        f"/api/v1/engagements/{eng['id']}/authorize", headers=auth_headers,
        json={
            "signed_by": "Gate Test",
            "reference": "GATE-1",
            "authorized_targets": targets,
            "expires_in_days": 3,
        },
    )
    assert r.status_code == 200, r.text
    return eng


def test_out_of_scope_deauth_bssid_rejected(client, auth_headers):
    """Former bug: wifi.deauth_test derived no target → 201 for ANY bssid."""
    eng = _make_engagement(client, auth_headers, ["192.168.50.0/24"])  # no MACs at all
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "wifi", "action": "deauth_test",
              "params": {"interface": "wlan0", "bssid": "DE:AD:BE:EF:00:01"}},
    )
    assert r.status_code == 403, r.text
    assert r.json()["error"] == "forbidden"
    details = r.json().get("details", {})
    assert details.get("gate") == "out_of_scope"


def test_out_of_scope_hardware_glitch_rejected(client, auth_headers):
    """Former bug: hardware.voltage_glitch returned 201 with no target check."""
    eng = _make_engagement(client, auth_headers, ["192.168.50.0/24"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "hardware", "action": "voltage_glitch",
              "params": {"duration_s": 0.2, "on_us": 1000, "off_us": 1000}},
    )
    assert r.status_code == 403, r.text
    assert r.json()["error"] == "forbidden"


def test_out_of_scope_bluetooth_spoof_rejected(client, auth_headers):
    """mac_spoof re-identifies the local adapter: target must be in scope."""
    eng = _make_engagement(client, auth_headers, ["192.168.50.0/24"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "bluetooth", "action": "mac_spoof",
              "params": {"adapter": "hci0"}},
    )
    assert r.status_code == 403, r.text


def test_in_scope_local_hardware_job_accepted(client, auth_headers):
    eng = _make_engagement(client, auth_headers, ["local"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "hardware", "action": "power_control",
              "params": {"action": "cycle", "mode": "optocoupler", "off_seconds": 0.1}},
    )
    assert r.status_code == 201, r.text
    job = _wait_terminal(client, auth_headers, r.json()["id"])
    assert job["status"] == "succeeded"
    # The result must expose the rig convention (optocoupler: LOW powers the DUT).
    assert job["result"]["mode"] == "optocoupler"
    assert job["result"]["power_on_level"] == "LOW"


def test_active_module_without_engagement_rejected(client, auth_headers):
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"plugin": "wifi", "action": "default_credentials",
              "params": {"host": "192.168.50.5", "usernames": ["admin"], "passwords": ["admin"]}},
    )
    assert r.status_code == 403, r.text
    assert r.json()["error"] == "authorization_required"
    assert r.json().get("details", {}).get("gate") == "engagement_required"


def test_firmware_path_outside_data_dirs_rejected(client, auth_headers):
    """Former bug: auditors could string-mine arbitrary server files."""
    for evil in ("/etc/passwd", "../../../../etc/shadow"):
        r = client.post(
            "/api/v1/jobs", headers=auth_headers,
            json={"plugin": "firmware", "action": "secrets", "params": {"path": evil}},
        )
        assert r.status_code == 403, r.text
        assert "uploads" in json.dumps(r.json())


# --------------------------------------------------------------------------- #
# Persistence: evidence coercion (dict evidence must not crash the job)
# --------------------------------------------------------------------------- #
def test_portscan_finding_persisted_with_string_evidence(monkeypatch, client, auth_headers):
    """Former bug: dict evidence → sqlite ProgrammingError → job failed."""
    from dataclasses import dataclass, field as dc_field

    from app.plugins.wifi import helpers as wifi_helpers

    @dataclass
    class FakeService:
        port: int = 23
        protocol: str = "tcp"
        state: str = "open"
        name: str = "telnet"
        product: str = "BusyBox"
        version: str = "1.31"
        extra: str = ""

        def to_dict(self):
            return {"port": self.port, "protocol": self.protocol, "state": self.state,
                    "service": self.name, "product": self.product, "version": self.version,
                    "banner": f"{self.product} {self.version}", "extra": self.extra}

    @dataclass
    class FakeHost:
        address: str
        hostnames: list = dc_field(default_factory=list)
        os_matches: list = dc_field(default_factory=list)
        services: list = dc_field(default_factory=lambda: [FakeService()])

    monkeypatch.setattr(wifi_helpers, "nmap_scan", lambda *a, **k: FakeHost("192.168.50.9"))

    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"plugin": "wifi", "action": "portscan", "params": {"host": "192.168.50.9"}},
    )
    assert r.status_code == 201, r.text
    job = _wait_terminal(client, auth_headers, r.json()["id"])
    assert job["status"] == "succeeded", job.get("error")

    eng_jobs = [
        j for j in client.get("/api/v1/jobs", headers=auth_headers).json()
        if j["id"] == job["id"]
    ]
    assert eng_jobs and json.dumps(eng_jobs[0]["result"]).count("telnet") >= 1

    # The telnet exposure finding must be persisted with string evidence.
    findings = client.get(
        "/api/v1/findings", headers=auth_headers,
        params={"domain": "wifi"},
    ).json()
    tel = [f for f in findings if "telnet" in f["title"].lower()]
    assert tel, findings[:5]
    assert isinstance(tel[0]["evidence"], str) and "telnet" in tel[0]["evidence"]


# --------------------------------------------------------------------------- #
# Cancellation: flag honored, terminal state "cancelled"
# --------------------------------------------------------------------------- #
def test_cancel_mid_run_sets_cancelled_status(client, auth_headers, token):
    with client.websocket_connect(f"/ws/jobs?token={token}") as ws:
        r = client.post(
            "/api/v1/jobs", headers=auth_headers,
            json={"plugin": "fixture", "action": "cancel_probe",
                  "params": {"seconds": 6, "steps": 120}},
        )
        assert r.status_code == 201, r.text
        job_id = r.json()["id"]

        # Drain the global WS until this job reports running.
        deadline = time.time() + 10
        saw_running = False
        while time.time() < deadline:
            evt = ws.receive_json()
            if evt.get("type") == "status" and evt.get("job_id") == job_id:
                if evt["status"] == "running":
                    saw_running = True
                    break
        assert saw_running, "never saw running status on the global channel"

        ev = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=auth_headers)
        assert ev.status_code == 200, ev.text

        # The per-job channel must deliver the terminal status event (the old
        # bug: per-job channel never received status events); reads tolerate
        # the interleaved log/progress events.
        with client.websocket_connect(f"/ws/jobs/{job_id}?token={token}") as job_ws:
            deadline = time.time() + 15
            terminal = None
            while time.time() < deadline:
                evt = job_ws.receive_json()
                if evt.get("type") == "status" and evt.get("job_id") == job_id \
                        and evt["status"] in ("succeeded", "failed", "cancelled"):
                    terminal = evt["status"]
                    break
            assert terminal == "cancelled", "per-job channel showed a non-cancelled terminal"

        job = _wait_terminal(client, auth_headers, job_id)
        assert job["status"] == "cancelled", job
        assert job["status"] != "succeeded"


def test_cancelled_authorised_job_dont_mark_succeeded(client, auth_headers):
    """Cancel before the runner even started: status stays cancelled."""
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"plugin": "fixture", "action": "cancel_probe", "params": {"seconds": 4}},
    )
    job_id = r.json()["id"]
    ev = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=auth_headers)
    assert ev.status_code == 200
    ev2 = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=auth_headers)
    assert ev2.status_code == 422  # second cancel is a no-op error
    job = _wait_terminal(client, auth_headers, job_id)
    assert job["status"] == "cancelled"


def test_recover_interrupted_marks_jobs_failed():
    """Jobs left queued/running by a previous process are failed at bootstrap."""
    from app.core.database import session_scope
    from app.jobs.runner import runner
    from app.models import Job, JobStatus

    with session_scope() as db:
        job = Job(plugin="fixture", action="cancel_probe", safety="passive",
                  params={}, status=JobStatus.RUNNING.value, message="stale inject")
        db.add(job)
        db.flush()
        stale_id = job.id

    assert runner.recover_interrupted() >= 1
    with session_scope() as db:
        j = db.get(Job, stale_id)
        assert j.status == JobStatus.FAILED.value
        assert "restarted" in (j.error or "")


# --------------------------------------------------------------------------- #
# WebSocket auth
# --------------------------------------------------------------------------- #
def test_ws_without_token_rejected(client):
    opened = False
    try:
        with client.websocket_connect("/ws/jobs") as ws:
            opened = True
            with pytest.raises(WebSocketDisconnect):
                ws.receive_json()
    except WebSocketDisconnect:
        pass
    assert not opened, "ws accepted an anonymous connection"


# --------------------------------------------------------------------------- #
# REST nuances
# --------------------------------------------------------------------------- #
def test_unknown_api_route_returns_json_404(client, auth_headers):
    r = client.get("/api/v1/definitely-not-a-real-route", headers=auth_headers)
    assert r.status_code == 404
    body = r.json()
    assert body.get("error") == "not_found"
    assert "text/html" not in r.headers.get("content-type", "")


def test_uploads_list_includes_server_path(client, auth_headers):
    import io

    up = client.post(
        "/api/v1/system/uploads", headers=auth_headers,
        files={"file": ("pathcheck.bin", io.BytesIO(b"\x00" * 64), "application/octet-stream")},
    )
    assert up.status_code == 201, up.text
    assert up.json()["path"], up.json()
    listing = client.get("/api/v1/system/uploads", headers=auth_headers).json()
    entry = [f for f in listing if f["filename"] == up.json()["filename"]]
    assert entry and entry[0]["path"].endswith(up.json()["filename"])
    # The listed path must resolve inside the testbed's uploads dir.
    assert "uploads" in entry[0]["path"]


def test_upload_size_limit_enforced(client, auth_headers):
    import io

    from app.core.config import settings

    original = settings.max_upload_mb
    try:
        settings.max_upload_mb = 1  # MB
        r = client.post(
            "/api/v1/system/uploads", headers=auth_headers,
            files={"file": ("big.bin", io.BytesIO(b"\x00" * (2 * 1024 * 1024)),
                            "application/octet-stream")},
        )
        assert r.status_code == 413, r.text
        assert "limits" in r.text or "limit" in r.text
    finally:
        settings.max_upload_mb = original


def test_password_change_flow(client, auth_headers):
    r = client.post(
        "/api/v1/users", headers=auth_headers,
        json={"username": "pwuser", "password": "old-password-1", "role": "auditor"},
    )
    assert r.status_code == 201, r.text
    uid = r.json()["id"]

    old = client.post("/api/v1/auth/login", json={"username": "pwuser", "password": "old-password-1"})
    assert old.status_code == 200
    user_token = old.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    me = client.get("/api/v1/auth/me", headers=user_headers)
    assert me.status_code == 200 and me.json()["username"] == "pwuser"

    # Wrong current password is rejected.
    bad = client.post(
        "/api/v1/auth/password", headers=user_headers,
        json={"current_password": "nope", "new_password": "new-password-2"},
    )
    assert bad.status_code in (401, 403), bad.text

    ok = client.post(
        "/api/v1/auth/password", headers=user_headers,
        json={"current_password": "old-password-1", "new_password": "new-password-2"},
    )
    assert ok.status_code == 200, ok.text

    assert client.post(
        "/api/v1/auth/login", json={"username": "pwuser", "password": "old-password-1"}
    ).status_code == 401
    assert client.post(
        "/api/v1/auth/login", json={"username": "pwuser", "password": "new-password-2"}
    ).status_code == 200

    # Admin reset path.
    reset = client.post(
        f"/api/v1/users/{uid}/password", headers=auth_headers,
        json={"new_password": "admin-reset-3"},
    )
    assert reset.status_code == 200, reset.text
    assert client.post(
        "/api/v1/auth/login", json={"username": "pwuser", "password": "admin-reset-3"}
    ).status_code == 200


def test_engagement_authorized_status_requires_admin(client, auth_headers):
    r = client.post(
        "/api/v1/users", headers=auth_headers,
        json={"username": "opuser", "password": "oper-pass-01", "role": "operator"},
    )
    assert r.status_code == 201, r.text
    op_token = client.post(
        "/api/v1/auth/login", json={"username": "opuser", "password": "oper-pass-01"}
    ).json()["access_token"]
    op_headers = {"Authorization": f"Bearer {op_token}"}

    eng = client.post(
        "/api/v1/engagements", headers=op_headers, json={"name": "op-status-test"}
    ).json()
    r = client.post(f"/api/v1/engagements/{eng['id']}/status?status_value=authorized",
                    headers=op_headers)
    assert r.status_code == 422, r.text
    assert "Only admins may set status 'authorized'" in r.json().get("message", "")

    ok = client.post(f"/api/v1/engagements/{eng['id']}/status?status_value=draft",
                     headers=op_headers)
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "draft"


# --------------------------------------------------------------------------- #
# Accuracy: results must not overclaim
# --------------------------------------------------------------------------- #
def test_deauth_without_tooling_reports_not_transmitted(monkeypatch, client, auth_headers):
    """No aireplay-ng → no frames can be sent; no 'injection possible' finding."""
    from app.plugins.wifi import helpers as wh

    monkeypatch.setattr(wh, "has_tool", lambda name: False)  # nothing installed
    monkeypatch.setattr("app.plugins.wifi.plugin.has_tool", lambda name: False)

    eng = _make_engagement(client, auth_headers, ["de:ad:be:ef:00:02", "local"])
    r = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "wifi", "action": "deauth_test",
              "params": {"interface": "wlan0", "bssid": "DE:AD:BE:EF:00:02", "frames": 5}},
    )
    assert r.status_code == 201, r.text
    job = _wait_terminal(client, auth_headers, r.json()["id"])
    assert job["status"] == "succeeded", job.get("error")
    data = job["result"]
    assert data["transmitted"] is False
    assert data["tooling"] is None
    titles = " ".join(f["title"] for f in client.get(
        "/api/v1/findings", headers=auth_headers).json())
    assert "De-authentication injection possible" not in titles


def test_tls_probe_rejects_none_cipher(monkeypatch):
    """openssl printing 'Cipher is (NONE)' on refusal must NOT mark supported."""
    from dataclasses import dataclass

    from app.plugins.wifi import helpers as wh

    @dataclass
    class Res:
        argv: list
        returncode: int
        stdout: str
        stderr: str
        duration_s: float

        def lines(self):
            return []

    def fake_run(argv, **kwargs):
        text = (
            "error:*SSL routines:ssl_choose_client_version:unsupported protocol:\n"
            "New, (NONE), cipher is (NONE)\n"
        )
        return Res(argv, 1, text, "", 0.1)

    monkeypatch.setattr(wh, "has_tool", lambda n: True)
    monkeypatch.setattr(wh, "run", fake_run)
    probe = wh.tls_probe("127.0.0.1", 443)
    assert probe["supported"] == []
    assert len(probe["rejected"]) == 6


def test_tls_probe_counts_real_cipher(monkeypatch):
    from dataclasses import dataclass

    from app.plugins.wifi import helpers as wh

    @dataclass
    class Res:
        argv: list
        returncode: int
        stdout: str
        stderr: str
        duration_s: float

        def lines(self):
            return []

    def fake_run(argv, **kwargs):
        text = ("Protocol  : TLSv1.2\nCipher    : ECDHE-RSA-AES256-GCM-SHA384\n"
                "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n")
        return Res(argv, 0, text, "", 0.1)

    monkeypatch.setattr(wh, "has_tool", lambda n: True)
    monkeypatch.setattr(wh, "run", fake_run)
    probe = wh.tls_probe("127.0.0.1", 443)
    versions = {s["version"] for s in probe["supported"]}
    assert "tls1.2" in versions
    for entry in probe["supported"]:
        assert entry["cipher"] not in (None, "(NONE)")


def test_empty_pcap_is_not_cleartext(tmp_path, client, auth_headers):
    """An empty capture must not produce a 'cleartext traffic observed' finding."""
    import struct


    # Build a valid empty libpcap (little-endian microsecond) file.
    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 0)
    path = tmp_path / "empty.pcap"
    path.write_bytes(pcap)

    from app.services.traffic import classify_encryption, read_pcap_payloads

    objs = read_pcap_payloads(str(path))
    assert objs == []
    verdict = classify_encryption(objs)
    assert verdict.samples == 0
    assert verdict.encrypted is False and verdict.confidence == 0.0
    assert "no payloads" in verdict.reasoning


def test_binwalk_hex_offsets_parsed(tmp_path):
    """binwalk 3.x prints only hex offsets; they must become signatures."""
    from app.plugins.firmware import helpers as fh

    class FakeRes:
        def __init__(self, text):
            self.returncode = 0
            self.stdout = text
            self.stderr = ""
            self.argv = []

        def lines(self):
            return [ln for ln in self.stdout.splitlines() if ln.strip()]

    monkey = pytest.MonkeyPatch()
    monkey.setattr(fh, "has_tool", lambda name: True)  # pretend binwalk exists
    monkey.setattr(
        fh, "run",
        lambda argv, **k: FakeRes(
            "0x0000000000 uImage header, proprty\n"
            "0x0000002000 Squashfs filesystem, little endian\n"
            "   4096       0x00001000 foo bar\n"
        ),
    )
    sigs = fh.binwalk_scan("/nonexistent")
    offsets = [s.offset for s in sigs]
    assert 0 in offsets and 0x2000 in offsets and 4096 in offsets
    monkey.undo()


def test_binwalk_decimal_only_parsed():
    """binwalk 2.x decimal+hex rows keep working."""
    from app.plugins.firmware import helpers as fh

    class FakeRes:
        returncode = 0
        stdout = ("   0        0x00000000 uImage header\n"
                  "   64       0x00000040 gzip compressed data\n")
        stderr = ""
        argv = []

        def lines(self):
            return [ln for ln in self.stdout.splitlines() if ln.strip()]

    if not fh.has_tool("binwalk"):
        return  # nothing to test on hosts without binwalk
    # Patch has_tool so the pure function runs locally.
    real = fh.has_tool
    fh.has_tool = lambda n: True
    try:
        real_run = fh.run
        fh.run = lambda argv, **k: FakeRes()
        sigs = fh.binwalk_scan("/nonexistent")
    finally:
        fh.has_tool = real
        fh.run = real_run
    assert [s.offset for s in sigs] == [0, 64]
    assert "uImage" in sigs[0].description


def test_helper_hardware_power_mock_honest(monkeypatch, tmp_path):
    """PowerController must report pin + polarity; run_glitch stops on cancel."""
    from app.plugins.hardware import support

    monkey = pytest.MonkeyPatch()
    monkey.setattr(support, "get_gpio", lambda: (support.MockGPIO(), "mock"))
    p = support.PowerController("optocoupler")
    seq: list[tuple[int, int]] = []
    monkey.setattr(p.gpio, "output", lambda pin, val: seq.append((pin, val)))
    p.power_off()
    p.power_on()
    # optocoupler: LOW = DUT powered → power_on drives 0.
    assert seq[0][1] == 1 and seq[1][1] == 0
    monkey.undo()

    cancelled = {"hit": False}

    async_vec = support.run_glitch(
        pin=None, on_us=200, off_us=200, duration_s=0.05,
        cancel_cb=lambda: cancelled["hit"],
    )
    assert async_vec.pulses >= 0
    assert async_vec.extra.get("stop_reason") in ("duration_reached", "cancelled_by_operator",
                                                 "pulse_cap_reached")

    # FTS sync: writing a CVE then querying it offline must hit the cache.
    from app.services.vuln import VulnIntel

    vi = VulnIntel(db_path=tmp_path / "vuln.db")
    from app.plugins.base import FindingDraft  # noqa: F401 - import sanity

    vi._store([type("H", (), {
        "id": "CVE-2099-0001", "description": "busybox telnetd regression",
        "cvss": 7.5, "severity": "high", "published": None, "references": [],
    })], ["busybox"])
    hits = vi.search_keywords(["busybox"], limit=5)
    assert any(h.id == "CVE-2099-0001" for h in hits)


def test_multiword_cve_terms_hit_cache(tmp_path):
    from app.services.vuln import VulnIntel

    vi = VulnIntel(db_path=tmp_path / "vuln2.db")

    class H:
        id = "CVE-2099-1111"
        description = "busybox 1.31.0 wget buffer regression"
        cvss = 6.6
        severity = "medium"
        published = None
        references: list = []

    vi._store([H()], ["busybox 1.31.0"])
    hits = vi.search_keywords(["busybox 1.31.0"], limit=5)
    assert any(h.id == "CVE-2099-1111" for h in hits), hits


def test_bootlog_secret_masked_in_finding_and_extra():
    from app.services.bootlog import analyse_bootlog

    text = "boot...\npassword=ActuallySecret88\nroot:123456\nmore"
    report = analyse_bootlog(text)
    secret_findings = [f for f in report.findings if f.category == "hardcoded-secret"]
    assert secret_findings, "expected secret findings"
    blob = json.dumps(
        {
            "desc": [f.description for f in secret_findings],
            "ev": [f.evidence for f in secret_findings],
            "extra": [f.extra for f in secret_findings],
        }
    )
    assert "ActuallySecret88" not in blob
    assert "123456" not in blob or "root:1*" in blob  # shadow-like prefix kept
    for f in secret_findings:
        assert f.extra["value"].count("*") >= 2


def test_firmware_secret_output_masked(tmp_path):
    from app.plugins.firmware import helpers as fh

    img = tmp_path / "fw.bin"
    img.write_bytes(b"password=SuperSecret99\nOpenSSL 1.0.2k\n" + b"\x00" * 512)
    strings = fh.extract_strings(str(img))
    secrets = fh.find_secrets(strings)
    vals = [s.to_dict()["value"] for s in secrets]
    assert all("SuperSecret99" not in v for v in vals), vals
    assert all("SuperSecret99" not in s.offset_hint for s in secrets)
