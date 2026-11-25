"""End-to-end API tests: auth, RBAC, the safety gate, jobs, reports."""

from __future__ import annotations

import io


def test_health(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"


def test_login_required(client):
    assert client.get("/api/v1/system/info").status_code == 401


def test_login_and_me(client, auth_headers):
    me = client.get("/api/v1/auth/me", headers=auth_headers)
    assert me.status_code == 200
    assert me.json()["role"] == "admin"


def test_plugins_manifest(client, auth_headers):
    resp = client.get("/api/v1/plugins", headers=auth_headers)
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()}
    assert {"bluetooth", "wifi", "hardware", "firmware"} <= names
    total_modules = sum(len(p["modules"]) for p in resp.json())
    assert total_modules >= 36


def test_engagement_lifecycle_and_gate(client, auth_headers):
    eng = client.post(
        "/api/v1/engagements", headers=auth_headers,
        json={"name": "Test Engagement", "client": "UnitTest"},
    ).json()
    assert eng["status"] == "draft"

    # Invasive before authorization -> 403 authorization_required.
    before = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "bluetooth", "action": "link_stress",
              "params": {"address": "AA:BB:CC:11:22:33", "packets": 10}},
    )
    assert before.status_code == 403
    assert before.json()["error"] == "authorization_required"

    # Authorize with a scoped RoE.
    auth = client.post(
        f"/api/v1/engagements/{eng['id']}/authorize", headers=auth_headers,
        json={
            "signed_by": "Unit Test",
            "reference": "TEST-1",
            "authorized_targets": ["AA:BB:CC:*", "192.168.50.0/24"],
            "expires_in_days": 5,
        },
    )
    assert auth.status_code == 200
    assert auth.json()["status"] == "authorized"

    # In scope -> accepted.
    inside = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "bluetooth", "action": "link_stress",
              "params": {"address": "AA:BB:CC:99:88:77", "packets": 10}},
    )
    assert inside.status_code == 201

    # Out of scope -> 403.
    outside = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"engagement_id": eng["id"], "plugin": "bluetooth", "action": "link_stress",
              "params": {"address": "DE:AD:BE:EF:00:01", "packets": 10}},
    )
    assert outside.status_code == 403
    assert outside.json()["error"] == "forbidden"


def test_passive_job_runs_and_persists(client, auth_headers):
    # Upload a small firmware blob with an identifiable component + secret.
    blob = b"BusyBox v1.31.0\nOpenSSL 1.0.2k\npassword=\"secret123\"\n" + b"\x00" * 4096
    up = client.post(
        "/api/v1/system/uploads", headers=auth_headers,
        files={"file": ("fw.bin", io.BytesIO(blob), "application/octet-stream")},
    )
    assert up.status_code == 201
    path = up.json()["path"]

    job = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"plugin": "firmware", "action": "secrets", "params": {"path": path}},
    ).json()

    # Wait for the worker thread to finish.
    import time

    for _ in range(40):
        j = client.get(f"/api/v1/jobs/{job['id']}", headers=auth_headers).json()
        if j["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.25)
    assert j["status"] == "succeeded", j.get("error")
    assert "secret" in (j["message"] or "").lower()

    logs = client.get(f"/api/v1/jobs/{job['id']}/logs", headers=auth_headers).json()
    assert any("starting" in ln["message"] for ln in logs)


def test_hardware_status_includes_bench_inventory(client, auth_headers):
    resp = client.get("/api/v1/system/hardware", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert {"debug_probes", "storage_devices", "i2c_buses", "spi_buses",
            "logic_analyzer_available"} <= set(data)
    assert isinstance(data["debug_probes"], list)
    assert isinstance(data["storage_devices"], list)


def test_hardware_info_module_is_safe_without_rig(client, auth_headers):
    job = client.post(
        "/api/v1/jobs", headers=auth_headers,
        json={"plugin": "hardware", "action": "hardware_info", "params": {}},
    ).json()
    import time

    for _ in range(40):
        j = client.get(f"/api/v1/jobs/{job['id']}", headers=auth_headers).json()
        if j["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.25)
    assert j["status"] == "succeeded"
    assert j["result"]["gpio_backend"] == "mock"  # no Pi in CI


def test_reports(client, auth_headers):
    eng = client.post(
        "/api/v1/engagements", headers=auth_headers, json={"name": "Report Test"}
    ).json()
    rep = client.post(
        f"/api/v1/engagements/{eng['id']}/reports", headers=auth_headers, json={"kind": "json"}
    )
    assert rep.status_code == 200
    rid = rep.json()["id"]
    view = client.get(f"/api/v1/reports/{rid}/view", headers=auth_headers)
    assert view.status_code == 200
    assert b"engagement" in view.content
