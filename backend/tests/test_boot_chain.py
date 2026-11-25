"""Static secure-boot / debug-lock audit regressions."""

from __future__ import annotations

from app.plugins.firmware import helpers


def test_boot_chain_detects_controls_and_debug_risk() -> None:
    audit = helpers.audit_boot_chain([
        "U-Boot 2024.01",
        "FIT_SIGNATURE=y verify=required",
        "anti-rollback version counter",
        "efuse root of trust",
        "init=/bin/sh",
    ])

    rules = {i["rule"] for i in audit["indicators"]}
    assert {"signed-image", "rollback", "root-of-trust", "debug-console"} <= rules
    assert audit["score"] >= 3
    assert audit["confidence"] == "low"
    assert any(f["title"].startswith("Boot-chain risk") for f in audit["findings"])
    assert "hardware" in audit["note"]


def test_boot_chain_reports_gaps_without_claiming_absence() -> None:
    audit = helpers.audit_boot_chain(["BusyBox v1.31.0"])

    assert audit["score"] == 0
    assert "signed boot image verification not evidenced" in audit["gaps"]
    assert "anti-rollback/version-counter references not evidenced" in audit["gaps"]
    titles = {f["title"] for f in audit["findings"]}
    assert "No signed-boot evidence found in firmware strings" in titles
    assert "No anti-rollback evidence found in firmware strings" in titles
    # Absence is explicitly not proof.
    signed = next(f for f in audit["findings"] if "signed-boot" in f["title"])
    assert "not proof" in signed["description"]


def test_boot_chain_module_is_exposed_in_plugin_manifest(client, auth_headers) -> None:
    resp = client.get("/api/v1/plugins", headers=auth_headers)
    assert resp.status_code == 200
    actions = {
        m["name"]
        for plugin in resp.json()
        for m in plugin["modules"]
    }
    assert {"boot_chain", "spi_identify", "i2c_scan", "logic_capture"} <= actions
