"""Bluetooth / BLE audit plugin.

Modules mirror the audit framework from Kavisankar et al., *A comprehensive
bluetooth security audit framework for IoT devices* (Computers & Security, 2026),
which this testbed implements and extends:

  scan            -> device profiling / behavioural discovery
  profile         -> device attributes + OS/version inference (SDP + CoD)
  gatt_firmware   -> Device Information Service firmware identification
  link_rtt        -> link quality / distance
  capture_audit   -> encrypted-vs-plaintext traffic verification
  cve_lookup      -> OS/firmware -> CVE mapping
  link_stress     -> (invasive, gated) bounded DoS / robustness validation
  mac_spoof       -> (invasive, gated) local adapter identity change

None of the invasive modules run without a signed, in-scope Rules of Engagement.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from app.core.authorization import Safety
from app.plugins.base import (
    BasePlugin,
    EvidenceDraft,
    FindingDraft,
    ModuleResult,
    PluginContext,
    module,
)
from app.plugins.capabilities import CAP_BLUEZ, CAP_BT_DBUS, CAP_L2PING, CAP_TSHARK
from app.plugins.tools import has_tool, run, validate_input_path, validate_mac
from app.services import risk
from app.services.traffic import classify_encryption, extract_version_hints, read_pcap_payloads
from app.services.vuln import vuln_intel

from . import helpers


class ScanParams(BaseModel):
    duration: int = Field(default=10, ge=5, le=60, description="Discovery window in seconds")


class AddressParams(BaseModel):
    address: str = Field(description="Bluetooth device MAC, e.g. AA:BB:CC:DD:EE:FF")


class RttParams(AddressParams):
    count: int = Field(default=10, ge=1, le=100)
    size: int = Field(default=44, ge=1, le=2000)
    rssi_dbm: int | None = Field(
        default=None, ge=-127, le=-1,
        description="Optional measured RSSI (dBm). If omitted, BlueZ's current RSSI is used.")
    reference_rssi_dbm: float | None = Field(
        default=None, ge=-100, le=-20,
        description="Optional RSSI measured at 1 m for this device. Default assumes -59 dBm.")
    path_loss_exponent: float = Field(
        default=2.5, ge=1.2, le=5.0,
        description="Environment path-loss exponent: 2.0 free space, 2.5 indoor, 3.0 obstructed.")


class CaptureParams(BaseModel):
    capture_path: str = Field(description="Server-side path to a pcap/pcapng capture")
    keywords: list[str] = Field(default_factory=list, description="Extra CVE keywords")


class CveParams(BaseModel):
    keywords: list[str] = Field(description="Product / OS / firmware tokens to map to CVEs")


class StressParams(AddressParams):
    packets: int = Field(default=100, ge=10, le=1000, description="Max L2CAP echo packets")
    size: int = Field(default=600, ge=1, le=2000, description="Echo payload size (bytes)")


class SpoofParams(BaseModel):
    adapter: str = Field(default="hci0", description="Local adapter to re-identify")


class GattEnumParams(AddressParams):
    read_values: bool = Field(
        default=True,
        description="Also read the value of every OPEN-readable characteristic (bounded).")
    max_read_bytes: int = Field(
        default=64, ge=1, le=512,
        description="Cap on bytes read per characteristic.")


class BluetoothPlugin(BasePlugin):
    name = "bluetooth"
    domain = "bluetooth"
    title = "Bluetooth / BLE Audit"
    description = (
        "Device discovery, SDP/attribute profiling, OS & firmware identification, "
        "full GATT enumeration with OPEN/PROTECTED access classification, LE pairing "
        "& privacy posture, encrypted-communication verification, CVE mapping, and "
        "gated resilience tests."
    )

    # ------------------------------------------------------------------ #
    @module(
        name="scan",
        title="Discover Bluetooth / BLE devices",
        safety=Safety.PASSIVE,
        params_model=ScanParams,
        capabilities=[CAP_BLUEZ],
        tags=["recon", "bluetooth"],
    )
    def scan(self, ctx: PluginContext, params: ScanParams) -> ModuleResult:
        """Passive discovery of nearby classic + LE devices, with RSSI ranking."""
        ctx.progress(10, "starting discovery")
        devices = helpers.scan(params.duration)
        ctx.progress(70, f"discovered {len(devices)} devices; attributing fingerprints")

        findings: list[FindingDraft] = []
        assets: list[dict] = []
        hints: list[dict] = []
        fingerprinted: list[dict] = []
        for dev in devices:
            infer = helpers.infer_os(dev)
            hints.append(
                {"address": dev.address, "name": dev.name or None, **infer.to_dict()}
            )
            assets.append(
                {
                    "kind": "bluetooth",
                    "identifier": dev.address,
                    "name": dev.name or None,
                    "vendor": dev.manufacturer,
                    "attributes": {"os": infer.os_family, **dev.to_dict()},
                }
            )
            if infer.confidence in ("medium", "high"):
                fingerprinted.append(
                    {
                        "address": dev.address,
                        "name": dev.name or None,
                        "family": infer.os_family,
                        "confidence": infer.confidence,
                        "reasons": infer.reasons,
                    }
                )
            # Passive hygiene signal: discoverable but unnamed devices are worth flagging.
            if dev.rssi is not None and dev.rssi > -45 and not dev.name:
                findings.append(
                    FindingDraft(
                        title=f"Strong-signal unnamed Bluetooth device in range ({dev.address})",
                        category="bluetooth-discovery",
                        severity="info",
                        description=(
                            f"A device advertising at RSSI {dev.rssi} dBm exposes no friendly name. "
                            "It may be a tracking tag, a headless sensor, or a device in an "
                            "unexpected pairing mode."
                        ),
                        remediation="Confirm the device belongs to the environment; disable "
                                    "discoverability when not pairing.",
                        evidence=f"address={dev.address} rssi={dev.rssi}",
                        extra={"address": dev.address, "rssi": dev.rssi},
                    )
                )

        if fingerprinted:
            top = fingerprinted[:8]
            listing = "; ".join(
                f"{d['name'] or d['address']} -> {d['family']} ({d['confidence']})"
                for d in top
            )
            findings.append(
                FindingDraft(
                    title=f"{len(fingerprinted)} nearby device(s) leak vendor/OS fingerprints",
                    category="bluetooth-fingerprinting",
                    severity="info",
                    description=(
                        "Advertising company IDs, device names and class-of-device records let "
                        "any unauthenticated peer infer vendor and OS family without pairing. "
                        "Attribution is heuristic - verify against the hardware before acting "
                        f"on it. {listing}"
                    ),
                    remediation="Use non-identifying Bluetooth names; disable discoverability "
                                "when not pairing; remember LE MAC randomisation limits "
                                "long-term tracking.",
                    evidence="; ".join(f"{d['address']}: {d['family']}" for d in top),
                    extra={"devices": fingerprinted},
                )
            )

        return ModuleResult(
            data={"devices": [d.to_dict() for d in devices], "os_hints": hints,
                  "assets": assets},
            findings=findings,
            summary=f"Discovered {len(devices)} Bluetooth/BLE device(s) in {params.duration}s.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="profile",
        title="Profile device & infer OS/version",
        safety=Safety.PASSIVE,
        params_model=AddressParams,
        capabilities=[CAP_BLUEZ],
        tags=["fingerprint", "bluetooth"],
    )
    def profile(self, ctx: PluginContext, params: AddressParams) -> ModuleResult:
        """Read SDP/class attributes and heuristically infer OS family/version."""
        address = validate_mac(params.address)
        ctx.progress(30, "querying device attributes")
        dev = helpers.device_info(address)
        dis = helpers.read_device_information(address)
        infer = helpers.infer_os(dev, dis)
        ctx.progress(80, f"inferred OS family: {infer.os_family}")

        findings: list[FindingDraft] = []
        if dev.paired and not dev.trusted:
            findings.append(
                FindingDraft(
                    title=f"Device paired but not trusted ({address})",
                    category="bluetooth-pairing",
                    severity="low",
                    description="The device holds a pairing but is not marked trusted; a re-pair "
                                "may silently succeed from any peer.",
                    remediation="Remove stale pairings; require authentication on re-pair.",
                )
            )
        if not dev.paired:
            findings.append(
                FindingDraft(
                    title=f"Device exposes services without a pairing requirement ({address})",
                    category="bluetooth-pairing",
                    severity="medium",
                    description="SDP records are visible to unauthenticated peers, enabling "
                                "further service enumeration.",
                    remediation="Require Secure Connections pairing (LE) / authenticated pairing "
                                "(classic) and minimise exposed profiles.",
                    evidence=f"uuids={dev.uuids}",
                )
            )
        if infer.confidence in ("medium", "high"):
            findings.append(
                FindingDraft(
                    title=f"Device fingerprinted as {infer.os_family} without pairing ({address})",
                    category="bluetooth-fingerprinting",
                    severity="info",
                    description=(
                        "Discovery-layer data (advertising company IDs, device name, class of "
                        "device) identifies the vendor/OS family to any unauthenticated peer: "
                        + " | ".join(infer.reasons)
                    ),
                    remediation="Rename the device to something non-identifying and disable "
                                "discoverability outside pairing windows.",
                    evidence=f"family={infer.os_family} confidence={infer.confidence}",
                    extra=infer.to_dict(),
                )
            )

        return ModuleResult(
            data={
                "device": dev.to_dict(),
                "os_inference": infer.to_dict(),
                "device_information_service": dis,
                "assets": [
                    {
                        "kind": "bluetooth",
                        "identifier": address,
                        "name": dev.name or None,
                        "vendor": dev.manufacturer,
                        "firmware": dis.get("firmware_revision") if "_error" not in dis else None,
                        "attributes": {"os": infer.os_family, **dev.to_dict()},
                    }
                ],
            },
            findings=findings,
            summary=f"{dev.name or address}: {infer.os_family} ({infer.confidence} confidence).",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="gatt_firmware",
        title="Identify firmware via GATT DIS",
        safety=Safety.PASSIVE,
        params_model=AddressParams,
        capabilities=[CAP_BT_DBUS],
        tags=["firmware", "bluetooth"],
    )
    def gatt_firmware(self, ctx: PluginContext, params: AddressParams) -> ModuleResult:
        """Read the Device Information Service and map the firmware to CVEs."""
        address = validate_mac(params.address)
        ctx.progress(30, "connecting to GATT server")
        dis = helpers.read_device_information(address)
        if "_error" in dis:
            return ModuleResult(
                data={"device_information_service": dis},
                summary=f"Firmware identification unavailable: {dis['_error']}",
            )

        keywords = [v for v in (
            dis.get("manufacturer_name"), dis.get("model_number"),
            dis.get("firmware_revision"), dis.get("software_revision"),
            dis.get("hardware_revision"),
        ) if v]
        ctx.progress(60, f"mapping {len(keywords)} token(s) to CVEs")
        hits = vuln_intel.search_keywords(keywords, limit=25) if keywords else []

        findings = [
            FindingDraft(
                title=f"Firmware fingerprint {h.id} for {dis.get('model_number', address)}",
                category="firmware-cve",
                severity=_sev(h.severity, h.cvss),
                description=h.description[:1500],
                cvss_score=h.cvss,
                epss_score=h.epss,
                cve_ids=[h.id],
                references=h.references,
                remediation="Track the vendor advisory and update the firmware; if no patch "
                            "exists, apply compensating network/host controls.",
                evidence=f"matched_on={h.matched_on}",
                extra={"matched_on": h.matched_on},
            )
            for h in hits
        ]
        return ModuleResult(
            data={
                "device_information_service": dis,
                "firmware_version": dis.get("firmware_revision"),
                "cves": [h.to_dict() for h in hits],
                "assets": [
                    {
                        "kind": "bluetooth",
                        "identifier": address,
                        "vendor": dis.get("manufacturer_name"),
                        "model": dis.get("model_number"),
                        "firmware": dis.get("firmware_revision"),
                        "attributes": {"dis": dis},
                    }
                ],
            },
            findings=findings,
            summary=(
                f"Firmware {dis.get('firmware_revision', 'unknown')} "
                f"({dis.get('model_number', 'unknown model')}); {len(hits)} CVE(s) mapped."
            ),
        )

    # ------------------------------------------------------------------ #
    @module(
        name="gatt_enum",
        title="Enumerate GATT database & access levels",
        safety=Safety.PASSIVE,
        params_model=GattEnumParams,
        capabilities=[CAP_BT_DBUS],
        tags=["ble", "gatt", "enumeration"],
    )
    def gatt_enum(self, ctx: PluginContext, params: GattEnumParams) -> ModuleResult:
        """Walk the full GATT attribute table and classify each characteristic's
        access as OPEN (reachable with no encryption/authentication) or
        PROTECTED. Reads OPEN-readable values (bounded). Enumerating an exposed
        attribute table is not an auth bypass — the device exposes it as-is."""
        address = validate_mac(params.address)
        ctx.progress(25, "connecting and resolving services")
        gatt = helpers.enumerate_gatt(address, read_values=params.read_values,
                                      max_read_bytes=params.max_read_bytes)
        if "_error" in gatt:
            return ModuleResult(data={"gatt": gatt},
                                summary=f"GATT enumeration unavailable: {gatt['_error']}")
        st = gatt["stats"]
        findings: list[FindingDraft] = []
        if gatt["open_writes"]:
            chars = ", ".join((c["label"] or c["uuid"]) for c in gatt["open_writes"][:8])
            findings.append(FindingDraft(
                title=f"{st['open_writable']} GATT characteristic(s) offer writes to an "
                      f"unpaired link ({address})",
                category="ble-gatt", severity="high",
                description="These characteristics declare write access and were reachable "
                            f"with no pairing: {chars}. No write was performed, so whether the "
                            "device rejects an unencrypted write is unverified - confirm with an "
                            "authorized test write. If accepted, an unpaired attacker in radio "
                            "range can change device state (actuator, lock, configuration, OTA).",
                remediation="Require LE Secure Connections (encryption + authentication) on "
                            "writable characteristics; reject writes on an unauthenticated link.",
                evidence=f"open_writable={st['open_writable']}",
                extra={"open_writes": gatt["open_writes"]}))
        if gatt["open_reads"]:
            findings.append(FindingDraft(
                title=f"{st['open_readable']} GATT characteristic(s) readable without "
                      f"authentication ({address})",
                category="ble-gatt", severity="medium",
                description="Attribute values were read over an unpaired, unencrypted link "
                            "(characteristics whose read was rejected for security are counted "
                            "as protected, not here); verify none expose secrets, tokens, PII or "
                            "security-relevant configuration.",
                remediation="Gate sensitive characteristics behind encryption/authentication.",
                evidence=f"open_readable={st['open_readable']}",
                extra={"sample": gatt["open_reads"][:10]}))
        ev = ctx.save_evidence(EvidenceDraft(
            kind="ble-gatt", filename=f"gatt_{address.replace(':', '')}.json",
            content=json.dumps(gatt, indent=2).encode(),
            note=f"full GATT enumeration of {address}"))
        ctx.progress(100, "enumeration complete")
        return ModuleResult(
            data={"gatt": gatt, "evidence": ev.filename},
            findings=findings, evidence=[ev],
            summary=f"{st['services']} services, {st['characteristics']} characteristics "
                    f"({st['open_readable']} open-read, {st['open_writable']} open-write, "
                    f"{st.get('protected', 0)} protected).")

    # ------------------------------------------------------------------ #
    @module(
        name="le_security",
        title="LE pairing & privacy posture",
        safety=Safety.PASSIVE,
        params_model=AddressParams,
        capabilities=[CAP_BLUEZ],
        tags=["ble", "pairing", "privacy"],
    )
    def le_security(self, ctx: PluginContext, params: AddressParams) -> ModuleResult:
        """Observable LE security posture: address privacy, pairing/bonding state,
        and whether services are exposed without pairing. Reports only what is
        observable without driving a pairing handshake."""
        address = validate_mac(params.address)
        ctx.progress(40, "reading security posture")
        sec = helpers.read_security_posture(address)
        findings: list[FindingDraft] = []
        if sec.get("address_type") == "public":
            findings.append(FindingDraft(
                title=f"Device uses a fixed public Bluetooth address ({address})",
                category="ble-privacy", severity="low",
                description="A public (non-random) address never changes, so the device is "
                            "trackable across time and location by any passive observer. "
                            "Privacy-conscious BLE devices use resolvable private addresses "
                            "that rotate periodically.",
                remediation="Enable LE privacy (resolvable private addresses) in the BLE stack.",
                evidence="address_type=public"))
        if sec.get("advertised_services", 0) > 0 and not sec.get("paired"):
            findings.append(FindingDraft(
                title=f"GATT services exposed without pairing ({address})",
                category="ble-pairing", severity="medium",
                description="The device exposes services while unpaired. Combined with OPEN "
                            "characteristics (see gatt_enum) these are directly reachable by any "
                            "unpaired peer in range. Verify sensitive operations require LE "
                            "Secure Connections.",
                remediation="Require bonding + authenticated encryption before exposing "
                            "sensitive GATT operations.",
                evidence=f"advertised_services={sec['advertised_services']} "
                         f"paired={sec['paired']}"))
        ctx.progress(100, "posture assessed")
        return ModuleResult(
            data={"security_posture": sec},
            findings=findings,
            summary=f"address_type={sec.get('address_type')} privacy={sec.get('privacy')} "
                    f"paired={sec.get('paired')} bonded={sec.get('bonded')}.")

    # ------------------------------------------------------------------ #
    @module(
        name="link_rtt",
        title="Measure link RTT / delivery",
        safety=Safety.PASSIVE,
        params_model=RttParams,
        capabilities=[CAP_L2PING],
        tags=["link-quality", "bluetooth"],
    )
    def link_rtt(self, ctx: PluginContext, params: RttParams) -> ModuleResult:
        """L2CAP echo RTT and packet-delivery statistics (link robustness)."""
        address = validate_mac(params.address)
        ctx.progress(40, "sending L2CAP echo requests")
        stats = helpers.l2ping(
            address, params.count, params.size,
            rssi_dbm=params.rssi_dbm,
            reference_rssi_dbm=params.reference_rssi_dbm,
            path_loss_exponent=params.path_loss_exponent,
        )
        if isinstance(stats, str):
            return ModuleResult(data={"error": stats}, summary=stats)

        findings: list[FindingDraft] = []
        if stats.loss_pct >= 20:
            findings.append(
                FindingDraft(
                    title=f"High Bluetooth packet loss to {address} ({stats.loss_pct:.0f}%)",
                    category="bluetooth-link",
                    severity="low",
                    description="Significant L2CAP echo loss can indicate interference, an "
                                "overloaded link, or a range/reliability problem.",
                    remediation="Relocate the device, reduce 2.4 GHz congestion, or review "
                                "antenna/power design.",
                    evidence=f"sent={stats.sent} recv={stats.received} avg={stats.avg_ms}ms",
                )
            )
        if stats.avg_ms and stats.avg_ms > 100:
            findings.append(
                FindingDraft(
                    title=f"Very high Bluetooth RTT to {address} ({stats.avg_ms} ms)",
                    category="bluetooth-link",
                    severity="low",
                    description="Round-trip latency above 100 ms is abnormal for a local link.",
                    remediation="Investigate link-layer retransmissions and interference.",
                )
            )
        distance = stats.distance or {}
        if distance.get("available"):
            distance_text = (
                f"estimated range ~{distance['estimated_m']} m "
                f"({distance['range_m'][0]}-{distance['range_m'][1]} m, "
                f"{distance['confidence']} confidence, RSSI model)"
            )
        else:
            distance_text = "range unavailable (no usable RSSI)"
        return ModuleResult(
            data={"rtt": stats.to_dict(), "distance_estimate": distance, "raw": stats.raw},
            findings=findings,
            summary=(
                f"RTT avg {stats.avg_ms} ms, loss {stats.loss_pct:.0f}% over "
                f"{stats.sent} pings; {distance_text}."
            ),
        )

    # ------------------------------------------------------------------ #
    @module(
        name="capture_audit",
        title="Verify encrypted vs plaintext traffic",
        safety=Safety.PASSIVE,
        params_model=CaptureParams,
        capabilities=[CAP_TSHARK],
        tags=["encryption", "traffic"],
    )
    def capture_audit(self, ctx: PluginContext, params: CaptureParams) -> ModuleResult:
        """Analyse a capture for encrypted-vs-plaintext application data."""
        from pathlib import Path

        # Same containment as the firmware modules: an analyst token must not
        # be able to point tshark at arbitrary server files.
        path = Path(validate_input_path(params.capture_path))
        if not path.exists():
            return ModuleResult(data={"error": "capture path not found"},
                                summary="capture not found")
        ctx.progress(30, "extracting application payloads")
        payloads = read_pcap_payloads(str(path))
        verdict = classify_encryption(payloads)
        hints = extract_version_hints(b"\n".join(payloads))
        ctx.progress(80, verdict.reasoning)

        findings: list[FindingDraft] = []
        if verdict.samples == 0:
            findings.append(
                FindingDraft(
                    title="No analysable payloads in the capture",
                    category="bluetooth-encryption",
                    severity="info",
                    description="The capture contained no application-layer payload, so no "
                                "encryption conclusion can be drawn (an empty capture is not "
                                "evidence of cleartext).",
                    remediation="Capture while the device is exchanging data (btmon/HCI snoop "
                                "or an nRF sniffer) and retry.",
                    evidence=str(verdict.to_dict()),
                )
            )
        elif not verdict.encrypted:
            findings.append(
                FindingDraft(
                    title="Bluetooth/application traffic appears unencrypted",
                    category="bluetooth-encryption",
                    severity="high",
                    description=(
                        "Payload entropy and printability indicate application data is "
                        f"transmitted in the clear ({verdict.reasoning})."
                    ),
                    remediation="Enforce link-layer encryption (Secure Connections / LE Secure "
                                "Connections) and application-layer encryption for sensitive data.",
                    evidence=str(verdict.to_dict()),
                )
            )
        hits = vuln_intel.search_keywords(
            (params.keywords or []) + hints.tokens[:8], limit=15
        )
        for h in hits:
            findings.append(
                FindingDraft(
                    title=f"{h.id} potentially relevant to captured traffic",
                    category="firmware-cve",
                    severity=_sev(h.severity, h.cvss),
                    description=h.description[:1200],
                    cvss_score=h.cvss, epss_score=h.epss, cve_ids=[h.id],
                    references=h.references,
                )
            )
        ev = ctx.save_evidence(
            EvidenceDraft(
                kind="capture-analysis",
                filename=f"encryption_audit_{path.stem}.json",
                content=(str(verdict.to_dict()) + "\n" + str(hints.to_dict())).encode(),
                note="encryption verdict + version hints",
            )
        )
        return ModuleResult(
            data={
                "encryption": verdict.to_dict(),
                "version_hints": hints.to_dict(),
                "cves": [h.to_dict() for h in hits],
            },
            findings=findings,
            evidence=[ev],
            summary=f"Encrypted={verdict.encrypted} (confidence {verdict.confidence:.0%}); "
                    f"{len(hits)} candidate CVE(s).",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="cve_lookup",
        title="Map OS/firmware keywords to CVEs",
        safety=Safety.PASSIVE,
        params_model=CveParams,
        tags=["cve", "bluetooth"],
    )
    def cve_lookup(self, ctx: PluginContext, params: CveParams) -> ModuleResult:
        """Standalone CVE mapping for OS/firmware tokens (offline-first, NVD online)."""
        ctx.progress(40, "querying vulnerability intelligence")
        hits = vuln_intel.search_keywords(params.keywords, limit=40)
        findings = [
            FindingDraft(
                title=f"{h.id}: {h.description[:80]}",
                category="firmware-cve",
                severity=_sev(h.severity, h.cvss),
                description=h.description[:1500],
                cvss_score=h.cvss, epss_score=h.epss, cve_ids=[h.id],
                references=h.references,
                remediation="Review the advisory and patch or mitigate.",
                extra={"matched_on": h.matched_on},
            )
            for h in hits
        ]
        return ModuleResult(
            data={"query": params.keywords, "cves": [h.to_dict() for h in hits]},
            findings=findings,
            summary=f"{len(hits)} CVE(s) mapped for {', '.join(params.keywords[:4])}",
        )

    # ======================== invasive (gated) ======================== #
    @module(
        name="link_stress",
        title="Link robustness validation (bounded)",
        safety=Safety.INVASIVE,
        params_model=StressParams,
        capabilities=[CAP_L2PING],
        tags=["resilience", "dos"],
        mitre=["T1499"],
    )
    def link_stress(self, ctx: PluginContext, params: StressParams) -> ModuleResult:
        """Bounded, reversible L2CAP echo load to validate link resilience.

        Hard-capped (<=1000 packets, <=2000 B) so it can never become an unbounded
        flood; it measures packet-delivery degradation under load and always stops.
        Requires a signed, in-scope RoE.
        """
        address = validate_mac(params.address)
        ctx.log("starting bounded link stress (authorized engagement)", level="warn")
        ctx.progress(20, "warm-up probes")
        result = run(
            ["l2ping", "-c", str(params.packets), "-s", str(params.size), address],
            timeout=min(120, params.packets // 5 + 30),
        )
        import re as _re

        times = [float(t) for t in _re.findall(r"time\s+([0-9.]+)\s*ms", result.stdout, _re.I)]
        times = times[:params.packets]
        recv = len(times)
        loss = 100.0 * (1 - recv / params.packets) if params.packets else 100.0
        ctx.progress(90, "load complete; evaluating degradation")

        output = result.stdout + result.stderr
        findings: list[FindingDraft] = []
        if recv == 0:
            # Nothing came back: the link was never established (out of range,
            # LE-only device, or l2ping lacks CAP_NET_RAW). That is "not
            # tested", not "100% degradation".
            reason = (output.strip().splitlines() or ["no output"])[-1][:200]
            verdict = "not_tested"
            findings.append(
                FindingDraft(
                    title=f"Link stress could not be performed against {address}",
                    category="resilience", severity="info",
                    description="No L2CAP echo reply was received, so no resilience conclusion "
                                f"can be drawn. Tool output: {reason}. l2ping needs a BR/EDR "
                                "(classic) target in range and CAP_NET_RAW on the test host.",
                    remediation="Confirm the target supports classic L2CAP echo, is in range, "
                                "and run the backend with CAP_NET_RAW.",
                    evidence=output[-3000:],
                    extra={"packets": params.packets, "received": 0, "tested": False},
                )
            )
        elif loss >= 5:
            verdict = "degraded"
            findings.append(
                FindingDraft(
                    title=f"Link degradation under load for {address} ({loss:.0f}% loss)",
                    category="resilience",
                    severity="medium" if loss >= 50 else "low",
                    description=(
                        f"Under a {params.packets}-packet / {params.size}-byte bounded echo load "
                        f"the device delivered {recv} replies ({loss:.0f}% loss). Persistent loss "
                        "under modest load indicates limited headroom against L2CAP flooding."
                    ),
                    remediation="Validate firmware update cadence and 2.4 GHz coexistence; "
                                "consider link-layer admission control for critical devices.",
                    evidence=output[-3000:],
                    extra={"packets": params.packets, "received": recv,
                           "loss_pct": round(loss, 1)},
                )
            )
        else:
            verdict = "resilient"
        ev = ctx.save_evidence(
            EvidenceDraft(
                kind="glitch-log",
                filename=f"link_stress_{address.replace(':','')}.log",
                content=output.encode(errors="replace"),
                note="bounded link-stress output (authorized engagement)",
            )
        )
        return ModuleResult(
            data={"sent": params.packets, "received": recv, "loss_pct": round(loss, 1),
                  "max_rtt_ms": max(times) if times else None, "verdict": verdict},
            findings=findings, evidence=[ev],
            summary=("Link stress NOT performed: no L2CAP reply from the target."
                     if verdict == "not_tested" else
                     f"Bounded stress: {recv}/{params.packets} replies ({loss:.0f}% loss) - "
                     f"{verdict}."),
        )

    @module(
        name="mac_spoof",
        title="Local adapter identity change (gated)",
        safety=Safety.INVASIVE,
        params_model=SpoofParams,
        capabilities=[CAP_BLUEZ],
        tags=["spoofing"],
        mitre=["T1036"],
    )
    def mac_spoof(self, ctx: PluginContext, params: SpoofParams) -> ModuleResult:
        """Change the local adapter's public address, then restore it.

        Demonstrates whether the testbed adapter can present an arbitrary identity
        (used to validate impersonation resistance). Fully reversible.
        """
        if not has_tool("btmgmt"):
            return ModuleResult(data={"error": "btmgmt not installed"},
                                summary="btmgmt not available for identity change")
        import re as _re

        ctx.log("reading current adapter address", level="warn")
        idx_m = _re.fullmatch(r"hci(\d{1,2})", params.adapter.strip())
        if not idx_m:
            return ModuleResult(data={"error": "adapter must look like hci0"},
                                summary=f"invalid adapter '{params.adapter}'")
        btmgmt = ["btmgmt", "--index", idx_m.group(1)]
        before = run([*btmgmt, "info"], timeout=15).stdout
        m = _re.search(r"addr\s+([0-9A-Fa-f:]{17})", before)
        original = m.group(1) if m else None
        new_addr = "02:00:" + ":".join(f"{b:02X}" for b in __import__("os").urandom(4))
        ctx.progress(50, f"setting {params.adapter} -> {new_addr}")
        set_res = run([*btmgmt, "public-addr", new_addr], timeout=20)
        success = set_res.returncode == 0
        if original:
            ctx.progress(90, "restoring original adapter address")
            run([*btmgmt, "public-addr", original], timeout=20)

        findings = [
            FindingDraft(
                title=f"Adapter identity change {'succeeded' if success else 'blocked'}",
                category="impersonation-resistance",
                severity="info" if not success else "low",
                description=(
                    f"The local adapter {'accepted' if success else 'rejected'} an arbitrary "
                    "public address. Devices that learn identity from the address are "
                    "susceptible to impersonation if this is possible on the target platform."
                ),
                remediation="Prefer bonded device identities / out-of-band verification over "
                            "address-only trust.",
                evidence=(set_res.stdout + set_res.stderr)[-1500:],
            )
        ]
        return ModuleResult(
            data={"previous_address": original, "attempted_address": new_addr,
                  "success": success, "restored": bool(original)},
            findings=findings,
            summary=f"Identity change {'applied and restored' if success else 'refused by controller'}.",
        )


def _sev(severity: str, cvss: float | None) -> str:
    if cvss is not None:
        return risk.cvss_to_severity(cvss)
    return severity if severity in risk.SEVERITY_ORDER else "info"
