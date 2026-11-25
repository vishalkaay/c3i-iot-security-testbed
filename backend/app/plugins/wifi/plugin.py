"""Wi-Fi / IP-network audit plugin.

Implements the seven-layer threat model from Kumar et al., *IoT device security
audit tools* (Int. J. Information Security, 2025) at the network/session/os
layers, plus the practical checks from the IIITA Wi-Fi testbed:

  discovery           -> network-layer asset discovery (mesh inventory)
  portscan            -> exposed service/port disclosure
  os_fingerprint      -> OS-layer fingerprinting (TTL/window/nmap)
  tls_audit           -> session-layer crypto posture (downgrade, weak ciphers)
  wireless_survey     -> RF-layer reconnaissance (encryption, WPS, rogue APs)
  mqtt_audit          -> session-layer unauthenticated broker detection
  traffic_capture     -> pass-the-wire capture + encryption/version analysis
  default_credentials -> (ACTIVE, gated) default-credential exposure on HTTP
  deauth_test         -> (INVASIVE, gated) bounded de-authentication validation
"""

from __future__ import annotations

import re
import time

from pydantic import BaseModel, Field

from app.core.authorization import Safety
from app.core.config import settings
from app.plugins.base import (
    BasePlugin,
    EvidenceDraft,
    FindingDraft,
    ModuleResult,
    PluginContext,
    module,
)
from app.plugins.capabilities import (
    CAP_NMAP,
    CAP_OPENSSL,
    CAP_TCPDUMP,
    CAP_TSHARK,
    CAP_WIRELESS,
)
from app.plugins.tools import (
    has_tool,
    run,
    validate_host,
    validate_interface,
    validate_mac,
    validate_port,
)
from app.services import risk
from app.services.traffic import classify_encryption, extract_version_hints, read_pcap_payloads
from app.services.vuln import vuln_intel

from . import helpers

# Services that are outright dangerous to expose on an IoT device.
DANGEROUS_SERVICES = {
    "telnet": ("high", "Telnet transmits credentials in cleartext."),
    "ftp": ("high", "FTP is unauthenticated/cleartext."),
    "rlogin": ("high", "rlogin provides unauthenticated remote login."),
    "vnc": ("high", "VNC frequently ships with no or weak authentication."),
    "smb": ("high", "SMB exposure on an IoT device is rarely intended."),
    "ms-wbt-server": ("high", "RDP exposed on an IoT device is rarely intended."),
    "rexec": ("high", "rexec is unauthenticated."),
    "mysql": ("medium", "Database exposed to the network."),
    "redis": ("high", "Redis is unauthenticated by default."),
    "mongodb": ("medium", "Database exposed to the network."),
    "upnp": ("medium", "UPnP enables device control from the LAN."),
    "ws-discovery": ("low", "WS-Discovery can amplify reflected traffic."),
    "http": ("info", "Unencrypted management interface."),
    "mqtt": ("medium", "MQTT broker reachable without TLS; run mqtt_audit to test "
                       "anonymous access."),
    "rtsp": ("medium", "RTSP cameras often stream without authentication."),
}


class DiscoverParams(BaseModel):
    subnet: str = Field(description="CIDR subnet, e.g. 192.168.1.0/24")
    action: str = Field(default="discovery", description="discovery (host sweep)")
    resolve: bool = Field(default=True)


class TargetParams(BaseModel):
    host: str = Field(description="Target IP or hostname")


class PortScanParams(TargetParams):
    ports: str = Field(default="1-1024,1883,4444,5683,8080,8443,5000,8883",
                       description="nmap port spec")


class OsParams(TargetParams):
    use_nmap_os: bool = Field(default=True, description="Enable nmap -O when running as root")


class TlsParams(TargetParams):
    port: int = Field(default=443, ge=1, le=65535)


class WirelessParams(BaseModel):
    interface: str = Field(default="wlan0", description="Wireless interface in managed mode")


class CaptureParams(TargetParams):
    interface: str = Field(description="Capture interface, e.g. wlan0 / eth0")
    seconds: int = Field(default=15, ge=5, le=120)
    keywords: list[str] = Field(default_factory=list)


class MqttParams(TargetParams):
    port: int = Field(default=1883, ge=1, le=65535)
    seconds: int = Field(default=8, ge=3, le=60)


class CredsParams(TargetParams):
    port: int = Field(default=80, ge=1, le=65535)
    usernames: list[str] = Field(default_factory=lambda: ["admin", "root"])
    passwords: list[str] = Field(default_factory=lambda: ["admin", "password", "1234", ""])


class DeauthParams(BaseModel):
    interface: str = Field(description="Wireless interface (will enter monitor mode, then restore)")
    bssid: str = Field(description="Target AP BSSID")
    client: str | None = Field(default=None, description="Client MAC (broadcast if omitted)")
    channel: int = Field(default=1, ge=1, le=196)
    frames: int = Field(default=5, ge=1, le=20, description="Deauth frames to send (hard-capped)")


class WifiPlugin(BasePlugin):
    name = "wifi"
    domain = "wifi"
    title = "Wi-Fi / IP Network Audit"
    description = (
        "Network inventory, service/port disclosure, OS fingerprinting, TLS posture, "
        "wireless reconnaissance, MQTT exposure, capture analysis, and gated active tests."
    )

    # ------------------------------------------------------------------ #
    @module(
        name="discovery",
        title="Discover hosts on a subnet",
        safety=Safety.PASSIVE,
        params_model=DiscoverParams,
        capabilities=[CAP_NMAP],
        tags=["recon", "network"],
    )
    def discovery(self, ctx: PluginContext, params: DiscoverParams) -> ModuleResult:
        """L2/L3 host sweep to inventory the mesh of IoT devices."""
        ctx.progress(20, f"sweeping {params.subnet}")
        hosts = helpers.ping_sweep(params.subnet)
        ctx.progress(90, f"{len(hosts)} live host(s)")
        assets = [
            {"kind": "wifi", "identifier": ip, "name": None, "attributes": {"discovered_by": "nmap -sn"}}
            for ip in hosts
        ]
        return ModuleResult(
            data={"subnet": params.subnet, "hosts": hosts, "assets": assets},
            summary=f"Discovered {len(hosts)} live host(s) in {params.subnet}.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="portscan",
        title="Scan ports & fingerprint services",
        safety=Safety.PASSIVE,
        params_model=PortScanParams,
        capabilities=[CAP_NMAP],
        tags=["recon", "services"],
    )
    def portscan(self, ctx: PluginContext, params: PortScanParams) -> ModuleResult:
        """Service/version discovery; flags dangerous or version-vulnerable services."""
        host = validate_host(params.host)
        ctx.progress(15, f"scanning {host}")
        result = helpers.nmap_scan(host, ports=params.ports, version=True)
        open_svcs = [s for s in result.services if s.state == "open"]
        identified = 0
        for svc in open_svcs:
            if ctx.cancelled():
                break
            if svc.name.lower() in ("", "unknown", "tcpwrapped") or svc.name.endswith("?"):
                guess = helpers.identify_service(host, svc.port)
                if guess:
                    svc.name = guess["service"]
                    svc.extra = (f"identified by {guess['method']}"
                                 + (f": {guess['banner']}" if guess.get("banner") else ""))
                    identified += 1
        ctx.progress(80, f"{len(open_svcs)} open port(s), {identified} identified by probe")

        findings: list[FindingDraft] = []
        for svc in open_svcs:
            key = svc.name.lower()
            if key in DANGEROUS_SERVICES:
                sev, why = DANGEROUS_SERVICES[key]
                findings.append(
                    FindingDraft(
                        title=f"{svc.name or 'service'} exposed on {host}:{svc.port}",
                        category="network-exposure",
                        severity=sev,
                        description=f"{why} (banner: {(svc.product + ' ' + svc.version).strip() or 'n/a'})",
                        remediation="Disable the service or bind it to localhost; if required, "
                                    "place it behind an authenticated, encrypted gateway.",
                        evidence=svc.to_dict(),
                    )
                )
            # Version-based CVE mapping.
            if svc.product and svc.version:
                hits = vuln_intel.search_keywords([f"{svc.product} {svc.version}"], limit=8)
                for h in hits:
                    findings.append(
                        FindingDraft(
                            title=f"{h.id} on {host}:{svc.port} ({svc.product} {svc.version})",
                            category="service-cve",
                            severity=_sev(h.severity, h.cvss),
                            description=h.description[:1200],
                            cvss_score=h.cvss, epss_score=h.epss, cve_ids=[h.id],
                            references=h.references,
                            evidence=f"service={svc.name} banner={svc.product} {svc.version}",
                        )
                    )

        return ModuleResult(
            data={
                "host": host,
                "services": [s.to_dict() for s in result.services],
                "hostnames": result.hostnames,
                "os_matches": result.os_matches,
                "assets": [{
                    "kind": "wifi", "identifier": host,
                    "name": result.hostnames[0] if result.hostnames else None,
                    "attributes": {"open_ports": [s.port for s in open_svcs]},
                }],
            },
            findings=findings,
            summary=f"{len(open_svcs)} open port(s) on {host}; {len(findings)} finding(s).",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="os_fingerprint",
        title="Fingerprint operating system",
        safety=Safety.PASSIVE,
        params_model=OsParams,
        capabilities=[CAP_NMAP],
        tags=["fingerprint"],
    )
    def os_fingerprint(self, ctx: PluginContext, params: OsParams) -> ModuleResult:
        """TTL-based heuristic plus optional nmap -O (active-only when root)."""
        host = validate_host(params.host)
        ctx.progress(25, "probing TTL")
        ttl_guess, ttl = _ttl_probe(host)
        os_matches: list[dict] = []
        if params.use_nmap_os:
            import os as _os

            if _os.geteuid() == 0 and has_tool("nmap"):
                ctx.progress(60, "running nmap OS detection")
                os_matches = helpers.nmap_scan(host, ports="1-100", version=False, os_detect=True).os_matches

        ctx.progress(90, "compiling fingerprint")
        return ModuleResult(
            data={"host": host, "ttl": ttl, "ttl_os_guess": ttl_guess, "nmap_os_matches": os_matches},
            summary=f"{host}: TTL-based guess '{ttl_guess}'"
                    + (f"; nmap: {os_matches[0]['name']}" if os_matches else ""),
        )

    # ------------------------------------------------------------------ #
    @module(
        name="tls_audit",
        title="Audit TLS configuration",
        safety=Safety.PASSIVE,
        params_model=TlsParams,
        capabilities=[CAP_OPENSSL],
        tags=["crypto", "session-layer"],
    )
    def tls_audit(self, ctx: PluginContext, params: TlsParams) -> ModuleResult:
        """Enumerate supported TLS versions/ciphers and flag downgrade exposure."""
        host = validate_host(params.host)
        port = validate_port(params.port)
        ctx.progress(20, "probing supported protocols")
        probe = helpers.tls_probe(host, port)
        if probe.get("error"):
            return ModuleResult(data=probe, summary=probe["error"])
        ctx.progress(80, "evaluating crypto posture")

        findings: list[FindingDraft] = []
        weak = probe["weak_protocols"]
        if weak:
            findings.append(
                FindingDraft(
                    title=f"Deprecated TLS versions accepted on {host}:{port}",
                    category="weak-crypto",
                    severity="high" if any(p["version"] in ("ssl2", "ssl3", "tls1") for p in weak)
                    else "medium",
                    description="The endpoint accepts " + ", ".join(p["version"] for p in weak)
                                + " which are broken or deprecated.",
                    remediation="Restrict the server to TLS 1.2+ and disable CBC/RC4 suites.",
                    evidence=weak,
                )
            )
        cert = probe.get("certificate", {})
        if cert.get("self_signed"):
            findings.append(
                FindingDraft(
                    title=f"Self-signed certificate on {host}:{port}",
                    category="certificate",
                    severity="medium",
                    description="A self-signed certificate prevents clients from validating the device.",
                    remediation="Install a certificate from a managed/internal CA.",
                    evidence=cert,
                )
            )
        if not probe["supported"]:
            return ModuleResult(
                data={"host": host, "port": port, "tls": probe},
                summary=f"No TLS handshake completed on {host}:{port} (not a TLS service, or "
                        "unreachable); no crypto conclusion drawn.")
        if cert.get("expired"):
            findings.append(
                FindingDraft(
                    title=f"Expired certificate on {host}:{port}",
                    category="certificate", severity="high",
                    description="The certificate's validity window ended "
                                f"{abs(cert['days_remaining'])} day(s) ago; clients that validate "
                                "certificates will reject it and users are trained to click through.",
                    remediation="Renew the certificate and automate rotation.",
                    evidence=cert,
                )
            )
        if cert.get("key_bits") and cert["key_bits"] < 2048 and \
                "ec" not in (cert.get("signature_algorithm") or "").lower():
            findings.append(
                FindingDraft(
                    title=f"Weak {cert['key_bits']}-bit certificate key on {host}:{port}",
                    category="weak-crypto", severity="high",
                    description="RSA keys below 2048 bits are factorable with modest resources.",
                    remediation="Re-issue with RSA >= 2048 or ECDSA P-256.",
                    evidence=cert,
                )
            )
        sig = (cert.get("signature_algorithm") or "").lower()
        if "md5" in sig or "sha1" in sig:
            findings.append(
                FindingDraft(
                    title=f"Certificate signed with a broken hash on {host}:{port}",
                    category="weak-crypto", severity="medium",
                    description=f"Signature algorithm {cert['signature_algorithm']} is "
                                "collision-prone.",
                    remediation="Re-issue with SHA-256 or better.",
                    evidence=cert,
                )
            )
        return ModuleResult(
            data={"host": host, "port": port, "tls": probe},
            findings=findings,
            summary=f"{len(probe['supported'])} protocol(s) accepted, {len(weak)} weak.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="wireless_survey",
        title="Survey wireless access points",
        safety=Safety.PASSIVE,
        params_model=WirelessParams,
        capabilities=[CAP_WIRELESS],
        tags=["rf", "recon"],
    )
    def wireless_survey(self, ctx: PluginContext, params: WirelessParams) -> ModuleResult:
        """List nearby APs, encryption types, and WPS exposure."""
        iface = validate_interface(params.interface)
        ctx.progress(30, f"scanning on {iface}")
        aps, meta = helpers.wireless_survey(iface)
        if not meta["complete"]:
            ctx.log(meta["note"], level="warn")
        ctx.progress(85, f"{len(aps)} AP(s) via {meta['source']}")

        findings: list[FindingDraft] = []
        for ap in aps:
            if ap.encryption == "open":
                findings.append(
                    FindingDraft(
                        title=f"Open (unencrypted) access point '{ap.ssid}'",
                        category="wireless-encryption",
                        severity="high",
                        description=f"AP {ap.bssid} broadcasts with no encryption.",
                        remediation="Enable WPA3 (or WPA2-Enterprise). Never use open Wi-Fi for "
                                    "IoT control traffic.",
                        evidence=ap.to_dict(),
                    )
                )
            if ap.encryption == "WEP":
                findings.append(
                    FindingDraft(
                        title=f"WEP-protected access point '{ap.ssid}'",
                        category="wireless-encryption", severity="critical",
                        description=f"AP {ap.bssid} sets the Privacy bit with no WPA/RSN element "
                                    "(WEP). WEP keys are recoverable in minutes.",
                        remediation="Replace with WPA2-AES or WPA3.",
                        evidence=ap.to_dict(),
                    )
                )
            if "TKIP" in ap.ciphers or ap.encryption == "WPA (legacy)":
                findings.append(
                    FindingDraft(
                        title=f"Legacy WPA/TKIP accepted by '{ap.ssid}'",
                        category="wireless-encryption", severity="medium",
                        description=f"AP {ap.bssid} still offers WPA1 and/or the deprecated TKIP "
                                    "cipher, which permits downgrade from AES-CCMP.",
                        remediation="Offer WPA2/WPA3 with CCMP/GCMP only.",
                        evidence=ap.to_dict(),
                    )
                )
            if ap.pmf == "disabled" and ap.encryption not in ("open", "WEP"):
                findings.append(
                    FindingDraft(
                        title=f"Management-frame protection (802.11w) off on '{ap.ssid}'",
                        category="wireless-dos", severity="low",
                        description=f"AP {ap.bssid} advertises neither MFP-capable nor "
                                    "MFP-required, so spoofed deauthentication/disassociation "
                                    "frames can disconnect its IoT clients.",
                        remediation="Enable 802.11w (PMF) - required for WPA3.",
                        evidence=ap.to_dict(),
                    )
                )
            if ap.wps:
                findings.append(
                    FindingDraft(
                        title=f"WPS enabled on '{ap.ssid}'",
                        category="wireless-wps",
                        severity="medium",
                        description="WPS PIN mode is brute-forceable (pixie-dust/online attacks).",
                        remediation="Disable WPS.",
                        evidence=ap.to_dict(),
                    )
                )
        assets = [
            {"kind": "wifi", "identifier": ap.bssid, "name": ap.ssid or None,
             "attributes": ap.to_dict()}
            for ap in aps
        ]
        return ModuleResult(
            data={"interface": iface, "scan": meta,
                  "access_points": [a.to_dict() for a in aps], "assets": assets},
            findings=findings,
            summary=f"{len(aps)} AP(s) ({meta['source']}); {len(findings)} finding(s)."
                    + ("" if meta["complete"] else " INCOMPLETE - active scan was not permitted."),
        )

    # ------------------------------------------------------------------ #
    @module(
        name="mqtt_audit",
        title="Audit MQTT broker exposure",
        safety=Safety.PASSIVE,
        params_model=MqttParams,
                tags=["mqtt", "session-layer"],
    )
    def mqtt_audit(self, ctx: PluginContext, params: MqttParams) -> ModuleResult:
        """Check for an anonymous-subscribe MQTT broker and sample topics."""
        host = validate_host(params.host)
        port = validate_port(params.port)
        # Native MQTT 3.1.1 probe: no external client needed (read-only).
        tool = True
        ctx.progress(30, "attempting anonymous connect + subscribe")
        probe = helpers.mqtt_anonymous_probe(host, port, seconds=params.seconds)
        topics: list[str] = probe["topics"]
        anon = bool(probe["anonymous"])
        if not probe["reachable"]:
            tool = False
            note = f"broker could not be tested: {probe.get('error', 'no response')}"
            ctx.log(note, level="warn")
        elif not anon:
            note = f"broker refused anonymous connection (CONNACK rc={probe['connack']})"
        elif topics:
            note = "ok"
        else:
            note = "anonymous connect + subscribe accepted; no messages in the window"
        ctx.progress(80, f"{len(topics)} topic message(s) observed")

        findings: list[FindingDraft] = []
        if anon:
            findings.append(
                FindingDraft(
                    title=f"MQTT broker allows anonymous subscription on {host}:{port}",
                    category="mqtt-exposure",
                    severity="critical" if topics else "high",
                    description="The broker accepted a CONNECT with no credentials and a "
                                "wildcard subscription, so an unauthenticated client can harvest "
                                "telemetry/commands. Topics observed: "
                                + (", ".join(topics[:10]) or "none in the sampling window"),
                    remediation="Enable authentication + ACLs, require TLS (8883), and never "
                                "publish secrets to plain topic names.",
                    evidence={"topics": topics[:50]},
                )
            )
        return ModuleResult(
            data={"host": host, "port": port, "anonymous_access": anon,
                  "tested": tool, "note": note, "connack": probe["connack"],
                  "topics": topics},
            findings=findings,
            summary=(f"Anonymous MQTT access: {anon} ({len(topics)} topic messages)"
                     if tool else f"MQTT audit skipped: {note}"),
        )

    # ------------------------------------------------------------------ #
    @module(
        name="traffic_capture",
        title="Capture & analyse live traffic",
        safety=Safety.PASSIVE,
        params_model=CaptureParams,
        capabilities=[CAP_TCPDUMP, CAP_TSHARK],
        tags=["traffic", "capture"],
    )
    def traffic_capture(self, ctx: PluginContext, params: CaptureParams) -> ModuleResult:
        """Capture N seconds of traffic, then verify encryption and mine version hints."""
        host = validate_host(params.host)
        iface = validate_interface(params.interface)
        out = settings.evidence_dir / f"capture_{host.replace('.', '_')}_{int(time.time())}.pcap"
        ctx.progress(10, f"capturing {params.seconds}s on {iface}")
        run(["tcpdump", "-i", iface, "-w", str(out), "host", host,
             "-G", str(params.seconds), "-W", "1"], timeout=params.seconds + 15)
        if not out.exists():
            return ModuleResult(data={"error": "capture produced no file"},
                                summary="capture failed (is tcpdump installed / interface up?)")
        ctx.progress(55, "analysing capture")
        payloads = read_pcap_payloads(str(out))
        verdict = classify_encryption(payloads)
        hints = extract_version_hints(b"\n".join(payloads))

        findings: list[FindingDraft] = []
        if verdict.samples == 0:
            findings.append(
                FindingDraft(
                    title=f"No analysable payloads in capture of {host}",
                    category="traffic-encryption",
                    severity="info",
                    description="The capture window produced no application-layer payload data "
                                "(no traffic or filtered interface). No encryption conclusion "
                                "can be drawn from an empty capture.",
                    remediation="Verify the interface sees the target's traffic "
                                "(same L2 segment, monitor mode, correct filter) and retry.",
                    evidence=verdict.to_dict(),
                )
            )
        elif not verdict.encrypted and verdict.confidence >= 0.7:
            findings.append(
                FindingDraft(
                    title=f"Cleartext traffic observed for {host}",
                    category="traffic-encryption",
                    severity="high",
                    description=f"Application-data analysis: {verdict.reasoning}.",
                    remediation="Move management/telemetry to TLS or an encrypted tunnel.",
                    evidence=verdict.to_dict(),
                )
            )
        elif not verdict.encrypted:
            findings.append(
                FindingDraft(
                    title=f"Ambiguous encryption posture for {host}",
                    category="traffic-encryption",
                    severity="low",
                    description=f"Analysis was inconclusive: {verdict.reasoning}. Manual review "
                                "of the saved capture is required.",
                    remediation="Re-capture a longer window and inspect the pcap manually.",
                    evidence=verdict.to_dict(),
                )
            )
        hits = vuln_intel.search_keywords((params.keywords or []) + hints.tokens[:8], limit=12)
        for h in hits:
            findings.append(
                FindingDraft(
                    title=f"{h.id} relevant to observed traffic from {host}",
                    category="service-cve",
                    severity=_sev(h.severity, h.cvss),
                    description=h.description[:1000], cvss_score=h.cvss, epss_score=h.epss,
                    cve_ids=[h.id], references=h.references,
                )
            )
        ev = ctx.save_evidence(
            EvidenceDraft(kind="pcap", filename=out.name, content=out.read_bytes(),
                          note=f"capture of {host} on {iface}")
        )
        return ModuleResult(
            data={"encryption": verdict.to_dict(), "version_hints": hints.to_dict(),
                  "cves": [h.to_dict() for h in hits], "capture_sha256": ev.sha256},
            findings=findings, evidence=[ev],
            summary=f"{verdict.samples} payload(s) analysed; encrypted={verdict.encrypted} "
                    f"({verdict.confidence:.0%}); {len(hits)} CVE hint(s).",
        )

    # ======================== active (gated) ========================= #
    @module(
        name="default_credentials",
        title="Test for default credentials",
        safety=Safety.ACTIVE,
        params_model=CredsParams,
        tags=["credentials", "auth"],
        mitre=["T1110.001"],
    )
    def default_credentials(self, ctx: PluginContext, params: CredsParams) -> ModuleResult:
        """Small, bounded default-credential check against an HTTP management UI.

        Treats a credential-free 200 page as "no auth required" (its own finding)
        rather than as "default credentials accepted".
        """
        host = validate_host(params.host)
        port = validate_port(params.port)
        ctx.log("starting bounded credential test (authorized engagement)", level="warn")
        attempts = 0
        hit = None
        baseline = None
        tried_any = False
        for user in params.usernames[:4]:
            for pw in params.passwords[:6]:
                attempts += 1
                ctx.progress(min(90, 10 + attempts * 8), f"trying {user}:{'*' * len(pw)}")
                res = helpers.http_basic_probe(host, port, user, pw)
                tried_any = True
                if "baseline_status" in res:
                    baseline = res["baseline_status"]
                if res.get("ok"):
                    hit = {"username": user, "password": pw}
                    break
            if hit:
                break

        findings: list[FindingDraft] = []
        if hit:
            findings.append(
                FindingDraft(
                    title=f"Default credentials accepted on {host}:{port}",
                    category="default-credentials",
                    severity="critical",
                    description=f"The device required authentication and accepted username "
                                f"'{hit['username']}' with a default password. This grants "
                                "immediate device control.",
                    remediation="Force a credential change on first boot; disable the default "
                                "account; require unique per-device secrets.",
                    evidence={"username": hit["username"], "port": port,
                              "attempts": attempts},
                )
            )
        elif tried_any and baseline is not None and baseline < 400:
            findings.append(
                FindingDraft(
                    title=f"Management interface on {host}:{port} requires no authentication",
                    category="default-credentials",
                    severity="high",
                    description="The page answered 200 without credentials, so password "
                                "spraying is pointless here - the real issue is that the "
                                "resource is unauthenticated at all.",
                    remediation="Require authentication for all management endpoints.",
                    evidence={"baseline_status": baseline, "port": port},
                )
            )
        data = {"host": host, "port": port, "attempts": attempts, "found": hit is not None,
                "credential": hit, "baseline_status_unauthenticated": baseline}
        return ModuleResult(
            data=data,
            findings=findings,
            summary=(f"Default credentials FOUND ({hit['username']})" if hit
                     else f"No default credentials among {attempts} attempt(s)."),
        )

    # ======================== invasive (gated) ======================== #
    @module(
        name="deauth_test",
        title="Bounded de-authentication validation",
        safety=Safety.INVASIVE,
        params_model=DeauthParams,
        capabilities=[CAP_WIRELESS],
        tags=["wireless", "resilience"],
        mitre=["T1498", "T1465"],
    )
    def deauth_test(self, ctx: PluginContext, params: DeauthParams) -> ModuleResult:
        """Send a hard-capped number of deauth frames and restore the adapter.

        Maximum 20 frames, monitor mode is always torn down, and the interface is
        restored even on failure. Requires a signed, in-scope RoE. The result is
        honest about what actually happened: without aireplay-ng nothing is
        transmitted and no "injection possible" finding is produced.
        """
        iface = validate_interface(params.interface)
        frames = max(1, min(20, params.frames))
        target = validate_mac(params.client) if params.client else "FF:FF:FF:FF:FF:FF"
        bssid = validate_mac(params.bssid)
        ctx.log(f"bounded deauth validation against {bssid} ({frames} frames)", level="warn")

        transmitted = False
        output = ""
        tooling = "aireplay-ng"
        if not has_tool("aireplay-ng"):
            tooling = ""
            ctx.log("aireplay-ng not installed - no frames can be transmitted; "
                    "reporting failure to perform the test", level="warn")

        mon = iface
        try:
            ctx.progress(15, "enabling monitor mode")
            if tooling and has_tool("airmon-ng"):
                run(["airmon-ng", "start", iface], timeout=30)
                mon = f"{iface}mon"
            if tooling and has_tool("iw"):
                run(["iw", "dev", mon, "set", "channel", str(params.channel)], timeout=15)
            if tooling:
                ctx.progress(55, f"sending {frames} frame(s)")
                args = ["aireplay-ng", "--deauth", str(frames), "-a", bssid]
                if params.client:
                    args += ["-c", target]
                args.append(mon if has_tool("airmon-ng") else iface)
                res = run(args, timeout=60)
                output = (res.stdout + "\n" + res.stderr)[-3000:]
                transmitted = res.returncode == 0 and "sent" in output.lower()
        finally:
            ctx.progress(90, "restoring interface")
            if has_tool("airmon-ng") and mon != iface:
                run(["airmon-ng", "stop", mon], timeout=30)

        data = {"bssid": bssid, "client": target, "frames_requested": frames,
                "transmitted": transmitted, "interface": iface,
                "channel": params.channel, "tooling": tooling or None,
                "output": output}
        findings: list[FindingDraft] = []

        if not tooling:
            summary = ("Deauth validation NOT performed: aireplay-ng is missing on this host "
                       "(no frame can be sent, no resilience conclusion available).")
            findings.append(
                FindingDraft(
                    title=f"De-authentication resilience not testable for {bssid} (tooling absent)",
                    category="wireless-dos",
                    severity="info",
                    description="aireplay-ng is not installed on the test host, so no deauth "
                                "frame could be transmitted and no 802.11w/PMF conclusion can "
                                "be drawn for this AP.",
                    remediation="Install the aircrack-ng suite on the test rig to enable "
                                "wireless resilience testing.",
                    extra={"frames_requested": frames, "transmitted": False},
                )
            )
            return ModuleResult(data=data, findings=findings, summary=summary)

        if transmitted:
            findings.append(
                FindingDraft(
                    title=f"De-authentication frames injected against {bssid}",
                    category="wireless-dos",
                    severity="medium",
                    description=(
                        f"{frames} de-authentication frame(s) were transmitted and aireplay-ng "
                        "reported success. Confirm by watching whether clients disconnected: if "
                        "they did, the AP does not enforce 802.11w (PMF) management-frame "
                        "protection. A successful transmission alone shows the frame path "
                        "works, not that client downtime occurred."
                    ),
                    remediation="Enable 802.11w (Protected Management Frames) on the AP and "
                                "clients; monitor for sustained deauth activity.",
                    evidence=output[-1500:],
                    extra={"frames": frames, "channel": params.channel, "transmitted": True},
                )
            )
            summary = f"Sent ~{frames} deauth frame(s) to {bssid}; interface restored."
        else:
            findings.append(
                FindingDraft(
                    title=f"De-authentication transmission failed against {bssid}",
                    category="wireless-dos",
                    severity="info",
                    description=(
                        "aireplay-ng did not report transmitted frames - the injection was "
                        "blocked (driver/channel mismatch or monitor mode not achieved). No "
                        "resilience conclusion can be drawn."
                    ),
                    remediation="Verify monitor-mode support (iw phy) and channel availability.",
                    evidence=output[-1500:] or "no tool output",
                    extra={"frames_requested": frames, "transmitted": False},
                )
            )
            summary = f"Deauth injection to {bssid} did NOT transmit; interface restored."
        return ModuleResult(
            data=data, findings=findings, summary=summary,
        )


def _sev(severity: str, cvss: float | None) -> str:
    if cvss is not None:
        return risk.cvss_to_severity(cvss)
    return severity if severity in risk.SEVERITY_ORDER else "info"


def _ttl_probe(host: str) -> tuple[str, int | None]:
    if not has_tool("ping"):
        return "unknown", None
    res = run(["ping", "-c", "2", "-W", "2", host], timeout=12)
    m = re.search(r"ttl=(\d+)", res.stdout, re.IGNORECASE)
    if not m:
        return "unknown", None
    ttl = int(m.group(1))
    # Initial TTL heuristics: 64 (Linux), 128 (Windows), 255 (network gear).
    if ttl <= 64:
        return "Linux/embedded (ttl<=64)", ttl
    if ttl <= 128:
        return "Windows (ttl<=128)", ttl
    return "Network device / Unix (ttl<=255)", ttl
