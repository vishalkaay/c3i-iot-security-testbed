"""Firmware static-analysis plugin.

This is a genuine extraction/analysis pipeline (unlike the legacy "firmware
extraction" that string-mined a network capture):

  analyse   -> end-to-end: signatures, entropy, secrets, components, CVE
  extract   -> binwalk carve of an uploaded image
  entropy   -> entropy profile (encryption / compression detection)
  secrets   -> hard-coded secrets, keys, and shadow hashes
  sbom      -> component inventory + CVE mapping
  boot_chain-> hardware-rooted secure-boot / debug-lock evidence audit
  bootlog   -> analyse an uploaded boot log (same engine as the UART module)

Every ``path`` parameter is validated against the testbed's own data
directories (uploads/evidence/firmware) at execution time as well as at job
creation, so an analyst token can never string-mine ``/etc/shadow`` through
this API.
"""

from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

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
from app.plugins.tools import has_tool, validate_input_path
from app.services import risk
from app.services.bootlog import analyse_bootlog
from app.services.vuln import vuln_intel

from . import helpers


class FirmwareParams(BaseModel):
    path: str = Field(description="Server-side path to a firmware image / binary")
    extract: bool = Field(default=False, description="Also run binwalk extraction (slower)")


class PathParams(BaseModel):
    path: str = Field(description="Server-side path to a firmware image / binary")


class BootlogParams(BaseModel):
    text: str | None = Field(default=None, description="Boot log text to analyse")
    path: str | None = Field(default=None, description="Or a server-side path to a boot log")


class FirmwarePlugin(BasePlugin):
    name = "firmware"
    domain = "firmware"
    title = "Firmware Analysis"
    description = (
        "Static analysis of firmware images: signature carving, entropy profiling, "
        "hard-coded secret detection, component/SBOM inventory, and CVE mapping."
    )

    # ------------------------------------------------------------------ #
    @module(
        name="analyse",
        title="Full firmware analysis",
        safety=Safety.PASSIVE,
        params_model=FirmwareParams,
        tags=["firmware", "static"],
    )
    def analyse(self, ctx: PluginContext, params: FirmwareParams) -> ModuleResult:
        """One-shot firmware assessment: signatures, entropy, secrets, SBOM, CVEs."""
        path = Path(validate_input_path(params.path))
        if not path.exists():
            return ModuleResult(data={"error": "file not found"},
                                summary=f"Firmware file not found: {params.path}")

        ctx.progress(10, "reading image")
        report = helpers.FirmwareReport(size=path.stat().st_size)

        ctx.progress(25, "scanning for embedded signatures")
        if has_tool("binwalk"):
            report.signatures = helpers.binwalk_scan(str(path))
        else:
            carved = helpers.carve(str(path))
            report.signatures = carved["signatures"]
            report.carve_engine = "carve"
            if carved["notes"]:
                report.carve_engine = "carve (notes: " + "; ".join(carved["notes"][:3]) + ")"

        ctx.progress(45, "entropy profiling")
        report.entropy = helpers.entropy_profile(str(path))

        ctx.progress(60, "extracting strings")
        strings = helpers.extract_strings(str(path))

        ctx.progress(70, "scanning for secrets and boot-chain evidence")
        report.secrets = helpers.find_secrets(strings)
        report.components = helpers.find_components(strings)
        report.default_creds = helpers.find_default_credentials(strings)
        report.boot_chain = helpers.audit_boot_chain(strings)

        findings = self._findings_from(report, ctx)

        extraction = None
        extraction_evidence = []
        if params.extract:
            extracted = self.extract(ctx, PathParams(path=str(path)))
            extraction = extracted.data
            extraction_evidence = extracted.evidence
        ctx.progress(95, "writing report")
        ev = ctx.save_evidence(
            EvidenceDraft(kind="firmware", filename=f"firmware_{path.stem}_report.json",
                          content=json.dumps(report.to_dict(), indent=2).encode(),
                          note="firmware analysis report")
        )
        return ModuleResult(
            data={"report": report.to_dict(), "extraction": extraction},
            findings=findings, evidence=[ev, *extraction_evidence],
            summary=f"{report.size} bytes, {len(report.signatures)} signatures, "
                    f"{len(report.secrets)} secret(s), {len(report.components)} component(s), "
                    f"{len(findings)} finding(s).",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="extract",
        title="Analyse: carve / extract files",
        safety=Safety.PASSIVE,
        params_model=PathParams,
        tags=["firmware", "extraction"],
    )
    def extract(self, ctx: PluginContext, params: PathParams) -> ModuleResult:
        """Carve embedded filesystems/archives from an ALREADY-ACQUIRED image
        (binwalk, else the pure-python engine). This is static analysis, not
        device acquisition -- acquire an image first via hardware.filesystem_dump
        or hardware.spi_dump."""
        path = Path(validate_input_path(params.path))
        if not path.exists():
            return ModuleResult(data={"error": "file not found"}, summary="file not found")
        if has_tool("binwalk"):
            ctx.progress(30, "carving with binwalk")
            outdir = ctx.workdir / "binwalk_extract"
            result = helpers.binwalk_extract(str(path), str(outdir))
            engine = "binwalk"
        else:
            ctx.progress(30, "carving with the built-in engine")
            outdir = ctx.workdir / "carve"
            result = helpers.carve(str(path), str(outdir))
            result["signatures"] = [s.to_dict() for s in result["signatures"]]
            result["ok"] = bool(result["extracted"])
            engine = "carve"
        ctx.progress(90, "done")
        if not result.get("ok"):
            return ModuleResult(data=result,
                                summary=f"Extraction ({engine}) found nothing: "
                                        f"{result.get('error', 'no recognisable embedded data')}")
        archive = io.BytesIO()
        files = []
        total = 0
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for file in outdir.rglob("*"):
                if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(outdir.resolve()):
                    continue
                total += file.stat().st_size
                if total > 256 * 1024 * 1024 or len(files) >= 4000:
                    result.setdefault("notes", []).append("download bundle size/file cap reached")
                    break
                name = str(file.relative_to(outdir))
                bundle.write(file, name)
                files.append(name)
        ev = ctx.save_evidence(EvidenceDraft(
            kind="filesystem", filename="extracted_files.zip", content=archive.getvalue(),
            note="Extracted files and carved segments; consult extraction notes for limitations"))
        result["files"] = files
        return ModuleResult(
            data=result,
            evidence=[ev],
            summary=f"Extracted {len(result.get('extracted', []))} entr(ies) with {engine}.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="entropy",
        title="Entropy profile",
        safety=Safety.PASSIVE,
        params_model=PathParams,
        tags=["firmware", "entropy"],
    )
    def entropy(self, ctx: PluginContext, params: PathParams) -> ModuleResult:
        """Per-block entropy to detect encryption/compression and signed regions."""
        path = Path(validate_input_path(params.path))
        if not path.exists():
            return ModuleResult(data={"error": "file not found"}, summary="file not found")
        ctx.progress(40, "computing entropy blocks")
        profile = helpers.entropy_profile(str(path))
        findings: list[FindingDraft] = []
        if profile["encrypted_or_compressed"]:
            findings.append(
                FindingDraft(
                    title="Firmware is largely encrypted or compressed",
                    category="firmware-entropy",
                    severity="info",
                    description=f"{profile['high_entropy_blocks']} high-entropy blocks detected "
                                "(> 7.5 bits/byte) - extraction/secrets analysis will be limited.",
                    remediation="Obtain a decrypted image or extract through the device's own "
                                "firmware-update path for deeper analysis.",
                    evidence={"overall_entropy": profile["overall_entropy"],
                              "high_blocks": profile["high_entropy_blocks"]},
                )
            )
        return ModuleResult(data={"entropy": profile}, findings=findings,
                            summary=f"Overall entropy {profile['overall_entropy']} bits/byte.")

    # ------------------------------------------------------------------ #
    @module(
        name="secrets",
        title="Scan for hard-coded secrets",
        safety=Safety.PASSIVE,
        params_model=PathParams,
        tags=["secrets", "credentials"],
    )
    def secrets(self, ctx: PluginContext, params: PathParams) -> ModuleResult:
        """Detect private keys, cloud credentials, password assignments, shadow hashes."""
        path = Path(validate_input_path(params.path))
        if not path.exists():
            return ModuleResult(data={"error": "file not found"}, summary="file not found")
        ctx.progress(40, "string-scanning for secrets")
        strings = helpers.extract_strings(str(path))
        secrets = helpers.find_secrets(strings)
        creds = helpers.find_default_credentials(strings)
        findings: list[FindingDraft] = []
        for s in secrets:
            findings.append(
                FindingDraft(
                    title=f"Hard-coded {s.kind.replace('-', ' ')} in firmware",
                    category="hardcoded-secret",
                    severity=s.severity,
                    description=f"A {s.kind} value was found in the image: {s.to_dict()['value']} "
                                f"(context: {s.offset_hint[:120]}).",
                    remediation="Remove embedded secrets; provision per-device credentials at "
                                "manufacture or first boot using a secure element.",
                    evidence=s.offset_hint[:400],
                    extra={"kind": s.kind},
                )
            )
        for user, _pw in creds:
            findings.append(
                FindingDraft(
                    title=f"Likely default credential pair in firmware ({user})",
                    category="default-credentials",
                    severity="high",
                    description=f"Both '{user}' and its password appear in the image; this is a "
                                "default-credentials candidate to test on the live device.",
                    remediation="Force credential rotation on first boot; never ship shared defaults.",
                    extra={"username": user},
                )
            )
        return ModuleResult(data={"secrets": [s.to_dict() for s in secrets],
                                  "default_credential_candidates": creds},
                            findings=findings,
                            summary=f"{len(secrets)} secret(s), {len(creds)} default-cred pair(s).")

    # ------------------------------------------------------------------ #
    @module(
        name="sbom",
        title="Component inventory & CVE mapping",
        safety=Safety.PASSIVE,
        params_model=PathParams,
        tags=["sbom", "cve"],
    )
    def sbom(self, ctx: PluginContext, params: PathParams) -> ModuleResult:
        """Identify third-party components/versions and map them to CVEs (SBOM-lite)."""
        path = Path(validate_input_path(params.path))
        if not path.exists():
            return ModuleResult(data={"error": "file not found"}, summary="file not found")
        ctx.progress(30, "extracting strings")
        strings = helpers.extract_strings(str(path))
        ctx.progress(55, "identifying components")
        components = helpers.find_components(strings)
        findings: list[FindingDraft] = []
        for c in components:
            hits = vuln_intel.search_keywords([c.keyword], limit=10)
            for h in hits:
                findings.append(
                    FindingDraft(
                        title=f"{h.id} in {c.name} {c.version or ''}".strip(),
                        category="component-cve",
                        severity=_sev(h.severity, h.cvss),
                        description=f"{c.name} {c.version or ''} -> {h.description[:1000]}",
                        cvss_score=h.cvss, epss_score=h.epss, cve_ids=[h.id],
                        references=h.references,
                        remediation="Patch the component to a fixed release and rebuild the image.",
                        extra={"component": c.name, "version": c.version},
                    )
                )
        ctx.progress(90, "done")
        return ModuleResult(
            data={"components": [c.to_dict() for c in components]},
            findings=findings,
            summary=f"{len(components)} component(s) identified; {len(findings)} CVE(s).",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="boot_chain",
        title="Audit secure boot / debug lock",
        safety=Safety.PASSIVE,
        params_model=PathParams,
        tags=["boot-chain", "secure-boot", "hardware-rooted"],
    )
    def boot_chain(self, ctx: PluginContext, params: PathParams) -> ModuleResult:
        """Static secure-boot evidence: signatures, fuses, rollback, debug locks.

        This is a *string-evidence* audit. It is the fast triage step before
        hardware confirmation (fuse read, boot-ROM behaviour, signed-image
        verification). It does not claim that a control is active or absent
        solely from a match.
        """
        path = Path(validate_input_path(params.path))
        if not path.exists():
            return ModuleResult(data={"error": "file not found"}, summary="file not found")
        ctx.progress(35, "extracting boot-chain strings")
        strings = helpers.extract_strings(str(path))
        ctx.progress(70, "matching secure-boot and debug-lock indicators")
        audit = helpers.audit_boot_chain(strings)
        findings = self._boot_chain_findings(audit)
        ev = ctx.save_evidence(EvidenceDraft(
            kind="boot-chain", filename=f"boot_chain_{path.stem}_{int(time.time())}.json",
            content=json.dumps(audit, indent=2).encode(),
            note="static boot-chain evidence audit (string matches, not hardware proof)",
        ))
        return ModuleResult(
            data={"boot_chain": audit}, findings=findings, evidence=[ev],
            summary=audit["summary"],
        )

    # ------------------------------------------------------------------ #
    @module(
        name="bootlog",
        title="Analyse a boot log",
        safety=Safety.PASSIVE,
        params_model=BootlogParams,
        tags=["bootlog"],
    )
    def bootlog(self, ctx: PluginContext, params: BootlogParams) -> ModuleResult:
        """Analyse boot-log text/uploaded file with the same engine as the UART module."""
        if params.text:
            text = params.text
        elif params.path:
            text = Path(validate_input_path(params.path)).read_text(errors="replace")
        else:
            return ModuleResult(data={"error": "no boot log provided"}, summary="no input")
        ctx.progress(50, "applying boot-log rules")
        report = analyse_bootlog(text)
        findings = [
            FindingDraft(title=f.title, category=f.category, severity=f.severity,
                         description=f.description, remediation=f.remediation,
                         evidence=f.evidence, extra=f.extra)
            for f in report.findings
        ]
        ctx.progress(80, "CVE mapping")
        hits = vuln_intel.search_keywords(report.tokens[:8] + report.versions[:4], limit=20)
        for h in hits:
            findings.append(
                FindingDraft(title=f"{h.id} referenced by boot-log component",
                             category="firmware-cve", severity=_sev(h.severity, h.cvss),
                             description=h.description[:1200], cvss_score=h.cvss,
                             epss_score=h.epss, cve_ids=[h.id], references=h.references)
            )
        return ModuleResult(data={"analysis": report.to_dict(),
                                  "cves": [h.to_dict() for h in hits]},
                            findings=findings,
                            summary=f"{len(report.findings)} boot-log finding(s), {len(hits)} CVE(s).")

    # ------------------------------------------------------------------ #
    @staticmethod
    def _findings_from(report: helpers.FirmwareReport, ctx: PluginContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for s in report.secrets:
            findings.append(
                FindingDraft(
                    title=f"Hard-coded {s.kind.replace('-', ' ')} in firmware",
                    category="hardcoded-secret", severity=s.severity,
                    description=f"Value: {s.to_dict()['value']} (context: {s.offset_hint[:120]}).",
                    remediation="Remove embedded secrets; use per-device provisioning.",
                    evidence=s.offset_hint[:400], extra={"kind": s.kind},
                )
            )
        for user, _pw in report.default_creds:
            findings.append(
                FindingDraft(
                    title=f"Likely default credential pair in firmware ({user})",
                    category="default-credentials", severity="high",
                    description="A username and its default password co-occur in the image.",
                    remediation="Force credential rotation on first boot.",
                    extra={"username": user},
                )
            )
        for c in report.components:
            for h in vuln_intel.search_keywords([c.keyword], limit=8):
                findings.append(
                    FindingDraft(
                        title=f"{h.id} in {c.name} {c.version or ''}".strip(),
                        category="component-cve", severity=_sev(h.severity, h.cvss),
                        description=f"{c.name} {c.version or ''} -> {h.description[:1000]}",
                        cvss_score=h.cvss, epss_score=h.epss, cve_ids=[h.id],
                        references=h.references,
                        remediation="Patch the component and rebuild the image.",
                        extra={"component": c.name, "version": c.version},
                    )
                )
        findings.extend(FirmwarePlugin._boot_chain_findings(report.boot_chain))
        if report.entropy.get("encrypted_or_compressed"):
            findings.append(
                FindingDraft(
                    title="Firmware is largely encrypted/compressed",
                    category="firmware-entropy", severity="info",
                    description="High-entropy blocks dominate; static analysis depth is limited.",
                )
            )
        return findings

    @staticmethod
    def _boot_chain_findings(audit: dict) -> list[FindingDraft]:
        return [
            FindingDraft(
                title=f["title"], category=f.get("category", "boot-chain"),
                severity=f.get("severity", "info"),
                description=f.get("description", ""),
                remediation=f.get("remediation") or "",
                evidence=f.get("evidence"),
                extra=f.get("extra") or {},
            )
            for f in (audit.get("findings") or [])
        ]


def _sev(severity: str, cvss: float | None) -> str:
    if cvss is not None:
        return risk.cvss_to_severity(cvss)
    return severity if severity in risk.SEVERITY_ORDER else "info"
