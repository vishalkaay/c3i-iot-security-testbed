"""Report generation: JSON, SARIF, self-contained HTML, and PDF."""

from __future__ import annotations

import datetime as dt
import html
import json
from pathlib import Path

from app.core.config import settings
from app.services.risk import engagement_risk_score, summary_counts

SEV_COLORS = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#0369a1", "info": "#475569",
}


def _now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC")


def build_dataset(engagement, assets, findings, jobs) -> dict:
    fdicts = [
        {
            "id": f.id, "title": f.title, "category": f.category, "domain": f.domain,
            "severity": f.severity, "cvss": f.cvss_score, "epss": f.epss_score,
            "cve_ids": f.cve_ids or [], "description": f.description, "evidence": f.evidence,
            "remediation": f.remediation, "references": f.references or [],
            "asset_id": f.asset_id, "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]
    return {
        "generated_at": _now(),
        "engagement": {
            "id": engagement.id, "name": engagement.name, "client": engagement.client,
            "status": engagement.status, "description": engagement.description,
            "roe_signed_by": engagement.roe_signed_by, "roe_reference": engagement.roe_reference,
            "authorized_targets": engagement.authorized_targets or [],
        },
        "summary": {
            "counts": summary_counts(fdicts),
            "risk_score": engagement_risk_score(fdicts),
            "total_findings": len(fdicts),
        },
        "assets": [
            {"id": a.id, "kind": a.kind, "identifier": a.identifier, "name": a.name,
             "vendor": a.vendor, "model": a.model, "firmware": a.firmware}
            for a in assets
        ],
        "findings": fdicts,
        "jobs": [
            {"id": j.id, "plugin": j.plugin, "action": j.action, "status": j.status,
             "safety": j.safety, "created_at": j.created_at.isoformat(),
             "message": j.message}
            for j in jobs
        ],
    }


# --------------------------------------------------------------------------- #
# JSON / SARIF
# --------------------------------------------------------------------------- #
def render_json(dataset: dict) -> bytes:
    return json.dumps(dataset, indent=2).encode()


def render_sarif(dataset: dict) -> bytes:
    rules: dict[str, dict] = {}
    results = []
    for f in dataset["findings"]:
        rule_id = f"c3i.{f['category']}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f["category"],
                "shortDescription": {"text": f["category"].replace("-", " ").title()},
                "properties": {"domain": f["domain"]},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning",
                          "low": "note", "info": "note"}.get(f["severity"], "note"),
                "message": {"text": f"{f['title']} :: {f.get('description') or ''}"[:1000]},
                "properties": {
                    "severity": f["severity"], "cvss": f.get("cvss"),
                    "cve_ids": f.get("cve_ids"), "remediation": f.get("remediation"),
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "C3i IoT Security Testbed",
                                    "version": "2.0.0",
                                    "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2).encode()


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def render_html(dataset: dict) -> bytes:
    eng = dataset["engagement"]
    summ = dataset["summary"]
    counts = summ["counts"]

    def chip(sev: str) -> str:
        return (f'<span style="background:{SEV_COLORS.get(sev, "#475569")};color:#fff;'
                f'padding:2px 8px;border-radius:10px;font-size:11px;text-transform:uppercase">'
                f'{html.escape(sev)}</span>')

    rows = []
    for f in sorted(dataset["findings"], key=lambda x: ("critical", "high", "medium", "low", "info").index(x["severity"])):
        cves = ", ".join(f["cve_ids"]) if f["cve_ids"] else "&mdash;"
        cvss = f"{f['cvss']:.1f}" if f["cvss"] else "&mdash;"
        rows.append(
            f"<tr><td>{chip(f['severity'])}</td><td><strong>{html.escape(f['title'])}</strong>"
            f"<div class='muted'>{html.escape(f['category'])}</div></td>"
            f"<td>{cvss}</td><td>{html.escape(cves)}</td>"
            f"<td>{html.escape((f['description'] or '')[:400])}"
            f"<div class='fix'><b>Fix:</b> {html.escape((f['remediation'] or '')[:400])}</div></td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='5'>No findings recorded.</td></tr>")
    cve_note = (
        "<p class='muted' style='margin-top:10px;font-size:11px'>"
        "CVE entries are <strong>candidate</strong> matches derived from component/version "
        "strings and are not proof of exploitability; confirm against the device and prioritise "
        "using the CVSS and EPSS signal.</p>"
        if any(f["cve_ids"] for f in dataset["findings"]) else ""
    )

    asset_rows = "".join(
        f"<tr><td>{html.escape(a['kind'])}</td><td>{html.escape(a['identifier'])}</td>"
        f"<td>{html.escape(a['name'] or '')}</td><td>{html.escape(a['vendor'] or '')}</td>"
        f"<td>{html.escape(a['firmware'] or '')}</td></tr>"
        for a in dataset["assets"]
    ) or "<tr><td colspan='5'>No assets.</td></tr>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>IoT Security Report &mdash; {html.escape(eng['name'])}</title>
<style>
 body{{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0b1020;color:#e5e7eb}}
 .wrap{{max-width:1080px;margin:0 auto;padding:32px}}
 header{{border-bottom:1px solid #1f2937;padding-bottom:16px;margin-bottom:24px}}
 h1{{margin:0 0 4px;font-size:26px}} .muted{{color:#94a3b8;font-size:12px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}}
 .card{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px 18px;min-width:120px}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{color:#94a3b8;font-size:12px;text-transform:uppercase}}
 table{{width:100%;border-collapse:collapse;margin:8px 0 28px;font-size:13px}}
 th,td{{text-align:left;padding:10px;border-bottom:1px solid #1f2937;vertical-align:top}}
 th{{color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.04em}}
 .fix{{margin-top:6px;color:#7dd3fc;font-size:12px}}
 footer{{color:#64748b;font-size:12px;border-top:1px solid #1f2937;padding-top:14px;margin-top:20px}}
</style></head>
<body><div class="wrap">
<header>
  <h1>IoT Security Assessment Report</h1>
  <div class="muted">{html.escape(eng['name'])} &middot; client: {html.escape(eng['client'] or 'n/a')}
    &middot; status: {html.escape(eng['status'])}</div>
  <div class="muted">Authorized by {html.escape(eng['roe_signed_by'] or 'n/a')}
    (ref {html.escape(eng['roe_reference'] or 'n/a')}) &middot; generated {dataset['generated_at']}</div>
</header>
<div class="cards">
  <div class="card"><div class="n" style="color:{SEV_COLORS['critical']}">{counts['critical']}</div><div class="l">Critical</div></div>
  <div class="card"><div class="n" style="color:{SEV_COLORS['high']}">{counts['high']}</div><div class="l">High</div></div>
  <div class="card"><div class="n" style="color:{SEV_COLORS['medium']}">{counts['medium']}</div><div class="l">Medium</div></div>
  <div class="card"><div class="n" style="color:{SEV_COLORS['low']}">{counts['low']}</div><div class="l">Low</div></div>
  <div class="card"><div class="n">{summ['risk_score']}</div><div class="l">Risk score /100</div></div>
  <div class="card"><div class="n">{summ['total_findings']}</div><div class="l">Total findings</div></div>
</div>
<h2>Assets in scope</h2>
<table><thead><tr><th>Domain</th><th>Identifier</th><th>Name</th><th>Vendor</th><th>Firmware</th></tr></thead>
<tbody>{asset_rows}</tbody></table>
<h2>Findings</h2>
<table><colgroup><col style="width:90px"><col><col style="width:60px"><col style="width:150px"><col></colgroup>
<thead><tr><th>Severity</th><th>Finding</th><th>CVSS</th><th>CVE</th><th>Detail</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{cve_note}
<footer>
 Authorized scope: {html.escape(', '.join(eng['authorized_targets']) or 'n/a')}<br>
 Generated by the C3i Hub IoT Security Testbed v2.0. This report is confidential and
 intended solely for the commissioning party named above.
</footer>
</div></body></html>""".encode("utf-8")


def render_pdf(dataset: dict) -> bytes:
    """Minimal, dependency-light PDF using reportlab."""
    try:
        from io import BytesIO

        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except Exception:
        # Fall back to HTML if reportlab isn't installed.
        return render_html(dataset)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="IoT Security Assessment Report")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("IoT Security Assessment Report", styles["Title"]),
        Paragraph(
            f"{dataset['engagement']['name']} &mdash; {dataset['engagement']['client'] or ''}",
            styles["Normal"],
        ),
        Paragraph(f"Generated {dataset['generated_at']}", styles["Italic"]),
        Spacer(1, 8 * mm),
    ]
    counts = dataset["summary"]["counts"]
    story.append(
        Paragraph(
            f"Risk score: {dataset['summary']['risk_score']}/100 &nbsp;&middot;&nbsp; "
            f"Critical {counts['critical']} &middot; High {counts['high']} &middot; "
            f"Medium {counts['medium']} &middot; Low {counts['low']}",
            styles["Heading2"],
        )
    )
    data = [["Severity", "Finding", "CVSS", "CVE"]]
    for f in dataset["findings"][:200]:
        data.append([
            f["severity"].upper(),
            Paragraph(html.escape(f["title"]), styles["Normal"]),
            f"{f['cvss']:.1f}" if f["cvss"] else "-",
            ", ".join(f["cve_ids"])[:40] or "-",
        ])
    table = Table(data, colWidths=[22 * mm, 100 * mm, 15 * mm, 30 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    if any(f["cve_ids"] for f in dataset["findings"]):
        story.append(Paragraph(
            "CVE entries are candidate matches from component/version strings, not proof "
            "of exploitability; confirm against the device and prioritise with CVSS/EPSS.",
            styles["Italic"]))
    doc.build(story)
    return buf.getvalue()


RENDERERS = {
    "json": (render_json, "json"),
    "sarif": (render_sarif, "sarif.json"),
    "html": (render_html, "html"),
    "pdf": (render_pdf, "pdf"),
}


def generate(dataset: dict, kind: str, engagement_id: str) -> tuple[Path, str]:
    renderer, ext = RENDERERS.get(kind, RENDERERS["html"])
    out_dir = settings.reports_dir / engagement_id
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"report_{stamp}.{ext}"
    path.write_bytes(renderer(dataset))
    return path, ext
