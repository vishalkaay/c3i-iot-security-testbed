import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, FileText, PlayCircle, Plus, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, downloadFile, openFile } from "../lib/api";
import {
  Card,
  EmptyState,
  ErrorBanner,
  PageHeader,
  SeverityBadge,
  Spinner,
  StatCard,
  StatusChip,
  Table,
} from "../components/ui";
import { cn, fmtDate } from "../lib/utils";

type Tab = "findings" | "assets" | "reports";

export default function EngagementDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("findings");
  const [error, setError] = useState<unknown>(null);

  const eng = useQuery({ queryKey: ["engagement", id], queryFn: () => api.engagement(id) });
  const findings = useQuery({ queryKey: ["findings", id], queryFn: () => api.findings({ engagement_id: id }) });
  const assets = useQuery({ queryKey: ["assets", id], queryFn: () => api.assets(id) });
  const reports = useQuery({ queryKey: ["reports", id], queryFn: () => api.reports(id) });

  const gen = useMutation({
    mutationFn: (kind: string) => api.createReport(id, kind),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports", id] }),
    onError: setError,
  });

  const e = eng.data;
  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "findings", label: "Findings", count: findings.data?.length ?? 0 },
    { key: "assets", label: "Assets", count: assets.data?.length ?? 0 },
    { key: "reports", label: "Reports", count: reports.data?.length ?? 0 },
  ];

  return (
    <div className="space-y-6 fade-in">
      <PageHeader
        title={e?.name || "Engagement"}
        subtitle={e?.description || e?.client || "Assessment workspace and authorization record."}
        meta={
          <>
            {e && <StatusChip status={e.status} />}
            {e?.client && <span className="chip-neutral">{e.client}</span>}
            {e?.roe_accepted_at && (
              <span className="chip border-emerald-800/50 bg-emerald-950/20 text-emerald-300">
                <ShieldCheck className="h-3 w-3" /> RoE signed
              </span>
            )}
            {e?.created_at && <span className="text-[11px] text-slate-500">Created {fmtDate(e.created_at)}</span>}
          </>
        }
        actions={
          <>
            <Link to="/engagements" className="btn-ghost">
              <ArrowLeft className="h-4 w-4" /> All engagements
            </Link>
            <Link className="btn-primary" to={`/runner?engagement=${id}`}>
              <PlayCircle className="h-4 w-4" /> Run a module
            </Link>
          </>
        }
      />

      <ErrorBanner error={error || eng.error || findings.error || assets.error || reports.error} />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Findings" value={findings.data?.length ?? "—"} sub="Across this engagement" />
        <StatCard label="Assets" value={assets.data?.length ?? "—"} sub="Discovered or registered" />
        <StatCard label="Reports" value={reports.data?.length ?? "—"} accent="text-accent" sub="Generated deliverables" />
      </div>

      <Card
        title="Scope & authorization"
        hint={e?.roe_reference ? `Reference ${e.roe_reference}` : "Rules of Engagement"}
        actions={
          <Link to="/engagements" className="text-xs text-accent hover:underline">
            Manage authorization
          </Link>
        }
      >
        {eng.isLoading ? (
          <Spinner />
        ) : (
          <div className="grid gap-6 md:grid-cols-3">
            <div>
              <div className="eyebrow mb-2">Authorized targets</div>
              <div className="flex flex-wrap gap-1.5">
                {e?.authorized_targets?.length ? (
                  e.authorized_targets.map((target) => (
                    <span key={target} className="chip-neutral font-mono normal-case tracking-normal">
                      {target}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-amber-400">Not authorized — sign the RoE before active testing.</span>
                )}
              </div>
            </div>
            <div>
              <div className="eyebrow mb-2">Signed by</div>
              <div className="text-sm text-slate-200">{e?.roe_signed_by || "—"}</div>
              <div className="mt-1 text-[11px] text-slate-500">{e?.roe_reference || "No reference"}</div>
            </div>
            <div>
              <div className="eyebrow mb-2">Validity</div>
              <div className="text-sm text-slate-200">Accepted {fmtDate(e?.roe_accepted_at)}</div>
              <div className="mt-1 text-[11px] text-slate-500">Expires {fmtDate(e?.roe_expires_at)}</div>
            </div>
          </div>
        )}
      </Card>

      <div role="tablist" aria-label="Engagement records" className="flex gap-1 border-b border-ink-700">
        {tabs.map((t) => (
          <button
            key={t.key}
            id={`tab-${t.key}`}
            role="tab"
            aria-selected={tab === t.key}
            aria-controls={`panel-${t.key}`}
            onClick={() => setTab(t.key)}
            className={cn(
              "-mb-px flex items-center gap-2 border-b-2 px-4 py-3 text-xs font-medium transition-colors",
              tab === t.key
                ? "border-accent text-accent"
                : "border-transparent text-slate-400 hover:text-slate-200",
            )}
          >
            {t.label}
            <span className={cn("rounded-sm px-1.5 py-0.5 font-mono text-[10px]", tab === t.key ? "bg-accent/10" : "bg-ink-800")}>
              {t.count}
            </span>
          </button>
        ))}
      </div>

      {tab === "findings" && (
        <div id="panel-findings" role="tabpanel" aria-labelledby="tab-findings">
          <Card title="Assessment findings" hint={`${findings.data?.length ?? 0} total`} dense>
            {findings.isLoading ? (
              <div className="p-5"><Spinner /></div>
            ) : !findings.data?.length ? (
              <EmptyState title="No findings" hint="Run a module against this engagement to populate the assessment." />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Category</th>
                    <th>CVSS</th>
                    <th>CVE</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.data.map((f) => (
                    <tr key={f.id}>
                      <td className="td"><SeverityBadge severity={f.severity} /></td>
                      <td className="td">
                        <div className="font-medium text-slate-200">{f.title}</div>
                        {f.description && (
                          <p className="mt-1 max-w-xl text-[11px] leading-relaxed text-slate-500">{f.description}</p>
                        )}
                      </td>
                      <td className="td text-slate-400">{f.category}</td>
                      <td className="td font-mono text-slate-300">{f.cvss_score?.toFixed(1) ?? "—"}</td>
                      <td className="td font-mono text-[10px] text-slate-500">{f.cve_ids?.join(", ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      )}

      {tab === "assets" && (
        <div id="panel-assets" role="tabpanel" aria-labelledby="tab-assets">
          <Card title="Discovered assets" hint={`${assets.data?.length ?? 0} total`} dense>
            {assets.isLoading ? (
              <div className="p-5"><Spinner /></div>
            ) : !assets.data?.length ? (
              <EmptyState title="No assets discovered" hint="Discovery modules register devices and network services here." />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Identifier</th>
                    <th>Name</th>
                    <th>Vendor</th>
                    <th>Firmware</th>
                    <th>First seen</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.data.map((a) => (
                    <tr key={a.id}>
                      <td className="td capitalize">{a.kind}</td>
                      <td className="td font-mono text-xs text-slate-300">{a.identifier}</td>
                      <td className="td">{a.name || "—"}</td>
                      <td className="td text-slate-400">{a.vendor || "—"}</td>
                      <td className="td text-slate-400">{a.firmware || "—"}</td>
                      <td className="td whitespace-nowrap text-[11px] text-slate-500">{fmtDate(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      )}

      {tab === "reports" && (
        <div id="panel-reports" role="tabpanel" aria-labelledby="tab-reports" className="space-y-5">
          <Card title="Generate report" hint="HTML · PDF · JSON · SARIF">
            <div className="flex flex-wrap items-center gap-2">
              {["html", "pdf", "json", "sarif"].map((kind) => (
                <button key={kind} className="btn-ghost" disabled={gen.isPending} onClick={() => gen.mutate(kind)}>
                  <FileText className="h-4 w-4" /> {kind.toUpperCase()}
                </button>
              ))}
              {gen.isPending && <span className="text-xs text-slate-500">Generating report…</span>}
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-slate-500">
              Reports snapshot the current findings, risk score, and evidence references for this engagement.
            </p>
          </Card>

          <Card title="Generated reports" hint={`${reports.data?.length ?? 0} report(s)`} dense>
            {reports.isLoading ? (
              <div className="p-5"><Spinner /></div>
            ) : !reports.data?.length ? (
              <EmptyState title="No reports yet" hint="Choose a format above to generate your first report." />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <th>Format</th>
                    <th>Created</th>
                    <th>Risk</th>
                    <th><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {reports.data.map((r) => (
                    <tr key={r.id}>
                      <td className="td"><span className="chip-neutral">{r.kind}</span></td>
                      <td className="td whitespace-nowrap text-[11px] text-slate-500">{fmtDate(r.created_at)}</td>
                      <td className="td font-mono text-slate-300">{r.summary?.risk_score ?? "—"}</td>
                      <td className="td">
                        <div className="flex justify-end gap-2">
                          <button className="btn-ghost" onClick={() => openFile(api.reportUrl(r.id, "view")).catch(setError)}>
                            Open
                          </button>
                          <button
                            className="btn-ghost"
                            onClick={() =>
                              downloadFile(api.reportUrl(r.id, "download"), `report.${r.kind}`).catch(setError)
                            }
                          >
                            <Download className="h-3.5 w-3.5" /> Download
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      )}

      <p className="flex items-center gap-1.5 text-xs text-slate-500">
        <Plus className="h-3.5 w-3.5" /> Need more coverage? Run another module from the
        <Link to={`/runner?engagement=${id}`} className="text-accent hover:underline"> module runner</Link>.
      </p>
    </div>
  );
}
