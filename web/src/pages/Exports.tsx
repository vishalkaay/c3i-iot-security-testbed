import { useQuery } from "@tanstack/react-query";
import { Download, ExternalLink, FileText } from "lucide-react";
import { useState } from "react";
import { api, downloadFile, openFile } from "../lib/api";
import {
  Card,
  EmptyState,
  ErrorBanner,
  PageHeader,
  Spinner,
  StatCard,
  StatusDot,
  Table,
} from "../components/ui";
import { fmtBytes, fmtDate } from "../lib/utils";

export default function Exports() {
  const [engagementId, setEngagementId] = useState("");
  const [exportError, setExportError] = useState<unknown>(null);
  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.engagements });
  const exportsQ = useQuery({
    queryKey: ["exports", engagementId],
    queryFn: () => api.exports(engagementId || undefined),
  });
  const jobs = useQuery({ queryKey: ["recentJobs"], queryFn: () => api.jobs({ limit: 15 }) });

  // Reports for all engagements (or the selected one).
  const reportQueries = useQuery({
    queryKey: ["allReports", engagements.data?.map((e) => e.id).join(",")],
    enabled: !!engagements.data?.length,
    queryFn: async () => {
      const lists = await Promise.all(
        engagements.data!.map(async (e) => {
          const reps = await api.reports(e.id);
          return reps.map((r) => ({ ...r, engagementName: e.name }));
        }),
      );
      return lists.flat().sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
  });

  const reports = (reportQueries.data || []).filter(
    (r) => !engagementId || r.engagement_id === engagementId,
  );
  const artefactBytes = exportsQ.data?.reduce((n, e) => n + e.size, 0) ?? 0;
  const successful = jobs.data?.filter((j) => j.status === "succeeded").length ?? 0;

  return (
    <div className="space-y-6 fade-in">
      <PageHeader
        title="Evidence & reports"
        subtitle="Download captured artefacts and generated assessment reports. Every file is content-hashed for integrity."
        meta={
          <>
            <span className="chip-neutral">{exportsQ.data?.length ?? 0} artefacts</span>
            <span className="chip-neutral">{reports.length} reports</span>
          </>
        }
      />

      <ErrorBanner
        error={exportError || exportsQ.error || reportQueries.error || jobs.error || engagements.error}
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Evidence artefacts" value={exportsQ.data?.length ?? "—"} accent="text-accent" sub="Files retained on this host" />
        <StatCard label="Artefact volume" value={fmtBytes(artefactBytes)} sub="Across the current filter" />
        <StatCard label="Reports" value={reports.length || "—"} sub="HTML, PDF, JSON, SARIF" />
        <StatCard label="Successful runs" value={jobs.data ? successful : "—"} sub={`of ${jobs.data?.length ?? 0} recent runs`} />
      </div>

      <section className="card flex flex-wrap items-end gap-4 p-4" aria-label="Filter evidence">
        <div className="w-full max-w-sm">
          <label className="label" htmlFor="export-engagement">Filter by engagement</label>
          <select
            id="export-engagement"
            className="input"
            value={engagementId}
            onChange={(e) => setEngagementId(e.target.value)}
          >
            <option value="">All engagements</option>
            {engagements.data?.map((e) => (
              <option key={e.id} value={e.id}>{e.name}</option>
            ))}
          </select>
        </div>
        <p className="pb-2 text-xs text-slate-500">
          Filters apply to both captured artefacts and reports.
        </p>
      </section>

      <Card
        title="Captured artefacts"
        hint={`${exportsQ.data?.length ?? 0} file(s) · ${fmtBytes(artefactBytes)}`}
        dense
      >
        {exportsQ.isLoading ? (
          <div className="p-5"><Spinner /></div>
        ) : !exportsQ.data?.length ? (
          <EmptyState
            title="No artefacts yet"
            hint="Run a capture module — boot log, traffic capture, SPI dump, or firmware extraction — to produce downloadable evidence."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>File</th>
                <th>Kind</th>
                <th>Source</th>
                <th>Size</th>
                <th>SHA-256</th>
                <th>Created</th>
                <th><span className="sr-only">Download</span></th>
              </tr>
            </thead>
            <tbody>
              {exportsQ.data.map((e) => (
                <tr key={e.id}>
                  <td className="td">
                    <div className="max-w-[260px] truncate font-mono text-xs text-slate-200" title={e.filename}>
                      {e.filename}
                    </div>
                    {e.note && <div className="mt-1 max-w-[320px] truncate text-[10px] text-slate-500">{e.note}</div>}
                  </td>
                  <td className="td"><span className="chip-neutral normal-case tracking-normal">{e.kind}</span></td>
                  <td className="td font-mono text-[10px] text-slate-500">{e.plugin}.{e.action}</td>
                  <td className="td whitespace-nowrap text-slate-400">{fmtBytes(e.size)}</td>
                  <td className="td font-mono text-[10px] text-slate-500" title={e.sha256}>
                    {e.sha256 ? `${e.sha256.slice(0, 16)}…` : "—"}
                  </td>
                  <td className="td whitespace-nowrap text-[11px] text-slate-500">{fmtDate(e.created_at)}</td>
                  <td className="td">
                    <button
                      className="btn-ghost"
                      onClick={() => downloadFile(e.download_url, e.filename).catch(setExportError)}
                    >
                      <Download className="h-3.5 w-3.5" /> Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Card title="Assessment reports" hint={`${reports.length} report(s)`} dense>
        {reportQueries.isLoading ? (
          <div className="p-5"><Spinner /></div>
        ) : !reports.length ? (
          <EmptyState
            title="No reports yet"
            hint="Open an engagement and use the Reports tab to generate HTML, PDF, JSON, or SARIF."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Engagement</th>
                <th>Format</th>
                <th>Risk score</th>
                <th>Created</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td className="td text-slate-200">{r.engagementName}</td>
                  <td className="td"><span className="chip-neutral">{r.kind}</span></td>
                  <td className="td font-mono text-slate-300">{r.summary?.risk_score ?? "—"}</td>
                  <td className="td whitespace-nowrap text-[11px] text-slate-500">{fmtDate(r.created_at)}</td>
                  <td className="td">
                    <div className="flex justify-end gap-2">
                      <button
                        className="btn-ghost"
                        onClick={() => openFile(api.reportUrl(r.id, "view")).catch(setExportError)}
                      >
                        <ExternalLink className="h-3.5 w-3.5" /> Open
                      </button>
                      <button
                        className="btn-ghost"
                        onClick={() =>
                          downloadFile(api.reportUrl(r.id, "download"), `report.${r.kind}`).catch(setExportError)
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

      <Card title="Recent runs" hint="Most recent 15" dense>
        {jobs.isLoading ? (
          <div className="p-5"><Spinner /></div>
        ) : !jobs.data?.length ? (
          <EmptyState title="No runs yet" hint="Use the module runner to produce evidence." />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Module</th>
                <th>Status</th>
                <th>Summary</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {jobs.data.map((j) => (
                <tr key={j.id}>
                  <td className="td font-mono text-xs text-slate-300">{j.plugin}.{j.action}</td>
                  <td className="td"><StatusDot status={j.status} /></td>
                  <td className="td max-w-[420px] truncate text-xs text-slate-500" title={j.message || j.error || ""}>
                    {j.message || j.error || "—"}
                  </td>
                  <td className="td whitespace-nowrap text-[11px] text-slate-500">{fmtDate(j.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <p className="flex items-center gap-1.5 text-xs text-slate-500">
        <FileText className="h-3.5 w-3.5" /> Artefacts are stored on the backend host under
        <code className="mx-1 rounded border border-ink-700 bg-ink-950 px-1.5 py-0.5 font-mono text-[10px] text-accent">
          data/evidence/&lt;job-id&gt;/
        </code>
      </p>
    </div>
  );
}
