import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/api";
import { Card, EmptyState, ErrorBanner, PageHeader, SeverityBadge, Spinner } from "../components/ui";
import { SEVERITIES } from "../lib/utils";

export default function Findings() {
  const [engagementId, setEngagementId] = useState("");
  const [severity, setSeverity] = useState("");
  const [domain, setDomain] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.engagements });
  const findings = useQuery({
    queryKey: ["findings", engagementId, severity, domain],
    queryFn: () =>
      api.findings({
        engagement_id: engagementId || undefined,
        severity: severity || undefined,
        domain: domain || undefined,
      }),
  });

  const filtered = findings.data?.filter((f) => `${f.title} ${f.category} ${f.cve_ids.join(" ")}`.toLowerCase().includes(search.toLowerCase()));
  return (
    <div className="mx-auto max-w-[1300px] space-y-6 fade-in">
      <PageHeader
        title="Finding intelligence"
        subtitle="Triage the signal. Inspect the evidence. Prioritize remediation."
        meta={
          <>
            <span className="chip-neutral">{findings.data?.length ?? 0} total</span>
            <span className="chip-neutral">{filtered?.length ?? 0} shown</span>
          </>
        }
      />
      <ErrorBanner error={findings.error || engagements.error} />

      <Card title="Filters">
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <div><label htmlFor="finding-search" className="label">Search findings</label><div className="relative"><Search className="absolute left-3 top-3 h-4 w-4 text-slate-500" /><input id="finding-search" className="input pl-9" placeholder="Title, category, CVE…" value={search} onChange={(e) => setSearch(e.target.value)} /></div></div>
          <div>
            <label className="label" htmlFor="finding-engagement">Engagement</label>
            <select id="finding-engagement" className="input" value={engagementId} onChange={(e) => setEngagementId(e.target.value)}>
              <option value="">All</option>
              {engagements.data?.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="finding-severity">Severity</label>
            <select id="finding-severity" className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="finding-domain">Domain</label>
            <select id="finding-domain" className="input" value={domain} onChange={(e) => setDomain(e.target.value)}>
              <option value="">All</option>
              {["bluetooth", "wifi", "hardware", "firmware"].map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      <Card title="Assessment findings" hint={`${filtered?.length ?? 0} shown`}>
        {findings.isLoading ? (
          <Spinner />
        ) : !filtered?.length ? (
          <EmptyState title="No findings match the filters" />
        ) : (
          <div className="divide-y divide-ink-800">
            {filtered.map((f) => (
              <div key={f.id}>
                <button
                  className="w-full flex flex-wrap items-center gap-3 py-4 text-left hover:bg-ink-850/50 px-2 rounded"
                  aria-expanded={open === f.id}
                  onClick={() => setOpen(open === f.id ? null : f.id)}
                >
                  {open === f.id ? (
                    <ChevronDown className="h-4 w-4 text-slate-500" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-slate-500" />
                  )}
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-[140px] flex-1 text-sm text-slate-200">{f.title}</span>
                  <span className="text-xs text-slate-500">{f.domain}</span>
                  {f.cvss_score != null && (
                    <span className="text-xs text-slate-400 font-mono">CVSS {f.cvss_score.toFixed(1)}</span>
                  )}
                </button>
                {open === f.id && (
                  <div className="pl-8 pb-4 space-y-3 text-sm">
                    <div>
                      <div className="label">Category</div>
                      <div className="text-slate-300">{f.category}</div>
                    </div>
                    {f.description && (
                      <div>
                        <div className="label">Description</div>
                        <p className="text-slate-300 whitespace-pre-wrap">{f.description}</p>
                      </div>
                    )}
                    {f.evidence && (
                      <div>
                        <div className="label">Evidence</div>
                        <pre className="terminal max-h-56 overflow-auto whitespace-pre-wrap p-3">
                          {f.evidence}
                        </pre>
                      </div>
                    )}
                    {f.remediation && (
                      <div>
                        <div className="label">Remediation</div>
                        <p className="text-emerald-300/90">{f.remediation}</p>
                      </div>
                    )}
                    {f.cve_ids?.length > 0 && (
                      <div>
                        <div className="label flex flex-wrap items-center gap-2">
                          CVE candidates
                          {f.epss_score != null && (
                            <span className="chip-neutral font-mono normal-case tracking-normal" title="EPSS: probability of exploitation in the next 30 days">
                              EPSS {(f.epss_score * 100).toFixed(1)}%
                            </span>
                          )}
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {f.cve_ids.map((c) => (
                            <a
                              key={c}
                              className="chip bg-ink-800 text-sky-300 border border-ink-700 font-mono hover:border-sky-700"
                              href={`https://nvd.nist.gov/vuln/detail/${c}`}
                              target="_blank"
                              rel="noreferrer"
                            >
                              {c}
                            </a>
                          ))}
                        </div>
                        <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                          Candidate match from component/version strings — not proof of exploitability.
                          Confirm against the device; prioritise with CVSS and EPSS.
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
