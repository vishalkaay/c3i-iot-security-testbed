import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowUpRight, Download, Play, Square, Terminal, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, downloadFile } from "../lib/api";
import { Card, EmptyState, ErrorBanner, PageHeader, SafetyBadge, StatusDot } from "../components/ui";
import ResultView from "../components/ResultView";
import { cn, fmtBytes } from "../lib/utils";

const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

function ParamField({ name, schema, value, required, onChange }: { name: string; schema: any; value: any; required: boolean; onChange: (v: any) => void }) {
  const definition = schema.anyOf?.find((s: any) => s.type !== "null") || schema;
  const type = definition.type;
  const id = `param-${name}`;
  const label = schema.title || name.replaceAll("_", " ");
  const numeric = type === "integer" || type === "number";
  if (type === "boolean") return <label className="flex items-start gap-3 rounded border border-ink-700 p-3 text-xs" htmlFor={id}>
    <input id={id} type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} className="mt-0.5" />
    <span><span className="text-slate-200">{label}</span>{schema.description && <span className="mt-1 block leading-relaxed text-slate-500">{schema.description}</span>}</span>
  </label>;
  return <div>
    <label className="label" htmlFor={id}>{label}{required && <span className="ml-1 text-accent">*</span>}</label>
    {definition.enum ? <select id={id} className="input" value={value ?? ""} onChange={(e) => onChange(e.target.value)}>{definition.enum.map((x: string) => <option key={x}>{x}</option>)}</select> :
      <input id={id} className={cn("input", type === "array" && "font-mono text-xs")} type={numeric ? "number" : /password|secret|token/i.test(name) ? "password" : "text"}
        required={required} min={definition.minimum} max={definition.maximum} step={type === "integer" ? 1 : numeric ? "any" : undefined}
        value={Array.isArray(value) ? value.join(", ") : value ?? ""} placeholder={schema.default != null ? String(schema.default) : required ? "Required" : "Optional"}
        autoComplete={/password|secret|token/i.test(name) ? "off" : undefined}
        onChange={(e) => onChange(type === "array" ? e.target.value.split(",").map((s) => s.trim()).filter(Boolean).map((s) => definition.items?.type === "integer" || definition.items?.type === "number" ? Number(s) : s) : numeric && e.target.value !== "" ? Number(e.target.value) : e.target.value)} />}
    {schema.description && <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">{schema.description}</p>}
  </div>;
}

export default function Runner() {
  const [search] = useSearchParams();
  const qc = useQueryClient();
  const [engagementId, setEngagementId] = useState(search.get("engagement") || "");
  const [pluginName, setPluginName] = useState(search.get("plugin") || "bluetooth");
  const [moduleName, setModuleName] = useState(search.get("module") || "");
  const [values, setValues] = useState<Record<string, any>>({});
  const [jobId, setJobId] = useState<string | null>(search.get("job"));
  const [error, setError] = useState<unknown>(null);
  const [preflight, setPreflight] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const lastTerminal = useRef<string | null>(null);
  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.engagements });
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins });
  const plugin = plugins.data?.find((p) => p.name === pluginName);
  const spec = plugin?.modules.find((m) => m.name === moduleName);
  const job = useQuery({ queryKey: ["runnerJob", jobId], queryFn: () => api.job(jobId!), enabled: !!jobId,
    refetchInterval: (q) => q.state.data && TERMINAL.has(q.state.data.status) ? false : 1000 });
  const active = !!jobId && !TERMINAL.has(job.data?.status || "");
  const logs = useQuery({ queryKey: ["runnerLogs", jobId], queryFn: () => api.jobLogs(jobId!), enabled: !!jobId, refetchInterval: active ? 1000 : false });
  const evidence = useQuery({ queryKey: ["jobEvidence", jobId], queryFn: () => api.jobEvidence(jobId!), enabled: !!jobId && !active });
  useEffect(() => {
    setPluginName(search.get("plugin") || "bluetooth"); setModuleName(search.get("module") || "");
    setJobId(search.get("job")); setEngagementId(search.get("engagement") || ""); setError(null);
  }, [search]);
  useEffect(() => {
    const next: Record<string, any> = {};
    Object.entries(spec?.params_schema.properties || {}).forEach(([k, s]: [string, any]) => { if (s.default !== undefined && s.default !== null) next[k] = s.default; });
    setValues(next);
    setPreflight(false);
  }, [spec]);
  useEffect(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight }); }, [logs.data]);
  useEffect(() => {
    if (jobId && job.data && TERMINAL.has(job.data.status) && lastTerminal.current !== jobId) {
      lastTerminal.current = jobId;
      qc.invalidateQueries({ queryKey: ["runnerLogs", jobId] });
      for (const key of ["summary", "findings", "recentJobs", "exports"]) qc.invalidateQueries({ queryKey: [key] });
    }
  }, [job.data, jobId, qc]);
  const run = useMutation({
    mutationFn: () => api.createJob({ engagement_id: engagementId || undefined, plugin: pluginName, action: moduleName,
      params: Object.fromEntries(Object.entries(values).filter(([key, value]) => value !== "" || spec?.params_schema.required?.includes(key) || key === "password")) }),
    onMutate: () => setError(null),
    onSuccess: (j) => { qc.setQueryData(["runnerJob", j.id], j); setJobId(j.id); }, onError: setError,
  });
  const cancel = useMutation({ mutationFn: () => api.cancelJob(jobId!), onSuccess: () => qc.invalidateQueries({ queryKey: ["runnerJob", jobId] }), onError: setError });
  const upload = useMutation({ mutationFn: (file: File) => api.upload(file), onSuccess: (r) => setValues((v) => ({ ...v, path: r.path })), onError: setError });
  const props = spec?.params_schema.properties || {};
  const progress = Math.max(0, Math.min(100, job.data?.progress || 0));
  const busy = active || run.isPending;
  const invasive = spec?.safety === "invasive";
  const preflightBlocked = invasive && !preflight;
  return <div className="mx-auto space-y-6 fade-in">
    <PageHeader title="Module runner" subtitle="Configure a target, run an assessment, and follow the evidence."
      actions={<Link to="/plugins" className="btn-ghost">Module catalogue <ArrowUpRight className="h-3.5 w-3.5" /></Link>} />
    <ErrorBanner error={error || job.error || logs.error || evidence.error || plugins.error || engagements.error} />
    <div className="grid items-start gap-5 lg:grid-cols-[340px_minmax(0,1fr)] xl:grid-cols-[370px_minmax(0,1fr)]">
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (!busy && spec && !preflightBlocked) run.mutate(); }}>
        <Card title="01 / Configure assessment" className="card-stack">
          <div><label htmlFor="runner-engagement" className="label">Engagement</label><select id="runner-engagement" className="input" value={engagementId} disabled={busy} onChange={(e) => setEngagementId(e.target.value)}><option value="">Unattached · passive modules only</option>{engagements.data?.map((e) => <option key={e.id} value={e.id}>{e.name} ({e.status})</option>)}</select></div>
          <div><label htmlFor="runner-domain" className="label">Security domain</label><select id="runner-domain" className="input" value={pluginName} disabled={busy} onChange={(e) => { setPluginName(e.target.value); setModuleName(""); }}><option value="" disabled>Choose a domain</option>{plugins.data?.map((p) => <option key={p.name} value={p.name}>{p.title}</option>)}</select></div>
          <div><label htmlFor="runner-module" className="label">Module</label><select id="runner-module" className="input" value={moduleName} disabled={busy} onChange={(e) => setModuleName(e.target.value)}><option value="">Choose a module…</option>{plugin?.modules.map((m) => <option key={m.name} value={m.name}>{m.title}</option>)}</select></div>
          {spec && <div className="rounded border border-ink-700 bg-ink-950 p-3"><div className="mb-2 flex items-center justify-between gap-2"><code className="text-[10px] text-slate-400">{pluginName}.{moduleName}</code><SafetyBadge safety={spec.safety} /></div><p className="text-xs leading-relaxed text-slate-400">{spec.description}</p></div>}
        </Card>
        {spec && <Card title="02 / Parameters" className="card-stack">
          {spec.missing_capabilities.length > 0 && <div className="flex gap-2 rounded border border-amber-800/50 bg-amber-950/20 p-3 text-xs text-amber-300"><AlertTriangle className="h-4 w-4 shrink-0" /><span>Unavailable capabilities: {spec.missing_capabilities.join(", ")}. Results depend on the module's fallback support.</span></div>}
          <fieldset disabled={busy} className="space-y-4">{Object.entries(props).map(([name, schema]) => <ParamField key={name} name={name} schema={schema} value={values[name]} required={!!spec.params_schema.required?.includes(name)} onChange={(v) => setValues((s) => ({ ...s, [name]: v }))} />)}</fieldset>
          {!Object.keys(props).length && <p className="text-xs text-slate-500">This module needs no additional parameters.</p>}
          {"path" in props && <label className="btn-ghost relative w-full cursor-pointer"><Upload className="h-4 w-4" />{upload.isPending ? "Uploading…" : "Choose firmware or capture"}<input aria-label="Upload artefact" type="file" className="absolute inset-0 cursor-pointer opacity-0" disabled={busy || upload.isPending} onChange={(e) => e.target.files?.[0] && upload.mutate(e.target.files[0])} /></label>}
          {invasive && <div className="rounded border border-amber-800/60 bg-amber-950/20 p-3 text-xs text-amber-200">
            <div className="mb-2 flex items-center gap-2 font-medium"><AlertTriangle className="h-4 w-4 shrink-0" /> Invasive module — pre-flight checklist</div>
            <ul className="mb-3 list-disc space-y-1 pl-5 text-[11px] leading-relaxed text-amber-200/90">
              <li>Target is powered <strong>off</strong> before wiring; probe ground is common with the DUT.</li>
              <li>The chip/package and logic voltage are confirmed (run <span className="font-mono">spi_identify</span> first for SPI).</li>
              <li>This target is in the signed Rules of Engagement and may be disrupted or power-cycled.</li>
              <li>A rollback plan exists and this is a maintenance window if the device is in use.</li>
            </ul>
            <label className="flex items-start gap-2"><input type="checkbox" className="mt-0.5" checked={preflight} onChange={(e) => setPreflight(e.target.checked)} /><span>I have completed these checks and am authorized to run this invasive module.</span></label>
          </div>}
          <button className="btn-primary w-full" disabled={busy || upload.isPending || preflightBlocked} type="submit"><Play className="h-3.5 w-3.5" />{run.isPending ? "Starting…" : active ? "Assessment in progress" : preflightBlocked ? "Confirm the checklist to run" : "Run assessment"}</button>
        </Card>}
      </form>
      <div className="min-w-0 space-y-5">
        <Card title="Execution console" dense actions={<div className="flex items-center gap-3">{jobId ? <StatusDot status={job.data?.status || "queued"} /> : <span className="chip-neutral">Standby</span>}{active && <button className="btn-ghost text-amber-300" disabled={cancel.isPending} onClick={() => cancel.mutate()}><Square className="h-3 w-3" />{cancel.isPending ? "Stopping…" : "Cancel"}</button>}</div>}>
          <div className="flex items-center justify-between gap-3 px-5 py-3 text-[10px] text-slate-500"><span className="truncate font-mono">{jobId ? `JOB ${jobId}` : "No active job"}</span><span className="font-mono">{progress}%</span></div>
          <div role="progressbar" aria-label="Assessment progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress} className="h-0.5 bg-ink-800"><div className="h-full bg-accent transition-all" style={{ width: `${progress}%` }} /></div>
          <div ref={logRef} role="log" aria-label="Execution log" className="h-[310px] overflow-auto bg-[#080d11] p-5 font-mono text-xs leading-6">
            {!logs.data?.length ? <div className="flex h-full flex-col items-center justify-center text-slate-600"><Terminal className="mb-4 h-8 w-8" strokeWidth={1.2} /><span className="text-slate-400">{active ? "Waiting for the first event…" : "Ready when you are."}</span><span className="mt-1 text-[11px]">{active ? "Job status refreshes every second." : "Select a module to begin an assessment."}</span></div> : logs.data.map((l, i) => <div key={i} className="flex gap-3"><span className="w-6 shrink-0 select-none text-right text-slate-600">{String(i + 1).padStart(2, "0")}</span><span className={cn("break-words whitespace-pre-wrap", l.level === "error" ? "text-red-300" : l.level === "warn" ? "text-amber-300" : "text-slate-300")}>{l.message}</span></div>)}
          </div>
          {job.data?.message && <p className="border-t border-ink-700 px-5 py-3 text-xs text-slate-400">{job.data.message}</p>}
        </Card>
        <ErrorBanner error={job.data?.error} />
        {job.data?.status === "cancelled" && <p role="status" className="rounded border border-amber-900/50 bg-amber-950/20 p-3 text-xs text-amber-300">Assessment cancelled. Any saved partial evidence is retained.</p>}
        <Card title="Results & evidence" hint={active ? "Collecting" : jobId ? "Latest job" : undefined}>
          {evidence.data && evidence.data.length > 0 && <div className="mb-5 flex flex-wrap gap-2">{evidence.data.map((e) => <button key={e.id} className="btn-ghost max-w-full text-xs" onClick={() => downloadFile(api.evidenceDownloadUrl(jobId!, e.id), e.filename).catch(setError)}><Download className="h-3.5 w-3.5 shrink-0" /><span className="truncate">{e.filename}</span><span className="shrink-0 text-slate-500">{fmtBytes(e.size)}</span></button>)}</div>}
          {job.data?.result ? <ResultView key={jobId} result={job.data.result} /> : <EmptyState title={active ? "Evidence is being collected" : "Results will appear here"} hint="Structured results, device details, and downloadable artefacts from your assessment." />}
        </Card>
      </div>
    </div>
  </div>;
}
