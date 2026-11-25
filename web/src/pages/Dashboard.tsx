import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowRight, ArrowUpRight, Bluetooth, Check, ChevronRight, Cpu, FileCode2, Plus, Wifi } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { Card, EmptyState, ErrorBanner, PageHeader, SeverityBadge, Spinner, StatCard, StatusDot, Table } from "../components/ui";
import { cn, fmtDate } from "../lib/utils";

const DOMAINS = [
  { key: "bluetooth", title: "Bluetooth & BLE", icon: Bluetooth, color: "text-sky-400", bg: "bg-sky-400/10", description: "Discovery, device profiles & GATT", module: "scan" },
  { key: "wifi", title: "Wi-Fi & network", icon: Wifi, color: "text-accent", bg: "bg-accent/10", description: "Services, wireless posture & TLS", module: "portscan" },
  { key: "hardware", title: "Hardware", icon: Cpu, color: "text-orange-300", bg: "bg-orange-300/10", description: "UART consoles, flash & the rig", module: "hardware_info" },
  { key: "firmware", title: "Firmware", icon: FileCode2, color: "text-violet-300", bg: "bg-violet-300/10", description: "Filesystems, secrets & components", module: "analyse" },
];
const SEVERITIES = [
  ["critical", "bg-red-400"], ["high", "bg-orange-400"], ["medium", "bg-amber-400"], ["low", "bg-sky-400"], ["info", "bg-slate-500"],
];

export default function Dashboard() {
  const info = useQuery({ queryKey: ["systemInfo"], queryFn: api.systemInfo });
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.findingsSummary() });
  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.engagements });
  const jobs = useQuery({ queryKey: ["recentJobs"], queryFn: () => api.jobs({ limit: 6 }), refetchInterval: 10000 });
  const exportsQ = useQuery({ queryKey: ["exports", ""], queryFn: () => api.exports() });
  const s = summary.data;
  const missing = info.data?.capabilities.filter((c) => !c.available).length;
  const ready = info.data?.capabilities.filter((c) => c.available).length;
  const steps = [
    { title: "Define the scope", subtitle: "Create an engagement", to: "/engagements", done: !!engagements.data?.length },
    { title: "Run an assessment", subtitle: "Choose a domain & module", to: "/runner", done: !!jobs.data?.length },
    { title: "Review the evidence", subtitle: "Triage findings", to: "/findings", done: !!s?.total },
    { title: "Deliver your report", subtitle: "Export results & artefacts", to: "/exports", done: !!exportsQ.data?.length },
  ];
  return <div className="mx-auto space-y-7 fade-in">
    <PageHeader title="Assessment overview" subtitle="Your devices, evidence, and security posture. One workspace."
      meta={<span className="eyebrow mt-1">C3i Hub · IoT security testbed</span>}
      actions={<><Link to="/engagements" className="btn-ghost"><Plus className="h-4 w-4" /> Engagement</Link><Link to="/runner" className="btn-primary">Run assessment <ArrowUpRight className="h-4 w-4" /></Link></>} />
    <ErrorBanner error={summary.error || jobs.error || engagements.error || exportsQ.error || info.error} />

    <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
      <section className="card instrument-grid relative overflow-hidden p-6 sm:p-7">
        <div className="relative z-10 max-w-xl">
          <div className="mb-5 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-accent"><Activity className="h-3.5 w-3.5" /> Assessment workspace</div>
          <h2 className="text-2xl sm:text-[28px] leading-tight tracking-tight">Understand every layer.<br /><span className="text-gradient">From radio to firmware.</span></h2>
          <p className="mt-3 max-w-md text-sm leading-relaxed text-slate-400">Start with a firmware image or connect a device. Build an evidence-backed assessment across four security domains.</p>
          <Link className="mt-5 inline-flex items-center gap-2 text-xs font-semibold text-accent hover:underline" to="/analyze">Analyse a firmware image <ArrowRight className="h-3.5 w-3.5" /></Link>
        </div>
        <div aria-hidden="true" className="pointer-events-none absolute -right-16 -bottom-32 h-80 w-80 rounded-full border border-accent/10 p-9"><div className="h-full rounded-full border border-accent/10 p-9"><div className="grid h-full place-items-center rounded-full border border-accent/20 bg-accent/5"><Cpu className="h-10 w-10 text-accent/30" strokeWidth={1} /></div></div></div>
      </section>
      <Card title="Host readiness" actions={<Link to="/plugins" aria-label="View host capabilities" className="text-slate-500 hover:text-accent"><ArrowUpRight className="h-4 w-4" /></Link>}>
        <div className="flex items-baseline gap-2"><span className="font-mono text-4xl text-slate-100">{ready ?? "—"}</span><span className="text-sm text-slate-500">/ {info.data?.capabilities.length ?? "—"} capabilities</span></div>
        <div className="my-5 h-1.5 overflow-hidden rounded-full bg-ink-800"><div className="h-full rounded-full bg-accent" style={{ width: `${info.data?.capabilities.length ? 100 * (ready || 0) / info.data.capabilities.length : 0}%` }} /></div>
        <p className="text-xs leading-relaxed text-slate-400">{missing === undefined ? "Checking installed tools…" : missing ? `${missing} capabilities unavailable on this host. Check module requirements before running.` : "All registered capabilities are available on this host."}</p>
        <Link className="mt-4 inline-flex items-center gap-1.5 text-xs text-accent" to="/hardware">View hardware connections <ChevronRight className="h-3 w-3" /></Link>
      </Card>
    </div>

    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <StatCard label="Total findings" value={s?.total ?? "—"} sub="Across all engagements" />
      <StatCard label="Critical / high" value={s ? (s.counts.critical || 0) + (s.counts.high || 0) : "—"} accent="text-orange-300" sub="Prioritize during review" />
      <StatCard label="Engagements" value={engagements.data?.length ?? "—"} sub="Assessment workspaces" />
      <StatCard label="Evidence artefacts" value={exportsQ.data?.length ?? "—"} accent="text-accent" sub="Available for export" />
    </div>

    <section>
      <div className="mb-3 flex items-center justify-between"><h2 className="text-sm">Assessment domains</h2><Link to="/plugins" className="text-xs text-slate-400 hover:text-accent">Explore all modules <ArrowRight className="ml-1 inline h-3 w-3" /></Link></div>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{DOMAINS.map((d) => <Link key={d.key} to={d.key === "firmware" ? "/analyze" : `/runner?plugin=${d.key}&module=${d.module}`} className="domain-tile group">
        <div className="mb-5 flex items-center justify-between"><div className={cn("rounded-lg p-2.5", d.color, d.bg)}><d.icon className="h-5 w-5" strokeWidth={1.6} /></div><ArrowUpRight className="h-4 w-4 text-slate-600 group-hover:text-slate-200" /></div>
        <h3 className="text-sm">{d.title}</h3><p className="mt-1 text-xs text-slate-500">{d.description}</p>
        <div className="mt-5 flex items-center justify-between border-t border-ink-700 pt-3 font-mono text-[10px] text-slate-400"><span>{info.data?.plugins.find((p) => p.name === d.key)?.modules ?? "—"} MODULES</span><span>{s?.by_domain[d.key] ?? "—"} FINDINGS</span></div>
      </Link>)}</div>
    </section>

    <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
      <Card title="Recent assessments" hint="Latest 6 runs" dense actions={<Link to="/exports" className="text-xs text-accent">View evidence <ArrowUpRight className="inline h-3.5 w-3.5" /></Link>}>
        {jobs.isLoading ? <Spinner /> : !jobs.data?.length ? <EmptyState title="Your first assessment starts here" hint={<Link to="/runner" className="text-accent hover:underline">Choose a module to get started →</Link>} /> : <Table><thead><tr><th>Module</th><th>Status</th><th>Progress</th><th>Started</th></tr></thead><tbody>{jobs.data.map((j) => <tr key={j.id}>
          <td><Link to={`/runner?job=${j.id}&plugin=${j.plugin}&module=${j.action}`} className="font-mono text-slate-200 hover:text-accent">{j.action}</Link><div className="mt-1 text-[10px] text-slate-500">{j.plugin}</div></td>
          <td><StatusDot status={j.status} /></td><td><div className="flex items-center gap-2"><div className="h-1 w-14 rounded bg-ink-800"><div className="h-full rounded bg-slate-500" style={{ width: `${Math.min(100, Math.max(0, j.progress))}%` }} /></div><span className="font-mono text-[10px]">{j.progress}%</span></div></td><td className="whitespace-nowrap text-slate-500">{fmtDate(j.created_at)}</td>
        </tr>)}</tbody></Table>}
      </Card>
      <Card title="Finding severity" hint={s ? `${s.total} total` : "Loading"}>
        <div className="mb-5 flex h-2 gap-0.5 overflow-hidden rounded-full bg-ink-800" aria-hidden="true">{SEVERITIES.map(([key, bg]) => <div key={key} className={bg} style={{ width: `${s?.total ? 100 * (s.counts[key] || 0) / s.total : 0}%` }} />)}</div>
        <div className="space-y-3">{SEVERITIES.map(([key]) => <div key={key} className="flex items-center justify-between"><SeverityBadge severity={key} /><span className="font-mono text-sm text-slate-300">{s?.counts[key] ?? "—"}</span></div>)}</div>
      </Card>
    </div>
    <section className="card grid divide-y divide-ink-700 md:grid-cols-4 md:divide-y-0 md:divide-x" aria-label="Assessment workflow">{steps.map((s, i) => <Link key={s.title} to={s.to} className="flex gap-3 p-5 hover:bg-ink-850/50"><span className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-full border font-mono text-[10px]", s.done ? "border-accent/20 text-accent bg-accent/5" : "border-ink-600 text-slate-400")}>{s.done ? <Check className="h-3 w-3" /> : `0${i + 1}`}</span><div><h3 className="text-xs font-medium">{s.title}</h3><p className="mt-1 text-[11px] text-slate-500">{s.subtitle}</p></div></Link>)}</section>
  </div>;
}
