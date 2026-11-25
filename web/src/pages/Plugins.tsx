import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, ArrowUpRight, CheckCircle2, Copy, Search } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import {
  Card,
  ErrorBanner,
  PageHeader,
  SafetyBadge,
  Spinner,
  StatCard,
  Table,
} from "../components/ui";
import { cn } from "../lib/utils";

export default function Plugins() {
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins });
  const caps = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities });
  const [query, setQuery] = useState("");
  const [safety, setSafety] = useState("all");

  const capabilities = caps.data || [];
  const available = capabilities.filter((c) => c.available).length;
  const moduleTotal = plugins.data?.reduce((n, p) => n + p.modules.length, 0) ?? 0;
  const q = query.trim().toLowerCase();
  const matches = (...values: string[]) => values.join(" ").toLowerCase().includes(q);

  const visible = (plugins.data || [])
    .map((plugin) => {
      const pluginMatches = matches(plugin.title, plugin.description, plugin.name);
      return {
        ...plugin,
        modules: plugin.modules.filter(
          (m) =>
            (safety === "all" || m.safety === safety) &&
            (!q ||
              pluginMatches ||
              matches(m.name, m.title, m.description, ...m.tags, ...m.mitre)),
        ),
      };
    })
    .filter((plugin) => plugin.modules.length);

  return (
    <div className="space-y-6 fade-in">
      <PageHeader
        title="Domains & modules"
        subtitle="Every assessment module declares its intrusiveness, host requirements, and the evidence it produces."
        meta={
          <>
            <span className="chip-neutral">{plugins.data?.length ?? 0} domains</span>
            <span className="chip-neutral">{moduleTotal} modules</span>
            <span className="chip border-emerald-800/50 bg-emerald-950/20 text-emerald-300">
              {available}/{capabilities.length} host capabilities
            </span>
          </>
        }
        actions={
          <Link to="/runner" className="btn-primary">
            Open module runner <ArrowRight className="h-4 w-4" />
          </Link>
        }
      />

      <ErrorBanner error={plugins.error || caps.error} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Security domains" value={plugins.data?.length ?? "—"} sub="Bluetooth, network, hardware, firmware" />
        <StatCard label="Assessment modules" value={moduleTotal || "—"} sub="Passive, active, and invasive" />
        <StatCard label="Host capabilities" value={`${available}/${capabilities.length || "—"}`} accent="text-accent" sub="Available on this backend host" />
        <StatCard label="Unavailable" value={capabilities.length ? capabilities.length - available : "—"} accent="text-amber-300" sub="Fallbacks may apply" />
      </div>

      <section className="card flex flex-wrap items-end gap-4 p-4" aria-label="Filter modules">
        <div className="min-w-[220px] flex-1">
          <label className="label" htmlFor="module-search">Search modules</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />
            <input
              id="module-search"
              className="input pl-9"
              placeholder="Name, tag, MITRE technique…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
        </div>
        <div className="w-full sm:w-48">
          <label className="label" htmlFor="safety-filter">Intrusiveness</label>
          <select id="safety-filter" className="input" value={safety} onChange={(e) => setSafety(e.target.value)}>
            <option value="all">All modules</option>
            <option value="passive">Read-only</option>
            <option value="active">Active</option>
            <option value="invasive">Invasive</option>
          </select>
        </div>
        <p className="pb-2 text-xs text-slate-500">
          {visible.reduce((n, p) => n + p.modules.length, 0)} module(s) shown
        </p>
      </section>

      {plugins.isLoading ? (
        <Card><Spinner /></Card>
      ) : !visible.length ? (
        <Card>
          <div className="py-10 text-center">
            <p className="text-sm text-slate-300">No modules match this filter.</p>
            <button
              className="mt-3 text-xs text-accent hover:underline"
              onClick={() => { setQuery(""); setSafety("all"); }}
            >
              Clear filters
            </button>
          </div>
        </Card>
      ) : (
        <div className="space-y-5">
          {visible.map((plugin) => (
            <Card
              key={plugin.name}
              title={plugin.title}
              hint={`${plugin.modules.length} module(s)`}
              dense
              actions={
                <Link
                  to={`/runner?plugin=${encodeURIComponent(plugin.name)}`}
                  className="text-xs text-accent hover:underline"
                >
                  Run a module <ArrowUpRight className="inline h-3.5 w-3.5" />
                </Link>
              }
            >
              <div className="border-b border-ink-800 px-5 py-4">
                <p className="max-w-3xl text-xs leading-relaxed text-slate-400">{plugin.description}</p>
              </div>
              <Table>
                <thead>
                  <tr>
                    <th>Module</th>
                    <th>Safety</th>
                    <th>Tags</th>
                    <th>Requirements</th>
                    <th>MITRE</th>
                    <th><span className="sr-only">Run</span></th>
                  </tr>
                </thead>
                <tbody>
                  {plugin.modules.map((m) => (
                    <tr key={m.name}>
                      <td className="td max-w-md">
                        <div className="text-xs font-medium text-slate-200">{m.title}</div>
                        <div className="mt-1 font-mono text-[10px] text-slate-500">
                          {plugin.name}.{m.name}
                        </div>
                        <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">{m.description}</p>
                      </td>
                      <td className="td"><SafetyBadge safety={m.safety} /></td>
                      <td className="td">
                        <div className="flex max-w-[180px] flex-wrap gap-1">
                          {m.tags.length ? m.tags.map((tag) => (
                            <span key={tag} className="chip-neutral normal-case tracking-normal">{tag}</span>
                          )) : <span className="text-slate-600">—</span>}
                        </div>
                      </td>
                      <td className="td">
                        <div className="flex max-w-[220px] flex-wrap gap-1">
                          {m.capabilities.length ? m.capabilities.map((cap) => {
                            const isAvailable = capabilities.find((c) => c.id === cap)?.available;
                            return (
                              <span
                                key={cap}
                                className={cn(
                                  "chip font-mono normal-case tracking-normal",
                                  isAvailable
                                    ? "border-emerald-800/50 bg-emerald-950/20 text-emerald-400"
                                    : "border-amber-800/50 bg-amber-950/20 text-amber-400",
                                )}
                                title={isAvailable ? "Available on this host" : "Unavailable — fallback or skip"}
                              >
                                {cap}
                              </span>
                            );
                          }) : <span className="text-slate-600">None</span>}
                        </div>
                      </td>
                      <td className="td font-mono text-[10px] text-slate-500">
                        {m.mitre.join(", ") || "—"}
                      </td>
                      <td className="td">
                        <Link
                          to={`/runner?plugin=${encodeURIComponent(plugin.name)}&module=${encodeURIComponent(m.name)}`}
                          className="btn-ghost"
                          aria-label={`Run ${m.title}`}
                        >
                          Run <ArrowRight className="h-3.5 w-3.5" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>
          ))}
        </div>
      )}

      <Card title="Host capabilities" hint="Probed on the backend host" dense>
        <div className="grid gap-px bg-ink-800 sm:grid-cols-2 xl:grid-cols-3">
          {[...capabilities].sort((a, b) => Number(a.available) - Number(b.available)).map((c) => (
            <div key={c.id} className="flex items-start gap-3 bg-ink-900 p-4">
              {c.available ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
              ) : (
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              )}
              <div className="min-w-0">
                <div className={cn("text-xs font-medium", c.available ? "text-slate-200" : "text-slate-400")}>
                  {c.label}
                </div>
                <div className="mt-1 font-mono text-[10px] text-slate-500">
                  {c.id} · {c.kind}
                </div>
                {!c.available && c.hint && (
                  <p className="mt-1.5 text-[11px] leading-relaxed text-amber-500/90">{c.hint}</p>
                )}
                {!c.available && c.install && (
                  <button
                    type="button"
                    className="mt-1.5 flex max-w-full items-center gap-1.5 rounded border border-ink-700 bg-ink-950 px-2 py-1 font-mono text-[10px] text-slate-300 hover:border-accent"
                    title="Copy install command"
                    onClick={() => navigator.clipboard?.writeText(c.install!)}
                  >
                    <Copy className="h-3 w-3 shrink-0 text-slate-500" />
                    <span className="truncate">{c.install}</span>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
