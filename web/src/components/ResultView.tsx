import { useState } from "react";
import { FileJson, LayoutList } from "lucide-react";
import { cn, fmtBytes } from "../lib/utils";
import { EmptyState, StatCard, Table } from "./ui";

function display(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function Records({ rows }: { rows: Record<string, unknown>[] }) {
  if (!rows.length) return <EmptyState title="No records returned" />;
  const columns = [...new Set(rows.slice(0, 20).flatMap(Object.keys))].filter((k) => rows.some((r) => r[k] !== null)).slice(0, 7);
  return <Table><thead><tr>{columns.map((k) => <th key={k}>{k.replaceAll("_", " ")}</th>)}</tr></thead><tbody>{rows.slice(0, 100).map((row, i) => <tr key={i}>{columns.map((k) => <td key={k}><div className="max-w-xs break-words font-mono text-[11px]" title={display(row[k])}>{display(row[k])}</div></td>)}</tr>)}</tbody></Table>;
}

/** Human-readable first, with the complete original response always available. */
export default function ResultView({ result }: { result: Record<string, any> }) {
  const [raw, setRaw] = useState(false);
  const report = result.report || result;
  const distance = result.distance_estimate || result.rtt?.distance_estimate;
  const tables = Object.entries(report).filter(([, v]) => Array.isArray(v) && v.length && v.every((x: any) => x && typeof x === "object" && !Array.isArray(x)));
  const scalar = Object.entries(report).filter(([, v]) => v !== null && typeof v !== "object");
  return <div className="space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <span className="eyebrow">Assessment output</span>
      <div className="flex gap-1 rounded border border-ink-700 p-1" role="group" aria-label="Result display">
        <button className={cn("flex items-center gap-1.5 rounded-sm px-2 py-1 text-xs", !raw && "bg-ink-800 text-accent")} onClick={() => setRaw(false)} aria-pressed={!raw}><LayoutList className="h-3 w-3" /> Summary</button>
        <button className={cn("flex items-center gap-1.5 rounded-sm px-2 py-1 text-xs", raw && "bg-ink-800 text-accent")} onClick={() => setRaw(true)} aria-pressed={raw}><FileJson className="h-3 w-3" /> JSON</button>
      </div>
    </div>
    {raw ? <pre className="terminal max-h-[600px] overflow-auto p-4 leading-relaxed">{JSON.stringify(result, null, 2)}</pre> : <>
      {result.report && <div className="grid grid-cols-2 gap-3 lg:grid-cols-4"><StatCard label="Image size" value={fmtBytes(report.size || 0)} /><StatCard label="Signatures" value={report.signatures?.length ?? 0} /><StatCard label="Secrets" value={report.secrets?.length ?? 0} accent="text-orange-300" /><StatCard label="Components" value={report.components?.length ?? 0} /></div>}
      {result.os_inference && <div className="rounded border border-sky-900/60 bg-sky-950/20 p-4"><div className="label">OS family hint · {result.os_inference.confidence} confidence</div><div className="text-lg text-slate-200">{result.os_inference.os_family}</div><p className="mt-2 text-xs text-slate-400">Heuristic attribution; device names and advertising data do not verify the installed OS.</p></div>}
      {distance && <div className={cn("rounded border p-4", distance.available ? "border-cyan-900/70 bg-cyan-950/20" : "border-ink-700 bg-ink-950/40")}><div className="flex flex-wrap items-baseline justify-between gap-2"><div><div className="label">Estimated distance · {distance.confidence || "unavailable"} confidence <span className="ml-1 cursor-help rounded border border-ink-600 px-1 text-[9px] uppercase tracking-wide text-slate-500" title="RSSI path-loss model estimate — not a measurement. Expect 2–3× error from one sample; calibrate a 1 m reference for better results.">model estimate</span></div><div className="mt-1 text-2xl font-medium text-slate-100">{distance.available ? `${distance.estimated_m} m` : "No RSSI estimate"}</div></div>{distance.available && <div className="text-right text-xs text-slate-400"><div>plausible range</div><div className="font-mono text-slate-300">{distance.range_m?.[0]}–{distance.range_m?.[1]} m</div></div>}</div>{distance.available && <div className="mt-3 grid gap-2 text-xs text-slate-400 sm:grid-cols-3"><div>RSSI <span className="font-mono text-slate-200">{distance.rssi_dbm} dBm</span></div><div>1 m reference <span className="font-mono text-slate-200">{distance.reference_rssi_dbm} dBm</span></div><div>path-loss <span className="font-mono text-slate-200">n={distance.path_loss_exponent}</span></div></div>}<p className="mt-3 text-xs leading-relaxed text-slate-500">{distance.caveat}</p></div>}
      {result.device && <dl className="grid gap-x-5 sm:grid-cols-2">{Object.entries(result.device).filter(([, v]) => v != null && !Array.isArray(v)).map(([key, value]) => <div className="kv min-w-0" key={key}><dt className="shrink-0 text-slate-500">{key.replaceAll("_", " ")}</dt><dd className="break-all text-right font-mono text-xs">{display(value)}</dd></div>)}</dl>}
      {scalar.length > 0 && <dl className="space-y-2">{scalar.map(([key, value]) => <div key={key} className="rounded bg-ink-950/60 p-3"><dt className="eyebrow mb-1">{key.replaceAll("_", " ")}</dt><dd className="whitespace-pre-wrap break-words font-mono text-xs text-slate-300">{display(value)}</dd></div>)}</dl>}
      {tables.map(([key, rows]) => <section key={key}><h3 className="mb-3 text-xs font-medium capitalize text-slate-400">{key.replaceAll("_", " ")} <span className="ml-1 font-mono text-slate-500">{(rows as any[]).length}</span></h3><Records rows={rows as any[]} />{(rows as any[]).length > 100 && <p className="mt-2 text-xs text-slate-500">First 100 records shown. JSON contains the full response.</p>}</section>)}
      {!scalar.length && !tables.length && !result.device && <p className="text-sm text-slate-400">The module returned structured data. Open JSON to inspect the full response.</p>}
      <details><summary className="text-xs text-slate-500 hover:text-accent">Complete response</summary><pre className="terminal mt-3 max-h-96 overflow-auto p-4">{JSON.stringify(result, null, 2)}</pre></details>
    </>}
  </div>;
}
