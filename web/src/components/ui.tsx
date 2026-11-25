import { Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { cn, SAFETY_LABEL, SAFETY_STYLES, SEV_DOT, SEV_STYLES } from "../lib/utils";

/* ------------------------------------------------------------------ */
/* Surfaces                                                            */
/* ------------------------------------------------------------------ */
export function Card({
  className,
  children,
  title,
  hint,
  actions,
  dense,
}: {
  className?: string;
  children: ReactNode;
  title?: ReactNode;
  hint?: ReactNode;
  actions?: ReactNode;
  dense?: boolean;
}) {
  return (
    <section className={cn("card min-w-0", className)}>
      {(title || actions) && (
        <header className="panel-header">
          <div className="flex items-baseline gap-2 min-w-0">
            <h2 className="text-sm font-semibold text-slate-200">
              {title}
            </h2>
            {hint && <span className="truncate text-2xs text-slate-500">{hint}</span>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
       <div className={dense ? "overflow-x-auto" : "card-body overflow-x-auto"}>{children}</div>
    </section>
  );
}

/** Legacy alias kept so existing pages keep compiling. */
export function SectionTitle({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-300">{children}</h2>
      {hint && <span className="text-2xs text-slate-500">{hint}</span>}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
  meta,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="min-w-0">
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="mt-2 max-w-2xl text-sm text-slate-400 leading-relaxed">{subtitle}</p>}
        {meta && <div className="mt-1.5 flex flex-wrap items-center gap-2">{meta}</div>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}

/* ------------------------------------------------------------------ */
/* Badges & status                                                     */
/* ------------------------------------------------------------------ */
export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={cn("chip", SEV_STYLES[severity] || SEV_STYLES.info)}>{severity}</span>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  return (
    <span
      className={cn("inline-block h-1.5 w-1.5 shrink-0 rounded-full", SEV_DOT[severity] || SEV_DOT.info)}
      title={severity}
    />
  );
}

export function SafetyBadge({ safety }: { safety: string }) {
  return (
    <span className={cn("chip", SAFETY_STYLES[safety] || SAFETY_STYLES.passive)}>
      {SAFETY_LABEL[safety] || safety}
    </span>
  );
}

export function StatusChip({ status }: { status: string }) {
  const styles: Record<string, string> = {
    draft: "border-ink-600 bg-ink-800 text-slate-400",
    authorized: "border-emerald-800/60 bg-emerald-950/30 text-emerald-300",
    active: "border-sky-800/60 bg-sky-950/30 text-sky-300",
    completed: "border-indigo-800/60 bg-indigo-950/30 text-indigo-300",
    archived: "border-ink-700 bg-ink-850 text-slate-500",
  };
  return (
    <span className={cn("chip", styles[status] || styles.draft)}>{status}</span>
  );
}

export function StatusDot({ status }: { status: string }) {
  const map: Record<string, [string, string]> = {
    succeeded: ["bg-emerald-500", "text-emerald-400"],
    running: ["bg-accent animate-pulse", "text-accent"],
    queued: ["bg-slate-500", "text-slate-400"],
    failed: ["bg-sev-critical", "text-sev-critical"],
    cancelled: ["bg-slate-600", "text-slate-500"],
  };
  const [dot, text] = map[status] || map.queued;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span className={cn("h-1.5 w-1.5 rounded-full", dot)} />
      <span className={cn("capitalize", text)}>{status}</span>
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Data display                                                        */
/* ------------------------------------------------------------------ */
export function Stat({
  label,
  value,
  tone,
  accent,
  sub,
}: {
  label: string;
  value: ReactNode;
  tone?: string;
  /** Legacy alias for `tone`. */
  accent?: string;
  sub?: string;
}) {
  return (
    <div className="stat-card">
      <div className="text-xs font-medium text-slate-400">{label}</div>
      <div
        className={cn(
          "mt-3 font-mono text-3xl font-medium tabnum text-slate-100 tracking-tight",
          tone || accent,
        )}
      >
        {value}
      </div>
      {sub && <div className="mt-2 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

/** Legacy alias. */
export const StatCard = Stat;

export function KeyValue({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-ink-800 py-1.5 last:border-0">
      <span className="text-xs text-slate-500">{k}</span>
      <span className="font-mono text-xs text-slate-200">{children}</span>
    </div>
  );
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="table-scroll">
      <table className="data-table">{children}</table>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Feedback                                                            */
/* ------------------------------------------------------------------ */
export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-6 text-xs text-slate-500">
      <Loader2 className="h-3.5 w-3.5 animate-spin" />
      {label || "Loading…"}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: ReactNode }) {
  return (
    <div className="py-10 px-4 text-center">
      <Inbox aria-hidden="true" className="mx-auto mb-4 h-7 w-7 text-slate-600" strokeWidth={1.3} />
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint && <p className="mt-2 text-xs text-slate-400">{hint}</p>}
    </div>
  );
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="flex items-start gap-2 rounded border border-red-900/60 bg-red-950/30 px-3 py-3 text-xs text-red-300">
      <span className="mt-px font-mono text-2xs font-bold text-red-400">ERR</span>
      <span className="whitespace-pre-wrap break-words">{msg}</span>
    </div>
  );
}

export function Notice({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "warn" | "ok" | "danger";
  title?: ReactNode;
  children: ReactNode;
}) {
  const tones = {
    info: "border-ink-600 bg-ink-850 text-slate-300",
    warn: "border-amber-900/60 bg-amber-950/20 text-amber-200",
    ok: "border-emerald-900/60 bg-emerald-950/20 text-emerald-200",
    danger: "border-red-900/60 bg-red-950/20 text-red-200",
  };
  return (
    <div className={cn("rounded border px-3 py-2.5 text-xs", tones[tone])}>
      {title && <div className="mb-0.5 font-semibold text-slate-100">{title}</div>}
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Steps & inline helpers                                              */
/* ------------------------------------------------------------------ */
export function Step({
  n,
  title,
  children,
  done,
}: {
  n: number;
  title: string;
  children?: ReactNode;
  done?: boolean;
}) {
  return (
    <div className="flex gap-2.5">
      <div
        className={cn(
          "mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-sm border font-mono text-2xs font-semibold",
          done
            ? "border-emerald-800 bg-emerald-950/50 text-emerald-400"
            : "border-ink-600 bg-ink-850 text-slate-400",
        )}
      >
        {done ? "✓" : n}
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium text-slate-200">{title}</div>
        {children && <div className="mt-0.5 text-xs text-slate-500">{children}</div>}
      </div>
    </div>
  );
}

export function InlineCode({ children }: { children: ReactNode }) {
  return (
    <code className="rounded-sm border border-ink-700 bg-ink-950 px-1 py-px font-mono text-2xs text-slate-300">
      {children}
    </code>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-xs text-slate-300", className)}>{children}</span>;
}
