import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

export function fmtDate(s?: string | null): string {
  if (!s) return "—";
  try {
    return new Date(s).toLocaleString();
  } catch {
    return s;
  }
}

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

// Muted, semantic severity chips (text + subtle tint, thin border).
export const SEV_STYLES: Record<string, string> = {
  critical: "border-sev-critical/50 bg-sev-critical/10 text-sev-critical",
  high: "border-sev-high/50 bg-sev-high/10 text-sev-high",
  medium: "border-sev-medium/50 bg-sev-medium/10 text-sev-medium",
  low: "border-sev-low/50 bg-sev-low/10 text-sev-low",
  info: "border-ink-600 bg-ink-800 text-slate-400",
};

export const SEV_DOT: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

export const SAFETY_STYLES: Record<string, string> = {
  passive: "border-emerald-800/60 bg-emerald-950/30 text-emerald-400",
  active: "border-amber-800/60 bg-amber-950/30 text-amber-400",
  invasive: "border-red-800/60 bg-red-950/30 text-red-400",
};

export const SAFETY_LABEL: Record<string, string> = {
  passive: "read-only",
  active: "active",
  invasive: "invasive",
};
