import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  CircleUserRound,
  Cpu,
  Download,
  FileUp,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScanSearch,
  ShieldAlert,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import { api, auth } from "../lib/api";
import { cn } from "../lib/utils";
import { ErrorBanner } from "./ui";
import CommandSearch from "./CommandSearch";

interface NavItem {
  to: string;
  label: string;
  icon: any;
  end?: boolean;
}

const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Overview",
    items: [{ to: "/", label: "Overview", icon: LayoutDashboard, end: true }],
  },
  {
    label: "Assessment",
    items: [
      { to: "/engagements", label: "Engagements", icon: ShieldAlert },
      { to: "/analyze", label: "Firmware analysis", icon: FileUp },
      { to: "/runner", label: "Module runner", icon: SlidersHorizontal },
    ],
  },
  {
    label: "Results",
    items: [
      { to: "/findings", label: "Findings", icon: ScanSearch },
      { to: "/exports", label: "Evidence & reports", icon: Download },
    ],
  },
  {
    label: "Testbed",
    items: [
      { to: "/hardware", label: "Hardware workbench", icon: Cpu },
      { to: "/plugins", label: "Domains & modules", icon: Radar },
    ],
  },
];

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data: info, isError: offline } = useQuery({ queryKey: ["systemInfo"], queryFn: api.systemInfo, refetchInterval: 30000 });
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: api.me, staleTime: Infinity });
  const [menuOpen, setMenuOpen] = useState(false);
  const [pwOpen, setPwOpen] = useState(false);
  const mobileNav = useRef<HTMLDialogElement>(null);
  useEffect(() => { mobileNav.current?.close(); setMenuOpen(false); }, [location.pathname, location.search]);

  const capsOk = info?.capabilities.filter((c) => c.available).length ?? 0;
  const capsTotal = info?.capabilities.length ?? 0;
  const current = NAV_GROUPS.flatMap((g) => g.items).find((i) =>
    i.end ? location.pathname === i.to : location.pathname.startsWith(i.to),
  );

  function logout() {
    auth.clear();
    qc.clear();
    navigate("/login", { replace: true });
  }

  return (
    <div className="flex h-full">
      <a href="#main-content" className="skip-link">Skip to content</a>
      {/* ---------------- sidebar ---------------- */}
      <aside className="hidden w-[236px] shrink-0 flex-col border-r border-ink-700 bg-ink-900 md:flex">
        {/* brand */}
        <div className="flex items-center gap-3 px-5 py-6">
          <div className="brand-icon"><Activity className="h-5 w-5" strokeWidth={2} /></div>
          <div className="min-w-0 leading-tight">
            <div className="text-lg font-semibold tracking-tight text-slate-100">C3i <span className="font-normal text-slate-500">/</span> Testbed</div>
            <div className="mt-1 text-[9px] uppercase tracking-[0.19em] text-slate-500">IoT security workspace</div>
          </div>
        </div>

        {/* nav */}
        <nav aria-label="Main navigation" className="flex-1 overflow-y-auto px-3 py-4">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="mb-6">
              <div className="eyebrow mb-2 px-3">
                {group.label}
              </div>
              <div className="space-y-px">
                {group.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      cn(
                        "nav-item", isActive && "active",
                      )
                    }
                  >
                    <item.icon className="h-4 w-4 shrink-0" strokeWidth={1.7} />
                    <span className="truncate">{item.label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* status footer */}
        <div className="mx-3 mb-4 rounded-lg border border-ink-700 bg-ink-950 p-3.5">
          <div className="mb-4 flex items-center gap-2 text-xs text-slate-300">
            <span className={cn("h-1.5 w-1.5 rounded-full", offline ? "bg-red-400" : info ? "bg-accent" : "bg-slate-500")} />
            {offline ? "API unavailable" : info ? "API connected" : "Connecting…"}
            <span className="ml-auto font-mono text-[10px] text-slate-500">v{info?.version || "—"}</span>
          </div>
          <div className="space-y-2.5">
            <StatusLine label="Host tools" value={`${capsOk}/${capsTotal}`} ok={capsOk === capsTotal} />
            <StatusLine
              label="Invasive"
              value={info?.invasive_enabled ? "enabled" : "disabled"}
              ok={!!info?.invasive_enabled}
              warnWhenOff
            />
            <StatusLine label="CVE cache" value={String(info?.vulnerability_intel?.cached_cves ?? 0)} ok />
          </div>
        </div>
      </aside>

      {/* ---------------- main ---------------- */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* context bar */}
        <div className="flex h-16 shrink-0 items-center justify-between gap-3 border-b border-ink-700 bg-ink-900/80 px-4 md:px-8">
          <button className="btn-ghost md:hidden" aria-label="Open navigation" onClick={() => mobileNav.current?.showModal()}><Menu className="h-4 w-4" /></button>
          <div className="flex items-center gap-2 text-xs">
            <span className="hidden text-slate-500 lg:inline">Workspace</span>
            <span className="hidden text-slate-600 lg:inline">/</span>
            <span className="font-medium text-slate-300">{current?.label || "Console"}</span>
          </div>
          <div className="flex items-center gap-3">
            <CommandSearch />
            <span
              className="hidden items-center gap-1.5 text-[10px] text-slate-500 xl:flex"
              title={info?.plugins.map((p) => `${p.title}: ${p.modules}`).join(" · ")}
            >
              <Radar className="h-3 w-3" strokeWidth={1.8} />
              <span className="font-mono">{info?.plugins.reduce((n, p) => n + p.modules, 0) ?? "—"}</span>
              modules
            </span>
            <span
              className={cn(
                "hidden items-center gap-1.5 rounded border px-2 py-1.5 text-[10px] font-medium xl:flex",
                info?.invasive_enabled
                  ? "border-red-900/60 bg-red-950/30 text-red-400"
                  : "border-ink-600 bg-ink-850 text-slate-500",
              )}
            >
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  info?.invasive_enabled ? "bg-sev-critical" : "bg-slate-600",
                )}
              />
              {info?.invasive_enabled ? "Invasive enabled" : "Invasive disabled"}
            </span>
            <div className="relative">
              <button
                className="flex min-h-9 items-center gap-2 rounded border border-ink-700 px-2.5 text-xs text-slate-300 hover:bg-ink-800"
                aria-label="Account menu" aria-expanded={menuOpen}
                onClick={() => setMenuOpen((v) => !v)}
              >
                <CircleUserRound className="h-3.5 w-3.5" strokeWidth={2} />
                <span className="font-mono">{me?.username || "user"}</span>
                <span className="hidden rounded-sm bg-ink-700 px-1 text-[10px] uppercase text-slate-400 lg:inline">
                  {me?.role || ""}
                </span>
              </button>
              {menuOpen && (
                <div
                  className="absolute right-0 z-50 mt-1 w-44 rounded-md border border-ink-700 bg-ink-900 py-1 shadow-xl"
                  onMouseLeave={() => setMenuOpen(false)}
                >
                  <button
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-slate-300 hover:bg-ink-800"
                    onClick={() => {
                      setMenuOpen(false);
                      setPwOpen(true);
                    }}
                  >
                    <KeyRound className="h-3.5 w-3.5" /> Change password
                  </button>
                  <button
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-slate-300 hover:bg-ink-800"
                    onClick={logout}
                  >
                    <LogOut className="h-3.5 w-3.5" /> Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {info?.dev_no_auth && (
          <div className="shrink-0 border-b border-amber-900/50 bg-amber-950/40 px-4 py-1 text-center text-2xs text-amber-300">
            Authentication is disabled (C3I_DEV_NO_AUTH) — every request runs as the
            bootstrap admin. For development only.
          </div>
        )}

        <main id="main-content" tabIndex={-1} className="workspace-content flex-1 overflow-y-auto bg-ink-950">
          <Outlet />
        </main>
      </div>
      <dialog ref={mobileNav} className="command-dialog" aria-label="Navigation" onClick={(e) => { if (e.target === e.currentTarget) mobileNav.current?.close(); }}>
        <div className="panel-header"><span className="font-semibold">C3i Testbed</span><button className="btn-ghost" aria-label="Close navigation" onClick={() => mobileNav.current?.close()}><X className="h-4 w-4" /></button></div>
        <nav className="max-h-[75vh] overflow-auto p-3">{NAV_GROUPS.map((g) => <div key={g.label} className="mb-4"><div className="eyebrow p-3">{g.label}</div>{g.items.map((i) => <NavLink key={i.to} to={i.to} end={i.end} className={({ isActive }) => cn("nav-item", isActive && "active")}><i.icon className="h-4 w-4" />{i.label}</NavLink>)}</div>)}</nav>
      </dialog>
      {pwOpen && <ChangePasswordDialog onClose={() => setPwOpen(false)} />}
    </div>
  );
}

function StatusLine({
  label,
  value,
  ok,
  warnWhenOff,
}: {
  label: string;
  value: string;
  ok?: boolean;
  warnWhenOff?: boolean;
}) {
  const tone = warnWhenOff && !ok ? "text-amber-400" : ok ? "text-slate-300" : "text-slate-500";
  return (
    <div className="flex items-center justify-between text-2xs">
      <span className="text-slate-400">{label}</span>
      <span className={cn("font-mono", tone)}>{value}</span>
    </div>
  );
}

function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    dialog.current?.showModal();
  }, []);

  const change = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: () => dialog.current?.close(),
    onError: setError,
  });

  return (
    <dialog
      ref={dialog}
      className="command-dialog max-w-sm"
      aria-labelledby="change-password-title"
      onClose={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) dialog.current?.close();
      }}
    >
      <div className="panel-header">
        <div>
          <div className="eyebrow mb-1">Account security</div>
          <h2 id="change-password-title" className="text-sm font-semibold text-slate-100">Change password</h2>
        </div>
        <button className="btn-ghost" aria-label="Close password dialog" onClick={() => dialog.current?.close()}>
          <X className="h-4 w-4" />
        </button>
      </div>
      <form
        className="card-body space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate();
        }}
      >
        <div>
          <label className="label" htmlFor="current-password">Current password</label>
          <input
            id="current-password"
            className="input"
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoComplete="current-password"
            autoFocus
            required
          />
        </div>
        <div>
          <label className="label" htmlFor="new-password">New password</label>
          <input
            id="new-password"
            className="input"
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="new-password"
            minLength={8}
            required
          />
          <p className="mt-1.5 text-[11px] text-slate-500">At least 8 characters.</p>
        </div>
        <div>
          <label className="label" htmlFor="confirm-password">Confirm new password</label>
          <input
            id="confirm-password"
            className="input"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
          />
        </div>
        <ErrorBanner error={error} />
        <button
          type="submit"
          className="btn-primary w-full justify-center"
          disabled={change.isPending || next.length < 8 || next !== confirm}
        >
          {change.isPending ? "Changing…" : "Change password"}
        </button>
      </form>
    </dialog>
  );
}
