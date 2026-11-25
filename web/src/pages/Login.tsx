import { Activity, ArrowRight, Bluetooth, Cpu, FileCode2, Wifi } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, auth } from "../lib/api";
import { ErrorBanner } from "../components/ui";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.login(username, password);
      auth.set(res.access_token);
      navigate("/");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-full bg-ink-950 lg:grid-cols-2">
      <section className="instrument-grid relative hidden flex-col justify-between overflow-hidden border-r border-ink-700 bg-ink-900 p-12 lg:flex">
        <div className="flex items-center gap-3"><div className="brand-icon"><Activity className="h-5 w-5" /></div><span className="text-lg font-semibold text-slate-100">C3i / Testbed</span></div>
        <div aria-hidden="true" className="pointer-events-none absolute -left-24 top-1/3 h-96 w-96 rounded-full bg-accent/10 blur-[120px]" />
        <div className="relative z-10 my-16 max-w-lg"><p className="eyebrow mb-6 text-accent">IoT security. Every layer.</p><h2 className="text-5xl leading-[1.08] font-medium tracking-tight">From the first signal<br /><span className="text-gradient">to the final report.</span></h2><p className="mt-6 max-w-sm leading-relaxed text-slate-400">A unified workspace for device discovery, hardware inspection, and evidence-backed security assessments.</p><div className="mt-10 flex gap-3" aria-label="Bluetooth, Wi-Fi, hardware and firmware">{[Bluetooth, Wifi, Cpu, FileCode2].map((Icon, i) => <div key={i} className="rounded-lg border border-ink-600 bg-ink-900/80 p-4 transition-all duration-200 hover:-translate-y-1 hover:border-accent/40"><Icon className="h-5 w-5 text-accent" strokeWidth={1.5} /></div>)}</div></div>
        <p className="eyebrow">C3i Hub · IIT Kanpur</p>
      </section>
      <div className="flex items-center justify-center p-6 sm:p-12">
      <div className="w-full max-w-sm fade-in">
        <div className="mb-10"><div className="brand-icon mb-6 lg:hidden"><Activity className="h-5 w-5" /></div><p className="eyebrow mb-3">C3i security workspace</p><h1 className="text-3xl font-semibold">Welcome back.</h1><p className="mt-3 text-sm text-slate-400">Sign in to your assessment console.</p></div>
        <form onSubmit={submit} className="space-y-5">
          <div>
            <label className="label" htmlFor="username">Username</label>
            <input
              className="input"
              id="username" required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </div>
          <div>
            <label className="label" htmlFor="password">Password</label>
            <input
              className="input"
              id="password" required
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              autoFocus
            />
          </div>
          <ErrorBanner error={error} />
          <button className="btn-primary w-full justify-center" disabled={busy}>
            {busy ? "Signing in…" : "Open workspace"}<ArrowRight className="h-4 w-4" />
          </button>
          <p className="text-[11px] text-slate-500 text-center">
            Authorized use only. All invasive actions are logged and require a signed
            Rules of Engagement.
          </p>
        </form>
      </div>
      </div>
    </div>
  );
}
