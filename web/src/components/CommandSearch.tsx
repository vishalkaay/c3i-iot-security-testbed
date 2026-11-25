import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Search, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";

const PAGES = [
  ["Overview", "/"], ["Engagements", "/engagements"], ["Firmware analysis", "/analyze"],
  ["Module runner", "/runner"], ["Findings", "/findings"], ["Evidence & reports", "/exports"],
  ["Hardware workbench", "/hardware"], ["Domains & modules", "/plugins"],
];

export default function CommandSearch() {
  const dialog = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins, enabled: open });
  function show() {
    setQuery("");
    setOpen(true);
    if (!dialog.current?.open) dialog.current?.showModal();
  }
  function close() {
    if (dialog.current?.open) dialog.current.close();
    setOpen(false);
  }
  useEffect(() => {
    const listener = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setQuery("");
        setOpen(true);
        if (!dialog.current?.open) dialog.current?.showModal();
      }
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, []);
  const items = [
    ...PAGES.map(([title, to]) => ({ title, to, detail: "Workspace" })),
    ...(plugins.data || []).flatMap((p) => p.modules.map((m) => ({
      title: m.title, detail: `${p.name}.${m.name}`,
      to: `/runner?plugin=${encodeURIComponent(p.name)}&module=${encodeURIComponent(m.name)}`,
    }))),
  ].filter((x) => `${x.title} ${x.detail}`.toLowerCase().includes(query.toLowerCase())).slice(0, 15);
  return <>
    <button className="flex min-h-9 items-center gap-2 rounded border border-ink-700 bg-ink-950 px-3 text-xs text-slate-400 hover:border-ink-600" onClick={show} aria-label="Search pages and modules">
      <Search className="h-3.5 w-3.5" /> <span className="hidden lg:inline">Search workspace</span>
      <kbd className="ml-8 hidden rounded border border-ink-700 px-1.5 py-0.5 text-[10px] lg:inline">Ctrl K</kbd>
    </button>
    <dialog
      ref={dialog}
      className="command-dialog"
      onClose={() => setOpen(false)}
      onClick={(e) => { if (e.target === e.currentTarget) close(); }}
      aria-label="Search workspace"
    >
      <div className="flex items-center gap-3 border-b border-ink-700 p-4">
        <Search className="h-5 w-5 text-accent" />
        <input
          autoFocus
          className="min-w-0 flex-1 bg-transparent p-1 outline-none"
          placeholder="Find a page or module…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && items[0]) {
              e.preventDefault();
              close();
              navigate(items[0].to);
            }
          }}
          aria-label="Search"
        />
        <button className="btn-ghost" aria-label="Close search" onClick={close}><X className="h-4 w-4" /></button>
      </div>
      <div className="max-h-[60vh] overflow-y-auto p-2">
        {items.map((x) => <button key={x.to} className="flex w-full items-center gap-3 rounded p-3 text-left hover:bg-ink-800 focus:bg-ink-800" onClick={() => { close(); navigate(x.to); }}>
          <div className="flex-1"><div className="text-sm text-slate-200">{x.title}</div><div className="mt-1 font-mono text-[10px] text-slate-500">{x.detail}</div></div>
          <ArrowUpRight className="h-4 w-4 text-slate-500" />
        </button>)}
        {!items.length && <p className="p-6 text-center text-slate-400">No matching pages or modules.</p>}
      </div>
      <div className="border-t border-ink-700 px-4 py-3 text-[10px] text-slate-500">Tab to navigate · Enter to open · Esc to close</div>
    </dialog>
  </>;
}
