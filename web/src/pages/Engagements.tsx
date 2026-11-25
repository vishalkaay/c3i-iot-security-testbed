import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, ArrowUpRight, Plus, ShieldCheck, ShieldOff, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import {
  Card,
  EmptyState,
  ErrorBanner,
  PageHeader,
  Spinner,
  StatusChip,
  Table,
} from "../components/ui";
import { fmtDate } from "../lib/utils";
import type { Engagement } from "../lib/types";

export default function Engagements() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["engagements"], queryFn: api.engagements });
  const [form, setForm] = useState({ name: "", client: "", description: "" });
  const [error, setError] = useState<unknown>(null);
  const [roeFor, setRoeFor] = useState<Engagement | null>(null);

  const create = useMutation({
    mutationFn: () => api.createEngagement(form),
    onSuccess: () => {
      setForm({ name: "", client: "", description: "" });
      qc.invalidateQueries({ queryKey: ["engagements"] });
    },
    onError: setError,
  });

  const authorized = list.data?.filter((e) => e.roe_accepted_at).length ?? 0;

  return (
    <div className="space-y-6 fade-in">
      <PageHeader
        title="Engagement workspace"
        subtitle="Each assessment carries a signed Rules of Engagement that authorizes and scopes active testing."
        meta={
          <>
            <span className="chip-neutral">{list.data?.length ?? 0} workspaces</span>
            <span className="chip border-emerald-800/50 bg-emerald-950/20 text-emerald-300">
              {authorized} authorized
            </span>
          </>
        }
        actions={
          <a href="#new-engagement" className="btn-primary">
            <Plus className="h-4 w-4" /> New engagement
          </a>
        }
      />

      <ErrorBanner error={error || list.error} />

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Card
          title="All engagements"
          hint={`${list.data?.length ?? 0} total`}
          dense
          actions={
            <Link to="/findings" className="text-xs text-accent hover:underline">
              Review findings <ArrowUpRight className="inline h-3.5 w-3.5" />
            </Link>
          }
        >
          {list.isLoading ? (
            <div className="p-5"><Spinner /></div>
          ) : !list.data?.length ? (
            <EmptyState
              title="No engagements yet"
              hint="Create your first assessment workspace using the form on the right."
            />
          ) : (
            <Table>
              <thead>
                <tr>
                  <th>Engagement</th>
                  <th>Status</th>
                  <th>Authorized scope</th>
                  <th>Rules of Engagement</th>
                  <th><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((e) => (
                  <tr key={e.id}>
                    <td className="td">
                      <Link
                        className="font-medium text-slate-200 hover:text-accent"
                        to={`/engagements/${e.id}`}
                      >
                        {e.name}
                      </Link>
                      <div className="mt-1 text-[10px] text-slate-500">
                        {e.client || "No client"} · created {fmtDate(e.created_at)}
                      </div>
                    </td>
                    <td className="td"><StatusChip status={e.status} /></td>
                    <td className="td">
                      <div className="flex max-w-[260px] flex-wrap gap-1.5">
                        {e.authorized_targets?.length ? (
                          e.authorized_targets.slice(0, 3).map((target) => (
                            <span key={target} className="chip-neutral font-mono normal-case tracking-normal">
                              {target}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-slate-500">Not signed</span>
                        )}
                        {(e.authorized_targets?.length ?? 0) > 3 && (
                          <span className="chip-neutral">+{(e.authorized_targets?.length ?? 0) - 3}</span>
                        )}
                      </div>
                    </td>
                    <td className="td">
                      {e.roe_accepted_at ? (
                        <>
                          <div className="text-xs text-slate-300">{e.roe_signed_by || "Signed"}</div>
                          <div className="mt-1 text-[10px] text-slate-500">
                            Expires {fmtDate(e.roe_expires_at)}
                          </div>
                        </>
                      ) : (
                        <span className="text-xs text-amber-400">Signature required</span>
                      )}
                    </td>
                    <td className="td">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          to={`/engagements/${e.id}`}
                          className="btn-ghost"
                          aria-label={`Open ${e.name}`}
                        >
                          Open <ArrowRight className="h-3.5 w-3.5" />
                        </Link>
                        <button className="btn-ghost whitespace-nowrap" onClick={() => setRoeFor(e)}>
                          {e.roe_accepted_at ? (
                            <><ShieldCheck className="h-3.5 w-3.5" /> Re-sign</>
                          ) : (
                            <><ShieldOff className="h-3.5 w-3.5" /> Authorize</>
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>

        <div id="new-engagement" className="scroll-mt-24">
          <Card title="New engagement" hint="Step 1 of 2">
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                if (form.name) create.mutate();
              }}
            >
              <div>
                <label className="label" htmlFor="engagement-name">Name <span className="text-accent">*</span></label>
                <input
                  id="engagement-name"
                  className="input"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Camera lab assessment"
                  required
                />
              </div>
              <div>
                <label className="label" htmlFor="engagement-client">Client</label>
                <input
                  id="engagement-client"
                  className="input"
                  value={form.client}
                  onChange={(e) => setForm({ ...form, client: e.target.value })}
                  placeholder="Internal lab"
                />
              </div>
              <div>
                <label className="label" htmlFor="engagement-description">Description</label>
                <textarea
                  id="engagement-description"
                  className="input"
                  rows={3}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Scope, objectives, and test window"
                />
              </div>
              <button
                type="submit"
                className="btn-primary w-full"
                disabled={!form.name || create.isPending}
              >
                <Plus className="h-4 w-4" />
                {create.isPending ? "Creating…" : "Create engagement"}
              </button>
              <p className="border-t border-ink-800 pt-4 text-[11px] leading-relaxed text-slate-500">
                Next, sign the Rules of Engagement with the exact targets you are
                authorized to test. Active and invasive modules stay locked until then.
              </p>
            </form>
          </Card>
        </div>
      </div>

      {roeFor && (
        <RoeDialog
          engagement={roeFor}
          onClose={() => setRoeFor(null)}
          onAuthorized={() => qc.invalidateQueries({ queryKey: ["engagements"] })}
        />
      )}
    </div>
  );
}

function RoeDialog({
  engagement,
  onClose,
  onAuthorized,
}: {
  engagement: Engagement;
  onClose: () => void;
  onAuthorized: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [roe, setRoe] = useState({
    signed_by: engagement.roe_signed_by || "",
    reference: engagement.roe_reference || "",
    targets: engagement.authorized_targets?.join("\n") || "",
    days: 30,
  });
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    dialog.current?.showModal();
  }, []);

  const authorize = useMutation({
    mutationFn: () =>
      api.authorizeEngagement(engagement.id, {
        signed_by: roe.signed_by,
        reference: roe.reference,
        authorized_targets: roe.targets
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
        expires_in_days: Number(roe.days) || 30,
        activate: true,
      }),
    onSuccess: () => {
      onAuthorized();
      dialog.current?.close();
    },
    onError: setError,
  });

  const targets = roe.targets.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);

  return (
    <dialog
      ref={dialog}
      className="command-dialog max-w-lg"
      aria-labelledby="roe-title"
      onClose={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) dialog.current?.close();
      }}
    >
      <div className="panel-header">
        <div>
          <div className="eyebrow mb-1">Step 2 of 2 · Authorization</div>
          <h2 id="roe-title" className="text-sm font-semibold text-slate-100">Sign Rules of Engagement</h2>
        </div>
        <button className="btn-ghost" aria-label="Close authorization dialog" onClick={() => dialog.current?.close()}>
          <X className="h-4 w-4" />
        </button>
      </div>
      <form
        className="card-body space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          authorize.mutate();
        }}
      >
        <div className="rounded border border-ink-700 bg-ink-950 p-3">
          <div className="eyebrow mb-1">Assessment</div>
          <div className="text-sm font-medium text-slate-200">{engagement.name}</div>
          <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">
            The signature is bound to the scope below. Targets can be IPs, CIDRs,
            MAC patterns, hostnames, or serial device paths.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="roe-signed-by">Authorized by <span className="text-accent">*</span></label>
            <input
              id="roe-signed-by"
              className="input"
              value={roe.signed_by}
              onChange={(e) => setRoe({ ...roe, signed_by: e.target.value })}
              placeholder="Name — role"
              required
            />
          </div>
          <div>
            <label className="label" htmlFor="roe-reference">Reference <span className="text-accent">*</span></label>
            <input
              id="roe-reference"
              className="input"
              value={roe.reference}
              onChange={(e) => setRoe({ ...roe, reference: e.target.value })}
              placeholder="PO / ticket"
              required
            />
          </div>
        </div>
        <div>
          <label className="label" htmlFor="roe-targets">Authorized targets <span className="text-accent">*</span></label>
          <textarea
            id="roe-targets"
            className="input font-mono text-xs"
            rows={4}
            value={roe.targets}
            onChange={(e) => setRoe({ ...roe, targets: e.target.value })}
            placeholder={"127.0.0.1\n192.168.1.0/24\nAA:BB:CC:*\n/dev/ttyUSB0"}
            required
          />
          <p className="mt-1.5 text-[11px] text-slate-500">
            {targets.length} target{targets.length === 1 ? "" : "s"} in scope · one per line or comma-separated
          </p>
        </div>
        <div className="max-w-[180px]">
          <label className="label" htmlFor="roe-days">Valid for (days)</label>
          <input
            id="roe-days"
            className="input"
            type="number"
            min={1}
            max={365}
            value={roe.days}
            onChange={(e) => setRoe({ ...roe, days: Number(e.target.value) })}
          />
        </div>
        <ErrorBanner error={error} />
        <div className="flex justify-end gap-2 border-t border-ink-800 pt-4">
          <button type="button" className="btn-ghost" onClick={() => dialog.current?.close()}>
            Cancel
          </button>
          <button
            type="submit"
            className="btn-primary"
            disabled={!roe.signed_by || !roe.reference || !targets.length || authorize.isPending}
          >
            <ShieldCheck className="h-4 w-4" />
            {authorize.isPending ? "Authorizing…" : "Sign & authorize"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
