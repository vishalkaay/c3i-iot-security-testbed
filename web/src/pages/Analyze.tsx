import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileUp } from "lucide-react";
import { useRef, useState } from "react";
import { api, downloadFile } from "../lib/api";
import {
  Card,
  EmptyState,
  ErrorBanner,
  InlineCode,
  PageHeader,
  Spinner,
  Step,
  Table,
} from "../components/ui";
import { fmtBytes, fmtDate } from "../lib/utils";
import ResultView from "../components/ResultView";

interface JobLine {
  level: string;
  message: string;
}

const FIRMWARE_ACTIONS = [
  { name: "analyse", label: "Full analysis", hint: "signatures + entropy + secrets + SBOM + CVEs" },
  { name: "secrets", label: "Secrets only", hint: "keys, passwords, shadow hashes" },
  { name: "sbom", label: "Components + CVEs", hint: "BusyBox, OpenSSL, openssl… → NVD" },
  { name: "entropy", label: "Entropy profile", hint: "is it compressed/encrypted?" },
  { name: "extract", label: "Carve / extract", hint: "filesystem and archive recovery" },
];

export default function Analyze() {
  const qc = useQueryClient();
  const [engagementId, setEngagementId] = useState("");
  const [action, setAction] = useState("analyse");
  const [uploaded, setUploaded] = useState<{ filename: string; path: string; size: number } | null>(null);
  const [logs, setLogs] = useState<JobLine[]>([]);
  const [result, setResult] = useState<any>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const uploadCard = useRef<HTMLDivElement>(null);

  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.engagements });
  const uploads = useQuery({ queryKey: ["uploads"], queryFn: api.uploads });

  const upload = useMutation({
    mutationFn: (f: File) => api.upload(f),
    onSuccess: (res) => {
      setUploaded(res);
      setError(null);
      qc.invalidateQueries({ queryKey: ["uploads"] });
    },
    onError: setError,
  });

  const run = useMutation({
    mutationFn: () =>
      api.createJob({
        engagement_id: engagementId || undefined,
        plugin: "firmware",
        action,
        params: { path: uploaded!.path },
      }),
    onMutate: () => {
      setLogs([]);
      setResult(null);
      setError(null);
    },
    onSuccess: async (job) => {
      setJobId(job.id);
      // Poll the job until it finishes (kept simple + robust).
      for (let i = 0; i < 240; i++) {
        await new Promise((r) => setTimeout(r, 400));
        const j = await api.job(job.id);
        const ls = await api.jobLogs(job.id);
        setLogs(ls.map((l) => ({ level: l.level, message: l.message })));
        if (j.status === "succeeded" || j.status === "failed" || j.status === "cancelled") {
          setResult(j.result);
          qc.invalidateQueries({ queryKey: ["jobEvidence", job.id] });
          if (j.error) setError(new Error(j.error));
          return;
        }
      }
    },
    onError: setError,
  });

  return (
    <div className="mx-auto max-w-[1100px] space-y-6 fade-in">
      <PageHeader
        title="Firmware analysis"
        subtitle="Turn a binary into evidence. Inspect filesystems, embedded secrets, and software components on this host."
      />

      <ErrorBanner error={error} />

      <Card title="How it works">
        <div className="grid md:grid-cols-3 gap-6">
          <Step n={1} title="Upload the file" done={!!uploaded}>
            <p>Firmware <InlineCode>.bin/.img</InlineCode>, a boot log, or a capture.</p>
          </Step>
          <Step n={2} title="Choose an analysis" done={!!result}>
            <p>Pick what to look for, then run it.</p>
          </Step>
          <Step n={3} title="Export results" done={false}>
            <p>Findings and raw artefacts download from the <b>Evidence &amp; reports</b> page.</p>
          </Step>
        </div>
      </Card>

      <div ref={uploadCard} className="scroll-mt-24">
      <Card title="Step 1 — Upload">
        <label onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); if (!upload.isPending && e.dataTransfer.files[0]) upload.mutate(e.dataTransfer.files[0]); }} className="instrument-grid relative flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-ink-600 bg-ink-950 px-6 py-12 cursor-pointer transition-colors hover:border-accent/60">
          <div className="brand-icon mb-2"><FileUp className="h-5 w-5" /></div>
          <span className="text-sm text-slate-300">
            {upload.isPending ? "Uploading…" : "Drop a firmware image here, or browse files"}
          </span>
          {uploaded && (
            <span className="text-xs text-emerald-400 font-mono">
              {uploaded.filename} · {fmtBytes(uploaded.size)}
            </span>
          )}
          <input
            type="file"
            aria-label="Upload firmware image"
            disabled={upload.isPending}
            className="absolute inset-0 cursor-pointer opacity-0"
            onChange={(e) => e.target.files?.[0] && upload.mutate(e.target.files[0])}
          />
        </label>
        {uploaded && (
          <div className="mt-3 text-xs text-slate-500">
            Server path: <InlineCode>{uploaded.path}</InlineCode>
          </div>
        )}
      </Card>
      </div>

      <Card title="Step 2 — Analysis">
        <div className="grid md:grid-cols-2 gap-3 mb-4">
          <div>
            <label className="label" htmlFor="analyze-engagement">Attach to engagement (optional)</label>
            <select
              id="analyze-engagement"
              className="input"
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
            >
              <option value="">— none —</option>
              {engagements.data?.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="analyze-action">Analysis</label>
            <select id="analyze-action" className="input" value={action} onChange={(e) => setAction(e.target.value)}>
              {FIRMWARE_ACTIONS.map((a) => (
                <option key={a.name} value={a.name}>
                  {a.label} — {a.hint}
                </option>
              ))}
            </select>
          </div>
        </div>
        <button
          className="btn-primary"
          disabled={!uploaded || run.isPending}
          onClick={() => run.mutate()}
        >
          {run.isPending ? "Running…" : "Run analysis"}
        </button>

        {logs.length > 0 && (
          <div role="log" aria-label="Analysis log" className="terminal mt-4 max-h-56 overflow-auto p-4">
            {logs.map((l, i) => (
              <div key={i} className={l.level === "error" ? "text-red-400" : "text-slate-400"}>
                <span className="text-slate-600">» </span>
                {l.message}
              </div>
            ))}
          </div>
        )}
      </Card>

      {result && (
        <Card title="Step 3 — Results" hint={jobId ? `job ${jobId.slice(0, 10)}` : ""}>
           <ResultView result={result} />
           <ResultSummary jobId={jobId} />
        </Card>
      )}

      <Card title="Uploads" hint="Files retained on this host" dense>
        {uploads.isLoading ? (
          <div className="p-5"><Spinner /></div>
        ) : !uploads.data?.length ? (
          <EmptyState title="No uploads yet" hint="Upload a firmware image above to get started." />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>File</th>
                <th>Size</th>
                <th>Uploaded</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {uploads.data.map((u) => (
                <tr key={u.filename}>
                  <td className="td max-w-[320px] truncate font-mono text-xs text-slate-300" title={u.filename}>{u.filename}</td>
                  <td className="td whitespace-nowrap text-slate-400">{fmtBytes(u.size)}</td>
                  <td className="td whitespace-nowrap text-[11px] text-slate-500">{fmtDate(u.modified)}</td>
                  <td className="td">
                    <div className="flex justify-end gap-2">
                      <button
                        className="btn-ghost"
                        onClick={() => {
                          setUploaded({
                            filename: u.filename,
                            path: u.path,
                            size: u.size,
                          });
                          uploadCard.current?.scrollIntoView({ behavior: "smooth", block: "start" });
                        }}
                      >
                        Use
                      </button>
                      <button
                        className="btn-ghost"
                        onClick={() => downloadFile(api.uploadDownloadUrl(u.filename), u.filename).catch(setError)}
                      >
                        <Download className="h-3.5 w-3.5" /> Download
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}

function ResultSummary({ jobId }: { jobId: string | null }) {
  const evidence = useQuery({
    queryKey: ["jobEvidence", jobId],
    queryFn: () => api.jobEvidence(jobId!),
    enabled: !!jobId,
  });

  return (
    <div className="space-y-4">
      {evidence.data?.length ? (
        <div>
          <div className="label">Artefacts from this run</div>
          <div className="flex flex-wrap gap-2">
            {evidence.data.map((e) => (
              <button
                key={e.id}
                className="btn-ghost text-xs"
                onClick={() =>
                  downloadFile(api.evidenceDownloadUrl(jobId!, e.id), e.filename)
                }
              >
                <Download className="h-3.5 w-3.5" /> {e.filename} ({fmtBytes(e.size)})
              </button>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
