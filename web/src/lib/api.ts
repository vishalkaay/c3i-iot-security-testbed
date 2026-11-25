// Typed API client. Auth token is kept in localStorage; a 401 clears it.

import type {
  Asset,
  Capability,
  Engagement,
  Finding,
  FindingsSummary,
  Job,
  JobLog,
  PluginManifest,
  Report,
  SystemInfo,
  TokenResponse,
  User,
} from "./types";

const TOKEN_KEY = "c3i_token";

export const auth = {
  get token(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  },
  set(token: string) {
    localStorage.setItem(TOKEN_KEY, token);
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
  },
  get isAuthed(): boolean {
    return !!localStorage.getItem(TOKEN_KEY);
  },
};

export class ApiError extends Error {
  status: number;
  code?: string;
  details?: unknown;
  constructor(status: number, message: string, code?: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const BASE = "/api/v1";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (auth.token) headers.set("Authorization", `Bearer ${auth.token}`);
  if (init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401) {
    auth.clear();
  }
  if (!res.ok) {
    let body: any = {};
    try {
      body = await res.json();
    } catch {
      /* ignore */
    }
    throw new ApiError(
      res.status,
      body.message || body.detail || res.statusText,
      body.error,
      body.details,
    );
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return (await res.json()) as T;
  return (await res.text()) as unknown as T;
}

export const api = {
  // ---- auth ----
  login: (username: string, password: string) =>
    request<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<User>("/auth/me"),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<User>("/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),

  // ---- system ----
  systemInfo: () => request<SystemInfo>("/system/info"),
  hardwareStatus: () =>
    request<{
      gpio_backend: string;
      gpio_is_mock: boolean;
      serial_ports: string[];
      uart_port: string | null;
      ready_for_physical_tests: boolean;
      pins: Record<string, string | number | null>;
      power_polarity?: Record<string, { power_on: string; power_off: string }>;
      debug_probes?: {
        vid_pid: string;
        name: string;
        transports: string;
        usb_description: string;
      }[];
      storage_devices?: {
        name: string;
        size: string;
        type: string;
        transport: string | null;
        model: string | null;
        serial: string | null;
        read_only: boolean;
      }[];
      i2c_buses?: string[];
      spi_buses?: string[];
      logic_analyzer_available?: boolean;
      readiness?: {
        uart: boolean;
        gpio_automation: boolean;
        spi: boolean;
        i2c: boolean;
        logic_decode: boolean;
      };
    }>("/system/hardware"),
  capabilities: () => request<Capability[]>("/plugins/capabilities"),
  upload: async (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return request<{ filename: string; path: string; size: number }>("/system/uploads", {
      method: "POST",
      body: fd,
    });
  },
  cveLookup: (keywords: string[], limit = 25) =>
    request<{ count: number; results: any[] }>("/system/cve/lookup", {
      method: "POST",
      body: JSON.stringify({ keywords, limit }),
    }),
  uploads: () =>
    request<{ filename: string; size: number; path: string; modified: string }[]>(
      "/system/uploads",
    ),
  uploadDownloadUrl: (filename: string) =>
    `/api/v1/system/uploads/${encodeURIComponent(filename)}/download`,
  exports: (engagement_id?: string) =>
    request<
      {
        id: string;
        kind: string;
        filename: string;
        size: number;
        sha256: string;
        note?: string;
        job_id: string;
        plugin?: string;
        action?: string;
        created_at: string;
        download_url: string;
      }[]
    >(`/system/exports${engagement_id ? `?engagement_id=${engagement_id}` : ""}`),
  jobEvidence: (id: string) =>
    request<
      { id: string; kind: string; filename: string; sha256: string; size: number; note?: string }[]
    >(`/jobs/${id}/evidence`),
  evidenceDownloadUrl: (jobId: string, evidenceId: string) =>
    `/api/v1/jobs/${jobId}/evidence/${evidenceId}/download`,

  // ---- plugins ----
  plugins: () => request<PluginManifest[]>("/plugins"),
  plugin: (name: string) => request<PluginManifest>(`/plugins/${name}`),

  // ---- engagements ----
  engagements: () => request<Engagement[]>("/engagements"),
  engagement: (id: string) => request<Engagement>(`/engagements/${id}`),
  createEngagement: (body: { name: string; client?: string; description?: string }) =>
    request<Engagement>("/engagements", { method: "POST", body: JSON.stringify(body) }),
  authorizeEngagement: (
    id: string,
    body: {
      signed_by: string;
      reference: string;
      authorized_targets: string[];
      expires_in_days?: number;
      activate?: boolean;
    },
  ) =>
    request<Engagement>(`/engagements/${id}/authorize`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  assets: (id: string) => request<Asset[]>(`/engagements/${id}/assets`),

  // ---- jobs ----
  jobs: (params?: { engagement_id?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.engagement_id) q.set("engagement_id", params.engagement_id);
    if (params?.limit) q.set("limit", String(params.limit));
    const qs = q.toString();
    return request<Job[]>(`/jobs${qs ? `?${qs}` : ""}`);
  },
  job: (id: string) => request<Job>(`/jobs/${id}`),
  jobLogs: (id: string) => request<JobLog[]>(`/jobs/${id}/logs`),
  createJob: (body: {
    engagement_id?: string;
    asset_id?: string;
    plugin: string;
    action: string;
    params: Record<string, unknown>;
  }) => request<Job>("/jobs", { method: "POST", body: JSON.stringify(body) }),
  cancelJob: (id: string) => request<Job>(`/jobs/${id}/cancel`, { method: "POST" }),

  // ---- findings ----
  findings: (params?: { engagement_id?: string; severity?: string; domain?: string }) => {
    const q = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => v && q.set(k, String(v)));
    const qs = q.toString();
    return request<Finding[]>(`/findings${qs ? `?${qs}` : ""}`);
  },
  findingsSummary: (engagement_id?: string) =>
    request<FindingsSummary>(
      `/findings/summary${engagement_id ? `?engagement_id=${engagement_id}` : ""}`,
    ),

  // ---- reports ----
  reports: (engagement_id: string) => request<Report[]>(`/engagements/${engagement_id}/reports`),
  createReport: (engagement_id: string, kind: string) =>
    request<Report>(`/engagements/${engagement_id}/reports`, {
      method: "POST",
      body: JSON.stringify({ kind }),
    }),
  reportUrl: (id: string, mode: "view" | "download" = "view") => `/api/v1/reports/${id}/${mode}`,
};

/**
 * Authenticated download helper.
 *
 * Plain <a href> links and window.open cannot attach the Authorization header,
 * so report/evidence artefacts are fetched as a Blob *with* the token and then
 * handed to the browser via an object URL. Attempting to download without a
 * valid session surfaces the API error message instead of a silent 401 body.
 */
export async function downloadFile(apiPath: string, filename: string): Promise<void> {
  const headers = new Headers();
  if (auth.token) headers.set("Authorization", `Bearer ${auth.token}`);
  const res = await fetch(apiPath, { headers });
  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = await res.json();
      message = body?.message || message;
    } catch {
      /* binary or empty body */
    }
    throw new Error(`Download failed (${res.status}): ${message}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Open an artefact (HTML/PDF report) in a new tab, auth included. */
export async function openFile(apiPath: string): Promise<void> {
  const headers = new Headers();
  if (auth.token) headers.set("Authorization", `Bearer ${auth.token}`);
  const res = await fetch(apiPath, { headers });
  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = await res.json();
      message = body?.message || message;
    } catch {
      /* empty */
    }
    throw new Error(`Open failed (${res.status}): ${message}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener");
  // Revoke lazily: the new tab needs a moment to load the blob.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// WebSocket helper for live job events.
export function jobSocket(path: string, onEvent: (e: any) => void): WebSocket | null {
  const token = auth.token;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = token
    ? `${proto}://${location.host}${path}?token=${encodeURIComponent(token)}`
    : `${proto}://${location.host}${path}`;
  const ws = new WebSocket(url);
  ws.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data));
    } catch {
      /* ignore */
    }
  };
  return ws;
}
