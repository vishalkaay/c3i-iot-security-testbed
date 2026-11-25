// Shared API types (mirrors backend/app/schemas.py).

export interface TokenResponse {
  access_token: string;
  token_type: string;
  role: string;
  username: string;
}

export interface User {
  id: string;
  username: string;
  email?: string | null;
  full_name?: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface Engagement {
  id: string;
  name: string;
  client?: string | null;
  description?: string | null;
  status: string;
  authorized_targets: string[];
  roe_reference?: string | null;
  roe_signed_by?: string | null;
  roe_accepted_at?: string | null;
  roe_expires_at?: string | null;
  created_at: string;
}

export interface Asset {
  id: string;
  engagement_id: string;
  kind: string;
  identifier: string;
  name?: string | null;
  vendor?: string | null;
  model?: string | null;
  firmware?: string | null;
  attributes: Record<string, unknown>;
  created_at: string;
}

export interface Job {
  id: string;
  engagement_id?: string | null;
  asset_id?: string | null;
  plugin: string;
  action: string;
  safety: string;
  params: Record<string, unknown>;
  status: string;
  progress: number;
  message?: string | null;
  error?: string | null;
  result?: Record<string, unknown> | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface JobLog {
  ts: string;
  level: string;
  message: string;
}

export interface Finding {
  id: string;
  job_id?: string | null;
  engagement_id?: string | null;
  asset_id?: string | null;
  title: string;
  category: string;
  domain: string;
  severity: string;
  cvss_score?: number | null;
  epss_score?: number | null;
  cve_ids: string[];
  cwe_ids: string[];
  description?: string | null;
  evidence?: string | null;
  remediation?: string | null;
  references: string[];
  extra: Record<string, unknown>;
  created_at: string;
}

export interface FindingsSummary {
  counts: Record<string, number>;
  risk_score: number;
  by_domain: Record<string, number>;
  total: number;
}

export interface Capability {
  id: string;
  label: string;
  kind: string;
  available: boolean;
  hint: string;
  install?: string;
}

export interface ModuleSpec {
  name: string;
  title: string;
  description: string;
  safety: string;
  tags: string[];
  mitre: string[];
  capabilities: string[];
  missing_capabilities: string[];
  params_schema: {
    properties?: Record<string, any>;
    required?: string[];
    title?: string;
    type?: string;
  };
}

export interface PluginManifest {
  name: string;
  domain: string;
  title: string;
  description: string;
  capabilities: Capability[];
  modules: ModuleSpec[];
}

export interface SystemInfo {
  version: string;
  environment: string;
  /** True when the backend runs with C3I_DEV_NO_AUTH (dev only). */
  dev_no_auth?: boolean;
  invasive_enabled: boolean;
  assistant_enabled: boolean;
  plugins: { name: string; domain: string; title: string; modules: number }[];
  capabilities: Capability[];
  vulnerability_intel: Record<string, unknown>;
  data_dir: string;
}

export interface Report {
  id: string;
  engagement_id: string;
  kind: string;
  path: string;
  summary: Record<string, any>;
  created_at: string;
}
