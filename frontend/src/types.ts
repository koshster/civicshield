// Mirrors the backend's Pydantic response schemas (src/civicshield/api/schemas.py).

export type Severity = 0 | 1 | 2 | 3 | 4; // info..critical (IntEnum on the backend)
export const SEVERITY_LABEL = ["Info", "Low", "Medium", "High", "Critical"] as const;
export const CONFIDENCE_LABEL = ["", "Low", "Medium", "High"] as const;

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_operator: boolean;
}
export interface Session {
  user: User;
  csrf_token: string;
}
export interface Org {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}
export interface Instructions {
  method: "dns_txt" | "http_file";
  summary: string;
  steps: string[];
  record_name: string | null;
  record_value: string | null;
  file_url: string | null;
  file_contents: string | null;
}
export interface Domain {
  id: string;
  name: string;
  verification_method: "dns_txt" | "http_file";
  status: "pending" | "verified" | "failed";
  scope_kind: "zone" | "host_only";
  verified_at: string | null;
  last_checked_at: string | null;
  last_check_error: string | null;
  instructions?: Instructions;
}
export interface AuthorizationText {
  version: string;
  text: string;
  sha256: string;
}
export interface Authorization {
  id: string;
  signer_name: string;
  signer_title: string;
  signer_email: string;
  text_version: string;
  max_impact: number;
  granted_at: string;
  expires_at: string;
  revoked_at: string | null;
  domain_names: string[];
}
export interface Scan {
  id: string;
  status: "queued" | "running" | "completed" | "failed" | "blocked";
  trigger: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  stats: Record<string, unknown>;
}
export interface CheckRun {
  check_id: string;
  check_version: string;
  target: string;
  status: "ok" | "error" | "timeout" | "skipped";
  duration_ms: number;
  error: string | null;
}
export interface ScanDetail extends Scan {
  check_runs: CheckRun[];
}
export interface Issue {
  id: string;
  check_id: string;
  finding_type: string;
  asset: string;
  title: string;
  severity: Severity;
  confidence: 1 | 2 | 3;
  status: "open" | "fixed" | "accepted_risk" | "false_positive";
  remediation_key: string;
  facts: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
}
export interface Evidence {
  kind: string;
  summary: string;
  data: Record<string, unknown>;
}
export interface Reference {
  kind: string;
  id: string;
  url: string | null;
}
export interface IssueDetail extends Issue {
  observations: { scan_id: string; created_at: string; evidence: Evidence[]; references: Reference[] }[];
}
