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

// --- Prioritization & remediation (api/routes/overview.py, remediation/) ---------------
export type Category = "tls" | "headers" | "email";
export const CATEGORY_LABEL: Record<Category, string> = {
  tls: "HTTPS & certificates",
  headers: "Website protections",
  email: "Email spoofing",
};

export interface Factor {
  symbol: string;
  name: string;
  value: number;
  explanation: string;
}
export interface Risk {
  score: number;
  factors: Factor[];
}
export interface Remediation {
  key: string;
  title: string;
  category: Category;
  effort: number;
  effort_minutes: number;
  why: string;
  steps: string[];
  technical: { platform: string; snippet: string }[];
  verify: string;
  references: string[];
}
export interface IssueWithGuidance extends IssueDetail {
  risk: Risk;
  remediation: Remediation;
}
export interface ActionIssue {
  id: string;
  title: string;
  asset: string;
  severity: Severity;
  confidence: 1 | 2 | 3;
  risk: number;
}
export interface Action {
  key: string;
  title: string;
  category: Category;
  zone: string;
  effort: number;
  effort_minutes: number;
  risk_reduction: number;
  priority: number;
  effective_priority: number;
  fix_now: boolean;
  plannable: boolean;
  blocked_by: string[];
  unblocks: string[];
  why: string[];
  issues: ActionIssue[];
}
export interface ScoreValue {
  score: number;
  grade: string;
  residual_risk: number;
}
export interface Overview {
  score: ScoreValue | null;
  categories: Partial<Record<Category, ScoreValue>>;
  plan: { action: Action; reason: string }[];
  actions: Action[];
  budget_minutes: number;
  issue_counts: Partial<Record<Issue["status"], number>>;
  last_scan: Scan | null;
  last_completed_scan_at: string | null;
}
