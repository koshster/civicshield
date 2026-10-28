import type { ReactNode } from "react";
import { SEVERITY_LABEL, type Severity } from "./types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}

export function StatusPill({ value }: { value: string }) {
  return <span className={`pill status-${value}`}>{value.replace("_", " ")}</span>;
}

export function ErrorBox({ error }: { error: string | null }) {
  return error ? (
    <p className="error" role="alert">
      {error}
    </p>
  ) : null;
}

export function Card({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

/** Text shown in a monospace box with a copy button (for DNS values, file contents). */
export function CopyValue({ value }: { value: string }) {
  return (
    <div className="copy">
      <code>{value}</code>
      <button type="button" onClick={() => void navigator.clipboard.writeText(value)}>
        Copy
      </button>
    </div>
  );
}
