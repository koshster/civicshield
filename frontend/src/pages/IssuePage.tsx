import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Card, ErrorBox, SeverityBadge, StatusPill } from "../components";
import { fmtDate, useFetch } from "../hooks";
import { CONFIDENCE_LABEL, type IssueDetail } from "../types";

export default function IssuePage() {
  const { orgId, issueId } = useParams();
  const [issue, error, reload] = useFetch<IssueDetail>(`/orgs/${orgId}/issues/${issueId}`);
  const [reason, setReason] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);

  const setStatus = async (status: string) => {
    setActionError(null);
    try {
      await api.patch(`/orgs/${orgId}/issues/${issueId}`, { status, reason });
      reload();
    } catch (err) {
      setActionError((err as Error).message);
    }
  };

  if (!issue) return <ErrorBox error={error} />;
  const latest = issue.observations[0];

  return (
    <>
      <p>
        <Link to={`/orgs/${orgId}`}>← Overview</Link>
      </p>
      <Card
        title={issue.title}
        actions={
          <span className="row">
            <SeverityBadge severity={issue.severity} /> <StatusPill value={issue.status} />
          </span>
        }
      >
        <p>
          <strong>Where:</strong> {issue.asset} · <strong>Confidence:</strong> {CONFIDENCE_LABEL[issue.confidence]} ·{" "}
          <strong>First seen:</strong> {fmtDate(issue.first_seen_at)}
        </p>
        <p className="muted">
          Plain-English fix guidance (remediation key <code>{issue.remediation_key}</code>) arrives with the remediation
          library in the next milestone.
        </p>
      </Card>

      {latest && (
        <Card title="What we saw">
          {latest.evidence.map((ev, i) => (
            // Evidence is rendered as text only. React escapes it, so a malicious header
            // value from a scanned site can't inject markup into our dashboard.
            <pre key={i} className="evidence">
              {ev.summary}
            </pre>
          ))}
          <ul className="refs">
            {latest.references.map((r) => (
              <li key={r.id}>{r.url ? <a href={r.url} target="_blank" rel="noopener noreferrer">{r.id}</a> : r.id}</li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Triage">
        <textarea placeholder="Reason (required to accept or dismiss)" value={reason} onChange={(e) => setReason(e.target.value)} />
        <ErrorBox error={actionError} />
        <span className="row">
          <button className="secondary" onClick={() => void setStatus("accepted_risk")}>
            Accept risk
          </button>
          <button className="secondary" onClick={() => void setStatus("false_positive")}>
            Not a real issue
          </button>
          {issue.status !== "open" && issue.status !== "fixed" && <button onClick={() => void setStatus("open")}>Reopen</button>}
        </span>
      </Card>
    </>
  );
}
