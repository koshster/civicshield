import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Card, CopyValue, ErrorBox, SeverityBadge, StatusPill } from "../components";
import { fmtDate, useFetch } from "../hooks";
import { CONFIDENCE_LABEL, type IssueWithGuidance, type Remediation } from "../types";
import { fmtMinutes } from "./OverviewTab";

/** Plain-text email for the volunteer or vendor who'll make the change. */
function helperEmail(r: Remediation, asset: string): string {
  const lines = [
    `Hi, could you help us with this? ${r.title}.`,
    "",
    r.why,
    "",
    "What needs doing:",
    ...r.steps.map((s, i) => `${i + 1}. ${s}`),
    "",
    ...r.technical.flatMap((t) => [`${t.platform}:`, t.snippet, ""]),
  ];
  if (r.verify) lines.push(`To check it worked: ${r.verify}`, "");
  if (r.references.length) lines.push("References:", ...r.references, "");
  lines.push(`(Found by CivicShield on ${asset}. Estimated effort: about ${fmtMinutes(r.effort_minutes)}.)`);
  return lines.join("\n");
}

export default function IssuePage() {
  const { orgId, issueId } = useParams();
  const [issue, error, reload] = useFetch<IssueWithGuidance>(`/orgs/${orgId}/issues/${issueId}`);
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

  const [copied, setCopied] = useState(false);
  if (!issue) return <ErrorBox error={error} />;
  const latest = issue.observations[0];
  const r = issue.remediation;
  const copyEmail = async () => {
    await navigator.clipboard.writeText(helperEmail(r, issue.asset));
    setCopied(true);
  };

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
      </Card>

      <Card
        title={`How to fix it: ${r.title}`}
        actions={
          <button className="secondary" onClick={() => void copyEmail()}>
            {copied ? "Copied ✓" : "Copy as email for your tech helper"}
          </button>
        }
      >
        <p>{r.why}</p>
        <p className="muted small">Estimated effort: about {fmtMinutes(r.effort_minutes)}.</p>
        <ol>
          {r.steps.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ol>
        {r.technical.length > 0 && (
          <details className="why" open>
            <summary>For your tech helper</summary>
            {r.technical.map((t) => (
              <div key={t.platform + t.snippet} className="snippet">
                <strong>{t.platform}</strong>
                <CopyValue value={t.snippet} />
              </div>
            ))}
            {r.verify && (
              <p>
                <strong>Check it worked:</strong> <code>{r.verify}</code>
              </p>
            )}
            {r.references.length > 0 && (
              <ul className="refs">
                {r.references.map((u) => (
                  <li key={u}>
                    <a href={u} target="_blank" rel="noopener noreferrer">
                      {u}
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </details>
        )}
      </Card>

      <Card title={`Why this rank? Risk ${issue.risk.score.toFixed(0)}/100`}>
        <p className="muted small">Risk = 100 × S × E × X × C × U. A factor near zero pulls the whole score down.</p>
        <table>
          <tbody>
            {issue.risk.factors.map((f) => (
              <tr key={f.symbol}>
                <td>
                  <strong>{f.symbol}</strong> {f.name}
                </td>
                <td>{f.value.toFixed(2)}</td>
                <td className="muted">{f.explanation}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
