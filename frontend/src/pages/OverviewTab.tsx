import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, ErrorBox, SeverityBadge } from "../components";
import { fmtDate, useFetch } from "../hooks";
import { CONFIDENCE_LABEL, type Issue, type Scan } from "../types";

export default function OverviewTab({ orgId }: { orgId: string }) {
  const [issues, error, reloadIssues] = useFetch<Issue[]>(`/orgs/${orgId}/issues?status=open`);
  const [scans, , reloadScans] = useFetch<Scan[]>(`/orgs/${orgId}/scans?limit=1`);
  const [scanError, setScanError] = useState<string | null>(null);
  const last = scans?.[0];
  const running = last && (last.status === "queued" || last.status === "running");

  const startScan = async () => {
    setScanError(null);
    try {
      await api.post(`/orgs/${orgId}/scans`);
      reloadScans();
    } catch (err) {
      setScanError((err as Error).message);
    }
  };

  // Until the prioritization engine lands (roadmap week 4), "top 3" = highest
  // severity, then highest confidence. The API already returns that order.
  const top = issues?.filter((i) => i.confidence >= 2).slice(0, 3) ?? [];

  return (
    <>
      <Card
        title="Latest scan"
        actions={
          <span className="row">
            <button onClick={() => void startScan()} disabled={!!running}>
              {running ? "Scan in progress…" : "Run a scan now"}
            </button>
            <button className="secondary" onClick={() => (reloadScans(), reloadIssues())}>
              Refresh
            </button>
          </span>
        }
      >
        <ErrorBox error={scanError} />
        {last ? (
          <p>
            <Link to={`/orgs/${orgId}/scans/${last.id}`}>{last.status}</Link> · started {fmtDate(last.created_at)}
            {last.error && <span className="error"> · {last.error}</span>}
          </p>
        ) : (
          <p className="muted">No scans yet. Verify a domain and record permission first.</p>
        )}
      </Card>

      <Card title="Fix these first">
        {top.length === 0 && <p className="muted">Nothing urgent. 🎉</p>}
        <ol className="fixlist">
          {top.map((i) => (
            <li key={i.id}>
              <SeverityBadge severity={i.severity} /> <Link to={`/orgs/${orgId}/issues/${i.id}`}>{i.title}</Link>
              <span className="muted"> on {i.asset}</span>
            </li>
          ))}
        </ol>
      </Card>

      <Card title={`All open issues (${issues?.length ?? 0})`}>
        <ErrorBox error={error} />
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Issue</th>
              <th>Where</th>
              <th>Confidence</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            {issues?.map((i) => (
              <tr key={i.id}>
                <td>
                  <SeverityBadge severity={i.severity} />
                </td>
                <td>
                  <Link to={`/orgs/${orgId}/issues/${i.id}`}>{i.title}</Link>
                </td>
                <td>{i.asset}</td>
                <td>{CONFIDENCE_LABEL[i.confidence]}</td>
                <td>{fmtDate(i.first_seen_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
