import { Link, useParams } from "react-router-dom";
import { Card, ErrorBox, StatusPill } from "../components";
import { fmtDate, useFetch } from "../hooks";
import type { ScanDetail } from "../types";

export default function ScanPage() {
  const { orgId, scanId } = useParams();
  const [scan, error] = useFetch<ScanDetail>(`/orgs/${orgId}/scans/${scanId}`);
  return (
    <>
      <p>
        <Link to={`/orgs/${orgId}/scans`}>← Scan history</Link>
      </p>
      <ErrorBox error={error} />
      {scan && (
        <Card title={`Scan ${fmtDate(scan.created_at)}`} actions={<StatusPill value={scan.status} />}>
          {scan.error && <p className="error">{scan.error}</p>}
          <p className="muted">
            Finished {fmtDate(scan.finished_at)} · connections per host:{" "}
            <code>{JSON.stringify(scan.stats.connections_per_host ?? {})}</code>
          </p>
          <table>
            <thead>
              <tr>
                <th>Check</th>
                <th>Target</th>
                <th>Result</th>
                <th>Time</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {scan.check_runs.map((c) => (
                <tr key={`${c.check_id}-${c.target}`}>
                  <td>
                    {c.check_id} <span className="muted">v{c.check_version}</span>
                  </td>
                  <td>{c.target}</td>
                  <td>
                    <StatusPill value={c.status === "ok" ? "completed" : c.status} />
                  </td>
                  <td>{c.duration_ms} ms</td>
                  <td className="muted">{c.status === "ok" ? "" : c.error ?? "couldn't check"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </>
  );
}
