import { Link } from "react-router-dom";
import { Card, StatusPill } from "../components";
import { fmtDate, useFetch } from "../hooks";
import type { Scan } from "../types";

export default function ScansTab({ orgId }: { orgId: string }) {
  const [scans] = useFetch<Scan[]>(`/orgs/${orgId}/scans?limit=50`);
  return (
    <Card title="Scan history">
      <table>
        <thead>
          <tr>
            <th>Started</th>
            <th>Status</th>
            <th>Trigger</th>
            <th>New</th>
            <th>Fixed</th>
            <th>Open</th>
          </tr>
        </thead>
        <tbody>
          {scans?.map((s) => (
            <tr key={s.id}>
              <td>
                <Link to={`/orgs/${orgId}/scans/${s.id}`}>{fmtDate(s.created_at)}</Link>
              </td>
              <td>
                <StatusPill value={s.status} />
              </td>
              <td>{s.trigger}</td>
              <td>{String(s.stats.new ?? "—")}</td>
              <td>{String(s.stats.resolved ?? "—")}</td>
              <td>{String(s.stats.open ?? "—")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
