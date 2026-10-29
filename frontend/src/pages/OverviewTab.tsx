import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, ErrorBox, SeverityBadge } from "../components";
import { fmtDate, useFetch } from "../hooks";
import { CATEGORY_LABEL, type Action, type Category, type Overview } from "../types";

export const fmtMinutes = (m: number) => (m < 60 ? `${m} min` : m < 480 ? `${m / 60} h` : "a day or more");

/** "Why is this ranked here?": the same numbers the backend used to rank it. */
function WhyRank({ action }: { action: Action }) {
  return (
    <details className="why">
      <summary>Why this rank?</summary>
      <ul>
        {action.why.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
    </details>
  );
}

function ScoreCard({ ov }: { ov: Overview }) {
  if (!ov.score) {
    return (
      <Card title="Security score">
        <p className="muted">Your score appears after the first scan finishes.</p>
      </Card>
    );
  }
  return (
    <Card title="Security score">
      <div className="score-row">
        <div className={`score grade-${ov.score.grade}`}>
          <span className="score-num">{ov.score.score}</span>
          <span className="score-grade">{ov.score.grade}</span>
        </div>
        <ul className="score-cats">
          {(Object.keys(ov.categories) as Category[]).map((c) => (
            <li key={c}>
              <span>{CATEGORY_LABEL[c] ?? c}</span>
              <meter min={0} max={100} low={60} high={80} optimum={100} value={ov.categories[c]!.score} />
              <strong>{ov.categories[c]!.score}</strong>
            </li>
          ))}
        </ul>
      </div>
      <p className="muted small">
        Based on what the last scan could check ({fmtDate(ov.last_completed_scan_at)}). Fixing anything above "info" level
        raises it. Accepting a risk doesn't.
      </p>
    </Card>
  );
}

function PlanCard({ ov, orgId }: { ov: Overview; orgId: string }) {
  return (
    <Card title="Fix these this week">
      {ov.score && ov.plan.length === 0 && <p className="muted">Nothing to fix right now. Nice work. 🎉</p>}
      {!ov.score && <p className="muted">Run a scan to get your plan.</p>}
      <ol className="plan">
        {ov.plan.map(({ action, reason }) => (
          <li key={`${action.key}@${action.zone}`} className={action.fix_now ? "fix-now" : undefined}>
            <div className="plan-head">
              <Link to={`/orgs/${orgId}/issues/${action.issues[0].id}`}>{action.title}</Link>
              <span className="muted">about {fmtMinutes(action.effort_minutes)}</span>
            </div>
            <p className="muted small">{reason}</p>
            <WhyRank action={action} />
          </li>
        ))}
      </ol>
      {ov.plan.length > 0 && (
        <p className="muted small">Sized to fit about {fmtMinutes(ov.budget_minutes)} of volunteer time.</p>
      )}
    </Card>
  );
}

function ActionsCard({ ov, orgId }: { ov: Overview; orgId: string }) {
  return (
    <Card title={`All open tasks (${ov.actions.length})`}>
      <table>
        <thead>
          <tr>
            <th>Task</th>
            <th>Fixes</th>
            <th>Effort</th>
            <th>Priority</th>
          </tr>
        </thead>
        <tbody>
          {ov.actions.map((a) => (
            <tr key={`${a.key}@${a.zone}`}>
              <td>
                <Link to={`/orgs/${orgId}/issues/${a.issues[0].id}`}>{a.title}</Link>
                {a.blocked_by.length > 0 && <div className="muted small">Waiting on: {a.blocked_by.join(", ")}</div>}
                <WhyRank action={a} />
              </td>
              <td>
                {a.issues.map((i) => (
                  <div key={i.id}>
                    <SeverityBadge severity={i.severity} />{" "}
                    <Link to={`/orgs/${orgId}/issues/${i.id}`}>{i.title}</Link>
                    <span className="muted"> on {i.asset}</span>
                  </div>
                ))}
              </td>
              <td>{fmtMinutes(a.effort_minutes)}</td>
              <td>{a.effective_priority.toFixed(1)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

export default function OverviewTab({ orgId }: { orgId: string }) {
  const [ov, error, reload] = useFetch<Overview>(`/orgs/${orgId}/overview`);
  const [scanError, setScanError] = useState<string | null>(null);
  const last = ov?.last_scan;
  const running = last && (last.status === "queued" || last.status === "running");

  const startScan = async () => {
    setScanError(null);
    try {
      await api.post(`/orgs/${orgId}/scans`);
      reload();
    } catch (err) {
      setScanError((err as Error).message);
    }
  };

  return (
    <>
      <Card
        title="Latest scan"
        actions={
          <span className="row">
            <button onClick={() => void startScan()} disabled={!!running}>
              {running ? "Scan in progress…" : "Run a scan now"}
            </button>
            <button className="secondary" onClick={reload}>
              Refresh
            </button>
          </span>
        }
      >
        <ErrorBox error={scanError ?? error} />
        {last ? (
          <p>
            <Link to={`/orgs/${orgId}/scans/${last.id}`}>{last.status}</Link> · started {fmtDate(last.created_at)}
            {last.error && <span className="error"> · {last.error}</span>}
          </p>
        ) : (
          <p className="muted">No scans yet. Verify a domain and record permission first.</p>
        )}
      </Card>
      {ov && (
        <>
          <ScoreCard ov={ov} />
          <PlanCard ov={ov} orgId={orgId} />
          {ov.actions.length > 0 && <ActionsCard ov={ov} orgId={orgId} />}
        </>
      )}
    </>
  );
}
