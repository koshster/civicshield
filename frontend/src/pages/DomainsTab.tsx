import { useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Card, CopyValue, ErrorBox, StatusPill } from "../components";
import { fmtDate, useFetch } from "../hooks";
import type { Domain } from "../types";

function DomainCard({ orgId, domain, onChange }: { orgId: string; domain: Domain; onChange: () => void }) {
  const [detail, , reload] = useFetch<Domain>(`/orgs/${orgId}/domains/${domain.id}`);
  const [busy, setBusy] = useState(false);
  const d = detail ?? domain;
  const ins = d.instructions;

  const verify = async () => {
    setBusy(true);
    await api.post(`/orgs/${orgId}/domains/${domain.id}/verify`).catch(() => undefined);
    setBusy(false);
    reload();
    onChange();
  };

  return (
    <Card
      title={d.name}
      actions={
        <span className="row">
          <StatusPill value={d.status} />
          <button onClick={() => void verify()} disabled={busy}>
            {busy ? "Checking…" : "Check verification"}
          </button>
        </span>
      }
    >
      <p className="muted">
        Covers {d.scope_kind === "zone" ? "this domain and its subdomains" : "only this exact website address"} · last
        checked {fmtDate(d.last_checked_at)}
      </p>
      {d.last_check_error && <p className="error">Last check: {d.last_check_error}</p>}
      {ins && d.status !== "verified" && (
        <div className="instructions">
          <p>
            <strong>{ins.summary}</strong>
          </p>
          <ol>
            {ins.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
          {ins.record_value && <CopyValue value={ins.record_value} />}
          {ins.file_contents && <CopyValue value={ins.file_contents} />}
        </div>
      )}
    </Card>
  );
}

export default function DomainsTab({ orgId }: { orgId: string }) {
  const { user } = useAuth();
  const [domains, error, reload] = useFetch<Domain[]>(`/orgs/${orgId}/domains`);
  const [name, setName] = useState("");
  const [method, setMethod] = useState<"dns_txt" | "http_file">("dns_txt");
  const [formError, setFormError] = useState<string | null>(null);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post(`/orgs/${orgId}/domains`, { name, verification_method: method });
      setName("");
      reload();
    } catch (err) {
      setFormError((err as Error).message);
    }
  };

  return (
    <>
      <ErrorBox error={error} />
      {domains?.map((d) => <DomainCard key={d.id} orgId={orgId} domain={d} onChange={reload} />)}
      {user?.is_operator && (
        <Card title="Add a domain">
          <form className="inline" onSubmit={(e) => void add(e)}>
            <input placeholder="example.org" value={name} onChange={(e) => setName(e.target.value)} required />
            <select value={method} onChange={(e) => setMethod(e.target.value as "dns_txt" | "http_file")}>
              <option value="dns_txt">DNS record (recommended)</option>
              <option value="http_file">Upload a file to the website</option>
            </select>
            <button type="submit">Add</button>
          </form>
          <ErrorBox error={formError} />
        </Card>
      )}
    </>
  );
}
