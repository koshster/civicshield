import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Card, ErrorBox } from "../components";
import { fmtDate, useFetch } from "../hooks";
import type { Authorization, AuthorizationText, Domain } from "../types";

export default function AuthorizationTab({ orgId }: { orgId: string }) {
  const [text] = useFetch<AuthorizationText>("/authorization-text");
  const [domains] = useFetch<Domain[]>(`/orgs/${orgId}/domains`);
  const [auths, , reload] = useFetch<Authorization[]>(`/orgs/${orgId}/authorizations`);
  const [form, setForm] = useState({ signer_name: "", signer_title: "", signer_email: "" });
  const [selected, setSelected] = useState<string[]>([]);
  const [lowImpact, setLowImpact] = useState(false);
  const [agree, setAgree] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const verified = domains?.filter((d) => d.status === "verified") ?? [];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!text) return;
    setError(null);
    try {
      await api.post(`/orgs/${orgId}/authorizations`, {
        ...form,
        domain_ids: selected,
        text_version: text.version,
        text_sha256: text.sha256, // proves we showed this exact text
        max_impact: lowImpact ? 2 : 1,
        agree,
      });
      setAgree(false);
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const revoke = async (id: string) => {
    if (!window.confirm("Revoke this permission? All scanning stops immediately.")) return;
    await api.post(`/orgs/${orgId}/authorizations/${id}/revoke`);
    reload();
  };

  return (
    <>
      <Card title="Permission on record">
        {auths?.length === 0 && <p className="muted">No permission recorded yet. Scans can't run until there is one.</p>}
        <ul className="list">
          {auths?.map((a) => (
            <li key={a.id}>
              <strong>{a.signer_name}</strong> ({a.signer_title}) for {a.domain_names.join(", ")} · granted{" "}
              {fmtDate(a.granted_at)} · expires {fmtDate(a.expires_at)}{" "}
              {a.revoked_at ? (
                <span className="pill status-failed">revoked</span>
              ) : (
                <button className="link danger" onClick={() => void revoke(a.id)}>
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Give permission to scan">
        {verified.length === 0 ? (
          <p className="muted">Verify at least one domain first (Domains tab).</p>
        ) : (
          <form onSubmit={(e) => void submit(e)} className="stack">
            <pre className="legal">{text?.text}</pre>
            <fieldset>
              <legend>Domains covered</legend>
              {verified.map((d) => (
                <label key={d.id} className="check">
                  <input
                    type="checkbox"
                    checked={selected.includes(d.id)}
                    onChange={(e) =>
                      setSelected(e.target.checked ? [...selected, d.id] : selected.filter((x) => x !== d.id))
                    }
                  />
                  {d.name}
                </label>
              ))}
            </fieldset>
            <label className="check">
              <input type="checkbox" checked={lowImpact} onChange={(e) => setLowImpact(e.target.checked)} />
              Also allow low-impact checks (a few requests for accidentally exposed files)
            </label>
            <div className="grid3">
              <input placeholder="Your full name" value={form.signer_name} onChange={(e) => setForm({ ...form, signer_name: e.target.value })} required />
              <input placeholder="Your role (e.g. Executive Director)" value={form.signer_title} onChange={(e) => setForm({ ...form, signer_title: e.target.value })} required />
              <input type="email" placeholder="Your email" value={form.signer_email} onChange={(e) => setForm({ ...form, signer_email: e.target.value })} required />
            </div>
            <label className="check">
              <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} required />I have read
              and agree to the text above, and I'm authorized to give this permission.
            </label>
            <ErrorBox error={error} />
            <button type="submit" disabled={!agree || selected.length === 0}>
              Record permission
            </button>
          </form>
        )}
      </Card>
    </>
  );
}
