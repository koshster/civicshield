import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { Card, ErrorBox } from "../components";
import { useFetch } from "../hooks";
import type { Org } from "../types";

export default function OrgsPage() {
  const { user } = useAuth();
  const [orgs, error, reload] = useFetch<Org[]>("/orgs");
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/orgs", { name, slug });
      setName("");
      setSlug("");
      reload();
    } catch (err) {
      setFormError((err as Error).message);
    }
  };

  return (
    <>
      <h1>Organizations</h1>
      <ErrorBox error={error} />
      <Card title="Your organizations">
        {orgs?.length === 0 && <p className="muted">No organizations yet.</p>}
        <ul className="list">
          {orgs?.map((o) => (
            <li key={o.id}>
              <Link to={`/orgs/${o.id}`}>{o.name}</Link>
            </li>
          ))}
        </ul>
      </Card>
      {user?.is_operator && (
        <Card title="Add an organization">
          <form className="inline" onSubmit={(e) => void create(e)}>
            <input placeholder="Name (e.g. Eastside Food Bank)" value={name} onChange={(e) => setName(e.target.value)} required />
            <input placeholder="short-id (e.g. eastside-food-bank)" value={slug} onChange={(e) => setSlug(e.target.value)} required />
            <button type="submit">Create</button>
          </form>
          <ErrorBox error={formError} />
        </Card>
      )}
    </>
  );
}
