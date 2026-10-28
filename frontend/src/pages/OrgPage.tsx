import { NavLink, Route, Routes, useParams } from "react-router-dom";
import { useFetch } from "../hooks";
import type { Org } from "../types";
import AuthorizationTab from "./AuthorizationTab";
import DomainsTab from "./DomainsTab";
import OverviewTab from "./OverviewTab";
import ScansTab from "./ScansTab";

export default function OrgPage() {
  const { orgId } = useParams();
  const [org] = useFetch<Org>(`/orgs/${orgId}`);
  const base = `/orgs/${orgId}`;
  return (
    <>
      <h1>{org?.name ?? "…"}</h1>
      <nav className="tabs">
        <NavLink end to={base}>
          Overview
        </NavLink>
        <NavLink to={`${base}/domains`}>Domains</NavLink>
        <NavLink to={`${base}/authorization`}>Permission</NavLink>
        <NavLink to={`${base}/scans`}>Scan history</NavLink>
      </nav>
      <Routes>
        <Route index element={<OverviewTab orgId={orgId!} />} />
        <Route path="domains" element={<DomainsTab orgId={orgId!} />} />
        <Route path="authorization" element={<AuthorizationTab orgId={orgId!} />} />
        <Route path="scans" element={<ScansTab orgId={orgId!} />} />
      </Routes>
    </>
  );
}
