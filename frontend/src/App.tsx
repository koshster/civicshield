import { Link, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import IssuePage from "./pages/IssuePage";
import LoginPage from "./pages/LoginPage";
import OrgPage from "./pages/OrgPage";
import OrgsPage from "./pages/OrgsPage";
import ScanPage from "./pages/ScanPage";

export default function App() {
  const { user, loading, logout } = useAuth();
  if (loading) return <p className="container">Loading…</p>;
  if (!user) return <LoginPage />;

  return (
    <>
      <header className="topbar">
        <Link to="/" className="brand">
          🛡️ CivicShield
        </Link>
        <span className="spacer" />
        <span className="muted">
          {user.email} {user.is_operator && <span className="pill">operator</span>}
        </span>
        <button className="link" onClick={() => void logout()}>
          Sign out
        </button>
      </header>
      <main className="container">
        <Routes>
          <Route path="/" element={<OrgsPage />} />
          <Route path="/orgs/:orgId/*" element={<OrgPage />} />
          <Route path="/orgs/:orgId/issues/:issueId" element={<IssuePage />} />
          <Route path="/orgs/:orgId/scans/:scanId" element={<ScanPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </>
  );
}
