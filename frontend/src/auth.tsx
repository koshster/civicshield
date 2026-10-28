import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setCsrfToken } from "./api";
import type { Session, User } from "./types";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // On page load, ask the server who we are. The cookie is sent automatically; the
  // response hands back the CSRF token for this session.
  useEffect(() => {
    api
      .get<Session>("/auth/me")
      .then((s) => {
        setCsrfToken(s.csrf_token);
        setUser(s.user);
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const s = await api.post<Session>("/auth/login", { email, password });
    setCsrfToken(s.csrf_token);
    setUser(s.user);
  };
  const logout = async () => {
    await api.post("/auth/logout").catch(() => undefined);
    setCsrfToken(null);
    setUser(null);
  };

  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
