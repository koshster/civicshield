import { useCallback, useEffect, useState } from "react";
import { api } from "./api";

/** Fetch JSON on mount (and on reload()). Returns [data, error, reload]. */
export function useFetch<T>(path: string | null): [T | null, string | null, () => void] {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!path) return;
    let cancelled = false;
    api
      .get<T>(path)
      .then((d) => !cancelled && (setData(d), setError(null)))
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [path, tick]);

  return [data, error, reload];
}

export const fmtDate = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
