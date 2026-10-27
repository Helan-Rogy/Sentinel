import { useCallback, useEffect, useRef, useState } from "react";
import { api, openSocket, AuthError } from "./api";

const MAX_EVENTS = 1500;

// Single source of truth for the console: REST for the first load, WebSocket for live updates.
export function useSentinel(onAuthLost) {
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState({});
  const [stats, setStats] = useState(null);
  const [audit, setAudit] = useState([]);
  const [health, setHealth] = useState(null);
  const [live, setLive] = useState(false);
  const [error, setError] = useState("");
  const authLost = useRef(onAuthLost);
  authLost.current = onAuthLost;

  const guard = useCallback((e) => {
    if (e instanceof AuthError) authLost.current();
    else setError(e.message || "Request failed");
  }, []);

  const refreshMeta = useCallback(async () => {
    try {
      const [s, a, h] = await Promise.all([api("/api/stats"), api("/api/audit?limit=100"), api("/api/health")]);
      setStats(s); setAudit(a); setHealth(h); setError("");
    } catch (e) { guard(e); }
  }, [guard]);

  const refreshIncidents = useCallback(async () => {
    try {
      const list = await api("/api/incidents");
      setIncidents(Object.fromEntries(list.map((i) => [i.id, i])));
    } catch (e) { guard(e); }
  }, [guard]);

  useEffect(() => {
    (async () => {
      try {
        const ev = await api("/api/events?limit=1000");
        setEvents(ev);
      } catch (e) { guard(e); }
    })();
    refreshIncidents();
    refreshMeta();
    const stop = openSocket((m) => {
      if (m.topic === "event") setEvents((prev) => [m.data, ...prev].slice(0, MAX_EVENTS));
      if (m.topic === "incident") {
        setIncidents((prev) => ({ ...prev, [m.data.id]: m.data }));
        refreshMeta();
      }
      if (m.topic === "reset") {
        setEvents([]);
        setIncidents({});
        refreshMeta();
      }
    }, setLive);
    const t = setInterval(refreshMeta, 6000);
    return () => { stop(); clearInterval(t); };
  }, [guard, refreshIncidents, refreshMeta]);

  const resetAll = useCallback(async () => {
    try {
      await api("/api/reset", { method: "POST" });
      setEvents([]);
      setIncidents({});
      await refreshMeta();
    } catch (e) { guard(e); }
  }, [guard, refreshMeta]);

  const decide = useCallback(async (incId, actId, approve) => {
    try {
      const inc = await api(`/api/incidents/${incId}/actions/${actId}/${approve ? "approve" : "reject"}`, { method: "POST" });
      setIncidents((p) => ({ ...p, [inc.id]: inc }));
      refreshMeta();
    } catch (e) { guard(e); }
  }, [guard, refreshMeta]);

  const setStatus = useCallback(async (incId, status) => {
    try {
      const inc = await api(`/api/incidents/${incId}/status`, { method: "POST", body: { status } });
      setIncidents((p) => ({ ...p, [inc.id]: inc }));
      refreshMeta();
    } catch (e) { guard(e); }
  }, [guard, refreshMeta]);

  return { events, incidents, stats, audit, health, live, error, decide, setStatus, resetAll };
}
