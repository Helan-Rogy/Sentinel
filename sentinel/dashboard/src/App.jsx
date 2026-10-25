import { useCallback, useEffect, useState } from "react";
import { api, getToken, setToken } from "./api";
import { Icon } from "./components";
import { useSentinel } from "./store";
import { Agent, Incidents, Live, Overview, Reports, Response } from "./views";
import { pendingActions } from "./util";

const TABS = [
  ["overview", "Overview"], ["live", "Live"], ["incidents", "Incidents"],
  ["agent", "Agent"], ["response", "Response"], ["reports", "Reports"],
];

function Login({ onDone }) {
  const [t, setT] = useState("");
  const [err, setErr] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    setToken(t.trim());
    try { await api("/api/stats"); onDone(); } catch { setToken(""); setErr("That token was not accepted. Check SENTINEL_TOKEN on the server."); }
  };
  return (
    <main className="login">
      <form onSubmit={submit}>
        <div className="brand" style={{ padding: 0 }}><Icon name="overview" /> Sentinel Console</div>
        <h1 style={{ fontSize: 28 }}>Sign in to the console</h1>
        <label htmlFor="tok">Access token</label>
        <input id="tok" className="input" type="password" autoFocus value={t} onChange={(e) => setT(e.target.value)} placeholder="The value of SENTINEL_TOKEN" />
        {err && <div className="banner" role="alert">{err}</div>}
        <button className="btn primary" disabled={!t.trim()}>Sign in</button>
      </form>
    </main>
  );
}

function Console({ onLogout }) {
  const s = useSentinel(onLogout);
  const [view, setView] = useState(() => location.hash.slice(1) || "overview");
  const [selected, setSelected] = useState(null);
  const [theme, setTheme] = useState("");

  useEffect(() => { location.hash = view; }, [view]);
  useEffect(() => { if (theme) document.documentElement.dataset.theme = theme; }, [theme]);

  const openIncident = useCallback((id) => { setSelected(id); setView("incidents"); }, []);
  const pending = pendingActions(s.incidents).length;

  const body = {
    overview: <Overview s={s} go={setView} openIncident={openIncident} />,
    live: <Live s={s} />,
    incidents: <Incidents s={s} selected={selected} select={setSelected} />,
    agent: <Agent s={s} openIncident={openIncident} />,
    response: <Response s={s} openIncident={openIncident} />,
    reports: <Reports s={s} />,
  }[view];

  const conn = <span><span className={`dot ${s.live ? "on" : ""}`} />{s.live ? "Live" : "Reconnecting"}</span>;

  return (
    <div className="app">
      <nav className="rail" aria-label="Main">
        <div className="brand"><Icon name="overview" /> Sentinel</div>
        {TABS.map(([id, label]) => (
          <button key={id} className="navbtn" aria-current={view === id ? "page" : undefined} onClick={() => setView(id)}>
            <Icon name={id} />{label}
            {id === "response" && pending > 0 && <span className="badge count" aria-label={`${pending} waiting`}>{pending}</span>}
          </button>
        ))}
        <div className="rail-foot">
          {conn}
          <button className="btn quiet" onClick={() => setTheme((document.documentElement.dataset.theme === "dark") ? "light" : "dark")}>Switch theme</button>
          <button className="btn quiet" onClick={onLogout}>Sign out</button>
        </div>
      </nav>
      <main className="main">
        <div className="mobile-top">{conn}<button className="btn quiet" onClick={onLogout}>Sign out</button></div>
        {s.error && <div className="banner" role="alert">{s.error}. Is the server running at the address in vite.config.js?</div>}
        {body}
      </main>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(!!getToken());
  const logout = useCallback(() => { setToken(""); setAuthed(false); }, []);
  return authed ? <Console onLogout={logout} /> : <Login onDone={() => setAuthed(true)} />;
}
