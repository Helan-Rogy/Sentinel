import { useCallback, useEffect, useState } from "react";
import { api, getToken, setToken } from "./api";
import { Icon } from "./components";
import { useSentinel } from "./store";
import { Agent, Incidents, Live, Overview, Reports, Response } from "./views";
import { pendingActions } from "./util";

const TABS = [
  ["overview", "Overview", "dashboard", "SYS.01"],
  ["live", "Live Stream", "sensors", "SYS.02"],
  ["incidents", "Incidents", "warning", "SYS.03"],
  ["agent", "Agent Telemetry", "terminal", "SYS.04"],
  ["response", "Response", "bolt", "SYS.05"],
  ["reports", "Reports & Audit", "analytics", "SYS.06"],
];

function Login({ onDone }) {
  const [t, setT] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!t.trim()) return;
    setLoading(true);
    setErr("");
    setToken(t.trim());
    try {
      await api("/api/stats");
      onDone();
    } catch {
      setToken("");
      setErr("UNAUTHORIZED: Access key was rejected by the SOC kernel.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-screen">
      <div className="login-card">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
          <div className="brand-icon-box" style={{ width: 40, height: 40 }}>
            <span className="material-symbols-outlined fill" style={{ fontSize: 24, color: "var(--primary-container)" }}>
              security
            </span>
          </div>
          <div>
            <div className="brand-title" style={{ fontSize: 18 }}>AEGIS SENTINEL</div>
            <div className="brand-subtitle">RANSOMWARE DEFENSE HUD // SOC V2.4</div>
          </div>
        </div>

        <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "var(--font-headline)", marginBottom: 6, color: "#ffffff" }}>
          AUTHENTICATE OPERATOR
        </div>
        <p className="muted" style={{ fontSize: 11.5, marginBottom: 20 }}>
          Enter institutional credential token to engage active kernel defenses.
        </p>

        <form onSubmit={submit}>
          <div style={{ marginBottom: 16 }}>
            <label htmlFor="tok" style={{ display: "block", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.12em", fontWeight: 700, marginBottom: 6, color: "var(--text-muted)" }}>
              Access Token (SENTINEL_TOKEN)
            </label>
            <input
              id="tok"
              className="input"
              type="password"
              autoFocus
              value={t}
              onChange={(e) => setT(e.target.value)}
              placeholder="e.g. sentinel-live-key"
              style={{ width: "100%", padding: "10px 12px", fontSize: 13 }}
            />
          </div>

          {err && <div className="banner" role="alert">{err}</div>}

          <button className="btn primary" disabled={!t.trim() || loading} style={{ width: "100%", padding: "11px 16px", fontSize: 12 }}>
            {loading ? "INITIALIZING SECURE LINK..." : "ENGAGE CONSOLE ACCESS"}
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>
              bolt
            </span>
          </button>
        </form>

        <div style={{ marginTop: 20, paddingTop: 14, borderTop: "1px solid #1c1c1c", display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)" }}>
          <span>NODE: SEC_L3 // ENCRYPTED</span>
          <span>STATION: ALPHA-09</span>
        </div>
      </div>
    </div>
  );
}

function Console({ onLogout }) {
  const s = useSentinel(onLogout);
  const [view, setView] = useState(() => location.hash.slice(1) || "overview");
  const [selected, setSelected] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    location.hash = view;
  }, [view]);

  const openIncident = useCallback((id) => {
    setSelected(id);
    setView("incidents");
    setMobileOpen(false);
  }, []);

  const pending = pendingActions(s.incidents).length;
  const endpoint = s.events[0]?.endpoint_id || "LOCAL_ENDPOINT";

  // Top search handles pressing Enter to jump to an incident or live stream
  const handleSearchKeyDown = (e) => {
    if (e.key === "Enter" && searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const match = Object.values(s.incidents).find(
        (i) =>
          i.title.toLowerCase().includes(q) ||
          i.id.toLowerCase().includes(q) ||
          (i.process_name || "").toLowerCase().includes(q) ||
          String(i.pid) === q
      );
      if (match) {
        openIncident(match.id);
      } else {
        setView("live");
      }
    }
  };

  const body = {
    overview: <Overview s={s} go={setView} openIncident={openIncident} />,
    live: <Live s={s} />,
    incidents: <Incidents s={s} selected={selected} select={setSelected} />,
    agent: <Agent s={s} openIncident={openIncident} />,
    response: <Response s={s} openIncident={openIncident} />,
    reports: <Reports s={s} />,
  }[view];

  return (
    <div className="app">
      {/* Mobile Backdrop */}
      {mobileOpen && <div className="mobile-backdrop" onClick={() => setMobileOpen(false)} />}

      {/* Left Sidebar - Pitch Black Tactical HUD */}
      <aside className={`rail ${mobileOpen ? "mobile-open" : ""}`} aria-label="Main Navigation">
        {/* Brand Header */}
        <div className="brand-section">
          <div className="brand-header">
            <div className="brand-identity">
              <div className="brand-icon-box">
                <span className="material-symbols-outlined fill" style={{ fontSize: 20 }}>
                  security
                </span>
              </div>
              <div>
                <div className="brand-title">AEGIS SENTINEL</div>
                <div className="brand-subtitle">SOC KERNEL V2.4</div>
              </div>
            </div>
            <span className="node-pill">NODE_OK</span>
          </div>

          <div className="latency-strip">
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: s.live ? "var(--amber)" : "var(--error)" }} />
              <span style={{ fontSize: 9.5, fontWeight: 700, color: "var(--amber)", letterSpacing: "0.1em" }}>
                {s.live ? "LIVE // 12ms LATENCY" : "LINK RECONNECTING"}
              </span>
            </div>
            <span style={{ fontSize: 9.5, color: "var(--text-muted)" }}>SEC_L3</span>
          </div>
        </div>

        {/* Navigation Modules */}
        <div className="nav-container">
          <div className="nav-category">TELEMETRY MODULES</div>
          {TABS.map(([id, label, iconName, code]) => {
            const isActive = view === id;
            return (
              <button
                key={id}
                className="navbtn"
                aria-current={isActive ? "page" : undefined}
                onClick={() => {
                  setView(id);
                  setMobileOpen(false);
                }}
              >
                <div className="navbtn-label">
                  <span className={`material-symbols-outlined ${isActive ? "fill" : ""}`}>
                    {iconName}
                  </span>
                  <span>{label}</span>
                </div>
                {id === "response" && pending > 0 ? (
                  <span className="badge critical" style={{ fontSize: 10, padding: "1px 5px" }}>
                    {pending}
                  </span>
                ) : id === "incidents" && Object.keys(s.incidents).length > 0 ? (
                  <span className="badge medium" style={{ fontSize: 10, padding: "1px 5px" }}>
                    {Object.keys(s.incidents).length}
                  </span>
                ) : (
                  <span className="nav-code">{code}</span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tactical Footer */}
        <div className="rail-footer">
          <div className="endpoint-info-box">
            <div>
              <div style={{ fontSize: 9, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.1em" }}>TARGET ENDPOINT</div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff" }}>{endpoint}</div>
            </div>
            <span style={{ fontSize: 10, color: "var(--primary)", fontWeight: 700 }}>ARMED</span>
          </div>

          <div className="analyst-row">
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#1f1f1f", display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid #333333" }}>
                <span className="material-symbols-outlined" style={{ fontSize: 16, color: "var(--primary-container)" }}>
                  admin_panel_settings
                </span>
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", lineHeight: 1.1 }}>ADMIN OPERATOR</div>
                <div style={{ fontSize: 9, color: "var(--text-muted)" }}>TOKEN AUTHENTICATED</div>
              </div>
            </div>
            <button className="btn quiet" style={{ padding: "4px 8px" }} onClick={onLogout} title="Sign Out">
              <span className="material-symbols-outlined" style={{ fontSize: 16 }}>
                logout
              </span>
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Viewport */}
      <div className="main-wrapper">
        {/* Top Header Bar */}
        <header className="top-bar">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              className="mobile-menu-btn"
              onClick={() => setMobileOpen(!mobileOpen)}
              aria-label="Toggle navigation"
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>
                {mobileOpen ? "close" : "menu"}
              </span>
            </button>

            <div className="status-indicator-tag">
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--primary-container)" }} />
              <span>// SYSTEM STATUS: OPERATIONAL</span>
              <span style={{ color: "#333333" }}>|</span>
              <span style={{ color: "var(--text-muted)" }}>KILL-CHAIN MONITOR ACTIVE</span>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <input
              className="top-search-input"
              placeholder=">> Search dossier, PID, or enter to filter live..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleSearchKeyDown}
            />
            <div
              style={{ position: "relative", cursor: "pointer", display: "flex", alignItems: "center" }}
              onClick={() => setView(pending > 0 ? "response" : "incidents")}
              title={pending > 0 ? `${pending} pending decisions waiting` : "View incidents"}
            >
              <span className="material-symbols-outlined" style={{ color: pending > 0 ? "var(--primary-container)" : "var(--text-muted)", fontSize: 20 }}>
                notifications
              </span>
              {pending > 0 && (
                <span style={{ position: "absolute", top: -2, right: -2, width: 7, height: 7, borderRadius: "50%", background: "var(--primary-container)" }} />
              )}
            </div>
          </div>
        </header>

        {/* Main Content Area */}
        <main className="content-canvas">
          {s.error && (
            <div className="banner" role="alert">
              <span className="material-symbols-outlined" style={{ fontSize: 16, marginRight: 6 }}>
                error
              </span>
              {s.error}. Verify connection to Sentinel SOC backend.
            </div>
          )}
          {body}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(!!getToken());
  const logout = useCallback(() => {
    setToken("");
    setAuthed(false);
  }, []);
  return authed ? <Console onLogout={logout} /> : <Login onDone={() => setAuthed(true)} />;
}
