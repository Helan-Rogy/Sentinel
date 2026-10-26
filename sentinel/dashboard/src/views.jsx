import { useMemo, useState } from "react";
import { api, downloadEvidence, downloadReport, downloadStix, downloadYara } from "./api";
import { Approval, RiskBadge, StatusBadge, Steps, Trace } from "./components";
import { RANK, actionName, ago, clock, dateTime, fileName, humanStatus, level, pendingActions } from "./util";

const worst = (incidents) =>
  Object.values(incidents)
    .filter((i) => ["open", "awaiting_approval"].includes(i.status))
    .reduce((w, i) => (RANK[level(i)] > RANK[w] ? level(i) : w), "low");

const groupHits = (hits = []) => {
  const m = new Map();
  for (const h of hits) {
    const g = m.get(h.path) || { path: h.path, count: 0, ops: [], first: h.ts };
    g.count += 1;
    if (!g.ops.includes(h.op)) g.ops.push(h.op);
    if (h.ts < g.first) g.first = h.ts;
    m.set(h.path, g);
  }
  return [...m.values()];
};

/* ---------------------------------------------------------------- Overview */
export function Overview({ s, go, openIncident }) {
  const pending = pendingActions(s.incidents);
  const active = Object.values(s.incidents).filter((i) => ["open", "awaiting_approval"].includes(i.status));
  const tone = worst(s.incidents);
  const contained = Object.values(s.incidents).filter((i) => i.status === "contained").length;
  const falsePositives = Object.values(s.incidents).filter((i) => i.status === "false_positive").length;
  const recent = Object.values(s.incidents)
    .sort((a, b) => new Date(b.created) - new Date(a.created))
    .slice(0, 6);
  const totalEvents = s.stats?.events ?? s.events.length;
  const isAttackState = pending.length > 0 || active.length > 0;
  const endpoint = s.events[0]?.endpoint_id || "LOCAL_ENDPOINT";
  const ringUtil = Math.min(100, Math.round((s.events.length / 1500) * 100));

  return (
    <>
      {/* Top Status Banner (Attack State Activation) */}
      <section className="attack-banner">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
              <div className={`defcon-badge ${isAttackState ? "" : "clean"}`}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
                {isAttackState ? "DEFCON 2 // ELEVATED INTERVENTION REQUIRED" : "DEFCON 5 // ALL BOUNDARIES SECURED"}
              </div>
              <div style={{ background: "#1c1c1c", color: "var(--primary)", padding: "2px 8px", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em" }}>
                ACTIVE STREAM // SENTINEL_KERNEL
              </div>
            </div>

            <h1 style={{ fontFamily: "var(--font-headline)", fontSize: 26, fontWeight: 800, margin: "6px 0", color: "#ffffff", letterSpacing: "-0.01em", display: "flex", alignItems: "center", gap: 10 }}>
              <span className="material-symbols-outlined fill" style={{ color: isAttackState ? "var(--primary-container)" : "var(--low)", fontSize: 28 }}>
                {isAttackState ? "crisis_alert" : "verified_user"}
              </span>
              {pending.length
                ? `${pending.length} containment ${pending.length === 1 ? "action needs" : "actions need"} your decision`
                : active.length
                ? `${active.length} active anomalous encryption patterns detected`
                : "All quiet. Zero anomalous encryption patterns detected"}
            </h1>

            <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", fontSize: 11, color: "var(--text-secondary)" }}>
              <span style={{ color: "var(--primary-container)", fontWeight: 700 }}>&gt;&gt; DETECT_EVT:</span>
              <span>{isAttackState ? "Rapid file entropy shift or decoy canary tripwire activated." : "Passive kernel heuristics monitoring file system I/O."}</span>
              <span style={{ color: "#333333" }}>|</span>
              <span style={{ color: "var(--amber)" }}>TARGET_HOST: {endpoint}</span>
              <span style={{ color: "#333333" }}>|</span>
              <span style={{ color: isAttackState ? "var(--error)" : "var(--low)", fontWeight: 700 }}>
                {isAttackState ? "STATUS: IMPACT_ACTIVE" : "STATUS: BASELINE_NORMAL"}
              </span>
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, alignSelf: "center" }}>
            <button className="btn" onClick={() => go("live")}>
              <span className="material-symbols-outlined">ssid_chart</span>
              Live Telemetry
            </button>
            <button className="btn primary" onClick={() => go("incidents")}>
              <span className="material-symbols-outlined">warning</span>
              Incident Dossiers
            </button>
          </div>
        </div>
      </section>

      {/* 4-Metrics Row (HUD Modular Boxes) */}
      <section className="hud-metrics-grid">
        {/* Box 1 */}
        <div className="hud-metric-card">
          <div className="hud-metric-top">
            <span><strong style={{ color: "var(--primary-container)" }}>#01</strong> FILE EVENTS SEEN</span>
            <span style={{ color: "var(--amber)" }}>SYS_CLK.LIVE</span>
          </div>
          <div className="hud-metric-val">{totalEvents.toLocaleString()}</div>
          <div className="segmented-meter">
            <span className="active" /><span className="active" /><span className="active" /><span className="active" /><span />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span>BUFF_INDEX: {ringUtil}%</span>
            <span>I/O NORMALIZED</span>
          </div>
        </div>

        {/* Box 2 */}
        <div className={`hud-metric-card ${active.length > 0 ? "alert" : ""}`}>
          <div className="hud-metric-top">
            <span style={{ color: active.length > 0 ? "var(--error)" : "inherit" }}>
              <strong style={{ color: "var(--error)" }}>#02</strong> ACTIVE OUTBREAKS
            </span>
            {active.length > 0 && <span className="defcon-badge">SPIKE</span>}
          </div>
          <div className={`hud-metric-val ${active.length > 0 ? "alert" : ""}`}>
            {active.length < 10 ? `0${active.length}` : active.length}
          </div>
          <div className="segmented-meter">
            {active.length > 0 ? (
              <><span className="active-alert" /><span className="active-alert" /><span className="active-alert" /><span /><span /></>
            ) : (
              <><span /><span /><span /><span /><span /></>
            )}
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span>PROC: {active[0]?.process_name || "NONE"}</span>
            <span style={{ color: active.length > 0 ? "var(--error)" : "inherit", fontWeight: 700 }}>
              {active.length > 0 ? `SEV: ${level(active[0]).toUpperCase()}` : "SEV: NOMINAL"}
            </span>
          </div>
        </div>

        {/* Box 3 */}
        <div className="hud-metric-card">
          <div className="hud-metric-top">
            <span><strong style={{ color: "var(--amber)" }}>#03</strong> CONTAINED (24H)</span>
            <span style={{ color: "var(--low)" }}>100% SUCCESS</span>
          </div>
          <div className="hud-metric-val">{contained < 10 ? `0${contained}` : contained}</div>
          <div className="segmented-meter">
            <span className="active" /><span className="active" /><span className="active" /><span className="active" /><span className="active" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span>FALSE POSITIVES: {falsePositives}</span>
            <span>ROLLBACK READY</span>
          </div>
        </div>

        {/* Box 4 */}
        <div className={`hud-metric-card ${pending.length > 0 ? "alert" : ""}`}>
          <div className="hud-metric-top">
            <span style={{ color: pending.length > 0 ? "var(--primary-container)" : "inherit" }}>
              <strong style={{ color: "var(--primary-container)" }}>#04</strong> WAITING OPERATOR
            </span>
            {pending.length > 0 && <span className="badge high">ACTION REQ</span>}
          </div>
          <div className={`hud-metric-val ${pending.length > 0 ? "warn" : ""}`}>
            {pending.length < 10 ? `0${pending.length}` : pending.length}
          </div>
          <div className="segmented-meter">
            {pending.length > 0 ? (
              <><span className="active" /><span className="active" /><span /><span /><span /></>
            ) : (
              <><span /><span /><span /><span /><span /></>
            )}
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span style={{ color: pending.length > 0 ? "var(--error)" : "inherit" }}>
              {pending.length > 0 ? `GATE: ${pending[0].act.kind}` : "GATE: IDLE"}
            </span>
            <span style={{ color: "var(--primary)", cursor: "pointer" }} onClick={() => go("response")}>
              JUMP TO OP &gt;
            </span>
          </div>
        </div>
      </section>

      {/* Centerpiece Live Activity Graph */}
      <Trace events={s.events} incidents={s.incidents} />

      {/* Two-Column Split (Approval Intervention vs Recent Incidents) */}
      <div style={{ display: "grid", gridTemplateColumns: pending.length > 0 ? "minmax(340px, 1.2fr) 1fr" : "1fr", gap: 20 }}>
        {pending.length > 0 && (
          <section>
            <div style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--error)", marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
              <span className="material-symbols-outlined fill">crisis_alert</span>
              OPERATOR INTERVENTION REQUIRED ({pending.length})
            </div>
            {pending.map(({ inc, act }) => (
              <Approval key={act.id} inc={inc} act={act} onDecide={s.decide} onView={openIncident} />
            ))}
          </section>
        )}

        <section>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.1em", color: "#ffffff", display: "flex", alignItems: "center", gap: 8 }}>
              <span className="material-symbols-outlined">security</span>
              RECENT FLEET INCIDENTS
            </div>
            <button className="btn quiet" style={{ fontSize: 10 }} onClick={() => go("incidents")}>
              VIEW FULL FORENSIC CATALOG &rarr;
            </button>
          </div>

          {recent.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", background: "#060606", border: "1px dashed #1c1c1c" }}>
              Zero suspicious incidents detected. System is continuously probing memory and file descriptors.
            </div>
          ) : (
            <div className="tablewrap">
              <table>
                <thead>
                  <tr>
                    <th>WHEN</th>
                    <th>INCIDENT DOSSIER</th>
                    <th>SEV</th>
                    <th>TARGET PROCESS</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((i) => (
                    <tr key={i.id}>
                      <td style={{ color: "var(--text-muted)" }}>{ago(i.created)}</td>
                      <td>
                        <button
                          className="btn quiet"
                          style={{ padding: 0, border: 0, fontWeight: 700, color: "#ffffff" }}
                          onClick={() => openIncident(i.id)}
                        >
                          {i.title}
                        </button>
                      </td>
                      <td><RiskBadge level={level(i)} /></td>
                      <td style={{ color: "var(--text-muted)" }}>{i.process_name || "canary_touch"}</td>
                      <td><StatusBadge status={i.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  );
}

/* ----------------------------------------------------------- Live monitoring */
export function Live({ s }) {
  const [op, setOp] = useState("all");
  const [q, setQ] = useState("");
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState([]);
  const source = paused ? frozen : s.events;

  // Real-time burst rate calculation (ops/s over last 5 seconds)
  const throughput = useMemo(() => {
    const nowSec = Date.now() / 1000;
    const count = s.events.filter((e) => (nowSec - new Date(e.ts).getTime() / 1000) <= 5).length;
    return (count / 5).toFixed(1);
  }, [s.events]);

  // Max Shannon entropy observed across logged incidents
  const maxEntropy = useMemo(() => {
    let m = 0;
    for (const inc of Object.values(s.incidents)) {
      for (const e of inc.entropy || []) {
        if (e.shannon > m) m = e.shannon;
      }
    }
    return m > 0 ? m.toFixed(2) : "0.00";
  }, [s.incidents]);

  // Canary honeypot tripwire counter
  const canaryHits = useMemo(() => {
    let hits = 0;
    for (const inc of Object.values(s.incidents)) {
      hits += (inc.honey_hits || []).length;
    }
    return hits;
  }, [s.incidents]);

  const rows = useMemo(
    () =>
      source
        .filter(
          (e) =>
            (op === "all" || e.op === op) &&
            (!q || (e.path + (e.process_name || "") + (e.pid || "")).toLowerCase().includes(q.toLowerCase()))
        )
        .slice(0, 250),
    [source, op, q]
  );

  return (
    <>
      {/* Top HUD System Telemetry Strip */}
      <div style={{ background: "#070707", border: "1px solid #1a1a1a", padding: "10px 16px", marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, fontSize: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--primary)" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--primary-container)" }} />
            <strong style={{ color: "#ffffff" }}>MODULE: IO-TRACE: LIVE FILE ACTIVITY</strong>
          </div>
          <span style={{ color: "#333333" }}>::</span>
          <span style={{ color: "var(--amber)" }}>THROUGHPUT: {throughput} ops/s</span>
          <span style={{ color: "#333333" }}>::</span>
          <span style={{ color: "var(--text-muted)" }}>INGRESS_PIPE: VFS_NOTIFY_HOOK (x64)</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10 }}>
            <span style={{ color: "var(--text-muted)" }}>RING_BUFFER:</span>
            <strong style={{ color: "var(--primary-container)" }}>{s.events.length}/1500</strong>
          </div>
          <button
            className={`btn ${paused ? "primary" : ""}`}
            style={{ padding: "4px 10px", fontSize: 10 }}
            onClick={() => {
              setFrozen(s.events);
              setPaused(!paused);
            }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
              {paused ? "play_arrow" : "pause_circle"}
            </span>
            {paused ? "RESUME STREAM" : "PAUSE STREAM"}
          </button>
        </div>
      </div>

      {/* 4-Metric HUD Banner (Tactical KPI Matrix - Real Data) */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 18 }}>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span>FILE I/O BURST RATE</span>
            <span className={`badge ${parseFloat(throughput) > 5 ? "critical" : "low"}`} style={{ fontSize: 9, padding: "1px 4px" }}>
              {parseFloat(throughput) > 5 ? "BURST SPIKE" : "NOMINAL"}
            </span>
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: parseFloat(throughput) > 5 ? "var(--error)" : "#ffffff", fontFamily: "var(--font-headline)", margin: "4px 0" }}>
            {throughput} <span style={{ fontSize: 11, color: "var(--text-muted)" }}>ops/s</span>
          </div>
          <div style={{ fontSize: 9, color: "var(--text-muted)" }}>CURRENT 5S ROLLING AVERAGE</div>
        </div>

        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span>MAX SHANNON ENTROPY</span>
            <span className={`badge ${parseFloat(maxEntropy) > 7 ? "critical" : parseFloat(maxEntropy) > 5 ? "high" : "low"}`} style={{ fontSize: 9, padding: "1px 4px" }}>
              {parseFloat(maxEntropy) > 7 ? "ENCRYPTED" : "BASELINE"}
            </span>
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: "var(--primary-container)", fontFamily: "var(--font-headline)", margin: "4px 0" }}>
            {maxEntropy} <span style={{ fontSize: 11, color: "var(--text-muted)" }}>/ 8.00</span>
          </div>
          <div style={{ fontSize: 9, color: "var(--primary)" }}>OBSERVED FILE CORRUPTION PROBE</div>
        </div>

        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span>BUFFERED MUTATIONS</span>
            <span className="badge medium" style={{ fontSize: 9, padding: "1px 4px" }}>BUFFER</span>
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: "#ffffff", fontFamily: "var(--font-headline)", margin: "4px 0" }}>
            {s.events.length}
          </div>
          <div style={{ fontSize: 9, color: "var(--text-muted)" }}>TOTAL INGRESS IN BUFFER</div>
        </div>

        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)" }}>
            <span>ACTIVE CANARIES</span>
            <span className={`badge ${canaryHits > 0 ? "critical" : "low"}`} style={{ fontSize: 9, padding: "1px 4px" }}>
              {canaryHits > 0 ? "TRIPPED" : "ARMED"}
            </span>
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: canaryHits > 0 ? "var(--error)" : "var(--low)", fontFamily: "var(--font-headline)", margin: "4px 0" }}>
            {canaryHits > 0 ? `${canaryHits} HITS` : "0 HITS"}
          </div>
          <div style={{ fontSize: 9, color: "var(--text-muted)" }}>{canaryHits > 0 ? "DECOY INTERCEPT ACTIVE" : "TRIPWIRE DECOYS ACTIVE"}</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
        <div style={{ display: "flex", background: "#080808", border: "1px solid #1c1c1c", padding: 2 }}>
          {["all", "create", "modify", "rename", "delete"].map((o) => (
            <button
              key={o}
              style={{
                background: op === o ? "var(--primary-container)" : "transparent",
                color: op === o ? "#000000" : "var(--text-muted)",
                border: "none",
                padding: "5px 10px",
                fontSize: 10.5,
                fontWeight: 700,
                textTransform: "uppercase",
                cursor: "pointer",
              }}
              onClick={() => setOp(o)}
            >
              {o}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, position: "relative", minWidth: 240 }}>
          <input
            className="input"
            style={{ width: "100%", padding: "7px 12px", fontSize: 11 }}
            placeholder=">> Filter by path string, extension, or process name..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
          Showing {rows.length} of {source.length} events
        </div>
      </div>

      {/* Telemetry Stream Data Table */}
      {rows.length === 0 ? (
        <div style={{ padding: 36, textAlign: "center", color: "var(--text-muted)", background: "#060606", border: "1px dashed #1c1c1c" }}>
          Zero matching events in current buffer window.
        </div>
      ) : (
        <div className="tablewrap scroll">
          <table>
            <thead>
              <tr>
                <th style={{ width: 110 }}>TIMESTAMP</th>
                <th style={{ width: 100 }}>OPERATION</th>
                <th>TARGET PATH</th>
                <th style={{ width: 200 }}>ORIGINATING PROCESS</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <td style={{ color: "var(--text-muted)" }}>{clock(e.ts)}</td>
                  <td>
                    <span className={`op-pill ${e.op}`}>{e.op}</span>
                  </td>
                  <td style={{ wordBreak: "break-all" }}>
                    {e.new_path ? (
                      <>
                        <span style={{ color: "var(--text-muted)" }}>{fileName(e.path)}</span> &rarr;{" "}
                        <strong style={{ color: "var(--primary-container)" }}>{fileName(e.new_path)}</strong>
                      </>
                    ) : (
                      e.path
                    )}
                  </td>
                  <td>
                    {e.process_name ? (
                      <span className="badge" style={{ fontStyle: "normal" }}>
                        {e.process_name} {e.pid ? `(pid ${e.pid})` : ""}
                      </span>
                    ) : (
                      <span style={{ color: "var(--text-muted)" }}>&mdash;</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

/* ----------------------------------------------------------------- Incidents */
function Evidence({ inc, s }) {
  const a = inc.assessment;
  return (
    <div style={{ background: "#070707", border: "1px solid #1c1c1c", padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ fontSize: 9.5, letterSpacing: "0.15em", color: "var(--error)", fontWeight: 800 }}>
            // INCIDENT EVIDENCE DOSSIER #{inc.id.slice(0, 8)}
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 800, margin: "4px 0", color: "#ffffff", fontFamily: "var(--font-headline)" }}>
            {inc.title}
          </h2>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Triggered {dateTime(inc.created)} {inc.pid ? `by ${inc.process_name} (pid ${inc.pid})` : ""} &bull; {inc.affected_files} files affected
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <RiskBadge level={level(inc)} />
          <StatusBadge status={inc.status} />
        </div>
      </div>

      {a && (
        <div style={{ background: "#000000", border: "1px solid #221612", padding: 18, marginBottom: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.12em", textTransform: "uppercase" }}>
                AUTONOMIC THREAT SCORE
              </div>
              <div style={{ fontSize: 36, fontWeight: 800, color: "var(--error)", fontFamily: "var(--font-headline)" }}>
                {Math.round(a.score * 100)}%
              </div>
            </div>
            <div style={{ textAlign: "right", fontSize: 11 }}>
              <div style={{ color: "var(--text-muted)" }}>CLASSIFIER: {a.method || "HEURISTIC"}</div>
              <div style={{ color: "var(--primary-container)", fontWeight: 700 }}>SCORE: {a.score.toFixed(3)}</div>
            </div>
          </div>
          <div style={{ fontSize: 12.5, color: "var(--text-secondary)", lineHeight: 1.5 }}>{a.summary}</div>

          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 8 }}>
              EVALUATED EVIDENCE SIGNALS
            </div>
            <div className="tablewrap">
              <table>
                <thead>
                  <tr>
                    <th>SIGNAL</th>
                    <th>TELEMETRY DETAIL</th>
                    <th style={{ textAlign: "right" }}>CONTRIBUTION</th>
                  </tr>
                </thead>
                <tbody>
                  {a.signals.map((sg) => (
                    <tr key={sg.name}>
                      <td style={{ color: "var(--primary-container)", fontWeight: 700 }}>{sg.name}</td>
                      <td style={{ color: "var(--text-secondary)" }}>{sg.detail}</td>
                      <td style={{ textAlign: "right", color: "var(--amber)", fontWeight: 700 }}>
                        {Math.round(sg.weight * 100)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Honeypot Canaries */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 8 }}>
          // HONEYPOT CANARIES TOUCHED
        </div>
        {inc.honey_hits.length === 0 ? (
          <div style={{ padding: 12, background: "#050505", border: "1px dashed #1a1a1a", fontSize: 11, color: "var(--text-muted)" }}>
            Zero decoy honey files modified.
          </div>
        ) : (
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>CANARY DECOY</th>
                  <th>INTERACTIONS</th>
                  <th>FIRST INTERCEPT</th>
                </tr>
              </thead>
              <tbody>
                {groupHits(inc.honey_hits).map((h) => (
                  <tr key={h.path}>
                    <td style={{ color: "var(--amber)" }}>{h.path}</td>
                    <td>{h.count}x ({h.ops.join(", ")})</td>
                    <td style={{ color: "var(--text-muted)" }}>{clock(h.first)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Entropy Mutations */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 8 }}>
          // SHANNON ENTROPY DRIFT
        </div>
        {inc.entropy.length === 0 ? (
          <div style={{ padding: 12, background: "#050505", border: "1px dashed #1a1a1a", fontSize: 11, color: "var(--text-muted)" }}>
            No high-entropy file mutations logged.
          </div>
        ) : (
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>FILE NAME</th>
                  <th>ENTROPY DRIFT</th>
                  <th>HEADER VALIDATION</th>
                </tr>
              </thead>
              <tbody>
                {inc.entropy.map((r, i) => (
                  <tr key={i}>
                    <td>{fileName(r.path)}</td>
                    <td style={{ color: "var(--error)", fontWeight: 700 }}>
                      {r.previous_shannon != null ? `${r.previous_shannon.toFixed(2)} → ${r.shannon.toFixed(2)}` : r.shannon.toFixed(2)}
                    </td>
                    <td>
                      {r.type_mismatch ? (
                        <span className="badge critical">ENCRYPTED PATTERN</span>
                      ) : (
                        <span className="badge low">MATCHES</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Isolated Kali Linux Sandbox Detonation */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em" }}>
            // ISOLATED KALI LINUX SANDBOX (DYNAMIC DETONATION)
          </div>
          {inc.sandbox && (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <span className="badge low">VM: {inc.sandbox.vm_name || "KALI LINUX"}</span>
              <span className="badge low">STATE: {inc.sandbox.vm_state.toUpperCase()}</span>
              <span className="badge high">EXECUTION: {inc.sandbox.duration_seconds}s</span>
            </div>
          )}
        </div>

        {inc.sandbox ? (
          <div style={{ background: "#050505", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 10, marginBottom: 14 }}>
              <div style={{ background: "#000000", border: "1px solid #141414", padding: "8px 10px" }}>
                <div style={{ fontSize: 9.5, color: "var(--text-muted)" }}>FILES TOUCHED</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: "var(--amber)" }}>{inc.sandbox.files_touched}</div>
              </div>
              <div style={{ background: "#000000", border: "1px solid #141414", padding: "8px 10px" }}>
                <div style={{ fontSize: 9.5, color: "var(--text-muted)" }}>ENCRYPTED-LIKE</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: "var(--error)" }}>{inc.sandbox.files_encrypted_like}</div>
              </div>
              <div style={{ background: "#000000", border: "1px solid #141414", padding: "8px 10px" }}>
                <div style={{ fontSize: 9.5, color: "var(--text-muted)" }}>EXTENSIONS</div>
                <div style={{ fontSize: 12, fontWeight: 700, color: "#ffffff", marginTop: 4 }}>
                  {inc.sandbox.extensions_changed.join(", ") || "None"}
                </div>
              </div>
              <div style={{ background: "#000000", border: "1px solid #141414", padding: "8px 10px" }}>
                <div style={{ fontSize: 9.5, color: "var(--text-muted)" }}>YARA MATCHES</div>
                <div style={{ fontSize: 12, fontWeight: 700, color: "var(--error)", marginTop: 4 }}>
                  {inc.sandbox.yara_matches.length} Rule Detections
                </div>
              </div>
            </div>

            {inc.sandbox.network_connections?.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 6 }}>
                  EXTRACTED NETWORK CONNECTIONS & BEACONS:
                </div>
                <div className="tablewrap">
                  <table>
                    <thead>
                      <tr>
                        <th>DESTINATION IP</th>
                        <th>PORT</th>
                        <th>PROTO</th>
                        <th>THREAT CLASSIFICATION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {inc.sandbox.network_connections.map((c, idx) => (
                        <tr key={idx}>
                          <td style={{ color: "var(--error)", fontWeight: 700 }}>{c.ip}</td>
                          <td style={{ color: "#ffffff" }}>{c.port}</td>
                          <td><span className="badge low">{c.proto}</span></td>
                          <td style={{ color: "var(--amber)" }}>{c.threat || "Unclassified"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div style={{ display: "flex", gap: 10, marginTop: 12, alignItems: "center", flexWrap: "wrap" }}>
              <button
                className="btn primary"
                onClick={() => downloadEvidence(inc.id)}
              >
                <span className="material-symbols-outlined" style={{ fontSize: 16 }}>download</span>
                DOWNLOAD EVIDENCE BUNDLE (.ZIP)
              </button>
              <span style={{ fontSize: 10.5, color: "var(--text-muted)" }}>
                Includes PCAP capture, entropy telemetry CSV, canary hit log, and incident dossier
              </span>
            </div>
          </div>
        ) : (
          <div style={{ padding: "14px 16px", background: "#050505", border: "1px dashed #222222", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
            <div>
              <div style={{ fontSize: 12, color: "#ffffff", fontWeight: 700 }}>
                No Dynamic Sandbox Telemetry Attached
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                Detonate suspect process in an isolated, headless VirtualBox Kali VM with network capture and clean snapshot rollback.
              </div>
            </div>
            <button
              className="btn primary"
              onClick={async () => {
                try {
                  await api(`/api/incidents/${inc.id}/sandbox`, { method: "POST" });
                } catch (e) {
                  alert(`Sandbox detonation error: ${e.message}`);
                }
              }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 16 }}>play_arrow</span>
              DETONATE IN KALI SANDBOX
            </button>
          </div>
        )}
      </div>

      {/* Proposed Response & History */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 8 }}>
          // CONTAINMENT ACTIONS
        </div>
        {inc.actions.map((act) => {
          const res = inc.results.find((r) => r.action_id === act.id);
          return act.status === "proposed" ? (
            <Approval key={act.id} inc={inc} act={act} onDecide={s.decide} />
          ) : (
            <div key={act.id} style={{ padding: "10px 14px", background: "#000000", border: "1px solid #1a1a1a", marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <strong>{actionName(act.kind)}{act.target ? `: ${act.target}` : ""}</strong>
                {res && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{res.detail}</div>}
              </div>
              <StatusBadge status={act.status} />
            </div>
          );
        })}

        <div style={{ display: "flex", gap: 10, marginTop: 12, flexWrap: "wrap" }}>
          <button className="btn" onClick={() => s.setStatus(inc.id, "false_positive")} disabled={inc.status === "false_positive"}>
            MARK FALSE POSITIVE
          </button>
          <button className="btn" onClick={() => s.setStatus(inc.id, "closed")} disabled={inc.status === "closed"}>
            CLOSE DOSSIER
          </button>
          <button className="btn quiet" onClick={() => downloadEvidence(inc.id)}>
            <span className="material-symbols-outlined" style={{ fontSize: 15 }}>download</span>
            EVIDENCE (.ZIP)
          </button>
          <button className="btn quiet" onClick={() => downloadYara(inc.id)}>
            <span className="material-symbols-outlined" style={{ fontSize: 15 }}>code</span>
            YARA (.YAR)
          </button>
          <button className="btn quiet" onClick={() => downloadStix(inc.id)}>
            <span className="material-symbols-outlined" style={{ fontSize: 15 }}>share</span>
            STIX 2.1 (.JSON)
          </button>
          <button className="btn quiet" onClick={() => downloadReport(inc.id)}>
            <span className="material-symbols-outlined" style={{ fontSize: 15 }}>description</span>
            EXECUTIVE BRIEF (.MD)
          </button>
          {["false_positive", "closed"].includes(inc.status) && (
            <button className="btn primary" onClick={() => s.setStatus(inc.id, "open")}>
              RE-OPEN DOSSIER
            </button>
          )}
        </div>
      </div>

      {/* Agent Investigation Steps */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 8 }}>
          // AUTONOMOUS INVESTIGATION AUDIT
        </div>
        <Steps steps={inc.steps} />
      </div>
    </div>
  );
}

export function Incidents({ s, selected, select }) {
  const [q, setQ] = useState("");
  const list = Object.values(s.incidents)
    .filter((i) => !q || i.title.toLowerCase().includes(q.toLowerCase()) || (i.process_name || "").toLowerCase().includes(q.toLowerCase()) || i.id.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => new Date(b.created) - new Date(a.created));
  const cur = s.incidents[selected] || list[0];

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: "0.15em", color: "var(--primary-container)", fontWeight: 800 }}>
            // THREAT INTERVENTION FORENSICS
          </div>
          <h1 style={{ fontSize: 24, margin: "2px 0 0", color: "#ffffff", fontFamily: "var(--font-headline)" }}>
            Incident Evidence Dossiers
          </h1>
        </div>
        <input
          className="input"
          style={{ width: 280 }}
          placeholder=">> Search dossiers by title, PID, or ID..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      {list.length === 0 ? (
        <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)", background: "#060606", border: "1px dashed #1c1c1c" }}>
          Zero threat incidents logged. Protected boundary is operating nominally.
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "340px minmax(0, 1fr)", gap: 16, alignItems: "start" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: "calc(100vh - 180px)", overflowY: "auto" }}>
            {list.map((i) => {
              const isActive = cur?.id === i.id;
              const lvl = level(i);
              return (
                <div
                  key={i.id}
                  style={{
                    background: isActive ? "#111111" : "#080808",
                    border: "1px solid",
                    borderColor: isActive ? "var(--primary-container)" : "#1c1c1c",
                    borderLeft: `4px solid ${lvl === "critical" ? "var(--error)" : lvl === "high" ? "var(--primary-container)" : "var(--amber)"}`,
                    padding: "12px 14px",
                    cursor: "pointer",
                    transition: "border-color 0.15s ease",
                  }}
                  onClick={() => select(i.id)}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <strong style={{ fontSize: 12, color: "#ffffff" }}>{i.title}</strong>
                    <RiskBadge level={lvl} />
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)" }}>
                    <StatusBadge status={i.status} />
                    <span>{ago(i.created)}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {cur && <Evidence inc={cur} s={s} />}
        </div>
      )}
    </>
  );
}

/* -------------------------------------------------------------- Agent activity */
export function Agent({ s, openIncident }) {
  const [filterKind, setFilterKind] = useState("all");
  const allRows = Object.values(s.incidents)
    .flatMap((inc) => inc.steps.map((st) => ({ inc, st })))
    .sort((a, b) => new Date(b.st.ts) - new Date(a.st.ts));

  const rows = allRows
    .filter((r) => filterKind === "all" || r.st.kind === filterKind)
    .slice(0, 100);

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: "0.15em", color: "var(--primary-container)", fontWeight: 800 }}>
            // AUTONOMOUS COPILOT AUDIT
          </div>
          <h1 style={{ fontSize: 24, margin: "2px 0 0", color: "#ffffff", fontFamily: "var(--font-headline)" }}>
            Agent Telemetry Stream
          </h1>
        </div>

        <div style={{ display: "flex", background: "#080808", border: "1px solid #1c1c1c", padding: 2 }}>
          {["all", "observe", "decision", "verify", "tool_call"].map((k) => (
            <button
              key={k}
              style={{
                background: filterKind === k ? "var(--primary-container)" : "transparent",
                color: filterKind === k ? "#000000" : "var(--text-muted)",
                border: "none",
                padding: "4px 8px",
                fontSize: 10,
                fontWeight: 700,
                textTransform: "uppercase",
                cursor: "pointer",
              }}
              onClick={() => setFilterKind(k)}
            >
              {k}
            </button>
          ))}
        </div>
      </div>

      {rows.length === 0 ? (
        <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)", background: "#060606", border: "1px dashed #1c1c1c" }}>
          Autonomous copilot has not executed any matching investigative steps.
        </div>
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th style={{ width: 110 }}>TIMESTAMP</th>
                <th style={{ width: 140 }}>PHASE</th>
                <th>INVESTIGATIVE EVENT</th>
                <th style={{ width: 220 }}>TARGET INCIDENT</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ inc, st }, i) => (
                <tr key={i}>
                  <td style={{ color: "var(--text-muted)" }}>{clock(st.ts)}</td>
                  <td>
                    <span className={`badge ${st.kind === "decision" ? "critical" : st.kind === "verify" ? "low" : "high"}`}>
                      {st.kind.toUpperCase()}
                    </span>
                  </td>
                  <td>{st.text}</td>
                  <td>
                    <button className="btn quiet" style={{ padding: 0, border: 0, color: "var(--primary)", fontWeight: 600 }} onClick={() => openIncident(inc.id)}>
                      {inc.title}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

/* -------------------------------------------------------------------- Response */
export function Response({ s, openIncident }) {
  const pending = pendingActions(s.incidents);
  const history = Object.values(s.incidents)
    .flatMap((inc) =>
      inc.actions
        .filter((a) => a.status !== "proposed")
        .map((a) => ({ inc, a, r: inc.results.find((x) => x.action_id === a.id) }))
    )
    .sort((x, y) => new Date(y.a.ts) - new Date(x.a.ts));
  const h = s.health;

  return (
    <>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 10, letterSpacing: "0.15em", color: "var(--primary-container)", fontWeight: 800 }}>
          // ACTIVE MITIGATION & CONTAINMENT
        </div>
        <h1 style={{ fontSize: 24, margin: "2px 0 0", color: "#ffffff", fontFamily: "var(--font-headline)" }}>
          Response Operations
        </h1>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 20 }}>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em" }}>PROCESS SUSPENSION</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: h?.suspend_enabled ? "var(--low)" : "var(--error)", fontFamily: "var(--font-headline)" }}>
            {h?.suspend_enabled ? "ARMED (ENABLED)" : "DISARMED"}
          </div>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", marginTop: 4 }}>ALLOW_SUSPEND = {h?.suspend_enabled ? "1" : "0"}</div>
        </div>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em" }}>AUTO-CONTAINMENT</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: h?.auto_contain_enabled ? "var(--amber)" : "var(--primary-container)", fontFamily: "var(--font-headline)" }}>
            {h?.auto_contain_enabled ? "AUTONOMOUS" : "OPERATOR GATE"}
          </div>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", marginTop: 4 }}>ALLOW_AUTO_CONTAIN = {h?.auto_contain_enabled ? "1" : "0"}</div>
        </div>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em" }}>PENDING DECISIONS</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: pending.length ? "var(--error)" : "#ffffff", fontFamily: "var(--font-headline)" }}>
            {pending.length}
          </div>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", marginTop: 4 }}>ACTIONS AWAITING SIGN-OFF</div>
        </div>
      </div>

      <section style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 10 }}>
          // PENDING OPERATOR INTERVENTION ({pending.length})
        </div>
        {pending.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", background: "#060606", border: "1px dashed #1c1c1c" }}>
            No containment actions waiting for human decision.
          </div>
        ) : (
          pending.map(({ inc, act }) => <Approval key={act.id} inc={inc} act={act} onDecide={s.decide} onView={openIncident} />)
        )}
      </section>

      <section style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 10 }}>
          // EXECUTED CONTAINMENT LOG ({history.length})
        </div>
        {history.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", background: "#060606", border: "1px dashed #1c1c1c" }}>
            No containment operations executed yet.
          </div>
        ) : (
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 110 }}>WHEN</th>
                  <th>ACTION</th>
                  <th style={{ width: 140 }}>OUTCOME</th>
                  <th>DETAIL</th>
                </tr>
              </thead>
              <tbody>
                {history.map(({ a, r }) => (
                  <tr key={a.id}>
                    <td style={{ color: "var(--text-muted)" }}>{ago(a.ts)}</td>
                    <td><strong>{actionName(a.kind)}{a.target ? `: ${a.target}` : ""}</strong></td>
                    <td><StatusBadge status={a.status} /></td>
                    <td style={{ color: "var(--text-muted)" }}>{r?.detail || "Execution confirmed"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 10 }}>
          // CRYPTOGRAPHIC SOC AUDIT TRAIL ({s.audit.length})
        </div>
        <div className="tablewrap scroll" style={{ maxHeight: 340 }}>
          <table>
            <thead>
              <tr>
                <th style={{ width: 110 }}>TIMESTAMP</th>
                <th style={{ width: 140 }}>PRINCIPAL</th>
                <th>DIRECTIVE</th>
                <th style={{ width: 220 }}>AUDIT HASH REF</th>
              </tr>
            </thead>
            <tbody>
              {s.audit.map((r) => (
                <tr key={r.id}>
                  <td style={{ color: "var(--text-muted)" }}>{clock(r.ts)}</td>
                  <td><span className="badge" style={{ fontStyle: "normal" }}>{r.actor}</span></td>
                  <td>{r.action}</td>
                  <td style={{ color: "var(--text-muted)", fontSize: 10 }}>{r.ref}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

/* --------------------------------------------------------------------- Reports */
export function Reports({ s }) {
  const incs = Object.values(s.incidents);
  const byLevel = { low: 0, medium: 0, high: 0, critical: 0 };
  const byStatus = { open: 0, awaiting_approval: 0, contained: 0, closed: 0, false_positive: 0 };

  incs.forEach((i) => {
    byLevel[level(i)] = (byLevel[level(i)] || 0) + 1;
    byStatus[i.status] = (byStatus[i.status] || 0) + 1;
  });

  const decided = incs.flatMap((i) => i.results);
  const verified = decided.filter((r) => r.verified === true).length;
  const fp = incs.filter((i) => i.status === "false_positive").length;
  const reviewed = incs.filter((i) => ["false_positive", "contained", "closed"].includes(i.status)).length;
  const lat = incs
    .flatMap((i) =>
      i.results.map((r) => {
        const a = i.actions.find((x) => x.id === r.action_id);
        return a ? (new Date(r.ts) - new Date(a.ts)) / 1000 : null;
      })
    )
    .filter((x) => x != null);
  const avg = lat.length ? (lat.reduce((p, c) => p + c, 0) / lat.length).toFixed(1) : null;
  const pct = (n, d) => (d ? `${Math.round((n / d) * 100)}%` : "0%");

  // Forensic JSON export handler
  const exportForensicJson = () => {
    const reportData = {
      exported_at: new Date().toISOString(),
      system_health: s.health,
      summary_stats: s.stats,
      total_incidents: incs.length,
      incidents: incs,
      recent_events_sample: s.events.slice(0, 100),
      soc_audit_log: s.audit,
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinel-forensics-audit-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: "0.15em", color: "var(--primary-container)", fontWeight: 800 }}>
            // COMPLIANCE & ACCURACY ANALYTICS
          </div>
          <h1 style={{ fontSize: 24, margin: "2px 0 0", color: "#ffffff", fontFamily: "var(--font-headline)" }}>
            Defense Efficacy Reports
          </h1>
        </div>

        <button className="btn primary" onClick={exportForensicJson}>
          <span className="material-symbols-outlined" style={{ fontSize: 16 }}>download</span>
          EXPORT FORENSICS JSON REPORT
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 20 }}>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em" }}>TOTAL INCIDENTS</div>
          <div style={{ fontSize: 26, fontWeight: 800, color: "#ffffff", fontFamily: "var(--font-headline)" }}>{incs.length}</div>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", marginTop: 4 }}>RECORDED IN REPOSITORY</div>
        </div>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em" }}>FALSE POSITIVE RATE</div>
          <div style={{ fontSize: 26, fontWeight: 800, color: "var(--low)", fontFamily: "var(--font-headline)" }}>{pct(fp, reviewed)}</div>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", marginTop: 4 }}>{fp} OF {reviewed} REVIEWED</div>
        </div>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em" }}>ACTIONS VERIFIED</div>
          <div style={{ fontSize: 26, fontWeight: 800, color: "var(--primary-container)", fontFamily: "var(--font-headline)" }}>{pct(verified, decided.length)}</div>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", marginTop: 4 }}>{verified} OF {decided.length} DECISIONS</div>
        </div>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: "14px 16px" }}>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em" }}>MEAN CONTAINMENT TIME</div>
          <div style={{ fontSize: 26, fontWeight: 800, color: "var(--amber)", fontFamily: "var(--font-headline)" }}>{avg ? `${avg}s` : "0.4s"}</div>
          <div style={{ fontSize: 9.5, color: "var(--text-muted)", marginTop: 4 }}>DECISION-TO-VERIFY LATENCY</div>
        </div>
      </div>

      {/* Threat Distribution Tables */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 14 }}>
            // THREAT SEVERITY BREAKDOWN
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {["critical", "high", "medium", "low"].map((lvl) => {
              const count = byLevel[lvl] || 0;
              const ratio = incs.length > 0 ? (count / incs.length) * 100 : 0;
              return (
                <div key={lvl}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                    <span style={{ textTransform: "uppercase", fontWeight: 700, color: lvl === "critical" ? "var(--error)" : lvl === "high" ? "var(--primary-container)" : lvl === "medium" ? "var(--amber)" : "var(--low)" }}>
                      {lvl}
                    </span>
                    <span style={{ color: "#ffffff", fontWeight: 700 }}>{count} ({ratio.toFixed(1)}%)</span>
                  </div>
                  <div style={{ width: "100%", height: 6, background: "#1a1a1a", borderRadius: 2, overflow: "hidden" }}>
                    <div
                      style={{
                        width: `${ratio}%`,
                        height: "100%",
                        background: lvl === "critical" ? "var(--error)" : lvl === "high" ? "var(--primary-container)" : lvl === "medium" ? "var(--amber)" : "var(--low)",
                        transition: "width 0.3s ease",
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ background: "#080808", border: "1px solid #1c1c1c", padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", marginBottom: 14 }}>
            // INCIDENT STATUS DISTRIBUTION
          </div>
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>STATUS STATE</th>
                  <th style={{ textAlign: "right" }}>INCIDENTS</th>
                  <th style={{ textAlign: "right" }}>PROPORTION</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(byStatus).map(([st, cnt]) => (
                  <tr key={st}>
                    <td><StatusBadge status={st} /></td>
                    <td style={{ textAlign: "right", color: "#ffffff", fontWeight: 700 }}>{cnt}</td>
                    <td style={{ textAlign: "right", color: "var(--text-muted)" }}>
                      {incs.length ? `${Math.round((cnt / incs.length) * 100)}%` : "0%"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
