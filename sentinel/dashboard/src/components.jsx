import { useEffect, useMemo, useState } from "react";
import { actionName, ago, clock, humanStatus } from "./util";

export const Icon = ({ name, filled = false }) => {
  const iconMap = {
    overview: "dashboard",
    dashboard: "dashboard",
    live: "ssid_chart",
    incidents: "warning",
    agent: "terminal",
    response: "bolt",
    reports: "analytics",
    alerts: "notifications",
  };
  const iconName = iconMap[name] || name;
  return (
    <span className={`material-symbols-outlined ${filled ? "fill" : ""}`} aria-hidden="true">
      {iconName}
    </span>
  );
};

export const RiskBadge = ({ level = "low" }) => {
  const normalized = level.toLowerCase();
  return (
    <span className={`badge ${normalized}`}>
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: "currentColor" }} />
      {normalized} risk
    </span>
  );
};

export const StatusBadge = ({ status }) => {
  let tone = "neutral";
  if (["contained", "verified", "done"].includes(status)) tone = "low";
  else if (["open", "awaiting_approval", "proposed"].includes(status)) tone = "high";
  else if (["false_positive", "closed"].includes(status)) tone = "neutral";
  else if (["failed", "rejected"].includes(status)) tone = "critical";

  return <span className={`badge ${tone}`}>{humanStatus(status)}</span>;
};

// VBLACK Tactical HUD Trace (100% Connected to Real Live Data)
const SPAN = 120;
export function Trace({ events = [], incidents = {} }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const { points, max } = useMemo(() => {
    const buckets = new Array(SPAN).fill(0);
    const start = now / 1000 - SPAN;
    for (const e of events) {
      const t = new Date(e.ts).getTime() / 1000;
      const i = Math.floor(t - start);
      if (i >= 0 && i < SPAN) buckets[i] += 1;
    }
    return { points: buckets, max: Math.max(5, ...buckets) };
  }, [events, now]);

  const W = 1000, H = 200, pad = 10;
  const x = (i) => (i / (SPAN - 1)) * W;
  const y = (v) => H - pad - (v / max) * (H - pad * 2);

  let line = `M0 ${y(points[0])}`;
  points.forEach((v, i) => {
    if (i) line += ` L${x(i).toFixed(1)} ${y(v).toFixed(1)}`;
  });
  const area = `${line} L${W} ${H} L0 ${H} Z`;

  const marks = Object.values(incidents)
    .map((inc) => ({
      inc,
      pos: (new Date(inc.created).getTime() - (now - SPAN * 1000)) / (SPAN * 1000),
    }))
    .filter((m) => m.pos >= 0 && m.pos <= 1);

  const currentWrites = points[points.length - 1] || 0;
  const lastActiveInc = Object.values(incidents).sort((a, b) => new Date(b.created) - new Date(a.created))[0];

  return (
    <div className="hud-trace-card">
      <div className="hud-trace-header">
        <div>
          <div className="trace-title">
            // FILE CHANGES PER SECOND (I/O BURST TELEMETRY) // 2-MIN WINDOW
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
            REAL-TIME KERNEL DISK PROBE // BUFFER: {events.length} EVENTS IN-MEMORY
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10 }}>
            <span style={{ width: 10, height: 2, background: "var(--amber)" }} />
            <span style={{ color: "var(--text-secondary)" }}>BASELINE</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10 }}>
            <span style={{ width: 10, height: 2, background: "var(--error)" }} />
            <span style={{ color: "var(--error)", fontWeight: 700 }}>SURGE VECTOR</span>
          </div>
          <div className="defcon-badge">
            <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--error)" }} />
            LIVE STREAM: {currentWrites} writes/s
          </div>
        </div>
      </div>

      <div className="hud-plot-window">
        <div className="hud-plot-grid" />

        <div className="peak-callout">
          <div className="peak-callout-val">{max} w/s PEAK</div>
          <div style={{ fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em" }}>MAX OBSERVED RATE</div>
        </div>

        <svg style={{ width: "100%", height: "100%", position: "relative", zIndex: 10 }} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
          <defs>
            <linearGradient id="attackGlow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ff3333" stopOpacity="0.4" />
              <stop offset="60%" stopColor="#ff6600" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#ff6600" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          <path d={area} fill="url(#attackGlow)" />
          <path d={line} fill="none" stroke="#ff5500" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />

          {marks.map((m) => (
            <g key={m.inc.id}>
              <line x1={m.pos * W} x2={m.pos * W} y1="0" y2={H} stroke="#ff3333" strokeWidth="1.5" strokeDasharray="4 3" />
              <circle cx={m.pos * W} cy={y(points[Math.floor(m.pos * (SPAN - 1))] || 0)} r="4" fill="#ff3333" />
            </g>
          ))}
        </svg>

        {marks.map((m) => (
          <div
            key={m.inc.id}
            style={{
              position: "absolute",
              left: `${m.pos * 100}%`,
              top: 10,
              transform: "translateX(-50%)",
              background: "var(--error)",
              color: "#ffffff",
              fontSize: 9,
              fontWeight: 800,
              padding: "2px 6px",
              borderRadius: 2,
              zIndex: 20,
              letterSpacing: "0.08em",
            }}
          >
            TRIGGER: {m.inc.assessment?.level?.toUpperCase() || "ALERT"}
          </div>
        ))}
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--text-muted)", paddingTop: 6 }}>
        <span>T-120s (NOMINAL)</span>
        <span>T-90s</span>
        <span>T-60s</span>
        <span style={{ color: "var(--primary-container)", fontWeight: 700 }}>T-30s</span>
        <span style={{ color: "var(--error)", fontWeight: 700 }}>T-00s (NOW)</span>
      </div>

      {/* Real-time Metric Readout Strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginTop: 12 }}>
        <div style={{ background: "#0c0c0c", padding: "8px 10px", border: "1px solid #1a1a1a" }}>
          <div style={{ fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em" }}>BUFFER VELOCITY</div>
          <div style={{ fontSize: 12, fontWeight: 700, color: "#ffffff" }}>{currentWrites} writes/s</div>
        </div>
        <div style={{ background: "#0c0c0c", padding: "8px 10px", border: "1px solid #1a1a1a" }}>
          <div style={{ fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em" }}>MAX 2M BURST</div>
          <div style={{ fontSize: 12, fontWeight: 700, color: "var(--error)" }}>{max} w/s peak</div>
        </div>
        <div style={{ background: "#0c0c0c", padding: "8px 10px", border: "1px solid #1a1a1a" }}>
          <div style={{ fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em" }}>LATEST AFFECTED TARGET</div>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--amber)", textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }} title={lastActiveInc?.title || events[0]?.path || "None"}>
            {lastActiveInc?.title || events[0]?.path || "None"}
          </div>
        </div>
        <div style={{ background: "#0c0c0c", padding: "8px 10px", border: "1px solid #1a1a1a" }}>
          <div style={{ fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em" }}>DETECTION ENGINE</div>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--primary)" }}>
            {lastActiveInc?.assessment?.method ? `ACTIVE (${lastActiveInc.assessment.method.toUpperCase()})` : "ACTIVE (HEURISTICS)"}
          </div>
        </div>
      </div>
    </div>
  );
}

// Tactical Intervention Card (Fully Dynamic & Actionable)
export function Approval({ inc, act, onDecide, onView }) {
  const a = inc.assessment;
  const isCritical = a?.level === "critical" || a?.level === "high";

  // Construct real actionable command display
  const targetPid = act.pid || inc.pid;
  const cmd = act.kind === "suspend_process"
    ? `kill -STOP ${targetPid || ""}`
    : act.kind === "quarantine_file"
    ? `quarantine ${act.target || "file"}`
    : `${actionName(act.kind)} ${act.target || ""}`;

  return (
    <article className="intervention-card" aria-label={`Approval needed: ${actionName(act.kind)}`}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: "var(--error)", letterSpacing: "0.1em" }}>
            // INTERVENTION-REQ #{act.id.slice(0, 8)}
          </span>
          <span style={{ fontSize: 10, color: "var(--text-muted)" }}>[RAISED {ago(act.ts)}]</span>
        </div>
        <span className={`badge ${isCritical ? "critical" : "high"}`}>
          {a ? `${Math.round(a.score * 100)}% RISK` : "ACTION REQUIRED"}
        </span>
      </div>

      <div style={{ background: "#000000", border: "1px solid #1c1c1c", padding: "10px 14px", marginBottom: 12 }}>
        <div style={{ fontSize: 9.5, color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
          PRIMARY INTERVENTION COMMAND:
        </div>
        <div className="command-pill-box" style={{ margin: "6px 0" }}>
          <code>{cmd}</code>
          <span className="material-symbols-outlined" style={{ color: "var(--primary-container)" }}>terminal</span>
        </div>
        <div style={{ fontSize: 11.5, color: "var(--text-secondary)" }}>
          {a?.summary || act.rationale || inc.title}
        </div>
      </div>

      {a?.uncertainty?.length > 0 && (
        <div style={{ background: "#050505", border: "1px solid #221a14", padding: "8px 12px", fontSize: 11, color: "var(--amber)", marginBottom: 14 }}>
          <strong>UNCERTAINTY:</strong> {a.uncertainty.join("; ")}
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <button className="btn primary" onClick={() => onDecide(inc.id, act.id, true)}>
          <span className="material-symbols-outlined" style={{ fontSize: 16 }}>bolt</span>
          APPROVE CONTAINMENT
        </button>
        <button className="btn danger" onClick={() => onDecide(inc.id, act.id, false)}>
          <span className="material-symbols-outlined" style={{ fontSize: 16 }}>close</span>
          REJECT
        </button>
        {onView && (
          <button className="btn quiet" onClick={() => onView(inc.id)}>
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>visibility</span>
            FORENSIC EVIDENCE
          </button>
        )}
      </div>
    </article>
  );
}

// Agent Timeline
export function Steps({ steps = [] }) {
  const label = {
    observe: "OBSERVED",
    tool_call: "EXECUTED",
    tool_result: "DISCOVERED",
    reasoning: "EVALUATED",
    decision: "DECIDED",
    verify: "VERIFIED",
  };

  if (steps.length === 0) {
    return (
      <div style={{ padding: 16, background: "#050505", border: "1px dashed #1a1a1a", fontSize: 11, color: "var(--text-muted)" }}>
        No autonomous agent steps logged for this record.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {steps.map((s, i) => (
        <div key={i} style={{ display: "flex", gap: 12, padding: "10px 12px", background: "#080808", border: "1px solid #1a1a1a" }}>
          <span className={`badge ${s.kind === "decision" ? "critical" : s.kind === "verify" ? "low" : "high"}`} style={{ height: "fit-content" }}>
            {label[s.kind] || s.kind}
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#ffffff", fontSize: 12 }}>{s.text}</div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
              TIMESTAMP: {clock(s.ts)}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
