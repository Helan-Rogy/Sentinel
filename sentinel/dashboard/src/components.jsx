import { useEffect, useMemo, useState } from "react";
import { actionName, ago, clock, humanStatus } from "./util";

export const Icon = ({ name }) => {
  const d = {
    overview: "M3 12h4l3-8 4 16 3-8h4",
    live: "M2 12a10 10 0 0 1 20 0M6 12a6 6 0 0 1 12 0M10 12a2 2 0 0 1 4 0",
    incidents: "M12 3 2 21h20L12 3zM12 10v5M12 18v.01",
    agent: "M12 3v3M5 9h14v10H5zM9 14h.01M15 14h.01",
    response: "M5 12l5 5L20 7",
    reports: "M4 20V10M10 20V4M16 20v-7M22 20H2",
  }[name];
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
};

export const RiskBadge = ({ level }) => <span className={`badge ${level}`}>{level} risk</span>;
export const StatusBadge = ({ status }) => <span className="badge">{humanStatus(status)}</span>;

// Live activity trace: file changes per second over the last two minutes, with incident markers.
const SPAN = 120;
export function Trace({ events, incidents, tone }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);

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

  const W = 1000, H = 200, pad = 14;
  const x = (i) => (i / (SPAN - 1)) * W;
  const y = (v) => H - pad - (v / max) * (H - pad * 2);
  let line = `M0 ${y(points[0])}`;
  points.forEach((v, i) => { if (i) line += ` L${x(i).toFixed(1)} ${y(v).toFixed(1)}`; });
  const area = `${line} L${W} ${H} L0 ${H} Z`;

  const marks = Object.values(incidents)
    .map((inc) => ({ inc, pos: ((new Date(inc.created).getTime() - (now - SPAN * 1000)) / (SPAN * 1000)) }))
    .filter((m) => m.pos >= 0 && m.pos <= 1);

  return (
    <figure className="trace-wrap" style={{ margin: 0 }}>
      <div className="trace" style={{ "--trace": `var(--${tone})` }}>
        <span className="trace-scale">{max} changes/s</span>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
             aria-label={`File activity over the last two minutes. Peak ${max} changes per second.`}>
          {[0.25, 0.5, 0.75].map((f) => <line key={f} className="grid" x1="0" x2={W} y1={H * f} y2={H * f} />)}
          <path className="area" d={area} />
          <path className="line" d={line} />
          {marks.map((m) => <line key={m.inc.id} className="mark" x1={m.pos * W} x2={m.pos * W} y1="0" y2={H} />)}
        </svg>
        {marks.map((m) => (
          <span key={m.inc.id} className="trace-flag" style={{ left: `${m.pos * 100}%` }}>
            {m.inc.assessment?.level || "alert"}
          </span>
        ))}
      </div>
      <figcaption className="trace-axis"><span>2 min ago</span><span>file changes per second</span><span>now</span></figcaption>
    </figure>
  );
}

export function Approval({ inc, act, onDecide, onView }) {
  const a = inc.assessment;
  return (
    <article className={`approval ${a?.level || ""}`} aria-label={`Approval needed: ${actionName(act.kind)}`}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h3>{actionName(act.kind)}{act.target ? `: ${act.target}` : ""}{act.pid ? ` (pid ${act.pid})` : ""}</h3>
        {a && <span className={`badge ${a.level}`}>{a.level} risk, {Math.round(a.score * 100)}%</span>}
      </div>
      <div className="muted">{a?.summary || act.rationale || inc.title}</div>
      {a?.uncertainty?.length > 0 && <div className="muted">Uncertain: {a.uncertainty.join("; ")}</div>}
      <div className="row">
        <button className="btn danger" onClick={() => onDecide(inc.id, act.id, true)}>Approve {actionName(act.kind).toLowerCase()}</button>
        <button className="btn" onClick={() => onDecide(inc.id, act.id, false)}>Reject</button>
        {onView && <button className="btn quiet" onClick={() => onView(inc.id)}>See evidence</button>}
        <span className="muted">Raised {ago(act.ts)}</span>
      </div>
    </article>
  );
}

export function Steps({ steps }) {
  return (
    <ol className="timeline">
      {steps.map((s, i) => (
        <li key={i} className={s.kind}>
          <span className="kind">{{ observe: "Saw", tool_call: "Ran", tool_result: "Found", reasoning: "Thought", decision: "Decided", verify: "Checked" }[s.kind] || s.kind}</span>
          {s.text} <span className="muted mono">{clock(s.ts)}</span>
        </li>
      ))}
    </ol>
  );
}
