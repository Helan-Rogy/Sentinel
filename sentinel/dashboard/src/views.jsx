import { useMemo, useState } from "react";
import { Approval, RiskBadge, StatusBadge, Steps, Trace } from "./components";
import { RANK, actionName, ago, clock, dateTime, fileName, humanStatus, level, pendingActions } from "./util";

const worst = (incidents) =>
  Object.values(incidents)
    .filter((i) => ["open", "awaiting_approval"].includes(i.status))
    .reduce((w, i) => (RANK[level(i)] > RANK[w] ? level(i) : w), "low");

// One row per decoy file instead of one row per raw event.
const groupHits = (hits) => {
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
  const headline = pending.length
    ? `${pending.length} containment ${pending.length === 1 ? "action needs" : "actions need"} your decision`
    : active.length ? "Suspicious activity is open, nothing waiting on you" : "All quiet. Nothing suspicious right now";
  const recent = Object.values(s.incidents).sort((a, b) => new Date(b.created) - new Date(a.created)).slice(0, 5);
  const contained = Object.values(s.incidents).filter((i) => i.status === "contained").length;

  return (
    <>
      <h1 aria-live="polite">{headline}</h1>
      <p className="lede">Watching the protected folder for encryption-like behavior. Detection is evidence, not proof, so every containment action waits for a person.</p>

      <Trace events={s.events} incidents={s.incidents} tone={tone === "low" ? "accent" : tone} />
      <ul className="stats">
        <li><b>{s.stats?.events ?? s.events.length}</b><span>file events seen</span></li>
        <li><b>{active.length}</b><span>open incidents</span></li>
        <li><b>{contained}</b><span>contained</span></li>
        <li><b>{s.stats?.pending_approvals ?? pending.length}</b><span>waiting for approval</span></li>
      </ul>

      {pending.length > 0 && (
        <section className="section" aria-label="Approvals needed">
          <h2>Needs your decision</h2>
          {pending.slice(0, 3).map(({ inc, act }) => (
            <Approval key={act.id} inc={inc} act={act} onDecide={s.decide} onView={openIncident} />
          ))}
        </section>
      )}

      <section className="section">
        <div className="section-head"><h2>Recent incidents</h2><button className="btn quiet" onClick={() => go("incidents")}>All incidents</button></div>
        {recent.length === 0 ? (
          <div className="empty">No incidents yet. Run the simulator against the watched folder to see one appear here.</div>
        ) : (
          <div className="tablewrap"><table>
            <thead><tr><th>When</th><th>Incident</th><th>Risk</th><th>Status</th></tr></thead>
            <tbody>{recent.map((i) => (
              <tr key={i.id}>
                <td>{ago(i.created)}</td>
                <td><button className="btn quiet" style={{ padding: 0, minHeight: 0, border: 0 }} onClick={() => openIncident(i.id)}>{i.title}</button></td>
                <td><RiskBadge level={level(i)} /></td>
                <td><StatusBadge status={i.status} /></td>
              </tr>))}</tbody>
          </table></div>
        )}
      </section>
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
  const rows = useMemo(
    () => source.filter((e) => (op === "all" || e.op === op) && (!q || (e.path + (e.process_name || "")).toLowerCase().includes(q.toLowerCase()))).slice(0, 200),
    [source, op, q]
  );
  return (
    <>
      <h1>Live file activity</h1>
      <p className="lede">Every change the endpoint service reports, newest first. Showing up to 200 rows.</p>
      <div className="toolbar">
        <div className="seg" role="group" aria-label="Filter by operation">
          {["all", "create", "modify", "rename", "delete"].map((o) => (
            <button key={o} aria-pressed={op === o} onClick={() => setOp(o)}>{o === "all" ? "All" : o[0].toUpperCase() + o.slice(1)}</button>
          ))}
        </div>
        <input className="input" placeholder="Filter by path or process" aria-label="Filter by path or process" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="btn" onClick={() => { setFrozen(s.events); setPaused(!paused); }}>{paused ? "Resume stream" : "Pause stream"}</button>
        <span className="muted">{s.events.length} in memory</span>
      </div>
      {rows.length === 0 ? <div className="empty">No events match. Start the endpoint agent and change a file in the watched folder.</div> : (
        <div className="tablewrap scroll"><table>
          <thead><tr><th>Time</th><th>Action</th><th>File</th><th>Process</th></tr></thead>
          <tbody>{rows.map((e) => (
            <tr key={e.id}>
              <td className="mono">{clock(e.ts)}</td>
              <td className={`op ${e.op}`}>{e.op}</td>
              <td className="path mono">{e.new_path ? `${fileName(e.path)} → ${fileName(e.new_path)}` : e.path}</td>
              <td>{e.process_name || <span className="muted">unknown</span>}</td>
            </tr>))}</tbody>
        </table></div>
      )}
    </>
  );
}

/* ----------------------------------------------------------------- Incidents */
function Evidence({ inc, s }) {
  const a = inc.assessment;
  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>{inc.title}</h2>
        <StatusBadge status={inc.status} />
      </div>
      <div className="muted">Opened {dateTime(inc.created)}{inc.pid ? `, process ${inc.process_name} (pid ${inc.pid})` : ""}, {inc.affected_files} files affected</div>

      {a && (
        <section className="section" style={{ marginTop: 22 }}>
          <div className="score"><b>{Math.round(a.score * 100)}%</b>
            <div><div className={`bar ${a.level}`} role="img" aria-label={`Risk score ${Math.round(a.score * 100)} percent`}><i style={{ width: `${a.score * 100}%` }} /></div>
              <div className="row" style={{ marginTop: 6 }}><RiskBadge level={a.level} /><span className="muted">scored by {a.method}</span></div></div>
          </div>
          <p>{a.summary}</p>
          <h3>Why this score</h3>
          <div className="tablewrap"><table>
            <thead><tr><th>Evidence</th><th>Detail</th><th>Weight</th></tr></thead>
            <tbody>{a.signals.map((sg) => (
              <tr key={sg.name}><td>{sg.name.replaceAll("_", " ")}</td><td className="muted">{sg.detail}</td><td>{Math.round(sg.weight * 100)}%</td></tr>))}</tbody>
          </table></div>
          {a.uncertainty.length > 0 && (<><h3 style={{ marginTop: 14 }}>What we are not sure about</h3><ul className="bullets">{a.uncertainty.map((u) => <li key={u}>{u}</li>)}</ul></>)}
        </section>
      )}

      <section className="section">
        <h2>Decoy files touched</h2>
        {inc.honey_hits.length === 0 ? <div className="empty">No decoy file was touched.</div> : (
          <div className="tablewrap"><table>
            <thead><tr><th>Decoy file</th><th>Touches</th><th>First seen</th></tr></thead>
            <tbody>{groupHits(inc.honey_hits).map((h) => (
              <tr key={h.path}><td className="path mono">{h.path}</td><td>{h.count}x ({h.ops.join(", ")})</td><td className="mono">{clock(h.first)}</td></tr>))}</tbody></table></div>)}
      </section>

      <section className="section">
        <h2>Files that look encrypted</h2>
        {inc.entropy.length === 0 ? <div className="empty">No entropy findings.</div> : (
          <div className="tablewrap"><table>
            <thead><tr><th>File</th><th>Entropy before to after</th><th>Type check</th></tr></thead>
            <tbody>{inc.entropy.map((r, i) => (
              <tr key={i}><td className="path mono">{fileName(r.path)}</td>
                <td>{r.previous_shannon != null ? `${r.previous_shannon.toFixed(2)} to ${r.shannon.toFixed(2)}` : r.shannon.toFixed(2)}</td>
                <td>{r.type_mismatch ? <span className="badge high">content does not match file type</span> : <span className="muted">matches</span>}</td></tr>))}</tbody>
          </table></div>)}
      </section>

      <section className="section">
        <h2>Sandbox analysis</h2>
        {!inc.sandbox ? <div className="empty">No sandbox report yet. Sandbox findings are one more piece of evidence, never proof.</div> : (
          <dl className="kv">
            <dt>Sample</dt><dd className="mono">{inc.sandbox.sample_path}</dd>
            <dt>Backend</dt><dd>{inc.sandbox.backend}</dd>
            <dt>Files touched</dt><dd>{inc.sandbox.files_touched} ({inc.sandbox.files_encrypted_like} encrypted-like)</dd>
            <dt>Extensions added</dt><dd>{inc.sandbox.extensions_changed.join(", ") || "none"}</dd>
            <dt>YARA matches</dt><dd>{inc.sandbox.yara_matches.join(", ") || "none"}</dd>
            <dt>Notes</dt><dd>{inc.sandbox.notes || "none"}</dd>
          </dl>)}
      </section>

      <section className="section">
        <h2>Response</h2>
        {inc.actions.length === 0 && <div className="empty">No actions proposed.</div>}
        {inc.actions.map((act) => {
          const res = inc.results.find((r) => r.action_id === act.id);
          return act.status === "proposed" ? (
            <Approval key={act.id} inc={inc} act={act} onDecide={s.decide} />
          ) : (
            <div key={act.id} style={{ marginBottom: 10 }}>
              <strong>{actionName(act.kind)}{act.target ? `: ${act.target}` : ""}</strong> <StatusBadge status={act.status} />
              {res && <div className="muted">{res.detail}{res.verified === true ? " Verified." : res.verified === false ? " Not verified." : ""}</div>}
            </div>
          );
        })}
        <div className="row" style={{ marginTop: 12 }}>
          <button className="btn" onClick={() => s.setStatus(inc.id, "false_positive")} disabled={inc.status === "false_positive"}>Mark as false positive</button>
          <button className="btn" onClick={() => s.setStatus(inc.id, "closed")} disabled={inc.status === "closed"}>Close incident</button>
        </div>
      </section>

      <section className="section"><h2>What the agent did</h2><Steps steps={inc.steps} /></section>
    </div>
  );
}

export function Incidents({ s, selected, select }) {
  const list = Object.values(s.incidents).sort((a, b) => new Date(b.created) - new Date(a.created));
  const cur = s.incidents[selected] || list[0];
  return (
    <>
      <h1>Incidents</h1>
      <p className="lede">Each incident gathers the evidence, the risk score and what was done about it.</p>
      {list.length === 0 ? <div className="empty">No incidents yet. When the detection engine scores activity as high risk, it appears here with its evidence.</div> : (
        <div className="split">
          <div className="inclist" role="list" aria-label="Incidents">
            {list.map((i) => (
              <button key={i.id} role="listitem" className="incitem" aria-current={cur?.id === i.id} onClick={() => select(i.id)}>
                <span className="row" style={{ justifyContent: "space-between" }}><strong>{i.title}</strong></span>
                <span className="row"><RiskBadge level={level(i)} /><span className="muted">{humanStatus(i.status)}</span></span>
                <span className="muted">{ago(i.created)}</span>
              </button>))}
          </div>
          {cur && <Evidence inc={cur} s={s} />}
        </div>
      )}
    </>
  );
}

/* -------------------------------------------------------------- Agent activity */
export function Agent({ s, openIncident }) {
  const rows = Object.values(s.incidents).flatMap((inc) => inc.steps.map((st) => ({ inc, st })))
    .sort((a, b) => new Date(b.st.ts) - new Date(a.st.ts)).slice(0, 80);
  const label = { observe: "Saw", tool_call: "Ran", tool_result: "Found", reasoning: "Thought", decision: "Decided", verify: "Checked" };
  return (
    <>
      <h1>Agent activity</h1>
      <p className="lede">Every investigation step, in order. The agent can only use approved tools and cannot run arbitrary commands.</p>
      {rows.length === 0 ? <div className="empty">The agent has not investigated anything yet.</div> : (
        <div className="tablewrap"><table>
          <thead><tr><th>Time</th><th>Step</th><th>What happened</th><th>Incident</th></tr></thead>
          <tbody>{rows.map(({ inc, st }, i) => (
            <tr key={i}><td className="mono">{clock(st.ts)}</td><td><strong>{label[st.kind] || st.kind}</strong></td><td>{st.text}</td>
              <td><button className="btn quiet" style={{ padding: 0, minHeight: 0, border: 0 }} onClick={() => openIncident(inc.id)}>{inc.title}</button></td></tr>))}</tbody>
        </table></div>)}
    </>
  );
}

/* -------------------------------------------------------------------- Response */
export function Response({ s, openIncident }) {
  const pending = pendingActions(s.incidents);
  const history = Object.values(s.incidents).flatMap((inc) => inc.actions.filter((a) => a.status !== "proposed").map((a) => ({ inc, a, r: inc.results.find((x) => x.action_id === a.id) })))
    .sort((x, y) => new Date(y.a.ts) - new Date(x.a.ts));
  const h = s.health;
  return (
    <>
      <h1>Response controls</h1>
      <p className="lede">Containment runs only after you approve it. Before acting, the endpoint re-checks that the process is still the one flagged.</p>

      <ul className="stats" aria-label="Safety switches">
        <li><b>{h?.suspend_enabled ? "On" : "Off"}</b><span>process suspension (server flag)</span></li>
        <li><b>{h?.auto_contain_enabled ? "On" : "Off"}</b><span>automatic containment</span></li>
        <li><b>{pending.length}</b><span>waiting</span></li>
      </ul>

      <section className="section"><h2>Waiting for approval</h2>
        {pending.length === 0 ? <div className="empty">Nothing is waiting. New requests appear here the moment the agent proposes an action.</div>
          : pending.map(({ inc, act }) => <Approval key={act.id} inc={inc} act={act} onDecide={s.decide} onView={openIncident} />)}
      </section>

      <section className="section"><h2>Action history</h2>
        {history.length === 0 ? <div className="empty">No actions have been decided yet.</div> : (
          <div className="tablewrap"><table>
            <thead><tr><th>When</th><th>Action</th><th>Outcome</th><th>Detail</th></tr></thead>
            <tbody>{history.map(({ a, r }) => (
              <tr key={a.id}><td>{ago(a.ts)}</td><td>{actionName(a.kind)}{a.target ? `: ${a.target}` : ""}</td><td><StatusBadge status={a.status} /></td><td className="muted">{r?.detail || ""}</td></tr>))}</tbody>
          </table></div>)}
      </section>

      <section className="section"><h2>Audit log</h2>
        <div className="tablewrap scroll" style={{ maxHeight: "40vh" }}><table>
          <thead><tr><th>Time</th><th>Who</th><th>What</th><th>Reference</th></tr></thead>
          <tbody>{s.audit.map((r) => (<tr key={r.id}><td className="mono">{clock(r.ts)}</td><td>{r.actor}</td><td>{r.action}</td><td className="mono muted">{r.ref}</td></tr>))}</tbody>
        </table></div>
      </section>
    </>
  );
}

/* --------------------------------------------------------------------- Reports */
const Bars = ({ data, tone }) => {
  const max = Math.max(1, ...Object.values(data));
  return Object.entries(data).map(([k, v]) => (
    <div className="hbar" key={k}><span>{k}</span><div className={`bar ${tone?.(k) || ""}`}><i style={{ width: `${(v / max) * 100}%` }} /></div><b>{v}</b></div>
  ));
};

export function Reports({ s }) {
  const incs = Object.values(s.incidents);
  const byLevel = { low: 0, medium: 0, high: 0, critical: 0 };
  const byStatus = {};
  incs.forEach((i) => { byLevel[level(i)] += 1; byStatus[humanStatus(i.status)] = (byStatus[humanStatus(i.status)] || 0) + 1; });
  const decided = incs.flatMap((i) => i.results);
  const verified = decided.filter((r) => r.verified === true).length;
  const fp = incs.filter((i) => i.status === "false_positive").length;
  const reviewed = incs.filter((i) => ["false_positive", "contained", "closed"].includes(i.status)).length;
  const lat = incs.flatMap((i) => i.results.map((r) => { const a = i.actions.find((x) => x.id === r.action_id); return a ? (new Date(r.ts) - new Date(a.ts)) / 1000 : null; })).filter((x) => x != null);
  const avg = lat.length ? (lat.reduce((p, c) => p + c, 0) / lat.length).toFixed(1) : null;
  const pct = (n, d) => (d ? `${Math.round((n / d) * 100)}%` : "n/a");

  return (
    <>
      <h1>Reports</h1>
      <p className="lede">Numbers for your evaluation. The false-positive rate counts only resolved incidents: contained, closed or marked as false positive.</p>
      <ul className="stats">
        <li><b>{incs.length}</b><span>incidents</span></li>
        <li><b>{pct(fp, reviewed)}</b><span>false positives among {reviewed} resolved incidents</span></li>
        <li><b>{pct(verified, decided.length)}</b><span>actions verified of {decided.length} executed</span></li>
        <li><b>{avg ? `${avg}s` : "n/a"}</b><span>average time from proposal to verified result</span></li>
      </ul>
      <div className="cols section">
        <div><h2>Incidents by risk</h2><Bars data={byLevel} tone={(k) => k} /></div>
        <div><h2>Incidents by status</h2>{Object.keys(byStatus).length ? <Bars data={byStatus} /> : <div className="empty">No incidents yet.</div>}</div>
      </div>
      <p className="muted section">The time from first suspicious file change to alert is measured by the evaluation script, not this page.</p>
    </>
  );
}
