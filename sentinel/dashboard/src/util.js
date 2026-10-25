export const RANK = { low: 0, medium: 1, high: 2, critical: 3 };

export const clock = (iso) =>
  new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export const dateTime = (iso) =>
  new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

export const ago = (iso) => {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
};

export const fileName = (p = "") => p.split(/[\\/]/).pop();

export const humanStatus = (s) =>
  ({
    open: "Open",
    awaiting_approval: "Needs your approval",
    contained: "Contained",
    closed: "Closed",
    false_positive: "False positive",
    proposed: "Waiting for approval",
    approved: "Approved, running",
    rejected: "Rejected",
    executed: "Executed, not verified",
    failed: "Failed",
    verified: "Done and verified",
  }[s] || s);

export const actionName = (k) =>
  ({
    suspend_process: "Suspend process",
    quarantine_file: "Quarantine file",
    run_sandbox: "Analyze in sandbox",
    alert: "Raise alert",
    log: "Log only",
  }[k] || k);

export const level = (inc) => inc?.assessment?.level || "low";

export const pendingActions = (incidents) =>
  Object.values(incidents)
    .flatMap((inc) => inc.actions.filter((a) => a.status === "proposed").map((a) => ({ inc, act: a })))
    .sort((a, b) => new Date(b.act.ts) - new Date(a.act.ts));
