// Thin API client. The token lives in sessionStorage so closing the tab logs you out.
const KEY = "sentinel.token";

export const getToken = () => {
  try { return sessionStorage.getItem(KEY) || localStorage.getItem(KEY) || ""; } catch { return ""; }
};
export const setToken = (t) => {
  try {
    if (t) {
      sessionStorage.setItem(KEY, t);
      localStorage.setItem(KEY, t);
    } else {
      sessionStorage.removeItem(KEY);
      localStorage.removeItem(KEY);
    }
  } catch { /* storage blocked */ }
};

export class AuthError extends Error {}

export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) throw new AuthError("Token rejected");
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch { /* not json */ }
    throw new Error(msg);
  }
  return res.json();
}

export async function downloadEvidence(incidentId) {
  const token = getToken();
  const res = await fetch(`/api/incidents/${incidentId}/evidence`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to download evidence package");
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `evidence_${incidentId}.zip`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export async function downloadYara(incidentId) {
  const token = getToken();
  const res = await fetch(`/api/incidents/${incidentId}/yara`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to download YARA rule");
  const text = await res.text();
  const blob = new Blob([text], { type: "text/plain" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ransomware_${incidentId}.yar`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export async function downloadStix(incidentId) {
  const token = getToken();
  const res = await fetch(`/api/incidents/${incidentId}/stix`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to download STIX 2.1 bundle");
  const text = await res.text();
  const blob = new Blob([text], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `stix_bundle_${incidentId}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export async function downloadReport(incidentId) {
  const token = getToken();
  const res = await fetch(`/api/incidents/${incidentId}/report`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to download executive report");
  const text = await res.text();
  const blob = new Blob([text], { type: "text/markdown" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel_report_${incidentId}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export function openSocket(onMessage, onState) {
  let ws, closed = false, retry = 1000;
  const connect = () => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(getToken())}`);
    ws.onopen = () => { retry = 1000; onState(true); };
    ws.onmessage = (m) => { try { onMessage(JSON.parse(m.data)); } catch { /* ignore */ } };
    ws.onclose = () => {
      onState(false);
      if (!closed) setTimeout(connect, (retry = Math.min(retry * 1.7, 8000)));
    };
  };
  connect();
  return () => { closed = true; ws && ws.close(); };
}
