// Thin API client. The token lives in sessionStorage so closing the tab logs you out.
const KEY = "sentinel.token";

export const getToken = () => {
  try { return sessionStorage.getItem(KEY) || ""; } catch { return ""; }
};
export const setToken = (t) => {
  try { t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY); } catch { /* storage blocked */ }
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
