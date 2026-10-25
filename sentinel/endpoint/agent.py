"""Endpoint agent: runs the pipeline, ships data to the server, and executes ONLY
actions a human approved on the dashboard (after policy validation and with verification).

  python -m endpoint.agent --watch C:\\SentinelLab\\watched --url http://127.0.0.1:8000 --token dev-token
Set SENTINEL_ALLOW_SUSPEND=1 to let it actually suspend processes (test folder/VM only).
"""
from __future__ import annotations

import argparse
import os
import queue
import threading
import time

import httpx

from contracts import ActionResult, FileEvent, Incident

from .pipeline import Pipeline
from .procinfo import suspend, validate_suspend


class HttpSink:
    """Sends events/incidents to the server from a background thread."""

    def __init__(self, url: str, token: str):
        self.h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.c = httpx.Client(base_url=url, timeout=5)
        self.q: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=5000)
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def event(self, e: FileEvent) -> None:
        self._put(("/api/events", e.model_dump_json()))

    def incident(self, i: Incident) -> None:
        self._put(("/api/incidents", i.model_dump_json()))

    def _put(self, item):
        try:
            self.q.put_nowait(item)
        except queue.Full:
            pass  # drop telemetry rather than block detection

    def _run(self):
        while True:
            path, body = self.q.get()
            try:
                self.c.post(path, content=body, headers=self.h)
            except httpx.HTTPError as e:
                print(f"[sink] server unreachable: {e}", flush=True)
                time.sleep(1)


class Executor:
    def __init__(self, url: str, token: str, pipe: Pipeline, allow_suspend: bool):
        self.h = {"Authorization": f"Bearer {token}"}
        self.c = httpx.Client(base_url=url, timeout=5)
        self.pipe, self.allow = pipe, allow_suspend
        self.done: set[str] = set()

    def poll_once(self) -> None:
        for inc in self.c.get("/api/incidents", headers=self.h).json():
            for a in inc["actions"]:
                if a["kind"] == "suspend_process" and a["status"] == "approved" and a["id"] not in self.done:
                    self.done.add(a["id"])
                    self._suspend(inc["id"], a)

    def _suspend(self, inc_id: str, a: dict) -> None:
        pid, name = a["pid"], a["target"]
        ok, why = validate_suspend(pid, name, self.pipe.root, self.allow)
        if not ok:
            res = ActionResult(action_id=a["id"], success=False, verified=False, detail=f"policy: {why}")
        else:
            t0 = time.time()
            ok, detail = suspend(pid)
            time.sleep(3.5)  # verification window: is the encryption activity really over?
            # Other programs may keep writing files legitimately, so verify on
            # encryption-like activity only, not on every file change.
            still = self.pipe.suspicious_count_since(t0 + 0.8)
            verified = ok and still == 0
            res = ActionResult(action_id=a["id"], success=ok, verified=verified,
                               detail=f"{detail}; {still} encryption-like writes after suspension")
        print(f"[executor] {name} pid={pid}: {res.detail} verified={res.verified}", flush=True)
        self.c.post(f"/api/incidents/{inc_id}/results", content=res.model_dump_json(),
                    headers={**self.h, "Content-Type": "application/json"})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", required=True)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--token", default=os.environ.get("SENTINEL_TOKEN", "dev-token"))
    ap.add_argument("--honey", type=int, default=3)
    a = ap.parse_args()
    allow = os.environ.get("SENTINEL_ALLOW_SUSPEND", "0") == "1"
    pipe = Pipeline(a.watch, HttpSink(a.url, a.token), honey_count=a.honey)
    pipe.start()
    ex = Executor(a.url, a.token, pipe, allow)
    print(f"[agent] watching {pipe.root} | suspend {'ENABLED' if allow else 'disabled'}", flush=True)
    try:
        while True:
            try:
                ex.poll_once()
            except httpx.HTTPError as e:
                print(f"[agent] poll failed: {e}", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        pipe.stop()


if __name__ == "__main__":
    main()
