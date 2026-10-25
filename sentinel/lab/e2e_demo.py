"""End-to-end check: server + agent + simulator, then approve the suspension and verify it.
Runs everything in a temp folder. Usage:  python -m lab.e2e_demo
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time

import httpx

PORT, TOKEN = 8766, "e2e-token"
H = {"Authorization": f"Bearer {TOKEN}"}


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="sentinel_e2e_")
    watched = os.path.join(tmp, "watched")
    env = {**os.environ, "SENTINEL_DB": os.path.join(tmp, "e2e.db"), "SENTINEL_TOKEN": TOKEN,
           "SENTINEL_ALLOW_SUSPEND": "1"}
    py = sys.executable
    procs = []

    def spawn(*args, name):
        log = open(os.path.join(tmp, f"{name}.log"), "w")
        p = subprocess.Popen([py, *args], env=env, stdout=log, stderr=subprocess.STDOUT)
        procs.append(p)
        return p

    try:
        subprocess.run([py, "-m", "lab.simulator", "seed", "--dir", watched, "--count", "80"],
                       check=True, capture_output=True)
        spawn("-m", "uvicorn", "server.main:app", "--port", str(PORT), name="server")
        time.sleep(2)
        base = f"http://127.0.0.1:{PORT}"
        spawn("-m", "endpoint.agent", "--watch", watched, "--url", base, "--token", TOKEN, name="agent")
        time.sleep(3)
        t0 = time.time()
        sim = spawn("-m", "lab.simulator", "attack", "--dir", watched, "--rate", "6", name="sim")

        inc = None
        while time.time() - t0 < 25 and not inc:
            r = httpx.get(f"{base}/api/incidents", headers=H).json()
            inc = r[0] if r else None
            time.sleep(0.3)
        if not inc:
            print("FAIL: no incident raised"); return 1
        print(f"alert after {time.time() - t0:.1f}s: {inc['assessment']['summary']}")
        print(f"attributed pid {inc['pid']} (simulator pid {sim.pid})")

        act = inc["actions"][0]
        httpx.post(f"{base}/api/incidents/{inc['id']}/actions/{act['id']}/approve", headers=H)
        final = None
        for _ in range(30):
            final = httpx.get(f"{base}/api/incidents/{inc['id']}", headers=H).json()
            if final["results"]:
                break
            time.sleep(0.5)
        res = final["results"][0] if final["results"] else None
        print("result:", res)
        print("incident status:", final["status"], "| action status:", final["actions"][0]["status"])
        ok = bool(res and res["success"] and res["verified"] and final["status"] == "contained")
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        for p in procs:
            p.kill()
        print("logs in", tmp)


if __name__ == "__main__":
    sys.exit(main())
