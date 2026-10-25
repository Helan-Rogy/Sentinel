# Sentinel

AI-powered ransomware detection and response agent (project build).
Status: **Day 1** — contracts, API, live stream, mock generator.

## Lab setup (Windows host + Kali VM)

- **Windows host** runs the server, dashboard, endpoint monitor, and the simulator against a
  throwaway folder such as `C:\SentinelLab\watched`.
- **Kali VM** is the isolated analysis sandbox (Day 5). Use a host-only network, take a snapshot
  before every run, and never copy real ransomware anywhere. Only the project simulator is used.

## Run (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest

$env:SENTINEL_TOKEN = "dev-token"
uvicorn server.main:app --port 8000
# second terminal
python -m lab.mock_generator --url http://127.0.0.1:8000 --token dev-token
```

Open http://127.0.0.1:8000/docs for the API. WebSocket: `ws://127.0.0.1:8000/ws?token=dev-token`.

## Backend demo (Windows, three PowerShell windows, venv active in each)

```powershell
pip install -e ".[dev,endpoint]"
python -m lab.e2e_demo                      # one-shot automated check, prints PASS/FAIL

# Manual version
# 1) server
$env:SENTINEL_TOKEN="dev-token"; uvicorn server.main:app --port 8000
# 2) agent (run as Administrator to allow suspend)
$env:SENTINEL_ALLOW_SUSPEND="1"
python -m endpoint.agent --watch C:\SentinelLab\watched --url http://127.0.0.1:8000 --token dev-token
# 3) lab: create dummy files, then attack
python -m lab.simulator seed   --dir C:\SentinelLab\watched --count 80
python -m lab.simulator attack --dir C:\SentinelLab\watched --rate 6
python -m lab.simulator benign --dir C:\SentinelLab\watched --seconds 20   # false-positive test
```

Then open http://127.0.0.1:8000/docs, authorize with the token, and call
`POST /api/incidents/{id}/actions/{action_id}/approve`. The agent suspends the process and verifies.

## Dashboard (React + Vite)

```powershell
cd dashboard
npm install
npm run dev            # http://localhost:5173, proxies /api and /ws to http://127.0.0.1:8000
```

Sign in with the value of `SENTINEL_TOKEN`. To point at another server:
`$env:VITE_API_TARGET="http://192.168.56.1:8000"; npm run dev`.
Views: Overview (live trace and approvals), Live, Incidents (evidence), Agent, Response, Reports.

## Layout

| Path | Purpose |
|---|---|
| `contracts/` | Pydantic schemas shared by every domain |
| `server/` | FastAPI, SQLite storage, auth, audit log, event bus |
| `lab/` | Mock generator now; simulator and benign workloads later |
| `tests/` | pytest suite |

Dangerous features are off by default: `SENTINEL_ALLOW_SUSPEND=1`, `SENTINEL_ALLOW_AUTO=1`.
