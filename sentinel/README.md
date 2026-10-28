# Sentinel

Sentinel is an AI-assisted ransomware detection and response project built around a live monitoring pipeline, decision engine, and response workflow. The system is designed to watch a directory or endpoint for suspicious file activity, classify whether a process is acting like ransomware, and trigger containment or investigation actions under operator approval.

## What this project does

- Watches directories and endpoint activity for abnormal behavior
- Collects process and file evidence from monitored endpoints
- Classifies suspicious activity using heuristic rules and model-based detection
- Exposes a FastAPI backend for incidents, actions, and event streaming
- Provides a React dashboard for monitoring and operator decisions
- Supports simulated lab and evaluation workflows for testing detection logic

## Project status

This repository is a research and prototype project. It includes:

- Contracts and shared schemas
- FastAPI server and API layer
- Lab simulation and mock generation tools
- Endpoint monitoring components
- Detection and analysis modules
- Dashboard frontend
- Evaluation and test harnesses

## Repository layout

- `contracts/` — shared Pydantic models used across the application
- `server/` — FastAPI API, auth, storage, audit log, and event bus
- `endpoint/` — watchers, process inspection, and response logic
- `detection/` — rule-based detection, classification, and model support
- `analyzers/` — entropy and file-analysis helpers
- `lab/` — simulator, demo scripts, mock generation, and evaluation tools
- `dashboard/` — React + Vite web interface
- `tests/` — automated pytest suite
- `data/` — evidence and artifact storage

## Quick start

### 1. Create a virtual environment

```powershell
cd Sentinel\sentinel
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -e ".[dev]"
```

### 3. Run tests

```powershell
pytest
```

### 4. Start the backend

```powershell
$env:SENTINEL_TOKEN = "dev-token"
uvicorn server.main:app --port 8000
```

Then open the API docs at:

- http://127.0.0.1:8000/docs
- WebSocket: `ws://127.0.0.1:8000/ws?token=dev-token`

### 5. Generate mock activity

In a second terminal:

```powershell
python -m lab.mock_generator --url http://127.0.0.1:8000 --token dev-token
```

## End-to-end demo

This project includes a simulated ransomware lab flow suitable for Windows host + isolated Kali VM testing.

```powershell
pip install -e ".[dev,endpoint]"
python -m lab.e2e_demo
```

Manual flow:

```powershell
# 1) Start the server
$env:SENTINEL_TOKEN="dev-token"; uvicorn server.main:app --port 8000

# 2) Start the endpoint monitor (run as Administrator where needed)
$env:SENTINEL_ALLOW_SUSPEND="1"
python -m endpoint.agent --watch C:\SentinelLab\watched --url http://127.0.0.1:8000 --token dev-token

# 3) Seed files and simulate activity
python -m lab.simulator seed --dir C:\SentinelLab\watched --count 80
python -m lab.simulator attack --dir C:\SentinelLab\watched --rate 6
python -m lab.simulator benign --dir C:\SentinelLab\watched --seconds 20
```

After the incident is created, you can approve an action from the API docs and trigger a real containment response through the endpoint agent.

## Dashboard

The frontend is a React + Vite app.

```powershell
cd dashboard
npm install
npm run dev
```

Open the dashboard at:

- http://localhost:5173

The app proxies API calls and WebSocket traffic to the backend. Sign in using the same token configured for `SENTINEL_TOKEN`.

## Safety notes

This project deals with ransomware simulation and endpoint response logic. Use it only in controlled lab environments.

- Use a throwaway directory such as `C:\SentinelLab\watched`
- Keep analysis workloads isolated in a dedicated VM or sandbox
- Take a snapshot before running destructive simulation tasks
- Never run real ransomware samples or sensitive data in this environment

Dangerous features are disabled by default. If you enable response actions, they may suspend or terminate processes depending on your environment.

## Environment variables

- `SENTINEL_TOKEN` — auth token for API and dashboard access
- `SENTINEL_ALLOW_SUSPEND` — enable process suspension behavior
- `SENTINEL_ALLOW_AUTO` — enable auto-response logic
- `VITE_API_TARGET` — optional override for the frontend API target

## License and usage

This project is intended for controlled security research, monitoring, and demonstration use. Review the code and execution environment before running it in any production or sensitive environment.

## Future direction

The project is structured to evolve toward:

- richer behavior-based detection models
- deeper endpoint telemetry collection
- human-in-the-loop response approval
- improved reporting and evidence export
- sandbox and malware analysis integration
