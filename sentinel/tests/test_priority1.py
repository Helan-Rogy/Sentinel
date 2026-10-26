import pytest
from fastapi.testclient import TestClient

from contracts import FileEvent, FileOp, RiskLevel
from detection.allowlist import Allowlist
from detection.rules import RuleConfig, Window, evaluate
from lab.mock_generator import attack_incident
from server.app import create_app
from server.config import Settings

H = {"Authorization": "Bearer t0k"}


@pytest.fixture()
def client(tmp_path):
    app = create_app(Settings(db_path=str(tmp_path / "t.db"), token="t0k"))
    return TestClient(app)


def test_allowlist_matches_backup_and_zip():
    al = Allowlist()
    assert al.is_allowlisted("7z.exe") is True
    assert al.is_allowlisted("robocopy.exe") is True
    assert al.is_allowlisted("zip.exe") is True
    assert al.is_allowlisted("python.exe", cmdline="python backup_task.py --backup") is True
    assert al.is_allowlisted("evil_locker.exe") is False
    assert al.is_allowlisted("python.exe", cmdline="python simulator.py attack") is False


def test_allowlist_prevents_high_alert():
    # Build a window with rapid events that would normally trigger High
    w = Window(
        events=[FileEvent(op=FileOp.MODIFY, path=f"file_{i}.txt") for i in range(25)],
        seconds=2.0
    )
    # Without allowlist
    unauth_eval = evaluate(w, process_name="untrusted_binary.exe")
    assert unauth_eval.level in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM)

    # With allowlisted backup tool
    allowed_eval = evaluate(w, process_name="robocopy.exe")
    assert allowed_eval.level != RiskLevel.HIGH
    assert allowed_eval.level != RiskLevel.CRITICAL
    assert any("Checked against allowlist" in u for u in allowed_eval.uncertainty)
    assert "[ALLOWLISTED: robocopy.exe]" in allowed_eval.summary


def test_incident_pid_deduplication(client):
    inc1 = attack_incident()
    inc1.pid = 9999
    r1 = client.post("/api/incidents", content=inc1.model_dump_json(),
                     headers={**H, "Content-Type": "application/json"})
    assert r1.status_code == 200

    # Second incident with same PID but different ID
    inc2 = attack_incident()
    inc2.pid = 9999
    r2 = client.post("/api/incidents", content=inc2.model_dump_json(),
                     headers={**H, "Content-Type": "application/json"})
    assert r2.status_code == 200
    assert r2.json()["id"] == inc1.id  # merged into inc1 ID

    # Total incidents must still be 1
    stats = client.get("/api/stats", headers=H).json()
    assert stats["incidents"] == 1


def test_api_reset(client):
    # Seed an incident
    inc = attack_incident()
    client.post("/api/incidents", content=inc.model_dump_json(),
                headers={**H, "Content-Type": "application/json"})
    assert client.get("/api/stats", headers=H).json()["incidents"] == 1

    # Call reset
    r = client.post("/api/reset", headers=H)
    assert r.status_code == 200

    # Verify everything wiped
    stats = client.get("/api/stats", headers=H).json()
    assert stats["incidents"] == 0
    assert stats["events"] == 0
