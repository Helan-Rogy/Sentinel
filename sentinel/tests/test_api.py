import pytest
from fastapi.testclient import TestClient

from lab.mock_generator import attack_incident, benign_event
from server.app import create_app
from server.config import Settings

H = {"Authorization": "Bearer t0k"}


@pytest.fixture()
def client(tmp_path):
    app = create_app(Settings(db_path=str(tmp_path / "t.db"), token="t0k"))
    return TestClient(app)


def test_auth_required(client):
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/events", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/health").status_code == 200


def test_event_roundtrip(client):
    e = benign_event()
    assert client.post("/api/events", content=e.model_dump_json(),
                       headers={**H, "Content-Type": "application/json"}).status_code == 200
    got = client.get("/api/events", headers=H).json()
    assert got[0]["id"] == e.id


def test_invalid_event_rejected(client):
    r = client.post("/api/events", json={"op": "explode", "path": "x"}, headers=H)
    assert r.status_code == 422


def test_incident_approval_flow(client):
    inc = attack_incident()
    client.post("/api/incidents", content=inc.model_dump_json(),
                headers={**H, "Content-Type": "application/json"})
    act = inc.actions[0]
    assert client.get("/api/stats", headers=H).json()["pending_approvals"] == 1

    r = client.post(f"/api/incidents/{inc.id}/actions/{act.id}/approve", headers=H)
    assert r.status_code == 200
    assert r.json()["actions"][0]["status"] == "approved"
    # cannot decide twice
    assert client.post(f"/api/incidents/{inc.id}/actions/{act.id}/reject",
                       headers=H).status_code == 409

    res = {"action_id": act.id, "success": True, "verified": True, "detail": "suspended"}
    assert client.post(f"/api/incidents/{inc.id}/results", json=res, headers=H).status_code == 200
    final = client.get(f"/api/incidents/{inc.id}", headers=H).json()
    assert final["status"] == "contained"
    assert final["actions"][0]["status"] == "verified"

    actions = [a["action"] for a in client.get("/api/audit", headers=H).json()]
    assert "action.approve" in actions and "action.result" in actions


def test_mark_false_positive(client):
    inc = attack_incident()
    client.post("/api/incidents", content=inc.model_dump_json(),
                headers={**H, "Content-Type": "application/json"})
    r = client.post(f"/api/incidents/{inc.id}/status", json={"status": "false_positive"}, headers=H)
    assert r.json()["status"] == "false_positive"
    assert client.post(f"/api/incidents/{inc.id}/status", json={"status": "contained"},
                       headers=H).status_code == 422
    assert client.post("/api/incidents/nope/status", json={"status": "closed"},
                       headers=H).status_code == 404


def test_websocket_stream(client):
    with client.websocket_connect("/ws?token=t0k") as ws:
        e = benign_event()
        client.post("/api/events", content=e.model_dump_json(),
                    headers={**H, "Content-Type": "application/json"})
        msg = ws.receive_json()
        assert msg["topic"] == "event" and msg["data"]["id"] == e.id


def test_websocket_rejects_bad_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=bad"):
            pass
