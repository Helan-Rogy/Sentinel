"""Tests for Priority 3: Sandbox Runner, Evidence Packager, and Dynamic Telemetry APIs."""
from __future__ import annotations

import os
import zipfile
import pytest
from fastapi.testclient import TestClient

from contracts import ActionKind, Incident, IncidentStatus, ProposedAction, RiskAssessment, RiskLevel
from sandbox.backend import StubSandboxBackend, VirtualBoxBackend, get_sandbox_backend
from sandbox.evidence import package_evidence
from server.app import create_app
from server.config import Settings


def test_stub_sandbox_execution():
    backend = StubSandboxBackend()
    report = backend.analyze("C:/samples/wannacry_sim.exe", timeout=60.0)

    assert report.completed is True
    assert report.vm_state == "reverted_to_clean"
    assert report.files_touched > 0
    assert report.files_encrypted_like > 0
    assert ".locked" in report.extensions_changed
    assert len(report.network_connections) > 0
    assert any(conn["port"] == 443 for conn in report.network_connections)
    assert len(report.dropped_files) > 0


def test_vbox_backend_detection():
    vbox = VirtualBoxBackend()
    # Verifies the class initializes cleanly and executes without crashing
    avail = vbox.is_available()
    assert isinstance(avail, bool)


def test_evidence_packager(tmp_path):
    inc = Incident(
        title="Test Ransomware Dossier",
        status=IncidentStatus.AWAITING_APPROVAL,
        process_name="locker_sample.exe",
        pid=4040,
        assessment=RiskAssessment(level=RiskLevel.HIGH, score=0.89, summary="HIGH: entropy_jump"),
        actions=[ProposedAction(kind=ActionKind.SUSPEND_PROCESS, pid=4040, target="locker_sample.exe")],
    )

    zip_path = package_evidence(inc, output_dir=str(tmp_path))
    assert os.path.exists(zip_path)
    assert zip_path.endswith(".zip")

    # Inspect zip contents
    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        assert "incident_dossier.json" in namelist
        assert "entropy_telemetry.csv" in namelist
        assert "canary_tripwires.json" in namelist
        assert "network_connections.json" in namelist
        assert "traffic_capture.pcap" in namelist
        assert "README.txt" in namelist


def test_sandbox_and_evidence_api_endpoints(tmp_path):
    db_file = str(tmp_path / "sentinel_test.db")
    app = create_app(Settings(db_path=db_file, token="test-token"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    # 1. Create an incident via event or direct db injection
    inc = Incident(
        id="inc_sandbox_test_01",
        title="Active Ransomware Outbreak",
        status=IncidentStatus.AWAITING_APPROVAL,
        process_name="ransom_payload.exe",
        pid=5555,
        assessment=RiskAssessment(level=RiskLevel.CRITICAL, score=0.95, summary="CRITICAL: canary touched"),
    )
    # Save via reset / app store
    from server.db import Store
    Store(db_file).save_incident(inc)

    # 2. Trigger Sandbox Detonation via API
    resp = client.post("/api/incidents/inc_sandbox_test_01/sandbox", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["sandbox"] is not None
    assert data["sandbox"]["completed"] is True
    assert data["sandbox"]["vm_state"] == "reverted_to_clean"
    assert len(data["sandbox"]["network_connections"]) > 0

    # 3. Download Evidence Package via API
    dl_resp = client.get("/api/incidents/inc_sandbox_test_01/evidence", headers=headers)
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/zip"
    assert len(dl_resp.content) > 500  # valid zip data
