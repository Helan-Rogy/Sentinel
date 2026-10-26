"""Tests for Priority 4: YARA rule generation, STIX 2.1 export, Killswitch Mutexes, and Reports."""
from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from contracts import ActionKind, Incident, IncidentStatus, ProposedAction, RiskAssessment, RiskLevel
from detection.yara_gen import generate_yara_rule
from endpoint.killswitch import KillSwitchManager
from export.report_gen import generate_markdown_report
from export.stix_export import export_stix_bundle
from server.app import create_app
from server.config import Settings
from server.db import Store


def test_yara_rule_generation():
    inc = Incident(
        id="inc_yara_test_01",
        title="LockBit Outbreak",
        status=IncidentStatus.OPEN,
        process_name="lockbit_payload.exe",
        pid=7777,
        assessment=RiskAssessment(level=RiskLevel.CRITICAL, score=0.96, summary="CRITICAL: encryption burst"),
    )
    rule = generate_yara_rule(inc)
    assert "rule Ransomware_inc_yara_test_01" in rule
    assert "lockbit_payload.exe" in rule
    assert "strings:" in rule
    assert "condition:" in rule
    assert "uint16(0) == 0x5a4d" in rule


def test_stix_bundle_export():
    inc = Incident(
        id="inc_stix_test_01",
        title="Ransomware Intercept",
        status=IncidentStatus.CONTAINED,
        process_name="wannacry_sim.exe",
        pid=8888,
        assessment=RiskAssessment(level=RiskLevel.HIGH, score=0.85, summary="HIGH: entropy jump"),
    )
    bundle = export_stix_bundle(inc)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    types = [o["type"] for o in bundle["objects"]]
    assert "malware" in types
    assert "attack-pattern" in types
    assert "indicator" in types
    assert "course-of-action" in types
    assert "report" in types


def test_killswitch_mutexes():
    mgr = KillSwitchManager()
    deployed = mgr.deploy()
    assert len(deployed) > 0
    assert "Global\\MsWinZonesCacheCounterMutexA" in deployed
    status = mgr.status()
    assert status["deployed_count"] > 0
    mgr.release()
    assert len(mgr.active_mutexes) == 0


def test_markdown_report_generation():
    inc = Incident(
        id="inc_report_test_01",
        title="Executive Report Target",
        status=IncidentStatus.CONTAINED,
        process_name="evil_encrypter.exe",
        pid=1234,
        assessment=RiskAssessment(level=RiskLevel.CRITICAL, score=0.98, summary="CRITICAL: decoy touched"),
    )
    md = generate_markdown_report(inc)
    assert "AEGIS SENTINEL // EXECUTIVE FORENSIC INCIDENT REPORT" in md
    assert "evil_encrypter.exe" in md
    assert "Strategic Recommendations" in md


def test_priority4_api_endpoints(tmp_path):
    db_file = str(tmp_path / "sentinel_p4_test.db")
    app = create_app(Settings(db_path=db_file, token="test-token"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    # Inject incident
    inc = Incident(
        id="inc_p4_api_01",
        title="Active Threat",
        status=IncidentStatus.AWAITING_APPROVAL,
        process_name="malware.exe",
        pid=9090,
        assessment=RiskAssessment(level=RiskLevel.HIGH, score=0.88, summary="HIGH threat"),
    )
    Store(db_file).save_incident(inc)

    # 1. YARA export
    yara_resp = client.get("/api/incidents/inc_p4_api_01/yara", headers=headers)
    assert yara_resp.status_code == 200
    assert "rule Ransomware_" in yara_resp.text

    # 2. STIX export
    stix_resp = client.get("/api/incidents/inc_p4_api_01/stix", headers=headers)
    assert stix_resp.status_code == 200
    stix_json = stix_resp.json()
    assert stix_json["type"] == "bundle"

    # 3. Report export
    report_resp = client.get("/api/incidents/inc_p4_api_01/report", headers=headers)
    assert report_resp.status_code == 200
    assert "# AEGIS SENTINEL" in report_resp.text

    # 4. Vaccine status & deploy
    v_status = client.get("/api/vaccine", headers=headers)
    assert v_status.status_code == 200
    v_deploy = client.post("/api/vaccine/deploy", headers=headers)
    assert v_deploy.status_code == 200
    assert v_deploy.json()["ok"] is True
