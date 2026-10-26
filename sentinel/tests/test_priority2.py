"""Tests for Priority 2: ML Classifier, Platt Confidence Calibration, and Local LLM Agent."""
from __future__ import annotations

import os
import pytest

from agents.llm_agent import synthesize_incident, _expert_synthesize
from contracts import (
    ActionKind, ActionStatus, FileEvent, FileOp, HoneyHit, Incident,
    IncidentStatus, ProposedAction, RiskAssessment, RiskLevel, Signal,
)
from detection.classifier import (
    RansomwareClassifier, extract_features, get_classifier,
)
from detection.rules import RuleConfig, Window, evaluate


def test_classifier_discrimination():
    clf = get_classifier()

    # Extreme attack profile: rapid writes, 10 entropy jumps, high entropy, decoy file hit
    attack_feat = [15.0, 10.0, 7.95, 3.8, 3.0, 8.0, 8.0]
    p_attack, margin = clf.predict_proba(attack_feat)
    assert p_attack >= 0.85, f"expected high attack probability, got {p_attack}"
    assert margin <= 0.10, f"expected low margin, got {margin}"

    # Benign profile: slow writes, no jumps, normal entropy, no decoys
    benign_feat = [0.5, 0.0, 4.2, 0.0, 0.0, 0.0, 0.0]
    p_benign, margin_b = clf.predict_proba(benign_feat)
    assert p_benign <= 0.20, f"expected low attack probability, got {p_benign}"


def test_confidence_calibration_and_triage_policy():
    clf = RansomwareClassifier()

    # Ambiguous profile: moderate rate, single jump, no decoys
    ambiguous_feat = [3.5, 1.0, 6.2, 1.5, 0.0, 1.0, 1.0]
    level, p, margin, conf_str, triage_needed = clf.evaluate_risk(ambiguous_feat)

    assert "p(attack) =" in conf_str
    assert "+/-" in conf_str
    # Ambiguous confidence requires human triage
    if 0.35 <= p < 0.70:
        assert triage_needed is True


def test_hybrid_rule_ml_scoring():
    w = Window(
        events=[
            FileEvent(op=FileOp.MODIFY, path="C:/test/file1.txt"),
            FileEvent(op=FileOp.RENAME, path="C:/test/file1.txt", new_path="C:/test/file1.txt.locked"),
        ],
        entropy=[],
        honey=[HoneyHit(path="C:/test/_decoy.txt", op=FileOp.MODIFY)],
        seconds=5.0,
    )
    a = evaluate(w, RuleConfig(), process_name="unknown_malware.exe")
    assert a.method == "hybrid"
    assert any("ml_classifier_confidence" in s.name for s in a.signals)
    assert any("Confidence: p(attack) =" in u for u in a.uncertainty)


def test_local_llm_agent_synthesis():
    inc = Incident(
        title="Test Incident",
        status=IncidentStatus.AWAITING_APPROVAL,
        process_name="evil_locker.exe",
        pid=9999,
        affected_files=24,
        assessment=RiskAssessment(
            level=RiskLevel.HIGH,
            score=0.88,
            signals=[
                Signal(name="entropy_jump", value=12.0),
                Signal(name="honey_file_touched", value=2.0),
            ],
            uncertainty=["No sandbox report available", "Confidence: p(attack) = 0.94 +/- 0.03"],
            summary="HIGH (0.88): entropy_jump, honey_file_touched",
        ),
    )

    brief, engine = synthesize_incident(inc, (9999, "evil_locker.exe"), timeout=0.1)

    assert len(brief.split(".")) >= 3, "must be at least 3 sentences"
    assert "evil_locker.exe" in brief or "9999" in brief
    assert any(s.kind == "reasoning" for s in inc.steps), "should attach a reasoning AgentStep"
    assert engine in ("sentinel_expert", "ollama_llama3.2")
