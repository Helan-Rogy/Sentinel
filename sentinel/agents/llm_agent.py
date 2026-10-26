"""Local LLM Agent for Incident Explanation and Autonomous Synthesis.

Synthesizes rule signals, ML confidence calibration, and process attribution into a clean
three-sentence executive brief for SOC human analysts.
Connects to Ollama running llama3.2 with graceful fallback to the Sentinel Expert Engine.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional, Tuple

from contracts import AgentStep, Incident, RiskAssessment, RiskLevel

OLLAMA_ENDPOINT = os.getenv("SENTINEL_OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("SENTINEL_OLLAMA_MODEL", "llama3.2")


def _query_ollama(prompt: str, timeout: float = 2.0) -> Optional[str]:
    """Attempt fast generation from local Ollama service."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 150,
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_ENDPOINT,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                response_text = body.get("response", "").strip()
                if response_text:
                    return response_text
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        pass
    return None


def _expert_synthesize(
    assessment: RiskAssessment,
    proc_name: Optional[str],
    pid: Optional[int],
    affected_files: int,
) -> str:
    """Deterministic, high-fidelity synthesis conforming to the 3-sentence contract."""
    # Sentence 1: Observation
    signals_present = [s.name for s in assessment.signals if s.value > 0]
    has_entropy = any("entropy" in s or "type_mismatch" in s for s in signals_present)
    has_honey = any("honey" in s for s in signals_present)

    if has_entropy and has_honey:
        s1 = f"Sentinel detected active ransomware-like behavior characterized by rapid file modifications ({affected_files} files), severe entropy increases, and tripwire canary file manipulation."
    elif has_entropy:
        s1 = f"Sentinel observed high-speed file alterations ({affected_files} files) exhibiting entropy inflation and header signature mismatches indicative of mass encryption."
    elif has_honey:
        s1 = f"Sentinel detected unauthorized write access to decoy canary files ({affected_files} files impacted) without widespread baseline encryption."
    else:
        s1 = f"Sentinel observed anomalous file modification activity affecting {affected_files} items within the monitored directory tree."

    # Sentence 2: Attribution
    if proc_name and pid:
        is_allowlisted = any("matches legitimate" in u for u in assessment.uncertainty)
        if is_allowlisted:
            s2 = f"The activity was attributed to legitimate utility '{proc_name}' (PID {pid}), recognized by system allowlists as an authorized workflow."
        else:
            s2 = f"The operations were traced to process '{proc_name}' (PID {pid}), which is unverified and not recognized on the safe workflow allowlist."
    elif proc_name:
        s2 = f"Telemetry correlates the writes with executable '{proc_name}', though direct kernel handle binding could not lock a PID."
    else:
        s2 = "The responsible process could not be definitively attributed before filesystem changes concluded."

    # Sentence 3: Recommendation
    conf_note = next((u for u in assessment.uncertainty if "p(attack)" in u), "")
    triage_needed = any("Triage required" in u for u in assessment.uncertainty)

    if assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and pid and not triage_needed:
        s3 = f"Immediate containment via process suspension is proposed for PID {pid} to safeguard system data, pending human SOC confirmation."
    elif triage_needed and pid:
        s3 = f"Because model confidence is in the triage margin ({conf_note}), routing to SOC human analysis is advised prior to enforcing containment."
    elif assessment.level == RiskLevel.MEDIUM:
        s3 = f"Targeted monitoring and audit logging remain active; manual triage is recommended if unexpected behavior persists."
    else:
        s3 = f"No automated containment action was initiated; telemetry has been indexed for SOC retrospective auditing."

    return f"{s1} {s2} {s3}"


def synthesize_incident(
    incident: Incident,
    proc_info: Optional[Tuple[int, str]] = None,
    timeout: float = 2.0,
) -> Tuple[str, str]:
    """Synthesizes the incident into a 3-sentence executive brief and attaches reasoning step.

    Returns: (three_sentence_brief, engine_used)
    """
    proc_name = incident.process_name or (proc_info[1] if proc_info else None)
    pid = incident.pid or (proc_info[0] if proc_info else None)
    assessment = incident.assessment or RiskAssessment(
        level=RiskLevel.MEDIUM, score=0.5, summary="Incident under analysis"
    )

    # Prepare prompt for Ollama
    signals_summary = ", ".join(f"{s.name}={s.value}" for s in assessment.signals)
    prompt = (
        f"You are Aegis Sentinel, an endpoint defense agent. Synthesize this ransomware incident into EXACTLY 3 sentences for a human SOC analyst:\n"
        f"Sentence 1 (Observation): What occurred ({assessment.summary}, signals: {signals_summary}).\n"
        f"Sentence 2 (Attribution): Who did it (Process: {proc_name or 'Unknown'}, PID: {pid or 'Unknown'}).\n"
        f"Sentence 3 (Recommendation): Recommended SOC response action.\n"
        f"Do not use markdown lists or bullet points; output only the 3 sentences."
    )

    ollama_resp = _query_ollama(prompt, timeout=timeout)
    if ollama_resp and len(ollama_resp.split(".")) >= 3:
        brief = ollama_resp.strip()
        engine = f"ollama_{OLLAMA_MODEL}"
    else:
        brief = _expert_synthesize(
            assessment, proc_name, pid, incident.affected_files
        )
        engine = "sentinel_expert"

    # Attach explanation step to incident steps
    incident.steps.append(
        AgentStep(
            kind="reasoning",
            text=brief,
            data={"engine": engine, "model": OLLAMA_MODEL if "ollama" in engine else "deterministic_expert"},
        )
    )

    return brief, engine
