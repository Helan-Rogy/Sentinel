"""Fake event generator. Feeds the API so the dashboard can be built before
any real monitoring exists. Uses only the shared contracts.

Usage:  python -m lab.mock_generator --url http://127.0.0.1:8000 --token dev-token
"""
from __future__ import annotations

import argparse
import random
import time

import httpx

from contracts import (
    ActionKind, AgentStep, EntropyResult, FileEvent, FileOp, HoneyHit, Incident,
    IncidentStatus, ProposedAction, RiskAssessment, RiskLevel, SandboxReport, Signal,
)

DOCS = ["report.docx", "budget.xlsx", "notes.txt", "photo.jpg", "thesis.pdf", "slides.pptx"]
BENIGN = [("chrome.exe", 4120), ("code.exe", 7788), ("7zip.exe", 5310), ("backup.exe", 2201)]


def benign_event(folder: str = r"C:\Users\demo\Documents") -> FileEvent:
    name, pid = random.choice(BENIGN)
    return FileEvent(op=random.choice([FileOp.MODIFY, FileOp.CREATE]),
                     path=f"{folder}\\{random.choice(DOCS)}", pid=pid,
                     process_name=name, size=random.randint(2_000, 900_000))


def attack_incident(level: RiskLevel = RiskLevel.HIGH, folder: str = r"C:\Users\demo\Documents"):
    pid, proc = random.randint(9000, 9999), "locker_sim.exe"
    files = random.randint(40, 220)
    score = {RiskLevel.MEDIUM: 0.55, RiskLevel.HIGH: 0.82, RiskLevel.CRITICAL: 0.95}.get(level, 0.2)
    signals = [
        Signal(name="modification_rate", value=round(files / 4, 1), weight=0.3,
               detail=f"{files} files modified in 4s"),
        Signal(name="entropy_jump", value=round(random.uniform(3.0, 4.5), 2), weight=0.3,
               detail="mean entropy 4.1 to 7.9"),
        Signal(name="honey_file_touched", value=1, weight=0.3, detail="decoy modified"),
        Signal(name="extension_change", value=1, weight=0.1, detail="*.docx to *.locked"),
    ]
    inc = Incident(
        title=f"Ransomware-like activity by {proc}",
        status=IncidentStatus.AWAITING_APPROVAL,
        process_name=proc, pid=pid, affected_files=files,
        assessment=RiskAssessment(level=level, score=score, method="rules", signals=signals,
                                  uncertainty=["No sandbox report yet"],
                                  summary="Burst of encrypt-like writes plus honey-file contact."),
        honey_hits=[HoneyHit(path=f"{folder}\\_budget_2024.xlsx", op=FileOp.MODIFY,
                             pid=pid, process_name=proc)],
        entropy=[EntropyResult(path=f"{folder}\\{random.choice(DOCS)}", shannon=7.92,
                               previous_shannon=4.4, delta=3.52, type_mismatch=True,
                               detail="docx header lost")],
        sandbox=SandboxReport(sample_path=rf"C:\samples\{proc}", backend="stub",
                              files_touched=files, files_encrypted_like=files - 3,
                              extensions_changed=[".locked"], notes="mock report"),
        steps=[
            AgentStep(kind="observe", text="Burst of file modifications detected"),
            AgentStep(kind="tool_call", text="get_process_info", data={"pid": pid}),
            AgentStep(kind="tool_result", text=f"{proc} spawned from Downloads, unsigned"),
            AgentStep(kind="decision", text="Propose suspending process; approval required"),
        ],
        actions=[ProposedAction(kind=ActionKind.SUSPEND_PROCESS, pid=pid, target=proc,
                                rationale="High risk with honey-file contact")],
    )
    return inc


def run(url: str, token: str, rate: float, attack_every: int) -> None:
    h = {"Authorization": f"Bearer {token}"}
    with httpx.Client(base_url=url, headers=h, timeout=5) as c:
        n = 0
        while True:
            c.post("/api/events", content=benign_event().model_dump_json(),
                   headers={**h, "Content-Type": "application/json"})
            n += 1
            if n % attack_every == 0:
                inc = attack_incident(random.choice([RiskLevel.HIGH, RiskLevel.CRITICAL]))
                c.post("/api/incidents", content=inc.model_dump_json(),
                       headers={**h, "Content-Type": "application/json"})
                print("posted incident", inc.id)
            time.sleep(1 / rate)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--token", default="dev-token")
    p.add_argument("--rate", type=float, default=2.0, help="events per second")
    p.add_argument("--attack-every", type=int, default=30)
    a = p.parse_args()
    run(a.url, a.token, a.rate, a.attack_every)
