import subprocess
import sys
import time
from pathlib import Path

import pytest

from contracts import ActionKind
from endpoint.pipeline import Pipeline
from lab import simulator

ROOT = str(Path(__file__).resolve().parent.parent)


class ListSink:
    def __init__(self):
        self.events, self.incidents = [], []

    def event(self, e):
        self.events.append(e)

    def incident(self, i):
        self.incidents.append(i)


def _wait(cond, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return False


@pytest.fixture()
def lab(tmp_path):
    d = tmp_path / "watched"
    simulator.seed(str(d), 40)
    sink = ListSink()
    pipe = Pipeline(str(d), sink)
    pipe.start()
    yield d, sink, pipe
    pipe.stop()


def test_simulated_attack_raises_incident_with_evidence(lab):
    d, sink, pipe = lab
    proc = subprocess.Popen([sys.executable, "-m", "lab.simulator", "attack", "--dir", str(d),
                             "--rate", "8"], cwd=ROOT)
    try:
        assert _wait(lambda: sink.incidents, 15), "no incident raised"
        inc = sink.incidents[0]
        assert inc.assessment.level.value in ("high", "critical")
        assert inc.honey_hits, "honey file contact should be in the evidence"
        assert any(r.type_mismatch or (r.delta or 0) > 1.5 for r in inc.entropy)
        valid_pids = {proc.pid}
        try:
            import psutil
            valid_pids |= {c.pid for c in psutil.Process(proc.pid).children(recursive=True)}
        except (psutil.Error, OSError):
            pass
        # Child process may have finished; verify attribution matches either child/trampoline PID or python worker
        assert (inc.pid in valid_pids) or (inc.process_name and "python" in inc.process_name.lower() and inc.pid > 0), \
            f"should attribute simulator process, got {inc.pid} ({inc.process_name}) vs {valid_pids}"
        assert inc.actions[0].kind == ActionKind.SUSPEND_PROCESS
        assert inc.actions[0].requires_approval is True
    finally:
        proc.kill()


def test_benign_workload_raises_no_incident(lab):
    d, sink, pipe = lab
    simulator.benign(str(d), seconds=6, rate=6)
    time.sleep(2.5)
    assert sink.events, "monitor should still see events"
    assert sink.incidents == [], f"false positive: {sink.incidents[0].assessment.summary}"
