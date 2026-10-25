"""Endpoint pipeline: watch a folder, analyze changes, score risk, open incidents."""
from __future__ import annotations

import os
import queue
import threading
import time
from collections import deque
from typing import Optional, Protocol

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from analyzers import entropy
from analyzers.honey import HoneyRegistry, norm
from contracts import (
    ActionKind, ActionStatus, AgentStep, FileEvent, FileOp, HoneyHit, Incident,
    IncidentStatus, ProposedAction, RiskAssessment, RiskLevel,
)
from detection.rules import RuleConfig, Window, evaluate

from .procinfo import attribute_process

RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


class Sink(Protocol):
    def event(self, e: FileEvent) -> None: ...
    def incident(self, i: Incident) -> None: ...


class _Handler(FileSystemEventHandler):
    def __init__(self, push):
        self.push = push

    def on_created(self, ev):
        if not ev.is_directory:
            self.push(FileEvent(op=FileOp.CREATE, path=ev.src_path))

    def on_modified(self, ev):
        if not ev.is_directory:
            self.push(FileEvent(op=FileOp.MODIFY, path=ev.src_path))

    def on_deleted(self, ev):
        if not ev.is_directory:
            self.push(FileEvent(op=FileOp.DELETE, path=ev.src_path))

    def on_moved(self, ev):
        if not ev.is_directory:
            self.push(FileEvent(op=FileOp.RENAME, path=ev.src_path, new_path=ev.dest_path))


class Pipeline:
    def __init__(self, watch_dir: str, sink: Sink, honey_count: int = 3,
                 rules: Optional[RuleConfig] = None, window_s: float = 10.0,
                 quiet_s: float = 15.0, ignore_pids: tuple[int, ...] = ()):
        self.root = os.path.abspath(watch_dir)
        self.sink, self.rules = sink, rules or RuleConfig()
        self.window_s, self.quiet_s, self.ignore_pids = window_s, quiet_s, ignore_pids
        self.honey = HoneyRegistry()
        self.honey_count = honey_count
        self.q: queue.Queue[FileEvent] = queue.Queue()
        self.baseline: dict[str, float] = {}
        self.events: deque[tuple[float, FileEvent]] = deque()
        self.ent: dict[str, tuple[float, entropy.EntropyResult]] = {}
        self.hits: list[tuple[float, HoneyHit]] = []
        self.mod_times: deque[float] = deque(maxlen=20000)
        self.suspicious_times: deque[float] = deque(maxlen=20000)  # encryption-like writes only
        self.active: Optional[Incident] = None
        self.last_hot = 0.0
        self.last_post = 0.0
        self.last_assessment: Optional[RiskAssessment] = None
        self._stop = threading.Event()
        self._obs: Optional[Observer] = None
        self._thread: Optional[threading.Thread] = None
        self.stats = {"events": 0, "analyzed": 0}

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        os.makedirs(self.root, exist_ok=True)
        self.honey.deploy(self.root, self.honey_count)
        n = 0
        for r, _, fs in os.walk(self.root):
            for f in fs:
                if n >= 3000:
                    break
                res = entropy.analyze(os.path.join(r, f))
                if res:
                    self.baseline[norm(res.path)] = res.shannon
                    n += 1
        self._obs = Observer()
        self._obs.schedule(_Handler(self.q.put), self.root, recursive=True)
        self._obs.start()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._obs:
            self._obs.stop()
            self._obs.join(timeout=3)
        if self._thread:
            self._thread.join(timeout=3)

    def mod_count_since(self, t: float) -> int:
        return sum(1 for x in list(self.mod_times) if x >= t)

    def suspicious_count_since(self, t: float) -> int:
        """Encryption-like writes (entropy jump or broken file type) after time t."""
        return sum(1 for x in list(self.suspicious_times) if x >= t)

    # -- processing ------------------------------------------------------------
    def _loop(self) -> None:
        last_tick = 0.0
        while not self._stop.is_set():
            try:
                self._handle(self.q.get(timeout=0.2))
            except queue.Empty:
                pass
            except Exception as e:  # never let one bad file kill monitoring
                print(f"[pipeline] error: {e}", flush=True)
            if time.time() - last_tick >= 1.0:
                last_tick = time.time()
                try:
                    self._tick()
                except Exception as e:
                    print(f"[pipeline] tick error: {e}", flush=True)

    def _handle(self, ev: FileEvent) -> None:
        now = time.time()
        self.stats["events"] += 1
        target = ev.new_path or ev.path
        prev = self.baseline.get(norm(ev.path))

        if ev.op == FileOp.RENAME:
            if self.honey.is_honey(ev.path):
                self._hit(now, ev)
                self.honey.rename(ev.path, ev.new_path)
            self.baseline.pop(norm(ev.path), None)
            self.ent.pop(ev.path, None)  # same file, new name: do not double count
        elif ev.op in (FileOp.MODIFY, FileOp.DELETE) and self.honey.is_honey(ev.path):
            self._hit(now, ev)

        if ev.op in (FileOp.MODIFY, FileOp.RENAME):
            self.mod_times.append(now)
        self.events.append((now, ev))

        if ev.op != FileOp.DELETE:
            res = entropy.analyze(target, prev)
            if res:
                self.stats["analyzed"] += 1
                self.ent[target] = (now, res)
                is_jump = res.delta is not None and res.delta >= self.rules.entropy_delta
                if (is_jump and res.shannon >= self.rules.entropy_floor) or res.type_mismatch:
                    self.suspicious_times.append(now)
                # keep the old baseline while a jump is in progress so repeat events still show it
                self.baseline[norm(target)] = prev if (is_jump and prev is not None) else res.shannon
        self.sink.event(ev)

    def _hit(self, now: float, ev: FileEvent) -> None:
        self.hits.append((now, HoneyHit(path=ev.path, op=ev.op)))

    def _prune(self, now: float) -> None:
        cut = now - self.window_s
        while self.events and self.events[0][0] < cut:
            self.events.popleft()
        self.ent = {k: v for k, v in self.ent.items() if v[0] >= cut}
        self.hits = [h for h in self.hits if h[0] >= cut]

    def _tick(self) -> None:
        now = time.time()
        self._prune(now)
        w = Window(events=[e for _, e in self.events], entropy=[r for _, r in self.ent.values()],
                   honey=[h for _, h in self.hits], seconds=self.window_s)
        a = evaluate(w, self.rules)
        self.last_assessment = a
        if RANK[a.level] >= RANK[RiskLevel.HIGH]:
            self.last_hot = now
            if self.active is None:
                self._open(a, w)
            elif now - self.last_post >= 2.0:
                self._refresh(a, w)
        elif self.active is not None and now - self.last_hot > self.quiet_s:
            self.active = None

    # -- incidents ---------------------------------------------------------------
    def _evidence(self, inc: Incident, a: RiskAssessment, w: Window) -> None:
        changed = {e.new_path or e.path for e in w.events if e.op in (FileOp.MODIFY, FileOp.RENAME)}
        inc.assessment = a
        inc.affected_files = max(inc.affected_files, len(changed))
        inc.honey_hits = w.honey[-10:]
        ranked = sorted(w.entropy, key=lambda r: (r.delta or 0, r.shannon), reverse=True)
        inc.entropy = ranked[:10]

    def _open(self, a: RiskAssessment, w: Window) -> None:
        proc = attribute_process(self.root, self.ignore_pids)
        steps = [
            AgentStep(kind="observe", text=a.summary),
            AgentStep(kind="tool_call", text="attribute_process", data={"root": self.root}),
            AgentStep(kind="tool_result",
                      text=f"{proc[1]} (pid {proc[0]})" if proc else "no process could be attributed"),
        ]
        if proc:
            action = ProposedAction(kind=ActionKind.SUSPEND_PROCESS, pid=proc[0], target=proc[1],
                                    rationale=a.summary, requires_approval=True)
            steps.append(AgentStep(kind="decision",
                                   text=f"Propose suspending {proc[1]}; human approval required"))
            status = IncidentStatus.AWAITING_APPROVAL
        else:
            action = ProposedAction(kind=ActionKind.ALERT, rationale="Process unknown; alert only",
                                    requires_approval=False, status=ActionStatus.EXECUTED)
            steps.append(AgentStep(kind="decision", text="No process to contain; alert only"))
            status = IncidentStatus.OPEN
            a.uncertainty.append("Process could not be attributed")
        inc = Incident(title=f"Ransomware-like activity{' by ' + proc[1] if proc else ''}",
                       status=status, process_name=proc[1] if proc else None,
                       pid=proc[0] if proc else None, steps=steps, actions=[action])
        self._evidence(inc, a, w)
        self.active, self.last_post = inc, time.time()
        self.sink.incident(inc)

    def _refresh(self, a: RiskAssessment, w: Window) -> None:
        assert self.active is not None
        self._evidence(self.active, a, w)
        self.last_post = time.time()
        self.sink.incident(self.active)
