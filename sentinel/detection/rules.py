"""Rule-based scoring. Explainable: every verdict lists the signals behind it.

Takes only contract objects, so the ML engine can later replace or join it.
Thresholds are configurable and must be tuned with simulator + benign runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from contracts import (
    EntropyResult, FileEvent, FileOp, HoneyHit, RiskAssessment, RiskLevel, Signal,
)


@dataclass
class RuleConfig:
    full_rate: float = 10.0        # files/sec that maxes the rate signal
    entropy_floor: float = 7.5     # "looks encrypted"
    entropy_delta: float = 1.5     # minimum rise vs baseline
    full_entropy_files: int = 10
    full_mismatch_files: int = 5
    full_ext_changes: int = 5
    w_rate: float = 0.30
    w_entropy: float = 0.30
    w_mismatch: float = 0.15
    w_ext: float = 0.10
    w_honey: float = 0.35
    medium: float = 0.30
    high: float = 0.55
    critical: float = 0.85


@dataclass
class Window:
    events: list[FileEvent] = field(default_factory=list)
    entropy: list[EntropyResult] = field(default_factory=list)
    honey: list[HoneyHit] = field(default_factory=list)
    seconds: float = 10.0


def evaluate(w: Window, cfg: RuleConfig | None = None) -> RiskAssessment:
    cfg = cfg or RuleConfig()
    # A file written then renamed is ONE changed file, not two.
    modified = {e.path for e in w.events if e.op == FileOp.MODIFY}
    renamed_src = {e.path for e in w.events if e.op == FileOp.RENAME}
    renamed_dst = {e.new_path for e in w.events if e.op == FileOp.RENAME and e.new_path}
    changed = (modified - renamed_src) | renamed_dst
    rate = len(changed) / max(w.seconds, 1.0)

    latest: dict[str, EntropyResult] = {r.path: r for r in w.entropy}
    jumps = [r for r in latest.values()
             if r.shannon >= cfg.entropy_floor and r.delta is not None and r.delta >= cfg.entropy_delta]
    mismatches = [r for r in latest.values() if r.type_mismatch]
    ext_changes = [e for e in w.events if e.op == FileOp.RENAME and e.new_path
                   and _ext(e.path) != _ext(e.new_path)]
    honey_paths = {h.path for h in w.honey}

    def clip(x: float) -> float:
        return max(0.0, min(1.0, x))

    signals = [
        Signal(name="modification_rate", value=round(rate, 2), weight=cfg.w_rate,
               detail=f"{len(changed)} files changed in {w.seconds:.0f}s window"),
        Signal(name="entropy_jump", value=float(len(jumps)), weight=cfg.w_entropy,
               detail=f"{len(jumps)} files rose to >= {cfg.entropy_floor} entropy"),
        Signal(name="type_mismatch", value=float(len(mismatches)), weight=cfg.w_mismatch,
               detail=f"{len(mismatches)} files no longer match their type"),
        Signal(name="extension_change", value=float(len(ext_changes)), weight=cfg.w_ext,
               detail=f"{len(ext_changes)} files renamed to a new extension"),
        Signal(name="honey_file_touched", value=float(len(honey_paths)), weight=cfg.w_honey,
               detail=f"{len(honey_paths)} decoy files touched"),
    ]
    contrib = [
        clip(rate / cfg.full_rate) * cfg.w_rate,
        clip(len(jumps) / cfg.full_entropy_files) * cfg.w_entropy,
        clip(len(mismatches) / cfg.full_mismatch_files) * cfg.w_mismatch,
        clip(len(ext_changes) / cfg.full_ext_changes) * cfg.w_ext,
        clip(len(honey_paths) / 1.0) * cfg.w_honey,
    ]
    score = round(clip(sum(contrib)), 3)
    level = (RiskLevel.CRITICAL if score >= cfg.critical else RiskLevel.HIGH if score >= cfg.high
             else RiskLevel.MEDIUM if score >= cfg.medium else RiskLevel.LOW)

    active = [s.name for s, c in zip(signals, contrib) if c > 0]
    uncertainty = ["No sandbox report available", "Not checked against an allowlist"]
    if honey_paths and len(active) == 1:
        uncertainty.append("Only a honey-file signal; could be a user mistake")
    summary = (f"{level.value.upper()} ({score:.2f}): " +
               (", ".join(active) if active else "no suspicious signals"))
    return RiskAssessment(level=level, score=score, method="rules", signals=signals,
                          uncertainty=uncertainty, summary=summary)


def _ext(p: str) -> str:
    import os
    return os.path.splitext(p)[1].lower()
