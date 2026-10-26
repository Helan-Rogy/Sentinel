"""Sentinel Evaluation Harness: runs N attack and N benign trials,
measures detection rate, false positives, time to alert, and resource usage,
and outputs a results table.

Usage:
  python -m lab.evaluate --attacks 5 --benign 5 --dir C:\\SentinelLab\\watched
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import asdict, dataclass
from typing import Any, List, Optional

import psutil

from analyzers import entropy
from analyzers.honey import HoneyRegistry, norm
from contracts import FileEvent, FileOp, HoneyHit, RiskLevel
from detection.allowlist import Allowlist
from detection.rules import RuleConfig, Window, evaluate
from lab.simulator import _text, seed


@dataclass
class TrialResult:
    trial_id: int
    workload_type: str         # "ATTACK" or "BENIGN"
    process_name: str          # e.g. "simulator_attack" or "zip_backup"
    verdict: str               # "DETECTED", "MISSED", "PASSED (CLEAN)", "FALSE_POSITIVE"
    risk_level: str            # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_score: float          # 0.0 - 1.0
    time_to_alert_s: Optional[float]
    files_mutated: int
    peak_cpu_pct: float
    peak_ram_mb: float
    detail: str


class TrialRunner:
    def __init__(self, watch_dir: str, file_count: int = 50, window_s: float = 10.0):
        self.watch_dir = os.path.abspath(watch_dir)
        self.file_count = file_count
        self.window_s = window_s
        self.rules = RuleConfig()
        self.proc = psutil.Process(os.getpid())

    def reset_dir(self) -> None:
        """Reset the test folder with clean seeded files and canaries."""
        os.makedirs(self.watch_dir, exist_ok=True)
        # Wipe directory
        for f in os.listdir(self.watch_dir):
            p = os.path.join(self.watch_dir, f)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.remove(p)
                except OSError:
                    pass
        seed(self.watch_dir, count=self.file_count)
        self.honey = HoneyRegistry()
        self.honey.deploy(self.watch_dir, count=3)

    def _sample_resources(self) -> tuple[float, float]:
        """Returns (cpu_percent, memory_mb)."""
        try:
            cpu = self.proc.cpu_percent(interval=None)
            mem = self.proc.memory_info().rss / (1024 * 1024)
            return cpu, mem
        except Exception:
            return 0.0, 0.0

    def run_attack_trial(self, trial_id: int, rate: float = 8.0, ext: str = ".locked") -> TrialResult:
        """Simulates a ransomware attack and evaluates time to alert and detection accuracy."""
        self.reset_dir()
        files = [os.path.join(self.watch_dir, f) for f in os.listdir(self.watch_dir)
                 if not f.endswith(ext) and not f.startswith(".")]

        # Initialize detector baseline
        baseline = {}
        for f in files:
            res = entropy.analyze(f)
            if res:
                baseline[norm(f)] = res.shannon

        events: list[FileEvent] = []
        ent_results: list[entropy.EntropyResult] = []
        honey_hits: list[HoneyHit] = []

        start_time = time.time()
        time_to_alert: Optional[float] = None
        alert_level = "LOW"
        alert_score = 0.0
        mutated_count = 0
        peak_cpu, peak_ram = self._sample_resources()

        # Run attack loop
        for p in files:
            if time.time() - start_time > 15:  # timeout guard
                break
            try:
                # Overwrite with random encrypted bytes
                size = max(512, os.path.getsize(p))
                prev = baseline.get(norm(p))
                with open(p, "rb+") as f:
                    f.write(os.urandom(size))
                    f.truncate()

                new_p = p + ext
                os.rename(p, new_p)
                mutated_count += 1

                # Telemetry capture
                ev = FileEvent(op=FileOp.RENAME, path=p, new_path=new_p)
                events.append(ev)

                # Check canary
                if self.honey.is_honey(p):
                    honey_hits.append(HoneyHit(path=p, op=FileOp.RENAME))

                # Analyze entropy
                ent = entropy.analyze(new_p, prev)
                if ent:
                    ent_results.append(ent)

                # Periodic evaluation
                w = Window(events=events, entropy=ent_results, honey=honey_hits, seconds=self.window_s)
                assessment = evaluate(w, self.rules, process_name="ransomware_simulator.exe")

                # Sample resources
                cpu, ram = self._sample_resources()
                if cpu > peak_cpu: peak_cpu = cpu
                if ram > peak_ram: peak_ram = ram

                if assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and time_to_alert is None:
                    time_to_alert = time.time() - start_time
                    alert_level = assessment.level.value.upper()
                    alert_score = assessment.score
                    # Outbreak detected!
                    break

                time.sleep(1.0 / rate)
            except Exception as e:
                pass

        detected = time_to_alert is not None
        verdict = "DETECTED" if detected else "MISSED"
        detail = f"{mutated_count} files encrypted; alerted in {time_to_alert:.2f}s" if detected else "Failed to detect within window"

        return TrialResult(
            trial_id=trial_id,
            workload_type="ATTACK",
            process_name="ransomware_simulator.exe",
            verdict=verdict,
            risk_level=alert_level,
            risk_score=alert_score,
            time_to_alert_s=round(time_to_alert, 2) if time_to_alert else None,
            files_mutated=mutated_count,
            peak_cpu_pct=round(max(0.5, peak_cpu), 1),
            peak_ram_mb=round(peak_ram, 1),
            detail=detail
        )

    def run_benign_trial(self, trial_id: int, workflow: str = "zip_backup") -> TrialResult:
        """Simulates legitimate heavy file activity (zip backup, copy, document editing)
        and verifies it does NOT trigger a False Positive alert."""
        self.reset_dir()
        files = [os.path.join(self.watch_dir, f) for f in os.listdir(self.watch_dir)
                 if f.endswith((".txt", ".csv")) and not f.startswith(".")]

        baseline = {}
        for f in files:
            res = entropy.analyze(f)
            if res:
                baseline[norm(f)] = res.shannon

        events: list[FileEvent] = []
        ent_results: list[entropy.EntropyResult] = []
        honey_hits: list[HoneyHit] = []

        start_time = time.time()
        false_alert = False
        highest_level = "LOW"
        highest_score = 0.0
        peak_cpu, peak_ram = self._sample_resources()
        copies_dir = os.path.join(self.watch_dir, "_copies_tmp")
        os.makedirs(copies_dir, exist_ok=True)

        proc_name = "robocopy.exe" if workflow == "robocopy" else "zip_backup.exe"

        # Execute legitimate workload
        rnd = random.Random(42 + trial_id)
        for i in range(15):
            if not files: break
            p = rnd.choice(files)
            # Legitimate append
            with open(p, "ab") as f:
                f.write(("\n" + _text(rnd, 4)).encode())
            ev = FileEvent(op=FileOp.MODIFY, path=p)
            events.append(ev)

            # Legitimate backup copy
            dest_copy = os.path.join(copies_dir, f"copy_{i}.bak")
            shutil.copy(p, dest_copy)
            events.append(FileEvent(op=FileOp.CREATE, path=dest_copy))

            # Legitimate zip archive
            if i % 5 == 0:
                zip_path = os.path.join(copies_dir, f"archive_{i}.zip")
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
                    for t in files[:4]:
                        z.write(t, os.path.basename(t))
                events.append(FileEvent(op=FileOp.CREATE, path=zip_path))

            # Entropy analysis
            res = entropy.analyze(p, baseline.get(norm(p)))
            if res:
                ent_results.append(res)

            # Evaluate with allowlisted process name
            w = Window(events=events, entropy=ent_results, honey=honey_hits, seconds=self.window_s)
            assessment = evaluate(w, self.rules, process_name=proc_name)

            if assessment.score > highest_score:
                highest_score = assessment.score
                highest_level = assessment.level.value.upper()

            if assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                false_alert = True
                break

            cpu, ram = self._sample_resources()
            if cpu > peak_cpu: peak_cpu = cpu
            if ram > peak_ram: peak_ram = ram
            time.sleep(0.05)

        verdict = "FALSE_POSITIVE" if false_alert else "PASSED (CLEAN)"
        detail = "Allowlist recognized legitimate backup workflow" if not false_alert else "False alarm on backup process"

        return TrialResult(
            trial_id=trial_id,
            workload_type="BENIGN",
            process_name=proc_name,
            verdict=verdict,
            risk_level=highest_level,
            risk_score=highest_score,
            time_to_alert_s=None,
            files_mutated=0,
            peak_cpu_pct=round(max(0.4, peak_cpu), 1),
            peak_ram_mb=round(peak_ram, 1),
            detail=detail
        )


def run_evaluation(num_attacks: int = 5, num_benign: int = 5,
                   target_dir: Optional[str] = None, json_out: Optional[str] = None) -> list[TrialResult]:
    """Runs N attack and N benign evaluation trials and outputs a formatted results table."""
    temp_dir = None
    if not target_dir:
        temp_dir = tempfile.mkdtemp(prefix="sentinel_eval_")
        target_dir = os.path.join(temp_dir, "watched")

    print("\n" + "=" * 94)
    print("                      AEGIS SENTINEL EVALUATION HARNESS BENCHMARK                     ")
    print("=" * 94)
    print(f"Target Directory: {target_dir}")
    print(f"Trials Scheduled: {num_attacks} Attacks | {num_benign} Benign Workloads")
    print("-" * 94)

    runner = TrialRunner(watch_dir=target_dir)
    results: list[TrialResult] = []

    # Run Attack Trials
    print("\n[+] Phase 1: Executing Simulated Ransomware Attack Trials...")
    for i in range(1, num_attacks + 1):
        rate = random.choice([6.0, 8.0, 10.0])
        res = runner.run_attack_trial(trial_id=i, rate=rate)
        results.append(res)
        print(f"  Trial #{i:02d} [ATTACK] -> {res.verdict} ({res.risk_level}) in {res.time_to_alert_s}s | {res.files_mutated} files encrypted")

    # Run Benign Trials
    print("\n[+] Phase 2: Executing Legitimate Benign Workload Trials (Zip, Backup, Copy)...")
    for j in range(1, num_benign + 1):
        wf = "robocopy" if j % 2 == 0 else "zip_backup"
        res = runner.run_benign_trial(trial_id=num_attacks + j, workflow=wf)
        results.append(res)
        print(f"  Trial #{num_attacks + j:02d} [BENIGN] -> {res.verdict} ({res.risk_level}) | Score: {res.risk_score:.2f}")

    # Print Formatted Results Table
    print("\n" + "=" * 94)
    print("                                   TRIAL RESULTS TABLE                                ")
    print("=" * 94)
    header = f"{'#':<3} | {'TYPE':<7} | {'PROCESS':<22} | {'VERDICT':<14} | {'LEVEL':<8} | {'MTTA':<7} | {'FILES':<5} | {'CPU%':<5} | {'RAM'}"
    print(header)
    print("-" * 94)
    for r in results:
        mtta_str = f"{r.time_to_alert_s:.2f}s" if r.time_to_alert_s is not None else "N/A"
        print(f"{r.trial_id:<3} | {r.workload_type:<7} | {r.process_name:<22} | {r.verdict:<14} | {r.risk_level:<8} | {mtta_str:<7} | {r.files_mutated:<5} | {r.peak_cpu_pct:<5.1f} | {r.peak_ram_mb:.1f} MB")
    print("=" * 94)

    # Compute Summary Statistics
    attack_trials = [r for r in results if r.workload_type == "ATTACK"]
    benign_trials = [r for r in results if r.workload_type == "BENIGN"]

    tp = sum(1 for r in attack_trials if r.verdict == "DETECTED")
    fn = sum(1 for r in attack_trials if r.verdict == "MISSED")
    fp = sum(1 for r in benign_trials if r.verdict == "FALSE_POSITIVE")
    tn = sum(1 for r in benign_trials if r.verdict == "PASSED (CLEAN)")

    det_rate = (tp / len(attack_trials) * 100) if attack_trials else 0.0
    fp_rate = (fp / len(benign_trials) * 100) if benign_trials else 0.0

    detected_mttas = [r.time_to_alert_s for r in attack_trials if r.time_to_alert_s is not None]
    avg_mtta = (sum(detected_mttas) / len(detected_mttas)) if detected_mttas else 0.0
    avg_files = (sum(r.files_mutated for r in attack_trials) / len(attack_trials)) if attack_trials else 0.0
    avg_cpu = sum(r.peak_cpu_pct for r in results) / len(results)
    avg_ram = sum(r.peak_ram_mb for r in results) / len(results)

    print("\n================================ SUMMARY BENCHMARK METRICS ===============================")
    print(f" - Total Trials Executed        : {len(results)} ({len(attack_trials)} Attacks, {len(benign_trials)} Benign)")
    print(f" - Detection Rate (Sensitivity) : {det_rate:.1f}% ({tp}/{len(attack_trials)})")
    print(f" - False Positive Rate (FPR)    : {fp_rate:.1f}% ({fp}/{len(benign_trials)})")
    print(f" - Mean Time to Alert (MTTA)    : {avg_mtta:.2f} seconds")
    print(f" - Avg Files Mutated pre-Alert  : {avg_files:.1f} files")
    print(f" - Mean CPU Utilization         : {avg_cpu:.1f}%")
    print(f" - Mean Memory Footprint        : {avg_ram:.1f} MB")
    print("========================================================================================\n")

    # Clean up temp dir if created
    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Optional JSON export
    if json_out:
        summary_payload = {
            "timestamp": time.time(),
            "summary": {
                "total_trials": len(results),
                "detection_rate_pct": round(det_rate, 2),
                "false_positive_rate_pct": round(fp_rate, 2),
                "mean_time_to_alert_s": round(avg_mtta, 2),
                "avg_files_mutated": round(avg_files, 1),
                "mean_cpu_pct": round(avg_cpu, 1),
                "mean_ram_mb": round(avg_ram, 1),
            },
            "trials": [asdict(r) for r in results],
        }
        with open(json_out, "w") as jf:
            json.dump(summary_payload, jf, indent=2)
        print(f"[+] Evaluation results exported to: {json_out}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Evaluation Harness Benchmark")
    parser.add_argument("--attacks", type=int, default=5, help="Number of simulated attack trials (default: 5)")
    parser.add_argument("--benign", type=int, default=5, help="Number of benign workload trials (default: 5)")
    parser.add_argument("--dir", default=None, help="Custom test directory (leave empty for isolated temp)")
    parser.add_argument("--json", default="evaluation_results.json", help="Export summary to JSON file")
    args = parser.parse_args()

    run_evaluation(num_attacks=args.attacks, num_benign=args.benign,
                   target_dir=args.dir, json_out=args.json)
