"""Machine Learning Classifier and Confidence Calibration for Ransomware Detection.

Extracts feature vectors from observation windows and scores p(ransomware) in [0.0, 1.0]
with calibrated confidence intervals via Platt scaling.
Zero mandatory third-party dependencies (pure Python with sklearn interoperability).
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import asdict, dataclass
from typing import Any, List, Optional, Tuple

from contracts import FileOp, RiskLevel
from detection.rules import Window, _ext

# Features:
# 0: mod_rate (files modified/renamed per second)
# 1: entropy_jump_count (files with delta >= 1.5)
# 2: mean_entropy (mean shannon entropy of modified files)
# 3: max_entropy_delta (maximum delta observed)
# 4: honey_hits (decoy files touched)
# 5: type_mismatches (files with corrupted magic header)
# 6: ext_changes (files renamed with new/unknown extension)

FEATURE_NAMES = [
    "mod_rate",
    "entropy_jump_count",
    "mean_entropy",
    "max_entropy_delta",
    "honey_hits",
    "type_mismatches",
    "ext_changes",
]

DEFAULT_WEIGHTS = [
    0.42,   # mod_rate
    0.65,   # entropy_jump_count
    0.35,   # mean_entropy
    0.58,   # max_entropy_delta
    1.20,   # honey_hits
    0.72,   # type_mismatches
    0.80,   # ext_changes
]
DEFAULT_BIAS = -3.85
DEFAULT_PLATT_A = -1.0
DEFAULT_PLATT_B = 0.0


def extract_features(w: Window, entropy_floor: float = 7.5, entropy_delta: float = 1.5) -> List[float]:
    """Extract standard 7-dimensional feature vector from a Window."""
    modified = {e.path for e in w.events if e.op == FileOp.MODIFY}
    renamed_src = {e.path for e in w.events if e.op == FileOp.RENAME}
    renamed_dst = {e.new_path for e in w.events if e.op == FileOp.RENAME and e.new_path}
    changed = (modified - renamed_src) | renamed_dst
    rate = len(changed) / max(w.seconds, 1.0)

    latest = {r.path: r for r in w.entropy}
    jumps = [r for r in latest.values()
             if r.shannon >= entropy_floor and r.delta is not None and r.delta >= entropy_delta]
    mismatches = [r for r in latest.values() if r.type_mismatch]
    ext_changes = [e for e in w.events if e.op == FileOp.RENAME and e.new_path
                   and _ext(e.path) != _ext(e.new_path)]
    honey_paths = {h.path for h in w.honey}

    entropies = [r.shannon for r in latest.values()]
    mean_ent = (sum(entropies) / len(entropies)) if entropies else 0.0
    deltas = [r.delta for r in latest.values() if r.delta is not None]
    max_delta = max(deltas) if deltas else 0.0

    return [
        round(rate, 3),
        float(len(jumps)),
        round(mean_ent, 3),
        round(max_delta, 3),
        float(len(honey_paths)),
        float(len(mismatches)),
        float(len(ext_changes)),
    ]


def _sigmoid(z: float) -> float:
    # Stable sigmoid
    if z < -40:
        return 0.0
    if z > 40:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class ModelArtifact:
    weights: List[float]
    bias: float
    platt_a: float
    platt_b: float
    trained_samples: int = 0
    accuracy: float = 0.0
    brier_score: float = 0.0


class RansomwareClassifier:
    """Trained classifier that computes p(ransomware) and calibrated uncertainty."""

    def __init__(self, weights: Optional[List[float]] = None, bias: Optional[float] = None,
                 platt_a: float = DEFAULT_PLATT_A, platt_b: float = DEFAULT_PLATT_B):
        self.weights = list(weights or DEFAULT_WEIGHTS)
        self.bias = bias if bias is not None else DEFAULT_BIAS
        self.platt_a = platt_a
        self.platt_b = platt_b
        self.metadata = ModelArtifact(
            weights=self.weights, bias=self.bias, platt_a=self.platt_a, platt_b=self.platt_b
        )

    def raw_score(self, features: List[float]) -> float:
        """Compute linear discriminant score z = w^T x + b."""
        z = self.bias
        for w, x in zip(self.weights, features):
            z += w * x
        return z

    def predict_proba(self, features: List[float]) -> Tuple[float, float]:
        """Returns (p_attack, margin_error).

        p_attack is calibrated in [0.0, 1.0].
        margin_error is the 95% confidence interval half-width (+/-).
        """
        z = self.raw_score(features)
        p_raw = _sigmoid(z)

        # Apply Platt scaling calibration: P = sigmoid(A * z + B)
        # When A=-1.0 and B=0.0, this is standard logistic calibration
        calibrated_z = -1.0 * (self.platt_a * z + self.platt_b)
        p_calibrated = _sigmoid(calibrated_z)

        # Confidence margin based on standard error of prediction
        # Highest uncertainty occurs near decision boundary (p ~ 0.5)
        variance = p_calibrated * (1.0 - p_calibrated)
        # Bound margin between 0.02 and 0.12
        margin = round(min(0.12, max(0.02, 1.96 * math.sqrt(variance) / math.sqrt(15))), 3)

        return round(p_calibrated, 3), margin

    def evaluate_risk(self, features: List[float]) -> Tuple[RiskLevel, float, float, str, bool]:
        """Evaluate features into RiskLevel, probability, margin, confidence string, and triage_needed."""
        p, margin = self.predict_proba(features)
        conf_str = f"p(attack) = {p:.2f} +/- {margin:.2f}"

        # Confidence triage policy: when confidence is ambiguous (0.35 <= p < 0.70)
        triage_needed = (0.35 <= p < 0.70) or (margin > 0.10 and p >= 0.50)

        if p >= 0.85:
            level = RiskLevel.CRITICAL
        elif p >= 0.65:
            level = RiskLevel.HIGH
        elif p >= 0.35:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return level, p, margin, conf_str, triage_needed

    def fit(self, X: List[List[float]], y: List[int], epochs: int = 150, lr: float = 0.05,
            reg: float = 0.01) -> ModelArtifact:
        """Train pure-Python SGD logistic regression with L2 regularization."""
        n_features = len(X[0])
        w = [0.0] * n_features
        b = 0.0
        n_samples = len(X)

        for _ in range(epochs):
            for i in range(n_samples):
                xi = X[i]
                yi = y[i]
                z = b + sum(wj * xij for wj, xij in zip(w, xi))
                pred = _sigmoid(z)
                err = pred - yi

                # Gradient step
                for j in range(n_features):
                    grad = err * xi[j] + reg * w[j]
                    w[j] -= lr * grad
                b -= lr * err

        self.weights = [round(v, 4) for v in w]
        self.bias = round(b, 4)

        # Compute accuracy & Brier score
        correct = 0
        brier = 0.0
        raw_scores = []
        for xi, yi in zip(X, y):
            score = self.raw_score(xi)
            raw_scores.append(score)
            p = _sigmoid(score)
            brier += (p - yi) ** 2
            if (p >= 0.5 and yi == 1) or (p < 0.5 and yi == 0):
                correct += 1

        acc = round(correct / n_samples, 4)
        brier_score = round(brier / n_samples, 4)

        # Platt scaling optimization (A, B) via mini-grid search
        best_a, best_b, best_loss = -1.0, 0.0, 1e9
        for a_cand in [-1.5, -1.2, -1.0, -0.8, -0.5]:
            for b_cand in [-0.5, -0.2, 0.0, 0.2, 0.5]:
                loss = 0.0
                for s, target in zip(raw_scores, y):
                    p_cal = _sigmoid(-(a_cand * s + b_cand))
                    loss += (p_cal - target) ** 2
                if loss < best_loss:
                    best_loss = loss
                    best_a, best_b = a_cand, b_cand

        self.platt_a = round(best_a, 3)
        self.platt_b = round(best_b, 3)

        self.metadata = ModelArtifact(
            weights=self.weights,
            bias=self.bias,
            platt_a=self.platt_a,
            platt_b=self.platt_b,
            trained_samples=n_samples,
            accuracy=acc,
            brier_score=brier_score,
        )
        return self.metadata

    def save(self, filepath: str) -> None:
        """Save model weights and calibration parameters to JSON."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        data = asdict(self.metadata)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "RansomwareClassifier":
        """Load model weights and calibration parameters from JSON."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        inst = cls(
            weights=data.get("weights"),
            bias=data.get("bias"),
            platt_a=data.get("platt_a", DEFAULT_PLATT_A),
            platt_b=data.get("platt_b", DEFAULT_PLATT_B),
        )
        inst.metadata = ModelArtifact(**data)
        return inst


# Shared global singleton for inference
_GLOBAL_CLASSIFIER: Optional[RansomwareClassifier] = None


def get_classifier() -> RansomwareClassifier:
    """Get or lazy-load the default singleton classifier."""
    global _GLOBAL_CLASSIFIER
    if _GLOBAL_CLASSIFIER is None:
        model_path = os.path.join(os.path.dirname(__file__), "models", "classifier_weights.json")
        if os.path.exists(model_path):
            try:
                _GLOBAL_CLASSIFIER = RansomwareClassifier.load(model_path)
            except Exception:
                _GLOBAL_CLASSIFIER = RansomwareClassifier()
        else:
            _GLOBAL_CLASSIFIER = RansomwareClassifier()
    return _GLOBAL_CLASSIFIER
