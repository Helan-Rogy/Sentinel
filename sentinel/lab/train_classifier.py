"""Train and calibrate the Sentinel ML classifier on attack vs. benign telemetry profiles.

Generates 200 attack profiles and 200 benign profiles, fits the logistic model,
calibrates confidence intervals using Platt scaling, and persists the model.
"""
from __future__ import annotations

import argparse
import os
import random
from typing import List, Tuple

from detection.classifier import FEATURE_NAMES, RansomwareClassifier

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_SAVE_PATH = os.path.join(ROOT_DIR, "detection", "models", "classifier_weights.json")


def generate_synthetic_telemetry(n_attacks: int = 200, n_benign: int = 200, seed: int = 42) -> Tuple[List[List[float]], List[int]]:
    """Synthesize empirical telemetry features representing attack and benign behaviors.

    Features:
    [mod_rate, entropy_jump_count, mean_entropy, max_entropy_delta, honey_hits, type_mismatches, ext_changes]
    """
    rng = random.Random(seed)
    X: List[List[float]] = []
    y: List[int] = []

    # 1. Attack profiles (ransomware behaviors)
    # Features exhibit rapid modifications, extreme entropy jumps, extension changes, decoy hits
    for _ in range(n_attacks):
        attack_type = rng.choice(["fast_lock", "slow_stealth", "intermittent", "selective"])
        if attack_type == "fast_lock":
            rate = rng.uniform(7.0, 25.0)
            jumps = rng.randint(5, 20)
            mean_ent = rng.uniform(7.5, 7.99)
            max_delta = rng.uniform(2.5, 4.2)
            honey = rng.choice([1, 2, 3, 3])
            mismatches = rng.randint(4, 18)
            exts = rng.randint(4, 18)
        elif attack_type == "slow_stealth":
            rate = rng.uniform(1.5, 4.5)
            jumps = rng.randint(3, 8)
            mean_ent = rng.uniform(7.3, 7.95)
            max_delta = rng.uniform(2.0, 3.8)
            honey = rng.choice([0, 1, 2])
            mismatches = rng.randint(2, 6)
            exts = rng.randint(2, 6)
        elif attack_type == "intermittent":
            rate = rng.uniform(3.0, 10.0)
            jumps = rng.randint(4, 12)
            mean_ent = rng.uniform(7.4, 7.98)
            max_delta = rng.uniform(2.2, 4.0)
            honey = rng.choice([1, 2])
            mismatches = rng.randint(3, 10)
            exts = rng.randint(3, 10)
        else:  # selective targeting
            rate = rng.uniform(2.0, 8.0)
            jumps = rng.randint(2, 7)
            mean_ent = rng.uniform(7.1, 7.85)
            max_delta = rng.uniform(1.8, 3.5)
            honey = rng.choice([0, 1, 1])
            mismatches = rng.randint(2, 8)
            exts = rng.randint(1, 5)

        X.append([round(rate, 2), float(jumps), round(mean_ent, 2), round(max_delta, 2),
                  float(honey), float(mismatches), float(exts)])
        y.append(1)

    # 2. Benign profiles (developer builds, backups, document edits, file downloads)
    for _ in range(n_benign):
        benign_type = rng.choice(["word_excel_edits", "zip_archive", "bulk_copy", "software_install", "git_checkout"])
        if benign_type == "word_excel_edits":
            rate = rng.uniform(0.1, 1.2)
            jumps = 0
            mean_ent = rng.uniform(3.5, 5.2)
            max_delta = rng.uniform(0.0, 0.4)
            honey = 0
            mismatches = 0
            exts = 0
        elif benign_type == "zip_archive":
            rate = rng.uniform(2.0, 12.0)
            jumps = rng.choice([0, 0, 1])  # rarely a single compressed bundle
            mean_ent = rng.uniform(5.5, 7.8)
            max_delta = rng.uniform(0.0, 0.8)
            honey = 0
            mismatches = 0
            exts = 0
        elif benign_type == "bulk_copy":
            rate = rng.uniform(5.0, 20.0)
            jumps = 0
            mean_ent = rng.uniform(4.0, 5.8)
            max_delta = rng.uniform(0.0, 0.2)
            honey = 0
            mismatches = 0
            exts = 0
        elif benign_type == "software_install":
            rate = rng.uniform(4.0, 15.0)
            jumps = rng.choice([0, 1])
            mean_ent = rng.uniform(5.0, 6.5)
            max_delta = rng.uniform(0.0, 0.9)
            honey = 0
            mismatches = rng.choice([0, 1])  # rare header quirk
            exts = 0
        else:  # git checkout
            rate = rng.uniform(8.0, 30.0)
            jumps = 0
            mean_ent = rng.uniform(3.8, 5.0)
            max_delta = 0.0
            honey = 0
            mismatches = 0
            exts = 0

        X.append([round(rate, 2), float(jumps), round(mean_ent, 2), round(max_delta, 2),
                  float(honey), float(mismatches), float(exts)])
        y.append(0)

    # Shuffle dataset
    combined = list(zip(X, y))
    rng.shuffle(combined)
    X_shuffled, y_shuffled = zip(*combined)
    return list(X_shuffled), list(y_shuffled)


def main():
    parser = argparse.ArgumentParser(description="Train and calibrate Sentinel ML classifier")
    parser.add_argument("--attacks", type=int, default=200, help="Number of simulated attack runs")
    parser.add_argument("--benign", type=int, default=200, help="Number of simulated benign runs")
    parser.add_argument("--epochs", type=int, default=200, help="Training epochs")
    parser.add_argument("--output", type=str, default=MODEL_SAVE_PATH, help="Output path for weights JSON")
    args = parser.parse_args()

    print("==================================================")
    print("      AEGIS SENTINEL ML CLASSIFIER TRAINING       ")
    print("==================================================")
    print(f"[*] Synthesizing telemetry profiles: {args.attacks} attacks, {args.benign} benign...")
    X, y = generate_synthetic_telemetry(n_attacks=args.attacks, n_benign=args.benign)

    # 80/20 train/test split
    split_idx = int(len(X) * 0.8)
    X_train, y_train = X[:split_idx], y[:split_idx]
    X_test, y_test = X[split_idx:], y[split_idx:]

    print(f"[*] Training on {len(X_train)} samples, testing on {len(X_test)} samples...")
    clf = RansomwareClassifier()
    artifact = clf.fit(X_train, y_train, epochs=args.epochs, lr=0.04, reg=0.005)

    # Test set evaluation
    test_correct = 0
    test_brier = 0.0
    tp, fp, tn, fn = 0, 0, 0, 0

    for xi, yi in zip(X_test, y_test):
        p, margin = clf.predict_proba(xi)
        test_brier += (p - yi) ** 2
        pred = 1 if p >= 0.5 else 0
        if pred == yi:
            test_correct += 1
        if pred == 1 and yi == 1:
            tp += 1
        elif pred == 1 and yi == 0:
            fp += 1
        elif pred == 0 and yi == 0:
            tn += 1
        elif pred == 0 and yi == 1:
            fn += 1

    test_acc = round(test_correct / len(X_test), 4)
    test_brier = round(test_brier / len(X_test), 4)
    precision = round(tp / max(1, tp + fp), 4)
    recall = round(tp / max(1, tp + fn), 4)
    f1 = round(2 * (precision * recall) / max(1e-6, precision + recall), 4)

    print("\n[+] MODEL VALIDATION RESULTS:")
    print(f"    Train Accuracy   : {artifact.accuracy * 100:.2f}%")
    print(f"    Test Accuracy    : {test_acc * 100:.2f}%")
    print(f"    Test Precision   : {precision * 100:.2f}%")
    print(f"    Test Recall      : {recall * 100:.2f}%")
    print(f"    Test F1-Score    : {f1:.4f}")
    print(f"    Brier Score (Cal): {test_brier:.4f} (lower is better)")
    print(f"    Platt Scaling    : A={artifact.platt_a:.3f}, B={artifact.platt_b:.3f}")

    print("\n[+] LEARNED FEATURE WEIGHTS:")
    for name, w in zip(FEATURE_NAMES, clf.weights):
        print(f"    - {name:<20}: {w:+.4f}")
    print(f"    - {'bias (intercept)':<20}: {clf.bias:+.4f}")

    clf.save(args.output)
    print(f"\n[+] Successfully saved calibrated model weights to:\n    {args.output}")
    print("==================================================")


if __name__ == "__main__":
    main()
