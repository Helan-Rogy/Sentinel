"""Entropy and file-type analysis. Pure Python, no third-party dependencies.

High entropy alone is NOT proof of ransomware (zip, jpg, mp4 are high entropy).
It is one signal; the rule engine combines it with others.
"""
from __future__ import annotations

import math
import os
from collections import Counter
from typing import Optional

from contracts import EntropyResult

SAMPLE_BYTES = 64 * 1024
MIN_BYTES = 512  # entropy of tiny files is unreliable

MAGIC: dict[str, tuple[bytes, ...]] = {
    ".docx": (b"PK\x03\x04",), ".xlsx": (b"PK\x03\x04",), ".pptx": (b"PK\x03\x04",),
    ".zip": (b"PK\x03\x04",), ".pdf": (b"%PDF",), ".png": (b"\x89PNG",),
    ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",), ".gif": (b"GIF8",),
}
TEXT_EXTS = {".txt", ".csv", ".md", ".log", ".json", ".xml", ".html", ".py"}


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    h = -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
    return max(0.0, min(8.0, h))


def chi_square(data: bytes) -> float:
    """Chi-square statistic vs. a uniform byte distribution (about 255 for random data)."""
    if not data:
        return 0.0
    expected = len(data) / 256
    counts = Counter(data)
    return sum(((counts.get(b, 0) - expected) ** 2) / expected for b in range(256))


def effective_ext(path: str) -> str:
    """Original extension, seeing through an appended one: report.docx.locked -> .docx"""
    base = os.path.basename(path).lower()
    parts = base.split(".")
    if len(parts) < 2:
        return ""
    last = "." + parts[-1]
    if last in MAGIC or last in TEXT_EXTS:
        return last
    if len(parts) >= 3:
        prev = "." + parts[-2]
        if prev in MAGIC or prev in TEXT_EXTS:
            return prev
    return last


def type_mismatch(path: str, head: bytes) -> bool:
    ext = effective_ext(path)
    if ext in MAGIC:
        return not any(head.startswith(m) for m in MAGIC[ext])
    if ext in TEXT_EXTS and head:
        odd = sum(1 for b in head[:4096] if b < 9 or (13 < b < 32) or b > 126)
        return odd / min(len(head), 4096) > 0.3
    return False


def analyze(path: str, previous: Optional[float] = None) -> Optional[EntropyResult]:
    """Analyze one file. Returns None if it is unreadable, missing, or too small."""
    try:
        if os.path.getsize(path) < MIN_BYTES:
            return None
        with open(path, "rb") as f:
            head = f.read(SAMPLE_BYTES)
    except OSError:
        return None
    h = shannon(head)
    mismatch = type_mismatch(path, head)
    delta = None if previous is None else round(h - previous, 3)
    detail = []
    if mismatch:
        detail.append(f"content does not match {effective_ext(path)}")
    if delta is not None and delta >= 1.5:
        detail.append(f"entropy rose {previous:.2f} to {h:.2f}")
    return EntropyResult(path=path, shannon=round(h, 3), chi_square=round(chi_square(head), 1),
                         previous_shannon=previous, delta=delta, type_mismatch=mismatch,
                         detail="; ".join(detail))
