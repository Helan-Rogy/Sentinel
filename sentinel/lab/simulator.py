"""Ransomware-LIKE simulator and benign workload generator. SAFE: it only touches a
directory you name, overwrites files with random bytes, and renames them. Use it ONLY in
a throwaway folder (e.g. C:\\SentinelLab\\watched). There is no real malware here.

  python -m lab.simulator seed   --dir C:\\SentinelLab\\watched --count 60
  python -m lab.simulator attack --dir C:\\SentinelLab\\watched --rate 8
  python -m lab.simulator benign --dir C:\\SentinelLab\\watched --seconds 20
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import sys
import time
import zipfile

WORDS = "alpha budget client report invoice meeting project review summary draft plan".split()


def _text(rnd: random.Random, n: int) -> str:
    return "\n".join(" ".join(rnd.choice(WORDS) for _ in range(12)) for _ in range(n))


def seed(directory: str, count: int = 60, rng_seed: int = 1) -> list[str]:
    """Create realistic dummy documents (txt, csv, pdf-like, docx-like)."""
    rnd = random.Random(rng_seed)
    os.makedirs(directory, exist_ok=True)
    out = []
    for i in range(count):
        kind = ("txt", "csv", "pdf", "docx")[i % 4]
        p = os.path.join(directory, f"doc_{i:03d}.{kind}")
        if kind == "txt":
            data = _text(rnd, 300).encode()
        elif kind == "csv":
            data = "\n".join(f"{j},{rnd.randint(0, 9999)},{rnd.choice(WORDS)}" for j in range(800)).encode()
        elif kind == "pdf":
            data = b"%PDF-1.4\n" + _text(rnd, 400).encode()
        else:
            with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("word/document.xml", os.urandom(1) + rnd.randbytes(30_000))
            out.append(p)
            continue
        with open(p, "wb") as f:
            f.write(data)
        out.append(p)
    return out


def attack(directory: str, rate: float = 8.0, ext: str = ".locked", limit: int = 0) -> int:
    """Overwrite each file with random bytes, then rename it with a new extension."""
    print(f"[simulator] attack pid={os.getpid()} dir={directory} rate={rate}/s", flush=True)
    files = sorted(
        os.path.join(r, f) for r, _, fs in os.walk(directory) for f in fs if not f.endswith(ext)
    )
    done = 0
    for p in files:
        if limit and done >= limit:
            break
        try:
            size = os.path.getsize(p)
            with open(p, "rb+") as f:
                f.write(os.urandom(size))
                f.truncate()
            os.rename(p, p + ext)
            done += 1
        except OSError as e:
            print(f"[simulator] skip {p}: {e}", flush=True)
        time.sleep(1 / rate)
    print(f"[simulator] finished, {done} files", flush=True)
    return done


def benign(directory: str, seconds: float = 20, rate: float = 3.0) -> None:
    """Legitimate-looking activity: edit text, copy files, create a zip backup."""
    print(f"[benign] pid={os.getpid()} dir={directory}", flush=True)
    rnd = random.Random(7)
    end = time.time() + seconds
    texts = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith((".txt", ".csv"))]
    copies = os.path.join(directory, "_copies_tmp")
    os.makedirs(copies, exist_ok=True)
    n = 0
    while time.time() < end and texts:
        p = rnd.choice(texts)
        with open(p, "ab") as f:
            f.write(("\n" + _text(rnd, 2)).encode())
        shutil.copy(p, os.path.join(copies, f"copy_{n}.bak"))
        n += 1
        if n % 10 == 0:
            with zipfile.ZipFile(os.path.join(copies, f"backup_{n}.zip"), "w", zipfile.ZIP_DEFLATED) as z:
                for t in texts[:5]:
                    z.write(t, os.path.basename(t))
        time.sleep(1 / rate)
    print("[benign] finished", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["seed", "attack", "benign"])
    ap.add_argument("--dir", required=True)
    ap.add_argument("--count", type=int, default=60)
    ap.add_argument("--rate", type=float, default=8.0)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    if not os.path.isdir(a.dir) and a.mode != "seed":
        sys.exit(f"directory not found: {a.dir}")
    if a.mode == "seed":
        print(f"created {len(seed(a.dir, a.count))} files")
    elif a.mode == "attack":
        attack(a.dir, a.rate, limit=a.limit)
    else:
        benign(a.dir, a.seconds, a.rate)
