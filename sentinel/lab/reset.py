"""Clean reset script for Sentinel.
Wipes the database (events, incidents, audit) and resets the watched folder with fresh seeds and canaries.

Usage:
  python -m lab.reset --dir C:\\SentinelLab\\watched --count 60
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from typing import Optional

import httpx

from analyzers.honey import HoneyRegistry
from lab.simulator import seed


def reset_database(url: Optional[str] = None, token: Optional[str] = None,
                   db_path: str = "sentinel.db") -> bool:
    """Wipes the database via the server REST API or directly via SQLite."""
    # Attempt server REST API first if URL is supplied
    if url and token:
        try:
            with httpx.Client(timeout=3) as client:
                res = client.post(f"{url.rstrip('/')}/api/reset",
                                  headers={"Authorization": f"Bearer {token}"})
                if res.status_code == 200:
                    print(f"[reset] Database wiped via API ({url}).", flush=True)
                    return True
        except Exception as e:
            print(f"[reset] Server API unavailable ({e}), falling back to direct SQLite wipe.", flush=True)

    # Fallback to direct SQLite wipe
    if os.path.exists(db_path):
        try:
            con = sqlite3.connect(db_path)
            con.execute("DELETE FROM events")
            con.execute("DELETE FROM incidents")
            con.execute("DELETE FROM audit")
            con.commit()
            con.execute("VACUUM")
            con.close()
            print(f"[reset] Direct SQLite database wipe successful ({db_path}).", flush=True)
            return True
        except Exception as e:
            print(f"[reset] Error wiping SQLite database: {e}", flush=True)
            return False
    else:
        print(f"[reset] Database file '{db_path}' does not exist; nothing to wipe.", flush=True)
        return True


def clean_watched_directory(directory: str, count: int = 60, canary_count: int = 3) -> None:
    """Removes all corrupted/locked/temporary files, re-seeds fresh documents, and deploys canaries."""
    os.makedirs(directory, exist_ok=True)

    # Remove temporary artifact directories and mutated files
    for root, dirs, files in os.walk(directory, topdown=False):
        for f in files:
            p = os.path.join(root, f)
            # Remove locked, backup, temporary, or canary files
            if f.endswith((".locked", ".bak", ".tmp", ".zip")) or f.startswith(("~", ".")):
                try:
                    os.remove(p)
                except OSError:
                    pass
        for d in dirs:
            if d in ("_copies_tmp", "scratch", "tmp"):
                try:
                    shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                except OSError:
                    pass

    # Clean existing docs to ensure fresh state
    for f in os.listdir(directory):
        p = os.path.join(directory, f)
        if os.path.isfile(p):
            try:
                os.remove(p)
            except OSError:
                pass

    print(f"[reset] Cleaned directory: {directory}", flush=True)

    # Re-seed clean documents
    seeded = seed(directory, count=count)
    print(f"[reset] Seeded {len(seeded)} clean documents in {directory}", flush=True)

    # Deploy fresh canary tripwires
    honey = HoneyRegistry()
    deployed = honey.deploy(directory, count=canary_count)
    print(f"[reset] Deployed {len(deployed)} canary tripwires: {[os.path.basename(c) for c in deployed]}", flush=True)


def full_reset(directory: str, count: int = 60, url: str = "http://127.0.0.1:8000",
               token: str = "dev-token", db_path: str = "sentinel.db") -> None:
    """Runs a complete reset of the database and watched directory."""
    print("==================================================", flush=True)
    print("             AEGIS SENTINEL CLEAN RESET           ", flush=True)
    print("==================================================", flush=True)
    reset_database(url=url, token=token, db_path=db_path)
    clean_watched_directory(directory, count=count)
    print("[reset] Sentinel system is in a clean baseline state.", flush=True)
    print("==================================================", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Sentinel clean reset tool")
    ap.add_argument("--dir", default=r"C:\SentinelLab\watched", help="Target watched directory")
    ap.add_argument("--count", type=int, default=60, help="Number of fresh documents to seed")
    ap.add_argument("--canaries", type=int, default=3, help="Number of canary files to deploy")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="Sentinel server URL")
    ap.add_argument("--token", default=os.environ.get("SENTINEL_TOKEN", "dev-token"), help="Auth token")
    ap.add_argument("--db", default="sentinel.db", help="Path to sentinel.db")
    args = ap.parse_args()

    full_reset(directory=args.dir, count=args.count, url=args.url, token=args.token, db_path=args.db)
