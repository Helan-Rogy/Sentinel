"""SQLite storage. Incidents are stored as validated JSON documents."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

from contracts import FileEvent, Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts TEXT NOT NULL, endpoint_id TEXT, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, updated TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, ref TEXT, detail TEXT);
"""


class Store:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # events
    def add_event(self, e: FileEvent) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO events VALUES (?,?,?,?)",
                (e.id, e.ts.isoformat(), e.endpoint_id, e.model_dump_json()),
            )
            self._db.commit()

    def list_events(self, limit: int = 200) -> list[FileEvent]:
        with self._lock:
            rows = self._db.execute(
                "SELECT body FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [FileEvent.model_validate_json(r["body"]) for r in rows]

    def count_events(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # incidents
    def save_incident(self, inc: Incident) -> None:
        inc.updated = datetime.now(timezone.utc)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?,?,?)",
                (inc.id, inc.updated.isoformat(), inc.model_dump_json()),
            )
            self._db.commit()

    def get_incident(self, inc_id: str) -> Optional[Incident]:
        with self._lock:
            r = self._db.execute(
                "SELECT body FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
        return Incident.model_validate_json(r["body"]) if r else None

    def list_incidents(self, limit: int = 100) -> list[Incident]:
        with self._lock:
            rows = self._db.execute(
                "SELECT body FROM incidents ORDER BY updated DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Incident.model_validate_json(r["body"]) for r in rows]

    # audit
    def audit(self, actor: str, action: str, ref: str = "", detail: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit (ts, actor, action, ref, detail) VALUES (?,?,?,?,?)",
                (self._now(), actor, action, ref, detail),
            )
            self._db.commit()

    def list_audit(self, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
