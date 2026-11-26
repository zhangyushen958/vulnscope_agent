"""SQLite-backed durable job state and trace event stream."""
from __future__ import annotations
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any


class RunStore:
    def __init__(self, path: Path, result_dir: Path | None = None):
        self.result_dir = result_dir
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, mode TEXT, status TEXT, total INT, processed INT DEFAULT 0, success INT DEFAULT 0, failures INT DEFAULT 0, created REAL, finished REAL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, created REAL, kind TEXT, payload TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS rows (job_id TEXT, row_order INT, idx TEXT, status TEXT, report TEXT, error TEXT, PRIMARY KEY(job_id,row_order))")
        self.db.execute("CREATE INDEX IF NOT EXISTS event_job_idx ON events(job_id,id)")
        self.db.execute("CREATE TABLE IF NOT EXISTS runtime_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.commit()

    def new_job(self, mode: str, total: int) -> str:
        job_id = uuid.uuid4().hex
        with self._lock:
            self.db.execute("INSERT INTO jobs (id,mode,status,total,created) VALUES(?,?,?,?,?)", (job_id, mode, "queued", total, time.time()))
            self.db.commit()
        return job_id

    def set_status(self, job_id: str, status: str) -> None:
        with self._lock:
            self.db.execute("UPDATE jobs SET status=?,finished=CASE WHEN ? IN ('completed','partial','failed') THEN ? ELSE finished END WHERE id=?",
                            (status, status, time.time(), job_id))
            self.db.commit()

    def add_event(self, job_id: str, kind: str, payload: dict) -> int:
        with self._lock:
            cur = self.db.execute("INSERT INTO events(job_id,created,kind,payload) VALUES(?,?,?,?)",
                                  (job_id, time.time(), kind, json.dumps(payload, ensure_ascii=False)))
            self.db.commit()
            event_id = cur.lastrowid
            if self.result_dir is not None:
                try:
                    folder = self.result_dir / job_id
                    folder.mkdir(parents=True, exist_ok=True)
                    with (folder / "events.jsonl").open("a", encoding="utf-8") as logfile:
                        logfile.write(json.dumps({"id": event_id, "created": time.time(), "kind": kind,
                                                  "data": payload}, ensure_ascii=False) + "\n")
                except OSError:
                    # SQLite event is authoritative, logs are best-effort mirror.
                    pass
            return event_id

    def add_row(self, job_id: str, order: int, idx: str, report: dict | None, error: str | None) -> None:
        with self._lock:
            self.db.execute("INSERT INTO rows(job_id,row_order,idx,status,report,error) VALUES(?,?,?,?,?,?)",
                            (job_id, order, idx, "completed" if report else "failed",
                             json.dumps(report, ensure_ascii=False) if report else None, error))
            self.db.execute("UPDATE jobs SET processed=processed+1,success=success+?,failures=failures+? WHERE id=?",
                            (1 if report else 0, 0 if report else 1, job_id))
            self.db.commit()

    def recent_jobs(self, limit: int = 30) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def job(self, job_id: str) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def events_since(self, job_id: str, since: int = 0, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT id,created,kind,payload FROM events WHERE job_id=? AND id>? ORDER BY id LIMIT ?",
                                   (job_id, since, limit)).fetchall()
        return [{"id": r["id"], "created": r["created"], "kind": r["kind"], "data": json.loads(r["payload"])} for r in rows]

    def rows(self, job_id: str) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM rows WHERE job_id=? ORDER BY row_order", (job_id,)).fetchall()
        return [{"idx": r["idx"], "status": r["status"], "report": json.loads(r["report"]) if r["report"] else None,
                 "error": r["error"]} for r in rows]

    def active_jobs(self) -> list[str]:
        """Guard destructive maintenance while background workers may still write."""
        with self._lock:
            rows = self.db.execute("SELECT id FROM jobs WHERE status IN ('queued','running')").fetchall()
        return [row["id"] for row in rows]

    def delete_finished(self, job_id: str | None = None) -> list[str]:
        """Delete only terminal tasks and their database traces, never model settings.

        Called with service maintenance lock; checking and deleting share the
        SQLite lock to prevent observing partially committed rows.
        """
        with self._lock:
            active = self.db.execute("SELECT id FROM jobs WHERE status IN ('queued','running') LIMIT 1").fetchone()
            if active:
                raise RuntimeError("存在正在排队或运行的任务，请等待结束后再清空")
            if job_id is not None:
                row = self.db.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
                if row is None:
                    raise LookupError("任务不存在")
                ids = [job_id]
            else:
                ids = [r["id"] for r in self.db.execute("SELECT id FROM jobs WHERE status IN ('completed','partial','failed')")]
            with self.db:
                for id_ in ids:
                    self.db.execute("DELETE FROM events WHERE job_id=?", (id_,))
                    self.db.execute("DELETE FROM rows WHERE job_id=?", (id_,))
                    self.db.execute("DELETE FROM jobs WHERE id=?", (id_,))
                    self.db.execute("DELETE FROM runtime_settings WHERE name=?", (f"batch_digest:{id_}",))
            return ids

    def get_setting(self, key: str) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT value FROM runtime_settings WHERE name=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None

    def set_setting(self, key: str, value: dict) -> None:
        with self._lock:
            self.db.execute("INSERT INTO runtime_settings(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
            self.db.commit()
