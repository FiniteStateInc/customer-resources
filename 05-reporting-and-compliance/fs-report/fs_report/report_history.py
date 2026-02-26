"""Global report history stored in ~/.fs-report/history.db (SQLite).

Tracks every successful report run so that ``fs-report serve`` can display
a landing page with clickable links to past reports.
"""

import json
import logging
import os
import sqlite3
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_HISTORY_DIR = Path.home() / ".fs-report"
_HISTORY_DB = _HISTORY_DIR / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    output_dir TEXT NOT NULL,
    domain TEXT,
    recipes TEXT,       -- JSON list of recipe names
    scope TEXT,         -- JSON dict: {project, folder, period}
    log_file TEXT,      -- log filename, e.g. 2026-02-25_a1b2c3d4.log
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS run_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    recipe TEXT NOT NULL,
    path TEXT NOT NULL,      -- relative to output_dir
    format TEXT NOT NULL     -- html, csv, xlsx
);
"""


def _ensure_db() -> sqlite3.Connection:
    """Open (and lazily create) the history database."""
    _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_HISTORY_DB))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    # Migrate: add log_file column if missing (pre-existing databases)
    try:
        conn.execute("SELECT log_file FROM runs LIMIT 0")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE runs ADD COLUMN log_file TEXT")
    _set_permissions()
    return conn


def _set_permissions() -> None:
    """Set 600 permissions on the history database (POSIX only)."""
    if sys.platform != "win32" and _HISTORY_DB.exists():
        try:
            os.chmod(_HISTORY_DB, 0o600)
        except OSError:
            pass


def append_run(
    output_dir: str,
    domain: str,
    recipes: list[str],
    scope: dict[str, Any],
    files: list[dict[str, str]],
    log_file: str = "",
) -> str:
    """Record a completed report run. Returns the run ID."""
    run_id = uuid.uuid4().hex[:8]
    timestamp = datetime.now(UTC).isoformat()

    conn = _ensure_db()
    try:
        conn.execute(
            "INSERT INTO runs (id, timestamp, output_dir, domain, recipes, scope, log_file) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                timestamp,
                output_dir,
                domain,
                json.dumps(recipes),
                json.dumps(scope),
                log_file or None,
            ),
        )
        for f in files:
            conn.execute(
                "INSERT INTO run_files (run_id, recipe, path, format) "
                "VALUES (?, ?, ?, ?)",
                (run_id, f["recipe"], f["path"], f["format"]),
            )
        conn.commit()
    finally:
        conn.close()

    return run_id


def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent runs, newest first."""
    conn = _ensure_db()
    try:
        cursor = conn.execute(
            "SELECT id, timestamp, output_dir, domain, recipes, scope, log_file "
            "FROM runs ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()

        runs = []
        for row in rows:
            run_id, ts, out_dir, domain, recipes_json, scope_json, log_file = row
            file_cursor = conn.execute(
                "SELECT recipe, path, format FROM run_files WHERE run_id = ?",
                (run_id,),
            )
            files = [
                {"recipe": r, "path": p, "format": fmt}
                for r, p, fmt in file_cursor.fetchall()
            ]
            runs.append(
                {
                    "id": run_id,
                    "timestamp": ts,
                    "output_dir": out_dir,
                    "domain": domain,
                    "recipes": json.loads(recipes_json) if recipes_json else [],
                    "scope": json.loads(scope_json) if scope_json else {},
                    "files": files,
                    "log_file": log_file or "",
                }
            )
        return runs
    finally:
        conn.close()


def get_run(run_id: str) -> dict[str, Any] | None:
    """Return a single run by ID, or None if not found."""
    conn = _ensure_db()
    try:
        cursor = conn.execute(
            "SELECT id, timestamp, output_dir, domain, recipes, scope, log_file "
            "FROM runs WHERE id = ?",
            (run_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        rid, ts, out_dir, domain, recipes_json, scope_json, log_file = row
        file_cursor = conn.execute(
            "SELECT recipe, path, format FROM run_files WHERE run_id = ?",
            (rid,),
        )
        files = [
            {"recipe": r, "path": p, "format": fmt}
            for r, p, fmt in file_cursor.fetchall()
        ]
        return {
            "id": rid,
            "timestamp": ts,
            "output_dir": out_dir,
            "domain": domain,
            "recipes": json.loads(recipes_json) if recipes_json else [],
            "scope": json.loads(scope_json) if scope_json else {},
            "files": files,
            "log_file": log_file or "",
        }
    finally:
        conn.close()


def prune(keep: int = 100) -> int:
    """Delete old runs beyond *keep* most recent. Returns count deleted."""
    conn = _ensure_db()
    try:
        cursor = conn.execute(
            "SELECT id FROM runs ORDER BY timestamp DESC LIMIT -1 OFFSET ?",
            (keep,),
        )
        old_ids = [row[0] for row in cursor.fetchall()]
        if old_ids:
            placeholders = ",".join("?" for _ in old_ids)
            conn.execute(
                f"DELETE FROM run_files WHERE run_id IN ({placeholders})",
                old_ids,
            )
            conn.execute(f"DELETE FROM runs WHERE id IN ({placeholders})", old_ids)
            conn.commit()
        return len(old_ids)
    finally:
        conn.close()
