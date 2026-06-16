"""Persistent file logging utilities for CLI and web UI runs."""

import glob as _glob
import logging
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

LOG_DIR = Path.home() / ".fs-report" / "logs"
LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
MAX_LOG_AGE_DAYS = 14


def generate_run_id() -> str:
    """Return an 8-character hex run identifier."""
    return uuid.uuid4().hex[:8]


def resolve_log_path(run_id: str, log_file: str | None = None) -> Path | None:
    """Resolve the on-disk log file for ``run_id`` (explicit filename, then glob).

    Single source of truth shared by the run router (``run_log`` /
    ``run_log_page``) and the reports router (``serve_history_log``) so all log
    viewers locate a log identically.  Returns the ``Path`` if a readable file
    exists, else None.

    * ``log_file`` — an explicit filename recorded for the run (in-memory for a
      live run, or the history DB's ``log_file`` column).  Tried first.
    * Glob fallback — ``LOG_DIR/<date>_<run_id>.log``.  The ``run_id`` is passed
      through :func:`glob.escape` so glob metacharacters (``*``, ``?``, ``[``)
      in a crafted/odd run_id are treated literally and can't match unrelated
      logs.  When several files match (the same run_id logged on different
      dates), the **newest** is returned: filenames are ``<date>_<run_id>.log``,
      so a lexical sort orders by date and the last element is the most recent.
    """
    if log_file:
        log_path: Path | None = LOG_DIR / log_file
    else:
        pattern = f"*_{_glob.escape(run_id)}.log"
        matches = sorted(LOG_DIR.glob(pattern))
        # Newest match: <date>_<run_id>.log sorts chronologically, so [-1] is
        # the most recent — the right one to surface for a failure-log viewer.
        log_path = matches[-1] if matches else None

    if not log_path or not log_path.is_file():
        return None
    return log_path


class TokenRedactionFilter(logging.Filter):
    """Logging filter that replaces a raw token with ``***REDACTED***``."""

    def __init__(self, token: str) -> None:
        super().__init__()
        self._token = token

    def filter(self, record: logging.LogRecord) -> bool:
        if self._token and self._token in str(record.msg):
            record.msg = str(record.msg).replace(self._token, "***REDACTED***")
        if record.args:
            args = record.args
            if isinstance(args, tuple):
                record.args = tuple(
                    (
                        str(a).replace(self._token, "***REDACTED***")
                        if self._token and self._token in str(a)
                        else a
                    )
                    for a in args
                )
            elif isinstance(args, dict):
                record.args = {
                    k: (
                        str(v).replace(self._token, "***REDACTED***")
                        if self._token and self._token in str(v)
                        else v
                    )
                    for k, v in args.items()
                }
        return True


def create_file_handler(
    run_id: str,
    token: str,
    level: int = logging.DEBUG,
) -> logging.FileHandler:
    """Create a file handler writing to ``~/.fs-report/logs/<date>_<run_id>.log``.

    Also triggers cleanup of old log files.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    # Owner-only permissions (POSIX)
    try:
        os.chmod(LOG_DIR, 0o700)
    except OSError:
        pass

    date_str = datetime.now().strftime("%Y-%m-%d")
    log_path = LOG_DIR / f"{date_str}_{run_id}.log"

    handler = logging.FileHandler(str(log_path), encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))

    if token:
        handler.addFilter(TokenRedactionFilter(token))

    _cleanup_old_logs()

    return handler


def _cleanup_old_logs() -> None:
    """Delete ``*.log`` files in the log directory older than *MAX_LOG_AGE_DAYS*."""
    if not LOG_DIR.is_dir():
        return

    cutoff = datetime.now() - timedelta(days=MAX_LOG_AGE_DAYS)
    for path in LOG_DIR.glob("*.log"):
        # Filename format: YYYY-MM-DD_<run_id>.log
        try:
            date_part = path.stem.split("_", 1)[0]
            file_date = datetime.strptime(date_part, "%Y-%m-%d")
            if file_date < cutoff:
                path.unlink()
        except (ValueError, IndexError):
            pass
