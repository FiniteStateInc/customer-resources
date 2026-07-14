"""Persistent file logging utilities for CLI and web UI runs."""

import glob as _glob
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path

LOG_DIR = Path.home() / ".fs-report" / "logs"
LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
MAX_LOG_AGE_DAYS = 14

# Secrets acquired only mid-run (e.g. the short-lived Copilot bearer minted by
# copilot_auth's token exchange) don't exist yet when a handler's
# TokenRedactionFilter snapshots its constructor tokens. They register here
# instead; every filter consults this registry on each record, so a secret
# registered at ANY point is scrubbed by all already-attached filters.
_RUNTIME_SECRETS: set[str] = set()
_RUNTIME_SECRETS_LOCK = threading.Lock()


def register_runtime_secret(secret: str) -> None:
    """Register a mid-run-acquired secret for redaction by all active filters."""
    if not secret:
        return
    with _RUNTIME_SECRETS_LOCK:
        _RUNTIME_SECRETS.add(secret)


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
    """Logging filter that replaces raw secrets with ``***REDACTED***``.

    Accepts any number of secret values (platform auth token, AI-provider
    API key, …) and scrubs each from ``record.msg`` and ``record.args``.
    Empty values are skipped, so callers can pass credentials that may not
    be configured without guarding. Secrets registered mid-run via
    :func:`register_runtime_secret` are scrubbed too, per record.
    """

    def __init__(self, *tokens: str) -> None:
        super().__init__()
        # Longest-first so a token that is a prefix of another (overlapping
        # secrets) can't leave a recoverable remnant after replacement.
        self._tokens = tuple(sorted((t for t in tokens if t), key=len, reverse=True))

    def _active_tokens(self) -> tuple[str, ...]:
        # The unlocked emptiness check is safe: it's a GIL-atomic truthiness
        # read (no iteration, so no mutation-during-iteration hazard), and a
        # lock here would add no ordering guarantee — a record processed
        # before a registration completes misses that secret with or without
        # one. Leak-freedom instead comes from ordering at the SOURCE:
        # get_copilot_token registers the bearer BEFORE returning it, so no
        # caller can possess (and log) a secret that isn't registered yet.
        if not _RUNTIME_SECRETS:
            return self._tokens  # fast path — already longest-first
        with _RUNTIME_SECRETS_LOCK:
            combined = set(self._tokens) | _RUNTIME_SECRETS
        return tuple(sorted(combined, key=len, reverse=True))

    @staticmethod
    def _has_secret(value: str, tokens: tuple[str, ...]) -> bool:
        return any(token in value for token in tokens)

    @staticmethod
    def _scrub(value: str, tokens: tuple[str, ...]) -> str:
        for token in tokens:
            value = value.replace(token, "***REDACTED***")
        return value

    def filter(self, record: logging.LogRecord) -> bool:
        tokens = self._active_tokens()
        msg = str(record.msg)
        if self._has_secret(msg, tokens):
            record.msg = self._scrub(msg, tokens)
        if record.args:
            args = record.args
            if isinstance(args, tuple):
                record.args = tuple(
                    (
                        self._scrub(str(a), tokens)
                        if self._has_secret(str(a), tokens)
                        else a
                    )
                    for a in args
                )
            elif isinstance(args, dict):
                record.args = {
                    k: (
                        self._scrub(str(v), tokens)
                        if self._has_secret(str(v), tokens)
                        else v
                    )
                    for k, v in args.items()
                }
        return True


def create_file_handler(
    run_id: str,
    *tokens: str,
    level: int = logging.DEBUG,
) -> logging.FileHandler:
    """Create a file handler writing to ``~/.fs-report/logs/<date>_<run_id>.log``.

    Every non-empty value in ``tokens`` (platform auth token, AI-provider
    API key, …) is redacted from records via :class:`TokenRedactionFilter`.
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

    # Always attach — even with no static tokens the filter consults the
    # runtime-secret registry, so mid-run credentials (e.g. a Copilot bearer
    # minted after handler creation) are scrubbed regardless of whether any
    # credential existed when the handler was built.
    handler.addFilter(TokenRedactionFilter(*tokens))

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
