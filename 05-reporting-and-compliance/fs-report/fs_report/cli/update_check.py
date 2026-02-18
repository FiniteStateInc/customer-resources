"""PyPI update check — notifies users when a newer fs-report version exists.

All public functions are designed to *never* raise; any failure is silently
swallowed so it cannot interfere with normal CLI operation.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Union

_CACHE_DIR = Path.home() / ".fs-report"
_CACHE_FILE = _CACHE_DIR / "update_check.json"
_CACHE_TTL = 86_400  # 24 hours
_PYPI_URL = "https://pypi.org/pypi/fs-report/json"


# ── Public API ────────────────────────────────────────────────────────


def get_update_notification(current_version: str) -> Union[str, None]:
    """Return a Rich-formatted notification string, or *None* if up-to-date.

    Never raises — any error is caught and silently ignored.
    """
    try:
        if current_version == "dev":
            return None
        if _is_check_suppressed():
            return None

        latest = _cached_or_fetched_version()
        if latest is None:
            return None

        from packaging.version import parse

        if parse(latest) <= parse(current_version):
            return None

        return (
            f"[yellow]A newer version of fs-report is available: "
            f"[bold]{latest}[/bold] (you have {current_version})[/yellow]\n"
            f"[dim]  Upgrade with: pipx upgrade fs-report\n"
            f"  Run 'fs-report changelog' to see what's new.\n"
            f"  To disable: set FS_REPORT_NO_UPDATE_CHECK=1[/dim]"
        )
    except Exception:  # noqa: BLE001
        return None


# ── Suppression logic ─────────────────────────────────────────────────


_CI_ENV_VARS = ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD", "GITLAB_CI")


def _is_check_suppressed() -> bool:
    """Return *True* when the update check should be skipped."""
    # Explicit opt-out
    if os.environ.get("FS_REPORT_NO_UPDATE_CHECK") == "1":
        return True

    # Config file opt-out
    try:
        from fs_report.cli.common import load_config_file

        cfg = load_config_file()
        if cfg.get("update_check") is False:
            return True
    except Exception:  # noqa: BLE001
        pass

    # CI environments
    for var in _CI_ENV_VARS:
        if os.environ.get(var):
            return True

    # Non-TTY stderr (pipes, cron)
    if not hasattr(sys.stderr, "isatty") or not sys.stderr.isatty():
        return True

    return False


# ── Cache ─────────────────────────────────────────────────────────────


def _read_cache() -> Union[dict, None]:
    """Read the cached version info; return *None* if missing or stale."""
    try:
        if not _CACHE_FILE.exists():
            return None
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        if time.time() - data.get("timestamp", 0) > _CACHE_TTL:
            return None
        return dict(data)
    except Exception:  # noqa: BLE001
        return None


def _write_cache(latest_version: str) -> None:
    """Persist the latest version and current timestamp."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(
            json.dumps({"version": latest_version, "timestamp": time.time()}),
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        pass


# ── PyPI fetch ────────────────────────────────────────────────────────


def _fetch_latest_version() -> Union[str, None]:
    """Query PyPI for the latest fs-report version; return *None* on error."""
    try:
        import httpx

        resp = httpx.get(_PYPI_URL, timeout=3, follow_redirects=True)
        resp.raise_for_status()
        version: str = resp.json()["info"]["version"]
        return version
    except Exception:  # noqa: BLE001
        return None


# ── Orchestration ─────────────────────────────────────────────────────


def _cached_or_fetched_version() -> Union[str, None]:
    """Return the latest version from cache, or fetch and cache it."""
    cached = _read_cache()
    if cached is not None:
        return cached.get("version")

    version = _fetch_latest_version()
    if version is not None:
        _write_cache(version)
    return version
