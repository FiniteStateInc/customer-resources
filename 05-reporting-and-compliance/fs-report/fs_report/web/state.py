"""Web application state management.

``WebAppState`` replaces the TUI's ``self.app.state`` dictionary.  It loads
from ``~/.fs-report/config.yaml``, merges env vars, and persists changes back.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path.home() / ".fs-report"
_CONFIG_FILE = _CONFIG_DIR / "config.yaml"

DEFAULTS: dict[str, Any] = {
    "cache_ttl": "4",
    "period": "30d",
    "output_dir": "./output",
    "finding_types": "cve",
    "current_version_only": True,
    "overwrite": False,
    "verbose": False,
    "ai": False,
    "ai_depth": "summary",
    "ai_prompts": False,
}


class WebAppState:
    """Server-side state container for the web UI."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self.reload()

    # ── Public API ────────────────────────────────────────────────

    def reload(self) -> None:
        """Rebuild state from defaults -> config file -> env vars."""
        from fs_report.cli.common import load_config_file

        cfg = load_config_file()
        self._data = {**DEFAULTS, **cfg}

        # Env vars take highest priority for connection settings
        token = os.getenv("FINITE_STATE_AUTH_TOKEN", cfg.get("token", ""))
        domain = os.getenv("FINITE_STATE_DOMAIN", cfg.get("domain", ""))
        self._data["token"] = token
        self._data["domain"] = domain

    def save(self, *, include_token: bool = False) -> None:
        """Persist state to ``~/.fs-report/config.yaml``.

        By default the token is excluded (it usually comes from an env var).
        Pass ``include_token=True`` to persist a user-supplied token (e.g.
        during initial setup).
        """
        skip_keys: set[str] = set() if include_token else {"token"}
        to_save: dict[str, Any] = {}

        for key, value in self._data.items():
            if key in skip_keys:
                continue
            if key in DEFAULTS and value == DEFAULTS[key]:
                continue
            to_save[key] = value

        # Always save domain if set
        if self._data.get("domain"):
            to_save["domain"] = self._data["domain"]

        # Merge with existing config to preserve unmanaged keys
        existing: dict[str, Any] = {}
        if _CONFIG_FILE.is_file():
            try:
                with open(_CONFIG_FILE, encoding="utf-8") as f:
                    existing = yaml.safe_load(f) or {}
            except Exception:
                pass

        merged = {**existing, **to_save}

        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write("# Finite State Report Kit configuration\n")
            f.write(
                "# CLI flags override these values; env vars override config file.\n"
            )
            yaml.safe_dump(merged, f, default_flow_style=False, sort_keys=True)

    # ── Dict-like access ──────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def update(self, data: dict[str, Any]) -> None:
        self._data.update(data)

    def to_dict(self) -> dict[str, Any]:
        """Return a shallow copy of the underlying data."""
        return dict(self._data)

    @property
    def token(self) -> str:
        return str(self._data.get("token", ""))

    @property
    def domain(self) -> str:
        return str(self._data.get("domain", ""))

    @property
    def has_config(self) -> bool:
        """True if the user has a domain and token configured."""
        return bool(self.token) and bool(self.domain)
