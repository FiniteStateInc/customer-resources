"""Standard fs-report filesystem paths.

Centralizes the conventions used elsewhere in the codebase:
``~/.fs-report/`` is the per-user state directory (matches the existing
cache, history, logs, logos, and config-file locations).

``get_user_recipes_dir()`` resolves the user-recipes directory by
checking, in order:

  1. Project-local config files: ``./.fs-report.yaml`` then
     ``./.fs-report.yml`` in the process working directory.
  2. Global config files: ``~/.fs-report/config.yaml`` then ``config.yml``.

If any of those declares a top-level ``recipes_dir:`` field, its value
is used. Relative paths anchor to the directory CONTAINING the config
file that supplied them (so a project-local ``recipes_dir: recipes``
resolves to ``./recipes``, not ``~/.fs-report/recipes``). Absolute and
``~``-prefixed values are honored as-is. If no config file declares
the field, the default is ``~/.fs-report/recipes/``.

The user-recipes directory contract is defined in the compound-reports
design spec § 6.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def _user_state_dir() -> Path:
    """``~/.fs-report/`` — root of per-user fs-report state."""
    return Path.home() / ".fs-report"


def get_user_recipes_dir() -> Path:
    """Return the path to the user's recipes directory.

    Resolution order:

    1. If ``~/.fs-report/config.yaml`` exists and contains a top-level
       ``recipes_dir`` field, return that path (expanded for ``~``).
       Useful for committing a team-shared recipes directory to a
       different location.
    2. Otherwise, return ``~/.fs-report/recipes/``.

    The returned path is NOT guaranteed to exist — callers must check
    ``.exists()`` before scanning. This keeps the helper pure and safe
    to call at module-import time.
    """
    cfg, config_source = _read_config_safely()
    override = cfg.get("recipes_dir") if cfg else None
    if isinstance(override, str) and override.strip():
        stripped = override.strip()
        if stripped.startswith("~"):
            # Use Path.home() consistently (rather than os.path.expanduser,
            # which reads $HOME directly and can disagree with Path.home()
            # under tests / sandboxes).
            return Path.home() / stripped.lstrip("~/").lstrip("~")
        path = Path(stripped)
        # Anchor a relative path against the DIRECTORY of the config file
        # that supplied the value. A project-local .fs-report.yaml with
        # `recipes_dir: recipes` resolves to ./recipes; a global config
        # with the same value resolves to ~/.fs-report/recipes. Without
        # this rule, project-local overrides would silently point at the
        # global location.
        if not path.is_absolute() and config_source is not None:
            return config_source.parent / path
        if not path.is_absolute():
            return _user_state_dir() / path
        return path
    return _user_state_dir() / "recipes"


def get_workflows_dir() -> Path:
    """Return ``~/.fs-report/workflows/``, creating it on demand.

    The directory is created with owner-only permissions (0o700, POSIX)
    mirroring the log-dir creation in ``logging_utils``.  The function
    always returns the same fixed path — no config-file override — so it
    is safe to call at import time (idempotent ``mkdir``; no I/O on the
    happy path once the directory exists).
    """
    workflows_dir = _user_state_dir() / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(workflows_dir, 0o700)
    except OSError:
        pass
    return workflows_dir


def _read_config_safely() -> tuple[dict[str, Any], Path | None]:
    """Read fs-report config from CWD first, then ``~/.fs-report/``.

    Returns ``(cfg_dict, source_path)``: the parsed dict plus the path
    to the file it was read from (so callers can anchor relative paths
    correctly). Returns ``({}, None)`` if no config exists. Matches
    the resolution order ``cli/common.load_config_file`` uses elsewhere
    in the codebase. Defensive — a parse error on one candidate falls
    through to the next rather than crashing recipe discovery.
    """
    candidates = [
        Path.cwd() / ".fs-report.yaml",
        Path.cwd() / ".fs-report.yml",
        _user_state_dir() / "config.yaml",
        _user_state_dir() / "config.yml",
    ]
    for config_file in candidates:
        if config_file.exists():
            try:
                import yaml

                with config_file.open(encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict):
                    return data, config_file
            except Exception:
                # Try the next candidate rather than crashing.
                continue
    return {}, None
