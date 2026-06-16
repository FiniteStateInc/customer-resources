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
    "ai_analysis": False,
    "logo": "",
    "product_type": "generic",
    "network_exposure": "unknown",
    "regulatory": "",
    "deployment_notes": "",
    # SP3: uploaded-file path globals (empty = none); route through the
    # diff-vs-default branch (NOT _NO_GLOBAL_KEYS), mirroring regulatory.
    "scoring_file": "",
    "context_file": "",
    "pinned_report": "",
    "pinned_project": "",
    "pinned_version": "",
    # Folder-targeting (design §4): stores the pinned folder's ID (consistent
    # with the ID-keyed scope cascade). shell_context resolves its display name
    # at render time and clears the pin if the ID is no longer a known folder.
    "pinned_folder": "",
    "open_only": False,
    "detailed": False,
    "standalone": False,
    "vex_override": False,
    # SP2: auto-apply VEX toggle. Baseline False (off) so a card override stores
    # only when toggled on, mirroring vex_override. Not a Settings-page field;
    # destructive autotriage is configured per-run on the TP surfaces only.
    "autotriage": False,
    "component_match": "contains",
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
        # Keys that match their default value — we drop these from the persisted
        # file so the user can reset a previously-customised setting (e.g.
        # selecting "(default Finite State logo)") and have the change stick.
        reset_keys: set[str] = set()

        for key, value in self._data.items():
            if key in skip_keys:
                continue
            if key in DEFAULTS and value == DEFAULTS[key]:
                reset_keys.add(key)
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

        for key in reset_keys:
            existing.pop(key, None)

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
        d = str(self._data.get("domain", "")).strip()
        if d.startswith(("http://", "https://")):
            d = d.split("://", 1)[1]
        return d.rstrip("/")

    @property
    def has_config(self) -> bool:
        """True if the user has a domain and token configured."""
        return bool(self.token) and bool(self.domain)


# ── Per-recipe override helpers (Command Center card config) ──────────
#
# ``recipe_overrides`` is a new top-level config key (NOT in DEFAULTS): a map
# of *lowercase* recipe name -> a sparse dict of fields that differ from the
# global config / supply a recipe's required card input.  It round-trips via
# ``WebAppState.reload``'s ``{**DEFAULTS, **config_file}`` merge; absent ->
# ``{}`` via ``state.get("recipe_overrides", {})``.
#
# Canonical key rule: every lookup uses ``recipe_name.lower()``.  Display names
# stay title-case in the UI; the key is lowercase.


def recipe_override(state: WebAppState, recipe_name: str) -> dict[str, Any]:
    """Return the saved override dict for ``recipe_name`` (canonical key).

    Guarded so a malformed (non-dict) ``recipe_overrides`` map, or a non-dict
    recipe value, degrades to ``{}`` and never raises.
    """
    overrides = state.get("recipe_overrides", {})
    if not isinstance(overrides, dict):
        return {}
    value = overrides.get(recipe_name.lower())
    if not isinstance(value, dict):
        return {}
    return value


def effective_value(state: WebAppState, recipe_name: str, key: str) -> Any:
    """Resolve a field's *effective* value for a recipe.

    The recipe's override value if present, else the global ``state.get(key)``.
    """
    override = recipe_override(state, recipe_name)
    if key in override:
        return override[key]
    return state.get(key)


def needs_setup(state: WebAppState, recipe: Any) -> bool:
    """Whether ``recipe`` declares a card-suppliable required input not yet met.

    True iff the recipe declares a card-suppliable required input — ``requires_cve``
    (→ ``cve_filter``) or ``requires_component`` (→ ``component_filter``, B4 #25) —
    and that input has no effective value (neither a per-card override nor the
    global ``state.get(<key>)``).  The scope gate (``requires_project*``) is
    run-bar-suppliable and is deliberately NOT part of this computation.

    Strip before the truthiness check so a whitespace-only effective value (e.g.
    ``"   "``) is treated as unset — matching missing_card_inputs and the engine's
    requires_* checks (all strip). Without this, a whitespace-only global value
    would make needs_setup return False, let the card run, then fail the engine's
    stripped check — a doomed run (PR #117 review Fix 3).
    """
    for flag, key in (
        ("requires_cve", "cve_filter"),
        ("requires_component", "component_filter"),
    ):
        if (
            getattr(recipe, flag, False)
            and not str(effective_value(state, recipe.name, key) or "").strip()
        ):
            return True
    return False


def missing_card_inputs(recipe: Any, override: dict[str, Any]) -> list[str]:
    """Card-suppliable required inputs missing from ``override``, driven by flags.

    ``requires_cve`` -> require a non-empty ``cve_filter``; ``requires_component``
    -> require a non-empty ``component_filter`` (B4 #25 — Component Impact /
    Component Remediation Package, whose component IS the primary input). A
    ``component_filter`` is NOT required for recipes that don't declare
    ``requires_component`` (it stays an optional narrowing there).
    ``requires_project*`` is run-bar-suppliable, not a card input, so it is not
    checked here.
    """
    missing: list[str] = []
    if getattr(recipe, "requires_cve", False):
        if not str(override.get("cve_filter", "")).strip():
            missing.append("cve_filter")
    if getattr(recipe, "requires_component", False):
        if not str(override.get("component_filter", "")).strip():
            missing.append("component_filter")
    return missing
