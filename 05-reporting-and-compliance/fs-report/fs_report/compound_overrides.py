# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

"""Compound section-override primitives (Builder compound authoring — Task A).

A compound recipe may carry an authored ``global`` block plus per-section
``overrides``.  This module is the single home for:

* :data:`COMPOUND_OVERRIDE_WHITELIST` — the **RESTRICTED** set of engine keys a
  section may override.  Deliberately a *safe subset*: scope, finding-types,
  current-version-only, AI, and date.  Destructive / workflow-only keys
  (``autotriage``, ``error_policy``, ``vex_override``, …) are EXCLUDED — a
  section can never silently turn on a VEX write or change failure policy.
* :func:`normalize_compound_global` — mirrors the workflow global date-mode
  normalization (``fs_report.workflow_store._normalize_global``): ``period`` and
  ``start``/``end`` are mutually exclusive (range wins when both are present),
  and the ``period_touched`` / ``range_touched`` / ``target_agnostic`` intent
  flags are preserved verbatim.  We deliberately reuse the workflow semantics
  rather than invent new ones so the two date-mode contracts can't drift.
* :func:`normalize_section_overrides` — keep ONLY whitelisted keys.
* :func:`effective_child_config` — merge a run-level effective config with a
  section's overrides, applying the same period/range mutual-exclusion the
  workflow ``_effective_step_config`` applies via
  ``merge_with_period_range_clearing``.

This module imports only ``fs_report.workflow_store`` (dependency-light), so it
is safe to import from both the web routers and ``report_engine`` without an
import cycle.
"""

from __future__ import annotations

from typing import Any

from fs_report.workflow_store import coerce_bool

# ---------------------------------------------------------------------------
# RESTRICTED per-section override whitelist
# ---------------------------------------------------------------------------
#
# A compound SECTION may override ONLY these engine keys.  This is intentionally
# a *safe subset* of the workflow per-step override set — it omits every
# destructive / workflow-control key.  Excluded on purpose (do NOT add without a
# spec change): ``autotriage`` / ``autotriage_status`` (write VEX to the
# platform), ``error_policy`` (workflow-loop control, meaningless for a compound
# section), ``vex_override``, ``overwrite``, and the comparison-only
# ``baseline_*`` / ``current_version`` keys.
COMPOUND_OVERRIDE_WHITELIST: frozenset[str] = frozenset(
    {
        # Scope
        "project_filter",
        "folder_filter",
        "version_filter",
        # Finding-type + version selection
        "finding_types",
        "current_version_only",
        # AI
        "ai",
        "ai_depth",
        # Date mode (period XOR start/end — handled by the merge below)
        "period",
        "start",
        "end",
    }
)

# Date-mode keys, used by the period/range mutual-exclusion merge below.
_DATE_KEYS: tuple[str, ...] = ("period", "start", "end")

# Override keys that must be coerced str→bool (a hand-edited / inline YAML
# ``"ai": "false"`` must become ``False``, never the truthy ``bool("false")``).
_BOOL_KEYS: frozenset[str] = frozenset({"ai", "current_version_only"})


def _coerce_value(key: str, value: Any) -> Any:
    """Coerce a single override value to its typed form (bools only here)."""
    if key in _BOOL_KEYS:
        return coerce_bool(value)
    return value


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_section_overrides(raw: Any) -> dict[str, Any]:
    """Return only whitelisted override keys from *raw*; drop everything else.

    Non-dict input yields ``{}``.  Empty-string / ``None`` values are kept as
    given (the caller's downstream emptiness filter handles them); the only
    filtering here is membership in :data:`COMPOUND_OVERRIDE_WHITELIST`.
    """
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if k in COMPOUND_OVERRIDE_WHITELIST}


def normalize_compound_global(raw: Any) -> dict[str, Any]:
    """Normalize a compound ``global`` block, mirroring the workflow contract.

    Reuses the workflow global date-mode semantics
    (``fs_report.workflow_store._normalize_global``):

    * ``period`` and ``start``/``end`` are mutually exclusive — when both a
      complete range and a period are present, the RANGE wins and ``period`` is
      dropped (``create_config`` gives ``period`` precedence over start/end, so
      a stored conflict would silently shadow the range).
    * Neither set ⇒ default ``period = "30d"``.
    * The intent flags ``period_touched`` / ``range_touched`` /
      ``target_agnostic`` are preserved verbatim (plain persisted bools, NOT
      engine keys — they steer precedence in :func:`effective_child_config`).
    * Scope (``project_filter`` / ``folder_filter`` / ``version_filter``),
      ``finding_types``, ``current_version_only``, ``ai``, and ``ai_depth`` are
      carried through when set.

    Returns a fresh dict; ``raw`` is never mutated.
    """
    if not isinstance(raw, dict):
        raw = {}

    g: dict[str, Any] = {}

    # --- Non-date carry-through (only when set) -----------------------------
    for key in (
        "project_filter",
        "folder_filter",
        "version_filter",
        "finding_types",
        "current_version_only",
        "ai",
        "ai_depth",
    ):
        if key in raw and raw[key] is not None and raw[key] != "":
            g[key] = _coerce_value(key, raw[key])

    # --- Intent flags (plain persisted bools) -------------------------------
    for flag in ("period_touched", "range_touched", "target_agnostic"):
        if flag in raw and raw[flag] is not None and raw[flag] != "":
            g[flag] = coerce_bool(raw[flag])

    # --- Date-mode resolution (period XOR range) ----------------------------
    period = raw.get("period")
    start = raw.get("start")
    end = raw.get("end")
    start = start if (start is not None and str(start).strip() != "") else None
    end = end if (end is not None and str(end).strip() != "") else None
    period = period if (period is not None and str(period).strip() != "") else None

    if start is not None and end is not None:
        # Range wins — period stays absent so create_config cannot shadow it.
        g["start"] = start
        g["end"] = end
    elif period is not None:
        g["period"] = period
    else:
        g["period"] = "30d"

    return g


# ---------------------------------------------------------------------------
# Period / range mutual-exclusion merge (mirrors the run-path helper)
# ---------------------------------------------------------------------------


def _merge_with_period_range_clearing(
    base: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    """Merge ``incoming`` over ``base`` with date-mode conflict clearing.

    Identical semantics to
    ``fs_report.web.routers.run.merge_with_period_range_clearing`` (kept as a
    small local copy to avoid importing the heavy web router into the engine):

    * ``incoming`` carries BOTH a non-empty ``start`` AND ``end`` → drop
      ``period`` from ``base`` (range wins).
    * Else ``incoming`` carries a non-empty ``period`` → drop ``start`` / ``end``
      from ``base`` (period wins).
    * Otherwise → plain merge.

    Returns a NEW dict; neither input is mutated.
    """

    def _nonempty(v: Any) -> bool:
        return v is not None and str(v).strip() != ""

    start_in = _nonempty(incoming.get("start"))
    end_in = _nonempty(incoming.get("end"))
    period_in = _nonempty(incoming.get("period"))

    effective_base = dict(base)
    if start_in and end_in:
        effective_base.pop("period", None)
    elif period_in:
        effective_base.pop("start", None)
        effective_base.pop("end", None)
    return {**effective_base, **incoming}


def effective_child_config(
    run_effective: dict[str, Any], section_overrides: Any
) -> dict[str, Any]:
    """Return ``run_effective ⊕ section_overrides`` for one compound child.

    Precedence, highest→lowest: section override ▸ run-level effective config
    ▸ recipe/engine defaults (the caller folds engine defaults in downstream).

    Mirrors the workflow ``_effective_step_config`` layering:

    * Only whitelisted, non-empty override keys participate (control / unknown
      keys are stripped via :func:`normalize_section_overrides`).
    * Override values are coerced (bool keys str→bool).
    * Date-mode conflicts resolve via :func:`_merge_with_period_range_clearing`
      so a section that sets a complete ``start``+``end`` clears an inherited
      run-level ``period`` (and vice-versa) — a child can never carry both.

    Returns a NEW dict; neither input is mutated.
    """
    overrides = normalize_section_overrides(section_overrides)
    incoming: dict[str, Any] = {}
    for k, v in overrides.items():
        if v is None or v == "":
            continue
        incoming[k] = _coerce_value(k, v)
    return _merge_with_period_range_clearing(dict(run_effective), incoming)
