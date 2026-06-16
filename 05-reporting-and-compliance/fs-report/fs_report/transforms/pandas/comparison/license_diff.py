"""B3.3: License-diff comparison transform.

Compares two component frames (from /public/v0/components) and identifies
license-set changes and copyleft-family deltas between the two sides.

License data rides on component rows.  License extraction reuses the approach
from ``license_report.py`` (``_API_COPYLEFT_FAMILY_MAP``,
``_extract_copyleft_family``, ``_extract_license_string``).

Design spec references: §3, decisions #6 (provenance), #7 (match key),
#13 (license/copyleft diff), #17 (filter noise), #18 (empty-side handling).
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from fs_report.transforms.pandas.comparison._shared import (
    add_component_match_key,
    filter_noise_components,
    prep_component_frame,
    safe_str,
)

# Import the API copyleft family map from license_report (single source of truth).
# The map is a module-level constant; importing it here keeps the copyleft
# classification in sync with the platform UI rather than duplicating the dict.
from fs_report.transforms.pandas.license_report import (
    _API_COPYLEFT_FAMILY_MAP as _COPYLEFT_MAP,
)
from fs_report.transforms.pandas.license_report import (
    _extract_copyleft_family,
    _extract_license_string,
)

# Only the two copyleft tiers matter for delta tracking (permissive additions
# are not a compliance concern in the way copyleft additions are).
_COPYLEFT_FAMILIES_OF_INTEREST = frozenset({"Strong Copyleft", "Weak Copyleft"})

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_license_set(row: dict[str, Any]) -> frozenset[str]:
    """Extract the set of license names from a component row dict.

    Delegates to the same ``_extract_license_string`` used by license_report,
    then splits on ``,`` to produce individual license tokens.  Empty strings
    are dropped so ``frozenset({"MIT"})`` rather than ``frozenset({"MIT", ""})``.
    """
    raw = _extract_license_string(row)
    if not raw:
        return frozenset()
    return frozenset(s.strip() for s in raw.split(",") if s.strip())


def _extract_display_family(row: dict[str, Any]) -> str:
    """Map a component row's copyleft-family enum to a display string.

    Returns the display string (e.g. ``"Strong Copyleft"``) or ``""`` when
    the component has no recognised copyleft family.
    """
    raw_family = _extract_copyleft_family(row)
    if not raw_family:
        return ""
    return _COPYLEFT_MAP.get(raw_family.strip(), "")


# ---------------------------------------------------------------------------
# Public transform
# ---------------------------------------------------------------------------


def license_diff_transform(
    left_df: pd.DataFrame,
    right_df: pd.DataFrame,
    *,
    left_label: str,
    right_label: str,
    config: dict | None = None,
) -> dict[str, Any]:
    """Diff two component frames' license data and return a template-ready dict.

    Args:
        left_df:      Left-side component DataFrame (license data on rows).
        right_df:     Right-side component DataFrame.
        left_label:   Human-readable label for the left scope.
        right_label:  Human-readable label for the right scope.
        config:       Optional per-run config dict (reserved for future use).

    Returns:
        Dict with keys:
        - ``summary``: counts of license-changed components + copyleft deltas
        - ``license_changes``: list of dicts (components with changed license sets)
        - ``copyleft_deltas``: list of dicts (copyleft family changes on shared components)
        - ``empty_side``: ``"left"`` | ``"right"`` | ``"both"`` | ``None``

    Copyleft delta semantics
    ------------------------
    Three mutually-exclusive cases for shared components:

    1. **Added** — left family is NOT of-interest, right IS of-interest.
       Increments ``copyleft_additions_count``.  Direction: ``"added in {right_label}"``.

    2. **Removed** — left family IS of-interest, right is NOT of-interest.
       Increments ``copyleft_removals_count``.  Direction: ``"removed in {right_label}"``.

    3. **Changed** — BOTH sides have of-interest families AND they differ
       (e.g. Strong Copyleft → Weak Copyleft or reverse).
       Increments ``copyleft_changes_count``.
       Direction: ``"changed ({left_family} → {right_family})"``.
    """
    # Detect empty sides
    left_is_empty = left_df is None or left_df.empty
    right_is_empty = right_df is None or right_df.empty

    empty_side: str | None
    if left_is_empty and right_is_empty:
        empty_side = "both"
    elif left_is_empty:
        empty_side = "left"
    elif right_is_empty:
        empty_side = "right"
    else:
        empty_side = None

    if left_is_empty or right_is_empty:
        return {
            "summary": {
                "left_label": left_label,
                "right_label": right_label,
                "license_changes_count": 0,
                "copyleft_additions_count": 0,
                "copyleft_removals_count": 0,
                "copyleft_changes_count": 0,
            },
            "license_changes": [],
            "copyleft_deltas": [],
            "empty_side": empty_side,
        }

    # Prep frames
    left_df = prep_component_frame(left_df)
    right_df = prep_component_frame(right_df)

    # Decision #17: filter noise on BOTH sides
    left_df = filter_noise_components(left_df)
    right_df = filter_noise_components(right_df)

    # Decision #7: add match keys
    left_df, right_df = add_component_match_key(left_df, right_df)

    # De-duplicate by match_key (keep first occurrence per side).
    # v1 limitation: dedup is by match_key alone, so under a folder: scope the
    # same component across multiple projects collapses to one row (per-project
    # provenance is lost). Project-vs-project is unaffected. See the meta-compare
    # design spec "Out of Scope / Future".
    left_dedup = left_df.drop_duplicates(subset=["match_key"])
    right_dedup = right_df.drop_duplicates(subset=["match_key"])

    # Build match_key → row dicts for license extraction
    left_records: list[dict[str, Any]] = left_dedup.to_dict("records")  # type: ignore[assignment]
    right_records: list[dict[str, Any]] = right_dedup.to_dict("records")  # type: ignore[assignment]
    left_by_key: dict[str, dict[str, Any]] = {
        str(row["match_key"]): row for row in left_records
    }
    right_by_key: dict[str, dict[str, Any]] = {
        str(row["match_key"]): row for row in right_records
    }

    shared_keys = set(left_by_key) & set(right_by_key)

    # -- License changes: shared components whose license sets differ ----------
    license_changes: list[dict[str, Any]] = []
    copyleft_deltas: list[dict[str, Any]] = []

    copyleft_additions = 0
    copyleft_removals = 0
    copyleft_changes = 0

    for key in sorted(
        shared_keys, key=lambda k: safe_str(left_by_key[k].get("name", "")).lower()
    ):
        lrow = left_by_key[key]
        rrow = right_by_key[key]

        l_licenses = _extract_license_set(lrow)
        r_licenses = _extract_license_set(rrow)
        name = safe_str(lrow.get("name", ""))
        project_name = safe_str(lrow.get("project_name", ""))

        if l_licenses != r_licenses:
            license_changes.append(
                {
                    "name": name,
                    "left_licenses": (
                        ", ".join(sorted(l_licenses)) if l_licenses else "(none)"
                    ),
                    "right_licenses": (
                        ", ".join(sorted(r_licenses)) if r_licenses else "(none)"
                    ),
                    "project_name": project_name,
                }
            )

        # Copyleft delta tracking
        l_family = _extract_display_family(lrow)
        r_family = _extract_display_family(rrow)

        l_is_of_interest = l_family in _COPYLEFT_FAMILIES_OF_INTEREST
        r_is_of_interest = r_family in _COPYLEFT_FAMILIES_OF_INTEREST

        if l_family == r_family:
            # No copyleft tier change — skip
            pass
        elif r_is_of_interest and not l_is_of_interest:
            # Case 1: Added in right (none → copyleft)
            copyleft_additions += 1
            copyleft_deltas.append(
                {
                    "name": name,
                    "family": r_family,
                    "direction": f"added in {right_label}",
                    "project_name": project_name,
                }
            )
        elif l_is_of_interest and not r_is_of_interest:
            # Case 2: Removed in right (copyleft → none)
            copyleft_removals += 1
            copyleft_deltas.append(
                {
                    "name": name,
                    "family": l_family,
                    "direction": f"removed in {right_label}",
                    "project_name": project_name,
                }
            )
        elif l_is_of_interest and r_is_of_interest:
            # Case 3: Inter-tier change (e.g. Strong Copyleft → Weak Copyleft)
            copyleft_changes += 1
            copyleft_deltas.append(
                {
                    "name": name,
                    "family": r_family,
                    "direction": f"changed ({l_family} → {r_family})",
                    "project_name": project_name,
                }
            )

    # Sort by name ascending — decision #12
    license_changes.sort(key=lambda r: r["name"].lower())
    copyleft_deltas.sort(key=lambda r: r["name"].lower())

    summary = {
        "left_label": left_label,
        "right_label": right_label,
        "license_changes_count": len(license_changes),
        "copyleft_additions_count": copyleft_additions,
        "copyleft_removals_count": copyleft_removals,
        "copyleft_changes_count": copyleft_changes,
    }

    return {
        "summary": summary,
        "license_changes": license_changes,
        "copyleft_deltas": copyleft_deltas,
        "empty_side": None,
    }
