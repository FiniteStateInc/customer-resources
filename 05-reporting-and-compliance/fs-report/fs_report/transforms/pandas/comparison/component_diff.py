"""B3.3: Component-diff comparison transform.

Compares two component frames (from /public/v0/components) and produces a
template-ready dict with shared / left-only / right-only / version-skew
classifications.

Design spec references: §3, decisions #6 (provenance column), #7 (match key),
#12 (sort order), #17 (filter noise), #18 (empty-side handling).
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from fs_report.transforms.pandas.comparison._shared import (
    add_component_match_key,
    filter_noise_components,
    leader_component_version,
    prep_component_frame,
    project_names_for,
    safe_str,
    version_owners,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _prep_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Flatten, ensure required columns, and fill missing string values."""
    df = prep_component_frame(df)
    # version is component_diff-specific (not in the shared skeleton)
    if "version" not in df.columns:
        df["version"] = ""
    else:
        df["version"] = df["version"].fillna("").astype(str)
    return df


# ---------------------------------------------------------------------------
# Public transform
# ---------------------------------------------------------------------------


def component_diff_transform(
    left_df: pd.DataFrame,
    right_df: pd.DataFrame,
    *,
    left_label: str,
    right_label: str,
    config: dict | None = None,
) -> dict[str, Any]:
    """Diff two component frames and return a template-ready dict.

    Args:
        left_df:      Left-side component DataFrame.
        right_df:     Right-side component DataFrame.
        left_label:   Human-readable label for the left scope (echoed in output).
        right_label:  Human-readable label for the right scope.
        config:       Optional per-run config dict (reserved for future use).

    Returns:
        Dict with keys:
        - ``summary``: counts + labels (all count keys end in ``_count``)
        - ``version_skew``: list of dicts (shared components with different versions)
        - ``left_only``: list of dicts (components only on the left)
        - ``right_only``: list of dicts (components only on the right)
        - ``empty_side``: ``"left"`` | ``"right"`` | ``"both"`` | ``None``
    """
    # Detect empty sides before any processing
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
                "shared_count": 0,
                "left_only_count": 0,
                "right_only_count": 0,
                "version_skew_count": 0,
            },
            "version_skew": [],
            "left_only": [],
            "right_only": [],
            "empty_side": empty_side,
        }

    # Prep frames
    left_df = _prep_frame(left_df)
    right_df = _prep_frame(right_df)

    # Decision #17: filter noise on BOTH sides
    left_df = filter_noise_components(left_df)
    right_df = filter_noise_components(right_df)

    # Decision #7: add match keys. The returned frames are the FULL (pre-dedup)
    # prepped frames, kept for folder-mode owner aggregation (§4a) and
    # leader_component_version version resolution (§4b).
    left_df, right_df = add_component_match_key(left_df, right_df)

    # De-duplicate by match_key (keep first occurrence per side) for key-set
    # membership only — the shared / left-only / right-only PARTITION is
    # presence-based, so dedup here is correct. Per-project provenance is
    # recovered separately from the full frames below.
    left_dedup = left_df.drop_duplicates(subset=["match_key"])
    right_dedup = right_df.drop_duplicates(subset=["match_key"])

    # Build match_key → row dicts for O(1) lookup (mirrors license_diff style)
    left_records: list[dict[str, Any]] = left_dedup.to_dict("records")  # type: ignore[assignment]
    right_records: list[dict[str, Any]] = right_dedup.to_dict("records")  # type: ignore[assignment]
    left_by_key: dict[str, dict[str, Any]] = {
        str(row["match_key"]): row for row in left_records
    }
    right_by_key: dict[str, dict[str, Any]] = {
        str(row["match_key"]): row for row in right_records
    }

    left_keys = set(left_by_key)
    right_keys = set(right_by_key)
    shared_keys = left_keys & right_keys
    left_only_keys = left_keys - right_keys
    right_only_keys = right_keys - left_keys

    # -- Version skew: shared components whose version field differs ------------
    # left_version / right_version are resolved via leader_component_version
    # (highest version of the name across folder projects) so §01 and §02 agree
    # with finding_diff's fix_target. They resolve IDENTICALLY to finding_diff's
    # fix_target — RAW leader_component_version with NO fallback (M1-2). The
    # earlier `or safe_str(row.version)` fallback meant §01 painted a version
    # arrow from the deduped ROW version on the unhappy path (falsy resolution)
    # while finding_diff's fix_target (no fallback) yielded None → §02 rendered
    # "Rebuild" with no arrow, so §01 and §02 DISAGREED on the null/pathological
    # path. In the normal case leader_component_version returns the real max
    # version for any shared component (unchanged display); only the falsy case
    # changes, and now both surfaces null-render that side (no spurious arrow).
    # Owners are kept PER SIDE (which variants carry which version) — never a
    # single merged set (§4a M2-2). They are VERSION-SPECIFIC (which variants
    # carry the DISPLAYED max version), not presence-only: when a side has the
    # component at several versions, a presence list over-states the owners of
    # the version actually shown (§4a M2-2/M3-2).
    version_skew_rows: list[dict[str, Any]] = []
    for key in sorted(
        shared_keys, key=lambda k: safe_str(left_by_key[k].get("name", "")).lower()
    ):
        lrow = left_by_key[key]
        name = safe_str(lrow.get("name", ""))
        lver = leader_component_version(left_df, name)
        rver = leader_component_version(right_df, name)
        if lver != rver:
            version_skew_rows.append(
                {
                    "name": name,
                    "type": safe_str(lrow.get("type", "")),
                    "left_version": lver,
                    "right_version": rver,
                    "left_project_names": version_owners(left_df, key, lver),
                    "right_project_names": version_owners(right_df, key, rver),
                }
            )
    # Already sorted by name (ascending) from the loop above — decision #12.
    # (Explicit sort below mirrors the left_only/right_only pattern for symmetry.)
    version_skew_rows.sort(key=lambda r: str(r["name"]).lower())

    # -- Left-only table --------------------------------------------------------
    left_only_rows: list[dict[str, Any]] = []
    for key in left_only_keys:
        row = left_by_key[key]
        left_only_rows.append(
            {
                "name": safe_str(row.get("name", "")),
                "type": safe_str(row.get("type", "")),
                "version": safe_str(row.get("version", "")),
                "left_project_names": project_names_for(left_df, key),
            }
        )
    # Sort by name ascending — decision #12
    left_only_rows.sort(key=lambda r: str(r["name"]).lower())

    # -- Right-only table -------------------------------------------------------
    right_only_rows: list[dict[str, Any]] = []
    for key in right_only_keys:
        row = right_by_key[key]
        right_only_rows.append(
            {
                "name": safe_str(row.get("name", "")),
                "type": safe_str(row.get("type", "")),
                "version": safe_str(row.get("version", "")),
                "right_project_names": project_names_for(right_df, key),
            }
        )
    right_only_rows.sort(key=lambda r: str(r["name"]).lower())

    # -- Summary ----------------------------------------------------------------
    summary = {
        "left_label": left_label,
        "right_label": right_label,
        "shared_count": len(shared_keys),
        "left_only_count": len(left_only_keys),
        "right_only_count": len(right_only_keys),
        "version_skew_count": len(version_skew_rows),
    }

    return {
        "summary": summary,
        "version_skew": version_skew_rows,
        "left_only": left_only_rows,
        "right_only": right_only_rows,
        "empty_side": None,
    }
