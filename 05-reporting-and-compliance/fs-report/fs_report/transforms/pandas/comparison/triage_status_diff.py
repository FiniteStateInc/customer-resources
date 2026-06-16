"""B3.4: Triage-status-diff comparison transform.

Compares triage decisions (VEX statuses) across two findings frames and
produces a template-ready dict with:

- ``status_divergence``: findings present in BOTH sides, BOTH triaged, but
  with different statuses (incl. suppressed-vs-fixed divergence).
- ``triaged_left_untriaged_right``: present in both, left triaged, right untriaged.
- ``triaged_right_untriaged_left``: mirror direction.

Scope note: findings present on only ONE side are finding_diff / component_diff
territory — they are NOT reported here.

Design spec references: §3, Resolved decision #9 (triage divergence sections),
#8 (triaged = NOT is_untriaged()), #6 (provenance), #18 (empty-side handling).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd

from fs_report.transforms.pandas.comparison._shared import (
    _sorted_unique_blank_filtered,
    add_finding_match_key,
    is_untriaged,
    pick_needs_action_representative,
    prep_findings_frame,
    safe_str,
    sort_findings_rows,
    untriaged_owners,
)

# ---------------------------------------------------------------------------
# Public transform
# ---------------------------------------------------------------------------


def triage_status_diff_transform(
    left_df: pd.DataFrame | None,
    right_df: pd.DataFrame | None,
    *,
    left_label: str,
    right_label: str,
    config: dict | None = None,
) -> dict[str, Any]:
    """Diff triage decisions across two findings frames and return a template-ready dict.

    Triaged is defined as NOT is_untriaged(status) — see _shared.is_untriaged.
    EXPLOITABLE is triaged (the team assessed it), but still needs action per
    needs_action(). NULL / OPEN / IN_TRIAGE / NO_STATUS are untriaged.

    Findings present on only one side are NOT included (that is finding_diff
    / component_diff territory).

    Args:
        left_df:     Left-side findings DataFrame.
        right_df:    Right-side findings DataFrame.
        left_label:  Human-readable label for the left scope.
        right_label: Human-readable label for the right scope.
        config:      Optional per-run config dict (reserved for future use).

    Returns:
        Dict with keys:
        - ``summary``: divergence counts + labels
        - ``status_divergence``: both triaged, different status (incl. suppressed-vs-fixed)
        - ``triaged_left_untriaged_right``: left triaged, right untriaged
        - ``triaged_right_untriaged_left``: right triaged, left untriaged
        - ``empty_side``: ``"left"`` | ``"right"`` | ``"both"`` | ``None``
    """
    # Detect empty sides before any processing
    left_is_empty = left_df is None or (
        isinstance(left_df, pd.DataFrame) and left_df.empty
    )
    right_is_empty = right_df is None or (
        isinstance(right_df, pd.DataFrame) and right_df.empty
    )

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
                "status_divergence_count": 0,
                "triaged_left_untriaged_right_count": 0,
                "triaged_right_untriaged_left_count": 0,
            },
            "status_divergence": [],
            "triaged_left_untriaged_right": [],
            "triaged_right_untriaged_left": [],
            "empty_side": empty_side,
        }

    # Normalize findings frames (both are non-None at this point — the early
    # return above fires when either is None or empty).
    assert left_df is not None and right_df is not None  # for mypy
    left_df = prep_findings_frame(left_df)
    right_df = prep_findings_frame(right_df)

    # Add match keys (mutates in place — per _shared contract)
    add_finding_match_key(left_df)
    add_finding_match_key(right_df)

    # Folder-mode per-project provenance (§4a): iterate the FULL pre-dedup rows
    # per match_key instead of a first-wins representative, so both the BUCKET
    # DECISION and owner aggregation are per-project — applied symmetrically with
    # finding_diff. The three triage buckets are INDEPENDENT per-key checks (NOT
    # a mutually-exclusive if/elif): when the laggard side carries both a triaged
    # and an untriaged variant for one key, that key can legitimately surface as
    # BOTH a divergence row AND a propagation row ("allow both"). Each bucket
    # counts a key at most once; in project-vs-project mode (one status per side)
    # a key still lands in exactly one bucket, so the result is unchanged.
    left_all_records: list[dict[str, Any]] = left_df.to_dict("records")  # type: ignore[assignment]
    right_all_records: list[dict[str, Any]] = right_df.to_dict("records")  # type: ignore[assignment]
    left_rows_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in left_all_records:
        left_rows_by_key[str(r["match_key"])].append(r)
    right_rows_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in right_all_records:
        right_rows_by_key[str(r["match_key"])].append(r)

    # Only process keys present in BOTH sides; sorted for deterministic output order
    shared_keys = sorted(set(left_rows_by_key) & set(right_rows_by_key))

    status_divergence: list[dict[str, Any]] = []
    triaged_left_untriaged_right: list[dict[str, Any]] = []
    triaged_right_untriaged_left: list[dict[str, Any]] = []

    for key in shared_keys:
        left_rows = left_rows_by_key[key]
        right_rows = right_rows_by_key[key]

        # Split each side's variants into triaged vs untriaged (per-project, over
        # the full pre-dedup rows). The bucket checks below read these splits
        # independently so a key with mixed variants can land in several buckets.
        left_triaged_rows = [
            r for r in left_rows if not is_untriaged(str(r.get("status", "")).strip())
        ]
        left_untriaged_rows = [
            r for r in left_rows if is_untriaged(str(r.get("status", "")).strip())
        ]
        right_triaged_rows = [
            r for r in right_rows if not is_untriaged(str(r.get("status", "")).strip())
        ]
        right_untriaged_rows = [
            r for r in right_rows if is_untriaged(str(r.get("status", "")).strip())
        ]

        # --- Bucket 1: status_divergence (both sides triaged, statuses differ) ---
        # Representative per side = highest-severity TRIAGED variant (§4a
        # comparator: severity → risk desc → lexicographic project_name).
        if left_triaged_rows and right_triaged_rows:
            lrep = pick_needs_action_representative(left_triaged_rows)
            rrep = pick_needs_action_representative(right_triaged_rows)
            assert lrep is not None and rrep is not None  # both lists non-empty
            left_status = str(lrep.get("status", "")).strip().upper()
            right_status = str(rrep.get("status", "")).strip().upper()
            if left_status != right_status:
                # Owners = the UNION of both sides' projects for this key (M1-10).
                union_owners = _sorted_unique_blank_filtered(
                    [r.get("project_name") for r in left_rows]
                    + [r.get("project_name") for r in right_rows]
                )
                status_divergence.append(
                    {
                        "display_id": safe_str(lrep.get("display_id", "")),
                        "component_name": safe_str(lrep.get("component_name", "")),
                        "severity": safe_str(lrep.get("severity", "")),
                        "risk": lrep.get("risk"),
                        "left_status": left_status,
                        "right_status": right_status,
                        "project_names": union_owners,
                    }
                )

        # --- Bucket 2: triaged_left_untriaged_right (propagation L→R) ---
        # Emit when left has a triaged variant AND right has an untriaged variant.
        # The untriaged (laggard) side supplies the representative row fields;
        # left_status comes from the left triaged representative.
        if left_triaged_rows and right_untriaged_rows:
            lrep = pick_needs_action_representative(left_triaged_rows)
            rep = pick_needs_action_representative(right_untriaged_rows)
            assert lrep is not None and rep is not None
            triaged_left_untriaged_right.append(
                {
                    "display_id": safe_str(rep.get("display_id", "")),
                    "component_name": safe_str(rep.get("component_name", "")),
                    "severity": safe_str(rep.get("severity", "")),
                    "risk": rep.get("risk"),
                    "left_status": str(lrep.get("status", "")).strip().upper(),
                    "project_names": untriaged_owners(right_rows),
                }
            )

        # --- Bucket 3: triaged_right_untriaged_left (propagation R→L) ---
        # Mirror of bucket 2: right triaged AND left untriaged.
        if right_triaged_rows and left_untriaged_rows:
            rrep = pick_needs_action_representative(right_triaged_rows)
            rep = pick_needs_action_representative(left_untriaged_rows)
            assert rrep is not None and rep is not None
            triaged_right_untriaged_left.append(
                {
                    "display_id": safe_str(rep.get("display_id", "")),
                    "component_name": safe_str(rep.get("component_name", "")),
                    "severity": safe_str(rep.get("severity", "")),
                    "risk": rep.get("risk"),
                    "right_status": str(rrep.get("status", "")).strip().upper(),
                    "project_names": untriaged_owners(left_rows),
                }
            )

    # Sort all result lists by severity-then-risk
    status_divergence = sort_findings_rows(status_divergence)
    triaged_left_untriaged_right = sort_findings_rows(triaged_left_untriaged_right)
    triaged_right_untriaged_left = sort_findings_rows(triaged_right_untriaged_left)

    summary = {
        "left_label": left_label,
        "right_label": right_label,
        "status_divergence_count": len(status_divergence),
        "triaged_left_untriaged_right_count": len(triaged_left_untriaged_right),
        "triaged_right_untriaged_left_count": len(triaged_right_untriaged_left),
    }

    return {
        "summary": summary,
        "status_divergence": status_divergence,
        "triaged_left_untriaged_right": triaged_left_untriaged_right,
        "triaged_right_untriaged_left": triaged_right_untriaged_left,
        "empty_side": None,
    }
