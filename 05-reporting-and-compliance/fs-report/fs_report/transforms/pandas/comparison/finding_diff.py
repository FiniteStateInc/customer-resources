"""B3.4: Finding-diff comparison transform.

Compares two findings frames (from /public/v0/findings) and produces a
template-ready dict showing:

- ``port_fixes_left_to_right``: findings fixed in left but still open in right
  (portable fix candidates).
- ``port_fixes_right_to_left``: the mirror direction.
- ``summary``: counts and metadata.

Design spec references: §3, Resolved decisions #8 (classification rules),
#16 (component-inventory evidence), #6 (provenance), #18 (empty-side handling).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd

from fs_report.transforms.pandas.comparison._shared import (
    FIXED_STATUSES,
    SUPPRESSED_STATUSES,
    add_finding_match_key,
    filter_noise_components,
    leader_component_version,
    needs_action,
    pick_needs_action_representative,
    port_fix_owners,
    prep_component_frame,
    prep_findings_frame,
    safe_str,
    sort_findings_rows,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_inventory_set(
    components: pd.DataFrame | None,
) -> tuple[set[str] | None, bool]:
    """Build a case-insensitive component name set from a component inventory.

    Returns:
        (name_set, inventory_available) where:
        - name_set is a set of lowercased names, or None when not available.
        - inventory_available is True when components were provided and processed.
    """
    if components is None:
        return None, False
    components = prep_component_frame(components)
    components = filter_noise_components(components)
    if components.empty:
        return set(), True
    names = components["name"].fillna("").astype(str).str.strip().str.lower()
    return set(names.tolist()), True


def _classify_port_fix(
    right_row: dict[str, Any],
    left_rows: list[dict[str, Any]],
    left_names: set[str] | None,
    inventory_available: bool,
) -> tuple[str | None, str | None, bool]:
    """Classify one needs-action finding in right vs the leader's per-project rows.

    Status-aware over the FULL per-project leader rows for the key (folder-mode
    provenance, §4a): the opposite-side lookup is per-project, not a first-wins
    representative — so a key the leader fixed in one project (but left open in
    another) is still caught instead of being classified by whichever leader row
    deduped first.  The classification *predicate* is unchanged: leader
    fixed/absent AND laggard needs-action.

    Args:
        right_row:           One needs-action laggard finding row.
        left_rows:           All leader rows for the same match_key (empty when
                             the key is absent on the leader side).
        left_names:          Lowercased leader inventory name set (or ``None``).
        inventory_available: Whether both inventories were supplied.

    Returns:
        (fix_evidence, suppressed_reason, is_needs_action_both)

        fix_evidence:
          - Non-None string → include as a port-fix row with this evidence.
          - None → do not include (either excluded or needs-action-both).

        suppressed_reason:
          - Non-None → the finding is a suppressed divergence (count only,
            refer to triage_status_diff).

        is_needs_action_both:
          - True → finding is open on both sides (count only, no port row).
    """
    comp_name = str(right_row.get("component_name", "")).strip().lower()

    if left_rows:
        # Key present on the leader side — inspect every per-project leader row.
        left_statuses = [str(r.get("status", "")).strip().upper() for r in left_rows]

        # ANY leader project that fixed it → portable fix (latent-miss fix). Pick
        # a deterministic evidence label from the fixed statuses present.
        fixed_present = sorted(s for s in left_statuses if s in FIXED_STATUSES)
        if fixed_present:
            return f"VEX: {fixed_present[0]}", None, False

        # No fix anywhere, but ANY leader project suppressed it → suppressed
        # divergence (excluded from port table, counted elsewhere).
        if any(s in SUPPRESSED_STATUSES for s in left_statuses):
            return None, "suppressed", False

        # Every leader project still needs action → needs action in both.
        return None, None, True
    else:
        # Key absent from the leader side
        if not inventory_available:
            # No inventory → conservative exclusion
            return None, None, False

        if left_names is None:
            return None, None, False

        if comp_name and comp_name in left_names:
            # Component still present on the leader but this specific finding is
            # absent (e.g., patched at a different version resolution path)
            return "not present (component still present)", None, False

        # Component not in leader inventory → component-diff fact, not a portable fix
        return None, None, False


def _build_port_fix_row(
    representative: dict[str, Any],
    fix_evidence: str,
    project_names: list[str],
    fix_target: str | None,
) -> dict[str, Any]:
    """Build a port-fix output row from the representative needs-action variant.

    Folder-mode (§4a/§4b): the representative supplies severity/risk/status/
    component_version (chosen by :func:`pick_needs_action_representative`);
    ``project_names`` lists the needs-action laggard variants (the owner chips);
    ``fix_target`` is the leader's clearing version (or ``None``).

    Args:
        representative: The representative needs-action laggard finding row.
        fix_evidence:   The evidence string explaining why a fix is portable.
        project_names:  Sorted-unique-blank-filtered needs-action laggard owners.
        fix_target:     The leader-side clearing version, or ``None`` when the
                        leader lacks the component at a resolvable version.
    """
    return {
        "display_id": safe_str(representative.get("display_id", "")),
        "component_name": safe_str(representative.get("component_name", "")),
        "component_version": safe_str(representative.get("component_version", "")),
        "severity": safe_str(representative.get("severity", "")),
        "risk": representative.get("risk"),
        "status": safe_str(representative.get("status", "")),
        "fix_evidence": fix_evidence,
        "fix_target": fix_target,
        "project_names": project_names,
    }


def _classify_key(
    needs_action_rows: list[dict[str, Any]],
    leader_rows: list[dict[str, Any]],
    leader_names: set[str] | None,
    inventory_available: bool,
) -> tuple[dict[str, Any] | None, str | None, str | None, bool]:
    """Classify one match_key from its per-project needs-action laggard rows.

    The key-level decision is made consistently with the per-row predicate
    (§4a): a key is a **port-fix** iff the classifier keeps ≥1 needs-action
    laggard row (``fix_evidence is not None``), independent of which single row
    is the probe.  The absent-leader branch of :func:`_classify_port_fix` is
    row-dependent (it keeps a row only when its component is in the leader
    inventory), so taking the decision from a single severity-tie-break probe
    would drop a genuine port-fix when the probe's component is absent but a
    lower-severity sibling's component is present.

    Each needs-action row is classified exactly once and partitioned into kept
    (port-fix) vs. not.  When ≥1 row is kept, the representative is the
    highest-severity (§4a comparator) row **among the kept rows** — so the
    emitted row's ``component_name`` / ``component_version`` / ``fix_evidence``
    match the owners that :func:`port_fix_owners` derives from the same kept set.

    The suppressed / needs-action-both outcomes only arise from the
    ``leader_rows``-non-empty branch, which inspects every leader status and
    ignores the laggard ``component_name`` — so it is probe-independent and
    every needs-action row agrees.  Reuse the first such signal among the
    non-kept rows rather than picking a separate probe.

    Args:
        needs_action_rows:   The per-project needs-action laggard rows for one
                             match_key (non-empty).
        leader_rows:         The per-project leader rows for the same key
                             (empty when the key is absent on the leader side).
        leader_names:        Lowercased leader inventory name set (or ``None``).
        inventory_available: Whether both inventories were supplied.

    Returns:
        ``(representative, fix_evidence, suppressed_reason, is_needs_action_both)``

        - When the key is a port-fix: ``representative`` is the chosen kept row
          and ``fix_evidence`` is that row's evidence; the other two are falsey.
        - Otherwise ``representative`` is ``None`` and exactly one of
          ``suppressed_reason`` / ``is_needs_action_both`` may be set (when the
          key is absent on the leader side and no row is kept, all three are
          falsey → the key is simply excluded).
    """
    kept: list[tuple[dict[str, Any], str]] = []
    suppressed_reason: str | None = None
    is_both = False
    for row in needs_action_rows:
        evidence, reason, both = _classify_port_fix(
            row, leader_rows, leader_names, inventory_available
        )
        if evidence is not None:
            kept.append((row, evidence))
        elif reason == "suppressed":
            suppressed_reason = "suppressed"
        elif both:
            is_both = True

    if kept:
        # Representative = highest-severity (§4a comparator) KEPT row, so its
        # component / fix_target line up with port_fix_owners' kept-row owners.
        representative = pick_needs_action_representative([r for r, _ in kept])
        assert representative is not None  # kept is non-empty
        rep_evidence = next(e for r, e in kept if r is representative)
        return representative, rep_evidence, None, False

    # No row kept → key is not a port-fix.  Surface the (probe-independent)
    # suppressed / both signal for the key-level count; both falsey → excluded.
    return None, None, suppressed_reason, is_both


# ---------------------------------------------------------------------------
# Public transform
# ---------------------------------------------------------------------------


def finding_diff_transform(
    left_df: pd.DataFrame | None,
    right_df: pd.DataFrame | None,
    *,
    left_label: str,
    right_label: str,
    config: dict | None = None,
    left_components: pd.DataFrame | None = None,
    right_components: pd.DataFrame | None = None,
) -> dict[str, Any]:
    """Diff two findings frames and return a template-ready dict.

    Classification rules follow the meta-compare design spec Resolved
    decisions #8 / #16 exactly.  See module docstring for the full
    port-fix classification decision tree.

    Args:
        left_df:           Left-side findings DataFrame.
        right_df:          Right-side findings DataFrame.
        left_label:        Human-readable label for the left scope.
        right_label:       Human-readable label for the right scope.
        config:            Optional per-run config dict (reserved for future use).
        left_components:   Optional left-side component inventory DataFrame for
                           fix-evidence classification.
        right_components:  Optional right-side component inventory DataFrame.

    Returns:
        Dict with keys:
        - ``summary``: counts + labels + ``inventory_available`` flag
        - ``port_fixes_left_to_right``: rows for fixes to port from left → right
        - ``port_fixes_right_to_left``: rows for fixes to port from right → left
        - ``empty_side``: ``"left"`` | ``"right"`` | ``"both"`` | ``None``
    """
    # Normalise None inputs to empty DataFrames so we can use uniform emptiness
    # logic below.  None inputs are only produced by some test helpers; the
    # engine always passes DataFrames.
    if left_df is None:
        left_df = pd.DataFrame()
    if right_df is None:
        right_df = pd.DataFrame()

    # Detect empty sides before any processing.
    # For finding_diff, we only hard-short-circuit when BOTH sides have no data
    # at all AND there is no component inventory.  When one side has no findings
    # but the other does, we still proceed — the inventory-based "absent from left"
    # classification path (spec decision #16) can yield portable fixes even when
    # left_df is empty.  We still set empty_side="left"/"right" for the template
    # callout, but we do NOT short-circuit early.
    left_is_empty = isinstance(left_df, pd.DataFrame) and left_df.empty
    right_is_empty = isinstance(right_df, pd.DataFrame) and right_df.empty

    empty_side: str | None
    if left_is_empty and right_is_empty:
        empty_side = "both"
    elif left_is_empty:
        empty_side = "left"
    elif right_is_empty:
        empty_side = "right"
    else:
        empty_side = None

    # Build component inventory sets for fix-evidence classification
    left_names, left_inv_available = _build_inventory_set(left_components)
    right_names, right_inv_available = _build_inventory_set(right_components)
    # inventory_available is True only when BOTH sides' inventories are provided
    inventory_available = left_inv_available and right_inv_available

    # Short-circuit only when BOTH sides have no findings — one empty side can
    # still yield inventory-based portable fixes if inventory is present.
    if left_is_empty and right_is_empty:
        return {
            "summary": {
                "left_label": left_label,
                "right_label": right_label,
                "needs_action_in_both_count": 0,
                "fixed_left_open_right_count": 0,
                "fixed_right_open_left_count": 0,
                "suppressed_divergence_count": 0,
                "inventory_available": inventory_available,
            },
            "port_fixes_left_to_right": [],
            "port_fixes_right_to_left": [],
            "empty_side": "both",
        }

    # Normalize findings frames. One side may be empty (empty DataFrame) while
    # the other is not — we still process to allow the inventory-based
    # "absent from left" classification path to yield portable fixes.
    left_df = prep_findings_frame(left_df, extra_cols=("component_version",))
    right_df = prep_findings_frame(right_df, extra_cols=("component_version",))

    # Add match keys (mutates in place — per _shared contract)
    add_finding_match_key(left_df)
    add_finding_match_key(right_df)

    # Folder-mode per-project provenance (§4a): iterate the FULL pre-dedup rows
    # per match_key — NOT a first-wins representative — so a key one project
    # fixed but another left open is still caught (latent-miss fix), and owners
    # = exactly the laggard projects whose own row the classifier kept. Counts
    # stay key-level (incremented once per key, not per project).
    left_all_records: list[dict[str, Any]] = left_df.to_dict("records")  # type: ignore[assignment]
    right_all_records: list[dict[str, Any]] = right_df.to_dict("records")  # type: ignore[assignment]
    left_rows_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in left_all_records:
        left_rows_by_key[str(r["match_key"])].append(r)
    right_rows_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in right_all_records:
        right_rows_by_key[str(r["match_key"])].append(r)

    # Prepped leader inventories for fix_target version resolution (§4b). Flatten
    # + noise-filter so the name/version columns mirror _build_inventory_set's
    # normalization; leader_component_version handles the case-insensitive match.
    left_inv_prepped = (
        filter_noise_components(prep_component_frame(left_components))
        if left_components is not None
        else None
    )
    right_inv_prepped = (
        filter_noise_components(prep_component_frame(right_components))
        if right_components is not None
        else None
    )

    # ---------------------------------------------------------------------------
    # Classify: "port fixes left → right" — fixed in LEFT (leader), open in RIGHT
    # ---------------------------------------------------------------------------
    port_left_to_right: list[dict[str, Any]] = []
    suppressed_divergence_count = 0
    needs_action_both_count = 0

    for key in sorted(right_rows_by_key):
        right_rows = right_rows_by_key[key]
        # Only the needs-action laggard variants are in scope for this table.
        needs_action_rows = [
            r for r in right_rows if needs_action(str(r.get("status", "")).strip())
        ]
        if not needs_action_rows:
            continue

        left_rows = left_rows_by_key.get(key, [])
        # Key-level classification (count once per key): a key is a port-fix iff
        # the classifier keeps ≥1 needs-action laggard row — the decision is NOT
        # taken from a single probe (the absent-leader branch is row-dependent).
        # The representative + evidence come from the KEPT rows so they line up
        # with port_fix_owners' kept-row owners.
        representative, fix_evidence, suppressed_reason, is_both = _classify_key(
            needs_action_rows, left_rows, left_names, inventory_available
        )

        if representative is not None and fix_evidence is not None:
            # Owners = the needs-action laggard projects the classifier kept.
            owners = port_fix_owners(
                needs_action_rows,
                left_rows,
                left_names,
                inventory_available,
                _classify_port_fix,
            )
            fix_target = leader_component_version(
                left_inv_prepped, str(representative.get("component_name", ""))
            )
            port_left_to_right.append(
                _build_port_fix_row(representative, fix_evidence, owners, fix_target)
            )
        elif suppressed_reason == "suppressed":
            suppressed_divergence_count += 1
        elif is_both:
            needs_action_both_count += 1

    # ---------------------------------------------------------------------------
    # Classify: "port fixes right → left" — fixed in RIGHT (leader), open in LEFT
    # ---------------------------------------------------------------------------
    port_right_to_left: list[dict[str, Any]] = []

    for key in sorted(left_rows_by_key):
        left_rows = left_rows_by_key[key]
        needs_action_rows = [
            r for r in left_rows if needs_action(str(r.get("status", "")).strip())
        ]
        if not needs_action_rows:
            continue

        right_rows = right_rows_by_key.get(key, [])
        representative, fix_evidence, suppressed_reason, is_both = _classify_key(
            needs_action_rows, right_rows, right_names, inventory_available
        )

        # Suppressed divergence in THIS direction (suppressed-right / open-left)
        # is counted here; the forward pass counts the opposite direction
        # (suppressed-left / open-right). Both-needs-action keys were already
        # counted in the forward pass, so they are dropped here to avoid a
        # double-count.
        if representative is not None and fix_evidence is not None:
            owners = port_fix_owners(
                needs_action_rows,
                right_rows,
                right_names,
                inventory_available,
                _classify_port_fix,
            )
            fix_target = leader_component_version(
                right_inv_prepped, str(representative.get("component_name", ""))
            )
            port_right_to_left.append(
                _build_port_fix_row(representative, fix_evidence, owners, fix_target)
            )
        elif suppressed_reason == "suppressed":
            suppressed_divergence_count += 1
        elif is_both:
            pass

    # Sort by severity desc, then risk desc
    port_left_to_right = sort_findings_rows(port_left_to_right)
    port_right_to_left = sort_findings_rows(port_right_to_left)

    # If we produced actual results despite one side's findings being empty
    # (inventory-based path), clear the empty_side marker so the template
    # shows results rather than the "no data" callout.
    has_results = bool(
        port_left_to_right
        or port_right_to_left
        or needs_action_both_count
        or suppressed_divergence_count
    )
    final_empty_side = None if has_results else empty_side

    summary = {
        "left_label": left_label,
        "right_label": right_label,
        "needs_action_in_both_count": needs_action_both_count,
        "fixed_left_open_right_count": len(port_left_to_right),
        "fixed_right_open_left_count": len(port_right_to_left),
        "suppressed_divergence_count": suppressed_divergence_count,
        "inventory_available": inventory_available,
    }

    return {
        "summary": summary,
        "port_fixes_left_to_right": port_left_to_right,
        "port_fixes_right_to_left": port_right_to_left,
        "empty_side": final_empty_side,
    }
