"""Shared identity, status, and hygiene helpers for comparison transforms.

Used by all four B3 diff transforms (finding_diff, component_diff, license_diff,
triage_status_diff) and imported by refactored source sites:
- version_comparison.py (match_key, EXCLUDED_COMPONENT_TYPES)
- triage_prioritization.py (VEX_RESOLVED_STATUSES legacy alias)

Status taxonomy (meta-compare design spec, Resolved decision #8):
  OPEN_STATUSES       — untriaged / actively open
  FIXED_STATUSES      — code-level remediation occurred
  SUPPRESSED_STATUSES — triage judgment (not a fix)
  needs_action()      — complement-based: unknown/future statuses fail OPEN
                        so findings never silently drop out of fix-sync views

Mutation note:
  add_finding_match_key   mutates the input DataFrame in place (match_key col
                          is added directly to the caller's frame).
  add_component_match_key always works on copies and returns (left_copy,
                          right_copy); the input frames are never mutated.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from typing import Any

import pandas as pd

from fs_report.purl_utils import _version_tuple
from fs_report.purl_utils import extract_group as _extract_group

# =============================================================================
# 1. Status taxonomy
# =============================================================================

#: Untriaged / actively open statuses.  Findings here are neither fixed nor
#: suppressed — they require action.
OPEN_STATUSES: frozenset[str] = frozenset({"OPEN", "IN_TRIAGE", "NO_STATUS"})

#: Code-level remediation confirmed — the component was patched or removed.
FIXED_STATUSES: frozenset[str] = frozenset({"RESOLVED", "RESOLVED_WITH_PEDIGREE"})

#: Triage judgment — NOT a code fix; the team decided the finding is
#: not-applicable or a false positive.
SUPPRESSED_STATUSES: frozenset[str] = frozenset({"NOT_AFFECTED", "FALSE_POSITIVE"})

#: Legacy triage_prioritization set — ``{NOT_AFFECTED, RESOLVED,
#: RESOLVED_WITH_PEDIGREE}``. It combines both FIXED statuses with the
#: NOT_AFFECTED suppression, but intentionally EXCLUDES FALSE_POSITIVE (so it
#: is NOT the full FIXED ∪ SUPPRESSED union — that is ``_NOT_NEEDS_ACTION``
#: below). Kept for backward compatibility with triage_prioritization.py,
#: which uses this exact membership for gate exclusion. The new taxonomy above
#: (FIXED / SUPPRESSED separately) supersedes this for new comparison code.
VEX_RESOLVED_STATUSES: frozenset[str] = frozenset(
    {"NOT_AFFECTED", "RESOLVED", "RESOLVED_WITH_PEDIGREE"}
)

# Resolved-action union — anything in either set does NOT need action.
_NOT_NEEDS_ACTION: frozenset[str] = FIXED_STATUSES | SUPPRESSED_STATUSES


def _is_null_or_empty(value: Any) -> bool:
    """Return True for None, empty string, NaN, pd.NA, and similar sentinels."""
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    try:
        # Catches pd.NA and similar NA sentinels
        if pd.isna(value):
            return True
    except (TypeError, ValueError):
        pass
    if isinstance(value, str) and value.strip() == "":
        return True
    return False


def needs_action(status: Any) -> bool:
    """Return True iff the finding status requires action.

    A finding needs action when its status is NOT in FIXED_STATUSES ∪
    SUPPRESSED_STATUSES.  This is deliberately a complement predicate so that
    unknown and future API statuses (e.g. ``EXPLOITABLE``) fail OPEN — they
    never silently drop out of fix-sync views.

    Args:
        status: VEX status value.  Null/empty/NaN → True (needs action).
                String comparison is case-insensitive and strips whitespace.

    Returns:
        True  iff the finding needs action (open, exploitable, unknown, null).
        False iff the finding is fixed or suppressed.
    """
    if _is_null_or_empty(status):
        return True
    normalized = str(status).strip().upper()
    return normalized not in _NOT_NEEDS_ACTION


def needs_action_mask(series: pd.Series) -> pd.Series:
    """Vectorised version of :func:`needs_action` for DataFrame columns.

    Args:
        series: A pandas Series of status strings (may contain NaN/None).

    Returns:
        Boolean pd.Series, True where the finding needs action.
    """
    normalized = series.fillna("").astype(str).str.strip().str.upper()
    return ~normalized.isin(_NOT_NEEDS_ACTION)


def is_untriaged(status: Any) -> bool:
    """Return True iff the finding has not been triaged.

    Untriaged ≝ status is null/empty/NaN OR uppercased value is in
    OPEN_STATUSES.  Note: ``EXPLOITABLE`` is triaged (the team assessed it)
    but still needs action — use :func:`needs_action` for that check.

    Args:
        status: VEX status value.

    Returns:
        True  iff untriaged (null, empty, or in OPEN_STATUSES).
        False iff triaged (any non-open, non-null status).
    """
    if _is_null_or_empty(status):
        return True
    normalized = str(status).strip().upper()
    return normalized in OPEN_STATUSES


def is_untriaged_mask(series: pd.Series) -> pd.Series:
    """Vectorised counterpart of :func:`is_untriaged` for DataFrame columns.

    Same semantics as the scalar version: a finding is untriaged when its
    status is null/empty/NaN OR its uppercased value is in
    :data:`OPEN_STATUSES`.  ``EXPLOITABLE`` is *triaged* (the team assessed
    it) and therefore returns ``False`` here — use :func:`needs_action_mask`
    to find statuses that still require remediation.

    Args:
        series: A pandas Series of status strings (may contain NaN/None).

    Returns:
        Boolean pd.Series, True where the finding is untriaged.
    """
    normalized = series.fillna("").astype(str).str.strip().str.upper()
    return normalized.isin(OPEN_STATUSES) | (normalized == "")


# =============================================================================
# 2. Finding match key
# =============================================================================


def add_finding_match_key(df: pd.DataFrame) -> pd.DataFrame:
    """Add a stable ``match_key`` column to a findings DataFrame.

    Key precedence: when a CVE is present — from ``cveId`` (non-empty) OR a
    CVE-shaped ``findingId`` (real ``/public/v0/findings`` rows put the CVE
    there and leave ``cveId`` null) — the key is the **component-qualified,
    upper-cased** ``component_name|CVE.upper()``. Otherwise the non-CVE
    fallback is ``component_name|title`` when title is non-empty, else
    ``component_name|cwe_id|finding_type``.

    Every CVE-derived key is component-qualified and upper-cased so that:

    - the same CVE on *different* components stays distinct rather than
      collapsing under match_key dedup (a bare-CVE key dropped all-but-one of
      those rows — the recurring meta-compare under-count / mis-attribution
      bug, M1-2);
    - ``CVE-x`` and ``cve-x`` form one key, not two (M1-8);
    - the key is version-independent (the title carries the component version,
      so the title fallback would split the same CVE+component across versions
      and over-count cross-build diffs).

    The qualifying component prefix is **case- and whitespace-normalized** for
    the KEY only — ``component_name.str.strip().str.lower()`` — across the WHOLE
    key family (CVE *and* both fallbacks), consistent with
    :func:`finding_diff._build_inventory_set` / :func:`leader_component_version`.
    This prevents the SAME component+CVE from splitting into two keys when the
    two sides' API responses differ in component-name casing or surrounding
    whitespace (``OpenSSL|CVE-X`` vs ``openssl|CVE-X``), which would recreate
    false port-fix deltas (M2-1) now that the CVE path is component-qualified.
    The row's displayed ``component_name`` is NOT changed — owners and the
    representative keep their original case; only the key's prefix is normalized.
    For same-project version comparison the component identity is stable across
    versions, so same-component CVEs still align.

    Defensive column creation mirrors the source: ``cwe_id``, ``finding_type``,
    and ``findingId`` are set to "" if absent so all rows produce a valid key.

    Args:
        df: Findings DataFrame.  Must contain ``cveId``, ``component_name``,
            and ``title`` columns at minimum; ``cwe_id``/``finding_type``/
            ``findingId`` are created as empty strings if missing.

    Returns:
        The same DataFrame with a ``match_key`` column added (in-place
        mutation is acceptable here to match the original behaviour).
    """
    # Defensive column creation — same as version_comparison source
    for col in ("cwe_id", "finding_type", "findingId"):
        if col not in df.columns:
            df[col] = ""

    cve_str = df["cveId"].fillna("").astype(str)
    has_cve = df["cveId"].notna() & (
        df["cveId"] != ""
    )  # bit-identical with version_comparison.py:840

    title_str = df["title"].fillna("").astype(str).str.strip()
    has_title = title_str != ""
    # Component prefix used for the KEY only — normalized with strip+lower
    # (consistent with ``_build_inventory_set`` / ``leader_component_version``) so
    # the same component never splits a key on casing or surrounding whitespace
    # (M2-1). The row's displayed ``component_name`` is untouched — only the key's
    # prefix is normalized. Applied across the WHOLE key family (CVE + both
    # fallbacks) so the key is casing/whitespace-stable everywhere.
    comp_str = df["component_name"].fillna("").astype(str).str.strip().str.lower()

    fallback_with_title = comp_str + "|" + title_str
    fallback_no_title = (
        comp_str
        + "|"
        + df["cwe_id"].fillna("").astype(str)
        + "|"
        + df["finding_type"].fillna("").astype(str)
    )
    fallback = fallback_with_title.where(has_title, fallback_no_title)

    # Resolve the CVE to key on: prefer ``cveId``; otherwise a CVE-shaped
    # ``findingId`` (real ``/public/v0/findings`` rows carry the CVE there and
    # leave ``cveId`` null).
    finding_id_str = df["findingId"].fillna("").astype(str).str.strip()
    fid_is_cve = finding_id_str.str.upper().str.startswith("CVE-")
    cve_value = cve_str.where(has_cve, finding_id_str)
    # A row is CVE-keyed when cveId is present OR findingId is a CVE.
    is_cve_keyed = has_cve | fid_is_cve

    # Every CVE-derived key is component-qualified and upper-cased so the same
    # CVE on different components never collapses (M1-2) and casing never splits
    # the key (M1-8).
    cve_key = comp_str + "|" + cve_value.str.upper()
    df["match_key"] = cve_key.where(is_cve_keyed, fallback)

    return df


# =============================================================================
# 3. Component hygiene + identity
# =============================================================================

#: Component types that are noise / not meaningful SBOM entries.  Lifted from
#: version_comparison._EXCLUDED_COMPONENT_TYPES (line ~863).  Version-comparison
#: imports this from here; new comparison transforms use it directly.
EXCLUDED_COMPONENT_TYPES: frozenset[str] = frozenset(
    {"file", "device driver", "device_driver"}
)

# Purl column name candidates — same probe order as _component_filter.py:54-58
_PURL_COLUMN_CANDIDATES: tuple[str, ...] = ("purl", "component.purl", "component_purl")


def filter_noise_components(df: pd.DataFrame) -> pd.DataFrame:
    """Drop rows whose normalised ``type`` is in EXCLUDED_COMPONENT_TYPES.

    Normalisation: fillna("") → str → strip → lower, matching the usage in
    version_comparison._make_components_df (line ~902).

    Args:
        df: Component DataFrame, may have a ``type`` column.

    Returns:
        A copy with noise-type rows removed.  If ``type`` column is absent,
        returns a copy of the original DataFrame unchanged.
    """
    if "type" not in df.columns:
        return df.copy()
    type_norm = df["type"].fillna("").astype(str).str.strip().str.lower()
    return df[~type_norm.isin(EXCLUDED_COMPONENT_TYPES)].copy()


def _detect_purl_col(df: pd.DataFrame) -> str | None:
    """Return the first purl column candidate found in *df*, or None."""
    for candidate in _PURL_COLUMN_CANDIDATES:
        if candidate in df.columns:
            return candidate
    return None


def add_component_match_key(
    left: pd.DataFrame, right: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Add a ``match_key`` column to copies of both component frames.

    Match-key strategy (meta-compare design spec, Resolved decision #7;
    purl-asymmetry hardening M2-3):
    - IF both frames have a purl column, key each row by its purl when that
      row has a non-empty purl, else by the (group, name, type) fallback.
    - ELSE use the fallback tuple key for all rows on both frames.

    Purl asymmetry (M2-3): API enrichment may attach a purl to a component on
    ONE side but leave it empty on the other, even though the two are the same
    underlying component (identical group/name/type fallback identity). Keying
    such a pair purl-vs-fallback would split it into false left-only/right-only
    deltas. To reconcile, a purl-bearing row is DOWNGRADED to its fallback key
    when the OPPOSITE side has a same-fallback-identity row whose purl is empty
    — so both sides land on the shared fallback key and MATCH. A purl-bearing
    row with no such empty-purl counterpart keeps its purl key, so genuinely
    distinct components never collapse together.

    Fallback key = lowercased ``f"{group}|{name}|{type}"`` where ``group``
    comes from :func:`component_list._extract_group(bomRef)`.  Rows without
    a ``bomRef`` column or unparseable bomRefs get ``""`` group and degrade to
    ``"|name|type"``.

    Note: ``group`` is always recomputed from ``bomRef`` via
    :func:`_extract_group`; any pre-existing ``group`` column in the input
    frames is ignored for the match-key calculation.

    Args:
        left:  Left-side component DataFrame.
        right: Right-side component DataFrame.

    Returns:
        ``(left_copy, right_copy)`` — both with a ``match_key`` column.
        Input frames are not mutated.
    """
    left = left.copy()
    right = right.copy()

    # Ensure required columns exist defensively
    for df in (left, right):
        for col in ("name", "type"):
            if col not in df.columns:
                df[col] = ""

    left_purl_col = _detect_purl_col(left)
    right_purl_col = _detect_purl_col(right)

    # Determine whether purl-based keying is possible
    use_purl = (left_purl_col is not None) and (right_purl_col is not None)

    # Pre-compute fallback key for both frames
    for df in (left, right):
        bom_refs = df["bomRef"].tolist() if "bomRef" in df.columns else [None] * len(df)
        groups = pd.Series(
            [_extract_group(br) for br in bom_refs], index=df.index, dtype=str
        )
        name_norm = df["name"].fillna("").astype(str).str.lower()
        type_norm = df["type"].fillna("").astype(str).str.lower()
        df["_fallback_key"] = groups + "|" + name_norm + "|" + type_norm

    if use_purl:
        # Normalised purl per side (stripped string; "" when absent/empty).
        left_purl = left[left_purl_col].fillna("").astype(str).str.strip()
        right_purl = right[right_purl_col].fillna("").astype(str).str.strip()

        # Fallback identities that appear with an EMPTY purl on each side.
        # A purl-bearing row on the OPPOSITE side whose fallback identity is in
        # the other side's empty-purl set must reconcile to the fallback key
        # (M2-3 purl asymmetry).
        left_empty_fallbacks = set(left.loc[left_purl == "", "_fallback_key"])
        right_empty_fallbacks = set(right.loc[right_purl == "", "_fallback_key"])

        for df, purl_vals, opposite_empty_fallbacks in (
            (left, left_purl, right_empty_fallbacks),
            (right, right_purl, left_empty_fallbacks),
        ):
            has_purl = purl_vals != ""
            # A purl row reconciles to fallback when the OTHER side has a
            # same-identity row with an empty purl.
            reconcile = has_purl & df["_fallback_key"].isin(opposite_empty_fallbacks)
            # Key by purl only when the row HAS a purl AND does not reconcile;
            # otherwise use the fallback key.
            use_purl_row = has_purl & ~reconcile
            df["match_key"] = purl_vals.where(use_purl_row, df["_fallback_key"])
    else:
        for df in (left, right):
            df["match_key"] = df["_fallback_key"]

    # Remove the temporary column
    left.drop(columns=["_fallback_key"], inplace=True)
    right.drop(columns=["_fallback_key"], inplace=True)

    return left, right


# =============================================================================
# 4. Shared component-frame prep helpers (hoisted from component_diff /
#    license_diff — single source of truth for B3 transforms)
# =============================================================================


def safe_str(val: Any) -> str:
    """Return a safe string representation, treating NaN/None as empty.

    Reuses the existing :func:`_is_null_or_empty` sentinel check so NaN
    detection logic is not duplicated.
    """
    if _is_null_or_empty(val):
        return ""
    return str(val)


def ensure_project_name(df: pd.DataFrame) -> pd.DataFrame:
    """Add an empty-string ``project_name`` column if the frame lacks one.

    Decision #6: every output table must carry a provenance column.
    Does NOT mutate the caller's frame — returns a copy when the column
    is absent, the original object otherwise (same contract as the old
    ``_ensure_project_name`` helpers).
    """
    if "project_name" not in df.columns:
        df = df.copy()
        df["project_name"] = ""
    return df


def flatten_nested_component(df: pd.DataFrame) -> pd.DataFrame:
    """Flatten nested ``component.name`` / ``component.version`` / ``component.type``.

    Some API response shapes carry a nested ``component`` dict whose fields
    override top-level columns.  Mirrors the defensive approach in
    ``version_comparison._make_components_df``.

    Uses the cleaner ``for field in (...)`` loop form (from license_diff).
    Always returns a copy.
    """
    df = df.copy()
    if "component" in df.columns:
        comp_col = df["component"]
        for field in ("name", "version", "type"):
            if field not in df.columns:
                df[field] = comp_col.apply(
                    lambda c, f=field: c.get(f, "") if isinstance(c, dict) else ""
                )
    return df


def prep_component_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Flatten nested fields, ensure provenance column, fill missing strings.

    Shared prep skeleton used by both :mod:`component_diff` and
    :mod:`license_diff`.  The set of columns filled here covers the union
    of what both transforms need; callers may fill additional columns after
    calling this function.
    """
    df = flatten_nested_component(df)
    df = ensure_project_name(df)
    for col in ("name", "type"):
        if col not in df.columns:
            df[col] = ""
        else:
            df[col] = df[col].fillna("").astype(str)
    return df


# =============================================================================
# 5. Shared findings-frame prep helper (hoisted from finding_diff /
#    triage_status_diff — single source of truth for B3 transforms)
# =============================================================================


#: Mapping of findings-frame target column → nested ``component`` dict key.
#: Mirrors the flatten in ``version_comparison._make_findings_df``.
_FINDINGS_COMPONENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("component_name", "name"),
    ("component_version", "version"),
)


def _flatten_findings_component(df: pd.DataFrame) -> None:
    """Populate ``component_name`` / ``component_version`` from a nested
    ``component`` dict, in place.

    Precedence (matches ``version_comparison._make_components_df``): an
    existing NON-EMPTY top-level value wins; an empty/absent top-level value
    is filled from the nested ``component`` object. Non-dict ``component``
    values contribute nothing (degrade to empty string). Does nothing when
    there is no ``component`` column.
    """
    if "component" not in df.columns:
        return
    comp = df["component"].apply(lambda c: c if isinstance(c, dict) else {})
    for target, nested_key in _FINDINGS_COMPONENT_FIELDS:
        nested_vals = comp.apply(lambda c, k=nested_key: c.get(k, ""))
        if target in df.columns:
            existing = df[target]
            # Treat null/empty top-level values as absent → fill from nested.
            existing_str = existing.where(existing.notna(), "").astype(str)
            is_empty = existing_str.str.strip() == ""
            df[target] = existing.where(~is_empty, nested_vals)
        else:
            df[target] = nested_vals


def prep_findings_frame(
    df: pd.DataFrame, *, extra_cols: tuple[str, ...] = ()
) -> pd.DataFrame:
    """Ensure all required finding columns exist with safe defaults.

    Adds missing columns as empty strings or NaN as appropriate, and
    normalises severity to uppercase with UNSPECIFIED fill.  Builds
    ``display_id`` as cveId with findingId fallback.

    Parallel to :func:`prep_component_frame` for findings DataFrames.

    Args:
        df:         Findings DataFrame to normalise.  Always returns a copy.
        extra_cols: Additional string columns to ensure (e.g.
                    ``("component_version",)`` for finding_diff).

    Returns:
        A copy of *df* with all required columns present and normalised.
    """
    df = df.copy()

    # Flatten the nested ``component`` object FIRST (M1-1/M2-2). Real
    # ``/public/v0/findings`` rows carry ``component: {"name": ...,
    # "version": ...}`` and DO NOT carry top-level ``component_name`` /
    # ``component_version``. Without this, component identity is lost in
    # production (non-CVE match keys + inventory-based port-fix evidence
    # break), even though the data is present. The integration fixtures use
    # pre-flattened columns, which hid the bug. Precedence mirrors
    # version_comparison._make_components_df: an existing NON-EMPTY top-level
    # value wins; otherwise the nested value fills in.
    _flatten_findings_component(df)

    required_str = [
        "cveId",
        "severity",
        "title",
        "status",
        "component_name",
        "project_name",
        *extra_cols,
    ]
    for col in required_str:
        if col not in df.columns:
            df[col] = ""
        else:
            df[col] = df[col].fillna("").astype(str)

    # Severity: uppercase + UNSPECIFIED fill for empty
    df["severity"] = df["severity"].str.strip().str.upper()
    df["severity"] = df["severity"].replace("", "UNSPECIFIED").fillna("UNSPECIFIED")

    # risk stays as-is (may be numeric or missing); safe to leave as object
    if "risk" not in df.columns:
        df["risk"] = None

    # Build display_id: prefer cveId, fall back to findingId
    if "findingId" not in df.columns:
        df["findingId"] = ""
    else:
        df["findingId"] = df["findingId"].fillna("").astype(str)
    cve_str = df["cveId"].str.strip()
    finding_id_str = df["findingId"].str.strip()
    df["display_id"] = cve_str.where(cve_str != "", finding_id_str)

    return df


# =============================================================================
# 6. Severity ordering helpers (for finding_diff / triage_status_diff)
# =============================================================================

#: Canonical severity order used by finding_diff and triage_status_diff.
#: Deliberately duplicated from version_comparison.py's severity constants —
#: do NOT refactor version_comparison; the duplication is intentional pending
#: a later consolidation into a shared severity module.
SEVERITY_ORDER: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNSPECIFIED"]

#: Maps each severity label to its sort rank (lower = more severe).
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def sort_findings_rows(rows: list[dict]) -> list[dict]:
    """Sort a list of finding row dicts by severity (ascending) then risk (descending).

    Primary key:  severity rank via :data:`SEVERITY_RANK`; unknown/missing
                  severity maps to rank 99 so it sorts last.
    Secondary key: risk score, coerced to float (non-numeric values → 0.0),
                   descending (higher risk first).

    Args:
        rows: List of finding dicts.  Each dict may contain ``severity`` and
              ``risk`` keys.  Missing keys are treated as unknown/zero.

    Returns:
        A new list sorted by the rules above.  The input list is not mutated.
    """

    def _sort_key(row: dict) -> tuple[int, float]:
        sev = str(row.get("severity", "")).strip().upper()
        rank = SEVERITY_RANK.get(sev, 99)
        try:
            risk_val = float(row.get("risk", 0) or 0)
        except (TypeError, ValueError):
            risk_val = 0.0
        return (rank, -risk_val)

    return sorted(rows, key=_sort_key)


# =============================================================================
# 7. Folder-mode provenance helpers (meta-compare playbook redesign §4a/§4b)
#
# Folder-vs-folder comparisons carry the same match_key across several projects
# within a scope.  Pre-dedup the diff kept only the first row per key, which
# (a) lost the other variants' identity and (b) classified the whole key by the
# first row's status — a latent miss when one project fixed a finding but
# another left it open.  These helpers aggregate owners over the FULL pre-dedup
# rows per key, status-aware, with deterministic ordering everywhere.
# =============================================================================


def _sorted_unique_blank_filtered(names: Any) -> list[str]:
    """Return a sorted, de-duplicated, blank-filtered list of project names.

    The single determinism gate for every owner list these transforms emit:
    no reliance on dict/set iteration order; blanks (``safe_str`` empties) are
    dropped so a missing ``project_name`` never produces a phantom owner chip.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in names:
        name = safe_str(raw)
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return sorted(out)


def leader_component_version(
    components_df: pd.DataFrame | None, name: str
) -> str | None:
    """Return the highest leader-side version for *name*, or ``None``.

    §4b clearing-version resolution — the single source of truth shared by
    ``finding_diff`` (``fix_target``) and ``component_diff``
    (``version_skew.left_version`` / ``right_version``) so §01 and §02 can never
    disagree.

    Matching is case-insensitive against the **same lowercase normalization** as
    :func:`_build_inventory_set` / :func:`add_finding_match_key`.  When a
    component name maps to several versions across folder projects, the maximum
    is selected deterministically:

    - Parse each version via :func:`purl_utils._version_tuple` (numeric tuple,
      ``None`` for unparseable).  A parseable version always outranks an
      unparseable one.
    - Among parseable versions, take the numerically-largest tuple.
    - When *no* version parses, fall back to the lexicographically-largest
      string (documented deterministic fallback for junk version strings).

    This is the MAX selection — NOT ``best_fix_for_version``, which picks the
    *smallest* upgrade relative to an installed version (wrong direction here).

    Resolution is by **name only** — NOT name+type or name+purl. This is a
    deliberate, bounded limitation (M3-1) imposed by the §01↔§02 agreement
    invariant (spec §4c): ``finding_diff``'s ``fix_target`` must EQUAL the
    matching ``version_skew.left_version``, and BOTH resolve via this helper.
    ``finding_diff`` calls it with a component **name** taken from a finding
    row, and ``/public/v0/findings`` rows expose only ``component_name`` /
    ``component_version`` (see ``_flatten_findings_component`` /
    ``version_comparison._make_findings_df``) — a finding's component carries no
    reliable ``type`` dimension. Narrowing ``component_diff``'s resolution by
    ``type`` while ``finding_diff`` cannot would make the two surfaces resolve
    DIFFERENTLY for a name collision and break the agreement. Consequence: two
    distinct components that share a name but differ by ecosystem/group/type
    *within one scope* can mis-resolve here (the max version across all
    same-name rows is taken). Lifting this is out of scope until findings carry
    component identity dimensions (type/purl); only then can both callers
    narrow identically and keep the agreement.

    Args:
        components_df: A leader-side component inventory frame with ``name`` and
                       ``version`` columns (already flattened / prepped by the
                       caller).  ``None`` / empty / missing columns → ``None``.
        name:          The component name to resolve (any casing).

    Returns:
        The highest version string for *name*, or ``None`` when the leader lacks
        the component at any resolvable version.
    """
    if components_df is None or components_df.empty:
        return None
    if "name" not in components_df.columns or "version" not in components_df.columns:
        return None

    target = safe_str(name).strip().lower()
    if not target:
        return None

    name_norm = components_df["name"].fillna("").astype(str).str.strip().str.lower()
    matched = components_df[name_norm == target]
    if matched.empty:
        return None

    versions = [
        v for v in (safe_str(x).strip() for x in matched["version"].tolist()) if v
    ]
    if not versions:
        return None

    def _version_sort_key(v: str) -> tuple[int, tuple[int, ...], str]:
        # Sort key for MAX selection: parseable beats unparseable (first
        # element 1 vs 0); then numeric tuple; finally the raw string as a
        # deterministic lexicographic fallback / final tie-break.
        parsed = _version_tuple(v)
        if parsed is None:
            return (0, (), v)
        return (1, parsed, v)

    return max(versions, key=_version_sort_key)


def project_names_for(df: pd.DataFrame, match_key: str) -> list[str]:
    """Presence-only owner aggregation for the **component** facet (§4a).

    Component rows carry no severity/status, so owners are simply every
    project whose row carries *match_key* — sorted, unique, blank-filtered.

    Args:
        df:        A pre-dedup component frame with ``match_key`` and
                   (optionally) ``project_name`` columns.
        match_key: The component match key to collect owners for.

    Returns:
        Sorted, de-duplicated, blank-filtered project names for the key.
    """
    if "match_key" not in df.columns or "project_name" not in df.columns:
        return []
    subset = df[df["match_key"].astype(str) == str(match_key)]
    if subset.empty:
        return []
    return _sorted_unique_blank_filtered(subset["project_name"].tolist())


def version_owners(df: pd.DataFrame, match_key: str, version: str | None) -> list[str]:
    """Version-specific owner aggregation for a ``version_skew`` side (§4a).

    Unlike :func:`project_names_for` (presence-only — every project carrying the
    component), a skew row picks the *displayed* (max) version per side, so its
    owners must answer "which variants carry THAT version" (M2-2/M3-2). When a
    side has the same component at several versions, presence-only over-lists
    owners; this filters to the rows whose ``version`` equals the displayed one.

    Versions are compared after the same normalization the displayed version
    came through (``leader_component_version`` returns a stripped string, so
    rows are compared on their stripped ``version``).

    Args:
        df:        A pre-dedup component frame with ``match_key``, ``version``,
                   and (optionally) ``project_name`` columns.
        match_key: The component match key to collect owners for.
        version:   The displayed (max) version for this side of the skew row, or
                   ``None`` when ``leader_component_version`` resolved nothing on
                   this side (the null/unhappy path — §01↔§02 agreement, M1-2).
                   ``None`` normalizes to ``""`` and matches only empty-version
                   rows (typically none), so the side renders no spurious owner.

    Returns:
        Sorted, de-duplicated, blank-filtered project names of the variants
        whose row carries *version* for this key.
    """
    if (
        "match_key" not in df.columns
        or "project_name" not in df.columns
        or "version" not in df.columns
    ):
        return []
    target_version = safe_str(version).strip()
    key_str = str(match_key)
    version_norm = df["version"].fillna("").astype(str).str.strip()
    subset = df[
        (df["match_key"].astype(str) == key_str) & (version_norm == target_version)
    ]
    if subset.empty:
        return []
    return _sorted_unique_blank_filtered(subset["project_name"].tolist())


def untriaged_owners(rows: list[dict[str, Any]]) -> list[str]:
    """Laggard-side owners for a triage-propagation row (§4a).

    Owners answer "which variant still needs the triage decision applied" — the
    projects whose own row is untriaged (per :func:`is_untriaged`).  Each facet
    keeps its OWN predicate; this is triage-only (never the finding predicate).

    Args:
        rows: The per-project laggard rows for one match_key (each a dict with
              ``status`` and ``project_name``).

    Returns:
        Sorted, de-duplicated, blank-filtered project names of the untriaged
        variants.
    """
    return _sorted_unique_blank_filtered(
        r.get("project_name") for r in rows if is_untriaged(r.get("status"))
    )


def pick_needs_action_representative(
    rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Pick the representative needs-action row for a key (§4a).

    Fixed comparator (deterministic): **highest severity, then risk desc, then
    lexicographic ``project_name``**.  The representative supplies the row's
    ``severity`` / ``risk`` / ``status`` / ``component_version`` fields.

    Args:
        rows: Candidate needs-action rows for one match_key.

    Returns:
        The chosen representative row, or ``None`` when *rows* is empty.
    """
    if not rows:
        return None

    def _key(row: dict[str, Any]) -> tuple[int, float, str]:
        sev = str(row.get("severity", "")).strip().upper()
        rank = SEVERITY_RANK.get(sev, 99)
        try:
            risk_val = float(row.get("risk", 0) or 0)
        except (TypeError, ValueError):
            risk_val = 0.0
        return (rank, -risk_val, safe_str(row.get("project_name", "")))

    return min(rows, key=_key)


def port_fix_owners(
    laggard_rows: list[dict[str, Any]],
    leader_rows: list[dict[str, Any]],
    leader_names: set[str] | None,
    inventory_available: bool,
    classifier: Callable[
        [dict[str, Any], list[dict[str, Any]], set[str] | None, bool],
        tuple[str | None, str | None, bool],
    ],
) -> list[str]:
    """Laggard-side owners for a port-fix row (§4a), evaluated PER project.

    Runs the caller's ``classifier`` (``finding_diff._classify_port_fix``) once
    per laggard project row, against the full per-project ``leader_rows`` for
    the key — so a key the leader fixed in one project (but left open in
    another) is still caught, and owners = exactly the laggard projects whose
    own row the predicate kept as a port-fix.

    The classifier is injected (not imported) to avoid a circular import; each
    facet keeps its own predicate.

    Args:
        laggard_rows:        The per-project laggard rows for one match_key
                             (already filtered to needs-action by the caller).
        leader_rows:         The per-project leader rows for the same key
                             (possibly empty when the key is absent on the
                             leader side).
        leader_names:        Lowercased leader inventory name set (or ``None``).
        inventory_available: Whether both inventories were supplied.
        classifier:          ``(laggard_row, leader_rows, leader_names,
                             inventory_available) -> (fix_evidence,
                             suppressed_reason, is_needs_action_both)``.

    Returns:
        Sorted, de-duplicated, blank-filtered project names of the laggard
        variants the classifier kept as port-fixes.
    """
    owners: list[Any] = []
    for row in laggard_rows:
        fix_evidence, _suppressed, _is_both = classifier(
            row, leader_rows, leader_names, inventory_available
        )
        if fix_evidence is not None:
            owners.append(row.get("project_name"))
    return _sorted_unique_blank_filtered(owners)
