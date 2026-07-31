"""
Pandas transform for the Reachability VEX Coverage report.

Audits reachability-driven VEX hygiene: every finding that binary analysis
proved **unreachable** (``reachabilityScore < 0``) should carry VEX status
``NOT_AFFECTED`` with justification ``CODE_NOT_REACHABLE``. This report
measures that coverage and lists every finding where it hasn't been applied.

Two design decisions carry most of the weight:

1. **Null score is not zero.** ``reachabilityScore`` is ``None`` when
   reachability analysis never ran for a finding, and ``0`` when it ran but
   was inconclusive. Collapsing those (as ``triage_prioritization``'s
   ``_normalize_columns`` does, NaN→0) would let a project that never had a
   ``VULNERABILITY_ANALYSIS`` scan report "0 gaps" — indistinguishable from a
   genuinely clean project, and the most dangerous possible output for an
   audit. ``_normalize_reachability`` preserves the distinction, and a version
   whose findings all have a null score is reported as ``NOT_RUN`` rather than
   contributing to coverage.

2. **Auto-resolvable is defined by the applier, not by a status list.** A gap is
   auto-resolvable only when it carries *no* stored VEX status and has the ids
   the VEX API needs — precisely what ``vex_applier._has_existing_status``
   lets through. Anything with a status already on it (``IN_TRIAGE`` just as
   much as ``EXPLOITABLE``/``FALSE_POSITIVE``/``RESOLVED``, or an unrecognized
   value) is skipped by a default ``--autotriage`` run, so it is needs-review.
   Both are listed; ``status_class`` separates them. See ``_is_auto_resolvable``
   — deriving this from the applier is what keeps the headline from promising
   closures that never happen.

The ``justification`` value on findings that *are* already ``NOT_AFFECTED`` is
deliberately **not** audited — this report checks status only.

Output is never truncated: an audit that silently drops rows is worse than no
audit. Emits ``vex_recommendations`` in the same shape Triage Prioritization
produces, so ``--autotriage`` / ``--apply-vex-triage`` can close the untriaged
gaps. This module never writes to the platform and holds no API client.
"""

from __future__ import annotations

import ast
import logging
import math
from typing import Any

import numpy as np
import pandas as pd

# Imported rather than reimplemented so the label semantics have exactly one
# definition. Duplicating the 4-tier mapping is how the null-vs-zero
# distinction drifts back out of the codebase.
from fs_report.transforms.pandas.cve_impact import _nested_get, _reachability_label

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────

#: The status an unreachable finding is supposed to carry.
TARGET_VEX_STATUS = "NOT_AFFECTED"

#: The justification the platform expects alongside it for this reason.
TARGET_VEX_JUSTIFICATION = "CODE_NOT_REACHABLE"

#: Display token for a finding with no VEX status set. MUST NOT reach a
#: recommendation's ``current_vex_status`` — see ``_build_recommendation``.
NO_STATUS_TOKEN = "NO_STATUS"

#: A gap's class. AUTO_RESOLVABLE means a single default ``--autotriage`` run
#: would actually close it; NEEDS_REVIEW means it would not, so a person must.
#: The split is defined by the applier's own gate, not by a hand-maintained
#: status list — see ``_is_auto_resolvable``. (These replaced an earlier
#: UNTRIAGED / TRIAGED_DIFFERENTLY pair whose "untriaged" set wrongly included
#: IN_TRIAGE: the applier skips ANY finding with a stored status, so IN_TRIAGE
#: was counted as auto-resolvable but never actually applied.)
STATUS_CLASS_AUTO_RESOLVABLE = "AUTO_RESOLVABLE"
STATUS_CLASS_NEEDS_REVIEW = "NEEDS_REVIEW"

#: Bucket label for versions with no folder in the by-folder chart, so they are
#: visible rather than silently dropped.
NO_FOLDER_LABEL = "(no folder)"

#: Platform statuses that mean "not yet triaged". Mirrors ``_OPEN_STATUSES`` in
#: ``customer_brief`` / ``assessment_overview``. ``NO_STATUS`` is this report's own
#: display token for an absent status and is handled separately.
_PLATFORM_OPEN_STATUSES = frozenset({"OPEN", "UNKNOWN"})

#: Per-version reachability states.
#:
#: There is deliberately no ``NO_FINDINGS`` state. Versions are discovered by
#: grouping the findings themselves, so a version with zero findings never
#: becomes a group at all — this transform cannot see it, let alone report on
#: it. An earlier draft carried the state and a ``versions_with_no_findings``
#: counter that was structurally always ``0``, which advertised a distinction
#: the report could never actually draw.
STATE_RAN = "RAN"
STATE_NOT_RUN = "NOT_RUN"

#: Sort order for the gap table. Values outside the ladder sort last.
_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "NONE": 4,
    "INFO": 5,
}

#: The band vocabulary shared with the VEX applier and ``--vex-band``. Note this is
#: NOT ``_SEVERITY_RANK``, which also carries ``NONE`` purely so unranked severities
#: sort last — emitting ``NONE`` as a *band* puts a recommendation outside every
#: exact-band filter.
_VEX_BANDS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

#: Severity tiers reported per project version, worst first. Anything outside
#: this ladder is counted under ``sev_other`` so a row's severity columns always
#: sum to its gap count.
SEVERITY_TIERS = ("critical", "high", "medium", "low")

#: Exact column list of the main table, in render order. Every entry must have
#: a matching ``output.columns`` entry in the recipe YAML — see
#: ``tests/test_reachability_vex_coverage.py::test_every_main_column_documented``.
#:
#: This is a per-project-version ROLLUP, not a per-finding list. Listing all
#: 500+ gaps individually made the report unreadable (a real run produced a
#: 38-page PDF whose Evidence column ran off the page); what an operator needs
#: from this report is how many findings each project version can auto-close and
#: at what severity. Every individual gap is still emitted, row for row, in
#: ``vex_recommendations.json`` and in the ``gap_detail`` frame.
MAIN_COLUMNS = [
    # Folder leads the row because it is the platform's access boundary: a
    # folder-ordered table can be handed to the owning team as one contiguous
    # section. Prefer the full breadcrumb (root->leaf) over the leaf name so
    # same-named folders in different trees stay distinguishable.
    "folder_name",
    "project_name",
    "version_name",
    # project_id and project_version_id are the two ids the platform deep links
    # need (project → /projects/<id>, version → /projects/<id>/versions/<vid>),
    # and project_version_id is also required to apply a VEX status.
    "project_id",
    "project_version_id",
    "reachability_state",
    "unreachable",
    "already_not_affected",
    "auto_triageable",
    "needs_review",
    "sev_critical",
    "sev_high",
    "sev_medium",
    "sev_low",
    "sev_other",
    # A RAN version is not necessarily FULLY analyzed: coverage_pct is computed
    # over the scored findings only, so this column is what stops a reader taking
    # "100%" on a barely-scored version at face value. It belongs in the rendered
    # table, not only in the JSON — the folder owner reads the table.
    "findings_not_analyzed",
    "coverage_pct",
]

#: The per-finding rows, kept out of the rendered table but retained in the
#: result so no detail is actually lost when the main table became a rollup.
GAP_DETAIL_COLUMNS = [
    "project_name",
    "version_name",
    "project_id",
    "project_version_id",
    "finding_id",
    "internal_id",
    "title",
    "severity",
    "component_name",
    "component_version",
    "current_vex_status",
    "status_class",
    # Whether a default --autotriage run would close this finding (no stored
    # status AND appliable ids). Kept in the detail export so a consumer can
    # reconcile the headline against individual rows.
    "auto_ok",
    "reachability_score",
    "reachability_evidence",
    "recommended_vex_status",
    "folder_name",
]

_COVERAGE_BY_VERSION_COLUMNS = [
    "folder_name",
    "project_name",
    "version_name",
    "project_id",
    "project_version_id",
    "reachability_state",
    "total_findings",
    "reachable",
    "unreachable",
    "inconclusive",
    "unknown",
    # Findings on a RAN version that carry no score at all. coverage_pct is
    # computed over the analyzed subset, so a non-zero value here means the
    # percentage describes part of the version, not all of it.
    "findings_not_analyzed",
    "unreachable_not_affected",
    "already_not_affected",
    "gap_count",
    "auto_triageable",
    "needs_review",
    "sev_critical",
    "sev_high",
    "sev_medium",
    "sev_low",
    "sev_other",
    "coverage_pct",
]

#: Above this many categories a bar chart's axis labels overprint into an
#: illegible smear rather than conveying anything — a real portfolio sweep put 493
#: projects on one axis. Past the cap the chart is suppressed and the reader is
#: pointed at the main table, which is already ordered by the same metric, so
#: nothing is lost but the noise. Charts with a fixed small domain (severity tiers,
#: reachability labels, VEX statuses) are unaffected by construction.
MAX_CHART_CATEGORIES = 25

#: Max factor summaries joined into ``reachability_evidence``. The factors
#: array is already trimmed upstream (see docs/reachability-data-trimming.md);
#: this keeps a single spreadsheet cell readable.
_MAX_EVIDENCE_SUMMARIES = 3
_MAX_EVIDENCE_CHARS = 500


# ── Reachability normalization ───────────────────────────────────────


def _coerce_score(raw: Any) -> tuple[float | None, bool]:
    """Return ``(score, was_coercion_failure)``.

    ``None`` score means reachability never ran for this finding. A
    non-numeric value is treated as never-ran (fail closed — an unparseable
    score must never be read as "unreachable") and flagged so the caller can
    report how many rows were affected.
    """
    if raw is None:
        return None, False
    if isinstance(raw, bool):  # bool is an int subclass; not a valid score
        return None, True
    if isinstance(raw, (int, float)):
        value = float(raw)
        # NaN means "no score". +/-Infinity is corrupt data, and treating it as a
        # score would classify it REACHABLE or UNREACHABLE with total confidence —
        # so it fails closed to never-ran AND is flagged, like an unparseable string.
        if math.isnan(value):
            return None, False
        if not math.isfinite(value):
            return None, True
        return value, False
    text = str(raw).strip()
    if not text or text.lower() in {"none", "nan", "null"}:
        return None, False
    try:
        return float(text), False
    except (TypeError, ValueError):
        return None, True


def _extract_score_and_factors(rec: dict[str, Any]) -> tuple[Any, Any]:
    """Pull the raw score and factors out of any of the response shapes.

    Handled, in precedence order:

    1. nested ``reachability`` dict — ``{"score": ..., "factors": [...]}``
       (newer API response shape)
    2. flat ``reachabilityScore`` — the documented portfolio-endpoint field
    3. snake ``reachability_score`` — rows served from the SQLite cache, which
       renames the field via ``sqlite_cache.FINDING_FIELDS``
    """
    factors = rec.get("factors")

    nested = rec.get("reachability")
    if isinstance(nested, dict):
        if factors is None:
            factors = nested.get("factors")
        if "score" in nested:
            return nested.get("score"), factors

    if "reachabilityScore" in rec and rec.get("reachabilityScore") is not None:
        return rec.get("reachabilityScore"), factors

    if "reachability_score" in rec and rec.get("reachability_score") is not None:
        return rec.get("reachability_score"), factors

    # Present but null in every shape — genuinely "never ran", not missing.
    if "reachabilityScore" in rec or "reachability_score" in rec:
        return None, factors
    if isinstance(nested, dict):
        return None, factors

    return None, factors


def _evidence_from_factors(factors: Any) -> str:
    """Render reachability factors into a short human-readable evidence string.

    Consumes the *trimmed* factor shape (``entity_name``, ``summary``) — see
    ``docs/reachability-data-trimming.md``. A cached row may hold the list as
    its ``repr``, so a string is parsed back with ``literal_eval``.
    """
    if isinstance(factors, str):
        try:
            factors = ast.literal_eval(factors)
        except (ValueError, SyntaxError):
            return ""
    if not isinstance(factors, list):
        return ""

    funcs: list[str] = []
    summaries: list[str] = []
    for factor in factors:
        if not isinstance(factor, dict):
            continue
        if factor.get("entity_type") == "vuln_func":
            name = str(factor.get("entity_name") or "").strip()
            if name and name not in funcs:
                funcs.append(name)
        summary = str(factor.get("summary") or "").strip()
        if summary and summary not in summaries:
            summaries.append(summary)

    parts: list[str] = []
    if funcs:
        parts.append("Vulnerable functions: " + ", ".join(funcs))
    if summaries:
        parts.append("; ".join(summaries[:_MAX_EVIDENCE_SUMMARIES]))
    return " — ".join(parts)[:_MAX_EVIDENCE_CHARS]


def _vuln_functions(factors: Any) -> str:
    """Comma-joined vulnerable function names, for the recommendation payload."""
    if isinstance(factors, str):
        try:
            factors = ast.literal_eval(factors)
        except (ValueError, SyntaxError):
            return ""
    if not isinstance(factors, list):
        return ""
    names: list[str] = []
    for factor in factors:
        if isinstance(factor, dict) and factor.get("entity_type") == "vuln_func":
            name = str(factor.get("entity_name") or "").strip()
            if name and name not in names:
                names.append(name)
    return ", ".join(names)


# ── Record normalization ─────────────────────────────────────────────


def _first_nonempty(rec: dict[str, Any], *keys: str) -> str:
    """First key with a non-empty scalar value, as a stripped string."""
    for key in keys:
        val = rec.get(key)
        if val is None:
            continue
        if isinstance(val, float) and math.isnan(val):
            continue
        text = str(val).strip()
        if text and text.lower() not in {"nan", "none"}:
            return text
    return ""


def _nested_or_flat(
    rec: dict[str, Any], parent: str, child: str, *flat_keys: str
) -> str:
    """Nested ``parent.child``, else the first non-empty *flat_keys* value.

    Two problems this exists to solve, both of which produced wrong output:

    1. **``_nested_get`` stringifies.** It returns ``str(parent_val.get(child))``,
       so a JSON ``null`` becomes the TRUTHY string ``"None"`` (and a pandas NaN
       becomes ``"nan"``). That silently defeated every ``x or fallback`` chain
       here, and worse: a ``project_version_id`` of ``"None"`` passed
       ``_is_auto_resolvable``'s "has appliable ids" gate, so the finding was
       counted in the auto-resolvable HEADLINE and written to
       ``vex_recommendations.json`` with a bogus id the applier cannot write.
       That breaks the report's central promise — that the headline equals what a
       single ``--autotriage`` run actually closes.
    2. **The SQLite cache serves FLAT snake_case columns.**
       ``sqlite_cache.FINDING_FIELDS`` maps ``project.name`` -> ``project_name``,
       ``projectVersion.version`` -> ``project_version``, ``component.name`` ->
       ``component_name``, and so on. Reading only the nested shape meant every
       ``--cache-ttl`` run rendered ``project_name`` as "Unknown" with a blank
       version and no platform deep links — and a portfolio sweep WITH caching is
       this report's primary use case.

    ``_first_nonempty`` already treats ``""``/``"none"``/``"nan"`` as absent, so
    routing the nested value through it fixes (1) and the extra keys fix (2).
    """
    return _first_nonempty(
        {"_nested": _nested_get(rec, parent, child), **rec}, "_nested", *flat_keys
    )


def _normalize_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Flatten one API/cache finding record into the fields this report needs."""
    raw_score, factors = _extract_score_and_factors(rec)
    score, coercion_failed = _coerce_score(raw_score)
    label = _reachability_label(score if score is not None else 0.0, score is None)

    status_raw = _first_nonempty(rec, "status", "vex_status")
    status = status_raw.upper() if status_raw else ""

    return {
        # Flat fallbacks are the cache's own column names — see _nested_or_flat.
        "project_name": _nested_or_flat(rec, "project", "name", "project_name")
        or "Unknown",
        "project_id": _nested_or_flat(rec, "project", "id", "project_id", "projectId"),
        "version_name": _nested_or_flat(
            rec, "projectVersion", "version", "project_version", "version_name"
        ),
        "project_version_id": _nested_or_flat(
            rec, "projectVersion", "id", "project_version_id", "projectVersionId"
        ),
        "finding_id": _first_nonempty(rec, "findingId", "finding_id", "cveId"),
        "internal_id": _first_nonempty(rec, "id", "internal_id"),
        "title": _first_nonempty(rec, "title"),
        # Left in the API's own (lowercase) casing. Normalizing it back into
        # the frame would break the declarative severity sort/pivot in
        # data_transformer, which assumes lowercase.
        "severity": _first_nonempty(rec, "severity"),
        "component_name": _nested_or_flat(rec, "component", "name", "component_name"),
        "component_version": _nested_or_flat(
            rec, "component", "version", "component_version"
        ),
        # folder_breadcrumb is the engine's full root->leaf path (injected for
        # multi-project scopes); folder_name is the leaf, always injected. On a
        # single-project run neither may be present, which renders blank.
        "folder_name": _first_nonempty(rec, "folder_breadcrumb", "folder_name"),
        "status": status,
        "reachability_score": score,
        "reachability_analyzed": score is not None,
        "reachability_label": label,
        "reachability_evidence": _evidence_from_factors(factors),
        "vuln_functions": _vuln_functions(factors),
        "_coercion_failed": coercion_failed,
    }


def _records_from_input(data: list[dict[str, Any]] | pd.DataFrame) -> list[dict]:
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return []
        return data.to_dict("records")
    return list(data or [])


# ── Classification ───────────────────────────────────────────────────


def _status_display(status: str) -> str:
    return status or NO_STATUS_TOKEN


def _is_real_id(value: Any) -> bool:
    """True only for a value the VEX API could actually address.

    The last line of defence for the report's central promise. Raw truthiness is
    not enough: ``str(None)`` is ``"None"`` and ``str(float("nan"))`` is ``"nan"``,
    both TRUTHY, so a normalization path that leaked one of those sentinels would
    put an unwritable finding into the auto-resolvable headline AND into
    ``vex_recommendations.json``. That exact bug has been introduced twice — once
    reading nested ids in this transform, once in the engine's folder lookup — so
    the gate rejects the sentinels itself rather than trusting every current and
    future caller to have cleaned them.
    """
    if value is None:
        return False
    text = str(value).strip()
    return bool(text) and text.lower() not in {"none", "nan", "nat", "<na>", "null"}


def _is_auto_resolvable(status: str, internal_id: Any, project_version_id: Any) -> bool:
    """True iff a single default ``--autotriage`` run would actually close this gap.

    This is the report's headline contract, so it is defined by what the applier
    does, not by a hand-maintained status list:

    * ``vex_applier._has_existing_status`` skips any recommendation whose
      ``current_vex_status`` is a non-empty string. A finding with ANY stored
      status — ``IN_TRIAGE`` and unrecognized values included, not just the
      deliberate ``EXPLOITABLE`` / ``FALSE_POSITIVE`` / ``RESOLVED`` set — is
      left alone unless ``--vex-override``. So only a finding with NO stored
      status (``status == ""``, shown as ``NO_STATUS``) is auto-resolvable.
    * ``validate_recommendations`` requires both ids; a gap missing either can't
      be applied at all.

    Counting anything the applier would skip would make the headline over-promise
    what one run closes — the drift three reviewers flagged.
    """
    return status == "" and _is_real_id(internal_id) and _is_real_id(project_version_id)


def _coverage_pct(covered: int, total: int) -> float | None:
    """Coverage as a percentage, FLOORED to one decimal.

    Floored rather than rounded because this is an audit headline: with
    ``round``, 99.995% coverage prints as ``100.0%`` while gaps are still open,
    and the KPI's "< 100" warning dot switches off at exactly the point a reader
    most needs it. Flooring can only ever understate hygiene, never overstate it.
    """
    if not total:
        return None
    return math.floor(covered / total * 1000) / 10


def _jsonable(obj: Any) -> Any:
    """Coerce numpy/pandas scalars to native Python types, recursively.

    ``DataFrame.to_dict`` hands back ``np.int64``/``np.bool_``/``NaT``, and the
    renderer serializes with ``default=str`` — which would silently turn a count
    of 5 into the string ``"5"`` and ``NaN`` into ``"nan"``. Coercing here keeps
    the machine-readable artifact actually machine-readable.
    """
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if obj is None or isinstance(obj, (str, bool, int, float)):
        # json.dumps emits a bare NaN/Infinity token here, which is not valid
        # JSON and breaks strict parsers. bool is checked implicitly — it is an
        # int subclass, and isinstance(True, float) is False, so only genuine
        # floats reach isnan.
        if isinstance(obj, float) and not math.isfinite(obj):
            return None
        return obj
    if isinstance(obj, np.generic):
        value = obj.item()
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return value
    if obj is pd.NaT or (not isinstance(obj, (list, dict)) and pd.isna(obj)):
        return None
    return str(obj)


def _severity_sort_key(row: dict[str, Any]) -> tuple:
    sev = str(row.get("severity") or "").strip().upper()
    return (
        _SEVERITY_RANK.get(sev, 99),
        0 if row.get("status_class") == STATUS_CLASS_AUTO_RESOLVABLE else 1,
        str(row.get("project_name") or ""),
        str(row.get("version_name") or ""),
        str(row.get("finding_id") or ""),
    )


# ── Recommendations ──────────────────────────────────────────────────


def _priority_band(severity: str) -> str:
    """Severity-derived band, so ``--vex-band`` filters stay meaningful.

    This report has no scoring model; the band is purely the severity tier
    uppercased, with anything unranked reported as INFO.
    """
    sev = str(severity or "").strip().upper()
    # The band vocabulary the applier and --vex-band share is
    # CRITICAL/HIGH/MEDIUM/LOW/INFO. `_SEVERITY_RANK` additionally carries NONE for
    # SORTING, so returning `sev in _SEVERITY_RANK` verbatim emitted a "NONE" band
    # no band filter recognizes — those recommendations would silently fall outside
    # an exact-band selection. `none` severity maps to the lowest real band.
    if sev in _VEX_BANDS:
        return sev
    return "INFO"


def _build_recommendation(row: dict[str, Any]) -> dict[str, Any]:
    """Build one appliable VEX recommendation for a gap row.

    ``current_vex_status`` is deliberately ``""`` for untriaged gaps.
    ``vex_applier._has_existing_status`` skips any recommendation whose
    ``current_vex_status`` is a non-empty string, so leaking the synthetic
    ``NO_STATUS`` token here would make ``--autotriage`` skip exactly the
    findings it exists to fix. Gaps that a human triaged differently *do*
    carry their real status, so they are skipped unless ``--vex-override``.
    """
    score = row.get("reachability_score")
    evidence = row.get("reachability_evidence") or ""
    status_display = row.get("current_vex_status") or NO_STATUS_TOKEN
    reason = (
        f"Reachability analysis scored this finding {score} (UNREACHABLE) — "
        f"the vulnerable code path is not reachable in the deployed build. "
        f"Current status {status_display} is not {TARGET_VEX_STATUS}."
    )
    if evidence:
        reason += f" Evidence: {evidence}"

    return {
        "id": row.get("internal_id", ""),
        "finding_id": row.get("finding_id", ""),
        "severity": row.get("severity", ""),
        "project_name": row.get("project_name", ""),
        "project_id": row.get("project_id", ""),
        "project_version_id": row.get("project_version_id", ""),
        "version_name": row.get("version_name", ""),
        "folder_name": row.get("folder_name", ""),
        # "" for untriaged — see docstring. Never NO_STATUS.
        "current_vex_status": row.get("status", ""),
        "priority_band": _priority_band(row.get("severity", "")),
        "triage_score": 0,
        "recommended_vex_status": TARGET_VEX_STATUS,
        "justification": TARGET_VEX_JUSTIFICATION,
        "reason": reason,
        "reachability_score": score,
        "reachability_label": "UNREACHABLE",
        "vuln_functions": row.get("vuln_functions", ""),
        "component_name": row.get("component_name", ""),
        "component_version": row.get("component_version", ""),
        # Extra field; ignored by the applier, used to audit the JSON against
        # the report.
        "gap_class": row.get("status_class", ""),
    }


# ── Empty result ─────────────────────────────────────────────────────


def _empty_summary(
    min_severity: str | None,
    open_only: bool = False,
    scan_window: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "versions_in_scope": 0,
        "versions_with_reachability": 0,
        "versions_without_reachability": 0,
        "total_findings": 0,
        "reachable_findings": 0,
        "unreachable_findings": 0,
        "inconclusive_findings": 0,
        "unknown_findings": 0,
        "unreachable_not_affected": 0,
        "gap_count": 0,
        "auto_resolvable_total": 0,
        "auto_resolvable_by_severity": dict(_severity_counts([])),
        "needs_review_total": 0,
        "gaps_not_appliable": 0,
        "needs_review_status_conflict": 0,
        "needs_review_missing_ids": 0,
        "findings_not_analyzed": 0,
        "coverage_pct": None,
        "reachability_ran_anywhere": False,
        "min_severity": min_severity,
        # Carried through even on the empty path. The notes list already tells a
        # HUMAN that --open-only was ignored / a severity floor is active / the
        # portfolio scan window is narrow; a machine reading only
        # coverage_summary would otherwise see open_only_requested=False and an
        # empty scan_window and conclude the audit was unscoped and complete.
        # For a report whose whole contract is "never present a partial audit as
        # complete", that contradiction is the defect, not a cosmetic gap.
        "open_only_requested": open_only,
        "scan_window": scan_window or {},
        "versions_hidden_no_action": 0,
    }


def _empty_result(
    notes: list[str] | None = None,
    min_severity: str | None = None,
    domain: str = "",
    open_only: bool = False,
    scan_window: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A well-formed empty result — every documented key, correct columns.

    Returning a bare ``{}`` or raising here would surface as a broken report
    for the legitimate "nothing in scope" case.

    This includes ``json_package``. ``_render_json``'s generic branch is gated on
    a non-empty ``report_data.data``, so an empty scope without a package writes
    NO json artifact at all — and into a reused output directory that leaves the
    PREVIOUS run's json sitting there, to be read as this run's coverage. An
    empty-but-well-formed artifact is the only safe output.
    """
    summary = _empty_summary(min_severity, open_only, scan_window)
    return {
        "main": pd.DataFrame(columns=MAIN_COLUMNS),
        "gap_detail": pd.DataFrame(columns=GAP_DETAIL_COLUMNS),
        "chart_suppression": {},
        "coverage_by_version": pd.DataFrame(columns=_COVERAGE_BY_VERSION_COLUMNS),
        "coverage_by_folder": pd.DataFrame(
            columns=[
                "folder_name",
                "unreachable",
                "unreachable_not_affected",
                "gap_count",
                "auto_triageable",
                "coverage_pct",
            ]
        ),
        "gap_status_breakdown": pd.DataFrame(
            columns=["current_vex_status", "status_class", "slice_label", "count"]
        ),
        "reachability_mix": pd.DataFrame(columns=["reachability_label", "count"]),
        "gaps_by_severity": pd.DataFrame(columns=["severity", "count"]),
        "coverage_summary": summary,
        "vex_recommendations": [],
        "json_package": {
            "report": "Reachability VEX Coverage",
            "coverage_summary": _jsonable(summary),
            "coverage_by_version": [],
            "coverage_by_folder": [],
            "work_list": [],
            "gap_detail": [],
            "versions_hidden_no_action": 0,
            "notes": notes or [],
        },
        "notes": notes or [],
        "domain": domain,
    }


# ── Main transform ───────────────────────────────────────────────────


def reachability_vex_coverage_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Audit whether UNREACHABLE findings carry the NOT_AFFECTED VEX status.

    Args:
        data: Findings records (list of dicts or DataFrame), raw API or
            SQLite-cache shape.
        config: Config object. Read for ``domain``, ``min_severity``,
            ``open_only`` and ``verbose``.
        additional_data: Extra engine data; ``config`` and ``domain`` are read
            from here as a fallback.

    Returns:
        Dict of DataFrames plus ``coverage_summary``, ``vex_recommendations``
        and ``notes``. See the module docstring.
    """
    cfg = config
    if cfg is None and additional_data:
        cfg = additional_data.get("config")

    domain = ""
    if additional_data and additional_data.get("domain"):
        domain = str(additional_data["domain"])
    elif cfg is not None:
        domain = str(getattr(cfg, "domain", "") or "")

    min_severity = getattr(cfg, "min_severity", None) if cfg is not None else None
    open_only = bool(getattr(cfg, "open_only", False)) if cfg is not None else False
    verbose = bool(getattr(cfg, "verbose", False)) if cfg is not None else False

    # Scope disclosure. On an unscoped (portfolio) run the engine discovers which
    # projects to audit from the /scans endpoint over the run's date window, which
    # defaults to the last 30 days. A project last scanned before that window is
    # therefore absent from this report entirely — and silently, unless we say so.
    # For a coverage audit that is a material omission: those projects still hold
    # unreachable findings missing NOT_AFFECTED. Surface the window and the lever.
    scan_window: dict[str, Any] = {}
    if cfg is not None:
        scoped = bool(
            getattr(cfg, "project_filter", None) or getattr(cfg, "folder_filter", None)
        )
        start = str(getattr(cfg, "start_date", "") or "")
        end = str(getattr(cfg, "end_date", "") or "")
        explicit = bool(getattr(cfg, "period_explicit", False))
        if not scoped and start and end:
            scan_window = {"start": start, "end": end, "explicit": explicit}

    notes: list[str] = []
    if open_only:
        notes.append(
            "--open-only was ignored for this report: NOT_AFFECTED findings are "
            "the coverage denominator, so excluding them would report 0% "
            "coverage everywhere."
        )
    if min_severity:
        notes.append(
            f"Severity floor {min_severity} is active — every coverage figure "
            f"below is scoped to {min_severity} and above, not the full portfolio."
        )
    # Version scope. Every other narrowing is disclosed; this one changes the
    # denominator more than most — latest-only vs every version of every in-scope
    # project — and is settable from a global or a web toggle, so the rendered
    # narrative could read as a current-version assessment while auditing all
    # versions, or the reverse.
    # Defaults to True to match Config/CLI. Defaulting False meant a caller passing
    # a partial config object without the attribute got the "EVERY version was
    # audited" note while the engine had in fact filtered to current versions.
    current_only = (
        bool(getattr(cfg, "current_version_only", True)) if cfg is not None else True
    )
    pinned_version = (
        str(getattr(cfg, "version_filter", "") or "") if cfg is not None else ""
    )
    if pinned_version:
        # --version pins an explicit version, which may not be the current one, so
        # the "current version" wording would misstate the denominator.
        notes.append(
            f"Only version {pinned_version} was audited (--version); unreachable "
            "findings on any other version of these projects are outside these "
            "figures."
        )
    elif current_only:
        notes.append(
            "Only each project's CURRENT version was audited "
            "(--current-version-only), so unreachable findings on pinned or older "
            "versions are outside these figures."
        )
    elif not pinned_version:
        notes.append(
            "EVERY version of each in-scope project was audited, not just the "
            "current one — a project with many retained versions contributes all of "
            "them to the counts below."
        )
    standalone = bool(getattr(cfg, "standalone", False)) if cfg is not None else False
    if standalone:
        notes.append(
            "--standalone was set, so dependency versions were NOT expanded: "
            "unreachable findings that live on a composite project's dependency "
            "versions are outside this audit."
        )
    detected_after = (
        str(getattr(cfg, "detected_after", "") or "") if cfg is not None else ""
    )
    if detected_after:
        # The engine DOES apply this to this recipe's findings fetch, so it narrows
        # the unreachable denominator, the coverage %, and the headline. Every
        # other narrowing is disclosed; leaving this one silent would let a
        # window-limited audit read as portfolio-wide.
        notes.append(
            f"Only findings first detected on or after {detected_after} were "
            "audited (--detected-after), so every figure below excludes older "
            "unreachable findings — including ones still missing NOT_AFFECTED."
        )
    if scan_window:
        lever = (
            "Widen it with --period (e.g. --period 5y) or --start/--end, "
            "or audit one project with --project."
            if not scan_window["explicit"]
            else "Widen it with a longer --period or --start/--end."
        )
        notes.append(
            "Portfolio scope covers only projects SCANNED between "
            f"{scan_window['start']} and {scan_window['end']}"
            + (
                " (the default 30-day window — no --period was given). "
                if not scan_window["explicit"]
                else ". "
            )
            + "A project last scanned before that is absent from this report and "
            "its unreachable findings are NOT counted above. Note this bounds which "
            "PROJECTS are audited, not how old their findings may be: every "
            "finding on an included version is counted regardless of when it was "
            "detected (use --detected-after to bound that too). " + lever
        )

    records = _records_from_input(data)
    if not records:
        notes.append(
            "No findings were returned for this scope. Nothing to audit — this "
            "is not the same as full VEX coverage."
        )
        logger.warning("Reachability VEX Coverage: no findings in scope")
        return _empty_result(notes, min_severity, domain, open_only, scan_window)

    logger.info(
        "Reachability VEX Coverage: processing %d findings%s",
        len(records),
        f" (severity floor {min_severity})" if min_severity else "",
    )

    rows = [_normalize_record(rec) for rec in records]

    # Defensive dedupe before any counting: overlapping version batches can
    # yield the same finding twice, which would push coverage above 100%.
    # Dedupe on the platform's own primary key, NOT on CVE id — the same CVE
    # in two versions is two findings with two independent statuses.
    deduped: dict[str, dict[str, Any]] = {}
    positional: list[dict[str, Any]] = []
    for row in rows:
        key = row.get("internal_id") or ""
        if key:
            deduped.setdefault(key, row)
        else:
            positional.append(row)
    # Id-less rows were concatenated without dedupe, so a finding appearing in two
    # overlapping version batches counted twice — inflating unreachable and
    # auto-resolvable, and able to push coverage above 100%. There is no primary key
    # to dedupe on, so use the fullest natural key the record carries.
    seen_natural: set[tuple[str, ...]] = set()
    positional_deduped: list[dict[str, Any]] = []
    for row in positional:
        natural = (
            # Project identity FIRST. Without it the same CVE on the same component
            # in two different projects looked like one duplicated row and was
            # collapsed before counting — under-reporting gaps and recommendations
            # in precisely the missing-id scenario this dedupe exists to handle.
            str(row.get("folder_name") or ""),
            str(row.get("project_id") or ""),
            str(row.get("project_name") or ""),
            str(row.get("version_name") or ""),
            str(row.get("project_version_id") or ""),
            str(row.get("finding_id") or ""),
            str(row.get("component_name") or ""),
            str(row.get("component_version") or ""),
            str(row.get("title") or ""),
            # Last discriminators available on a row with no primary key. Two rows
            # agreeing on all of these are indistinguishable by anything this
            # transform can see, so collapsing them is the only defensible choice.
            str(row.get("reachability_score")),
            str(row.get("status") or ""),
        )
        # A row with nothing identifying at all cannot be compared; keep it rather
        # than collapsing unrelated blanks into one.
        if any(natural) and natural in seen_natural:
            continue
        seen_natural.add(natural)
        positional_deduped.append(row)
    rows = list(deduped.values()) + positional_deduped
    dropped = len(records) - len(rows)
    if dropped > 0:
        logger.debug("Dropped %d duplicate finding record(s) before counting", dropped)

    coercion_failures = sum(1 for r in rows if r["_coercion_failed"])
    if coercion_failures:
        notes.append(
            f"{coercion_failures} finding(s) had a non-numeric reachabilityScore "
            "and were treated as 'analysis never ran' rather than unreachable."
        )

    if not any(
        (
            "reachabilityScore" in rec
            or "reachability_score" in rec
            or "reachability" in rec
        )
        for rec in records
    ):
        notes.append(
            "The findings data carried no reachability score at all, so every "
            "version is reported as 'analysis never ran'. Either reachability "
            "(VULNERABILITY_ANALYSIS) has not run for this scope, or the data "
            "source did not include the field."
        )

    # Surface unrecognized status VALUES purely as a data-quality note; they are
    # counted as needs-review (any stored status blocks a default auto-apply), so
    # this does not affect the headline.
    _KNOWN_STATUSES = {
        NO_STATUS_TOKEN,
        TARGET_VEX_STATUS,
        "IN_TRIAGE",
        "EXPLOITABLE",
        "FALSE_POSITIVE",
        "RESOLVED",
        "RESOLVED_WITH_PEDIGREE",
        # Documented platform statuses meaning "not yet triaged" — the same set
        # `_OPEN_STATUSES` in customer_brief / assessment_overview uses. Calling
        # them "unrecognized" was simply wrong.
        *_PLATFORM_OPEN_STATUSES,
    }
    # Surfaced SEPARATELY, because their consequence is counter-intuitive and
    # material: these findings are OPEN on the platform, yet
    # `vex_applier._has_existing_status` treats ANY non-empty status as already-set
    # and skips them. So they are needs-review, not auto-resolvable — the headline
    # still equals what one --autotriage run closes, which is the contract, but on a
    # tenant whose findings all carry OPEN the honest headline is 0 and the reason is
    # the applier's gate rather than anyone's triage decision. Saying so is the
    # difference between a useless number and an explained one.
    open_status_rows = [r for r in rows if r["status"] in _PLATFORM_OPEN_STATUSES]
    if open_status_rows:
        _seen = sorted({r["status"] for r in open_status_rows})
        notes.append(
            f"{len(open_status_rows)} finding(s) carry an open/untriaged platform "
            f"status ({', '.join(_seen)}). The VEX applier skips any finding that "
            "has a status stored at all, so these count as needs-review rather than "
            "auto-resolvable even though nobody has triaged them — apply them with "
            "--vex-override, or clear the status first."
        )
    unknown_statuses = sorted(
        {
            _status_display(r["status"])
            for r in rows
            if _status_display(r["status"]) not in _KNOWN_STATUSES
        }
    )
    if unknown_statuses:
        notes.append(
            "Unrecognized VEX status value(s) seen and counted as needs-review: "
            + ", ".join(unknown_statuses)
        )

    gap_rows, per_version = _build_gaps_and_versions(rows, verbose)

    return _assemble_result(
        gap_rows=gap_rows,
        per_version=per_version,
        notes=notes,
        min_severity=min_severity,
        open_only=open_only,
        domain=domain,
        verbose=verbose,
        scan_window=scan_window,
    )


def _severity_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Per-tier counts for *rows*, keyed ``sev_<tier>`` plus ``sev_other``.

    ``sev_other`` catches ``none``/``info`` and any value outside the ladder, so
    the severity columns always sum to ``len(rows)`` — a row whose severities
    don't add up to its gap count is the kind of quiet arithmetic error a
    reviewer would have to reverse-engineer.
    """
    counts = {f"sev_{tier}": 0 for tier in SEVERITY_TIERS}
    counts["sev_other"] = 0
    for row in rows:
        tier = str(row.get("severity") or "").strip().lower()
        key = f"sev_{tier}" if tier in SEVERITY_TIERS else "sev_other"
        counts[key] += 1
    return counts


def _build_gaps_and_versions(
    rows: list[dict[str, Any]],
    verbose: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into gap rows and per-version coverage rows."""
    # Key on the platform's stable version id ALONE when present. Adding the
    # display names could only fragment: two rows for one real version whose
    # project or version name differs by whitespace, casing or enrichment would
    # split into two rollup rows, inflating versions_in_scope and splitting one
    # team's work item in two. Rows with no id fall back to the names, the only
    # thing left to group them by.
    by_version: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in rows:
        pvid = str(row["project_version_id"] or "")
        key = (
            ("", "", pvid)
            if pvid
            # No version id: fall back to the fullest identity available. Project
            # NAME alone would merge two genuinely different versions that happen
            # to share display names (same-named projects in different folders is
            # a known shape on these tenants), so the project id joins the key —
            # the opposite failure from the one id-first grouping fixed.
            else (
                # Fullest identity available when there is no version id. Folder
                # joins project id and name because two projects can share BOTH
                # names and be missing project_id; folder is then the only thing
                # left that distinguishes their work items.
                f"{row['folder_name']}|{row['project_id']}|{row['project_name']}",
                row["version_name"],
                "",
            )
        )
        by_version.setdefault(key, []).append(row)

    gap_rows: list[dict[str, Any]] = []
    per_version: list[dict[str, Any]] = []

    for (_k_name, _k_ver, _k_id), version_rows in sorted(by_version.items()):
        # Identity comes from the rows now that the key is id-first.
        pname = version_rows[0]["project_name"]
        vname = version_rows[0]["version_name"]
        pvid = _k_id or str(version_rows[0]["project_version_id"] or "")
        labels = [r["reachability_label"] for r in version_rows]
        analyzed = sum(1 for r in version_rows if r["reachability_analyzed"])

        unreachable_rows = [
            r for r in version_rows if r["reachability_label"] == "UNREACHABLE"
        ]
        not_affected = sum(
            1 for r in unreachable_rows if r["status"] == TARGET_VEX_STATUS
        )

        version_gaps: list[dict[str, Any]] = []
        for row in unreachable_rows:
            if row["status"] == TARGET_VEX_STATUS:
                continue
            auto_ok = _is_auto_resolvable(
                row["status"], row.get("internal_id"), row.get("project_version_id")
            )
            version_gaps.append(
                {
                    **row,
                    "current_vex_status": _status_display(row["status"]),
                    "status_class": (
                        STATUS_CLASS_AUTO_RESOLVABLE
                        if auto_ok
                        else STATUS_CLASS_NEEDS_REVIEW
                    ),
                    "auto_ok": auto_ok,
                    "recommended_vex_status": TARGET_VEX_STATUS,
                }
            )
        gap_rows.extend(version_gaps)

        # version_rows is never empty — a version only exists here because a
        # finding put it in the group — so there are exactly two states.
        state = STATE_NOT_RUN if analyzed == 0 else STATE_RAN
        # RAN means "analysis ran", NOT "analysis covered every finding": the gate
        # is `analyzed > 0`, so one scored finding among hundreds of unscored ones
        # still reads RAN, and coverage_pct is then computed over only the scored
        # subset. That is the right denominator (you cannot measure what was never
        # analyzed) but it must not be presented as whole-version coverage, so the
        # unmeasured remainder is carried per version and disclosed.
        unanalyzed = len(version_rows) - analyzed

        # Auto-triageable = exactly the gaps a default --autotriage run would close
        # (no stored status AND appliable ids — see _is_auto_resolvable). Anything
        # else the apply step skips, so it is needs-review, not auto-resolvable.
        # Counting per version from the same predicate the headline uses keeps the
        # table's column and the hero figure in lockstep.
        auto_rows = [g for g in version_gaps if g["auto_ok"]]
        auto_count = len(auto_rows)
        # Severity mix of the auto-resolvable rows only, for the same reason.
        sev_counts = _severity_counts(auto_rows)
        coverage_pct = (
            _coverage_pct(not_affected, len(unreachable_rows))
            if state == STATE_RAN
            else None
        )

        per_version.append(
            {
                # Every finding on a version belongs to the same project, so the
                # first row's folder and id are correct for the whole version.
                "folder_name": version_rows[0]["folder_name"] if version_rows else "",
                "project_name": pname,
                "version_name": vname,
                "project_id": version_rows[0]["project_id"] if version_rows else "",
                "project_version_id": pvid,
                "reachability_state": state,
                "total_findings": len(version_rows),
                "reachable": labels.count("REACHABLE"),
                "unreachable": len(unreachable_rows),
                "inconclusive": labels.count("INCONCLUSIVE"),
                "unknown": labels.count("UNKNOWN"),
                "findings_not_analyzed": unanalyzed,
                "unreachable_not_affected": not_affected,
                "already_not_affected": not_affected,
                "gap_count": len(version_gaps),
                "auto_triageable": auto_count,
                "needs_review": len(version_gaps) - auto_count,
                **sev_counts,
                "coverage_pct": coverage_pct,
            }
        )

        if verbose:
            logger.info(
                "%s %s — %d CVE findings, %d unreachable, %d gaps "
                "(%d auto-resolvable) [%s]",
                pname,
                vname or "(current)",
                len(version_rows),
                len(unreachable_rows),
                len(version_gaps),
                auto_count,
                state,
            )

    return gap_rows, per_version


def _assemble_result(
    *,
    gap_rows: list[dict[str, Any]],
    per_version: list[dict[str, Any]],
    notes: list[str],
    min_severity: str | None,
    open_only: bool,
    domain: str,
    verbose: bool,
    scan_window: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build every output frame, the KPI summary, and the recommendations."""
    gap_rows = sorted(gap_rows, key=_severity_sort_key)

    version_df = (
        pd.DataFrame(per_version)[_COVERAGE_BY_VERSION_COLUMNS]
        if per_version
        else pd.DataFrame(columns=_COVERAGE_BY_VERSION_COLUMNS)
    )

    # The table is a WORK LIST, so it carries only versions with something to do —
    # at least one auto-resolvable finding. Versions that are already fully covered,
    # that hold only needs-review conflicts, or where reachability never ran are
    # dropped from it. They are NOT dropped from the measurements: the KPI bar, the
    # coverage percentage and coverage_by_version all still count them, and the
    # hidden count is disclosed below the table, so a shorter table can't be read as
    # a smaller problem.
    actionable = [v for v in per_version if int(v.get("auto_triageable") or 0) > 0]
    hidden_versions = len(per_version) - len(actionable)

    # Ordered by FOLDER first, then by how much each version can shed. Folders are
    # the platform's access boundary, so grouping by folder makes the table
    # sectionable: a team or folder owner gets one contiguous block. Within a
    # folder, most-auto-resolvable leads, so each section is its own to-do list.
    # Projects with no folder sort last (U+FFFF, not "") — an unfoldered project is
    # an edge case and shouldn't head the report.
    main_rows = sorted(
        actionable,
        key=lambda v: (
            str(v.get("folder_name") or "\uffff"),
            -int(v.get("auto_triageable") or 0),
            -int(v.get("sev_critical") or 0),
            -int(v.get("sev_high") or 0),
            str(v.get("project_name") or ""),
            str(v.get("version_name") or ""),
        ),
    )
    main = (
        pd.DataFrame(main_rows)[MAIN_COLUMNS]
        if main_rows
        else pd.DataFrame(columns=MAIN_COLUMNS)
    )

    # Per-finding rows are retained rather than rendered — nothing is lost by the
    # main table becoming a rollup, and vex_recommendations.json remains the
    # row-level artifact.
    gap_detail = (
        pd.DataFrame(gap_rows)[GAP_DETAIL_COLUMNS]
        if gap_rows
        else pd.DataFrame(columns=GAP_DETAIL_COLUMNS)
    )

    ran = [v for v in per_version if v["reachability_state"] == STATE_RAN]
    unreachable_total = sum(v["unreachable"] for v in ran)
    not_affected_total = sum(v["unreachable_not_affected"] for v in ran)
    coverage_pct = _coverage_pct(not_affected_total, unreachable_total)

    # Per-FOLDER rollup — folders are the platform's access boundary, so a
    # by-folder chart is both legible (a handful of folders, not hundreds of
    # projects) and actionable (each bar is a team's queue). Only versions where
    # analysis ran are aggregated, so the chart can never read as portfolio-wide
    # when half the portfolio is unscanned. Unfoldered versions bucket under a
    # visible label rather than vanishing.
    # Every in-scope version, not just RAN ones. The CHART aggregates measured work
    # (a folder with nothing measured has no bar to draw), but the artifact is the
    # complete folder view — a folder whose versions are all NOT_RUN is exactly the
    # one a team needs to see, and omitting it made a missing row read as "no work"
    # when it means "never analyzed". Same mistake the work-list filter made for
    # versions, repeated one level up.
    by_folder: dict[str, dict[str, int]] = {}
    for v in per_version:
        folder = str(v.get("folder_name") or "") or NO_FOLDER_LABEL
        agg = by_folder.setdefault(
            folder,
            {
                "unreachable": 0,
                "not_affected": 0,
                "gaps": 0,
                "auto": 0,
                "versions": 0,
                "versions_not_run": 0,
            },
        )
        agg["unreachable"] += v["unreachable"]
        agg["not_affected"] += v["unreachable_not_affected"]
        agg["gaps"] += v["gap_count"]
        agg["auto"] += v["auto_triageable"]
        # Carried so a consumer can tell "this folder has no work" from "this
        # folder was never analyzed" — the distinction the whole report rests on.
        agg["versions"] += 1
        if v["reachability_state"] == STATE_NOT_RUN:
            agg["versions_not_run"] += 1
    _FOLDER_COLUMNS = [
        "folder_name",
        "unreachable",
        "unreachable_not_affected",
        "gap_count",
        "auto_triageable",
        "versions",
        "versions_not_run",
        "coverage_pct",
    ]
    folder_rows = [
        {
            "folder_name": folder,
            "unreachable": agg["unreachable"],
            "unreachable_not_affected": agg["not_affected"],
            "gap_count": agg["gaps"],
            "auto_triageable": agg["auto"],
            "versions": agg["versions"],
            "versions_not_run": agg["versions_not_run"],
            "coverage_pct": _coverage_pct(agg["not_affected"], agg["unreachable"]),
        }
        # Most auto-resolvable first, so the chart's tallest bar is the folder
        # with the most to gain — matching the work-list ordering.
        for folder, agg in sorted(by_folder.items(), key=lambda kv: -kv[1]["auto"])
    ]
    # The CHART shows only folders with something to do (a bar of height zero is
    # noise); the machine-readable artifact must stay complete, or folder-level
    # reconciliation silently drops fully-covered and needs-review-only folders —
    # the same mistake the work-list filter made for versions.
    chartable_folder_rows = [
        r for r in folder_rows if int(r["auto_triageable"] or 0) > 0
    ]
    folder_df = (
        pd.DataFrame(chartable_folder_rows)
        if chartable_folder_rows
        else pd.DataFrame(columns=_FOLDER_COLUMNS)
    )
    complete_folder_df = (
        pd.DataFrame(folder_rows)
        if folder_rows
        else pd.DataFrame(columns=_FOLDER_COLUMNS)
    )

    status_counts: dict[tuple[str, str], int] = {}
    severity_counts: dict[str, int] = {}
    for row in gap_rows:
        key = (row["current_vex_status"], row["status_class"])
        status_counts[key] = status_counts.get(key, 0) + 1
        # Severity chart counts the AUTO-RESOLVABLE gaps only, matching the
        # headline number — mixing in gaps the applier will skip would overstate
        # what a single --autotriage run actually closes.
        if not row.get("auto_ok"):
            continue
        sev = str(row.get("severity") or "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    status_df = (
        pd.DataFrame(
            [
                {
                    "current_vex_status": s,
                    "status_class": c,
                    # The chart plots ONE label per slice. Grouping is by
                    # (status, class), and NO_STATUS legitimately appears in both —
                    # auto-resolvable, and needs-review when the ids are missing —
                    # so plotting the bare status produced two slices with the same
                    # name and no way to tell which was which. This is the label the
                    # chart uses; the two raw fields stay for consumers.
                    "slice_label": (
                        s
                        if c == STATUS_CLASS_AUTO_RESOLVABLE
                        else f"{s} (needs review)"
                    ),
                    "count": n,
                }
                for (s, c), n in sorted(status_counts.items(), key=lambda kv: -kv[1])
            ]
        )
        if status_counts
        else pd.DataFrame(
            columns=["current_vex_status", "status_class", "slice_label", "count"]
        )
    )

    severity_rows: list[dict[str, Any]] = [
        {"severity": s, "count": n} for s, n in severity_counts.items()
    ]
    severity_rows.sort(key=lambda r: _SEVERITY_RANK.get(str(r["severity"]).upper(), 99))
    severity_df = (
        pd.DataFrame(severity_rows)
        if severity_rows
        else pd.DataFrame(columns=["severity", "count"])
    )

    mix_counts = {
        "REACHABLE": sum(v["reachable"] for v in per_version),
        "UNREACHABLE": sum(v["unreachable"] for v in per_version),
        "INCONCLUSIVE": sum(v["inconclusive"] for v in per_version),
        "UNKNOWN": sum(v["unknown"] for v in per_version),
    }
    mix_df = pd.DataFrame(
        [{"reachability_label": k, "count": v} for k, v in mix_counts.items()]
    )

    # A gap with no platform ids cannot be applied — keep it in the table but
    # out of the recs, and report the divergence rather than let the two counts
    # differ silently.
    appliable = [
        r
        for r in gap_rows
        if _is_real_id(r.get("internal_id"))
        and _is_real_id(r.get("project_version_id"))
    ]
    not_appliable = len(gap_rows) - len(appliable)
    if not_appliable:
        notes.append(
            f"{not_appliable} gap(s) are missing the platform ids needed to apply "
            "a VEX status and are listed in the report but excluded from "
            "vex_recommendations.json."
        )
    recommendations = [_build_recommendation(r) for r in appliable]

    not_run = sum(1 for v in per_version if v["reachability_state"] == STATE_NOT_RUN)
    # The headline: exactly the gaps a single default --autotriage run would close.
    # `auto_ok` already encodes both halves of that — no stored status (so the
    # applier won't skip it) AND appliable ids — so every auto_ok gap has a rec
    # the applier will actually apply, and the figure can't drift from the apply
    # step or from the per-version `auto_triageable` column (same predicate).
    auto_rows_all = [r for r in gap_rows if r.get("auto_ok")]
    auto_resolvable_total = len(auto_rows_all)

    summary = {
        "versions_in_scope": len(per_version),
        "versions_with_reachability": len(ran),
        "versions_without_reachability": not_run,
        "total_findings": sum(v["total_findings"] for v in per_version),
        "reachable_findings": mix_counts["REACHABLE"],
        "unreachable_findings": mix_counts["UNREACHABLE"],
        "inconclusive_findings": mix_counts["INCONCLUSIVE"],
        "unknown_findings": mix_counts["UNKNOWN"],
        "unreachable_not_affected": not_affected_total,
        "gap_count": len(gap_rows),
        "auto_resolvable_total": auto_resolvable_total,
        "auto_resolvable_by_severity": dict(_severity_counts(auto_rows_all)),
        "needs_review_total": len(gap_rows) - auto_resolvable_total,
        "gaps_not_appliable": not_appliable,
        # needs_review has two causes with DIFFERENT remedies, so the single total
        # cannot tell a folder owner what to do: a stored status needs a human
        # decision (or --vex-override), a missing platform id needs the id chased
        # down. Split so the work list is actionable.
        # Counted directly from the rows, NOT by subtraction. A gap can have BOTH
        # a stored status and missing ids; subtracting not_appliable pushed every
        # such row into the missing-ids bucket alone, undercounting the status
        # conflicts that need a policy decision. The two therefore overlap and
        # deliberately do not sum to needs_review_total — each answers "how many
        # need THIS remedy".
        "needs_review_status_conflict": sum(
            1 for r in gap_rows if not r.get("auto_ok") and r.get("status")
        ),
        "needs_review_missing_ids": not_appliable,
        # Findings on measured versions that carry no score. Non-zero means every
        # coverage figure describes the analyzed subset, not the whole scope.
        "findings_not_analyzed": sum(
            int(v.get("findings_not_analyzed") or 0) for v in ran
        ),
        "coverage_pct": coverage_pct,
        "reachability_ran_anywhere": bool(ran),
        "min_severity": min_severity,
        "open_only_requested": open_only,
        "scan_window": scan_window or {},
        # Versions omitted from the work list because they have nothing to
        # auto-resolve. Still counted in every figure above.
        "versions_hidden_no_action": hidden_versions,
    }

    if summary["findings_not_analyzed"]:
        notes.append(
            f"{summary['findings_not_analyzed']} finding(s) on versions where "
            "reachability DID run still carry no score, so every coverage figure "
            "describes only the findings that were analyzed — a version reported "
            "RAN is not necessarily fully analyzed."
        )
    if not summary["reachability_ran_anywhere"]:
        notes.append(
            "Reachability analysis has not run anywhere in this scope, so VEX "
            "coverage cannot be measured. A zero gap count here means 'unknown', "
            "not 'clean'."
        )
    elif unreachable_total == 0:
        notes.append(
            "Reachability analysis ran, but no finding in scope was proven "
            "unreachable, so there is no coverage denominator."
        )

    logger.info(
        "Reachability VEX Coverage: %d findings could be auto-resolved across "
        "%d version(s) (%d more need review); %d version(s) had no reachability "
        "data; coverage=%s",
        summary["auto_resolvable_total"],
        summary["versions_with_reachability"],
        summary["needs_review_total"],
        summary["versions_without_reachability"],
        "n/a" if coverage_pct is None else f"{coverage_pct}%",
    )

    # Suppress a chart whose category count makes it unreadable rather than
    # rendering an axis of overprinted labels. Decided here, not in the template,
    # because it is a property of the data. Grouping by folder rather than project
    # keeps this well under the cap for any realistic tenant, but the backstop
    # stays — a tenant with hundreds of folders would hit the same wall.
    chart_suppression: dict[str, dict[str, Any]] = {}
    if len(folder_df) > MAX_CHART_CATEGORIES:
        chart_suppression["coverage_by_folder"] = {
            "count": int(len(folder_df)),
            "limit": MAX_CHART_CATEGORIES,
            "reason": (
                f"{len(folder_df)} folders would overprint into an illegible "
                f"axis (readable up to {MAX_CHART_CATEGORIES}). The table below is "
                "grouped by the same folders — read it instead."
            ),
        }
        logger.info(
            "Suppressing the by-folder chart: %d folders exceeds the %d-category "
            "legibility cap",
            len(folder_df),
            MAX_CHART_CATEGORIES,
        )

    # The rendered table is a work list, so the JSON artifact — not the table —
    # is where the COMPLETE per-version rollup has to live. Without a
    # json_package the renderer falls through to its generic branch and
    # serializes only ``main``, i.e. the filtered rows, which would make the
    # "coverage_by_version stays complete" promise false for the one output
    # format that exists to be machine-read.
    json_package = {
        "report": "Reachability VEX Coverage",
        "coverage_summary": _jsonable(summary),
        # Complete: every version in scope, including fully-covered, needs-review
        # only, and NOT_RUN ones that the table omits.
        "coverage_by_version": _jsonable(version_df.to_dict(orient="records")),
        # Complete, unlike the chart frame — see chartable_folder_rows.
        "coverage_by_folder": _jsonable(complete_folder_df.to_dict(orient="records")),
        # The filtered work list, matching what the HTML/PDF table shows.
        "work_list": _jsonable(main.to_dict(orient="records")),
        # Every individual gap, row for row. The rendered table is a per-version
        # rollup and vex_recommendations.json carries only APPLIABLE rows, so
        # without this the gaps counted in `gaps_not_appliable` — the ones missing
        # the platform ids, i.e. exactly the rows an operator has to chase by hand
        # — appeared in no artifact at all, and `reachability_evidence` was
        # computed for every gap and then discarded.
        "gap_detail": _jsonable(gap_detail.to_dict(orient="records")),
        "versions_hidden_no_action": hidden_versions,
        "notes": notes,
    }

    return {
        "main": main,
        "gap_detail": gap_detail,
        "chart_suppression": chart_suppression,
        "coverage_by_version": version_df,
        "coverage_by_folder": folder_df,
        "gap_status_breakdown": status_df,
        "reachability_mix": mix_df,
        "gaps_by_severity": severity_df,
        "coverage_summary": summary,
        "vex_recommendations": recommendations,
        "json_package": json_package,
        "notes": notes,
        "domain": domain,
    }
