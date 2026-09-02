"""
Pandas transform for the Version Comparison report.

Shows version-over-version progression for each project:
- Per-version totals and severity breakdown
- Consecutive-pair deltas (new / fixed between adjacent versions)
- Aggregate KPI cards (first version → latest version)
- Detailed fixed/new tables for the most recent version pair
- Component churn for the most recent version pair
"""

import logging
from collections import Counter
from typing import Any

import pandas as pd

from fs_report.purl_utils import _version_tuple
from fs_report.transforms.pandas._cve_updates import (
    _process_cve_updates,
    _to_iso8601z,
)
from fs_report.transforms.pandas.comparison._shared import (
    EXCLUDED_COMPONENT_TYPES as _EXCLUDED_COMPONENT_TYPES,
)
from fs_report.transforms.pandas.comparison._shared import (
    add_finding_match_key as _add_finding_match_key,
)
from fs_report.transforms.pandas.comparison._shared import version_sort_key

logger = logging.getLogger(__name__)

# Severity ordering for display
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNSPECIFIED"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_SUMMARY_COLUMNS = [
    "Project",
    "Version",
    "Date",
    "Total Findings",
    "Critical",
    "High",
    "Medium",
    "Low",
    "Fixed (vs prev)",
    "New (vs prev)",
    "Components",
]

_DETAIL_FINDINGS_COLUMNS = [
    "Project",
    "Version",
    "Date",
    "ID",
    "Severity",
    "Component Name",
    "Component Version",
    "Score",
    "Title",
]

_DETAIL_CHURN_COLUMNS = [
    "Project",
    "From Version",
    "To Version",
    "Change Type",
    "ID",
    "Severity",
    "Component Name",
    "Component Version",
    "Score",
    "Title",
]

_COMPONENT_CHURN_COLUMNS = [
    "Project",
    "From Version",
    "To Version",
    "Change Type",
    "Component Name",
    "Version Baseline",
    "Version Current",
    "Findings Impact",
]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def version_comparison_transform(
    data: "list[dict[str, Any]] | pd.DataFrame",
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform version data into a progression report.

    Expects ``additional_data["projects"]`` — a list of dicts, each with::

        {
            "project_name": str,
            "versions": [
                {"id": str, "name": str, "created": str,
                 "findings": list[dict], "components": list[dict]},
                ...
            ]
        }

    Returns a dict consumed by the template with:
      - projects: list of per-project progression dicts
      - kpi: aggregate first-to-last KPI cards
      - summary: DataFrame for CSV/XLSX export
    """
    additional_data = additional_data or {}
    projects_raw = additional_data.get("projects", [])
    api_client = additional_data.get("api_client")

    if not projects_raw:
        logger.warning("No project data for version comparison")
        return _empty_result()

    project_results: list[dict[str, Any]] = []
    all_summary_rows: list[dict] = []

    for proj in projects_raw:
        pname = proj.get("project_name", "Unknown")
        versions = proj.get("versions", [])
        is_pair = proj.get("is_pair_comparison", False)

        if len(versions) < 2:
            logger.debug("Skipping %s — only %d version(s)", pname, len(versions))
            continue

        result = _process_single_project(pname, versions, api_client=api_client)
        # Skip projects where all versions were filtered out (e.g. failed scans)
        if not result.get("progression"):
            continue
        result["is_pair_comparison"] = is_pair
        project_results.append(result)
        all_summary_rows.extend(result["_summary_rows"])

    if not project_results:
        logger.warning("No projects with ≥ 2 versions to compare")
        return _empty_result()

    # Aggregate KPI: first version of first project → latest of latest
    agg_kpi = _aggregate_kpi(project_results)

    # Build detail DataFrames for CSV/XLSX export
    detail_findings_rows: list[dict[str, Any]] = []
    detail_findings_churn_rows: list[dict[str, Any]] = []
    detail_component_churn_rows: list[dict[str, Any]] = []
    for proj in project_results:
        pname = proj.get("project_name", "Unknown")
        for step in proj.get("progression", []):
            vname = step.get("version", "")
            created = step.get("created", "")
            for row in step.get("findings_in_version", []):
                detail_findings_rows.append(
                    {
                        "Project": pname,
                        "Version": vname,
                        "Date": created,
                        "ID": row.get("display_id", row.get("findingId", "")),
                        "Severity": row.get("severity", ""),
                        "Component Name": row.get("component_name", ""),
                        "Component Version": row.get("component_version", ""),
                        "Score": (
                            round(row.get("risk", 0) / 10.0, 1)
                            if row.get("risk")
                            else ""
                        ),
                        "Title": row.get("title", ""),
                    }
                )
        for step in proj.get("progression", []):
            if not step.get("from_version"):
                continue
            from_ver = step["from_version"]
            to_ver = step.get("version", "")
            for row in step.get("fixed_findings", []):
                detail_findings_churn_rows.append(
                    {
                        "Project": pname,
                        "From Version": from_ver,
                        "To Version": to_ver,
                        "Change Type": "Fixed",
                        "ID": row.get("display_id", row.get("findingId", "")),
                        "Severity": row.get("severity", ""),
                        "Component Name": row.get("component_name", ""),
                        "Component Version": row.get("component_version", ""),
                        "Score": (
                            round(row.get("risk", 0) / 10.0, 1)
                            if row.get("risk")
                            else ""
                        ),
                        "Title": row.get("title", ""),
                    }
                )
            for row in step.get("new_findings", []):
                detail_findings_churn_rows.append(
                    {
                        "Project": pname,
                        "From Version": from_ver,
                        "To Version": to_ver,
                        "Change Type": "New",
                        "ID": row.get("display_id", row.get("findingId", "")),
                        "Severity": row.get("severity", ""),
                        "Component Name": row.get("component_name", ""),
                        "Component Version": row.get("component_version", ""),
                        "Score": (
                            round(row.get("risk", 0) / 10.0, 1)
                            if row.get("risk")
                            else ""
                        ),
                        "Title": row.get("title", ""),
                    }
                )
            for row in step.get("component_churn", []):
                detail_component_churn_rows.append(
                    {
                        "Project": pname,
                        "From Version": from_ver,
                        "To Version": to_ver,
                        "Change Type": row.get("change_type", ""),
                        "Component Name": row.get("name", ""),
                        "Version Baseline": row.get("version_baseline", ""),
                        "Version Current": row.get("version_current", ""),
                        "Findings Impact": row.get("findings_impact", 0),
                    }
                )

    detail_findings_df = (
        pd.DataFrame(detail_findings_rows) if detail_findings_rows else pd.DataFrame()
    )
    detail_findings_churn_df = (
        pd.DataFrame(detail_findings_churn_rows)
        if detail_findings_churn_rows
        else pd.DataFrame()
    )
    detail_component_churn_df = (
        pd.DataFrame(detail_component_churn_rows)
        if detail_component_churn_rows
        else pd.DataFrame()
    )

    # Apply canonical column ordering to detail DataFrames
    if not detail_findings_df.empty:
        cols = [c for c in _DETAIL_FINDINGS_COLUMNS if c in detail_findings_df.columns]
        detail_findings_df = detail_findings_df[cols]
    if not detail_findings_churn_df.empty:
        cols = [
            c for c in _DETAIL_CHURN_COLUMNS if c in detail_findings_churn_df.columns
        ]
        detail_findings_churn_df = detail_findings_churn_df[cols]
    if not detail_component_churn_df.empty:
        cols = [
            c
            for c in _COMPONENT_CHURN_COLUMNS
            if c in detail_component_churn_df.columns
        ]
        detail_component_churn_df = detail_component_churn_df[cols]

    # Build CSV/XLSX summary
    summary_df = pd.DataFrame(all_summary_rows) if all_summary_rows else pd.DataFrame()
    if not summary_df.empty and "Severity" in summary_df.columns:
        summary_df["_sev_rank"] = summary_df["Severity"].map(SEVERITY_RANK).fillna(99)
        summary_df = summary_df.sort_values(
            ["Project", "Version", "_sev_rank"],
            ascending=True,
        )
        summary_df = summary_df.drop(columns="_sev_rank")

    # Apply canonical column ordering to summary
    if not summary_df.empty:
        cols = [c for c in _SUMMARY_COLUMNS if c in summary_df.columns]
        summary_df = summary_df[cols]

    # Remove internal keys from project results before passing to template
    for pr in project_results:
        pr.pop("_summary_rows", None)

    logger.info(
        "Version comparison: %d project(s), %d total versions processed",
        len(project_results),
        sum(len(pr["progression"]) for pr in project_results),
    )

    # Collect failed version names for renderer consumption
    failed_names: list[str] = []
    for proj in projects_raw:
        for v in proj.get("versions", []):
            if v.get("fetch_failed"):
                failed_names.append(v.get("name", v.get("id", "?")))

    return {
        "projects": project_results,
        "kpi": agg_kpi,
        "summary": summary_df,
        "detail_findings": detail_findings_df,
        "detail_findings_churn": detail_findings_churn_df,
        "detail_component_churn": detail_component_churn_df,
        "project_count": len(project_results),
        "is_pair_comparison": any(
            pr.get("is_pair_comparison") for pr in project_results
        ),
        "partial_report": bool(failed_names),
        "failed_version_names": failed_names,
    }


# ---------------------------------------------------------------------------
# Per-project processing
# ---------------------------------------------------------------------------


def _process_single_project(
    project_name: str,
    versions: list[dict[str, Any]],
    api_client: Any = None,
) -> dict[str, Any]:
    """
    Build the progression data for a single project.

    Returns a dict with:
      - project_name
      - progression: list of per-version snapshot dicts (for trend chart)
      - latest_delta: dict with fixed/new/component_churn for the last pair
      - kpi: first→last KPI
    """
    # Filter out versions with 0 findings AND 0 components — these are failed scans
    # (a legitimate scan always produces at least some components).
    # Exception: versions explicitly marked fetch_failed=True are kept so the
    # progression renders them as honest placeholders.
    valid_versions = []
    for v in versions:
        if v.get("fetch_failed"):
            valid_versions.append(v)
            continue
        findings = v.get("findings", [])
        components = v.get("components", [])
        if len(findings) == 0 and len(components) == 0:
            vname = v.get("name", v.get("id", "unknown"))
            logger.warning(
                "Skipping version '%s' of %s — 0 findings and 0 components (likely failed scan)",
                vname,
                project_name,
            )
            continue
        valid_versions.append(v)

    if len(valid_versions) < 2:
        logger.debug(
            "Skipping %s — only %d valid version(s) after filtering failed scans",
            project_name,
            len(valid_versions),
        )
        return {
            "project_name": project_name,
            "progression": [],
            "latest_delta": {},
            "kpi": {},
            "_summary_rows": [],
        }

    # Build findings DataFrames per version
    version_dfs: list[tuple[dict, pd.DataFrame, pd.DataFrame]] = []
    for v in valid_versions:
        f_df = _make_findings_df(v.get("findings", []))
        c_df = _make_components_df(v.get("components", []))
        version_dfs.append((v, f_df, c_df))

    # Build progression: per-version snapshot + delta from previous
    progression: list[dict[str, Any]] = []
    summary_rows: list[dict] = []

    # Track CVE updates for the last pair to reuse in latest_delta (avoids double fetch)
    _last_ext_updates: dict[str, list[dict]] = {}

    for i, (v_meta, f_df, c_df) in enumerate(version_dfs):
        vname = v_meta.get("name", v_meta.get("id", f"v{i+1}"))
        created = v_meta.get("created", "")

        # Failed-fetch placeholder: emit a progression row with None numeric fields
        # and delta_unavailable=True so the renderer can show the version existed
        # but its data was unavailable.
        if v_meta.get("fetch_failed"):
            step: dict[str, Any] = {
                "version": vname,
                "version_project_name": v_meta.get("project_name", ""),
                "created": created[:10] if created else "",
                "total": None,
                "critical": None,
                "high": None,
                "medium": None,
                "low": None,
                "components": None,
                "findings_in_version": [],
                "new": None,
                "fixed": None,
                "from_version": version_dfs[i - 1][0].get("name", "") if i > 0 else "",
                "fixed_findings": [],
                "new_findings": [],
                "fixed_severity_summary": "—",
                "new_severity_summary": "—",
                "component_churn": [],
                "externally_changed": [],
                "externally_changed_count": 0,
                "external_changes_window": {},
                "fetch_failed": True,
                "delta_unavailable": True,
            }
            progression.append(step)
            continue

        total = len(f_df)
        sev_counts = _severity_counts(f_df)
        comp_count = _distinct_component_count(c_df)

        step = {
            "version": vname,
            "version_project_name": v_meta.get("project_name", ""),
            "created": created[:10] if created else "",
            "total": total,
            "critical": sev_counts.get("CRITICAL", 0),
            "high": sev_counts.get("HIGH", 0),
            "medium": sev_counts.get("MEDIUM", 0),
            "low": sev_counts.get("LOW", 0),
            "components": comp_count,
        }

        # Findings present in this version (for detail export)
        step["findings_in_version"] = _df_to_records(f_df)

        if i == 0:
            step["new"] = 0
            step["fixed"] = 0
            step["from_version"] = ""
            step["fixed_findings"] = []
            step["new_findings"] = []
            step["fixed_severity_summary"] = "0"
            step["new_severity_summary"] = "0"
            step["component_churn"] = []
            step["externally_changed"] = []
            step["externally_changed_count"] = 0
            step["external_changes_window"] = {}
        else:
            prev_v_meta_i = version_dfs[i - 1][0]
            # If the prior version failed to fetch, we have no baseline to compare
            # against — emit the step with delta fields as unavailable.
            if prev_v_meta_i.get("fetch_failed"):
                step["delta_unavailable"] = True
                step["new"] = None
                step["fixed"] = None
                step["from_version"] = prev_v_meta_i.get("name", "")
                step["fixed_findings"] = []
                step["new_findings"] = []
                step["fixed_severity_summary"] = "—"
                step["new_severity_summary"] = "—"
                step["component_churn"] = []
                step["externally_changed"] = []
                step["externally_changed_count"] = 0
                step["external_changes_window"] = {}
                progression.append(step)
                continue
            prev_f_df = version_dfs[i - 1][1]
            prev_c_df = version_dfs[i - 1][2]
            fixed_df, new_df, unchanged_df = _classify_findings(prev_f_df, f_df)
            churn_df = _classify_components(prev_c_df, c_df)
            churn_df = _attach_findings_impact(churn_df, fixed_df, new_df)

            # Fetch external CVE changes for this version pair
            prev_created = prev_v_meta_i.get("created", "")
            if api_client is not None:
                ext_updates = _fetch_external_cve_changes(
                    api_client, prev_created, created
                )
                new_df = _annotate_new_findings(new_df, ext_updates)
                externally_changed = _build_externally_changed(
                    unchanged_df, ext_updates
                )
                ext_window: dict[str, str] = {
                    "from": prev_created[:10] if prev_created else "",
                    "to": created[:10] if created else "",
                }
                if i == len(version_dfs) - 1:
                    _last_ext_updates = ext_updates
            else:
                externally_changed = []
                ext_window = {}

            step["fixed"] = len(fixed_df)
            step["new"] = len(new_df)
            step["from_version"] = prev_v_meta_i.get(
                "name", prev_v_meta_i.get("id", "")
            )
            step["fixed_findings"] = _df_to_records(fixed_df)
            step["new_findings"] = _df_to_records(new_df)
            step["fixed_severity_summary"] = _severity_summary_str(
                _severity_counts(fixed_df)
            )
            step["new_severity_summary"] = _severity_summary_str(
                _severity_counts(new_df)
            )
            step["component_churn"] = _df_to_records(churn_df)
            step["externally_changed"] = externally_changed
            step["externally_changed_count"] = len(externally_changed)
            step["external_changes_window"] = ext_window

        progression.append(step)

    # Count fetch_failed versions for KPI tracking
    n_versions_excluded = sum(
        1 for v_meta, _, _ in version_dfs if v_meta.get("fetch_failed")
    )

    # Latest pair: detailed tables
    # Use last two non-failed versions for latest_delta so failed endpoints don't
    # produce misleading "0 findings" comparisons.
    non_failed_dfs = [
        (vm, ff, cf) for vm, ff, cf in version_dfs if not vm.get("fetch_failed")
    ]

    first_v_meta, first_f_df, first_c_df = version_dfs[0]
    last_v_meta, last_f_df, last_c_df = version_dfs[-1]

    # For KPI and latest_delta, prefer non-failed endpoints when available
    kpi_first_v_meta, kpi_first_f_df, kpi_first_c_df = (
        non_failed_dfs[0] if non_failed_dfs else (first_v_meta, first_f_df, first_c_df)
    )
    kpi_last_v_meta, kpi_last_f_df, kpi_last_c_df = (
        non_failed_dfs[-1] if non_failed_dfs else (last_v_meta, last_f_df, last_c_df)
    )

    # KPI prev: prefer the second-to-last non-failed version.
    # When only one non-failed version exists (e.g. sequence is [failed, ok]),
    # there is no valid baseline — set kpi_prev to None so the delta
    # computation is skipped rather than using the failed version as baseline
    # (which would produce a misleading "all findings are new" delta).
    if len(non_failed_dfs) >= 2:
        kpi_prev_v_meta, kpi_prev_f_df, kpi_prev_c_df = non_failed_dfs[-2]
        _kpi_prev_available = True
    else:
        _kpi_prev_available = False

    # Latest delta — only computed when a valid (non-failed) baseline exists.
    if _kpi_prev_available:
        fixed_latest, new_latest, unchanged_latest = _classify_findings(
            kpi_prev_f_df, kpi_last_f_df
        )
        component_churn = _classify_components(kpi_prev_c_df, kpi_last_c_df)
        component_churn = _attach_findings_impact(
            component_churn, fixed_latest, new_latest
        )

        # Annotate new_latest and compute externally_changed for the latest pair.
        # Reuse _last_ext_updates from the loop (same pair) to avoid a double fetch.
        if api_client is not None:
            new_latest = _annotate_new_findings(new_latest, _last_ext_updates)
            latest_externally_changed = _build_externally_changed(
                unchanged_latest, _last_ext_updates
            )
            latest_ext_window: dict[str, str] = {
                "from": kpi_prev_v_meta.get("created", "")[:10],
                "to": kpi_last_v_meta.get("created", "")[:10],
            }
        else:
            latest_externally_changed = []
            latest_ext_window = {}

        bv_name = kpi_prev_v_meta.get("name", "")
        bv_proj = kpi_prev_v_meta.get("project_name", "")
    else:
        # No valid baseline — skip delta computation entirely.
        fixed_latest = _make_findings_df([])
        new_latest = _make_findings_df([])
        unchanged_latest = _make_findings_df([])
        component_churn = _classify_components(pd.DataFrame(), pd.DataFrame())
        latest_externally_changed = []
        latest_ext_window = {}
        bv_name = ""
        bv_proj = ""

    # First→Last KPI (using non-failed endpoints)
    kpi = _compute_kpi(
        kpi_first_f_df,
        kpi_last_f_df,
        kpi_first_c_df,
        kpi_last_c_df,
        fixed_latest,
        new_latest,
        {"name": kpi_first_v_meta.get("name", "First")},
        {"name": kpi_last_v_meta.get("name", "Latest")},
    )
    kpi["n_versions_excluded"] = n_versions_excluded

    # Build summary rows for CSV export (one row per finding per version)
    for step in progression:
        summary_rows.append(
            {
                "Project": project_name,
                "Version": step["version"],
                "Date": step["created"],
                "Total Findings": step["total"],
                "Critical": step["critical"],
                "High": step["high"],
                "Medium": step["medium"],
                "Low": step["low"],
                "Fixed (vs prev)": step["fixed"],
                "New (vs prev)": step["new"],
                "Components": step["components"],
            }
        )

    # Build display labels for baseline/current that include project name
    # when the two versions come from different projects.
    # Use non-failed endpoints so labels reflect actual comparison targets.
    cv_name = kpi_last_v_meta.get("name", "")
    cv_proj = kpi_last_v_meta.get("project_name", "")
    cross_project = bv_proj and cv_proj and bv_proj != cv_proj
    baseline_label = f"{bv_proj} / {bv_name}" if cross_project else bv_name
    current_label = f"{cv_proj} / {cv_name}" if cross_project else cv_name

    latest_delta: dict[str, Any] = {
        "baseline_version": bv_name,
        "current_version": cv_name,
        "baseline_project_name": bv_proj,
        "current_project_name": cv_proj,
        "baseline_label": baseline_label,
        "current_label": current_label,
        "fixed_findings": _df_to_records(fixed_latest),
        "new_findings": _df_to_records(new_latest),
        "fixed_by_severity": _severity_counts(fixed_latest),
        "new_by_severity": _severity_counts(new_latest),
        "fixed_severity_summary": _severity_summary_str(_severity_counts(fixed_latest)),
        "new_severity_summary": _severity_summary_str(_severity_counts(new_latest)),
        "component_churn": _df_to_records(component_churn),
        "fixed_count": len(fixed_latest),
        "new_count": len(new_latest),
        "unchanged_count": len(unchanged_latest),
        "externally_changed": latest_externally_changed,
        "externally_changed_count": len(latest_externally_changed),
        "external_changes_window": latest_ext_window,
    }
    if not _kpi_prev_available:
        latest_delta["unavailable"] = True
        latest_delta["reason"] = "only_one_non_failed_version"

    return {
        "project_name": project_name,
        "progression": progression,
        "latest_delta": latest_delta,
        "kpi": kpi,
        "_summary_rows": summary_rows,
    }


def _df_to_records(df: pd.DataFrame) -> list[dict]:
    """Convert DataFrame to list of dicts for template consumption."""
    if df.empty:
        return []
    return df.to_dict(orient="records")


def _severity_counts(df: pd.DataFrame) -> dict[str, int]:
    """Return severity → count mapping."""
    if df.empty:
        return {}
    return {str(k): int(v) for k, v in df["severity"].value_counts().items()}


def _severity_summary_str(sev_counts: dict[str, int]) -> str:
    """Format severity counts as '2 CRITICAL, 1 HIGH' for display."""
    if not sev_counts:
        return "0"
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNSPECIFIED"]
    parts = [f"{sev_counts.get(s, 0)} {s}" for s in order if sev_counts.get(s)]
    return ", ".join(parts) if parts else "0"


# ---------------------------------------------------------------------------
# Aggregate KPI across all projects
# ---------------------------------------------------------------------------


def _aggregate_kpi(project_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build portfolio-level KPI from per-project results.

    fetch_failed progression steps have None totals — skip them when computing
    first/last endpoint values so failed versions don't skew the aggregate.
    """

    def _first_non_none(progression: list[dict], key: str) -> int:
        for step in progression:
            val = step.get(key)
            if val is not None:
                return int(val)
        return 0

    def _last_non_none(progression: list[dict], key: str) -> int:
        for step in reversed(progression):
            val = step.get(key)
            if val is not None:
                return int(val)
        return 0

    total_first = sum(
        _first_non_none(pr["progression"], "total") for pr in project_results
    )
    total_last = sum(
        _last_non_none(pr["progression"], "total") for pr in project_results
    )

    crit_first = sum(
        _first_non_none(pr["progression"], "critical") for pr in project_results
    )
    crit_last = sum(
        _last_non_none(pr["progression"], "critical") for pr in project_results
    )

    high_first = sum(
        _first_non_none(pr["progression"], "high") for pr in project_results
    )
    high_last = sum(_last_non_none(pr["progression"], "high") for pr in project_results)

    comp_first = sum(
        _first_non_none(pr["progression"], "components") for pr in project_results
    )
    comp_last = sum(
        _last_non_none(pr["progression"], "components") for pr in project_results
    )

    total_fixed_latest = sum(
        pr["latest_delta"]["fixed_count"] for pr in project_results
    )
    total_new_latest = sum(pr["latest_delta"]["new_count"] for pr in project_results)

    def _delta(a: int, b: int) -> dict:
        d = b - a
        pct = round((d / a) * 100, 1) if a else 0.0
        return {"baseline": a, "current": b, "delta": d, "pct": pct}

    return {
        "total_findings": _delta(total_first, total_last),
        "critical_findings": _delta(crit_first, crit_last),
        "high_findings": _delta(high_first, high_last),
        "components": _delta(comp_first, comp_last),
        "fixed_count": total_fixed_latest,
        "new_count": total_new_latest,
        "baseline_version": "First versions",
        "current_version": "Latest versions",
        "project_count": len(project_results),
    }


# ---------------------------------------------------------------------------
# Empty result helper
# ---------------------------------------------------------------------------


def _empty_result() -> dict[str, Any]:
    return {
        "projects": [],
        "kpi": {
            "total_findings": {"baseline": 0, "current": 0, "delta": 0, "pct": 0.0},
            "critical_findings": {"baseline": 0, "current": 0, "delta": 0, "pct": 0.0},
            "high_findings": {"baseline": 0, "current": 0, "delta": 0, "pct": 0.0},
            "components": {"baseline": 0, "current": 0, "delta": 0, "pct": 0.0},
            "fixed_count": 0,
            "new_count": 0,
            "baseline_version": "",
            "current_version": "",
            "project_count": 0,
        },
        "summary": pd.DataFrame(),
        "detail_findings": pd.DataFrame(),
        "detail_findings_churn": pd.DataFrame(),
        "detail_component_churn": pd.DataFrame(),
        "project_count": 0,
    }


# ---------------------------------------------------------------------------
# Internal helpers (reused from original)
# ---------------------------------------------------------------------------


def _make_findings_df(raw: list[dict]) -> pd.DataFrame:
    """Normalise raw finding records into a flat DataFrame."""
    if not raw:
        return pd.DataFrame(
            columns=[
                "id",
                "cveId",
                "severity",
                "risk",
                "match_key",
                "display_id",
                "component_name",
                "component_version",
                "title",
            ]
        )

    df = pd.DataFrame(raw)

    # Flatten nested component if present
    if "component" in df.columns:
        comp = df["component"].apply(lambda x: x if isinstance(x, dict) else {})
        df["component_name"] = comp.apply(lambda x: x.get("name", ""))
        df["component_version"] = comp.apply(lambda x: x.get("version", ""))
    else:
        df["component_name"] = df.get("component_name", "")
        df["component_version"] = df.get("component_version", "")

    # Ensure core columns exist
    for col in ("id", "cveId", "severity", "risk", "title"):
        if col not in df.columns:
            df[col] = "" if col != "risk" else 0

    # Display ID for reports: prefer CVE/finding identifier, never show internal id
    df["display_id"] = df["cveId"].fillna("").astype(str).str.strip()
    if "findingId" in df.columns:
        empty = df["display_id"] == ""
        df.loc[empty, "display_id"] = df.loc[empty, "findingId"].fillna("").astype(str)

    # Normalise severity to uppercase (before match_key so fingerprint is consistent)
    df["severity"] = df["severity"].fillna("UNSPECIFIED").str.upper()

    # Build a stable match key for version-over-version comparison.
    # Logic lives in comparison._shared.add_finding_match_key — imported here
    # so the match-key chain stays single-sourced.
    _add_finding_match_key(df)

    return df


# _EXCLUDED_COMPONENT_TYPES is imported from comparison._shared above; the
# alias preserves the private name so existing usages in this file are unchanged.


def _make_components_df(raw: list[dict]) -> pd.DataFrame:
    """Normalise raw component records into a flat DataFrame.
    Excludes FILE and device-driver types (like report_engine exclusion for FILE).
    Flattens nested 'component' object (name/version) when API returns that shape.
    """
    if not raw:
        return pd.DataFrame(
            columns=[
                "id",
                "name",
                "version",
                "type",
                "warnings",
                "violations",
            ]
        )

    # Flatten nested "component" so name/version are always at top level
    flat: list[dict] = []
    for r in raw:
        rec = dict(r)
        comp = rec.get("component")
        if isinstance(comp, dict):
            rec["name"] = comp.get("name") or rec.get("name") or ""
            rec["version"] = comp.get("version") or rec.get("version") or ""
        flat.append(rec)

    df = pd.DataFrame(flat)
    for col in ("id", "name", "version", "type"):
        if col not in df.columns:
            df[col] = ""
    for col in ("warnings", "violations"):
        if col not in df.columns:
            df[col] = 0

    # Exclude placeholder/noise types (FILE, device driver)
    type_norm = df["type"].fillna("").astype(str).str.strip().str.lower()
    df = df[~type_norm.isin(_EXCLUDED_COMPONENT_TYPES)].copy()
    return df


def _classify_findings(
    baseline: pd.DataFrame, current: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Return (fixed, new, unchanged) as DataFrames."""
    baseline_keys = set(baseline["match_key"])
    current_keys = set(current["match_key"])

    fixed_keys = baseline_keys - current_keys
    new_keys = current_keys - baseline_keys
    unchanged_keys = baseline_keys & current_keys

    fixed_df = baseline[baseline["match_key"].isin(fixed_keys)].copy()
    new_df = current[current["match_key"].isin(new_keys)].copy()
    unchanged_df = current[current["match_key"].isin(unchanged_keys)].copy()

    # Sort by severity rank then risk descending
    for df in (fixed_df, new_df):
        df["_sev_rank"] = df["severity"].map(SEVERITY_RANK).fillna(99)
        df["risk"] = pd.to_numeric(df["risk"], errors="coerce").fillna(0)
    fixed_df = fixed_df.sort_values(
        ["_sev_rank", "risk"], ascending=[True, False]
    ).drop(columns="_sev_rank")
    new_df = new_df.sort_values(["_sev_rank", "risk"], ascending=[True, False]).drop(
        columns="_sev_rank"
    )

    return fixed_df, new_df, unchanged_df


def _component_identity(name: Any, version: Any) -> tuple[str, tuple[int, ...] | str]:
    """What two component rows must share to be the same component.

    The single identity rule for this module.  Every surface that answers "is
    this the same component?" goes through it — churn classification, the
    Findings Impact lookup and the component count — so they can never disagree
    about whether ``OpenSSL 1.0`` and ``openssl 1.0.0`` are one component or two.

    Name is lowercased to match ``add_finding_match_key``; version reduces to
    :func:`_version_identity`.
    """
    return (_clean_cell(name).lower(), _version_identity(_clean_cell(version)))


def _distinct_component_count(df: pd.DataFrame | None) -> int:
    """Count distinct components, by the same identity churn classification uses.

    Counting distinct NAMES undercounts an inventory that ships one name at
    several versions.  Counting raw ``(name, version)`` strings overcounts it in
    the other direction: it would call ``OpenSSL 1.0`` and ``openssl 1.0.0`` two
    components while churn treats them as one unchanged component, and it would
    count nameless rows that churn drops.  Counting identities agrees with churn
    on every one of those.
    """
    if df is None or df.empty or "name" not in df.columns:
        return 0
    versions = df["version"].tolist() if "version" in df.columns else [""] * len(df)
    return len(
        {
            _component_identity(name, version)
            for name, version in zip(df["name"].tolist(), versions, strict=True)
            if _clean_cell(name)
        }
    )


# Above this many candidate pairs for ONE component name, _pair_surplus stops
# pairing and reports the surplus as plain removals and additions.  100x100
# unmatched versions of a single name is already far past anything a real
# inventory produces.
_MAX_PAIRING_CANDIDATES = 10_000


def _version_identity(version: str) -> tuple[int, ...] | str:
    """Collapse versions that name the same release to one identity.

    ``1.0`` and ``1.0.0`` are the same release written two ways, so they must
    count as held-on-both-sides rather than as a removal plus an addition.
    Only fully numeric dotted versions reduce to their numeric tuple (with
    trailing zeros stripped): ``_version_tuple`` reads the digits and stops at
    the first non-digit, so trusting it for suffixed versions would collapse
    ``2.9.1+dfsg1-5`` and ``2.9.1+dfsg1-6`` — a real revision bump — into one
    release, and call ``1.0.0-alpha``/``1.0.0-beta`` unchanged.  Anything with
    a suffix keeps its lowercased raw string as its identity.
    """
    text = version.strip()
    if text and all(seg.isdigit() for seg in text.split(".")):
        parsed = _version_tuple(text)
        if parsed is not None:
            trimmed = list(parsed)
            while trimmed and trimmed[-1] == 0:
                trimmed.pop()
            return tuple(trimmed)
    return text.lower()


def _version_distance(before: str, after: str) -> tuple[int, tuple[int, ...]]:
    """How far apart two versions are, for pairing surplus variants.

    Returns a sort key, smallest = closest.  Pairs where either side is
    unparseable sort last (first element 1), since no meaningful distance
    exists for them.  For parseable pairs the key is the per-position absolute
    difference of the zero-padded numeric tuples, so a difference in the major
    version outweighs any difference further right: ``2.3`` is nearer to
    ``2.4`` than to ``3.0``.
    """
    left = _version_tuple(before)
    right = _version_tuple(after)
    if left is None or right is None:
        return (1, ())
    width = max(len(left), len(right))
    left += (0,) * (width - len(left))
    right += (0,) * (width - len(right))
    return (0, tuple(abs(a - b) for a, b in zip(left, right, strict=True)))


def _pair_surplus(
    leftover_base: list[str], leftover_curr: list[str], name: str = ""
) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Pair surplus versions of one name by closeness, nearest pair first.

    Returns ``(pairs, unpaired_base, unpaired_curr)``.  Each pair is one real
    version move; whatever is left over on either side is a variant that only
    exists on that side.

    Greedy nearest-first, not a global optimum: the candidate pairs are sorted
    by distance and taken in order, skipping any whose either end is already
    claimed.  Equal distances prefer the upgrade: ``2.3`` leaving while ``2.2``
    and ``2.4`` arrive pairs ``2.3 → 2.4``, not the equally-near downgrade —
    a downgrade shown as an update misleads more than an upgrade does.
    Remaining ties break on input position, so the result is deterministic.

    Pairs with no meaningful distance (either side unparseable) are taken only
    when exactly one version remains unclaimed on each side — the name's one
    leftover variant changed, whatever the strings look like.  With more than
    one remaining, any junk-to-junk assignment would be arbitrary, so those
    versions are reported plainly as removed and added instead.

    Cost is O(b*c) over the UNMATCHED versions of a SINGLE name, not over the
    inventory — the whole-frame pass stays linear.  Past
    ``_MAX_PAIRING_CANDIDATES`` candidate pairs the pairing is skipped (with a
    warning) and every surplus version is reported plainly as removed or
    added.  That bounds the work, and it is the more honest output at that
    size: with hundreds of unmatched versions on one name, any pairing this
    could invent is noise.
    """
    if len(leftover_base) * len(leftover_curr) > _MAX_PAIRING_CANDIDATES:
        logger.warning(
            "Version Comparison: component %r has %d x %d unmatched versions, "
            "past the pairing bound — reporting them as plain removals and "
            "additions instead of pairing.",
            name or "<unknown>",
            len(leftover_base),
            len(leftover_curr),
        )
        return [], list(leftover_base), list(leftover_curr)

    def _is_downgrade(before: str, after: str) -> int:
        left = _version_tuple(before)
        right = _version_tuple(after)
        if left is None or right is None:
            return 0
        width = max(len(left), len(right))
        return (
            1
            if right + (0,) * (width - len(right)) < left + (0,) * (width - len(left))
            else 0
        )

    candidates = sorted(
        (_version_distance(before, after), _is_downgrade(before, after), bi, ci)
        for bi, before in enumerate(leftover_base)
        for ci, after in enumerate(leftover_curr)
    )
    claimed_base: set[int] = set()
    claimed_curr: set[int] = set()
    pairs: list[tuple[str, str]] = []
    for distance, _downgrade, bi, ci in candidates:
        if bi in claimed_base or ci in claimed_curr:
            continue
        if distance[0] == 1 and not (
            len(leftover_base) - len(claimed_base) == 1
            and len(leftover_curr) - len(claimed_curr) == 1
        ):
            # No meaningful distance and more than one candidate remains on a
            # side: pairing would be arbitrary.  Candidates are sorted, so
            # every parseable pair was already taken — remaining counts are
            # final and this skip applies to all further candidates too.
            continue
        claimed_base.add(bi)
        claimed_curr.add(ci)
        pairs.append((leftover_base[bi], leftover_curr[ci]))
    return (
        pairs,
        [v for i, v in enumerate(leftover_base) if i not in claimed_base],
        [v for i, v in enumerate(leftover_curr) if i not in claimed_curr],
    )


def _clean_cell(value: Any) -> str:
    """Trim a frame cell to a plain string, treating NaN/"nan" as empty."""
    if pd.isna(value):
        return ""
    text = str(value).strip()
    return "" if text.lower() == "nan" else text


def _versions_by_name(df: pd.DataFrame) -> dict[str, tuple[str, list[str]]]:
    """Group a component frame into ``lowercased name -> (display name, versions)``.

    Names are keyed case-insensitively to match ``add_finding_match_key``, which
    lowercases ``component_name`` for its key — otherwise a casing-only rename
    reads as a removal plus an addition here while the findings tables treat it
    as the same component.  The display name is the first spelling encountered
    in row order, so the report still shows the name as the SBOM wrote it.

    Rows with a blank name are dropped: they carry no identity, so grouping them
    all under ``""`` would pair unrelated nameless components with each other.
    """
    if df.empty or "name" not in df.columns:
        return {}
    versions_col = df["version"].tolist() if "version" in df.columns else [""] * len(df)
    display: dict[str, str] = {}
    seen: dict[str, dict[tuple[int, ...] | str, str]] = {}
    for raw_name, raw_version in zip(df["name"].tolist(), versions_col, strict=True):
        name = _clean_cell(raw_name)
        if not name:
            continue
        key = name.lower()
        version = _clean_cell(raw_version)
        display.setdefault(key, name)
        # Keyed by identity, so one release written two ways (1.0 and 1.0.0)
        # collapses to a single entry WITHIN a side too, not just across sides.
        # Otherwise the second spelling has nothing to pair with and surfaces as
        # a phantom removal.  The first spelling in row order is the one shown.
        seen.setdefault(key, {}).setdefault(_version_identity(version), version)
    return {
        key: (
            display[key],
            sorted(versions.values(), key=version_sort_key, reverse=True),
        )
        for key, versions in seen.items()
    }


def _classify_components(baseline: pd.DataFrame, current: pd.DataFrame) -> pd.DataFrame:
    """Return a DataFrame of component changes (added, removed, updated).

    Components are matched on (name, version), not on name alone.  A name that
    carries the same version on both sides is unchanged even when that name also
    appears at other versions.  Matching on name alone cross-joined every
    variant of a repeated name against every other variant, so a component
    present at two versions on both sides produced two phantom "updated" rows
    pointing in opposite directions (e.g. tcp_cubic 5.10.61 -> 2.3 AND
    2.3 -> 5.10.61).

    Versions left unmatched on both sides are paired by closeness
    (:func:`_pair_surplus`), so ``2.3`` disappearing while ``2.4`` and ``3.0``
    appear reports ``2.3 -> 2.4`` updated plus ``3.0`` added, not an arbitrary
    ``2.3 -> 3.0``.  A pairing is reported as ``updated`` in either direction;
    the row carries both versions, so a downgrade is visible as such.
    """
    columns = ["change_type", "name", "version_baseline", "version_current"]
    if baseline.empty and current.empty:
        return pd.DataFrame(columns=columns)

    base_by_name = _versions_by_name(baseline)
    curr_by_name = _versions_by_name(current)

    rows: list[dict[str, str]] = []
    for key in sorted(set(base_by_name) | set(curr_by_name)):
        display_name, base_versions = base_by_name.get(key, ("", []))
        curr_display, curr_versions = curr_by_name.get(key, ("", []))
        display_name = display_name or curr_display

        # A version carried on both sides is unchanged and drops out entirely.
        held = {_version_identity(v) for v in base_versions} & {
            _version_identity(v) for v in curr_versions
        }
        leftover_base = [v for v in base_versions if _version_identity(v) not in held]
        leftover_curr = [v for v in curr_versions if _version_identity(v) not in held]

        pairs, unpaired_base, unpaired_curr = _pair_surplus(
            leftover_base, leftover_curr, display_name
        )
        for before, after in pairs:
            rows.append(
                {
                    "change_type": "updated",
                    "name": display_name,
                    "version_baseline": before,
                    "version_current": after,
                }
            )
        for before in unpaired_base:
            rows.append(
                {
                    "change_type": "removed",
                    "name": display_name,
                    "version_baseline": before,
                    "version_current": "",
                }
            )
        for after in unpaired_curr:
            rows.append(
                {
                    "change_type": "added",
                    "name": display_name,
                    "version_baseline": "",
                    "version_current": after,
                }
            )

    churn = pd.DataFrame(rows, columns=columns)
    if churn.empty:
        return churn

    # Explicit, fully-specified order so CSV/XLSX output is reproducible run to
    # run: removed, then updated, then added; within each, by name and version.
    type_order = {"removed": 0, "updated": 1, "added": 2}
    churn["_type_sort"] = churn["change_type"].map(type_order)
    churn["_name_sort"] = churn["name"].str.lower()
    churn["_version_sort"] = churn.apply(
        lambda r: version_sort_key(r["version_baseline"] or r["version_current"]),
        axis=1,
    )
    churn = churn.sort_values(
        ["_type_sort", "_name_sort", "_version_sort"], kind="stable"
    ).drop(columns=["_type_sort", "_name_sort", "_version_sort"])

    return churn


def _attach_findings_impact(
    churn: pd.DataFrame,
    fixed_df: pd.DataFrame,
    new_df: pd.DataFrame,
) -> pd.DataFrame:
    """Add 'findings_impact' column to component churn."""
    if churn.empty:
        churn["findings_impact"] = pd.Series(dtype=int)
        return churn

    # Pre-compute counts per (lowercased name, version) so a name that churns at
    # several versions attributes each finding to the variant that carries it,
    # instead of every row claiming the whole name-level total.  Names are
    # lowercased to match _versions_by_name's case-insensitive keying.
    def _variant_counts(df: pd.DataFrame) -> Counter:
        if df.empty or "component_name" not in df.columns:
            return Counter()
        versions = (
            df["component_version"].tolist()
            if "component_version" in df.columns
            else [""] * len(df)
        )
        return Counter(
            _component_identity(name, version)
            for name, version in zip(
                df["component_name"].tolist(), versions, strict=True
            )
        )

    fixed_counts = _variant_counts(fixed_df)
    new_counts = _variant_counts(new_df)

    def _impact(row: pd.Series) -> int:
        change_type = row["change_type"]
        # Keyed by _component_identity, the same rule that decided which rows
        # are churn at all — matching on the raw version string would miss a
        # finding recorded at 1.0.0 against a churn row that reads 1.0.
        before = _component_identity(row["name"], row["version_baseline"])
        after = _component_identity(row["name"], row["version_current"])
        if change_type == "removed":
            return int(fixed_counts.get(before, 0))
        if change_type == "added":
            return int(new_counts.get(after, 0))
        # An update clears the baseline variant's findings and introduces the
        # current variant's, so both sides count.
        return int(new_counts.get(after, 0)) + int(fixed_counts.get(before, 0))

    churn["findings_impact"] = churn.apply(_impact, axis=1)
    return churn


def _compute_kpi(
    baseline: pd.DataFrame,
    current: pd.DataFrame,
    baseline_comp: pd.DataFrame,
    current_comp: pd.DataFrame,
    fixed: pd.DataFrame,
    new: pd.DataFrame,
    baseline_info: dict,
    current_info: dict,
) -> dict[str, Any]:
    """Produce KPI card values (first → latest)."""

    def _delta(a: int, b: int) -> dict:
        d = b - a
        pct = round((d / a) * 100, 1) if a else 0.0
        return {"baseline": a, "current": b, "delta": d, "pct": pct}

    total = _delta(len(baseline), len(current))

    crit_base = (
        int((baseline["severity"] == "CRITICAL").sum()) if not baseline.empty else 0
    )
    crit_curr = (
        int((current["severity"] == "CRITICAL").sum()) if not current.empty else 0
    )
    critical = _delta(crit_base, crit_curr)

    high_base = int((baseline["severity"] == "HIGH").sum()) if not baseline.empty else 0
    high_curr = int((current["severity"] == "HIGH").sum()) if not current.empty else 0
    high = _delta(high_base, high_curr)

    comp_base = _distinct_component_count(baseline_comp)
    comp_curr = _distinct_component_count(current_comp)
    components = _delta(comp_base, comp_curr)

    return {
        "total_findings": total,
        "critical_findings": critical,
        "high_findings": high,
        "components": components,
        "fixed_count": len(fixed),
        "new_count": len(new),
        "baseline_version": baseline_info.get("name", "First"),
        "current_version": current_info.get("name", "Latest"),
    }


# ---------------------------------------------------------------------------
# External CVE change helpers
# ---------------------------------------------------------------------------


def _fetch_external_cve_changes(
    api_client: Any,
    baseline_created: str,
    current_created: str,
) -> dict[str, list[dict]]:
    """Fetch and classify CVE updates between two version creation dates.

    Returns the same structure as ``_process_cve_updates``:
    ``{"added": [...], "severity_escalated": [...], "exploit_gained": [...], ...}``
    Returns an empty dict if ``api_client`` is None or dates are missing.
    """
    if api_client is None:
        return {}

    start = _to_iso8601z(baseline_created)
    end = _to_iso8601z(current_created)
    if not start or not end:
        return {}

    params: dict[str, Any] = {
        "startDate": start,
        "endDate": end,
        "limit": 100,
        "offset": 0,
    }
    results: list[dict] = []
    while True:
        try:
            batch = api_client.get("/public/v0/cves/updates", params=params)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not fetch CVE updates (offset=%d): %s", params["offset"], exc
            )
            break
        if not batch:
            break
        results.extend(batch)
        if len(batch) < 100:
            break
        params["offset"] += 100

    logger.debug("Fetched %d CVE updates for window %s → %s", len(results), start, end)
    return _process_cve_updates(results)


def _build_externally_changed(
    unchanged_df: pd.DataFrame,
    cve_updates: dict[str, list[dict]],
) -> list[dict]:
    """Cross-reference unchanged CVE findings with severity/exploit updates.

    Returns a list of dicts describing findings that were present in both
    versions but whose CVE metadata changed externally during the window.
    A finding qualifies if its CVE ID appears in ``severity_escalated``,
    ``exploit_gained``, or ``exploit_subsided``.
    """
    if unchanged_df.empty or not cve_updates:
        return []

    # Effective CVE id: ``cveId`` when present, else a CVE-shaped ``findingId``
    # (real /public/v0/findings rows carry the CVE in findingId with cveId
    # null). Matching on cveId alone would skip those rows entirely.
    eff_cve = unchanged_df["cveId"].fillna("").astype(str).str.strip()
    if "findingId" in unchanged_df.columns:
        fid = unchanged_df["findingId"].fillna("").astype(str).str.strip()
        fid_is_cve = fid.str.upper().str.startswith("CVE-")
        eff_cve = eff_cve.where(eff_cve != "", fid.where(fid_is_cve, ""))
    cve_df = unchanged_df.assign(_eff_cve=eff_cve)
    cve_df = cve_df[cve_df["_eff_cve"] != ""]
    if cve_df.empty:
        return []

    unchanged_cve_ids = set(cve_df["_eff_cve"])
    result: list[dict] = []

    for change_type in ("severity_escalated", "exploit_gained", "exploit_subsided"):
        for upd in cve_updates.get(change_type, []):
            cve_id = upd.get("cve_id", "")
            if cve_id not in unchanged_cve_ids:
                continue
            matching = cve_df[cve_df["_eff_cve"] == cve_id]
            for _, row in matching.iterrows():
                entry: dict[str, Any] = {
                    "cve_id": cve_id,
                    "component_name": row.get("component_name", ""),
                    "change_type": change_type,
                    "projects": upd.get("projects", []),
                }
                if change_type == "severity_escalated":
                    entry["old_severity"] = upd.get("old_severity")
                    entry["new_severity"] = upd.get("new_severity")
                    entry["old_exploit"] = None
                    entry["new_exploit"] = None
                else:
                    entry["old_severity"] = None
                    entry["new_severity"] = upd.get("severity")
                    entry["old_exploit"] = upd.get("old_exploit")
                    entry["new_exploit"] = upd.get("new_exploit")
                result.append(entry)

    return result


def _annotate_new_findings(
    new_df: pd.DataFrame,
    cve_updates: dict[str, list[dict]],
) -> pd.DataFrame:
    """Add ``external_change_note`` field to new findings whose CVE was
    externally updated during the comparison window.

    The note communicates that the severity escalation or exploit gain is not
    a developer-introduced regression.
    """
    if new_df.empty or not cve_updates:
        return new_df

    escalated = {
        u.get("cve_id", ""): u for u in cve_updates.get("severity_escalated", [])
    }
    exploit_gained = {
        u.get("cve_id", ""): u for u in cve_updates.get("exploit_gained", [])
    }

    def _note(row: pd.Series) -> str:
        cve_id = str(row.get("cveId") or "").strip()
        if not cve_id:
            # Real findings carry the CVE in findingId with cveId null.
            fid = str(row.get("findingId") or "").strip()
            if fid.upper().startswith("CVE-"):
                cve_id = fid
        if not cve_id:
            return ""
        if cve_id in escalated:
            u = escalated[cve_id]
            return (
                f"Severity escalated from {u.get('old_severity')} to "
                f"{u.get('new_severity')} by platform update "
                f"(not a developer-introduced regression)"
            )
        if cve_id in exploit_gained:
            u = exploit_gained[cve_id]
            return (
                f"Exploit maturity gained ({u.get('new_exploit')}) by platform update "
                f"(not a developer-introduced regression)"
            )
        return ""

    new_df = new_df.copy()
    new_df["external_change_note"] = new_df.apply(_note, axis=1)
    return new_df
