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
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Severity ordering for display
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNSPECIFIED"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def version_comparison_transform(
    data: list[dict[str, Any]],
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

    if not projects_raw:
        logger.warning("No project data for version comparison")
        return _empty_result()

    project_results: list[dict[str, Any]] = []
    all_summary_rows: list[dict] = []

    for proj in projects_raw:
        pname = proj.get("project_name", "Unknown")
        versions = proj.get("versions", [])

        if len(versions) < 2:
            logger.debug("Skipping %s — only %d version(s)", pname, len(versions))
            continue

        result = _process_single_project(pname, versions)
        # Skip projects where all versions were filtered out (e.g. failed scans)
        if not result.get("progression"):
            continue
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
                        "Risk": row.get("risk", ""),
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
                        "Risk": row.get("risk", ""),
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
                        "Risk": row.get("risk", ""),
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

    # Build CSV/XLSX summary
    summary_df = pd.DataFrame(all_summary_rows) if all_summary_rows else pd.DataFrame()
    if not summary_df.empty and "Severity" in summary_df.columns:
        summary_df["_sev_rank"] = summary_df["Severity"].map(SEVERITY_RANK).fillna(99)
        summary_df.sort_values(
            ["Project", "Version", "_sev_rank"],
            ascending=True,
            inplace=True,
        )
        summary_df.drop(columns="_sev_rank", inplace=True)

    # Remove internal keys from project results before passing to template
    for pr in project_results:
        pr.pop("_summary_rows", None)

    logger.info(
        "Version comparison: %d project(s), %d total versions processed",
        len(project_results),
        sum(len(pr["progression"]) for pr in project_results),
    )

    return {
        "projects": project_results,
        "kpi": agg_kpi,
        "summary": summary_df,
        "detail_findings": detail_findings_df,
        "detail_findings_churn": detail_findings_churn_df,
        "detail_component_churn": detail_component_churn_df,
        "project_count": len(project_results),
    }


# ---------------------------------------------------------------------------
# Per-project processing
# ---------------------------------------------------------------------------


def _process_single_project(
    project_name: str,
    versions: list[dict[str, Any]],
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
    # (a legitimate scan always produces at least some components)
    valid_versions = []
    for v in versions:
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

    for i, (v_meta, f_df, c_df) in enumerate(version_dfs):
        vname = v_meta.get("name", v_meta.get("id", f"v{i+1}"))
        created = v_meta.get("created", "")

        total = len(f_df)
        sev_counts = _severity_counts(f_df)
        comp_count = len(c_df["name"].unique()) if not c_df.empty else 0

        step: dict[str, Any] = {
            "version": vname,
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
        else:
            prev_v_meta_i = version_dfs[i - 1][0]
            prev_f_df = version_dfs[i - 1][1]
            prev_c_df = version_dfs[i - 1][2]
            fixed_df, new_df, _ = _classify_findings(prev_f_df, f_df)
            churn_df = _classify_components(prev_c_df, c_df)
            churn_df = _attach_findings_impact(
                churn_df,
                fixed_df,
                new_df,
                prev_f_df,
                f_df,
            )
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

        progression.append(step)

    # Latest pair: detailed tables
    first_v_meta, first_f_df, first_c_df = version_dfs[0]
    last_v_meta, last_f_df, last_c_df = version_dfs[-1]
    prev_v_meta, prev_f_df, prev_c_df = version_dfs[-2]

    # Latest delta
    fixed_latest, new_latest, unchanged_latest = _classify_findings(
        prev_f_df, last_f_df
    )
    component_churn = _classify_components(prev_c_df, last_c_df)
    component_churn = _attach_findings_impact(
        component_churn,
        fixed_latest,
        new_latest,
        prev_f_df,
        last_f_df,
    )

    # First→Last KPI
    kpi = _compute_kpi(
        first_f_df,
        last_f_df,
        first_c_df,
        last_c_df,
        fixed_latest,
        new_latest,
        {"name": first_v_meta.get("name", "First")},
        {"name": last_v_meta.get("name", "Latest")},
    )

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

    return {
        "project_name": project_name,
        "progression": progression,
        "latest_delta": {
            "baseline_version": prev_v_meta.get("name", ""),
            "current_version": last_v_meta.get("name", ""),
            "fixed_findings": _df_to_records(fixed_latest),
            "new_findings": _df_to_records(new_latest),
            "fixed_by_severity": _severity_counts(fixed_latest),
            "new_by_severity": _severity_counts(new_latest),
            "fixed_severity_summary": _severity_summary_str(
                _severity_counts(fixed_latest)
            ),
            "new_severity_summary": _severity_summary_str(_severity_counts(new_latest)),
            "component_churn": _df_to_records(component_churn),
            "fixed_count": len(fixed_latest),
            "new_count": len(new_latest),
            "unchanged_count": unchanged_latest,
        },
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
    """Build portfolio-level KPI from per-project results."""
    total_first = sum(pr["progression"][0]["total"] for pr in project_results)
    total_last = sum(pr["progression"][-1]["total"] for pr in project_results)

    crit_first = sum(pr["progression"][0]["critical"] for pr in project_results)
    crit_last = sum(pr["progression"][-1]["critical"] for pr in project_results)

    high_first = sum(pr["progression"][0]["high"] for pr in project_results)
    high_last = sum(pr["progression"][-1]["high"] for pr in project_results)

    comp_first = sum(pr["progression"][0]["components"] for pr in project_results)
    comp_last = sum(pr["progression"][-1]["components"] for pr in project_results)

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
    # Prefer cveId when available; otherwise build a composite fingerprint
    # from component name + severity + risk score.  This avoids false churn
    # when the platform assigns new finding IDs to the same vulnerability
    # after a component version bump (e.g. musl 1.2.5-r8 → 1.2.5-r21).
    has_cve = df["cveId"].notna() & (df["cveId"] != "")
    fallback = (
        df["component_name"].fillna("").astype(str)
        + "|"
        + df["severity"].astype(str)
        + "|"
        + pd.to_numeric(df["risk"], errors="coerce").fillna(0).astype(str)
    )
    df["match_key"] = df["cveId"].where(has_cve, fallback)

    return df


# Component types to exclude from churn (noise, not meaningful SBOM entries)
_EXCLUDED_COMPONENT_TYPES = {"file", "device driver", "device_driver"}


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
) -> tuple[pd.DataFrame, pd.DataFrame, int]:
    """Return (fixed, new, unchanged_count)."""
    baseline_keys = set(baseline["match_key"])
    current_keys = set(current["match_key"])

    fixed_keys = baseline_keys - current_keys
    new_keys = current_keys - baseline_keys
    unchanged_count = len(baseline_keys & current_keys)

    fixed_df = baseline[baseline["match_key"].isin(fixed_keys)].copy()
    new_df = current[current["match_key"].isin(new_keys)].copy()

    # Sort by severity rank then risk descending
    for df in (fixed_df, new_df):
        df["_sev_rank"] = df["severity"].map(SEVERITY_RANK).fillna(99)
        df["risk"] = pd.to_numeric(df["risk"], errors="coerce").fillna(0)
        df.sort_values(["_sev_rank", "risk"], ascending=[True, False], inplace=True)
        df.drop(columns="_sev_rank", inplace=True)

    return fixed_df, new_df, unchanged_count


def _classify_components(baseline: pd.DataFrame, current: pd.DataFrame) -> pd.DataFrame:
    """Return a DataFrame of component changes (added, removed, updated)."""
    if baseline.empty and current.empty:
        return pd.DataFrame(
            columns=[
                "change_type",
                "name",
                "version_baseline",
                "version_current",
            ]
        )

    merged = pd.merge(
        baseline[["name", "version"]].drop_duplicates("name"),
        current[["name", "version"]].drop_duplicates("name"),
        on="name",
        how="outer",
        suffixes=("_baseline", "_current"),
    )

    conditions = [
        merged["version_baseline"].isna(),
        merged["version_current"].isna(),
        merged["version_baseline"] != merged["version_current"],
    ]
    choices = ["added", "removed", "updated"]
    merged["change_type"] = np.select(conditions, choices, default="unchanged")
    churn = merged[merged["change_type"] != "unchanged"].copy()

    type_order = {"removed": 0, "updated": 1, "added": 2}
    churn["_sort"] = churn["change_type"].map(type_order)
    churn.sort_values("_sort", inplace=True)
    churn.drop(columns="_sort", inplace=True)

    # Avoid NaN in version columns (shows as "nan" in HTML); use empty string for missing
    def _version_str(x: Any) -> str:
        if pd.isna(x):
            return ""
        s = str(x).strip()
        return "" if s.lower() == "nan" else s

    for col in ("version_baseline", "version_current"):
        churn[col] = churn[col].apply(_version_str)

    return churn


def _attach_findings_impact(
    churn: pd.DataFrame,
    fixed_df: pd.DataFrame,
    new_df: pd.DataFrame,
    baseline: pd.DataFrame,
    current: pd.DataFrame,
) -> pd.DataFrame:
    """Add 'findings_impact' column to component churn."""
    if churn.empty:
        churn["findings_impact"] = pd.Series(dtype=int)
        return churn

    impact = []
    for _, row in churn.iterrows():
        name = row["name"]
        ct = row["change_type"]
        if ct == "removed":
            count = len(fixed_df[fixed_df["component_name"] == name])
        elif ct == "added":
            count = len(new_df[new_df["component_name"] == name])
        else:
            count = len(new_df[new_df["component_name"] == name]) + len(
                fixed_df[fixed_df["component_name"] == name]
            )
        impact.append(count)
    churn["findings_impact"] = impact
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

    comp_base = len(baseline_comp["name"].unique()) if not baseline_comp.empty else 0
    comp_curr = len(current_comp["name"].unique()) if not current_comp.empty else 0
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
