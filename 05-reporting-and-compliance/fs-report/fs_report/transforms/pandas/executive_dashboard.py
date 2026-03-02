"""
Executive Dashboard transform for the Finite State Reporting Kit.

Produces chart-ready data structures for an executive-level security dashboard
with 11 visualization sections.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# Severity ordering and colors (matches triage_prioritization / executive_summary)
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {
    "critical": "#d32f2f",
    "high": "#f57c00",
    "medium": "#fbc02d",
    "low": "#388e3c",
}

# Statuses considered resolved (findings excluded from "open issues")
RESOLVED_STATUSES = frozenset(
    {
        "RESOLVED",
        "RESOLVED_WITH_PEDIGREE",
        "NOT_AFFECTED",
        "FALSE_POSITIVE",
    }
)

# Finding category mapping
CATEGORY_MAP = {
    "cve": "CVEs",
    "potential_zero_day": "Potential Zero Days",
    "crypto_material": "Crypto",
    "credentials": "Credentials",
    "config_issues": "Config Issues",
}


def _get_config(config: Any, additional_data: dict[str, Any] | None) -> Any:
    """Resolve config from direct param or additional_data."""
    if config is not None:
        return config
    if additional_data and "config" in additional_data:
        return additional_data["config"]
    return None


def _parse_date(value: Any) -> datetime | None:
    """Parse a date string into a datetime, returning None on failure."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    if not s:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            # Ensure tz-aware (API timestamps are UTC)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return None


def _severity_sort_key(sev: str) -> int:
    """Return sort key for severity (lower = more severe)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(sev.lower() if isinstance(sev, str) else "", 99)


def _build_findings_by_group(
    df: pd.DataFrame, folder_filter: str | None
) -> tuple[dict[str, Any], str]:
    """Build stacked bar chart data grouped by folder or project."""
    if folder_filter:
        group_col = "project_name"
        group_label = "Project"
    else:
        group_col = "folder_name"
        group_label = "Folder"

    if df.empty or group_col not in df.columns:
        return {"labels": [], "datasets": []}, group_label

    # Pivot: group × severity → count
    pivot = df.groupby([group_col, "severity"]).size().unstack(fill_value=0)

    # Sort groups by total descending
    pivot["_total"] = pivot.sum(axis=1)
    pivot = pivot.sort_values("_total", ascending=False)
    pivot = pivot.drop(columns=["_total"])

    # Limit to top 30, group rest as "Other"
    if len(pivot) > 30:
        top = pivot.iloc[:30]
        rest = pivot.iloc[30:].sum()
        rest.name = "Other"
        pivot = pd.concat([top, rest.to_frame().T])

    labels = pivot.index.tolist()
    datasets = []
    for sev in SEVERITY_ORDER:
        if sev in pivot.columns:
            datasets.append(
                {
                    "label": sev.capitalize(),
                    "data": pivot[sev].tolist(),
                    "backgroundColor": SEVERITY_COLORS[sev],
                }
            )

    return {"labels": labels, "datasets": datasets}, group_label


def _build_severity_trends(
    df: pd.DataFrame, start_date: str | None, end_date: str | None
) -> dict[str, Any]:
    """Build multi-line chart data for Critical + High over the configured period."""
    if df.empty:
        return {"labels": [], "datasets": [], "month_count": 0}

    dates = df["_detected_dt"].dropna()
    if dates.empty:
        return {"labels": [], "datasets": [], "month_count": 0}

    # Determine month range from config period (fall back to last 12 months)
    now = datetime.now(UTC)
    period_start = _parse_date(start_date) if start_date else None
    period_end = _parse_date(end_date) if end_date else None
    if period_start is None:
        # Default: 12 months back
        y, m = now.year, now.month - 11
        while m <= 0:
            m += 12
            y -= 1
        period_start = datetime(y, m, 1, tzinfo=UTC)
    if period_end is None:
        period_end = now

    # Generate month labels spanning the period
    months = []
    y, m = period_start.year, period_start.month
    while (y, m) <= (period_end.year, period_end.month):
        months.append((y, m))
        m += 1
        if m > 12:
            m = 1
            y += 1

    month_labels = [f"{y}-{m:02d}" for y, m in months]

    # Count critical and high per month
    critical_counts: dict[str, int] = defaultdict(int)
    high_counts: dict[str, int] = defaultdict(int)
    for _, row in df.iterrows():
        dt = row.get("_detected_dt")
        sev = str(row.get("severity", "")).lower()
        if dt is None:
            continue
        key = f"{dt.year}-{dt.month:02d}"
        if sev == "critical":
            critical_counts[key] += 1
        elif sev == "high":
            high_counts[key] += 1

    return {
        "labels": month_labels,
        "month_count": len(month_labels),
        "datasets": [
            {
                "label": "Critical",
                "data": [critical_counts.get(m, 0) for m in month_labels],
                "borderColor": SEVERITY_COLORS["critical"],
                "backgroundColor": SEVERITY_COLORS["critical"] + "33",
                "tension": 0.3,
                "fill": False,
            },
            {
                "label": "High",
                "data": [high_counts.get(m, 0) for m in month_labels],
                "borderColor": SEVERITY_COLORS["high"],
                "backgroundColor": SEVERITY_COLORS["high"] + "33",
                "tension": 0.3,
                "fill": False,
            },
        ],
    }


def _build_risk_donut_and_table(
    df: pd.DataFrame,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build risk doughnut and top-risk products table."""
    if df.empty or "project_name" not in df.columns:
        return {
            "labels": [],
            "data": [],
            "backgroundColor": [],
            "total_artifacts": 0,
        }, []

    # Score per project: min(100, critical*10 + high*5 + medium*2 + low*0.5)
    project_scores: dict[str, dict[str, Any]] = {}
    for project, grp in df.groupby("project_name"):
        sev_counts = grp["severity"].str.lower().value_counts()
        c = int(sev_counts.get("critical", 0))
        h = int(sev_counts.get("high", 0))
        m = int(sev_counts.get("medium", 0))
        lo = int(sev_counts.get("low", 0))
        score = min(100, c * 10 + h * 5 + m * 2 + lo * 0.5)
        max_sev = "low"
        if c > 0:
            max_sev = "critical"
        elif h > 0:
            max_sev = "high"
        elif m > 0:
            max_sev = "medium"
        project_scores[str(project)] = {
            "score": score,
            "max_severity": max_sev,
            "critical": c,
            "high": h,
            "medium": m,
            "low": lo,
            "total": c + h + m + lo,
        }

    # Donut: bucket projects by risk score range
    score_buckets = {
        "Critical (80-100)": 0,
        "High (50-79)": 0,
        "Medium (20-49)": 0,
        "Low (0-19)": 0,
    }
    for v in project_scores.values():
        s = v["score"]
        if s >= 80:
            score_buckets["Critical (80-100)"] += 1
        elif s >= 50:
            score_buckets["High (50-79)"] += 1
        elif s >= 20:
            score_buckets["Medium (20-49)"] += 1
        else:
            score_buckets["Low (0-19)"] += 1

    bucket_colors = [
        SEVERITY_COLORS["critical"],
        SEVERITY_COLORS["high"],
        SEVERITY_COLORS["medium"],
        SEVERITY_COLORS["low"],
    ]
    donut_labels = []
    donut_data = []
    donut_colors = []
    for (label, count), color in zip(score_buckets.items(), bucket_colors, strict=True):
        if count > 0:
            donut_labels.append(label)
            donut_data.append(count)
            donut_colors.append(color)

    donut = {
        "labels": donut_labels,
        "data": donut_data,
        "backgroundColor": donut_colors,
        "total_artifacts": len(project_scores),
    }

    # Top risk products table (top 15 by score)
    sorted_projects = sorted(
        project_scores.items(), key=lambda x: x[1]["score"], reverse=True
    )[:15]
    top_products = []
    for name, info in sorted_projects:
        top_products.append(
            {
                "project": name,
                "risk_score": round(info["score"], 1),
                "critical": info["critical"],
                "high": info["high"],
                "medium": info["medium"],
                "low": info["low"],
                "total": info["total"],
            }
        )

    return donut, top_products


def _build_open_issues_pie(df: pd.DataFrame) -> dict[str, Any]:
    """Build pie chart for open issues by severity."""
    if df.empty:
        return {"labels": [], "data": [], "backgroundColor": []}

    # Filter out resolved findings
    open_df = df[~df["status"].fillna("").str.upper().isin(RESOLVED_STATUSES)]
    if open_df.empty:
        return {"labels": [], "data": [], "backgroundColor": []}

    sev_counts = open_df["severity"].str.lower().value_counts()
    labels = []
    data = []
    colors = []
    for sev in SEVERITY_ORDER:
        count = int(sev_counts.get(sev, 0))
        if count > 0:
            labels.append(sev.capitalize())
            data.append(count)
            colors.append(SEVERITY_COLORS[sev])

    return {"labels": labels, "data": data, "backgroundColor": colors}


def _build_license_bar(
    components: list[dict[str, Any]], project_ids: set[str]
) -> dict[str, Any]:
    """Build vertical bar chart for top 10 licenses from components."""
    if not components:
        return {"labels": [], "data": []}

    license_counts: Counter = Counter()
    for comp in components:
        # Filter to project scope
        pid = comp.get("projectId") or ""
        if isinstance(pid, dict):
            pid = str(pid.get("id", ""))
        else:
            pid = str(pid)
        # Skip filtering when pid is empty — component was already API-scoped
        if project_ids and pid and pid not in project_ids:
            continue

        license_name = (
            comp.get("declaredLicenses")
            or comp.get("declaredLicense")
            or comp.get("license")
            or "Unknown"
        )
        if not license_name or license_name.strip() == "":
            license_name = "Unknown"
        license_counts[license_name] += 1

    if not license_counts:
        return {"labels": [], "data": []}

    top10 = license_counts.most_common(10)
    return {
        "labels": [lic for lic, _ in top10],
        "data": [count for _, count in top10],
    }


def _build_license_kpis(
    components: list[dict[str, Any]], project_ids: set[str]
) -> dict[str, Any]:
    """Build license health KPIs: copyleft breakdown, permissive count, etc."""
    from fs_report.transforms.pandas.component_list import COPYLEFT_LOOKUP

    if not components:
        return {
            "total": 0,
            "copyleft_strong": 0,
            "copyleft_weak": 0,
            "permissive": 0,
            "unknown": 0,
            "no_license": 0,
            "unique_licenses": 0,
            "copyleft_pct": 0.0,
        }

    strong = 0
    weak = 0
    permissive = 0
    unknown = 0
    no_license = 0
    seen_licenses: set[str] = set()
    total = 0

    for comp in components:
        pid = comp.get("projectId") or ""
        if isinstance(pid, dict):
            pid = str(pid.get("id", ""))
        else:
            pid = str(pid)
        # Skip filtering when pid is empty — component was already API-scoped
        if project_ids and pid and pid not in project_ids:
            continue

        total += 1
        license_name = (
            comp.get("declaredLicenses")
            or comp.get("declaredLicense")
            or comp.get("license")
            or ""
        )
        if not license_name or license_name.strip() == "":
            no_license += 1
            continue

        license_name = license_name.strip()
        seen_licenses.add(license_name)

        classification = COPYLEFT_LOOKUP.get(license_name)
        if classification == "STRONG_COPYLEFT":
            strong += 1
        elif classification == "WEAK_COPYLEFT":
            weak += 1
        elif classification == "PERMISSIVE":
            permissive += 1
        else:
            unknown += 1

    copyleft_pct = round(100 * (strong + weak) / total, 1) if total > 0 else 0.0

    return {
        "total": total,
        "copyleft_strong": strong,
        "copyleft_weak": weak,
        "permissive": permissive,
        "unknown": unknown,
        "no_license": no_license,
        "unique_licenses": len(seen_licenses),
        "copyleft_pct": copyleft_pct,
    }


def _build_project_table(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Build project findings table sorted by total descending."""
    if df.empty or "project_name" not in df.columns:
        return []

    table = []
    for project, grp in df.groupby("project_name"):
        sev_counts = grp["severity"].str.lower().value_counts()
        c = int(sev_counts.get("critical", 0))
        h = int(sev_counts.get("high", 0))
        m = int(sev_counts.get("medium", 0))
        lo = int(sev_counts.get("low", 0))
        table.append(
            {
                "project": str(project),
                "critical": c,
                "high": h,
                "medium": m,
                "low": lo,
                "total": c + h + m + lo,
            }
        )

    table.sort(key=lambda x: x.get("total", 0), reverse=True)  # type: ignore[arg-type, return-value]
    return table


def _build_exploit_intel(df: pd.DataFrame) -> dict[str, Any]:
    """Build horizontal bar chart for exploit intelligence from findings data.

    Uses the boolean flags available directly on finding records (inKev,
    hasKnownExploit).  Detailed exploit breakdown (ransomware, PoC, etc.)
    requires per-finding API calls and is not yet available at portfolio scale.
    """
    if df.empty:
        return {"labels": [], "data": []}

    # Use vectorised column access where possible
    kev_col = "inKev" if "inKev" in df.columns else "in_kev"
    exploit_col = (
        "hasKnownExploit" if "hasKnownExploit" in df.columns else "has_known_exploit"
    )

    kev_count = (
        int(df[kev_col].fillna(False).astype(bool).sum())
        if kev_col in df.columns
        else 0
    )
    has_exploit_count = (
        int(df[exploit_col].fillna(False).astype(bool).sum())
        if exploit_col in df.columns
        else 0
    )

    labels = ["CISA KEV", "Known Exploits"]
    data = [kev_count, has_exploit_count]

    return {"labels": labels, "data": data}


def _build_findings_by_type(df: pd.DataFrame) -> dict[str, Any]:
    """Build horizontal bar chart for findings categorized by type."""
    if df.empty:
        return {"labels": [], "data": []}

    type_counts: Counter = Counter()
    for _, row in df.iterrows():
        category = str(row.get("category", "") or "").lower().strip()
        label = CATEGORY_MAP.get(
            category, category.replace("_", " ").title() if category else "Other"
        )
        type_counts[label] += 1

    if not type_counts:
        return {"labels": [], "data": []}

    # Sort by count descending
    sorted_types = type_counts.most_common()
    return {
        "labels": [t for t, _ in sorted_types],
        "data": [c for _, c in sorted_types],
    }


_POLICY_ORDER: dict[str, int] = {"PERMITTED": 0, "WARNING": 1, "VIOLATION": 2}


def _extract_policy(comp: dict[str, Any]) -> str:
    """Extract the most restrictive policy from a component's license details."""
    best_rank = -1
    best_policy = ""
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        details = comp.get(field)
        if not isinstance(details, list):
            continue
        for ld in details:
            if not isinstance(ld, dict):
                continue
            p = (ld.get("policy") or "").upper()
            rank = _POLICY_ORDER.get(p, -1)
            if rank > best_rank:
                best_rank = rank
                best_policy = p
    return best_policy


def _build_sca_summary(
    df: pd.DataFrame,
    components: list[dict[str, Any]],
    project_ids: set[str],
    start_date: str | None,
) -> dict[str, Any]:
    """Build SCA summary KPI cards with optional delta indicators."""
    # Count unique projects
    project_count = (
        df["project_name"].nunique()
        if not df.empty and "project_name" in df.columns
        else 0
    )

    # Count components in scope
    comp_count = 0
    violation_count = 0
    warning_count = 0
    for comp in components:
        pid = comp.get("projectId") or ""
        if isinstance(pid, dict):
            pid = str(pid.get("id", ""))
        else:
            pid = str(pid)
        # Skip filtering when pid is empty — component was already API-scoped
        if project_ids and pid and pid not in project_ids:
            continue
        comp_count += 1
        policy = _extract_policy(comp)
        if policy == "VIOLATION":
            violation_count += 1
        elif policy == "WARNING":
            warning_count += 1

    findings_count = len(df) if not df.empty else 0

    result: dict[str, Any] = {
        "projects": project_count,
        "violations": violation_count,
        "warnings": warning_count,
        "components": comp_count,
        "findings": findings_count,
    }

    # Compute deltas if start_date is available
    if start_date and not df.empty and "_detected_dt" in df.columns:
        try:
            cutoff = _parse_date(start_date)
            if cutoff:
                before = df[df["_detected_dt"] < cutoff]
                after = df[df["_detected_dt"] >= cutoff]
                before_count = len(before)
                after_count = len(after)
                if before_count > 0:
                    delta_pct = round(
                        ((after_count - before_count) / before_count) * 100, 1
                    )
                    result["findings_delta"] = delta_pct
                else:
                    result["findings_delta"] = None
            else:
                result["findings_delta"] = None
        except Exception:
            result["findings_delta"] = None
    else:
        result["findings_delta"] = None

    return result


def _build_finding_age(df: pd.DataFrame) -> dict[str, Any]:
    """Build horizontal bar chart for finding age distribution."""
    if df.empty:
        return {"labels": [], "data": []}

    now = datetime.now(UTC)

    # Only open findings
    open_df = df[~df["status"].fillna("").str.upper().isin(RESOLVED_STATUSES)]
    if open_df.empty:
        return {"labels": [], "data": []}

    buckets = {"0-30 days": 0, "30-90 days": 0, "90-180 days": 0, "180+ days": 0}
    for _, row in open_df.iterrows():
        dt = row.get("_detected_dt")
        if dt is None:
            continue
        days = (now - dt).days
        if days <= 30:
            buckets["0-30 days"] += 1
        elif days <= 90:
            buckets["30-90 days"] += 1
        elif days <= 180:
            buckets["90-180 days"] += 1
        else:
            buckets["180+ days"] += 1

    labels = list(buckets.keys())
    data = list(buckets.values())
    return {"labels": labels, "data": data}


# =============================================================================
# Main Entry Point
# =============================================================================


def executive_dashboard_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Main transform for the Executive Dashboard report.

    Args:
        data: Raw findings data from the API (list of dicts or DataFrame)
        config: Config object (optional)
        additional_data: Dict containing 'config', 'components', 'cves', etc.

    Returns:
        Dict with chart data keys that get merged into the Jinja2 template context.
    """
    additional_data = additional_data or {}
    cfg = _get_config(config, additional_data)

    # Convert to DataFrame
    if isinstance(data, pd.DataFrame):
        df = data.copy()
    else:
        df = pd.DataFrame(data) if data else pd.DataFrame()

    logger.info(f"Executive Dashboard transform: {len(df)} findings")

    # Parse detected dates once
    if not df.empty and "detected" in df.columns:
        df["_detected_dt"] = df["detected"].apply(_parse_date)
    elif not df.empty:
        df["_detected_dt"] = None

    # Ensure required columns exist
    for col in ("severity", "status", "project_name", "folder_name", "category"):
        if col not in df.columns:
            df[col] = ""

    # Get folder_filter and period from config
    folder_filter = getattr(cfg, "folder_filter", None) if cfg else None
    start_date = getattr(cfg, "start_date", None) if cfg else None
    end_date = getattr(cfg, "end_date", None) if cfg else None

    # Get additional data (components — fetched scoped by engine)
    components_raw = additional_data.get("components") or []
    if isinstance(components_raw, pd.DataFrame):
        components: list[dict[str, Any]] = [
            {str(k): v for k, v in rec.items()}
            for rec in components_raw.to_dict("records")
        ]
    elif isinstance(components_raw, list):
        components = components_raw
    else:
        components = []

    # Collect project IDs from findings for scoping components
    project_ids: set[str] = set()
    if not df.empty:
        for col in ("project_id", "projectId"):
            if col in df.columns:
                project_ids = {str(pid) for pid in df[col].dropna().unique()}
                break
        # Also try nested project dict
        if not project_ids and "project" in df.columns:
            for val in df["project"].dropna():
                if isinstance(val, dict):
                    pid = val.get("id")
                    if pid:
                        project_ids.add(str(pid))

    # Scope label
    folder_name = None
    if additional_data:
        # Check metadata chain
        folder_name = additional_data.get("folder_name")
    if not folder_name and cfg:
        folder_name = getattr(cfg, "folder_filter", None)
    scope_label = folder_name if folder_filter else "All Folders"

    # Build all sections
    findings_by_group, group_label = _build_findings_by_group(df, folder_filter)
    severity_trends = _build_severity_trends(df, start_date, end_date)
    risk_donut, top_risk_products = _build_risk_donut_and_table(df)
    open_issues_pie = _build_open_issues_pie(df)
    license_bar = _build_license_bar(components, project_ids)
    license_kpis = _build_license_kpis(components, project_ids)
    project_table = _build_project_table(df)
    exploit_intel = _build_exploit_intel(df)
    findings_by_type = _build_findings_by_type(df)
    sca_summary = _build_sca_summary(df, components, project_ids, start_date)
    finding_age = _build_finding_age(df)

    # Build main DataFrame for CSV/XLSX fallback
    main_df = df.drop(columns=["_detected_dt"], errors="ignore")

    result = {
        "main": main_df,
        "findings_by_group": findings_by_group,
        "group_label": group_label,
        "severity_trends": severity_trends,
        "risk_donut": risk_donut,
        "top_risk_products": top_risk_products,
        "open_issues_pie": open_issues_pie,
        "license_bar": license_bar,
        "license_kpis": license_kpis,
        "project_table": project_table,
        "exploit_intel": exploit_intel,
        "findings_by_type": findings_by_type,
        "sca_summary": sca_summary,
        "finding_age": finding_age,
        "scope_label": scope_label,
    }

    logger.info(
        f"Executive Dashboard transform complete: "
        f"{len(df)} findings, {len(components)} components"
    )

    return result
