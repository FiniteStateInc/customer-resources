"""
Pandas transform for the License Report.

Groups components by license, classifies into risk categories
(Permissive, Weak Copyleft, Strong Copyleft, Proprietary/Restricted, Unknown),
and produces chart-ready data plus a tabular breakdown.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

import pandas as pd

from fs_report.transforms.pandas.component_list import COPYLEFT_LOOKUP

logger = logging.getLogger(__name__)

# Categories in display order (highest risk first)
RISK_CATEGORIES = [
    "Strong Copyleft",
    "Weak Copyleft",
    "Proprietary/Restricted",
    "Unknown",
    "Permissive",
]

CATEGORY_COLORS = {
    "Strong Copyleft": "#d32f2f",
    "Weak Copyleft": "#f57c00",
    "Proprietary/Restricted": "#7b1fa2",
    "Unknown": "#757575",
    "Permissive": "#388e3c",
}

# Map internal COPYLEFT_LOOKUP values to display categories
_CLASSIFICATION_MAP = {
    "STRONG_COPYLEFT": "Strong Copyleft",
    "WEAK_COPYLEFT": "Weak Copyleft",
    "PERMISSIVE": "Permissive",
}


def _classify_license(name: str) -> str:
    """Classify a license SPDX identifier into a risk category."""
    if not name or name.strip() == "":
        return "Unknown"
    classification = COPYLEFT_LOOKUP.get(name.strip())
    if classification:
        return _CLASSIFICATION_MAP.get(classification, "Unknown")
    # Heuristic fallback for non-SPDX names
    upper = name.upper()
    if any(kw in upper for kw in ("PROPRIETARY", "COMMERCIAL", "RESTRICTED", "EULA")):
        return "Proprietary/Restricted"
    return "Unknown"


def _flatten_component(comp: dict[str, Any]) -> dict[str, str]:
    """Extract license name and project info from raw component record."""
    license_name = (
        comp.get("declaredLicenses")
        or comp.get("declaredLicense")
        or comp.get("license")
        or ""
    )
    if not license_name or (isinstance(license_name, float) and pd.isna(license_name)):
        license_name = ""

    # Extract project name from nested dict or flat field
    project = comp.get("project", {})
    if isinstance(project, dict):
        project_name = project.get("name", "")
    else:
        project_name = comp.get("project.name", "")

    return {
        "component_name": comp.get("name", ""),
        "component_version": comp.get("version", ""),
        "license_name": str(license_name).strip(),
        "project_name": str(project_name),
    }


def license_report_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform component data into a license risk report.

    Args:
        data: Raw component data from the API (list of dicts or DataFrame).
        config: Optional config object.
        additional_data: Dict with 'config', etc.

    Returns:
        Dict with keys for the Jinja2 template context:
          - main: DataFrame for CSV/XLSX export
          - license_table: list of dicts for the HTML table
          - risk_pie: dict for Chart.js pie chart
          - category_summary: dict of category → count
          - total_components: int
          - total_licenses: int
    """
    additional_data = additional_data or {}

    # Convert to list of dicts
    records: list[dict[str, Any]] = []
    if isinstance(data, pd.DataFrame):
        if not data.empty:
            records = data.to_dict("records")  # type: ignore[assignment]
    elif isinstance(data, list):
        records = data

    if not records:
        return _empty_result()

    # Flatten and classify
    rows: list[dict[str, Any]] = []
    for comp in records:
        flat = _flatten_component(comp)
        flat["risk_category"] = _classify_license(flat["license_name"])
        rows.append(flat)

    df = pd.DataFrame(rows)

    # Apply component filter if configured
    cfg = config or (additional_data.get("config") if additional_data else None)
    component_filter = getattr(cfg, "component_filter", None) if cfg else None
    if component_filter:
        from fs_report.transforms.pandas._component_filter import (
            apply_component_filter,
        )

        match_mode = getattr(cfg, "component_match", "contains")
        df = apply_component_filter(
            df,
            component_filter,
            match_mode=match_mode,
            name_col="component_name",
            version_col="component_version",
        )

    logger.info(f"License report: {len(df)} components")

    # --- License table: group by license ---
    license_groups = (
        df.groupby("license_name")
        .agg(
            component_count=("component_name", "count"),
            risk_category=("risk_category", "first"),
            projects=(
                "project_name",
                lambda x: ", ".join(sorted({str(v) for v in x if v})),
            ),
        )
        .reset_index()
        .sort_values("component_count", ascending=False)
    )

    license_table = license_groups.to_dict("records")

    # --- Category summary for KPIs ---
    category_counts: Counter[str] = Counter()
    for _, row in df.iterrows():
        category_counts[row["risk_category"]] += 1

    # --- Risk pie chart ---
    pie_labels = []
    pie_data = []
    pie_colors = []
    for cat in RISK_CATEGORIES:
        count = category_counts.get(cat, 0)
        if count > 0:
            pie_labels.append(cat)
            pie_data.append(count)
            pie_colors.append(CATEGORY_COLORS.get(cat, "#757575"))

    risk_pie = {
        "labels": pie_labels,
        "data": pie_data,
        "backgroundColor": pie_colors,
    }

    # --- Build main DataFrame for CSV/XLSX ---
    main_df = pd.DataFrame(
        {
            "License": license_groups["license_name"],
            "Risk Category": license_groups["risk_category"],
            "Component Count": license_groups["component_count"],
            "Projects": license_groups["projects"],
        }
    )

    # No-license components
    no_license_count = int((df["license_name"] == "").sum())

    return {
        "main": main_df,
        "license_table": license_table,
        "risk_pie": risk_pie,
        "category_summary": dict(category_counts),
        "total_components": len(df),
        "total_licenses": int(
            license_groups[license_groups["license_name"] != ""].shape[0]
        ),
        "no_license_count": no_license_count,
    }


def _empty_result() -> dict[str, Any]:
    return {
        "main": pd.DataFrame(),
        "license_table": [],
        "risk_pie": {"labels": [], "data": [], "backgroundColor": []},
        "category_summary": {},
        "total_components": 0,
        "total_licenses": 0,
        "no_license_count": 0,
    }
