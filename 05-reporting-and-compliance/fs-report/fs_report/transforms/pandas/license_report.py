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

# Map the API's copyleftFamily enum (returned in `*LicenseDetails[].copyleftFamily`)
# to display categories. This is the same source of truth the platform UI uses.
# Verified enum on adamd: 'PERMISSIVE', 'COPYLEFT_WEAK', 'COPYLEFT_STRONG' (note the
# permissive value has no COPYLEFT_ prefix).
_API_COPYLEFT_FAMILY_MAP = {
    "COPYLEFT_STRONG": "Strong Copyleft",
    "COPYLEFT_WEAK": "Weak Copyleft",
    "PERMISSIVE": "Permissive",
    # Forward-compat aliases in case the API ever flips the prefix order.
    "STRONG_COPYLEFT": "Strong Copyleft",
    "WEAK_COPYLEFT": "Weak Copyleft",
}


def _classify_license(name: str) -> str:
    """Classify a license SPDX identifier into a risk category.

    Used as a fallback when the API doesn't surface a copyleftFamily for the
    component (e.g. components without licenseDetails arrays). When
    licenseDetails IS present, prefer `_classify_from_copyleft_family` which
    matches the platform UI exactly.
    """
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


def _classify_from_copyleft_family(copyleft_family: str) -> str:
    """Map the API's copyleftFamily enum to a display risk category, or '' if
    the value is unrecognised / empty."""
    if not copyleft_family:
        return ""
    return _API_COPYLEFT_FAMILY_MAP.get(copyleft_family.strip(), "")


def _extract_copyleft_family(comp: dict[str, Any]) -> str:
    """Pull the API's copyleftFamily classification from a component record.

    Precedence mirrors `_extract_license_string` and component_list.py's
    `_best_license_details`: concluded > declared > generic. Returns the raw
    enum value (e.g. 'COPYLEFT_STRONG') or '' if no license-detail array on
    the record carries a copyleftFamily.
    """
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        details = comp.get(field)
        if not isinstance(details, list):
            continue
        for ld in details:
            if isinstance(ld, dict):
                cf = ld.get("copyleftFamily")
                if isinstance(cf, str) and cf.strip():
                    return cf.strip()
    return ""


def _coerce_license_value(val: Any) -> str:
    """Normalise a license field value into a comma-joined SPDX string.

    Handles four real-world shapes returned by /public/v0/components:
      - plain string ("Sleepycat", "MIT OR Apache-2.0")
      - list of strings (["MIT", "Apache-2.0"])
      - list of dicts with `spdx` / `license` / `name` keys
        (e.g. [{"spdx": "Sleepycat", "name": "Sleepycat License"}])
      - None / NaN / non-iterable scalars → ""
    """
    import math

    if val is None:
        return ""
    if isinstance(val, float):
        if math.isnan(val):
            return ""
        return str(val).strip()
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, list):
        parts: list[str] = []
        for item in val:
            if isinstance(item, str):
                if item.strip():
                    parts.append(item.strip())
            elif isinstance(item, dict):
                # Match the precedence used by component_list.extract_licenses_summary
                # plus a `name` fallback for the {"name": "Sleepycat"} shape.
                spdx = item.get("spdx") or item.get("license") or item.get("name") or ""
                if isinstance(spdx, str) and spdx.strip():
                    parts.append(spdx.strip())
        return ", ".join(parts)
    return str(val).strip()


def _extract_license_string(comp: dict[str, Any]) -> str:
    """Pull the best available license string from a component record.

    Precedence mirrors fs_report.transforms.pandas.component_list (and
    customer_brief): user-curated `concludedLicenses` wins over auto-detected
    `declaredLicenses`, with `licenses` (legacy) and the structured
    `*LicenseDetails` arrays as fallbacks. The field-precedence rationale
    is documented in `sqlite_cache.py` ("User-specified licenses (takes
    precedence)") and `component_list.py::_best_license_details`.
    """
    for field in ("concludedLicenses", "declaredLicenses", "licenses"):
        s = _coerce_license_value(comp.get(field))
        if s:
            return s
    # Singular variants kept for backward compat with older fixtures.
    for field in ("declaredLicense", "license"):
        s = _coerce_license_value(comp.get(field))
        if s:
            return s
    # Structured-array fallback — concluded > declared > generic.
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        s = _coerce_license_value(comp.get(field))
        if s:
            return s
    return ""


def _flatten_component(comp: dict[str, Any]) -> dict[str, str]:
    """Extract license name and project info from raw component record."""
    license_name = _extract_license_string(comp)
    copyleft_family = _extract_copyleft_family(comp)

    # Extract project name from nested dict or flat field
    project = comp.get("project", {})
    if isinstance(project, dict):
        project_name = project.get("name", "")
    else:
        project_name = comp.get("project.name", "")

    return {
        "component_name": comp.get("name", ""),
        "component_version": comp.get("version", ""),
        "license_name": license_name,
        "copyleft_family": copyleft_family,
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
        # Prefer the API's copyleftFamily classification (matches platform UI
        # exactly, includes licenses missing from COPYLEFT_LOOKUP — e.g.
        # Sleepycat → Strong Copyleft). Fall back to SPDX lookup, then to the
        # proprietary-keyword heuristic, and finally Unknown.
        flat["risk_category"] = _classify_from_copyleft_family(
            flat["copyleft_family"]
        ) or _classify_license(flat["license_name"])
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

    # Apply license filter (case-insensitive substring, comma-separated terms)
    license_filter = getattr(cfg, "license_filter", None) if cfg else None
    if license_filter:
        terms = [t.strip().lower() for t in str(license_filter).split(",") if t.strip()]
        if terms:
            df = df[
                df["license_name"]
                .str.lower()
                .apply(lambda name: any(t in name for t in terms))
            ].reset_index(drop=True)
            logger.info(
                f"License report: filtered to {len(df)} components "
                f"matching license terms {terms}"
            )

    logger.info(f"License report: {len(df)} components")

    # Sanity check: warn if a large fraction of components have no license
    # after extraction. This is the canary for the next regression where the
    # API adds a new license field we don't read (cf. concludedLicenses miss
    # before this code path).
    if len(df) > 0:
        empty_frac = float((df["license_name"] == "").sum()) / len(df)
        if empty_frac > 0.10:
            logger.debug(
                f"License report: {empty_frac:.0%} of components have no "
                f"license after extraction. If this looks wrong, verify the "
                f"API still surfaces licenses under concludedLicenses / "
                f"declaredLicenses / licenseDetails."
            )

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

    # --- Detail DataFrame: one row per component (License × Project × Component) ---
    detail_df = (
        pd.DataFrame(
            {
                "License": df["license_name"],
                "Risk Category": df["risk_category"],
                "Project": df["project_name"],
                "Component": df["component_name"],
                "Version": df["component_version"],
            }
        )
        .sort_values(
            by=["License", "Project", "Component", "Version"],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )

    # No-license components
    no_license_count = int((df["license_name"] == "").sum())

    return {
        "main": main_df,
        "detail": detail_df,
        "detail_table": detail_df.to_dict("records"),
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
        "detail": pd.DataFrame(),
        "detail_table": [],
        "license_table": [],
        "risk_pie": {"labels": [], "data": [], "backgroundColor": []},
        "category_summary": {},
        "total_components": 0,
        "total_licenses": 0,
        "no_license_count": 0,
    }
