"""
Pandas transform for the Component Impact report.

Answers the question: "We just heard component X (version range Y) is
compromised — where in our portfolio do we have it?"

Primary data source: /public/v0/components (via api_client) — returns
every project that contains the component regardless of CVE findings.

Secondary context: /public/v0/findings (recipe query) — provides known
CVE findings for those projects, summarised per project (count + severity
breakdown + top 3 CVEs). Full findings dumps are NOT shown.

Requires --component to be set. Optional: --component-version for version
range filtering.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)


def component_impact_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform component + findings data into a location-first impact report.

    Returns dict with keys:
    - main: flat DataFrame for CSV/XLSX (findings-based, for export)
    - locations: list of per-project location dicts (primary HTML view)
    - summary: portfolio-level counts
    - mode: "dossier" if component filter set, else "summary"
    """
    additional_data = additional_data or {}
    component_name = getattr(config, "component_filter", None) or "component"
    version_range = getattr(config, "component_version", None)

    # ------------------------------------------------------------------
    # 1. Build CVE context from findings data (secondary — enrichment only)
    # ------------------------------------------------------------------
    df = pd.DataFrame()
    if isinstance(data, pd.DataFrame):
        if not data.empty:
            df = data.copy()
    elif data:
        df = pd.DataFrame(data)

    cve_context: dict[str, dict[str, Any]] = {}  # project_name → cve stats

    if not df.empty:
        df = _normalize_fields(df)

        # Filter findings to the target component
        if component_name and component_name != "component":
            try:
                from fs_report.transforms.pandas._component_filter import (
                    apply_component_filter,
                )

                df = apply_component_filter(df, component_name)
            except Exception as exc:
                logger.warning(f"Component filter failed: {exc}")

        if version_range:
            df = _filter_by_version_range(df, version_range)

        if "risk" in df.columns:
            df["cvss_score"] = pd.to_numeric(df["risk"], errors="coerce") / 10.0
        else:
            df["cvss_score"] = 0.0

        # Exclude suppressed findings
        if "status" in df.columns:
            df = df[~df["status"].isin(["FALSE_POSITIVE", "NOT_AFFECTED"])]

        # Build per-project CVE context from findings
        proj_col = "project_name" if "project_name" in df.columns else None
        if proj_col and not df.empty:
            for proj, group in df.groupby(proj_col, dropna=False):
                sev_counts: dict[str, int] = {}
                if "severity" in group.columns:
                    for sev, cnt in group["severity"].value_counts().items():
                        sev_counts[str(sev).upper()] = int(cnt)

                top_cves: list[dict[str, Any]] = []
                if "cve_id" in group.columns and "cvss_score" in group.columns:
                    raw_top = (
                        group[["cve_id", "severity", "cvss_score"]]
                        .sort_values("cvss_score", ascending=False)
                        .head(3)
                        .to_dict(orient="records")
                    )
                    top_cves = [{str(k): v for k, v in r.items()} for r in raw_top]

                versions: list[str] = []
                if "component_version_name" in group.columns:
                    versions = sorted(
                        str(v)
                        for v in group["component_version_name"].dropna().unique()
                        if v
                    )

                cve_context[str(proj)] = {
                    "cve_count": len(group),
                    "critical_count": sev_counts.get("CRITICAL", 0),
                    "high_count": sev_counts.get("HIGH", 0),
                    "medium_count": sev_counts.get("MEDIUM", 0),
                    "top_cves": top_cves,
                    "detected_versions": versions,
                }

    # ------------------------------------------------------------------
    # 2. Build locations from components (prefer pre-fetched search results)
    # ------------------------------------------------------------------
    component_search_results = additional_data.get("component_search_results")
    if component_search_results is not None:
        locations = _build_locations_from_search(
            component_search_results, component_name, cve_context
        )
    else:
        api_client = additional_data.get("api_client")
        locations = _build_locations(api_client, component_name, cve_context)

    # Fallback: if no API client, build locations from findings data alone
    if not locations and cve_context:
        for proj_name, ctx in cve_context.items():
            locations.append(
                {
                    "project_name": proj_name,
                    "detected_versions": ctx["detected_versions"],
                    "cve_count": ctx["cve_count"],
                    "critical_count": ctx["critical_count"],
                    "high_count": ctx["high_count"],
                    "medium_count": ctx["medium_count"],
                    "top_cves": ctx["top_cves"],
                    "source": "findings",
                }
            )

    # Sort: projects with findings first (by severity), then no-findings alpha
    locations.sort(
        key=lambda d: (
            0 if d.get("cve_count", 0) > 0 else 1,
            -(d.get("critical_count", 0)),
            -(d.get("high_count", 0)),
            d["project_name"].lower(),
        )
    )

    # ------------------------------------------------------------------
    # 3. Summary
    # ------------------------------------------------------------------
    projects_with_component = len(locations)
    projects_with_findings = sum(1 for loc in locations if loc.get("cve_count", 0) > 0)

    summary: dict[str, Any] = {
        "component_name": component_name,
        "version_range": version_range,
        "projects_with_component": projects_with_component,
        "projects_with_findings": projects_with_findings,
        "total_cve_count": sum(loc.get("cve_count", 0) for loc in locations),
        "critical_count": sum(loc.get("critical_count", 0) for loc in locations),
        "high_count": sum(loc.get("high_count", 0) for loc in locations),
    }

    # Build flat DataFrame for CSV/XLSX export.
    # Always include project rows from locations (the primary output).
    # Merge in findings data when available.
    main_df = _build_main_df_from_locations(
        locations, component_name, df if not df.empty else None
    )

    return {
        "main": main_df,
        "locations": locations,
        "summary": summary,
        "mode": "dossier" if getattr(config, "component_filter", None) else "summary",
    }


# ---------------------------------------------------------------------------
# Primary helper: build location list from components API
# ---------------------------------------------------------------------------


def _build_locations(
    api_client: Any,
    component_name: str,
    cve_context: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Query /public/v0/components for every project that has component_name.

    Returns one entry per project with version(s) detected and CVE context
    from *cve_context* attached.
    """
    if not api_client:
        return []

    try:
        from fs_report.models import QueryConfig, QueryParams

        q = QueryConfig(
            endpoint="/public/v0/components",
            params=QueryParams(limit=5000, filter=f"name=={component_name}"),
        )
        raw: list[dict[str, Any]] = api_client.fetch_all_with_resume(
            q, show_progress=False
        )
    except Exception as exc:
        logger.warning(f"Component blast-radius query failed: {exc}")
        return []

    # Group versions by project
    project_versions: dict[str, set[str]] = {}
    for comp in raw:
        pv = comp.get("projectVersion") or {}
        if isinstance(pv, dict):
            project_name = pv.get("projectName") or pv.get("name") or ""
        else:
            project_name = str(pv) if pv else ""
        if not project_name:
            project_name = comp.get("projectName") or ""
        if not project_name:
            continue
        comp_version = str(comp.get("version") or "").strip()
        if project_name not in project_versions:
            project_versions[project_name] = set()
        if comp_version:
            project_versions[project_name].add(comp_version)

    locations: list[dict[str, Any]] = []

    # Projects found via components API
    for proj_name, versions in project_versions.items():
        ctx = cve_context.get(proj_name, {})
        finding_versions = ctx.get("detected_versions", [])
        all_versions = sorted(versions | set(finding_versions))
        locations.append(
            {
                "project_name": proj_name,
                "detected_versions": all_versions,
                "cve_count": ctx.get("cve_count", 0),
                "critical_count": ctx.get("critical_count", 0),
                "high_count": ctx.get("high_count", 0),
                "medium_count": ctx.get("medium_count", 0),
                "top_cves": ctx.get("top_cves", []),
                "source": "both" if ctx else "component_api",
            }
        )

    # Projects in findings but NOT returned by components API
    for proj_name, ctx in cve_context.items():
        if proj_name not in project_versions:
            locations.append(
                {
                    "project_name": proj_name,
                    "detected_versions": ctx.get("detected_versions", []),
                    "cve_count": ctx["cve_count"],
                    "critical_count": ctx["critical_count"],
                    "high_count": ctx["high_count"],
                    "medium_count": ctx["medium_count"],
                    "top_cves": ctx["top_cves"],
                    "source": "findings",
                }
            )

    return locations


def _build_locations_from_search(
    search_results: list[dict[str, Any]],
    component_name: str,
    cve_context: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build location list from pre-fetched component search results.

    Uses the same output format as _build_locations() for compatibility.
    """
    # Group versions by project.
    # The search endpoint returns: { "componentName", "componentVersion",
    #   "project": { "projectId", "projectName",
    #                "latestMatchingProjectVersionId", "projectVersionName" } }
    # Also handle the ComponentV0 shape as fallback.
    project_versions: dict[str, set[str]] = {}
    for comp in search_results:
        # Try search-endpoint shape first, then ComponentV0 shape
        proj = comp.get("project") or {}
        if isinstance(proj, dict):
            project_name = proj.get("projectName") or proj.get("name") or ""
        else:
            project_name = ""
        if not project_name:
            pv = comp.get("projectVersion") or {}
            if isinstance(pv, dict):
                project_name = pv.get("projectName") or pv.get("name") or ""
        if not project_name:
            project_name = comp.get("projectName") or ""
        if not project_name:
            continue
        comp_version = str(
            comp.get("componentVersion", comp.get("version", ""))
        ).strip()
        if project_name not in project_versions:
            project_versions[project_name] = set()
        if comp_version:
            project_versions[project_name].add(comp_version)

    locations: list[dict[str, Any]] = []

    for proj_name, versions in project_versions.items():
        ctx = cve_context.get(proj_name, {})
        finding_versions = ctx.get("detected_versions", [])
        all_versions = sorted(versions | set(finding_versions))
        locations.append(
            {
                "project_name": proj_name,
                "detected_versions": all_versions,
                "cve_count": ctx.get("cve_count", 0),
                "critical_count": ctx.get("critical_count", 0),
                "high_count": ctx.get("high_count", 0),
                "medium_count": ctx.get("medium_count", 0),
                "top_cves": ctx.get("top_cves", []),
                "source": "both" if ctx else "component_search",
            }
        )

    # Projects in findings but NOT returned by component search
    for proj_name, ctx in cve_context.items():
        if proj_name not in project_versions:
            locations.append(
                {
                    "project_name": proj_name,
                    "detected_versions": ctx.get("detected_versions", []),
                    "cve_count": ctx["cve_count"],
                    "critical_count": ctx["critical_count"],
                    "high_count": ctx["high_count"],
                    "medium_count": ctx["medium_count"],
                    "top_cves": ctx["top_cves"],
                    "source": "findings",
                }
            )

    return locations


# ---------------------------------------------------------------------------
# Normalization helpers (unchanged)
# ---------------------------------------------------------------------------


def _extract_nested(row: Any, *keys: str) -> str:
    """Try each key in order; handle dot-notation, nested dicts, and plain strings."""
    for key in keys:
        if isinstance(row, dict):
            val = row.get(key)
            if val is not None:
                if isinstance(val, dict):
                    return str(val.get("name", val))
                return str(val)
    return ""


def _normalize_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Extract and normalise nested API fields into flat columns."""
    df = df.copy()

    def _col(
        df: pd.DataFrame,
        target: str,
        *candidates: str,
        nested_key: str = "name",
    ) -> pd.DataFrame:
        """Set df[target] from the first matching candidate column."""
        for col in candidates:
            if col in df.columns:
                df[target] = df[col].apply(
                    lambda x: (
                        x.get(nested_key, "")
                        if isinstance(x, dict)
                        else (str(x) if x is not None else "")
                    )
                )
                return df
        if target not in df.columns:
            df[target] = ""
        return df

    df = _col(df, "component_name", "componentName", "component.name", "component")
    df = _col(
        df,
        "component_version_name",
        "componentVersionName",
        "componentVersion",
        "component.version",
        nested_key="name",
    )
    # componentVersion may itself be a dict with a "name" key
    if (
        "component_version_name" not in df.columns
        or df["component_version_name"].eq("").all()
    ):
        if "componentVersion" in df.columns:
            df["component_version_name"] = df["componentVersion"].apply(
                lambda x: (
                    x.get("name", "")
                    if isinstance(x, dict)
                    else (str(x) if x is not None else "")
                )
            )

    df = _col(df, "project_name", "projectName", "project.name", "project")
    df = _col(
        df,
        "project_version_name",
        "versionName",
        "projectVersionName",
        "projectVersion.name",
    )
    df = _col(df, "cve_id", "cveId", "cve.id", "cve")

    return df


def _parse_version_range(version_range: str) -> list[tuple[str, str]]:
    """
    Parse a version range string into a list of (operator, version_str) tuples.

    Examples:
        "<2.0"          -> [("<",  "2.0")]
        ">=1.0,<2.0"    -> [(">=", "1.0"), ("<", "2.0")]
        "1.36.1-r2"     -> [("==", "1.36.1-r2")]
    """
    parts = [p.strip() for p in version_range.split(",") if p.strip()]
    result: list[tuple[str, str]] = []
    op_re = re.compile(r"^(>=|<=|!=|>|<|==|~=)(.+)$")
    for part in parts:
        m = op_re.match(part)
        if m:
            result.append((m.group(1), m.group(2).strip()))
        else:
            result.append(("==", part))
    return result


def _version_matches(version_str: str, constraints: list[tuple[str, str]]) -> bool:
    """Return True if version_str satisfies all constraints."""
    if not version_str:
        return False

    try:
        from packaging.version import InvalidVersion, Version

        try:
            v = Version(version_str)
        except InvalidVersion:
            return _version_matches_string(version_str, constraints)

        for op, constraint_str in constraints:
            try:
                cv = Version(constraint_str)
            except InvalidVersion:
                return _version_matches_string(version_str, constraints)

            if op == "==" and v != cv:
                return False
            elif op == "!=" and v == cv:
                return False
            elif op == "<" and not (v < cv):
                return False
            elif op == "<=" and not (v <= cv):
                return False
            elif op == ">" and not (v > cv):
                return False
            elif op == ">=" and not (v >= cv):
                return False
        return True

    except ImportError:
        return _version_matches_string(version_str, constraints)


def _numeric_tuple(v: str) -> tuple[int, ...]:
    """Convert a version string to a tuple of ints for comparison."""
    parts = []
    for seg in re.split(r"[.\-_]", v):
        m = re.match(r"(\d+)", seg)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _version_matches_string(
    version_str: str, constraints: list[tuple[str, str]]
) -> bool:
    """Tuple-based version fallback for non-PEP-440 strings (e.g. APK '1.36.1-r2')."""
    vt = _numeric_tuple(version_str)
    for op, constraint_str in constraints:
        if op == "==" and version_str != constraint_str:
            return False
        elif op == "!=" and version_str == constraint_str:
            return False
        elif op in ("<", "<=", ">", ">="):
            ct = _numeric_tuple(constraint_str)
            if op == "<" and not (vt < ct):
                return False
            elif op == "<=" and not (vt <= ct):
                return False
            elif op == ">" and not (vt > ct):
                return False
            elif op == ">=" and not (vt >= ct):
                return False
    return True


def _filter_by_version_range(df: pd.DataFrame, version_range: str) -> pd.DataFrame:
    """Filter the DataFrame to rows whose component_version_name satisfies version_range."""
    try:
        constraints = _parse_version_range(version_range)
    except Exception as exc:
        logger.warning(
            f"Could not parse version range '{version_range}': {exc}. Skipping filter."
        )
        return df

    if not constraints:
        return df

    mask = df["component_version_name"].apply(
        lambda v: _version_matches(str(v) if v is not None else "", constraints)
    )
    return df[mask].copy()


def _build_main_df_from_locations(
    locations: list[dict[str, Any]],
    component_name: str,
    findings_df: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Build CSV export DataFrame from locations, optionally enriched with findings.

    Always produces one row per project per version (from locations).
    When findings exist, appends CVE-level rows for projects that have them.
    """
    rows: list[dict[str, str | int | float]] = []

    # Build project-level rows from locations
    for loc in locations:
        proj = loc.get("project_name", "")
        versions = loc.get("detected_versions", [])
        cve_count = loc.get("cve_count", 0)
        critical = loc.get("critical_count", 0)
        high = loc.get("high_count", 0)
        medium = loc.get("medium_count", 0)

        ver_str = ", ".join(versions) if versions else ""
        rows.append(
            {
                "Component": component_name,
                "Version": ver_str,
                "Project": proj,
                "CVE Count": cve_count,
                "Critical": critical,
                "High": high,
                "Medium": medium,
            }
        )

    return pd.DataFrame(rows)


def _build_main_df(df: pd.DataFrame) -> pd.DataFrame:
    """Select and rename columns into the flat export DataFrame.

    Legacy — kept for backward compatibility when locations are not available.
    """
    cols_map = {
        "cve_id": "CVE ID",
        "severity": "Severity",
        "cvss_score": "CVSS Score",
        "component_name": "Component Name",
        "component_version_name": "Component Version",
        "project_name": "Project",
        "project_version_name": "Project Version",
        "status": "Status",
    }
    if "title" in df.columns:
        cols_map["title"] = "Title"
    elif "name" in df.columns:
        cols_map["name"] = "Name"

    available = {k: v for k, v in cols_map.items() if k in df.columns}
    result = df[list(available.keys())].copy()
    result = result.rename(columns=available)
    return result
