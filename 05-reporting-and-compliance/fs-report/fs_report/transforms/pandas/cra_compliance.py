"""
Pandas transform for the CRA Compliance report.

Consumes findings from ``/public/v0/findings`` filtered to KEV hits or
known-exploit findings (``inKev==true or hasKnownExploit==true`` — RSQL ``or`` keyword)
and produces:

- A flat DataFrame (one row per finding) for CSV/XLSX/Markdown export
- A summary dict with aggregate counts for HTML rendering
- A ``cra_findings`` list of dicts for HTML template consumption

EU Cyber Resilience Act context: manufacturers must notify ENISA within 24 hours
of becoming aware of an actively exploited vulnerability in a product with digital
elements.  KEV inclusion or a known exploit is the primary trigger signal.
"""

from __future__ import annotations

import ast
import logging
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

# Severity ordering for sort (lower index = higher priority)
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

# Statuses that represent suppressed / resolved findings — excluded from CRA scope
_EXCLUDED_STATUSES = {
    "FALSE_POSITIVE",
    "NOT_AFFECTED",
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
}

# Canonical output columns for the main DataFrame
_OUTPUT_COLUMNS = [
    "cve_id",
    "title",
    "severity",
    "cvss_score",
    "component",
    "component_version",
    "project",
    "project_version",
    "status",
    "cra_trigger",
    "in_kev",
    "has_known_exploit",
    "epss_score",
    "epss_percentile",
    "detected_date",
]


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------


def _extract_str(record: dict[str, Any], *keys: str, default: str = "") -> str:
    """Return the first non-empty string found among ``keys`` in ``record``."""
    for key in keys:
        val = record.get(key)
        if val is None:
            continue
        if isinstance(val, dict):
            # e.g. component.name nested dict
            inner = val.get("name") or val.get("id") or val.get("version")
            if inner is not None:
                return str(inner)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if not isinstance(val, str):
            return str(val)
    return default


def _extract_component_name(record: dict[str, Any]) -> str:
    """Extract component name handling nested dicts and flat keys."""
    # Flat key first
    for key in ("componentName",):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    # Nested dict under "component"
    comp = record.get("component")
    if isinstance(comp, dict):
        name = comp.get("name") or comp.get("id")
        if name:
            return str(name)
    if isinstance(comp, str):
        # May be a stringified dict
        try:
            parsed = ast.literal_eval(comp)
            if isinstance(parsed, dict):
                name = parsed.get("name") or parsed.get("id")
                if name:
                    return str(name)
        except Exception:
            pass
        if comp.strip():
            return comp.strip()

    return "Unknown"


def _extract_component_version(record: dict[str, Any]) -> str:
    """Extract component version handling nested dicts and flat keys."""
    for key in ("componentVersion", "componentVersionName"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    comp = record.get("component")
    if isinstance(comp, dict):
        ver = comp.get("version")
        if ver:
            return str(ver)
    if isinstance(comp, str):
        try:
            parsed = ast.literal_eval(comp)
            if isinstance(parsed, dict):
                ver = parsed.get("version")
                if ver:
                    return str(ver)
        except Exception:
            pass

    return "Unknown"


def _extract_project_name(record: dict[str, Any]) -> str:
    """Extract project name handling nested dicts and flat keys."""
    for key in ("projectName",):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    proj = record.get("project")
    if isinstance(proj, dict):
        name = proj.get("name") or proj.get("id")
        if name:
            return str(name)
    if isinstance(proj, str):
        try:
            parsed = ast.literal_eval(proj)
            if isinstance(parsed, dict):
                name = parsed.get("name") or parsed.get("id")
                if name:
                    return str(name)
        except Exception:
            pass
        if proj.strip():
            return proj.strip()

    return "Unknown"


def _extract_project_version(record: dict[str, Any]) -> str:
    """Extract project version name from nested projectVersion or flat keys."""
    for key in ("versionName", "projectVersion"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            ver = v.get("version") or v.get("name")
            if ver:
                return str(ver)

    return "Unknown"


def _extract_cve_id(record: dict[str, Any]) -> str:
    """Extract CVE/advisory ID from various field shapes."""
    for key in ("cveId", "findingId"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    cve = record.get("cve")
    if isinstance(cve, dict):
        cve_id = cve.get("id")
        if cve_id:
            return str(cve_id)
    if isinstance(cve, str) and cve.strip():
        return cve.strip()

    return "N/A"


def _safe_str(value: Any) -> str:
    """Convert to string, treating None and NaN as empty."""
    if value is None:
        return ""
    s = str(value)
    if s in ("nan", "None", "NaN"):
        return ""
    return s


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float, returning ``default`` on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _severity_rank(severity: str) -> int:
    """Return sort rank for severity (lower = higher priority)."""
    try:
        return _SEVERITY_ORDER.index(severity.upper())
    except (ValueError, AttributeError):
        return len(_SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Main transform
# ---------------------------------------------------------------------------


def cra_compliance_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform ``/findings`` endpoint data into a CRA Compliance report.

    Args:
        data: Raw findings records (list of dicts or DataFrame).  The caller
              has already applied the ``inKev==true,hasKnownExploit==true``
              RSQL filter via the recipe query, but we re-check the fields
              defensively.
        config: Application configuration.
        additional_data: Not used; accepted for signature compatibility.

    Returns:
        Dictionary with keys:
        - ``main``: flat DataFrame for CSV/XLSX/Markdown (one row per finding)
        - ``summary``: aggregate counts dict for HTML rendering
        - ``cra_findings``: list of per-finding dicts for HTML template
    """
    _empty = {"main": pd.DataFrame(), "summary": {}, "cra_findings": []}

    # ------------------------------------------------------------------
    # 1. Normalise input to a list of dicts
    # ------------------------------------------------------------------
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return _empty
        records: list[dict[str, Any]] = [
            {str(k): v for k, v in r.items()} for r in data.to_dict(orient="records")
        ]
    elif not data:
        return _empty
    else:
        records = list(data)

    if not records:
        return _empty

    # ------------------------------------------------------------------
    # 2. Build a flat row for each finding
    # ------------------------------------------------------------------
    rows: list[dict[str, Any]] = []
    for rec in records:
        status = str(rec.get("status") or "").upper()
        if status in _EXCLUDED_STATUSES:
            continue

        in_kev = bool(rec.get("inKev", False))
        # The API filter field "exploit" is not returned in the response.
        # Detect exploit status from exploitInfo (list of sources like
        # "kev", "vcKev", etc.) and exploitMaturity.
        exploit_info = rec.get("exploitInfo") or []
        exploit_maturity = rec.get("exploitMaturity")
        has_exploit = bool(exploit_info) or bool(exploit_maturity)

        # CRA trigger label
        if in_kev:
            cra_trigger = "KEV"
        elif has_exploit:
            cra_trigger = "Known Exploit"
        else:
            cra_trigger = "Unknown"

        # CVSS score (API returns 0-100; divide by 10)
        raw_risk = rec.get("risk")
        cvss_score = _safe_float(raw_risk) / 10.0 if raw_risk is not None else 0.0

        severity = str(rec.get("severity") or "UNKNOWN").upper()

        row: dict[str, Any] = {
            "cve_id": _extract_cve_id(rec),
            "title": str(rec.get("title") or ""),
            "severity": severity,
            "cvss_score": cvss_score,
            "component": _extract_component_name(rec),
            "component_version": _extract_component_version(rec),
            "project": _extract_project_name(rec),
            "project_version": _extract_project_version(rec),
            "status": _safe_str(rec.get("status")),
            "cra_trigger": cra_trigger,
            "in_kev": in_kev,
            "has_known_exploit": has_exploit,
            "epss_score": _safe_float(rec.get("epssScore")),
            "epss_percentile": _safe_float(rec.get("epssPercentile")),
            "detected_date": str(
                rec.get("detectedDate") or rec.get("firstDetected") or ""
            ),
        }
        rows.append(row)

    if not rows:
        return _empty

    # ------------------------------------------------------------------
    # 3. Build DataFrame and sort
    # ------------------------------------------------------------------
    df = pd.DataFrame(rows, columns=_OUTPUT_COLUMNS)

    # Sort: severity order (CRITICAL first), then CVSS descending
    df["_severity_rank"] = df["severity"].apply(_severity_rank)
    df = df.sort_values(
        ["_severity_rank", "cvss_score"],
        ascending=[True, False],
    ).drop(columns=["_severity_rank"])
    df = df.reset_index(drop=True)

    # ------------------------------------------------------------------
    # 4. Build summary dict
    # ------------------------------------------------------------------
    total_count = len(df)
    kev_count = int(df["in_kev"].sum())
    known_exploit_count = int(df["has_known_exploit"].sum())
    critical_count = int((df["severity"] == "CRITICAL").sum())
    high_count = int((df["severity"] == "HIGH").sum())
    open_count = int(df["status"].isin({"OPEN", ""}).sum())
    triaged_count = int((df["status"] == "IN_TRIAGE").sum())

    by_project: dict[str, int] = {
        str(k): int(v)
        for k, v in df.groupby("project").size().sort_values(ascending=False).items()
    }

    summary: dict[str, Any] = {
        "total_count": total_count,
        "kev_count": kev_count,
        "known_exploit_count": known_exploit_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "by_project": by_project,
        "open_count": open_count,
        "triaged_count": triaged_count,
    }

    # ------------------------------------------------------------------
    # 5. Build cra_findings list for HTML template
    # ------------------------------------------------------------------
    cra_findings: list[dict[str, Any]] = [
        {str(k): v for k, v in r.items()} for r in df.to_dict(orient="records")
    ]

    # ------------------------------------------------------------------
    # 6. Build project dossiers — primary view for legal/compliance
    # ------------------------------------------------------------------
    project_dossiers: list[dict[str, Any]] = []
    for proj_name, group in df.groupby("project", sort=False):
        top_cves = (
            group[["cve_id", "severity", "cvss_score", "component", "cra_trigger"]]
            .sort_values("cvss_score", ascending=False)
            .head(5)
            .to_dict(orient="records")
        )
        project_dossiers.append(
            {
                "project_name": str(proj_name),
                "finding_count": len(group),
                "critical_count": int((group["severity"] == "CRITICAL").sum()),
                "high_count": int((group["severity"] == "HIGH").sum()),
                "kev_count": int(group["in_kev"].sum()),
                "exploit_count": int(group["has_known_exploit"].sum()),
                "top_cves": top_cves,
            }
        )

    # Sort dossiers: most findings first
    project_dossiers.sort(key=lambda d: d["finding_count"], reverse=True)

    # Build scope label from config
    scope_label = "All Projects"
    if hasattr(config, "project_filter") and config.project_filter:
        scope_label = config.project_filter
    elif hasattr(config, "folder_filter") and config.folder_filter:
        scope_label = f"Folder: {config.folder_filter}"

    return {
        "main": df,
        "summary": summary,
        "cra_findings": cra_findings,
        "project_dossiers": project_dossiers,
        "scope_label": scope_label,
    }
