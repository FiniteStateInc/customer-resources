"""
Pandas transform for the Security Progress report.

Produces:
- A flat DataFrame (one row per finding) for CSV/XLSX export
- Triage funnel snapshot (status distribution)
- Severity distribution (open findings only)
- Period comparison delta (if config.baseline_date is set)
- CVE change tracking via /public/v0/cves/updates (new, retracted, severity/exploit changes)

CVE Updates Integration:
    The transform calls GET /public/v0/cves/updates?startDate=...&endDate=... to fetch
    CVE changes during the reporting window. Results are classified into:
    - added: new CVEs introduced
    - retracted: CVEs removed/retracted
    - severity_escalated / severity_downgraded: CVSS severity changed
    - exploit_gained / exploit_subsided: exploit maturity changed
    - other_updates: remaining updates with no severity/exploit change

    Requires api_client in additional_data["api_client"].

Note: Triage velocity (time-in-triage, status transitions) requires
status_changed_at from the API, which is not yet available.
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

# Ordered severity levels for consistent display
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Statuses that count as "open/untriaged" (not yet resolved or suppressed).
# NO_STATUS = untriaged/unset (API added 2026-03-15).
_OPEN_STATUSES = {"OPEN", "IN_TRIAGE", "NO_STATUS"}

# All known triage statuses (ordered for consistent display)
_ALL_STATUSES = [
    "OPEN",
    "IN_TRIAGE",
    "NO_STATUS",
    "RESOLVED",
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
    "RESOLVED_WITH_PEDIGREE",
]

_API_LIMITATION_NOTE = (
    "Triage velocity (time-in-triage, status transitions) requires "
    "status_changed_at field not yet available in the API"
)

# Severity rank mapping for comparison
_SEVERITY_RANK: dict[str, int] = {
    "UNKNOWN": 0,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _to_iso8601z(date_str: str | None) -> str | None:
    """Convert "2024-01-01" or "2024-01-01T00:00:00" to "2024-01-01T00:00:00Z".

    Returns None if date_str is None or unparseable.
    """
    if not date_str:
        return None
    try:
        dt = pd.to_datetime(date_str, utc=False)
        # Format without microseconds, with Z suffix
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001
        return None


def _fetch_cve_updates(api_client: Any, config: Config) -> list[dict]:
    """Fetch all CVE updates from /public/v0/cves/updates with pagination.

    Returns empty list if api_client is None or dates are missing.
    """
    if api_client is None:
        return []

    start = _to_iso8601z(getattr(config, "start_date", None))
    end = _to_iso8601z(getattr(config, "end_date", None))

    if not start or not end:
        return []

    params: dict[str, Any] = {
        "startDate": start,
        "endDate": end,
        "limit": 100,
        "offset": 0,
    }

    folder_filter = getattr(config, "folder_filter", None)
    if folder_filter:
        params["folderId"] = folder_filter

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

    logger.info("Fetched %d CVE updates for period %s to %s", len(results), start, end)
    return results


def _exploit_rank(maturity: str | None) -> int:
    """Map exploit maturity string to a comparable rank (0–3)."""
    if not maturity:
        return 0
    m = maturity.upper()
    if m in ("POC", "PROOF_OF_CONCEPT"):
        return 1
    if m == "FUNCTIONAL":
        return 2
    if m in ("HIGH", "WEAPONIZED", "EXPLOITED_IN_WILD"):
        return 3
    # UNPROVEN and unknown values → 0
    return 0


def _process_cve_updates(updates: list[dict]) -> dict[str, list[dict]]:
    """Classify CVE updates into categories.

    Returns a dict with keys:
        added, retracted, severity_escalated, severity_downgraded,
        exploit_gained, exploit_subsided, other_updates

    A single update may appear in BOTH severity_escalated AND exploit_gained.
    """
    result: dict[str, list[dict]] = {
        "added": [],
        "retracted": [],
        "severity_escalated": [],
        "severity_downgraded": [],
        "exploit_gained": [],
        "exploit_subsided": [],
        "other_updates": [],
    }

    for update in updates:
        cve_id = update.get("cveId", "")
        utype = update.get("type", "")
        old_val = update.get("oldValue") or {}
        new_val = update.get("newValue") or {}
        project_names = [
            p.get("name", "") for p in update.get("projects", []) if isinstance(p, dict)
        ]

        if utype == "new":
            result["added"].append(
                {
                    "cve_id": cve_id,
                    "new_severity": new_val.get("severity"),
                    "new_cvss": new_val.get("cvss"),
                    "projects": project_names,
                }
            )
        elif utype == "retract":
            result["retracted"].append(
                {
                    "cve_id": cve_id,
                    "old_severity": old_val.get("severity"),
                    "projects": project_names,
                }
            )
        elif utype == "update":
            old_sev = old_val.get("severity")
            new_sev = new_val.get("severity")
            old_exploit = old_val.get("exploitMaturity")
            new_exploit = new_val.get("exploitMaturity")

            old_sev_rank = _SEVERITY_RANK.get((old_sev or "").upper(), 0)
            new_sev_rank = _SEVERITY_RANK.get((new_sev or "").upper(), 0)
            old_exp_rank = _exploit_rank(old_exploit)
            new_exp_rank = _exploit_rank(new_exploit)

            sev_changed = False
            exp_changed = False

            if new_sev_rank > old_sev_rank:
                sev_changed = True
                result["severity_escalated"].append(
                    {
                        "cve_id": cve_id,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                        "old_cvss": old_val.get("cvss"),
                        "new_cvss": new_val.get("cvss"),
                        "projects": project_names,
                    }
                )
            elif new_sev_rank < old_sev_rank:
                sev_changed = True
                result["severity_downgraded"].append(
                    {
                        "cve_id": cve_id,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                        "old_cvss": old_val.get("cvss"),
                        "new_cvss": new_val.get("cvss"),
                        "projects": project_names,
                    }
                )

            if new_exp_rank > old_exp_rank:
                exp_changed = True
                result["exploit_gained"].append(
                    {
                        "cve_id": cve_id,
                        "old_exploit": old_exploit,
                        "new_exploit": new_exploit,
                        "severity": new_sev,
                        "projects": project_names,
                    }
                )
            elif new_exp_rank < old_exp_rank:
                exp_changed = True
                result["exploit_subsided"].append(
                    {
                        "cve_id": cve_id,
                        "old_exploit": old_exploit,
                        "new_exploit": new_exploit,
                        "severity": new_sev,
                        "projects": project_names,
                    }
                )

            if not sev_changed and not exp_changed:
                result["other_updates"].append(
                    {
                        "cve_id": cve_id,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                        "projects": project_names,
                    }
                )

    return result


def _cve_update_summary(processed: dict[str, list[dict]]) -> dict[str, int]:
    """Return counts for each CVE update category plus total."""
    categories = [
        "added",
        "retracted",
        "severity_escalated",
        "severity_downgraded",
        "exploit_gained",
        "exploit_subsided",
        "other_updates",
    ]
    counts = {cat: len(processed.get(cat, [])) for cat in categories}
    counts["total"] = sum(counts[cat] for cat in categories)
    return counts


def security_progress_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform /findings data into security progress report.

    Returns dict with keys:
    - main: flat DataFrame for CSV/XLSX
    - summary: portfolio-level summary dict
    - charts: dict of chart data (severity_distribution, triage_funnel, cve_changes)
    - triage_funnel: dict {status: count}
    - severity_distribution: dict {severity: count} for open findings
    - cve_updates: classified CVE change data from /public/v0/cves/updates
    - cve_update_summary: counts per CVE change category
    """
    additional_data = additional_data or {}

    # Fetch CVE updates from /public/v0/cves/updates
    api_client = additional_data.get("api_client")
    cve_updates = _process_cve_updates(_fetch_cve_updates(api_client, config))
    cve_update_summary = _cve_update_summary(cve_updates)

    # Accept list-of-dicts or DataFrame
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return _empty_result()
        df = data.copy()
    elif not data:
        return _empty_result()
    else:
        df = pd.DataFrame(data)

    if df.empty:
        return _empty_result()

    # Normalize nested fields into flat columns
    df = _normalize_fields(df)

    # Parse detected_at as datetime
    df = _parse_detected_at(df)

    # Apply start_date filter
    start_date = getattr(config, "start_date", None)
    if start_date and "detected_at" in df.columns:
        try:
            cutoff = pd.to_datetime(start_date, utc=True)
            before = len(df)
            df = df[df["detected_at"] >= cutoff].copy()
            logger.debug(
                "start_date filter: %d → %d findings (cutoff %s)",
                before,
                len(df),
                start_date,
            )
        except Exception as exc:
            logger.warning(
                "Could not apply start_date filter '%s': %s", start_date, exc
            )

    if df.empty:
        return _empty_result()

    # --- Triage funnel snapshot ---
    triage_funnel = _build_triage_funnel(df)

    # --- Severity distribution (open findings only) ---
    severity_dist = _build_severity_distribution(df)

    # --- Period comparison (if baseline_date is set) ---
    period_comparison: dict[str, Any] | None = None
    baseline_date = getattr(config, "baseline_date", None)
    if baseline_date and "detected_at" in df.columns:
        period_comparison = _build_period_comparison(df, baseline_date)

    # --- Build main DataFrame ---
    main_df = _build_main_df(df)

    # --- Build chart data ---
    charts = _build_charts(severity_dist, triage_funnel, cve_update_summary)

    # --- Build summary ---
    summary = _build_summary(
        df=df,
        triage_funnel=triage_funnel,
        severity_dist=severity_dist,
        period_comparison=period_comparison,
        config=config,
        cve_update_summary=cve_update_summary,
    )

    return {
        "main": main_df,
        "summary": summary,
        "charts": charts,
        "triage_funnel": triage_funnel,
        "severity_distribution": severity_dist,
        "cve_updates": cve_updates,
        "cve_update_summary": cve_update_summary,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_result() -> dict[str, Any]:
    return {
        "main": pd.DataFrame(),
        "summary": {},
        "charts": {},
        "triage_funnel": {},
        "severity_distribution": {},
        "cve_updates": {},
        "cve_update_summary": {},
    }


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
    df = _col(df, "project_name", "projectName", "project.name", "project")
    df = _col(df, "cve_id", "cveId", "cve.id", "cve")

    # Severity: already a flat column in most API responses
    if "severity" not in df.columns:
        df["severity"] = "UNKNOWN"

    # Status: already flat
    if "status" not in df.columns:
        df["status"] = "OPEN"

    # Title / name
    for title_col in ("title", "name"):
        if title_col in df.columns:
            df["title"] = df[title_col].fillna("").astype(str)
            break
    if "title" not in df.columns:
        df["title"] = ""

    # CVSS score: API returns risk as 0–100; divide by 10 for standard scale
    if "risk" in df.columns:
        df["cvss_score"] = pd.to_numeric(df["risk"], errors="coerce") / 10.0
    else:
        df["cvss_score"] = None

    return df


def _parse_detected_at(df: pd.DataFrame) -> pd.DataFrame:
    """Parse detectedDate / firstDetected into a tz-aware datetime column."""
    df = df.copy()
    for col in ("detectedDate", "firstDetected", "detected_date"):
        if col in df.columns:
            parsed = pd.to_datetime(df[col], errors="coerce", utc=True)
            # Only use this column if we got at least some valid dates
            if parsed.notna().any():
                df["detected_at"] = parsed
                return df
    # If no suitable column found, create a NaT column
    df["detected_at"] = pd.NaT
    return df


def _build_triage_funnel(df: pd.DataFrame) -> dict[str, int]:
    """Count findings by triage status."""
    funnel: dict[str, int] = dict.fromkeys(_ALL_STATUSES, 0)
    if "status" in df.columns:
        for status, count in df["status"].value_counts().items():
            funnel[str(status)] = int(count)
    return funnel


def _build_severity_distribution(df: pd.DataFrame) -> dict[str, int]:
    """Count open (OPEN + IN_TRIAGE) findings by severity."""
    dist: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    if "status" not in df.columns or "severity" not in df.columns:
        return dist
    open_df = df[df["status"].isin(_OPEN_STATUSES)]
    for sev, count in open_df["severity"].value_counts().items():
        dist[str(sev)] = int(count)
    return dist


def _build_period_comparison(
    df: pd.DataFrame, baseline_date: str
) -> dict[str, Any] | None:
    """
    Split findings into baseline vs current period and compute severity delta.

    baseline period: detected_at < baseline_date
    current period:  detected_at >= baseline_date

    Returns dict with baseline_counts, current_counts, delta per severity.
    Note: this is a detected-count delta, not a triage-state delta (API limitation).
    """
    try:
        cutoff = pd.to_datetime(baseline_date, utc=True)
    except Exception as exc:
        logger.warning("Could not parse baseline_date '%s': %s", baseline_date, exc)
        return None

    if "detected_at" not in df.columns:
        return None

    valid = df.dropna(subset=["detected_at"])
    baseline_df = valid[valid["detected_at"] < cutoff]
    current_df = valid[valid["detected_at"] >= cutoff]

    def _counts(period_df: pd.DataFrame) -> dict[str, int]:
        counts: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
        if "severity" in period_df.columns:
            for sev, cnt in period_df["severity"].value_counts().items():
                counts[str(sev)] = int(cnt)
        return counts

    baseline_counts = _counts(baseline_df)
    current_counts = _counts(current_df)
    delta = {sev: current_counts[sev] - baseline_counts[sev] for sev in _SEVERITY_ORDER}

    return {
        "baseline_date": baseline_date,
        "baseline_counts": baseline_counts,
        "current_counts": current_counts,
        "delta": delta,
        "note": "Detected-count delta only; triage state delta requires status_changed_at (not yet in API)",
    }


def _build_main_df(df: pd.DataFrame) -> pd.DataFrame:
    """Select and order columns for the flat export DataFrame."""
    col_map = {
        "severity": "Severity",
        "status": "Status",
        "detected_at": "Detected Date",
        "project_name": "Project",
        "component_name": "Component",
        "cve_id": "CVE ID",
        "title": "Title",
    }
    available = {k: v for k, v in col_map.items() if k in df.columns}
    result = df[list(available.keys())].copy()
    result = result.rename(columns=available)
    return result


def _build_charts(
    severity_dist: dict[str, int],
    triage_funnel: dict[str, int],
    cve_update_summary: dict[str, int],
) -> dict[str, Any]:
    """Build chart-ready data structures."""
    # Severity distribution bar chart — filter out zeros for cleaner chart
    sev_x = [s for s in _SEVERITY_ORDER if severity_dist.get(s, 0) > 0]
    sev_y = [severity_dist[s] for s in sev_x]

    # Triage funnel pie chart — filter out zeros
    funnel_labels = [s for s in _ALL_STATUSES if triage_funnel.get(s, 0) > 0]
    funnel_values = [triage_funnel[s] for s in funnel_labels]

    charts: dict[str, Any] = {
        "severity_distribution": {"x": sev_x, "y": sev_y},
        "triage_funnel": {"labels": funnel_labels, "values": funnel_values},
    }

    # CVE changes bar chart — only include if any changes exist
    change_labels = ["Added", "Retracted", "Severity ↑", "Severity ↓", "Exploit ↑"]
    change_values = [
        cve_update_summary.get("added", 0),
        cve_update_summary.get("retracted", 0),
        cve_update_summary.get("severity_escalated", 0),
        cve_update_summary.get("severity_downgraded", 0),
        cve_update_summary.get("exploit_gained", 0),
    ]
    if any(v > 0 for v in change_values):
        charts["cve_changes"] = {
            "labels": [
                lb for lb, v in zip(change_labels, change_values, strict=True) if v > 0
            ],
            "values": [v for v in change_values if v > 0],
        }

    return charts


def _build_summary(
    df: pd.DataFrame,
    triage_funnel: dict[str, int],
    severity_dist: dict[str, int],
    period_comparison: dict[str, Any] | None,
    config: Config,
    cve_update_summary: dict[str, int],
) -> dict[str, Any]:
    """Build portfolio-level summary dict."""
    total_findings = len(df)

    open_findings = sum(triage_funnel.get(s, 0) for s in _OPEN_STATUSES)
    resolved_findings = sum(
        triage_funnel.get(s, 0)
        for s in (
            "RESOLVED",
            "RESOLVED_WITH_PEDIGREE",
            "NOT_AFFECTED",
            "FALSE_POSITIVE",
        )
    )

    if cve_update_summary.get("total", 0) > 0:
        cve_updates_note = "CVE change data fetched from /public/v0/cves/updates"
    else:
        cve_updates_note = (
            "No CVE updates fetched (api_client not available or no changes in period)"
        )

    summary: dict[str, Any] = {
        "total_findings": total_findings,
        "open_findings": open_findings,
        "resolved_findings": resolved_findings,
        "severity_distribution": severity_dist,
        "triage_funnel": triage_funnel,
        "cve_update_summary": cve_update_summary,
        "cve_updates_note": cve_updates_note,
        "period_start": getattr(config, "start_date", None),
        "period_end": getattr(config, "end_date", None),
    }

    baseline_date = getattr(config, "baseline_date", None)
    if baseline_date:
        summary["baseline_date"] = baseline_date

    if period_comparison is not None:
        summary["period_comparison"] = period_comparison

    return summary
