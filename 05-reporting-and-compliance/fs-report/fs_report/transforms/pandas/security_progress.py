"""
Pandas transform for the Security Progress report.

Produces:
- Per-project version progression with CVE lifecycle tracking
- Portfolio-level KPIs (total resolved, new, net change)
- Portfolio progression timeline for trend charts
- CVE change tracking via /public/v0/cves/updates (new, retracted, severity/exploit changes)

CVE Lifecycle Model:
    For each consecutive version pair, CVEs are classified as:
    - resolved_by_triage: CVE exists in current version with a resolved VEX status
    - resolved_by_removal: CVE was in previous version but absent from current
    - new: CVE in current version but not in previous
    - still_open: CVE in both versions without a resolved status

CVE Updates Integration:
    The transform calls GET /public/v0/cves/updates?startDate=...&endDate=... to fetch
    CVE changes during the reporting window. Results are classified into:
    - added: new CVEs introduced
    - retracted: CVEs removed/retracted
    - severity_escalated / severity_downgraded: CVSS severity changed
    - exploit_gained / exploit_subsided: exploit maturity changed
    - other_updates: remaining updates with no severity/exploit change

    Requires api_client in additional_data["api_client"].
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

# VEX statuses that mean "resolved" for lifecycle tracking
_RESOLVED_STATUSES = {
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
    "EXPLOITABLE",
}

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
    """Map exploit maturity string to a comparable rank (0-3)."""
    if not maturity:
        return 0
    m = maturity.upper()
    if m in ("POC", "PROOF_OF_CONCEPT"):
        return 1
    if m == "FUNCTIONAL":
        return 2
    if m in ("HIGH", "WEAPONIZED", "EXPLOITED_IN_WILD"):
        return 3
    # UNPROVEN and unknown values -> 0
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


# ---------------------------------------------------------------------------
# CVE Lifecycle Classification
# ---------------------------------------------------------------------------


def _is_resolved_status(status: str | None) -> bool:
    """Return True if the VEX status indicates the finding is resolved."""
    if not status:
        return False
    return status.upper() in _RESOLVED_STATUSES


def _extract_cve_map(findings: list[dict]) -> dict[str, dict]:
    """Build a map of CVE ID -> finding dict from a list of findings.

    If multiple findings share a CVE ID, the last one wins (shouldn't happen
    in practice since findings are per-version).
    """
    cve_map: dict[str, dict] = {}
    for f in findings:
        cve_id = f.get("findingId") or f.get("cveId") or f.get("cve_id") or ""
        if cve_id:
            cve_map[cve_id] = f
    return cve_map


def _classify_cve_lifecycle(
    prev_findings: list[dict],
    curr_findings: list[dict],
) -> dict[str, set[str]]:
    """Classify CVE lifecycle between two consecutive versions.

    Returns dict with keys:
    - resolved_by_triage: CVE IDs in curr with a resolved VEX status
    - resolved_by_removal: CVE IDs in prev but absent from curr
    - new: CVE IDs in curr but not in prev
    - still_open: CVE IDs in both without resolved status
    """
    prev_map = _extract_cve_map(prev_findings)
    curr_map = _extract_cve_map(curr_findings)

    prev_ids = set(prev_map.keys())
    curr_ids = set(curr_map.keys())

    resolved_by_removal = prev_ids - curr_ids
    new_cves = curr_ids - prev_ids
    common = prev_ids & curr_ids

    resolved_by_triage: set[str] = set()
    still_open: set[str] = set()

    for cve_id in common:
        curr_status = curr_map[cve_id].get("status")
        prev_status = prev_map[cve_id].get("status")
        if _is_resolved_status(curr_status) and not _is_resolved_status(prev_status):
            # Transitioned from open to resolved in this version step
            resolved_by_triage.add(cve_id)
        elif not _is_resolved_status(curr_status):
            still_open.add(cve_id)
        # else: was already resolved in prev, stays resolved — not a new resolution

    # Also check new CVEs that might already be resolved
    # (these are still "new" but not "open")
    # We don't reclassify them — they count as new regardless of status

    return {
        "resolved_by_triage": resolved_by_triage,
        "resolved_by_removal": resolved_by_removal,
        "new": new_cves,
        "still_open": still_open,
    }


def _count_open(findings: list[dict]) -> int:
    """Count findings that are not resolved."""
    count = 0
    for f in findings:
        status = f.get("status")
        if not _is_resolved_status(status):
            count += 1
    return count


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    """Count open findings by severity."""
    counts: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for f in findings:
        if not _is_resolved_status(f.get("status")):
            sev = (f.get("severity") or "UNKNOWN").upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["UNKNOWN"] += 1
    return counts


# ---------------------------------------------------------------------------
# Project Progression Builder
# ---------------------------------------------------------------------------


def _build_project_progression(
    project_name: str,
    versions: list[dict],
) -> dict[str, Any]:
    """Build a version-over-version progression for a single project.

    Returns dict with:
    - project_name: str
    - progression: list of per-version snapshots
    - baseline_open: open count at first version
    - current_open: open count at last version
    - total_resolved: cumulative resolved across all version steps
    - total_new: cumulative new across all version steps
    - net_change: current_open - baseline_open
    """
    if not versions:
        return {
            "project_name": project_name,
            "progression": [],
            "baseline_open": 0,
            "current_open": 0,
            "total_resolved": 0,
            "total_new": 0,
            "net_change": 0,
        }

    progression: list[dict[str, Any]] = []
    total_resolved = 0
    total_new = 0

    for i, version in enumerate(versions):
        findings = version.get("findings", [])
        open_count = _count_open(findings)
        sev = _severity_counts(findings)

        if i == 0:
            # First version: baseline, no deltas
            snapshot: dict[str, Any] = {
                "version": version.get("name", ""),
                "date": version.get("created", ""),
                "open_count": open_count,
                "resolved": 0,
                "new": 0,
                "total": len(findings),
                "severity": sev,
            }
        else:
            prev_findings = versions[i - 1].get("findings", [])
            lifecycle = _classify_cve_lifecycle(prev_findings, findings)
            resolved = len(lifecycle["resolved_by_triage"]) + len(
                lifecycle["resolved_by_removal"]
            )
            new_count = len(lifecycle["new"])
            total_resolved += resolved
            total_new += new_count

            snapshot = {
                "version": version.get("name", ""),
                "date": version.get("created", ""),
                "open_count": open_count,
                "resolved": resolved,
                "new": new_count,
                "total": len(findings),
                "severity": sev,
            }

        progression.append(snapshot)

    baseline_open = progression[0]["open_count"]
    current_open = progression[-1]["open_count"]

    return {
        "project_name": project_name,
        "progression": progression,
        "baseline_open": baseline_open,
        "current_open": current_open,
        "total_resolved": total_resolved,
        "total_new": total_new,
        "net_change": current_open - baseline_open,
    }


# ---------------------------------------------------------------------------
# Main Transform
# ---------------------------------------------------------------------------


def security_progress_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform version progression data into a security progress report.

    If additional_data["projects"] is available, uses version-progression model.
    Otherwise, falls back to flat snapshot for backward compatibility.

    Returns dict with keys:
    - projects: list of per-project progression dicts
    - portfolio_kpi: portfolio-level KPI summary
    - portfolio_progression: combined timeline for trend chart
    - main: DataFrame for CSV export
    - summary: dict with period info for template
    - charts: chart data dicts for template
    - cve_updates: classified CVE change data
    - cve_update_summary: counts per CVE change category
    """
    additional_data = additional_data or {}

    # Fetch CVE updates from /public/v0/cves/updates
    api_client = additional_data.get("api_client")
    cve_updates = _process_cve_updates(_fetch_cve_updates(api_client, config))
    cve_update_summary = _cve_update_summary(cve_updates)

    projects_data = additional_data.get("projects")

    if projects_data:
        return _transform_with_projects(
            projects_data, config, cve_updates, cve_update_summary
        )

    # Fallback: flat snapshot (backward compat)
    return _transform_flat_snapshot(data, config, cve_updates, cve_update_summary)


# ---------------------------------------------------------------------------
# Version-Progression Transform
# ---------------------------------------------------------------------------


def _transform_with_projects(
    projects_data: list[dict],
    config: Config,
    cve_updates: dict[str, list[dict]],
    cve_update_summary: dict[str, int],
) -> dict[str, Any]:
    """Build progression report from per-project version data."""
    if not projects_data:
        return _empty_result(cve_updates, cve_update_summary)

    # Build per-project progressions
    project_progressions: list[dict[str, Any]] = []
    for proj in projects_data:
        prog = _build_project_progression(
            proj.get("project_name", "Unknown"),
            proj.get("versions", []),
        )
        project_progressions.append(prog)

    # Sort by most improved (most negative net_change first)
    project_progressions.sort(key=lambda p: p["net_change"])

    # Portfolio KPIs
    total_resolved = sum(p["total_resolved"] for p in project_progressions)
    total_new = sum(p["total_new"] for p in project_progressions)
    net_change = sum(p["net_change"] for p in project_progressions)
    projects_improved = sum(1 for p in project_progressions if p["net_change"] < 0)
    projects_regressed = sum(1 for p in project_progressions if p["net_change"] > 0)

    portfolio_kpi = {
        "total_resolved": total_resolved,
        "total_new": total_new,
        "net_change": net_change,
        "projects_improved": projects_improved,
        "projects_regressed": projects_regressed,
    }

    # Portfolio progression: combined open count at each timestamp
    portfolio_progression = _build_portfolio_progression(project_progressions)

    # Build main DataFrame for CSV export
    main_df = _build_progression_df(project_progressions)

    # Build charts
    charts = _build_progression_charts(
        project_progressions, portfolio_progression, cve_update_summary
    )

    # Build summary
    summary = {
        "period_start": getattr(config, "start_date", None),
        "period_end": getattr(config, "end_date", None),
        "total_projects": len(project_progressions),
        "total_resolved": total_resolved,
        "total_new": total_new,
        "net_change": net_change,
        "projects_improved": projects_improved,
        "projects_regressed": projects_regressed,
        "cve_update_summary": cve_update_summary,
        "mode": "version_progression",
    }

    return {
        "projects": project_progressions,
        "portfolio_kpi": portfolio_kpi,
        "portfolio_progression": portfolio_progression,
        "main": main_df,
        "summary": summary,
        "charts": charts,
        "cve_updates": cve_updates,
        "cve_update_summary": cve_update_summary,
    }


def _build_portfolio_progression(
    project_progressions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build combined timeline by aggregating open counts across projects at each timestamp."""
    # Collect all (date, open_count) from each project
    date_totals: dict[str, int] = {}
    for proj in project_progressions:
        for snap in proj.get("progression", []):
            date = snap.get("date", "")
            if date:
                date_totals[date] = date_totals.get(date, 0) + snap["open_count"]

    # Sort by date
    sorted_dates = sorted(date_totals.keys())
    return [{"date": d, "open_count": date_totals[d]} for d in sorted_dates]


def _build_progression_df(
    project_progressions: list[dict[str, Any]],
) -> pd.DataFrame:
    """Build a flat DataFrame for CSV export from progression data."""
    rows: list[dict[str, Any]] = []
    for proj in project_progressions:
        for snap in proj.get("progression", []):
            rows.append(
                {
                    "Project": proj["project_name"],
                    "Version": snap["version"],
                    "Date": snap["date"],
                    "Open": snap["open_count"],
                    "Resolved": snap["resolved"],
                    "New": snap["new"],
                    "Net": (
                        snap["open_count"] - proj["progression"][0]["open_count"]
                        if proj["progression"]
                        else 0
                    ),
                }
            )
    if not rows:
        return pd.DataFrame(
            columns=["Project", "Version", "Date", "Open", "Resolved", "New", "Net"]
        )
    return pd.DataFrame(rows)


def _build_progression_charts(
    project_progressions: list[dict[str, Any]],
    portfolio_progression: list[dict[str, Any]],
    cve_update_summary: dict[str, int],
) -> dict[str, Any]:
    """Build chart data for the progression report."""
    charts: dict[str, Any] = {}

    # Portfolio trend line
    if portfolio_progression:
        charts["portfolio_trend"] = {
            "x": [p["date"] for p in portfolio_progression],
            "y": [p["open_count"] for p in portfolio_progression],
        }

    # Per-project bar chart: net change
    if project_progressions:
        charts["project_net_change"] = {
            "x": [p["project_name"] for p in project_progressions],
            "y": [p["net_change"] for p in project_progressions],
        }

    # CVE changes bar chart
    change_labels = ["Added", "Retracted", "Severity Up", "Severity Down", "Exploit Up"]
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


# ---------------------------------------------------------------------------
# Flat Snapshot Fallback (backward compatibility)
# ---------------------------------------------------------------------------


def _transform_flat_snapshot(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    cve_updates: dict[str, list[dict]],
    cve_update_summary: dict[str, int],
) -> dict[str, Any]:
    """Fallback: flat snapshot transform when version data is not available."""
    # Accept list-of-dicts or DataFrame
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return _empty_result(cve_updates, cve_update_summary)
        df = data.copy()
    elif not data:
        return _empty_result(cve_updates, cve_update_summary)
    else:
        df = pd.DataFrame(data)

    if df.empty:
        return _empty_result(cve_updates, cve_update_summary)

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
                "start_date filter: %d -> %d findings (cutoff %s)",
                before,
                len(df),
                start_date,
            )
        except Exception as exc:
            logger.warning(
                "Could not apply start_date filter '%s': %s", start_date, exc
            )

    if df.empty:
        return _empty_result(cve_updates, cve_update_summary)

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
    charts = _build_flat_charts(severity_dist, triage_funnel, cve_update_summary)

    # --- Build summary ---
    summary = _build_flat_summary(
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
# Helpers (shared)
# ---------------------------------------------------------------------------


def _empty_result(
    cve_updates: dict[str, list[dict]] | None = None,
    cve_update_summary: dict[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "main": pd.DataFrame(),
        "summary": {},
        "charts": {},
        "triage_funnel": {},
        "severity_distribution": {},
        "cve_updates": cve_updates if cve_updates is not None else {},
        "cve_update_summary": (
            cve_update_summary if cve_update_summary is not None else {}
        ),
    }


# ---------------------------------------------------------------------------
# Helpers (flat snapshot)
# ---------------------------------------------------------------------------


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

    # CVSS score: API returns risk as 0-100; divide by 10 for standard scale
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
    """Split findings into baseline vs current period and compute severity delta."""
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
        "note": (
            "Detected-count delta only; triage state delta requires "
            "status_changed_at (not yet in API)"
        ),
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


def _build_flat_charts(
    severity_dist: dict[str, int],
    triage_funnel: dict[str, int],
    cve_update_summary: dict[str, int],
) -> dict[str, Any]:
    """Build chart-ready data structures for flat snapshot."""
    # Severity distribution bar chart
    sev_x = [s for s in _SEVERITY_ORDER if severity_dist.get(s, 0) > 0]
    sev_y = [severity_dist[s] for s in sev_x]

    # Triage funnel pie chart
    funnel_labels = [s for s in _ALL_STATUSES if triage_funnel.get(s, 0) > 0]
    funnel_values = [triage_funnel[s] for s in funnel_labels]

    charts: dict[str, Any] = {
        "severity_distribution": {"x": sev_x, "y": sev_y},
        "triage_funnel": {"labels": funnel_labels, "values": funnel_values},
    }

    # CVE changes bar chart
    change_labels = ["Added", "Retracted", "Severity Up", "Severity Down", "Exploit Up"]
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


def _build_flat_summary(
    df: pd.DataFrame,
    triage_funnel: dict[str, int],
    severity_dist: dict[str, int],
    period_comparison: dict[str, Any] | None,
    config: Config,
    cve_update_summary: dict[str, int],
) -> dict[str, Any]:
    """Build portfolio-level summary dict for flat snapshot."""
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
        "mode": "flat_snapshot",
    }

    baseline_date = getattr(config, "baseline_date", None)
    if baseline_date:
        summary["baseline_date"] = baseline_date

    if period_comparison is not None:
        summary["period_comparison"] = period_comparison

    return summary
