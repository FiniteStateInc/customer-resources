"""
Pandas transform functions for Scan Quality report.

Produces per-project scan quality assessment including scan coverage analysis
and quality signals. Distinct from Scan Analysis (throughput/failures): this
report surfaces customer-facing quality signals such as scan type coverage.
"""

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan type classification constants
# ---------------------------------------------------------------------------

# Coverage categories (0-4 scale):
#   Source path: SBOM_IMPORT or SOURCE_SCA = full coverage (4)
#   Binary path: additive — Binary SCA(1) + SAST(2) + Config(3) + Reachability(4)
#   Final score = max(source_path, binary_path)

_SBOM_IMPORT_TYPES = frozenset({"SBOM_IMPORT"})
_SOURCE_SCA_TYPES = frozenset({"SOURCE_SCA"})
_BINARY_SCA_TYPES = frozenset({"BINARY_SCA", "SCA"})
_SAST_TYPES = frozenset({"SAST", "BINARY_SAST"})
_CONFIG_TYPES = frozenset({"CONFIG", "CONFIGURATION_ANALYSIS"})
_REACHABILITY_TYPES = frozenset({"VULNERABILITY_ANALYSIS"})

# Default staleness thresholds (days)
_DEFAULT_STALENESS_THRESHOLDS: dict[str, int] = {
    "fresh": 30,
    "aging": 90,
    "stale": 365,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    """Return current UTC datetime — patchable in tests."""
    return datetime.now(UTC)


def _load_staleness_thresholds(
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Load staleness thresholds with priority: --scoring-file > recipe_parameters > defaults.

    Returns a dict with keys: fresh, aging, stale (all in days).
    """
    thresholds = dict(_DEFAULT_STALENESS_THRESHOLDS)

    # Layer 1: recipe parameters (lowest-priority override)
    if additional_data:
        recipe_params = additional_data.get("recipe_parameters", {})
        recipe_thresholds = (
            recipe_params.get("staleness_thresholds", {}) if recipe_params else {}
        )
        if recipe_thresholds and isinstance(recipe_thresholds, dict):
            for k, v in recipe_thresholds.items():
                if k in thresholds:
                    thresholds[k] = int(v)
            logger.debug(
                "Applied %d staleness thresholds from recipe parameters",
                len(recipe_thresholds),
            )

    # Layer 2: --scoring-file (highest-priority override)
    scoring_file = None
    if config and hasattr(config, "scoring_file"):
        scoring_file = getattr(config, "scoring_file", None)
    elif additional_data and "config" in additional_data:
        cfg = additional_data["config"]
        scoring_file = getattr(cfg, "scoring_file", None)

    if scoring_file:
        try:
            import yaml

            path = Path(scoring_file)
            if path.exists():
                with open(path) as f:
                    file_data = yaml.safe_load(f) or {}
                if isinstance(file_data, dict):
                    file_thresholds = file_data.get("staleness_thresholds", file_data)
                    if isinstance(file_thresholds, dict):
                        for k, v in file_thresholds.items():
                            if k in thresholds:
                                thresholds[k] = int(v)
                        logger.info(
                            "Applied staleness thresholds from %s", scoring_file
                        )
            else:
                logger.warning("Scoring file not found: %s", scoring_file)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load scoring file %s: %s", scoring_file, exc)

    return thresholds


def _score_to_rating(score: int) -> str:
    """Convert an unpack score (0–100) to a human-readable rating tier."""
    if score >= 85:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Fair"
    return "Poor"


def _compute_staleness(days: float, thresholds: dict[str, int]) -> str:
    """Classify staleness from days-since-last-scan.

    Boundaries (inclusive): days <= fresh → FRESH, days <= aging → AGING,
    days <= stale → STALE, else DORMANT.
    """
    if days <= thresholds["fresh"]:
        return "FRESH"
    if days <= thresholds["aging"]:
        return "AGING"
    if days <= thresholds["stale"]:
        return "STALE"
    return "DORMANT"


def _fetch_json(api_client: Any, path: str) -> Any:
    """GET ``{base_url}{path}`` and return parsed JSON.

    Uses the httpx client on the api_client object.
    """
    url = f"{api_client.base_url}{path}"
    resp = api_client.client.get(url)
    resp.raise_for_status()
    return resp.json()


def _enrich_severity_counts(detail_df: pd.DataFrame, api_client: Any) -> pd.DataFrame:
    """Populate critical_findings, high_findings, total_findings via API.

    Calls GET /public/v0/project/version/{pvId}/findings/severities/counts for
    each unique pv_id.  Fails silently per-version on any exception.
    """
    for idx, row in detail_df.iterrows():
        pv_id = row["pv_id"]
        try:
            endpoint = f"/public/v0/project/version/{pv_id}/findings/severities/counts"
            data = _fetch_json(api_client, endpoint)
            by_sev = data.get("bySeverity", {}) if isinstance(data, dict) else {}
            total = data.get("total", 0) if isinstance(data, dict) else 0
            # API may return lowercase or uppercase severity keys
            by_sev_lower = {k.lower(): v for k, v in by_sev.items()}
            detail_df.at[idx, "critical_findings"] = int(
                by_sev_lower.get("critical", 0)
            )
            detail_df.at[idx, "high_findings"] = int(by_sev_lower.get("high", 0))
            detail_df.at[idx, "total_findings"] = int(total)
        except Exception:  # noqa: BLE001
            logger.debug(
                "Failed to fetch severity counts for pv_id=%s", pv_id, exc_info=True
            )
    return detail_df


def _enrich_unpack_evaluation(
    detail_df: pd.DataFrame, api_client: Any, config: Any
) -> pd.DataFrame:
    """Populate unpack_score, unpack_rating, unpack_issues_count, unpack_short_summary.

    Only runs when config.project_filter or config.folder_filter is set (not
    portfolio-wide).  Processes only rows where _latest_binary_scan_id is
    non-null.  Capped at 50 API calls.
    """
    # Skip for portfolio-wide runs
    project_filter = getattr(config, "project_filter", None)
    folder_filter = getattr(config, "folder_filter", None)
    if not project_filter and not folder_filter:
        return detail_df

    if "_latest_binary_scan_id" not in detail_df.columns:
        return detail_df

    call_count = 0
    for idx, row in detail_df.iterrows():
        if call_count >= 50:
            break
        scan_id = row.get("_latest_binary_scan_id")
        if not scan_id:
            continue
        try:
            endpoint = f"/public/v0/scans/{scan_id}/unpack-evaluation"
            data = _fetch_json(api_client, endpoint)
            call_count += 1
            report = (data or {}).get("report", {}) if isinstance(data, dict) else {}
            if not report:
                continue
            score = report.get("unpackingScore")
            if score is not None:
                detail_df.at[idx, "unpack_score"] = int(score)
                detail_df.at[idx, "unpack_rating"] = _score_to_rating(int(score))
            issues = report.get("potentialIssues") or []
            detail_df.at[idx, "unpack_issues_count"] = len(issues)
            detail_df.at[idx, "unpack_short_summary"] = report.get("shortSummary")
        except Exception:  # noqa: BLE001
            logger.debug(
                "Failed to fetch unpack evaluation for scan_id=%s",
                scan_id,
                exc_info=True,
            )
    return detail_df


def _compute_reachability(scan_types: set[str], completed_types: set[str]) -> str:
    """Return Yes/No/N/A reachability label.

    - Yes  : VULNERABILITY_ANALYSIS completed.
    - No   : has binary SCA scans but no VULNERABILITY_ANALYSIS completed.
    - N/A  : no binary SCA scans at all.
    """
    has_binary = bool(scan_types & _BINARY_SCA_TYPES)
    has_reach = bool(completed_types & _REACHABILITY_TYPES)
    if has_reach:
        return "Yes"
    if has_binary:
        return "No"
    return "N/A"


def _compute_coverage_score(completed_types: set[str]) -> int:
    """Compute coverage score (0-4).

    SBOM Import or Source SCA provide full coverage (4) on their own.
    Binary scan pipeline adds up: Binary SCA(1) + SAST(2) + Config(3) + Reachability(4).
    Returns the max of source and binary paths.
    """
    # Source path: SBOM Import or Source SCA = full coverage
    source_score = 0
    if completed_types & _SBOM_IMPORT_TYPES or completed_types & _SOURCE_SCA_TYPES:
        source_score = 4

    # Binary path: additive
    binary_score = 0
    if completed_types & _BINARY_SCA_TYPES:
        binary_score += 1
    if completed_types & _SAST_TYPES:
        binary_score += 1
    if completed_types & _CONFIG_TYPES:
        binary_score += 1
    if completed_types & _REACHABILITY_TYPES:
        binary_score += 1

    return max(source_score, binary_score)


def _parse_date(date_str: str) -> datetime | None:
    """Parse an ISO-8601 UTC date string into a timezone-aware datetime."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Table builders
# ---------------------------------------------------------------------------


def _build_detail_table(
    records: list[dict[str, Any]],
    thresholds: dict[str, int],
    project_folder_map: dict[int, str] | None = None,
) -> pd.DataFrame:
    """Build one row per project-version from raw scan records."""
    now = _now()

    # Group records by (project_id, pv_id)
    groups: dict[tuple[int, int], list[dict[str, Any]]] = {}
    for rec in records:
        project = rec.get("project") or {}
        pv = rec.get("projectVersion") or {}
        project_id = project.get("id", 0) if isinstance(project, dict) else 0
        pv_id = pv.get("id", 0) if isinstance(pv, dict) else 0
        key = (int(project_id), int(pv_id))
        groups.setdefault(key, []).append(rec)

    rows: list[dict[str, Any]] = []
    for (project_id, pv_id), group_recs in groups.items():
        first = group_recs[0]
        project = first.get("project") or {}
        pv = first.get("projectVersion") or {}

        project_name = (
            project.get("name", "Unknown") if isinstance(project, dict) else "Unknown"
        )
        # API may use "name" or "version" for the version label
        version_name = (
            (pv.get("name") or pv.get("version") or "") if isinstance(pv, dict) else ""
        )

        # All scan types seen (any status)
        all_types: set[str] = set()
        # Completed scan types only
        completed_types: set[str] = set()
        # Latest scan date
        latest_dt: datetime | None = None
        scan_count = len(group_recs)
        # Latest completed BINARY_SCA scan id (for unpack evaluation)
        latest_binary_scan_id: str | None = None
        latest_binary_dt: datetime | None = None

        for rec in group_recs:
            raw_type = str(rec.get("scanType") or rec.get("type") or "").upper()
            all_types.add(raw_type)
            status = str(rec.get("status", "")).upper()
            if status == "COMPLETED":
                completed_types.add(raw_type)
            created_str = rec.get("created", "")
            dt = _parse_date(created_str)
            if dt is not None:
                if latest_dt is None or dt > latest_dt:
                    latest_dt = dt
            # Track latest completed BINARY_SCA for unpack enrichment
            if raw_type in _BINARY_SCA_TYPES and status == "COMPLETED":
                if dt is not None and (
                    latest_binary_dt is None or dt > latest_binary_dt
                ):
                    latest_binary_dt = dt
                    latest_binary_scan_id = str(rec.get("id", "") or "")

        # Coverage flags (COMPLETED only)
        has_sbom_import = bool(completed_types & _SBOM_IMPORT_TYPES)
        has_source_sca = bool(completed_types & _SOURCE_SCA_TYPES)
        has_binary_sca = bool(completed_types & _BINARY_SCA_TYPES)
        has_sast = bool(completed_types & _SAST_TYPES)
        has_config = bool(completed_types & _CONFIG_TYPES)
        has_reachability_str = _compute_reachability(all_types, completed_types)
        coverage_score = _compute_coverage_score(completed_types)

        # Staleness
        if latest_dt is not None:
            days_since = (now - latest_dt).total_seconds() / 86400.0
            staleness = _compute_staleness(days_since, thresholds)
            last_scan_date = latest_dt.strftime("%Y-%m-%d")
        else:
            staleness = "DORMANT"
            last_scan_date = ""

        rows.append(
            {
                "project_id": project_id,
                "project_name": project_name,
                "folder_name": (project_folder_map or {}).get(project_id, ""),
                "pv_id": pv_id,
                "version_name": version_name,
                "has_sbom_import": has_sbom_import,
                "has_source_sca": has_source_sca,
                "has_binary_sca": has_binary_sca,
                "has_sast": has_sast,
                "has_config": has_config,
                "has_reachability": has_reachability_str,
                "coverage_score": coverage_score,
                "last_scan_date": last_scan_date,
                "staleness": staleness,
                "scan_count": scan_count,
                # Enrichment placeholder columns
                "critical_findings": 0,
                "high_findings": 0,
                "total_findings": 0,
                "unpack_score": None,
                "unpack_rating": None,
                "unpack_issues_count": 0,
                "unpack_short_summary": None,
                # Keep latest_dt for summary aggregation (will be dropped later)
                "_latest_dt": latest_dt,
                # Keep latest binary scan id for unpack enrichment (will be dropped later)
                "_latest_binary_scan_id": latest_binary_scan_id,
            }
        )

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


def _build_summary_table(detail_df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate detail rows into one row per project (latest version)."""
    if detail_df.empty:
        return pd.DataFrame()

    rows: list[dict[str, Any]] = []

    for project_id, group in detail_df.groupby("project_id", sort=False):
        # Find the latest version by _latest_dt
        latest_row = group.loc[
            group["_latest_dt"]
            .apply(lambda x: (x if x is not None else datetime.min.replace(tzinfo=UTC)))
            .idxmax()
        ]

        version_count = len(group)
        project_name = latest_row["project_name"]
        folder_name = latest_row["folder_name"]
        latest_version = latest_row["version_name"]
        last_scan_date = latest_row["last_scan_date"]
        staleness = latest_row["staleness"]
        coverage_score = latest_row["coverage_score"]
        has_sbom_import = latest_row["has_sbom_import"]
        has_source_sca = latest_row["has_source_sca"]
        has_binary_sca = latest_row["has_binary_sca"]
        has_sast = latest_row["has_sast"]
        has_config = latest_row["has_config"]
        has_reachability = latest_row["has_reachability"]

        rows.append(
            {
                "project_id": project_id,
                "project_name": project_name,
                "folder_name": folder_name,
                "version_count": version_count,
                "latest_version": latest_version,
                "last_scan_date": last_scan_date,
                "staleness": staleness,
                "has_sbom_import": has_sbom_import,
                "has_source_sca": has_source_sca,
                "has_binary_sca": has_binary_sca,
                "has_sast": has_sast,
                "has_config": has_config,
                "has_reachability": has_reachability,
                "coverage_score": coverage_score,
                "critical_findings": int(latest_row.get("critical_findings", 0) or 0),
                "high_findings": int(latest_row.get("high_findings", 0) or 0),
                "total_findings": int(latest_row.get("total_findings", 0) or 0),
                "unpack_score": latest_row.get("unpack_score"),
                "unpack_rating": latest_row.get("unpack_rating"),
                "unpack_issues_count": int(
                    latest_row.get("unpack_issues_count", 0) or 0
                ),
                "unpack_short_summary": latest_row.get("unpack_short_summary"),
            }
        )

    return pd.DataFrame(rows)


def _build_charts(
    summary_df: pd.DataFrame,
    detail_df: pd.DataFrame,
) -> dict[str, Any]:
    """Build chart data structures for staleness distribution and scan type coverage."""
    # staleness_distribution — always include all 4 labels
    staleness_labels = ["FRESH", "AGING", "STALE", "DORMANT"]
    if not summary_df.empty and "staleness" in summary_df.columns:
        counts = summary_df["staleness"].value_counts()
        staleness_values = [int(counts.get(label, 0)) for label in staleness_labels]
    else:
        staleness_values = [0, 0, 0, 0]

    # scan_type_coverage — project counts from summary table (one row per project)
    if not summary_df.empty:
        type_counts: dict[str, int] = {}
        for col, label in [
            ("has_source_sca", "Source SCA"),
            ("has_binary_sca", "Binary SCA"),
            ("has_sast", "SAST"),
            ("has_config", "Config"),
        ]:
            if col in summary_df.columns:
                type_counts[label] = int(summary_df[col].sum())
        if "has_reachability" in summary_df.columns:
            type_counts["Reachability"] = int(
                (summary_df["has_reachability"] == "Yes").sum()
            )
        scan_type_labels = list(type_counts.keys())
        scan_type_values = list(type_counts.values())
    else:
        scan_type_labels = []
        scan_type_values = []

    charts: dict[str, Any] = {
        "staleness_distribution": {
            "labels": staleness_labels,
            "values": staleness_values,
        },
        "scan_type_coverage": {
            "labels": scan_type_labels,
            "values": scan_type_values,
        },
    }

    # unpack_rating_distribution — only when unpack data is present
    if (
        not detail_df.empty
        and "unpack_rating" in detail_df.columns
        and detail_df["unpack_rating"].notna().any()
    ):
        rating_labels = ["Excellent", "Good", "Fair", "Poor"]
        rating_counts = detail_df["unpack_rating"].value_counts()
        charts["unpack_rating_distribution"] = {
            "labels": rating_labels,
            "values": [int(rating_counts.get(label, 0)) for label in rating_labels],
        }

    return charts


def _build_summary_dict(summary_df: pd.DataFrame) -> dict[str, Any]:
    """Build KPI summary dict from the summary (project-level) table."""
    if summary_df.empty:
        return {
            "total_projects": 0,
            "avg_coverage_score": 0.0,
            "reachability_coverage": {
                "with_reachability": 0,
                "binary_projects": 0,
                "source_only_projects": 0,
            },
            "stale_project_count": 0,
        }

    total_projects = len(summary_df)
    avg_coverage_score = float(summary_df["coverage_score"].mean())

    # Reachability coverage stats
    with_reachability = int((summary_df["has_reachability"] == "Yes").sum())
    binary_projects = int(
        (
            (summary_df["has_binary_sca"] == True)  # noqa: E712
            & (summary_df["has_reachability"] == "No")
        ).sum()
    )
    source_only_projects = int((summary_df["has_reachability"] == "N/A").sum())

    stale_project_count = int(summary_df["staleness"].isin(["STALE", "DORMANT"]).sum())

    return {
        "total_projects": total_projects,
        "avg_coverage_score": avg_coverage_score,
        "reachability_coverage": {
            "with_reachability": with_reachability,
            "binary_projects": binary_projects,
            "source_only_projects": source_only_projects,
        },
        "stale_project_count": stale_project_count,
    }


def _empty_result() -> dict[str, Any]:
    """Return a consistent empty result structure."""
    summary_table = pd.DataFrame()
    return {
        "main": summary_table,
        "summary_table": summary_table,
        "detail_table": pd.DataFrame(),
        "summary": {
            "total_projects": 0,
            "avg_coverage_score": 0.0,
            "reachability_coverage": {
                "with_reachability": 0,
                "binary_projects": 0,
                "source_only_projects": 0,
            },
            "stale_project_count": 0,
        },
        "charts": {
            "staleness_distribution": {
                "labels": ["FRESH", "AGING", "STALE", "DORMANT"],
                "values": [0, 0, 0, 0],
            },
            "scan_type_coverage": {"labels": [], "values": []},
        },
        "thresholds": dict(_DEFAULT_STALENESS_THRESHOLDS),
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_quality_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config | None = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Transform scan data for the Scan Quality report.

    Args:
        data: Raw scan records from ``/public/v0/scans`` (list of dicts or
              DataFrame).
        config: Application configuration (for --scoring-file support).
        additional_data: Optional dict that may contain:
            - ``recipe_parameters``: dict with ``staleness_thresholds`` override.
            - ``config``: alternative config object location.

    Returns:
        Dictionary with keys:
        - ``main``: alias for summary_table (same object)
        - ``summary_table``: DataFrame — one row per project
        - ``detail_table``: DataFrame — one row per project-version
        - ``summary``: dict of aggregate quality metrics
        - ``charts``: dict of chart-ready data structures
    """
    additional_data = additional_data or {}

    # ------------------------------------------------------------------
    # Normalise input
    # ------------------------------------------------------------------
    records: list[dict[str, Any]]
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return _empty_result()
        records = data.to_dict("records")  # type: ignore[assignment]
    elif not data:
        return _empty_result()
    else:
        records = list(data)

    if not records:
        return _empty_result()

    # ------------------------------------------------------------------
    # Filter to active projects only
    # ------------------------------------------------------------------
    projects_data = additional_data.get("projects")
    valid_project_ids: set[int] | None = None
    project_folder_map: dict[int, str] = {}

    if projects_data:
        valid_project_ids = set()
        for p in projects_data:
            pid = p.get("id")
            if pid is not None:
                valid_project_ids.add(int(pid))
                folder = p.get("folder") or {}
                if isinstance(folder, dict):
                    project_folder_map[int(pid)] = folder.get("name", "")

        before_count = len(records)
        records = [
            r
            for r in records
            if int((r.get("project") or {}).get("id", 0)) in valid_project_ids
        ]
        if before_count != len(records):
            logger.info(
                "Filtered %d scans to %d (removed %d for deleted/archived projects)",
                before_count,
                len(records),
                before_count - len(records),
            )

    if not records:
        return _empty_result()

    # ------------------------------------------------------------------
    # Load configuration
    # ------------------------------------------------------------------
    thresholds = _load_staleness_thresholds(config, additional_data)

    # ------------------------------------------------------------------
    # Build tables
    # ------------------------------------------------------------------
    detail_df = _build_detail_table(records, thresholds, project_folder_map)

    if detail_df.empty:
        return _empty_result()

    # ------------------------------------------------------------------
    # API enrichment (severity counts + unpack evaluation)
    # ------------------------------------------------------------------
    api_client = additional_data.get("api_client")
    if api_client is not None:
        detail_df = _enrich_severity_counts(detail_df, api_client)
        cfg = additional_data.get("config") or config
        if cfg is not None:
            detail_df = _enrich_unpack_evaluation(detail_df, api_client, cfg)

    summary_df = _build_summary_table(detail_df)

    # Drop internal helper columns from detail table before returning
    cols_to_drop = [
        c for c in ["_latest_dt", "_latest_binary_scan_id"] if c in detail_df.columns
    ]
    if cols_to_drop:
        detail_df = detail_df.drop(columns=cols_to_drop)

    # ------------------------------------------------------------------
    # Charts and summary dict
    # ------------------------------------------------------------------
    charts = _build_charts(summary_df, detail_df)
    summary_dict = _build_summary_dict(summary_df)

    return {
        "main": summary_df,
        "summary_table": summary_df,
        "detail_table": detail_df,
        "summary": summary_dict,
        "charts": charts,
        "thresholds": thresholds,
    }
