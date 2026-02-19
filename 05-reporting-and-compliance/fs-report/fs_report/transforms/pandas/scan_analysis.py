"""
Pandas transform functions for Scan Analysis report.
"""

from datetime import date, datetime
from typing import Any

import pandas as pd

from fs_report.models import Config

# Scan types that complete instantly at creation time and never get a separate
# "completed" timestamp.  Used in several places for duration / date handling.
INSTANT_COMPLETE_TYPES: frozenset[str] = frozenset({"SOURCE_SCA", "SBOM_IMPORT"})


def scan_analysis_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config | None = None,
    additional_data: dict[str, Any] | None = None,
) -> pd.DataFrame | dict[str, Any]:
    """
    Transform scan data for the Scan Analysis report.

    Args:
        data: Raw scan data from API (list of dicts or DataFrame)
        config: Configuration object with start_date and end_date for filtering
        additional_data: Optional dict containing 'projects' list for new vs existing analysis

    Returns:
        Dictionary with DataFrames:
        - 'daily_metrics': Daily aggregated scan metrics
        - 'raw_data': All individual scans with metadata
        - 'failure_types': Failure distribution by scan type
    """
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return pd.DataFrame()
        df = data
    elif not data:
        return pd.DataFrame()
    else:
        df = pd.DataFrame(data)

    # Extract project data if available (for new vs existing analysis)
    projects_data = None
    if additional_data and "projects" in additional_data:
        projects_data = additional_data["projects"]

    # Filter by date range client-side (since 'created' is not filterable on scans endpoint)
    # Include scans that were either created OR completed within the date range
    if (
        config is not None
        and hasattr(config, "start_date")
        and hasattr(config, "end_date")
        and config.start_date
        and config.end_date
    ):
        # Parse dates from config (format: "YYYY-MM-DD")
        start_date_str = config.start_date  # e.g., "2025-11-01"
        end_date_str = config.end_date  # e.g., "2025-11-30"

        # Parse created and completed timestamps
        if "created" in df.columns and len(df) > 0:
            import logging

            logger = logging.getLogger(__name__)

            # Parse created timestamps (may include timezone like "2025-11-15T10:30:00Z")
            df["created_parsed"] = pd.to_datetime(
                df["created"], errors="coerce", utc=True
            )
            df["created_date"] = df["created_parsed"].dt.date.astype(str)

            # Parse completed timestamps if available
            if "completed" in df.columns:
                df["completed_parsed"] = pd.to_datetime(
                    df["completed"], errors="coerce", utc=True
                )
                df["completed_date"] = df["completed_parsed"].dt.date.astype(str)
            else:
                df["completed_date"] = None

            initial_count = len(df)

            # Filter to include scans that were either:
            # 1. Created within the date range, OR
            # 2. Completed within the date range (even if created before)
            created_in_range = (df["created_date"] >= start_date_str) & (
                df["created_date"] <= end_date_str
            )
            completed_in_range = (
                df["completed_date"].notna()
                & (df["completed_date"] >= start_date_str)
                & (df["completed_date"] <= end_date_str)
            )
            mask = created_in_range | completed_in_range

            # Log date range of ALL data before filtering (for debugging)
            if initial_count > 0:
                all_min_created = df["created_parsed"].min()
                all_max_created = df["created_parsed"].max()
                if df["completed_parsed"].notna().any():
                    all_min_completed = df["completed_parsed"].min()
                    all_max_completed = df["completed_parsed"].max()
                    logger.info(
                        f"All scans date range (before filtering): created {all_min_created} to {all_max_created}, completed {all_min_completed} to {all_max_completed} ({initial_count} total scans)"
                    )
                else:
                    logger.info(
                        f"All scans date range (before filtering): created {all_min_created} to {all_max_created} ({initial_count} total scans, no completions)"
                    )

            df = df[mask].copy()
            filtered_count = len(df)

            # Log date range of filtered data for verification
            if filtered_count > 0:
                min_created = df["created_parsed"].min()
                max_created = df["created_parsed"].max()
                if df["completed_parsed"].notna().any():
                    min_completed = df["completed_parsed"].min()
                    max_completed = df["completed_parsed"].max()
                    logger.info(
                        f"Date filtering: {initial_count} scans -> {filtered_count} scans (range: {start_date_str} to {end_date_str})"
                    )
                    logger.info(
                        f"Filtered scan date range: created {min_created} to {max_created}, completed {min_completed} to {max_completed}"
                    )
                else:
                    logger.info(
                        f"Date filtering: {initial_count} scans -> {filtered_count} scans (range: {start_date_str} to {end_date_str})"
                    )
                    logger.info(
                        f"Filtered scan date range: created {min_created} to {max_created}"
                    )
            else:
                logger.warning(
                    f"Date filtering: {initial_count} scans -> 0 scans (range: {start_date_str} to {end_date_str})"
                )

            # Drop temporary columns
            df = df.drop(
                columns=[
                    "created_parsed",
                    "created_date",
                    "completed_parsed",
                    "completed_date",
                ],
                errors="ignore",
            )

    if df.empty:
        return pd.DataFrame()

    # Build project creation date lookup if we have project data
    project_created_map = {}
    if projects_data:
        for p in projects_data:
            pid = str(p.get("id", ""))
            created = p.get("created")
            if pid and created:
                project_created_map[pid] = created

    # Flatten nested data structures
    df = flatten_scan_data(df, project_created_map)

    # Parse timestamps and calculate durations
    df = calculate_scan_durations(df)

    # Generate analysis metrics (pass config for date range context)
    result_df = generate_scan_metrics(df, config)

    return result_df


def flatten_scan_data(
    df: pd.DataFrame, project_created_map: dict[str, str] | None = None
) -> pd.DataFrame:
    """Flatten nested project and projectVersion data.

    Args:
        df: DataFrame with scan data
        project_created_map: Optional dict mapping project_id -> created timestamp
    """
    df_flattened = df.copy()

    # Flatten project data
    if "project" in df.columns:

        def extract_project_name(project: Any) -> str:
            if isinstance(project, dict):
                return str(project.get("name", "Unknown"))
            return str(project) if project else "Unknown"

        def extract_project_id(project: Any) -> str:
            if isinstance(project, dict):
                return str(project.get("id", "Unknown"))
            return str(project) if project else "Unknown"

        df_flattened["project_name"] = df["project"].apply(extract_project_name)
        df_flattened["project_id"] = df["project"].apply(extract_project_id)

        # Add project creation date if we have the mapping
        if project_created_map:

            def get_project_created(project: Any) -> str | None:
                if isinstance(project, dict):
                    pid = str(project.get("id", ""))
                else:
                    pid = str(project) if project else ""
                return project_created_map.get(pid)

            df_flattened["project_created"] = df["project"].apply(get_project_created)

    # Flatten projectVersion data
    # Note: The API returns 'version' field (not 'name') for the version label
    if "projectVersion" in df.columns:

        def extract_version_name(version: Any) -> str:
            if isinstance(version, dict):
                # API uses 'version' field for the version name/label
                return str(version.get("version", "Unknown"))
            return str(version) if version else "Unknown"

        df_flattened["version_name"] = df["projectVersion"].apply(extract_version_name)

    return df_flattened


def calculate_scan_durations(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate scan durations and parse timestamps."""
    df_with_durations = df.copy()

    # Parse timestamps
    df_with_durations["created_dt"] = pd.to_datetime(
        df_with_durations["created"], errors="coerce"
    )
    df_with_durations["completed_dt"] = pd.to_datetime(
        df_with_durations["completed"], errors="coerce"
    )

    # SOURCE_SCA and SBOM_IMPORT scans are completed when created and never get a completed date
    # Set completed_dt = created_dt for these scan types
    instant_complete_mask = df_with_durations["type"].isin(INSTANT_COMPLETE_TYPES)
    df_with_durations.loc[
        instant_complete_mask & df_with_durations["completed_dt"].isna(), "completed_dt"
    ] = df_with_durations.loc[
        instant_complete_mask & df_with_durations["completed_dt"].isna(), "created_dt"
    ]

    # Calculate duration in minutes for completed scans
    def calculate_duration(row: pd.Series) -> Any:
        if pd.isna(row["created_dt"]) or pd.isna(row["completed_dt"]):
            return None
        duration = (row["completed_dt"] - row["created_dt"]).total_seconds() / 60
        return int(round(duration)) if duration >= 0 else None

    df_with_durations["duration_minutes"] = df_with_durations.apply(
        calculate_duration, axis=1
    )

    # Explicitly set duration to 0 for instant-complete scan types (SOURCE_SCA, SBOM_IMPORT)
    # These are completed instantly when created, so duration should be 0
    df_with_durations.loc[instant_complete_mask, "duration_minutes"] = 0

    # Calculate current status timing for active scans
    now = datetime.utcnow()

    def calculate_current_status_time(row: pd.Series) -> Any:
        """Calculate how long a scan has been in its current status."""
        if pd.isna(row["created_dt"]):
            return None

        # For completed scans, we have the actual duration
        if row["status"] == "COMPLETED" and pd.notna(row["completed_dt"]):
            return None  # Use duration_minutes instead

        # For active scans (INITIAL, STARTED), calculate time since created
        current_time = (
            now - row["created_dt"].replace(tzinfo=None)
        ).total_seconds() / 60
        return int(round(current_time)) if current_time >= 0 else None

    df_with_durations["current_status_time_minutes"] = df_with_durations.apply(
        calculate_current_status_time, axis=1
    )

    # Add date for grouping
    df_with_durations["scan_date"] = df_with_durations["created_dt"].dt.date
    # Add completion date for grouping completed scans by when they completed
    # For SOURCE_SCA and SBOM_IMPORT scans, use created date as completion date
    df_with_durations["completion_date"] = df_with_durations["completed_dt"].dt.date
    # Fill in completion_date for instant-complete scan types that might still have NaN
    instant_complete_mask = df_with_durations["type"].isin(INSTANT_COMPLETE_TYPES)
    df_with_durations.loc[
        instant_complete_mask & df_with_durations["completion_date"].isna(),
        "completion_date",
    ] = df_with_durations.loc[
        instant_complete_mask & df_with_durations["completion_date"].isna(), "scan_date"
    ]

    return df_with_durations


def generate_scan_metrics(
    df: pd.DataFrame, config: Config | None = None
) -> pd.DataFrame | dict[str, Any]:
    """Generate comprehensive scan analysis metrics.

    Args:
        df: DataFrame with scan data (already flattened with project_created column if available)
        config: Configuration object with start_date for new vs existing project analysis
    """

    # Group by date for time series analysis
    daily_metrics = []

    # Verify we have valid dates
    if df["created_dt"].isna().all():
        # No valid dates, return empty DataFrame
        return pd.DataFrame()

    # Determine report date range for filtering and new vs existing analysis
    report_start_date = None
    report_end_date = None
    if config and hasattr(config, "start_date") and config.start_date:
        report_start_date = pd.to_datetime(config.start_date).date()
    if config and hasattr(config, "end_date") and config.end_date:
        report_end_date = pd.to_datetime(config.end_date).date()

    # Generate daily metrics — iterate only over dates that have data
    # instead of every calendar day in the range.
    created_by_date = dict(tuple(df.groupby("scan_date")))
    if "completion_date" in df.columns:
        completed_by_date = dict(tuple(df.groupby("completion_date")))
    else:
        completed_by_date = {}
    active_dates = sorted(set(created_by_date) | set(completed_by_date), key=str)

    for current_date in active_dates:
        day_data_created = created_by_date.get(current_date, pd.DataFrame())
        day_data_completed = completed_by_date.get(current_date, pd.DataFrame())

        day_data = (
            day_data_created.copy()
            if len(day_data_created) > 0
            else day_data_completed.head(0).copy()
        )
        metrics = calculate_daily_metrics(
            day_data,
            date.fromisoformat(str(current_date)),
            day_data_completed,
            all_scans=df,
            report_start_date=report_start_date,
        )
        daily_metrics.append(metrics)

    # Convert to DataFrame
    if not daily_metrics:
        return pd.DataFrame()

    result_df = pd.DataFrame(daily_metrics)

    # Add queue analysis (current state)
    analyze_current_queue(df)

    # Add overall summary row
    summary_row = calculate_summary_metrics(df, report_start_date, report_end_date)
    summary_row["period"] = "Overall Summary"
    summary_row["date"] = "Total"

    # Combine daily metrics with summary
    result_df = pd.concat([result_df, pd.DataFrame([summary_row])], ignore_index=True)

    # Convert date column to strings for JSON serialization
    result_df["date"] = result_df["date"].astype(str)

    # Calculate failure type distribution (ERROR scans by type) - filter to period
    # Use scans that STARTED in the period for failure counts
    report_start = None
    report_end = None
    if config and hasattr(config, "start_date") and config.start_date:
        report_start = pd.to_datetime(config.start_date).date()
    if config and hasattr(config, "end_date") and config.end_date:
        report_end = pd.to_datetime(config.end_date).date()

    if report_start and report_end and "scan_date" in df.columns:
        scans_in_period = df[
            (df["scan_date"] >= report_start) & (df["scan_date"] <= report_end)
        ]
    else:
        scans_in_period = df

    error_scans = scans_in_period[scans_in_period["status"] == "ERROR"]
    external_scan_types_for_fail = ["SOURCE_SCA", "JAR", "SBOM_IMPORT"]
    # For non-external scans, INITIAL is a failed attempt
    non_external_initial = scans_in_period[
        (scans_in_period["status"] == "INITIAL")
        & (~scans_in_period["type"].isin(external_scan_types_for_fail))
    ]
    # For external scans (SOURCE_SCA, JAR, SBOM_IMPORT), any non-COMPLETED status is failed
    # since these should complete almost immediately
    external_non_completed = scans_in_period[
        (scans_in_period["type"].isin(external_scan_types_for_fail))
        & (
            ~scans_in_period["status"].isin(["COMPLETED", "ERROR"])
        )  # ERROR already in error_scans
    ]
    failed_scans = pd.concat(
        [error_scans, non_external_initial, external_non_completed]
    )

    failure_type_counts = (
        failed_scans["type"].value_counts().to_dict() if len(failed_scans) > 0 else {}
    )
    failure_types_df = (
        pd.DataFrame(
            [
                {"type": scan_type, "count": count}
                for scan_type, count in failure_type_counts.items()
            ]
        )
        if failure_type_counts
        else pd.DataFrame(columns=["type", "count"])
    )

    # Prepare raw scan data for the detailed table
    raw_data_df = df.copy()

    # Add useful columns for the raw data table
    raw_data_df["scan_date"] = raw_data_df["created"].astype(str)

    # Handle completion date properly (avoid "nan" strings)
    # For SOURCE_SCA and SBOM_IMPORT scans, use created date as completion date

    def format_completion_date(row: pd.Series) -> str:
        # For instant-complete scan types, use created date if completed is missing
        if row["type"] in INSTANT_COMPLETE_TYPES and (
            pd.isna(row.get("completed")) or str(row.get("completed")) == "NaT"
        ):
            return str(row["created"]) if pd.notna(row.get("created")) else "-"
        # Otherwise use completed date
        completed = row.get("completed")
        if pd.notna(completed) and str(completed) != "NaT":
            return str(completed)
        return "-"

    raw_data_df["completion_date"] = raw_data_df.apply(format_completion_date, axis=1)

    # Ensure duration is properly calculated and filled
    raw_data_df["duration_minutes"] = raw_data_df["duration_minutes"].fillna(0)

    # Clean up error messages (replace NaN with "-")
    if "errorMessage" in raw_data_df.columns:
        raw_data_df["errorMessage"] = raw_data_df["errorMessage"].fillna("-")
        raw_data_df["errorMessage"] = raw_data_df["errorMessage"].replace("nan", "-")

    # Select and order columns for the raw data export
    raw_data_columns = [
        "id",
        "scan_date",
        "completion_date",
        "status",
        "type",
        "folder_name",
        "project_name",
        "version_name",
        "duration_minutes",
        "current_status_time_minutes",
        "errorMessage",
    ]

    # Only include columns that exist
    available_columns = [col for col in raw_data_columns if col in raw_data_df.columns]
    raw_data_df = raw_data_df[available_columns]

    # Convert failure_types to list of dicts for template rendering
    failure_types_list = (
        failure_types_df.to_dict(orient="records") if len(failure_types_df) > 0 else []
    )

    return {
        "daily_metrics": result_df,
        "raw_data": raw_data_df,
        "failure_types": failure_types_list,
    }


def calculate_daily_metrics(
    day_data: pd.DataFrame,
    date: date,
    day_data_completed: pd.DataFrame | None = None,
    all_scans: pd.DataFrame | None = None,
    report_start_date: date | None = None,
) -> dict[str, Any]:
    """Calculate metrics for a single day.

    Args:
        day_data: Scans that were created on this date (for started counts, active scans, etc.)
        date: The date being analyzed
        day_data_completed: Scans that were completed on this date (for completion counts)
        all_scans: All scans in the dataset (for finding failed scans that may have been created on different dates)
        report_start_date: Report start date for determining new vs existing projects
    """
    # Use all_scans if provided, otherwise use day_data as fallback
    if all_scans is None:
        all_scans = day_data

    # Use completed scans for completion metrics if provided, otherwise use created scans
    if day_data_completed is not None and len(day_data_completed) > 0:
        # For completion counts, use scans that completed on this date
        completed_day_data = day_data_completed
    else:
        # Fallback to scans created on this date
        completed_day_data = day_data

    initial_scans = day_data[day_data["status"] == "INITIAL"]
    started_scans = day_data[day_data["status"] == "STARTED"]

    # Separate external/third-party scans - they're completed externally and uploaded
    external_scan_types = ["SOURCE_SCA", "JAR", "SBOM_IMPORT"]
    # Only count COMPLETED external scans as completed; STARTED/INITIAL external scans are failed
    external_scans = completed_day_data[
        (completed_day_data["type"].isin(external_scan_types))
        & (completed_day_data["status"] == "COMPLETED")
    ]
    other_scans = completed_day_data[
        ~completed_day_data["type"].isin(external_scan_types)
    ]

    # External scans that are not COMPLETED are failed (they should complete immediately)
    external_failed = day_data[
        (day_data["type"].isin(external_scan_types))
        & (~day_data["status"].isin(["COMPLETED", "ERROR"]))  # ERROR counted separately
    ]

    # For non-external scans, INITIAL scans are failed attempts, only STARTED scans are actually waiting
    # Use day_data (created scans) for active scan counts
    other_scans_for_active = day_data[~day_data["type"].isin(external_scan_types)]
    other_initial = other_scans_for_active[
        other_scans_for_active["status"] == "INITIAL"
    ]
    other_started = other_scans_for_active[
        other_scans_for_active["status"] == "STARTED"
    ]

    # All INITIAL scans are considered failed attempts (regardless of age)
    stuck_scans = len(other_initial)

    # Only STARTED scans are actually waiting/processing
    recently_queued = len(other_started)

    # Count completed scans: external scans (all) + other scans with completion dates
    # Use completed_day_data to count scans that completed on this date
    other_completed = other_scans[
        (other_scans["status"] == "COMPLETED")
        & (other_scans["completed"].notna())
        & (other_scans["completed"] != "-")
    ]

    # Count failed scans: ERROR status scans that were created on this date
    # Check both day_data and all_scans to ensure we catch all ERROR scans
    # Use case-insensitive comparison in case status values vary
    if "status" in day_data.columns:
        error_scans_from_day_data = day_data[day_data["status"].str.upper() == "ERROR"]
    else:
        error_scans_from_day_data = pd.DataFrame()

    # Also check all_scans for ERROR scans created on this date (in case day_data is filtered)
    error_scans_from_all = pd.DataFrame()
    if (
        all_scans is not None
        and len(all_scans) > 0
        and "scan_date" in all_scans.columns
        and "status" in all_scans.columns
    ):
        error_scans_from_all = all_scans[
            (all_scans["scan_date"] == date)
            & (all_scans["status"].str.upper() == "ERROR")
        ]

    # Combine both sources and remove duplicates
    if len(error_scans_from_day_data) > 0 and len(error_scans_from_all) > 0:
        # Both have data, combine and deduplicate
        if (
            "id" in error_scans_from_day_data.columns
            and "id" in error_scans_from_all.columns
        ):
            error_scans_created_today = pd.concat(
                [error_scans_from_day_data, error_scans_from_all]
            ).drop_duplicates(subset=["id"])
        else:
            error_scans_created_today = pd.concat(
                [error_scans_from_day_data, error_scans_from_all]
            ).drop_duplicates()
    elif len(error_scans_from_day_data) > 0:
        error_scans_created_today = error_scans_from_day_data
    elif len(error_scans_from_all) > 0:
        error_scans_created_today = error_scans_from_all
    else:
        error_scans_created_today = pd.DataFrame()

    failed_scans = (
        len(error_scans_created_today) + len(other_initial) + len(external_failed)
    )

    # Count unique artifacts for this day
    unique_projects = (
        day_data["project_id"].nunique() if "project_id" in day_data.columns else 0
    )
    if "projectVersion" in day_data.columns:
        version_ids = (
            day_data["projectVersion"]
            .dropna()
            .apply(lambda x: x.get("id") if isinstance(x, dict) else x)
        )
        unique_versions = version_ids.nunique()
    else:
        unique_versions = 0

    # Calculate new vs existing projects based on project_created date
    new_projects = 0
    existing_projects = 0
    if (
        "project_id" in day_data.columns
        and "project_created" in day_data.columns
        and report_start_date
    ):
        # Get unique projects for this day with their creation dates
        project_info = day_data[["project_id", "project_created"]].drop_duplicates(
            subset=["project_id"]
        )
        for _, row in project_info.iterrows():
            project_created = row.get("project_created")
            if pd.notna(project_created):
                try:
                    created_date = pd.to_datetime(project_created).date()
                    if created_date >= report_start_date:
                        new_projects += 1
                    else:
                        existing_projects += 1
                except Exception:
                    existing_projects += 1  # Assume existing if we can't parse date
            else:
                existing_projects += 1  # No date means we don't know, assume existing

    metrics: dict[str, Any] = {
        "period": str(date),
        "date": str(date),
        "total_scans_started": len(day_data),
        "unique_projects": unique_projects,
        "new_projects": new_projects,
        "existing_projects": existing_projects,
        "unique_versions": unique_versions,
        "server_completed_scans": len(other_completed),
        "external_completed_scans": len(external_scans),
        "total_completed_scans": len(external_scans) + len(other_completed),
        "failed_scans": failed_scans,
        "stuck_scans": stuck_scans,
        "recently_queued": recently_queued,
        "still_active_scans": len(other_started),
    }

    # Calculate success rate (only for finished scans)
    total_finished = metrics["total_completed_scans"] + metrics["failed_scans"]
    if total_finished > 0:
        metrics["success_rate"] = (
            metrics["total_completed_scans"] / total_finished
        ) * 100
    else:
        metrics["success_rate"] = 0

    # Calculate completion rate (completed vs total started)
    if metrics["total_scans_started"] > 0:
        metrics["completion_rate"] = (
            metrics["total_completed_scans"] / metrics["total_scans_started"]
        ) * 100
    else:
        metrics["completion_rate"] = 0

    # Duration analysis for completed scans (exclude external scans)
    # Use completed_day_data to get scans that completed on this date
    external_scan_types = ["SOURCE_SCA", "JAR", "SBOM_IMPORT"]
    completed_scans = completed_day_data[
        (completed_day_data["status"] == "COMPLETED")
        & (completed_day_data["duration_minutes"].notna())
        & (~completed_day_data["type"].isin(external_scan_types))
    ]

    if len(completed_scans) > 0:
        metrics["avg_duration_minutes"] = int(
            round(completed_scans["duration_minutes"].mean())
        )
        metrics["median_duration_minutes"] = int(
            round(completed_scans["duration_minutes"].median())
        )
        metrics["min_duration_minutes"] = int(completed_scans["duration_minutes"].min())
        metrics["max_duration_minutes"] = int(completed_scans["duration_minutes"].max())
    else:
        metrics["avg_duration_minutes"] = 0
        metrics["median_duration_minutes"] = 0
        metrics["min_duration_minutes"] = 0
        metrics["max_duration_minutes"] = 0

    # Current status analytics for active scans (exclude external scans)
    active_scans = day_data[
        (day_data["status"].isin(["INITIAL", "STARTED"]))
        & (~day_data["type"].isin(external_scan_types))
    ]
    if len(active_scans) > 0 and "current_status_time_minutes" in active_scans.columns:
        valid_times = active_scans["current_status_time_minutes"].dropna()
        if len(valid_times) > 0:
            metrics["avg_active_time_minutes"] = int(round(valid_times.mean()))
            metrics["max_active_time_minutes"] = int(valid_times.max())
        else:
            metrics["avg_active_time_minutes"] = 0
            metrics["max_active_time_minutes"] = 0
    else:
        metrics["avg_active_time_minutes"] = 0
        metrics["max_active_time_minutes"] = 0

    # Separate analytics for INITIAL vs STARTED scans
    initial_scans = day_data[day_data["status"] == "INITIAL"]
    started_scans = day_data[day_data["status"] == "STARTED"]

    if (
        len(initial_scans) > 0
        and "current_status_time_minutes" in initial_scans.columns
    ):
        valid_initial_times = initial_scans["current_status_time_minutes"].dropna()
        if len(valid_initial_times) > 0:
            metrics["avg_initial_time_minutes"] = int(round(valid_initial_times.mean()))
            metrics["max_initial_time_minutes"] = int(valid_initial_times.max())
        else:
            metrics["avg_initial_time_minutes"] = 0
            metrics["max_initial_time_minutes"] = 0
    else:
        metrics["avg_initial_time_minutes"] = 0
        metrics["max_initial_time_minutes"] = 0

    if (
        len(started_scans) > 0
        and "current_status_time_minutes" in started_scans.columns
    ):
        valid_started_times = started_scans["current_status_time_minutes"].dropna()
        if len(valid_started_times) > 0:
            metrics["avg_started_time_minutes"] = int(round(valid_started_times.mean()))
            metrics["max_started_time_minutes"] = int(valid_started_times.max())
        else:
            metrics["avg_started_time_minutes"] = 0
            metrics["max_started_time_minutes"] = 0
    else:
        metrics["avg_started_time_minutes"] = 0
        metrics["max_started_time_minutes"] = 0

    # Scan type breakdown
    type_counts = day_data["type"].value_counts().to_dict()
    metrics["sca_scans"] = type_counts.get("SCA", 0)
    metrics["sast_scans"] = type_counts.get("SAST", 0)
    metrics["config_scans"] = type_counts.get("CONFIG", 0)
    metrics["source_sca_scans"] = type_counts.get("SOURCE_SCA", 0)
    metrics["vulnerability_analysis_scans"] = type_counts.get(
        "VULNERABILITY_ANALYSIS", 0
    )
    metrics["sbom_import_scans"] = type_counts.get("SBOM_IMPORT", 0)

    # Failure counts by scan type for this day (for time series chart)
    failed_day_data = day_data[day_data["status"].isin(["ERROR", "INITIAL"])]
    # Exclude instant-complete types from INITIAL (not real failures)
    failed_day_data = failed_day_data[
        ~(
            (failed_day_data["status"] == "INITIAL")
            & (failed_day_data["type"].isin(["SOURCE_SCA", "JAR", "SBOM_IMPORT"]))
        )
    ]
    failure_type_counts = failed_day_data["type"].value_counts().to_dict()
    metrics["sca_failures"] = failure_type_counts.get("SCA", 0)
    metrics["sast_failures"] = failure_type_counts.get("SAST", 0)
    metrics["config_failures"] = failure_type_counts.get("CONFIG", 0)
    metrics["vulnerability_analysis_failures"] = failure_type_counts.get(
        "VULNERABILITY_ANALYSIS", 0
    )

    # Overall failure rate for context
    total_started = metrics["total_scans_started"]
    total_failed = metrics["failed_scans"]
    metrics["failure_rate"] = (
        (total_failed / total_started * 100) if total_started > 0 else 0
    )

    return metrics


def calculate_summary_metrics(
    df: pd.DataFrame,
    report_start_date: date | None = None,
    report_end_date: date | None = None,
) -> dict[str, Any]:
    """Calculate overall summary metrics.

    Args:
        df: DataFrame with scan data
        report_start_date: Report start date for filtering and new vs existing projects
        report_end_date: Report end date for filtering
    """
    # Filter to scans that STARTED in the period (for started count)
    # and scans that COMPLETED in the period (for completed count)
    if report_start_date and report_end_date and "scan_date" in df.columns:
        scans_started_in_period = df[
            (df["scan_date"] >= report_start_date)
            & (df["scan_date"] <= report_end_date)
        ]
    else:
        scans_started_in_period = df

    if report_start_date and report_end_date and "completion_date" in df.columns:
        scans_completed_in_period = df[
            (df["completion_date"].notna())
            & (df["completion_date"] >= report_start_date)
            & (df["completion_date"] <= report_end_date)
        ]
    else:
        scans_completed_in_period = df[df["completion_date"].notna()]

    initial_scans = df[df["status"] == "INITIAL"]
    started_scans = df[df["status"] == "STARTED"]

    # Separate external/third-party scans - they're completed externally and uploaded
    external_scan_types = ["SOURCE_SCA", "JAR", "SBOM_IMPORT"]
    # Only count COMPLETED external scans as completed; STARTED/INITIAL external scans are failed
    external_scans_in_period = scans_completed_in_period[
        (scans_completed_in_period["type"].isin(external_scan_types))
        & (scans_completed_in_period["status"] == "COMPLETED")
    ]
    other_scans_started_in_period = scans_started_in_period[
        ~scans_started_in_period["type"].isin(external_scan_types)
    ]
    other_scans_completed_in_period = scans_completed_in_period[
        ~scans_completed_in_period["type"].isin(external_scan_types)
    ]

    # External scans started in period that aren't COMPLETED are failed
    external_failed_in_period = scans_started_in_period[
        (scans_started_in_period["type"].isin(external_scan_types))
        & (
            ~scans_started_in_period["status"].isin(["COMPLETED", "ERROR"])
        )  # ERROR counted separately
    ]

    # For non-external scans, INITIAL scans are failed attempts, only STARTED scans are actually waiting
    # Use scans started in period for these counts
    other_initial = other_scans_started_in_period[
        other_scans_started_in_period["status"] == "INITIAL"
    ]
    other_started = other_scans_started_in_period[
        other_scans_started_in_period["status"] == "STARTED"
    ]

    # All INITIAL scans are considered failed attempts (regardless of age)
    stuck_scans = len(other_initial)

    # Only STARTED scans are actually waiting/processing
    recently_queued = len(other_started)

    # Count completed scans IN THE PERIOD: external scans + other scans with completion dates
    other_completed = other_scans_completed_in_period[
        (other_scans_completed_in_period["status"] == "COMPLETED")
        & (other_scans_completed_in_period["completed"].notna())
        & (other_scans_completed_in_period["completed"] != "-")
    ]

    # Count unique artifacts from scans STARTED in the period
    unique_projects = (
        scans_started_in_period["project_id"].nunique()
        if "project_id" in scans_started_in_period.columns
        else 0
    )
    if "projectVersion" in scans_started_in_period.columns:
        version_ids = (
            scans_started_in_period["projectVersion"]
            .dropna()
            .apply(lambda x: x.get("id") if isinstance(x, dict) else x)
        )
        unique_versions = version_ids.nunique()
    else:
        unique_versions = 0

    # Calculate new vs existing projects from scans STARTED in the period
    new_projects = 0
    existing_projects = 0
    if (
        "project_id" in scans_started_in_period.columns
        and "project_created" in scans_started_in_period.columns
        and report_start_date
    ):
        project_info = scans_started_in_period[
            ["project_id", "project_created"]
        ].drop_duplicates(subset=["project_id"])
        for _, row in project_info.iterrows():
            project_created = row.get("project_created")
            if pd.notna(project_created):
                try:
                    created_date = pd.to_datetime(project_created).date()
                    if created_date >= report_start_date:
                        new_projects += 1
                    else:
                        existing_projects += 1
                except Exception:
                    existing_projects += 1
            else:
                existing_projects += 1

    summary: dict[str, Any] = {
        "total_scans_started": len(scans_started_in_period),  # Scans STARTED in period
        "unique_projects": unique_projects,
        "new_projects": new_projects,
        "existing_projects": existing_projects,
        "unique_versions": unique_versions,
        "server_completed_scans": len(other_completed),
        "external_completed_scans": len(external_scans_in_period),
        "total_completed_scans": len(external_scans_in_period)
        + len(other_completed),  # Scans COMPLETED in period
        "failed_scans": len(
            scans_started_in_period[scans_started_in_period["status"] == "ERROR"]
        )
        + len(other_initial)
        + len(
            external_failed_in_period
        ),  # ERROR + non-external INITIAL + external non-COMPLETED
        "stuck_scans": stuck_scans,
        "recently_queued": recently_queued,
        "still_active_scans": len(other_started),
    }

    # Calculate overall success rate (only for finished scans)
    total_finished = summary["total_completed_scans"] + summary["failed_scans"]
    if total_finished > 0:
        summary["success_rate"] = (
            summary["total_completed_scans"] / total_finished
        ) * 100
    else:
        summary["success_rate"] = 0

    # Calculate overall completion rate (completed vs total started)
    if summary["total_scans_started"] > 0:
        summary["completion_rate"] = (
            summary["total_completed_scans"] / summary["total_scans_started"]
        ) * 100
    else:
        summary["completion_rate"] = 0

    # Overall duration analysis (exclude external scans) - use scans COMPLETED in period
    external_scan_types = ["SOURCE_SCA", "JAR", "SBOM_IMPORT"]
    completed_scans = scans_completed_in_period[
        (scans_completed_in_period["status"] == "COMPLETED")
        & (scans_completed_in_period["duration_minutes"].notna())
        & (~scans_completed_in_period["type"].isin(external_scan_types))
    ]

    if len(completed_scans) > 0:
        summary["avg_duration_minutes"] = int(
            round(completed_scans["duration_minutes"].mean())
        )
        summary["median_duration_minutes"] = int(
            round(completed_scans["duration_minutes"].median())
        )
        summary["min_duration_minutes"] = int(completed_scans["duration_minutes"].min())
        summary["max_duration_minutes"] = int(completed_scans["duration_minutes"].max())
    else:
        summary["avg_duration_minutes"] = 0
        summary["median_duration_minutes"] = 0
        summary["min_duration_minutes"] = 0
        summary["max_duration_minutes"] = 0

    # Overall current status analytics (exclude external scans)
    active_scans = df[
        (df["status"].isin(["INITIAL", "STARTED"]))
        & (~df["type"].isin(external_scan_types))
    ]
    if len(active_scans) > 0 and "current_status_time_minutes" in active_scans.columns:
        valid_times = active_scans["current_status_time_minutes"].dropna()
        if len(valid_times) > 0:
            summary["avg_active_time_minutes"] = int(round(valid_times.mean()))
            summary["max_active_time_minutes"] = int(valid_times.max())
        else:
            summary["avg_active_time_minutes"] = 0
            summary["max_active_time_minutes"] = 0
    else:
        summary["avg_active_time_minutes"] = 0
        summary["max_active_time_minutes"] = 0

    # Separate analytics for INITIAL vs STARTED scans
    initial_scans = df[df["status"] == "INITIAL"]
    started_scans = df[df["status"] == "STARTED"]

    if (
        len(initial_scans) > 0
        and "current_status_time_minutes" in initial_scans.columns
    ):
        valid_initial_times = initial_scans["current_status_time_minutes"].dropna()
        if len(valid_initial_times) > 0:
            summary["avg_initial_time_minutes"] = int(round(valid_initial_times.mean()))
            summary["max_initial_time_minutes"] = int(valid_initial_times.max())
        else:
            summary["avg_initial_time_minutes"] = 0
            summary["max_initial_time_minutes"] = 0
    else:
        summary["avg_initial_time_minutes"] = 0
        summary["max_initial_time_minutes"] = 0

    if (
        len(started_scans) > 0
        and "current_status_time_minutes" in started_scans.columns
    ):
        valid_started_times = started_scans["current_status_time_minutes"].dropna()
        if len(valid_started_times) > 0:
            summary["avg_started_time_minutes"] = int(round(valid_started_times.mean()))
            summary["max_started_time_minutes"] = int(valid_started_times.max())
        else:
            summary["avg_started_time_minutes"] = 0
            summary["max_started_time_minutes"] = 0
    else:
        summary["avg_started_time_minutes"] = 0
        summary["max_started_time_minutes"] = 0

    # Overall scan type breakdown - use scans STARTED in period
    type_counts = scans_started_in_period["type"].value_counts().to_dict()
    summary["sca_scans"] = type_counts.get("SCA", 0)
    summary["sast_scans"] = type_counts.get("SAST", 0)
    summary["config_scans"] = type_counts.get("CONFIG", 0)
    summary["source_sca_scans"] = type_counts.get("SOURCE_SCA", 0)
    summary["vulnerability_analysis_scans"] = type_counts.get(
        "VULNERABILITY_ANALYSIS", 0
    )
    summary["sbom_import_scans"] = type_counts.get("SBOM_IMPORT", 0)

    return summary


def analyze_current_queue(df: pd.DataFrame) -> dict[str, Any]:
    """Analyze current active scans with detailed INITIAL vs STARTED breakdown."""
    initial_scans = df[df["status"] == "INITIAL"]
    started_scans = df[df["status"] == "STARTED"]

    queue_analysis: dict[str, Any] = {
        "current_active_scans": len(initial_scans) + len(started_scans),
        "initial_scans": len(initial_scans),
        "started_scans": len(started_scans),
    }

    # Analytics for INITIAL scans (waiting in queue)
    if (
        len(initial_scans) > 0
        and "current_status_time_minutes" in initial_scans.columns
    ):
        valid_initial_times = initial_scans["current_status_time_minutes"].dropna()
        if len(valid_initial_times) > 0:
            queue_analysis["avg_initial_time_minutes"] = int(
                round(valid_initial_times.mean())
            )
            queue_analysis["max_initial_time_minutes"] = int(valid_initial_times.max())
            queue_analysis["oldest_initial_scan_id"] = (
                initial_scans.loc[
                    initial_scans["current_status_time_minutes"].idxmax(), "id"
                ]
                if not valid_initial_times.empty
                else None
            )
        else:
            queue_analysis["avg_initial_time_minutes"] = 0
            queue_analysis["max_initial_time_minutes"] = 0
            queue_analysis["oldest_initial_scan_id"] = None
    else:
        queue_analysis["avg_initial_time_minutes"] = 0
        queue_analysis["max_initial_time_minutes"] = 0
        queue_analysis["oldest_initial_scan_id"] = None

    # Analytics for STARTED scans (actively processing)
    if (
        len(started_scans) > 0
        and "current_status_time_minutes" in started_scans.columns
    ):
        valid_started_times = started_scans["current_status_time_minutes"].dropna()
        if len(valid_started_times) > 0:
            queue_analysis["avg_started_time_minutes"] = int(
                round(valid_started_times.mean())
            )
            queue_analysis["max_started_time_minutes"] = int(valid_started_times.max())
            queue_analysis["longest_started_scan_id"] = (
                started_scans.loc[
                    started_scans["current_status_time_minutes"].idxmax(), "id"
                ]
                if not valid_started_times.empty
                else None
            )
        else:
            queue_analysis["avg_started_time_minutes"] = 0
            queue_analysis["max_started_time_minutes"] = 0
            queue_analysis["longest_started_scan_id"] = None
    else:
        queue_analysis["avg_started_time_minutes"] = 0
        queue_analysis["max_started_time_minutes"] = 0
        queue_analysis["longest_started_scan_id"] = None

    return queue_analysis
