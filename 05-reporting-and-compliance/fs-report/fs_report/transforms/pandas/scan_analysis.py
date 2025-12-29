"""
Pandas transform functions for Scan Analysis report.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from fs_report.models import Config


def scan_analysis_transform(data: List[Dict[str, Any]], config: Optional[Config] = None) -> Dict[str, pd.DataFrame]:
    """
    Transform scan data for the Scan Analysis report.
    
    Args:
        data: Raw scan data from API
        config: Configuration object with start_date and end_date for filtering
    
    Returns:
        Dictionary with two DataFrames:
        - 'daily_metrics': Daily aggregated scan metrics
        - 'raw_data': All individual scans with metadata
    """
    if not data:
        return pd.DataFrame()
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Filter by date range client-side (since 'created' is not filterable on scans endpoint)
    # Include scans that were either created OR completed within the date range
    if config is not None and hasattr(config, 'start_date') and hasattr(config, 'end_date') and config.start_date and config.end_date:
        # Parse dates from config (format: "YYYY-MM-DD")
        start_date_str = config.start_date  # e.g., "2025-11-01"
        end_date_str = config.end_date     # e.g., "2025-11-30"
        
        # Parse created and completed timestamps
        if 'created' in df.columns and len(df) > 0:
            import logging
            logger = logging.getLogger(__name__)
            
            # Parse created timestamps (may include timezone like "2025-11-15T10:30:00Z")
            df['created_parsed'] = pd.to_datetime(df['created'], errors='coerce', utc=True)
            df['created_date'] = df['created_parsed'].dt.date.astype(str)
            
            # Parse completed timestamps if available
            if 'completed' in df.columns:
                df['completed_parsed'] = pd.to_datetime(df['completed'], errors='coerce', utc=True)
                df['completed_date'] = df['completed_parsed'].dt.date.astype(str)
            else:
                df['completed_date'] = None
            
            initial_count = len(df)
            
            # Filter to include scans that were either:
            # 1. Created within the date range, OR
            # 2. Completed within the date range (even if created before)
            created_in_range = (df['created_date'] >= start_date_str) & (df['created_date'] <= end_date_str)
            completed_in_range = df['completed_date'].notna() & (df['completed_date'] >= start_date_str) & (df['completed_date'] <= end_date_str)
            mask = created_in_range | completed_in_range
            
            # Log date range of ALL data before filtering (for debugging)
            if initial_count > 0:
                all_min_created = df['created_parsed'].min()
                all_max_created = df['created_parsed'].max()
                if df['completed_parsed'].notna().any():
                    all_min_completed = df['completed_parsed'].min()
                    all_max_completed = df['completed_parsed'].max()
                    logger.info(f"All scans date range (before filtering): created {all_min_created} to {all_max_created}, completed {all_min_completed} to {all_max_completed} ({initial_count} total scans)")
                else:
                    logger.info(f"All scans date range (before filtering): created {all_min_created} to {all_max_created} ({initial_count} total scans, no completions)")
            
            df = df[mask].copy()
            filtered_count = len(df)
            
            # Log date range of filtered data for verification
            if filtered_count > 0:
                min_created = df['created_parsed'].min()
                max_created = df['created_parsed'].max()
                if df['completed_parsed'].notna().any():
                    min_completed = df['completed_parsed'].min()
                    max_completed = df['completed_parsed'].max()
                    logger.info(f"Date filtering: {initial_count} scans -> {filtered_count} scans (range: {start_date_str} to {end_date_str})")
                    logger.info(f"Filtered scan date range: created {min_created} to {max_created}, completed {min_completed} to {max_completed}")
                else:
                    logger.info(f"Date filtering: {initial_count} scans -> {filtered_count} scans (range: {start_date_str} to {end_date_str})")
                    logger.info(f"Filtered scan date range: created {min_created} to {max_created}")
            else:
                logger.warning(f"Date filtering: {initial_count} scans -> 0 scans (range: {start_date_str} to {end_date_str})")
            
            # Drop temporary columns
            df = df.drop(columns=['created_parsed', 'created_date', 'completed_parsed', 'completed_date'], errors='ignore')
    
    if df.empty:
        return pd.DataFrame()
    
    # Flatten nested data structures
    df = flatten_scan_data(df)
    
    # Parse timestamps and calculate durations
    df = calculate_scan_durations(df)
    
    # Generate analysis metrics
    result_df = generate_scan_metrics(df)
    
    return result_df


def flatten_scan_data(df: pd.DataFrame) -> pd.DataFrame:
    """Flatten nested project and projectVersion data."""
    df_flattened = df.copy()
    
    # Flatten project data
    if 'project' in df.columns:
        def extract_project_name(project):
            if isinstance(project, dict):
                return project.get('name', 'Unknown')
            return str(project) if project else 'Unknown'
        
        def extract_project_id(project):
            if isinstance(project, dict):
                return project.get('id', 'Unknown')
            return str(project) if project else 'Unknown'
        
        df_flattened['project_name'] = df['project'].apply(extract_project_name)
        df_flattened['project_id'] = df['project'].apply(extract_project_id)
    
    # Flatten projectVersion data
    if 'projectVersion' in df.columns:
        def extract_version_name(version):
            if isinstance(version, dict):
                return version.get('name', 'Unknown')
            return str(version) if version else 'Unknown'
        
        df_flattened['version_name'] = df['projectVersion'].apply(extract_version_name)
    
    return df_flattened


def calculate_scan_durations(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate scan durations and parse timestamps."""
    df_with_durations = df.copy()
    
    # Parse timestamps
    df_with_durations['created_dt'] = pd.to_datetime(df_with_durations['created'], errors='coerce')
    df_with_durations['completed_dt'] = pd.to_datetime(df_with_durations['completed'], errors='coerce')
    
    # SOURCE_SCA and SBOM_IMPORT scans are completed when created and never get a completed date
    # Set completed_dt = created_dt for these scan types
    instant_complete_types = ['SOURCE_SCA', 'SBOM_IMPORT']
    instant_complete_mask = df_with_durations['type'].isin(instant_complete_types)
    df_with_durations.loc[instant_complete_mask & df_with_durations['completed_dt'].isna(), 'completed_dt'] = \
        df_with_durations.loc[instant_complete_mask & df_with_durations['completed_dt'].isna(), 'created_dt']
    
    # Calculate duration in minutes for completed scans
    def calculate_duration(row):
        if pd.isna(row['created_dt']) or pd.isna(row['completed_dt']):
            return None
        duration = (row['completed_dt'] - row['created_dt']).total_seconds() / 60
        return int(round(duration)) if duration >= 0 else None
    
    df_with_durations['duration_minutes'] = df_with_durations.apply(calculate_duration, axis=1)
    
    # Explicitly set duration to 0 for instant-complete scan types (SOURCE_SCA, SBOM_IMPORT)
    # These are completed instantly when created, so duration should be 0
    df_with_durations.loc[instant_complete_mask, 'duration_minutes'] = 0
    
    # Calculate current status timing for active scans
    now = datetime.utcnow()
    def calculate_current_status_time(row):
        """Calculate how long a scan has been in its current status."""
        if pd.isna(row['created_dt']):
            return None
        
        # For completed scans, we have the actual duration
        if row['status'] == 'COMPLETED' and pd.notna(row['completed_dt']):
            return None  # Use duration_minutes instead
        
        # For active scans (INITIAL, STARTED), calculate time since created
        current_time = (now - row['created_dt'].replace(tzinfo=None)).total_seconds() / 60
        return int(round(current_time)) if current_time >= 0 else None
    
    df_with_durations['current_status_time_minutes'] = df_with_durations.apply(calculate_current_status_time, axis=1)
    
    # Add date for grouping
    df_with_durations['scan_date'] = df_with_durations['created_dt'].dt.date
    # Add completion date for grouping completed scans by when they completed
    # For SOURCE_SCA and SBOM_IMPORT scans, use created date as completion date
    df_with_durations['completion_date'] = df_with_durations['completed_dt'].dt.date
    # Fill in completion_date for instant-complete scan types that might still have NaN
    instant_complete_types = ['SOURCE_SCA', 'SBOM_IMPORT']
    instant_complete_mask = df_with_durations['type'].isin(instant_complete_types)
    df_with_durations.loc[instant_complete_mask & df_with_durations['completion_date'].isna(), 'completion_date'] = \
        df_with_durations.loc[instant_complete_mask & df_with_durations['completion_date'].isna(), 'scan_date']
    
    return df_with_durations


def generate_scan_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """Generate comprehensive scan analysis metrics."""
    
    # Group by date for time series analysis
    daily_metrics = []
    
    # Get date range - include both created and completed dates
    if df['created_dt'].isna().all():
        # No valid dates, return empty DataFrame
        return pd.DataFrame()
    
    min_created = df['created_dt'].min().date()
    max_created = df['created_dt'].max().date()
    
    # Also check completion dates to include scans that completed in the range
    if 'completed_dt' in df.columns and df['completed_dt'].notna().any():
        min_completed = df['completed_dt'].min().date()
        max_completed = df['completed_dt'].max().date()
        min_date = min(min_created, min_completed)
        max_date = max(max_created, max_completed)
    else:
        min_date = min_created
        max_date = max_created
    
    # Generate daily metrics
    current_date = min_date
    while current_date <= max_date:
        # Get scans that were created on this date (for "scans started" count)
        day_data_created = df[df['scan_date'] == current_date]
        
        # Get scans that were completed on this date (for "scans completed" count)
        # This may include scans created on earlier dates
        if 'completion_date' in df.columns:
            day_data_completed = df[df['completion_date'] == current_date]
        else:
            day_data_completed = pd.DataFrame()
        
        # We need metrics for this date if:
        # - Any scans were created on this date, OR
        # - Any scans were completed on this date
        if len(day_data_created) > 0 or len(day_data_completed) > 0:
            # Use created scans for the base data (for started counts, active scans, etc.)
            # But pass completed scans separately for completion counts
            day_data = day_data_created.copy() if len(day_data_created) > 0 else day_data_completed.head(0).copy()
            metrics = calculate_daily_metrics(day_data, current_date, day_data_completed)
            daily_metrics.append(metrics)
        
        current_date += timedelta(days=1)
    
    # Convert to DataFrame
    if not daily_metrics:
        return pd.DataFrame()
    
    result_df = pd.DataFrame(daily_metrics)
    
    # Add queue analysis (current state)
    queue_data = analyze_current_queue(df)
    
    # Add overall summary row
    summary_row = calculate_summary_metrics(df)
    summary_row['period'] = 'Overall Summary'
    summary_row['date'] = 'Total'
    
    # Combine daily metrics with summary
    result_df = pd.concat([result_df, pd.DataFrame([summary_row])], ignore_index=True)
    
    # Convert date column to strings for JSON serialization
    result_df['date'] = result_df['date'].astype(str)
    
    # Prepare raw scan data for the detailed table
    raw_data_df = df.copy()
    
    # Add useful columns for the raw data table
    raw_data_df['scan_date'] = raw_data_df['created'].astype(str)
    
    # Handle completion date properly (avoid "nan" strings)
    # For SOURCE_SCA and SBOM_IMPORT scans, use created date as completion date
    instant_complete_types = ['SOURCE_SCA', 'SBOM_IMPORT']
    instant_complete_mask = raw_data_df['type'].isin(instant_complete_types)
    
    def format_completion_date(row):
        # For instant-complete scan types, use created date if completed is missing
        if row['type'] in instant_complete_types and (pd.isna(row.get('completed')) or str(row.get('completed')) == 'NaT'):
            return str(row['created']) if pd.notna(row.get('created')) else '-'
        # Otherwise use completed date
        completed = row.get('completed')
        if pd.notna(completed) and str(completed) != 'NaT':
            return str(completed)
        return '-'
    
    raw_data_df['completion_date'] = raw_data_df.apply(format_completion_date, axis=1)
    
    # Ensure duration is properly calculated and filled
    raw_data_df['duration_minutes'] = raw_data_df['duration_minutes'].fillna(0)
    
    # Clean up error messages (replace NaN with "-")
    if 'errorMessage' in raw_data_df.columns:
        raw_data_df['errorMessage'] = raw_data_df['errorMessage'].fillna('-')
        raw_data_df['errorMessage'] = raw_data_df['errorMessage'].replace('nan', '-')
    
    # Select and order columns for the raw data export
    raw_data_columns = [
        'id', 'scan_date', 'completion_date', 'status', 'type', 
        'project_name', 'duration_minutes', 'current_status_time_minutes', 'errorMessage'
    ]
    
    # Only include columns that exist
    available_columns = [col for col in raw_data_columns if col in raw_data_df.columns]
    raw_data_df = raw_data_df[available_columns]
    
    return {
        'daily_metrics': result_df,
        'raw_data': raw_data_df
    }


def calculate_daily_metrics(day_data: pd.DataFrame, date, day_data_completed: pd.DataFrame = None) -> Dict[str, Any]:
    """Calculate metrics for a single day.
    
    Args:
        day_data: Scans that were created on this date (for started counts, active scans, etc.)
        date: The date being analyzed
        day_data_completed: Scans that were completed on this date (for completion counts)
    """
    # For historical analysis, distinguish between scans that are truly stuck vs recently created
    # SOURCE_SCA scans are completed locally and uploaded - treat as instantly completed
    from datetime import datetime, timedelta
    today = datetime.now().date()
    days_ago = (today - date).days
    
    # Use completed scans for completion metrics if provided, otherwise use created scans
    if day_data_completed is not None and len(day_data_completed) > 0:
        # For completion counts, use scans that completed on this date
        completed_day_data = day_data_completed
    else:
        # Fallback to scans created on this date
        completed_day_data = day_data
    
    initial_scans = day_data[day_data['status'] == 'INITIAL']
    started_scans = day_data[day_data['status'] == 'STARTED']
    
    # Separate external/third-party scans - they're completed externally and uploaded
    external_scan_types = ['SOURCE_SCA', 'JAR', 'SBOM_IMPORT']
    external_scans = completed_day_data[completed_day_data['type'].isin(external_scan_types)]
    other_scans = completed_day_data[~completed_day_data['type'].isin(external_scan_types)]
    
    # For non-external scans, INITIAL scans are failed attempts, only STARTED scans are actually waiting
    # Use day_data (created scans) for active scan counts
    other_scans_for_active = day_data[~day_data['type'].isin(external_scan_types)]
    other_initial = other_scans_for_active[other_scans_for_active['status'] == 'INITIAL']
    other_started = other_scans_for_active[other_scans_for_active['status'] == 'STARTED']
    
    # All INITIAL scans are considered failed attempts (regardless of age)
    stuck_scans = len(other_initial)
    
    # Only STARTED scans are actually waiting/processing
    recently_queued = len(other_started)
    
    # Count completed scans: external scans (all) + other scans with completion dates
    # Use completed_day_data to count scans that completed on this date
    other_completed = other_scans[
        (other_scans['status'] == 'COMPLETED') & 
        (other_scans['completed'].notna()) & 
        (other_scans['completed'] != '-')
    ]
    
    metrics = {
        'period': str(date),
        'date': str(date),
        'total_scans_started': len(day_data),
        'server_completed_scans': len(other_completed),
        'external_completed_scans': len(external_scans),
        'total_completed_scans': len(external_scans) + len(other_completed),
        'failed_scans': len(day_data[day_data['status'] == 'ERROR']) + len(other_initial),
        'stuck_scans': stuck_scans,
        'recently_queued': recently_queued,
        'still_active_scans': len(other_started),
    }
    
    # Calculate success rate (only for finished scans)
    total_finished = metrics['total_completed_scans'] + metrics['failed_scans']
    if total_finished > 0:
        metrics['success_rate'] = (metrics['total_completed_scans'] / total_finished) * 100
    else:
        metrics['success_rate'] = 0
    
    # Calculate completion rate (completed vs total started)
    if metrics['total_scans_started'] > 0:
        metrics['completion_rate'] = (metrics['total_completed_scans'] / metrics['total_scans_started']) * 100
    else:
        metrics['completion_rate'] = 0
    
    # Duration analysis for completed scans (exclude external scans)
    # Use completed_day_data to get scans that completed on this date
    external_scan_types = ['SOURCE_SCA', 'JAR', 'SBOM_IMPORT']
    completed_scans = completed_day_data[
        (completed_day_data['status'] == 'COMPLETED') & 
        (completed_day_data['duration_minutes'].notna()) &
        (~completed_day_data['type'].isin(external_scan_types))
    ]
    
    if len(completed_scans) > 0:
        metrics['avg_duration_minutes'] = int(round(completed_scans['duration_minutes'].mean()))
        metrics['median_duration_minutes'] = int(round(completed_scans['duration_minutes'].median()))
        metrics['min_duration_minutes'] = int(completed_scans['duration_minutes'].min())
        metrics['max_duration_minutes'] = int(completed_scans['duration_minutes'].max())
    else:
        metrics['avg_duration_minutes'] = 0
        metrics['median_duration_minutes'] = 0
        metrics['min_duration_minutes'] = 0
        metrics['max_duration_minutes'] = 0
    
    # Current status analytics for active scans (exclude external scans)
    active_scans = day_data[
        (day_data['status'].isin(['INITIAL', 'STARTED'])) &
        (~day_data['type'].isin(external_scan_types))
    ]
    if len(active_scans) > 0 and 'current_status_time_minutes' in active_scans.columns:
        valid_times = active_scans['current_status_time_minutes'].dropna()
        if len(valid_times) > 0:
            metrics['avg_active_time_minutes'] = int(round(valid_times.mean()))
            metrics['max_active_time_minutes'] = int(valid_times.max())
        else:
            metrics['avg_active_time_minutes'] = 0
            metrics['max_active_time_minutes'] = 0
    else:
        metrics['avg_active_time_minutes'] = 0
        metrics['max_active_time_minutes'] = 0
    
    # Separate analytics for INITIAL vs STARTED scans
    initial_scans = day_data[day_data['status'] == 'INITIAL']
    started_scans = day_data[day_data['status'] == 'STARTED']
    
    if len(initial_scans) > 0 and 'current_status_time_minutes' in initial_scans.columns:
        valid_initial_times = initial_scans['current_status_time_minutes'].dropna()
        if len(valid_initial_times) > 0:
            metrics['avg_initial_time_minutes'] = int(round(valid_initial_times.mean()))
            metrics['max_initial_time_minutes'] = int(valid_initial_times.max())
        else:
            metrics['avg_initial_time_minutes'] = 0
            metrics['max_initial_time_minutes'] = 0
    else:
        metrics['avg_initial_time_minutes'] = 0
        metrics['max_initial_time_minutes'] = 0
    
    if len(started_scans) > 0 and 'current_status_time_minutes' in started_scans.columns:
        valid_started_times = started_scans['current_status_time_minutes'].dropna()
        if len(valid_started_times) > 0:
            metrics['avg_started_time_minutes'] = int(round(valid_started_times.mean()))
            metrics['max_started_time_minutes'] = int(valid_started_times.max())
        else:
            metrics['avg_started_time_minutes'] = 0
            metrics['max_started_time_minutes'] = 0
    else:
        metrics['avg_started_time_minutes'] = 0
        metrics['max_started_time_minutes'] = 0
    
    # Scan type breakdown
    type_counts = day_data['type'].value_counts().to_dict()
    metrics['sca_scans'] = type_counts.get('SCA', 0)
    metrics['sast_scans'] = type_counts.get('SAST', 0)
    metrics['config_scans'] = type_counts.get('CONFIG', 0)
    metrics['source_sca_scans'] = type_counts.get('SOURCE_SCA', 0)
    metrics['vulnerability_analysis_scans'] = type_counts.get('VULNERABILITY_ANALYSIS', 0)
    metrics['sbom_import_scans'] = type_counts.get('SBOM_IMPORT', 0)
    
    return metrics


def calculate_summary_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """Calculate overall summary metrics."""
    # For historical analysis, distinguish between scans that are truly stuck vs recently created
    # SOURCE_SCA scans are completed locally and uploaded - treat as instantly completed
    from datetime import datetime, timedelta
    today = datetime.now().date()
    
    initial_scans = df[df['status'] == 'INITIAL']
    started_scans = df[df['status'] == 'STARTED']
    
    # Separate external/third-party scans - they're completed externally and uploaded
    external_scan_types = ['SOURCE_SCA', 'JAR', 'SBOM_IMPORT']
    external_scans = df[df['type'].isin(external_scan_types)]
    other_scans = df[~df['type'].isin(external_scan_types)]
    
    # For non-external scans, INITIAL scans are failed attempts, only STARTED scans are actually waiting
    other_initial = other_scans[other_scans['status'] == 'INITIAL']
    other_started = other_scans[other_scans['status'] == 'STARTED']
    
    # All INITIAL scans are considered failed attempts (regardless of age)
    stuck_scans = len(other_initial)
    
    # Only STARTED scans are actually waiting/processing
    recently_queued = len(other_started)
    
    # Count completed scans: external scans (all) + other scans with completion dates
    other_completed = other_scans[
        (other_scans['status'] == 'COMPLETED') & 
        (other_scans['completed'].notna()) & 
        (other_scans['completed'] != '-')
    ]
    
    summary = {
        'total_scans_started': len(df),
        'server_completed_scans': len(other_completed),
        'external_completed_scans': len(external_scans),
        'total_completed_scans': len(external_scans) + len(other_completed),
        'failed_scans': len(df[df['status'] == 'ERROR']) + len(other_initial),
        'stuck_scans': stuck_scans,
        'recently_queued': recently_queued,
        'still_active_scans': len(other_started),
    }
    
    # Calculate overall success rate (only for finished scans)
    total_finished = summary['total_completed_scans'] + summary['failed_scans']
    if total_finished > 0:
        summary['success_rate'] = (summary['total_completed_scans'] / total_finished) * 100
    else:
        summary['success_rate'] = 0
    
    # Calculate overall completion rate (completed vs total started)
    if summary['total_scans_started'] > 0:
        summary['completion_rate'] = (summary['total_completed_scans'] / summary['total_scans_started']) * 100
    else:
        summary['completion_rate'] = 0
    
    # Overall duration analysis (exclude external scans)
    external_scan_types = ['SOURCE_SCA', 'JAR', 'SBOM_IMPORT']
    completed_scans = df[
        (df['status'] == 'COMPLETED') & 
        (df['duration_minutes'].notna()) &
        (~df['type'].isin(external_scan_types))
    ]
    
    if len(completed_scans) > 0:
        summary['avg_duration_minutes'] = int(round(completed_scans['duration_minutes'].mean()))
        summary['median_duration_minutes'] = int(round(completed_scans['duration_minutes'].median()))
        summary['min_duration_minutes'] = int(completed_scans['duration_minutes'].min())
        summary['max_duration_minutes'] = int(completed_scans['duration_minutes'].max())
    else:
        summary['avg_duration_minutes'] = 0
        summary['median_duration_minutes'] = 0
        summary['min_duration_minutes'] = 0
        summary['max_duration_minutes'] = 0
    
    # Overall current status analytics (exclude external scans)
    active_scans = df[
        (df['status'].isin(['INITIAL', 'STARTED'])) &
        (~df['type'].isin(external_scan_types))
    ]
    if len(active_scans) > 0 and 'current_status_time_minutes' in active_scans.columns:
        valid_times = active_scans['current_status_time_minutes'].dropna()
        if len(valid_times) > 0:
            summary['avg_active_time_minutes'] = int(round(valid_times.mean()))
            summary['max_active_time_minutes'] = int(valid_times.max())
        else:
            summary['avg_active_time_minutes'] = 0
            summary['max_active_time_minutes'] = 0
    else:
        summary['avg_active_time_minutes'] = 0
        summary['max_active_time_minutes'] = 0
    
    # Separate analytics for INITIAL vs STARTED scans
    initial_scans = df[df['status'] == 'INITIAL']
    started_scans = df[df['status'] == 'STARTED']
    
    if len(initial_scans) > 0 and 'current_status_time_minutes' in initial_scans.columns:
        valid_initial_times = initial_scans['current_status_time_minutes'].dropna()
        if len(valid_initial_times) > 0:
            summary['avg_initial_time_minutes'] = int(round(valid_initial_times.mean()))
            summary['max_initial_time_minutes'] = int(valid_initial_times.max())
        else:
            summary['avg_initial_time_minutes'] = 0
            summary['max_initial_time_minutes'] = 0
    else:
        summary['avg_initial_time_minutes'] = 0
        summary['max_initial_time_minutes'] = 0
    
    if len(started_scans) > 0 and 'current_status_time_minutes' in started_scans.columns:
        valid_started_times = started_scans['current_status_time_minutes'].dropna()
        if len(valid_started_times) > 0:
            summary['avg_started_time_minutes'] = int(round(valid_started_times.mean()))
            summary['max_started_time_minutes'] = int(valid_started_times.max())
        else:
            summary['avg_started_time_minutes'] = 0
            summary['max_started_time_minutes'] = 0
    else:
        summary['avg_started_time_minutes'] = 0
        summary['max_started_time_minutes'] = 0
    
    # Overall scan type breakdown
    type_counts = df['type'].value_counts().to_dict()
    summary['sca_scans'] = type_counts.get('SCA', 0)
    summary['sast_scans'] = type_counts.get('SAST', 0)
    summary['config_scans'] = type_counts.get('CONFIG', 0)
    summary['source_sca_scans'] = type_counts.get('SOURCE_SCA', 0)
    summary['vulnerability_analysis_scans'] = type_counts.get('VULNERABILITY_ANALYSIS', 0)
    summary['sbom_import_scans'] = type_counts.get('SBOM_IMPORT', 0)
    
    return summary


def analyze_current_queue(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze current active scans with detailed INITIAL vs STARTED breakdown."""
    initial_scans = df[df['status'] == 'INITIAL']
    started_scans = df[df['status'] == 'STARTED']
    
    queue_analysis = {
        'current_active_scans': len(initial_scans) + len(started_scans),
        'initial_scans': len(initial_scans),
        'started_scans': len(started_scans),
    }
    
    # Analytics for INITIAL scans (waiting in queue)
    if len(initial_scans) > 0 and 'current_status_time_minutes' in initial_scans.columns:
        valid_initial_times = initial_scans['current_status_time_minutes'].dropna()
        if len(valid_initial_times) > 0:
            queue_analysis['avg_initial_time_minutes'] = int(round(valid_initial_times.mean()))
            queue_analysis['max_initial_time_minutes'] = int(valid_initial_times.max())
            queue_analysis['oldest_initial_scan_id'] = initial_scans.loc[
                initial_scans['current_status_time_minutes'].idxmax(), 'id'
            ] if not valid_initial_times.empty else None
        else:
            queue_analysis['avg_initial_time_minutes'] = 0
            queue_analysis['max_initial_time_minutes'] = 0
            queue_analysis['oldest_initial_scan_id'] = None
    else:
        queue_analysis['avg_initial_time_minutes'] = 0
        queue_analysis['max_initial_time_minutes'] = 0
        queue_analysis['oldest_initial_scan_id'] = None
    
    # Analytics for STARTED scans (actively processing)
    if len(started_scans) > 0 and 'current_status_time_minutes' in started_scans.columns:
        valid_started_times = started_scans['current_status_time_minutes'].dropna()
        if len(valid_started_times) > 0:
            queue_analysis['avg_started_time_minutes'] = int(round(valid_started_times.mean()))
            queue_analysis['max_started_time_minutes'] = int(valid_started_times.max())
            queue_analysis['longest_started_scan_id'] = started_scans.loc[
                started_scans['current_status_time_minutes'].idxmax(), 'id'
            ] if not valid_started_times.empty else None
        else:
            queue_analysis['avg_started_time_minutes'] = 0
            queue_analysis['max_started_time_minutes'] = 0
            queue_analysis['longest_started_scan_id'] = None
    else:
        queue_analysis['avg_started_time_minutes'] = 0
        queue_analysis['max_started_time_minutes'] = 0
        queue_analysis['longest_started_scan_id'] = None
    
    return queue_analysis 