"""
Pandas transform functions for Scan Analysis report.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from fs_report.models import Config


def scan_analysis_transform(data: List[Dict[str, Any]], config: Config) -> Dict[str, pd.DataFrame]:
    """
    Transform scan data for the Scan Analysis report.
    
    Args:
        data: Raw scan data from API
        config: Configuration object
    
    Returns:
        Dictionary with two DataFrames:
        - 'daily_metrics': Daily aggregated scan metrics
        - 'raw_data': All individual scans with metadata
    """
    if not data:
        return pd.DataFrame()
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
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
    
    # Calculate duration in minutes for completed scans
    def calculate_duration(row):
        if pd.isna(row['created_dt']) or pd.isna(row['completed_dt']):
            return None
        duration = (row['completed_dt'] - row['created_dt']).total_seconds() / 60
        return int(round(duration)) if duration >= 0 else None
    
    df_with_durations['duration_minutes'] = df_with_durations.apply(calculate_duration, axis=1)
    
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
    
    return df_with_durations


def generate_scan_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """Generate comprehensive scan analysis metrics."""
    
    # Group by date for time series analysis
    daily_metrics = []
    
    # Get date range
    if df['created_dt'].isna().all():
        # No valid dates, return empty DataFrame
        return pd.DataFrame()
    
    min_date = df['created_dt'].min().date()
    max_date = df['created_dt'].max().date()
    
    # Generate daily metrics
    current_date = min_date
    while current_date <= max_date:
        day_data = df[df['scan_date'] == current_date]
        
        if len(day_data) > 0:
            metrics = calculate_daily_metrics(day_data, current_date)
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
    raw_data_df['completion_date'] = raw_data_df['completed'].apply(
        lambda x: str(x) if pd.notna(x) and str(x) != 'NaT' else '-'
    )
    
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


def calculate_daily_metrics(day_data: pd.DataFrame, date) -> Dict[str, Any]:
    """Calculate metrics for a single day."""
    # For historical analysis, distinguish between scans that are truly stuck vs recently created
    # SOURCE_SCA scans are completed locally and uploaded - treat as instantly completed
    from datetime import datetime, timedelta
    today = datetime.now().date()
    days_ago = (today - date).days
    
    initial_scans = day_data[day_data['status'] == 'INITIAL']
    started_scans = day_data[day_data['status'] == 'STARTED']
    
    # Separate external/third-party scans - they're completed externally and uploaded
    external_scan_types = ['SOURCE_SCA', 'JAR', 'SBOM_IMPORT']
    external_scans = day_data[day_data['type'].isin(external_scan_types)]
    other_scans = day_data[~day_data['type'].isin(external_scan_types)]
    
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
    external_scan_types = ['SOURCE_SCA', 'JAR', 'SBOM_IMPORT']
    completed_scans = day_data[
        (day_data['status'] == 'COMPLETED') & 
        (day_data['duration_minutes'].notna()) &
        (~day_data['type'].isin(external_scan_types))
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