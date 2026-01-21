"""
Pandas transform functions for User Activity report.
"""

import pandas as pd
from typing import Any, Dict, List, Optional
from fs_report.models import Config


def user_activity_pandas_transform(data: List[Dict[str, Any]], config: Optional[Config] = None) -> Dict[str, Any]:
    """
    Transform audit data for the User Activity report.
    
    Args:
        data: Raw audit events from API
        config: Configuration object
    
    Returns:
        Dictionary with DataFrames and metrics for the report:
        - 'main': Main activity table (recent activity)
        - 'summary': Summary statistics dict
        - 'daily_logins': Daily active user metrics DataFrame
        - 'activity_by_type': Activity breakdown DataFrame
        - 'top_users': Top active users DataFrame
    """
    import logging
    logger = logging.getLogger(__name__)
    
    if not data:
        logger.warning("User activity transform: No data provided")
        return {
            'main': pd.DataFrame(),
            'summary': {'total_events': 0, 'unique_users': 0, 'active_days': 0, 'event_types': 0},
            'daily_logins': [],
            'activity_by_type': [],
            'top_users': [],
        }
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    logger.debug(f"User activity transform: DataFrame created with shape {df.shape}")
    
    # Normalize fields that may be strings or {value: ...} objects
    df = normalize_audit_fields(df)
    
    # Parse timestamps
    df['timestamp'] = pd.to_datetime(df['time'], errors='coerce', utc=True)
    df['date'] = df['timestamp'].dt.date
    
    # Filter out rows with invalid timestamps
    df = df.dropna(subset=['timestamp'])
    
    if df.empty:
        logger.warning("User activity transform: No valid events after parsing")
        return {
            'main': pd.DataFrame(),
            'summary': {'total_events': 0, 'unique_users': 0, 'active_days': 0, 'event_types': 0},
            'daily_logins': [],
            'activity_by_type': [],
            'top_users': [],
        }
    
    # Calculate all metrics
    daily_metrics = calculate_daily_activity_metrics(df)
    activity_metrics = calculate_activity_metrics(df)
    user_metrics = calculate_user_metrics(df)
    
    # Create the main activity table for display
    activity_df = create_activity_table(df)
    
    # Calculate average daily users
    daily_user_counts = df.groupby('date')['user'].nunique()
    avg_daily_users = daily_user_counts.mean() if len(daily_user_counts) > 0 else 0
    
    # Build summary
    summary = {
        'total_events': len(df),
        'unique_users': df['user'].nunique(),
        'active_days': df['date'].nunique(),
        'avg_daily_users': round(avg_daily_users, 1),
    }
    
    # Convert DataFrames to list of dicts for template rendering
    daily_activity_list = daily_metrics['daily_activity'].to_dict('records') if not daily_metrics['daily_activity'].empty else []
    activity_by_type_list = activity_metrics['activity_by_type'].to_dict('records')
    top_users_list = user_metrics['top_users'].to_dict('records')
    
    return {
        'main': activity_df,
        'summary': summary,
        'daily_logins': daily_activity_list,  # Keep key name for template compatibility
        'activity_by_type': activity_by_type_list,
        'top_users': top_users_list,
    }


def normalize_audit_fields(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize audit fields that may be strings or {value: ...} objects.
    
    Args:
        df: Raw audit DataFrame
    
    Returns:
        DataFrame with normalized fields
    """
    def extract_value(field):
        """Extract value from field that may be string or dict with 'value' key."""
        if isinstance(field, dict):
            return field.get('value', str(field))
        return field
    
    # Normalize user, time, and type fields
    if 'user' in df.columns:
        df['user'] = df['user'].apply(extract_value)
    else:
        df['user'] = 'Unknown'
    
    if 'time' in df.columns:
        df['time'] = df['time'].apply(extract_value)
    else:
        df['time'] = None
    
    if 'type' in df.columns:
        df['type'] = df['type'].apply(extract_value)
    else:
        df['type'] = 'Unknown'
    
    return df


def create_activity_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create the main activity table for display.
    
    Args:
        df: Normalized audit DataFrame
    
    Returns:
        Activity table DataFrame
    """
    # Select and format columns for the activity table
    activity_df = df[['timestamp', 'user', 'type']].copy()
    
    # Extract application name if present
    if 'application' in df.columns:
        activity_df['project'] = df['application'].apply(
            lambda x: x.get('name', '') if isinstance(x, dict) else ''
        )
    else:
        activity_df['project'] = ''
    
    # Format for display
    activity_df = activity_df.rename(columns={
        'timestamp': 'Time',
        'user': 'User',
        'type': 'Event Type',
        'project': 'Project'
    })
    
    # Sort by time descending (most recent first)
    activity_df = activity_df.sort_values('Time', ascending=False)
    
    # Format time for display
    activity_df['Time'] = activity_df['Time'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    return activity_df


def calculate_daily_activity_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate daily activity metrics (unique active users per day).
    
    Args:
        df: Normalized audit DataFrame
    
    Returns:
        Dictionary with daily activity metrics
    """
    if df.empty:
        return {
            'daily_activity': pd.DataFrame(columns=['Date', 'Unique Users', 'Total Logins']),
        }
    
    # Daily unique active users and total events
    daily_activity = df.groupby('date').agg(
        unique_users=('user', 'nunique'),
        total_events=('user', 'count')
    ).reset_index()
    daily_activity.columns = ['Date', 'Unique Users', 'Total Logins']  # Keep column names for template compatibility
    daily_activity = daily_activity.sort_values('Date')
    
    # Convert date to string for JSON serialization
    daily_activity['Date'] = daily_activity['Date'].astype(str)
    
    return {
        'daily_activity': daily_activity,
    }


def calculate_activity_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate activity breakdown metrics.
    
    Args:
        df: Normalized audit DataFrame
    
    Returns:
        Dictionary with activity metrics
    """
    # Activity by type
    activity_by_type = df['type'].value_counts().reset_index()
    activity_by_type.columns = ['Event Type', 'Count']
    activity_by_type['Percentage'] = (
        activity_by_type['Count'] / activity_by_type['Count'].sum() * 100
    ).round(1)
    
    return {
        'total_events': len(df),
        'event_types': df['type'].nunique(),
        'activity_by_type': activity_by_type,
    }


def calculate_user_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculate user-specific metrics.
    
    Args:
        df: Normalized audit DataFrame
    
    Returns:
        Dictionary with user metrics
    """
    # Top users by activity
    user_activity = df.groupby('user').agg(
        total_actions=('type', 'count'),
        first_active=('timestamp', 'min'),
        last_active=('timestamp', 'max'),
        event_types=('type', 'nunique'),
        active_days=('date', 'nunique')
    ).reset_index()
    
    user_activity = user_activity.sort_values('total_actions', ascending=False)
    user_activity.columns = ['User', 'Total Actions', 'First Active', 'Last Active', 'Event Types', 'Active Days']
    
    # Calculate "Logins" as active days for template compatibility
    user_activity['Logins'] = user_activity['Active Days']
    
    # Format dates
    user_activity['First Active'] = user_activity['First Active'].dt.strftime('%Y-%m-%d')
    user_activity['Last Active'] = user_activity['Last Active'].dt.strftime('%Y-%m-%d %H:%M')
    
    # Reorder columns for display
    user_activity = user_activity[['User', 'Total Actions', 'Logins', 'Last Active', 'Event Types']]
    
    return {
        'total_users': df['user'].nunique(),
        'top_users': user_activity.head(20),
    }
