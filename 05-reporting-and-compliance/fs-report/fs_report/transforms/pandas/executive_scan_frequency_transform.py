import pandas as pd
from datetime import datetime
from typing import List, Dict, Any
from fs_report.models import Config

def executive_scan_frequency_transform(data: List[Dict[str, Any]], config: Config = None) -> pd.DataFrame:
    """
    Transform findings data for the Executive Summary scan frequency chart.
    Groups by day, week, month, or quarter based on the date range.
    Returns a DataFrame with a 'period_label' attribute for chart labeling.
    """
    if config is None:
        raise ValueError("Config object is required for executive_scan_frequency_transform")
    if not data:
        df = pd.DataFrame()
        df.period_label = "Day"
        return df
    df = pd.DataFrame(data)
    if 'detected' not in df.columns:
        df = pd.DataFrame()
        df.period_label = "Day"
        return df
    df['detected_dt'] = pd.to_datetime(df['detected'], errors='coerce')
    # Determine period length
    start = pd.to_datetime(config.start_date)
    end = pd.to_datetime(config.end_date)
    period_days = (end - start).days + 1
    # Infer grouping period
    if period_days <= 31:
        period_type = 'D'
        period_label = 'Day'
        df['period'] = df['detected_dt'].dt.strftime('%Y-%m-%d')
    elif period_days <= 180:
        period_type = 'W'
        period_label = 'Week'
        df['period'] = df['detected_dt'].dt.to_period('W').apply(lambda r: r.start_time.strftime('%Y-%m-%d'))
    elif period_days <= 730:
        period_type = 'M'
        period_label = 'Month'
        df['period'] = df['detected_dt'].dt.strftime('%Y-%m')
    else:
        period_type = 'Q'
        period_label = 'Quarter'
        df['period'] = df['detected_dt'].dt.to_period('Q').astype(str)
    result = (
        df.groupby('period')
        .agg(finding_count=('id', 'count'))
        .reset_index()
        .sort_values('period')
    )
    # Attach the period label for use in chart labeling
    result.period_label = period_label
    return result 