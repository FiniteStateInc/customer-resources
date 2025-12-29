"""Period parser for CLI date range specifications."""

import re
from datetime import datetime, timedelta
from typing import Tuple


class PeriodParser:
    """Parse period specifications into start and end dates."""
    
    @staticmethod
    def parse_period(period: str) -> Tuple[str, str]:
        """
        Parse a period specification into start and end dates.
        
        Args:
            period: Period specification string
            
        Returns:
            Tuple of (start_date, end_date) in ISO format
            
        Examples:
            - "7d" -> last 7 days
            - "30d" -> last 30 days
            - "1w" -> last week
            - "4w" -> last 4 weeks
            - "1m" -> last month
            - "3m" -> last 3 months
            - "1q" -> last quarter
            - "1y" -> last year
            - "ytd" -> year to date (Jan 1 to today)
            - "Q1" -> Q1 of current year
            - "Q2-2024" -> Q2 of 2024
            - "2024" -> entire year 2024
            - "2023-2024" -> 2023 to 2024
            - "monday" -> this week (monday to sunday)
            - "january" -> this month
            - "january-2024" -> january 2024
        """
        period = period.lower().strip()
        
        # YTD (Year-to-Date)
        if period == "ytd":
            current_year = datetime.now().year
            start_date = datetime(current_year, 1, 1).date()
            end_date = datetime.now().date()
            return start_date.isoformat(), end_date.isoformat()
        
        # Days
        if re.match(r'^\d+d$', period):
            days = int(period[:-1])
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            return start_date.isoformat(), end_date.isoformat()
        
        # Weeks
        if re.match(r'^\d+w$', period):
            weeks = int(period[:-1])
            end_date = datetime.now().date()
            start_date = end_date - timedelta(weeks=weeks)
            return start_date.isoformat(), end_date.isoformat()
        
        # Months
        if re.match(r'^\d+m$', period):
            months = int(period[:-1])
            today = datetime.now().date()
            
            # For "1m", calculate the previous calendar month
            if months == 1:
                # Get the first day of the current month
                first_of_current = today.replace(day=1)
                # Get the last day of the previous month (first of current minus 1 day)
                # This handles year boundaries correctly (e.g., Jan 1 - 1 day = Dec 31 of previous year)
                end_date = first_of_current - timedelta(days=1)
                # Get first day of previous month
                start_date = end_date.replace(day=1)
                return start_date.isoformat(), end_date.isoformat()
            else:
                # For multiple months (2m, 3m, etc.), use rolling window
                end_date = today
                start_date = end_date - timedelta(days=months * 30)
                return start_date.isoformat(), end_date.isoformat()
        
        # Quarters
        if re.match(r'^\d+q$', period):
            quarters = int(period[:-1])
            end_date = datetime.now().date()
            # Approximate quarters (90 days each)
            start_date = end_date - timedelta(days=quarters * 90)
            return start_date.isoformat(), end_date.isoformat()
        
        # Years
        if re.match(r'^\d+y$', period):
            years = int(period[:-1])
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=years * 365)
            return start_date.isoformat(), end_date.isoformat()
        
        # Specific quarters: Q1, Q2, Q3, Q4
        if re.match(r'^q[1-4]$', period):
            quarter = int(period[1])
            current_year = datetime.now().year
            return PeriodParser._get_quarter_dates(current_year, quarter)
        
        # Specific quarters with year: Q1-2024, Q2-2024, etc.
        if re.match(r'^q[1-4]-\d{4}$', period):
            quarter = int(period[1])
            year = int(period[3:])
            return PeriodParser._get_quarter_dates(year, quarter)
        
        # Specific years: 2024, 2023, etc.
        if re.match(r'^\d{4}$', period):
            year = int(period)
            return f"{year}-01-01", f"{year}-12-31"
        
        # Year ranges: 2023-2024, 2022-2024, etc.
        if re.match(r'^\d{4}-\d{4}$', period):
            start_year, end_year = period.split('-')
            return f"{start_year}-01-01", f"{end_year}-12-31"
        
        # Days of week: monday, tuesday, etc.
        if period in ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']:
            return PeriodParser._get_week_dates(period)
        
        # Months: january, february, etc.
        if period in ['january', 'february', 'march', 'april', 'may', 'june',
                     'july', 'august', 'september', 'october', 'november', 'december']:
            current_year = datetime.now().year
            return PeriodParser._get_month_dates(current_year, period)
        
        # Months with year: january-2024, february-2024, etc.
        if re.match(r'^(january|february|march|april|may|june|july|august|september|october|november|december)-\d{4}$', period):
            month, year = period.split('-')
            return PeriodParser._get_month_dates(int(year), month)
        
        raise ValueError(f"Invalid period specification: {period}")
    
    @staticmethod
    def _get_quarter_dates(year: int, quarter: int) -> Tuple[str, str]:
        """Get start and end dates for a specific quarter."""
        quarter_starts = {
            1: (1, 1),    # January 1
            2: (4, 1),    # April 1
            3: (7, 1),    # July 1
            4: (10, 1),   # October 1
        }
        
        quarter_ends = {
            1: (3, 31),   # March 31
            2: (6, 30),   # June 30
            3: (9, 30),   # September 30
            4: (12, 31),  # December 31
        }
        
        start_month, start_day = quarter_starts[quarter]
        end_month, end_day = quarter_ends[quarter]
        
        start_date = datetime(year, start_month, start_day).date()
        end_date = datetime(year, end_month, end_day).date()
        
        return start_date.isoformat(), end_date.isoformat()
    
    @staticmethod
    def _get_week_dates(day_name: str) -> Tuple[str, str]:
        """Get start and end dates for a week containing the specified day."""
        day_map = {
            'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
            'friday': 4, 'saturday': 5, 'sunday': 6
        }
        
        target_day = day_map[day_name]
        today = datetime.now().date()
        days_since_monday = (today.weekday() - target_day) % 7
        
        # Find the most recent occurrence of the target day
        target_date = today - timedelta(days=days_since_monday)
        
        # Get the week (Monday to Sunday)
        monday = target_date - timedelta(days=target_date.weekday())
        sunday = monday + timedelta(days=6)
        
        return monday.isoformat(), sunday.isoformat()
    
    @staticmethod
    def _get_month_dates(year: int, month_name: str) -> Tuple[str, str]:
        """Get start and end dates for a specific month."""
        month_map = {
            'january': 1, 'february': 2, 'march': 3, 'april': 4,
            'may': 5, 'june': 6, 'july': 7, 'august': 8,
            'september': 9, 'october': 10, 'november': 11, 'december': 12
        }
        
        month = month_map[month_name]
        
        # Start of month
        start_date = datetime(year, month, 1).date()
        
        # End of month (first day of next month minus 1 day)
        if month == 12:
            end_date = datetime(year + 1, 1, 1).date() - timedelta(days=1)
        else:
            end_date = datetime(year, month + 1, 1).date() - timedelta(days=1)
        
        return start_date.isoformat(), end_date.isoformat()
    
    @staticmethod
    def get_help_text() -> str:
        """Get help text for period specifications."""
        return """
Period specifications:

Days:
  - "7d"     - Last 7 days
  - "30d"    - Last 30 days

Weeks:
  - "1w"     - Last week
  - "4w"     - Last 4 weeks

Months:
  - "1m"     - Last month
  - "3m"     - Last 3 months

Quarters:
  - "1q"     - Last quarter
  - "Q1"     - Q1 of current year
  - "Q2-2024" - Q2 of 2024

Years:
  - "1y"     - Last year
  - "ytd"    - Year to date (Jan 1 to today)
  - "2024"   - Entire year 2024
  - "2023-2024" - 2023 to 2024

Days of week:
  - "monday" - This week (Monday to Sunday)

Months:
  - "january" - This month
  - "january-2024" - January 2024
""" 