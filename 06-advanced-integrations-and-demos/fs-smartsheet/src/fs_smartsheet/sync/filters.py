"""Sync filters for scoping data synchronization."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class SyncFilters:
    """
    Filters for scoping sync operations.

    Use these to limit sync to specific subsets of data,
    which is essential for large enterprise deployments.
    """

    # Project filters
    project_ids: list[str] = field(default_factory=list)
    project_names: list[str] = field(default_factory=list)

    # Severity filter (for findings)
    severities: list[str] = field(default_factory=list)

    # Status filter (for findings)
    statuses: list[str] = field(default_factory=list)

    # Time-based filters
    since_days: int | None = None
    since_date: datetime | None = None

    # Finding type filter
    finding_types: list[str] = field(default_factory=list)

    # Component type filter
    include_files: bool = False  # Exclude "file" component types by default

    # Version override (use a specific version instead of current)
    version_id: str | None = None

    # Target folder override (bypasses hierarchy logic)
    target_folder: int | None = None

    # Safety limits
    max_rows: int | None = None

    def is_empty(self) -> bool:
        """Check if no filters are set."""
        return (
            not self.project_ids
            and not self.project_names
            and not self.severities
            and not self.statuses
            and not self.since_days
            and not self.since_date
            and not self.finding_types
        )

    def get_since_datetime(self) -> datetime | None:
        """Get the effective 'since' datetime."""
        if self.since_date:
            return self.since_date
        if self.since_days:
            return datetime.utcnow() - timedelta(days=self.since_days)
        return None

    def get_description(self) -> str:
        """Get a human-readable description of active filters."""
        parts = []

        if self.project_ids:
            parts.append(f"projects: {', '.join(self.project_ids[:3])}")
            if len(self.project_ids) > 3:
                parts[-1] += f" (+{len(self.project_ids) - 3} more)"

        if self.project_names:
            parts.append(f"project names: {', '.join(self.project_names[:3])}")
            if len(self.project_names) > 3:
                parts[-1] += f" (+{len(self.project_names) - 3} more)"

        if self.severities:
            parts.append(f"severity: {', '.join(self.severities)}")

        if self.statuses:
            parts.append(f"status: {', '.join(self.statuses)}")

        if self.finding_types:
            parts.append(f"types: {', '.join(self.finding_types)}")

        since = self.get_since_datetime()
        if since:
            parts.append(f"since: {since.strftime('%Y-%m-%d')}")

        if self.version_id:
            parts.append(f"version: {self.version_id}")

        if self.max_rows:
            parts.append(f"max rows: {self.max_rows}")

        if not parts:
            return "no filters (all data)"

        return "; ".join(parts)

    @classmethod
    def from_cli_args(
        cls,
        project: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        since: str | None = None,
        finding_type: str | None = None,
        max_rows: int | None = None,
        include_files: bool = False,
        target_folder: int | None = None,
        version: str | None = None,
    ) -> "SyncFilters":
        """
        Create filters from CLI arguments.

        Args:
            project: Comma-separated project IDs or names
            severity: Comma-separated severity levels
            status: Comma-separated status values
            since: Time filter (e.g., "30d", "2024-01-01")
            finding_type: Comma-separated finding types
            max_rows: Maximum rows to sync
            include_files: Include 'file' component types (excluded by default)
            target_folder: Smartsheet folder ID (bypasses hierarchy)
            version: Specific project version ID to sync
        """
        filters = cls(
            max_rows=max_rows,
            include_files=include_files,
            target_folder=target_folder,
            version_id=version,
        )

        if project:
            # Split by comma and determine if ID or name
            for p in project.split(","):
                p = p.strip()
                # IDs are typically large negative numbers or positive numbers
                if re.match(r"^-?\d+$", p):
                    filters.project_ids.append(p)
                else:
                    filters.project_names.append(p)

        if severity:
            filters.severities = [s.strip().lower() for s in severity.split(",")]

        if status:
            statuses = []
            for s in status.split(","):
                s = s.strip().lower()
                # Handle "null" or "none" as None status
                if s in ("null", "none", "unset"):
                    statuses.append("")
                else:
                    statuses.append(s)
            filters.statuses = statuses

        if since:
            since = since.strip()
            # Parse "Nd" format (e.g., "30d" for 30 days)
            day_match = re.match(r"^(\d+)d$", since, re.IGNORECASE)
            if day_match:
                filters.since_days = int(day_match.group(1))
            else:
                # Try parsing as date
                try:
                    filters.since_date = datetime.fromisoformat(since)
                except ValueError:
                    pass  # Invalid format, ignore

        if finding_type:
            filters.finding_types = [t.strip().lower() for t in finding_type.split(",")]

        return filters


# No default row limit — sync everything unless user sets --max-rows
DEFAULT_MAX_ROWS = None
HARD_MAX_ROWS = None
