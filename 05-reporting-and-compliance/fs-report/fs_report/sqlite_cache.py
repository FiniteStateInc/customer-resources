# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
SQLite-based cache for API data with TTL support and crash recovery.

This module provides a persistent cache that:
- Trims API responses to only needed fields (~80% storage reduction)
- Supports crash recovery via implicit progress tracking
- Enables optional cache reuse across runs with configurable TTL

[BETA] This feature is experimental. Default behavior (fresh data each run)
is unchanged unless --cache-ttl is specified.
"""

import gc
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# Field Trimming Maps
# =============================================================================
# These define which fields to extract from API responses for each endpoint.
# Nested fields use dot notation (e.g., 'component.name').

FINDING_FIELDS = {
    "id": "id",
    "findingId": "finding_id",
    "title": "title",
    "severity": "severity",
    "status": "status",
    "risk": "risk",
    "detected": "detected",
    "component.id": "component_id",
    "component.vcId": "component_vc_id",  # Version component ID (used in BOM URL componentId= param)
    "component.name": "component_name",
    "component.version": "component_version",
    "project.id": "project_id",
    "project.name": "project_name",
    "projectVersion.id": "project_version_id",
    "projectVersion.version": "project_version",
    "cwes": "cwes",  # Stored as JSON array
    "exploitInfo": "exploit_info",  # Stored as JSON array
    "inKev": "in_kev",
    "inVcKev": "in_vc_kev",
    "epssPercentile": "epss_percentile",
    "epssScore": "epss_score",  # Raw EPSS score (0-1)
    "reachabilityScore": "reachability_score",
    "attackVector": "attack_vector",  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    "factors": "factors",  # Reachability factors array (stored as JSON)
    "hasKnownExploit": "has_known_exploit",  # Direct boolean from API
}

SCAN_FIELDS = {
    "id": "id",
    "type": "type",
    "status": "status",
    "created": "created",
    "completed": "completed",
    "errorMessage": "error_message",
    "project.id": "project_id",
    "project.name": "project_name",
    "projectVersion.id": "project_version_id",
    "projectVersion.version": "project_version",
}

COMPONENT_FIELDS = {
    "id": "id",
    "gcId": "gc_id",
    "name": "name",
    "version": "version",
    "type": "type",
    "supplier": "supplier",
    "declaredLicenses": "declared_licenses",  # Auto-detected licenses
    "concludedLicenses": "concluded_licenses",  # User-specified licenses (takes precedence)
    "releaseDate": "release_date",
    "findings": "findings",
    "warnings": "warnings",
    "violations": "violations",
    "severityCounts": "severity_counts",  # Stored as JSON
    "source": "source",  # Stored as JSON array
    "status": "status",
    "edited": "edited",
    # Project context (needed for Component List report)
    "project.id": "project_id",
    "project.name": "project_name",
    "projectVersion.id": "project_version_id",
    "projectVersion.version": "project_version",
}

PROJECT_FIELDS = {
    "id": "id",
    "name": "name",
    "description": "description",
    "type": "type",
    "created": "created",
    "createdBy": "created_by",
    "defaultBranch.latestVersion.id": "default_branch_latest_version_id",
}

CVE_FIELDS = {
    "cveId": "cve_id",
    "severity": "severity",
    "risk": "risk",
    "cwes": "cwes",  # Stored as JSON array
    "exploitInfo": "exploit_info",  # Stored as JSON array
    "exploitMaturity": "exploit_maturity",
    "epssPercentile": "epss_percentile",
    "epssScore": "epss_score",
    "inKev": "in_kev",
    "inVcKev": "in_vc_kev",
    "firstDetected": "first_detected",
    "lastDetected": "last_detected",
    "affectedProjects": "affected_projects",  # Stored as JSON array
    "affectedComponents": "affected_components",  # Stored as JSON array
    "cvssSeverity": "cvss_severity",  # Stored as JSON object
}

AUDIT_FIELDS = {
    "user": "user",
    "time": "time",
    "type": "type",
    "comment": "comment",
    "username": "username",
    "application": "application",  # Stored as JSON
    "appVersion": "app_version",  # Stored as JSON
    "component": "component",  # Stored as JSON
    "data": "data",  # Stored as JSON
}

# Map endpoint patterns to field definitions
ENDPOINT_FIELD_MAP = {
    "/findings": FINDING_FIELDS,
    "/scans": SCAN_FIELDS,
    "/components": COMPONENT_FIELDS,
    "/projects": PROJECT_FIELDS,
    "/audit": AUDIT_FIELDS,
    "/cves": CVE_FIELDS,
}


# =============================================================================
# Database Schema
# =============================================================================

SCHEMA_SQL = """
-- Metadata table for cache management
CREATE TABLE IF NOT EXISTS cache_meta (
    query_hash TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    query_params TEXT,
    created_at REAL NOT NULL,
    completed_at REAL,
    record_count INTEGER DEFAULT 0,
    ttl_seconds INTEGER
);

-- Findings table (trimmed fields only)
CREATE TABLE IF NOT EXISTS findings (
    query_hash TEXT NOT NULL,
    id TEXT NOT NULL,
    finding_id TEXT,
    title TEXT,
    severity TEXT,
    status TEXT,
    risk REAL,
    detected TEXT,
    component_id TEXT,
    component_vc_id TEXT,
    component_name TEXT,
    component_version TEXT,
    project_id TEXT,
    project_name TEXT,
    project_version_id TEXT,
    project_version TEXT,
    cwes TEXT,
    exploit_info TEXT,
    in_kev INTEGER,
    in_vc_kev INTEGER,
    epss_percentile REAL,
    epss_score REAL,
    reachability_score REAL,
    attack_vector TEXT,
    factors TEXT,
    has_known_exploit INTEGER,
    PRIMARY KEY (query_hash, id)
);

-- Scans table (trimmed fields only)
CREATE TABLE IF NOT EXISTS scans (
    query_hash TEXT NOT NULL,
    id TEXT NOT NULL,
    type TEXT,
    status TEXT,
    created TEXT,
    completed TEXT,
    error_message TEXT,
    project_id TEXT,
    project_name TEXT,
    project_version_id TEXT,
    project_version TEXT,
    PRIMARY KEY (query_hash, id)
);

-- Components table (trimmed fields only)
CREATE TABLE IF NOT EXISTS components (
    query_hash TEXT NOT NULL,
    id TEXT NOT NULL,
    gc_id TEXT,
    name TEXT,
    version TEXT,
    type TEXT,
    supplier TEXT,
    declared_licenses TEXT,
    concluded_licenses TEXT,
    release_date TEXT,
    findings INTEGER,
    warnings INTEGER,
    violations INTEGER,
    severity_counts TEXT,
    source TEXT,
    status TEXT,
    edited INTEGER,
    project_id TEXT,
    project_name TEXT,
    project_version_id TEXT,
    project_version TEXT,
    PRIMARY KEY (query_hash, id)
);

-- Projects table (trimmed fields only)
CREATE TABLE IF NOT EXISTS projects (
    query_hash TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT,
    description TEXT,
    type TEXT,
    created TEXT,
    created_by TEXT,
    default_branch_latest_version_id TEXT,
    PRIMARY KEY (query_hash, id)
);

-- Audit events table (trimmed fields only)
CREATE TABLE IF NOT EXISTS audit_events (
    query_hash TEXT NOT NULL,
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    time TEXT,
    type TEXT,
    comment TEXT,
    username TEXT,
    application TEXT,
    app_version TEXT,
    component TEXT,
    data TEXT
);

-- CVEs table (pre-aggregated by CVE ID from /public/v0/cves)
CREATE TABLE IF NOT EXISTS cves (
    query_hash TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT,
    risk REAL,
    cwes TEXT,
    exploit_info TEXT,
    exploit_maturity TEXT,
    epss_percentile REAL,
    epss_score REAL,
    in_kev INTEGER,
    in_vc_kev INTEGER,
    first_detected TEXT,
    last_detected TEXT,
    affected_projects TEXT,
    affected_components TEXT,
    cvss_severity TEXT,
    PRIMARY KEY (query_hash, cve_id)
);

-- LLM-generated remediation guidance (keyed by CVE)
CREATE TABLE IF NOT EXISTS cve_remediations (
    cve_id TEXT PRIMARY KEY,
    component_name TEXT,
    fix_version TEXT,
    guidance TEXT,
    workaround TEXT,
    code_search_hints TEXT,
    generated_by TEXT,
    generated_at TEXT,
    confidence TEXT
);

-- CVE detail cache (from /findings/{pvId}/{findingId}/cves)
CREATE TABLE IF NOT EXISTS cve_detail_cache (
    finding_id TEXT PRIMARY KEY,
    cve_metadata TEXT,
    fetched_at TEXT
);

-- Exploit detail cache (from /findings/{pvId}/{findingId}/exploits)
CREATE TABLE IF NOT EXISTS exploit_detail_cache (
    finding_id TEXT PRIMARY KEY,
    exploit_metadata TEXT,
    fetched_at TEXT
);

-- Per-project version lists (lightweight cache for /projects/{id}/versions)
CREATE TABLE IF NOT EXISTS version_lists (
    project_id TEXT PRIMARY KEY,
    versions_json TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- Index for faster TTL checks
CREATE INDEX IF NOT EXISTS idx_cache_meta_created ON cache_meta(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_query ON findings(query_hash);
CREATE INDEX IF NOT EXISTS idx_scans_query ON scans(query_hash);
CREATE INDEX IF NOT EXISTS idx_components_query ON components(query_hash);
CREATE INDEX IF NOT EXISTS idx_projects_query ON projects(query_hash);
CREATE INDEX IF NOT EXISTS idx_audit_query ON audit_events(query_hash);
"""


# =============================================================================
# Helper Functions
# =============================================================================


def parse_ttl(ttl_string: str) -> int:
    """
    Parse a TTL string into seconds.

    Supports formats: '1h', '30m', '1d', '3600s', '1h30m'
    Bare numbers are treated as hours (e.g., '4' = 4 hours).

    Args:
        ttl_string: TTL specification string

    Returns:
        TTL in seconds

    Raises:
        ValueError: If format is invalid
    """
    if not ttl_string:
        return 0

    # If it's just a number, treat as hours (more intuitive default)
    try:
        hours = int(ttl_string)
        return hours * 3600
    except ValueError:
        pass

    # Parse duration string like '1h', '30m', '1d', '1h30m'
    total_seconds = 0
    pattern = r"(\d+)([dhms])"
    matches = re.findall(pattern, ttl_string.lower())

    if not matches:
        raise ValueError(
            f"Invalid TTL format: {ttl_string}. Use formats like '1h', '30m', '1d', or seconds."
        )

    multipliers = {"d": 86400, "h": 3600, "m": 60, "s": 1}

    for value, unit in matches:
        total_seconds += int(value) * multipliers[unit]

    return total_seconds


def _trim_factors(factors: list) -> list:
    """
    Trim a reachability factors array to only the fields consumed downstream.

    The raw ``factors`` array from the API can be enormous (up to 7 MB per
    finding) because ``details.stripped_bins`` / ``details.non_stripped_bins``
    list every binary path in the firmware image — repeated identically in
    every factor entry.

    Preserved per factor entry:
    - ``entity_type`` + ``entity_name`` (triage_prioritization, llm_client)
    - ``summary`` truncated to 300 chars (triage_prioritization)
    - ``score_change`` (required API field, per-factor score contribution)
    - ``details`` scalars (e.g. ``builtin_modules``, ``loadable_modules``)
    - ``details.comp_files`` capped at 5 entries (llm_client)

    Stripped from ``details`` (the bloat):
    - ``stripped_bins`` — list of every stripped binary path in the firmware
    - ``non_stripped_bins`` — same for non-stripped binaries
    - ``missing_callgraph_bins`` — same for binaries missing callgraph info

    These lists contain 100-367 long firmware extraction paths (~200 chars each),
    duplicated identically across every factor entry in the same finding.

    Trimming before SQLite storage typically reduces the column from ~22 KB
    average (up to 7.6 MB) to ~200-500 bytes per finding — a 97 %+ reduction.
    """
    # details keys that contain huge lists of binary paths — the source of bloat.
    # comp_files is handled separately (capped at 5 instead of dropped).
    _BLOAT_KEYS = {
        "stripped_bins",
        "non_stripped_bins",
        "missing_callgraph_bins",
        "component_files",  # Full list of component binaries (100-300+ paths)
        "non_comp_files",  # Binaries not associated with the component
    }

    trimmed: list[dict[str, Any]] = []
    for item in factors:
        if not isinstance(item, dict):
            continue
        entry: dict[str, Any] = {}
        if "entity_type" in item:
            entry["entity_type"] = item["entity_type"]
        if "entity_name" in item:
            entry["entity_name"] = item["entity_name"]
        if "summary" in item:
            summary = item["summary"]
            if isinstance(summary, str) and len(summary) > 300:
                summary = summary[:300]
            entry["summary"] = summary
        if "score_change" in item:
            entry["score_change"] = item["score_change"]
        # Keep all details *except* the bloat keys (binary path lists).
        # Cap comp_files at 5 entries (only sub-field consumed by llm_client).
        details = item.get("details")
        if isinstance(details, dict):
            trimmed_details: dict[str, Any] = {}
            for dk, dv in details.items():
                if dk in _BLOAT_KEYS:
                    continue
                if dk == "comp_files" and isinstance(dv, list):
                    if dv:
                        trimmed_details[dk] = dv[:5]
                else:
                    trimmed_details[dk] = dv
            if trimmed_details:
                entry["details"] = trimmed_details
        trimmed.append(entry)
    return trimmed


def get_nested_value(record: dict, key: str) -> Any:
    """
    Get a value from a nested dictionary using dot notation.

    Args:
        record: Dictionary to extract from
        key: Key with optional dot notation (e.g., 'component.name')

    Returns:
        The value, or None if not found
    """
    if "." not in key:
        return record.get(key)

    parts = key.split(".")
    value: Any = record
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def generate_query_hash(endpoint: str, params: dict) -> str:
    """
    Generate a unique hash for a query based on endpoint and parameters.

    Args:
        endpoint: API endpoint path
        params: Query parameters

    Returns:
        MD5 hash of the query
    """
    # Normalize parameters for consistent hashing
    normalized = {k: v for k, v in sorted(params.items()) if v is not None}
    key_string = f"{endpoint}:{json.dumps(normalized, sort_keys=True)}"
    return hashlib.md5(key_string.encode()).hexdigest()


def get_table_for_endpoint(endpoint: str) -> str:
    """
    Determine the table name for a given endpoint.

    Args:
        endpoint: API endpoint path

    Returns:
        Table name

    Raises:
        ValueError: If endpoint is not recognized (security measure to prevent
                   dynamic table name creation from untrusted input)
    """
    endpoint_lower = endpoint.lower()
    # Check /cves before /components to avoid false match on substrings
    if endpoint_lower.endswith("/cves") or "/cves?" in endpoint_lower:
        return "cves"
    elif "/findings" in endpoint_lower:
        return "findings"
    elif "/scans" in endpoint_lower:
        return "scans"
    elif "/components" in endpoint_lower:
        return "components"
    elif "/projects" in endpoint_lower:
        return "projects"
    elif "/audit" in endpoint_lower:
        return "audit_events"
    else:
        raise ValueError(
            f"Unknown endpoint '{endpoint}'. SQLite cache only supports: "
            "findings, scans, components, projects, audit, cves. "
            "Data from this endpoint will not be cached."
        )


def get_fields_for_endpoint(endpoint: str) -> dict:
    """
    Get the field mapping for a given endpoint.

    Args:
        endpoint: API endpoint path

    Returns:
        Field mapping dictionary
    """
    endpoint_lower = endpoint.lower()
    for pattern, fields in ENDPOINT_FIELD_MAP.items():
        if pattern in endpoint_lower:
            return fields
    # Return empty dict for unknown endpoints (store all as JSON)
    return {}


# =============================================================================
# SQLiteCache Class
# =============================================================================


@dataclass
class CacheStats:
    """Statistics about cache usage."""

    total_entries: int
    total_records: int
    cache_hits: int
    cache_misses: int
    db_size_bytes: int


class SQLiteCache:
    """
    SQLite-based cache for API data with TTL support and crash recovery.

    [BETA] This feature is experimental.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        default_ttl: int = 0,  # 0 = no caching across runs
        domain: str | None = None,  # Domain for instance-specific cache
    ):
        """
        Initialize the SQLite cache.

        Args:
            cache_dir: Directory to store cache database.
                       Defaults to ~/.fs-report/
            default_ttl: Default TTL in seconds. 0 disables cross-run caching.
            domain: Finite State domain (e.g., "customer.finitestate.io").
                   Creates domain-specific cache file to avoid mixing data.
        """
        self.default_ttl = default_ttl
        self.cache_hits = 0
        self.cache_misses = 0

        # Session start time - cache validity is checked against this, not current time
        # This ensures cache doesn't expire mid-report for long-running reports
        self.session_start_time = time.time()

        # Determine cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".fs-report"

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Use domain-specific cache file to avoid mixing data between instances
        if domain:
            # Sanitize domain for filename (replace dots, remove protocol)
            safe_domain = domain.replace("https://", "").replace("http://", "")
            safe_domain = safe_domain.replace("/", "_").replace(":", "_")
            self.db_path = self.cache_dir / f"{safe_domain}.db"
        else:
            self.db_path = self.cache_dir / "cache.db"

        # Initialize database
        self._init_db()

        # Clean up expired and incomplete entries on startup
        self._startup_cleanup()

        logger.debug(f"SQLite cache initialized at {self.db_path}")

    def _init_db(self) -> None:
        """Initialize the database schema and apply migrations."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA_SQL)
            self._migrate_schema(conn)
            conn.commit()

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add any missing columns to existing tables (backward-compatible)."""
        # Column migrations: (table, column_name, column_type)
        migrations = [
            ("findings", "epss_score", "REAL"),
            ("findings", "reachability_score", "REAL"),
            ("findings", "attack_vector", "TEXT"),
            ("findings", "factors", "TEXT"),
            ("findings", "has_known_exploit", "INTEGER"),
            ("findings", "component_vc_id", "TEXT"),
            ("findings", "title", "TEXT"),
            ("projects", "default_branch_latest_version_id", "TEXT"),
        ]
        for table, col, col_type in migrations:
            try:
                conn.execute(f"SELECT {col} FROM {table} LIMIT 1")
            except sqlite3.OperationalError:
                # Column doesn't exist — add it
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
                logger.debug(f"Migrated: added {col} ({col_type}) to {table}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with concurrency settings."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)  # Wait up to 30s for locks
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency (readers don't block writers)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")  # 30 second timeout
        return conn

    def close(self) -> None:
        """Release database file handles (needed on Windows before temp dir cleanup)."""
        try:
            with self._get_connection() as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                # Switch out of WAL so -wal/-shm are released (Windows holds locks otherwise)
                conn.execute("PRAGMA journal_mode=DELETE")
            gc.collect()  # Encourage release of file handles on Windows
        except Exception:
            pass

    def is_cache_valid(
        self, endpoint: str, params: dict, ttl: int | None = None
    ) -> bool:
        """
        Check if cached data exists and is still valid.

        Args:
            endpoint: API endpoint
            params: Query parameters
            ttl: TTL to check against (uses default if not specified)

        Returns:
            True if cache is valid and can be used
        """
        ttl = ttl if ttl is not None else self.default_ttl

        # If TTL is 0, never use cache from previous runs
        if ttl == 0:
            return False

        query_hash = generate_query_hash(endpoint, params)

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT created_at, completed_at, record_count
                FROM cache_meta
                WHERE query_hash = ?
                """,
                (query_hash,),
            )
            row = cursor.fetchone()

            if not row:
                return False

            # Check if fetch was completed
            if row["completed_at"] is None:
                logger.debug(
                    f"Cache entry for {endpoint} exists but fetch was incomplete"
                )
                return False

            # Check TTL against session start time (not current time)
            # This ensures cache doesn't expire mid-report for long-running reports
            age_at_session_start = self.session_start_time - row["created_at"]
            if age_at_session_start > ttl:
                logger.debug(
                    f"Cache entry for {endpoint} expired at session start (age: {age_at_session_start:.0f}s, ttl: {ttl}s)"
                )
                return False

            logger.debug(
                f"Cache hit for {endpoint} (age at session start: {age_at_session_start:.0f}s, records: {row['record_count']})"
            )
            return True

    def get_cached_data(
        self, endpoint: str, params: dict, *, allow_empty: bool = False
    ) -> list[dict] | None:
        """
        Retrieve cached data for a query.

        Args:
            endpoint: API endpoint
            params: Query parameters
            allow_empty: If True, return ``[]`` when the cache entry exists but
                has zero records (i.e. the fetch completed with no results).
                The caller should first verify the entry is valid via
                ``is_cache_valid()``.  Default ``False`` preserves the legacy
                behaviour where empty results return ``None``.

        Returns:
            List of records, or None if not cached or endpoint not supported
        """
        try:
            table_name = get_table_for_endpoint(endpoint)
        except ValueError:
            # Unknown endpoint - not cacheable
            return None

        query_hash = generate_query_hash(endpoint, params)
        fields = get_fields_for_endpoint(endpoint)

        with self._get_connection() as conn:
            # Get all records for this query
            try:
                cursor = conn.execute(
                    f"SELECT * FROM {table_name} WHERE query_hash = ?", (query_hash,)
                )
                rows = cursor.fetchall()
            except sqlite3.OperationalError as e:
                logger.warning(f"Error reading from cache table {table_name}: {e}")
                return None

            if not rows:
                # The query returned 0 data rows.  When allow_empty is set the
                # caller has already confirmed (via is_cache_valid) that this
                # entry was completed — so 0 rows is a legitimate cached result
                # (e.g. a version with no components).
                return [] if allow_empty else None

            # Convert back to original API format
            records = []
            for row in rows:
                record = self._row_to_record(dict(row), fields)
                records.append(record)

            self.cache_hits += 1
            return records

    def _row_to_record(self, row: dict, fields: dict) -> dict:
        """
        Convert a database row back to API record format.

        Args:
            row: Database row as dict
            fields: Field mapping (api_field -> db_column)

        Returns:
            Record in original API format
        """
        # Remove query_hash from output
        row.pop("query_hash", None)

        # Reverse the field mapping
        reverse_map = {v: k for k, v in fields.items()}

        record: dict[str, Any] = {}
        for db_col, value in row.items():
            if value is None:
                continue

            api_field = reverse_map.get(db_col, db_col)

            # Handle nested fields
            if "." in api_field:
                parts = api_field.split(".")
                current = record
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = value
            else:
                # Parse JSON fields
                if db_col in (
                    "cwes",
                    "exploit_info",
                    "severity_counts",
                    "source",
                    "application",
                    "app_version",
                    "component",
                    "data",
                    "factors",
                    "affected_projects",
                    "affected_components",
                    "cvss_severity",
                ):
                    try:
                        value = json.loads(value) if value else None
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Convert booleans
                if db_col in ("in_kev", "in_vc_kev", "edited", "has_known_exploit"):
                    value = bool(value) if value is not None else None

                record[api_field] = value

        return record

    def get_progress(self, endpoint: str, params: dict) -> int:
        """
        Get the current progress (record count) for an incomplete fetch.

        Used for crash recovery - returns the number of records already fetched.

        Args:
            endpoint: API endpoint
            params: Query parameters

        Returns:
            Number of records already fetched, or 0 if no progress or endpoint not supported
        """
        try:
            table_name = get_table_for_endpoint(endpoint)
        except ValueError:
            # Unknown endpoint - no progress tracking
            return 0

        query_hash = generate_query_hash(endpoint, params)

        with self._get_connection() as conn:
            # Check if we have an incomplete fetch
            cursor = conn.execute(
                "SELECT completed_at FROM cache_meta WHERE query_hash = ?",
                (query_hash,),
            )
            row = cursor.fetchone()

            if not row or row["completed_at"] is not None:
                # No incomplete fetch, or fetch was completed
                return 0

            # Count records in the table
            try:
                cursor = conn.execute(
                    f"SELECT COUNT(*) as count FROM {table_name} WHERE query_hash = ?",
                    (query_hash,),
                )
                count_row = cursor.fetchone()
                return count_row["count"] if count_row else 0
            except sqlite3.OperationalError:
                return 0

    def start_fetch(self, endpoint: str, params: dict, ttl: int | None = None) -> str:
        """
        Start tracking a new fetch operation.

        Args:
            endpoint: API endpoint
            params: Query parameters
            ttl: TTL for this cache entry

        Returns:
            Query hash for this fetch
        """
        query_hash = generate_query_hash(endpoint, params)
        ttl = ttl if ttl is not None else self.default_ttl

        with self._get_connection() as conn:
            # Clear any existing data for this query
            self._clear_query_data(conn, query_hash, endpoint)

            # Insert new metadata entry
            conn.execute(
                """
                INSERT OR REPLACE INTO cache_meta
                (query_hash, endpoint, query_params, created_at, completed_at, record_count, ttl_seconds)
                VALUES (?, ?, ?, ?, NULL, 0, ?)
                """,
                (query_hash, endpoint, json.dumps(params), time.time(), ttl),
            )
            conn.commit()

        self.cache_misses += 1
        return query_hash

    def _clear_query_data(
        self, conn: sqlite3.Connection, query_hash: str, endpoint: str
    ) -> None:
        """Clear existing data for a query hash."""
        try:
            table_name = get_table_for_endpoint(endpoint)
        except ValueError:
            return  # Unknown endpoint - nothing to clear

        try:
            conn.execute(
                f"DELETE FROM {table_name} WHERE query_hash = ?", (query_hash,)
            )
        except sqlite3.OperationalError:
            pass  # Table might not exist yet

    def store_records(self, query_hash: str, endpoint: str, records: list[dict]) -> int:
        """
        Store a batch of records in the cache.

        Args:
            query_hash: Query hash from start_fetch
            endpoint: API endpoint (for determining table)
            records: Records to store

        Returns:
            Number of records stored, or 0 if endpoint not supported
        """
        if not records:
            return 0

        try:
            table_name = get_table_for_endpoint(endpoint)
        except ValueError as e:
            logger.warning(f"Cannot cache records: {e}")
            return 0

        fields = get_fields_for_endpoint(endpoint)

        # Trim records to needed fields
        trimmed_records = [self._trim_record(r, fields) for r in records]

        with self._get_connection() as conn:
            stored = 0
            for record in trimmed_records:
                record["query_hash"] = query_hash
                try:
                    self._insert_record(conn, table_name, record)
                    stored += 1
                except sqlite3.IntegrityError:
                    # Duplicate record, skip
                    logger.debug(
                        f"Skipping duplicate record: {record.get('id', 'unknown')}"
                    )
                except Exception as e:
                    logger.warning(f"Error storing record: {e}")

            # Update record count in metadata
            conn.execute(
                """
                UPDATE cache_meta
                SET record_count = record_count + ?
                WHERE query_hash = ?
                """,
                (stored, query_hash),
            )
            conn.commit()

        return stored

    def _trim_record(self, record: dict, fields: dict) -> dict:
        """
        Trim a record to only the needed fields.

        Args:
            record: Full API record
            fields: Field mapping (api_field -> db_column)

        Returns:
            Trimmed record with only needed fields
        """
        if not fields:
            # Unknown endpoint, store essential fields only
            return {"id": record.get("id"), "data": json.dumps(record)}

        # The API may return reachability as a nested dict
        # ({"score": N, "label": "...", "factors": [...]}) instead of flat
        # "reachabilityScore" and "factors" fields.  Flatten before trimming
        # so the normal field-extraction loop finds the values.
        reach = record.get("reachability")
        if isinstance(reach, dict):
            if "reachabilityScore" not in record and "score" in reach:
                record["reachabilityScore"] = reach["score"]
            if "factors" not in record and "factors" in reach:
                record["factors"] = reach["factors"]

        trimmed = {}
        for api_field, db_column in fields.items():
            value = get_nested_value(record, api_field)

            # Trim factors to only the sub-fields consumed downstream
            if db_column == "factors" and isinstance(value, list):
                value = _trim_factors(value)

            # Convert complex types to JSON strings
            if isinstance(value, list | dict):
                value = json.dumps(value)
            # Convert booleans to integers for SQLite
            elif isinstance(value, bool):
                value = 1 if value else 0

            trimmed[db_column] = value

        return trimmed

    def _insert_record(
        self, conn: sqlite3.Connection, table_name: str, record: dict
    ) -> None:
        """Insert a single record into the appropriate table."""
        columns = list(record.keys())
        placeholders = ",".join(["?" for _ in columns])
        column_names = ",".join(columns)
        values = [record[c] for c in columns]

        conn.execute(
            f"INSERT OR IGNORE INTO {table_name} ({column_names}) VALUES ({placeholders})",
            values,
        )

    def complete_fetch(self, query_hash: str) -> None:
        """
        Mark a fetch as complete.

        Args:
            query_hash: Query hash from start_fetch
        """
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE cache_meta SET completed_at = ? WHERE query_hash = ?",
                (time.time(), query_hash),
            )
            conn.commit()

        logger.debug(f"Fetch completed for query {query_hash}")

    def clear(self, endpoint: str | None = None) -> None:
        """
        Clear cached data and reset schema.

        Args:
            endpoint: If specified, only clear data for this endpoint.
                     If None, clear all cached data and recreate tables with current schema.

        Raises:
            ValueError: If endpoint is specified but not recognized
        """
        with self._get_connection() as conn:
            if endpoint:
                table_name = get_table_for_endpoint(endpoint)  # May raise ValueError
                # Drop and recreate to get updated schema
                conn.execute(f"DROP TABLE IF EXISTS {table_name}")
                conn.execute(
                    "DELETE FROM cache_meta WHERE endpoint LIKE ?", (f"%{endpoint}%",)
                )
            else:
                # Drop all tables to reset schema
                for table in [
                    "findings",
                    "scans",
                    "components",
                    "projects",
                    "audit_events",
                    "cache_meta",
                ]:
                    conn.execute(f"DROP TABLE IF EXISTS {table}")
            conn.commit()

        # Recreate tables with current schema
        self._init_db()

        # Reclaim disk space — SQLite keeps freed pages in the file without VACUUM
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("VACUUM")
        except Exception as e:
            logger.debug(f"VACUUM after clear failed (non-fatal): {e}")

        logger.info(
            f"Cache cleared and schema reset{f' for {endpoint}' if endpoint else ''}"
        )

    def get_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        with self._get_connection() as conn:
            # Count entries
            cursor = conn.execute("SELECT COUNT(*) as count FROM cache_meta")
            total_entries = cursor.fetchone()["count"]

            # Count total records
            total_records = 0
            for table in [
                "findings",
                "scans",
                "components",
                "projects",
                "audit_events",
            ]:
                try:
                    cursor = conn.execute(f"SELECT COUNT(*) as count FROM {table}")
                    total_records += cursor.fetchone()["count"]
                except sqlite3.OperationalError:
                    pass

        # Get database size
        db_size = os.path.getsize(self.db_path) if self.db_path.exists() else 0

        return {
            "total_entries": total_entries,
            "total_records": total_records,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "db_size_bytes": db_size,
            "db_size_mb": round(db_size / (1024 * 1024), 2),
            "db_path": str(self.db_path),
        }

    # ------------------------------------------------------------------
    # Lightweight version-list cache (per-project, not per-query)
    # ------------------------------------------------------------------

    def get_version_list(self, project_id: str, ttl: int) -> list[dict] | None:
        """
        Retrieve a cached version list for a project.

        Returns the list of version dicts, or None on cache miss / expiry.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT versions_json, created_at FROM version_lists WHERE project_id = ?",
                (project_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            age = self.session_start_time - row["created_at"]
            if age > ttl:
                return None
            try:
                result: list[dict[Any, Any]] | None = json.loads(row["versions_json"])
                return result
            except (json.JSONDecodeError, TypeError):
                return None

    def store_version_list(self, project_id: str, versions: list[dict]) -> None:
        """Store a version list for a project (upsert)."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO version_lists (project_id, versions_json, created_at)
                VALUES (?, ?, ?)
                """,
                (project_id, json.dumps(versions), time.time()),
            )
            conn.commit()

    def _startup_cleanup(self) -> None:
        """Run cleanup tasks on initialization: expired entries and stale incomplete fetches."""
        expired = self.cleanup_expired()
        incomplete = self.cleanup_incomplete()
        if expired or incomplete:
            logger.info(
                f"Startup cleanup: removed {expired} expired + {incomplete} stale incomplete cache entries"
            )

    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries and their associated records.

        Returns:
            Number of entries removed
        """
        now = time.time()
        removed = 0

        with self._get_connection() as conn:
            # Find expired completed entries
            cursor = conn.execute(
                """
                SELECT query_hash, endpoint
                FROM cache_meta
                WHERE completed_at IS NOT NULL
                  AND ttl_seconds > 0
                  AND (created_at + ttl_seconds) < ?
                """,
                (now,),
            )
            expired = cursor.fetchall()

            for row in expired:
                query_hash = row["query_hash"]
                endpoint = row["endpoint"]

                # Clear data for this query
                self._clear_query_data(conn, query_hash, endpoint)

                # Remove metadata
                conn.execute(
                    "DELETE FROM cache_meta WHERE query_hash = ?", (query_hash,)
                )
                removed += 1

            # Also clean expired version_lists (use default_ttl as threshold)
            if self.default_ttl > 0:
                try:
                    conn.execute(
                        "DELETE FROM version_lists WHERE (created_at + ?) < ?",
                        (self.default_ttl, now),
                    )
                except sqlite3.OperationalError:
                    pass  # Table may not exist yet

            conn.commit()

        return removed

    def cleanup_incomplete(self) -> int:
        """
        Remove incomplete fetch entries older than 1 hour (from crashed/interrupted runs).

        Only removes entries older than 1 hour to avoid deleting an in-progress
        fetch from the current session.

        Returns:
            Number of entries removed
        """
        now = time.time()
        one_hour_ago = now - 3600
        removed = 0

        with self._get_connection() as conn:
            # Find incomplete entries older than 1 hour
            cursor = conn.execute(
                """
                SELECT query_hash, endpoint
                FROM cache_meta
                WHERE completed_at IS NULL AND created_at < ?
                """,
                (one_hour_ago,),
            )
            incomplete = cursor.fetchall()

            for row in incomplete:
                query_hash = row["query_hash"]
                endpoint = row["endpoint"]

                # Clear data for this query
                self._clear_query_data(conn, query_hash, endpoint)

                # Remove metadata
                conn.execute(
                    "DELETE FROM cache_meta WHERE query_hash = ?", (query_hash,)
                )
                removed += 1

            conn.commit()

        return removed
