"""
SQLite-based cache for Finite State API data with TTL support and crash recovery.

This module provides a persistent cache that:
- Stores raw JSON API responses for replay through Pydantic validation
- Supports crash recovery via incomplete-fetch tracking
- Enables optional cache reuse across runs with configurable TTL
- Uses domain-specific DB files (~/.fs-smartsheet/{domain}.db) to avoid
  collisions with fs-report caches

Default behaviour (cache_ttl=0) is unchanged — every run fetches fresh data.
Pass --cache-ttl to the CLI to opt in.
"""

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

from ._compat import secure_file

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

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

-- Generic record store (raw JSON blobs)
CREATE TABLE IF NOT EXISTS cached_records (
    query_hash TEXT NOT NULL,
    idx INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (query_hash, idx)
);

-- Indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_cache_meta_created ON cache_meta(created_at);
CREATE INDEX IF NOT EXISTS idx_cached_records_query ON cached_records(query_hash);
"""

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def parse_ttl(ttl_string: str) -> int:
    """
    Parse a TTL string into seconds.

    Supports formats: ``'1h'``, ``'30m'``, ``'1d'``, ``'3600s'``, ``'1h30m'``.
    Bare numbers are treated as **hours** (e.g. ``'4'`` = 4 hours).

    Args:
        ttl_string: TTL specification string.

    Returns:
        TTL in seconds.

    Raises:
        ValueError: If format is invalid.
    """
    if not ttl_string:
        return 0

    # Bare number → treat as hours
    try:
        hours = int(ttl_string)
        return hours * 3600
    except ValueError:
        pass

    # Parse duration tokens like '1h', '30m', '1d', '1h30m'
    pattern = r"(\d+)([dhms])"
    matches = re.findall(pattern, ttl_string.lower())

    if not matches:
        raise ValueError(
            f"Invalid TTL format: {ttl_string}. "
            "Use formats like '1h', '30m', '1d', or a bare number for hours."
        )

    multipliers = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    total = 0
    for value, unit in matches:
        total += int(value) * multipliers[unit]
    return total


def generate_query_hash(endpoint: str, params: dict[str, Any]) -> str:
    """
    Generate a deterministic hash for an endpoint + parameters combination.

    ``None`` values are stripped so that ``{limit: 100, sort: None}`` hashes
    identically to ``{limit: 100}``.
    """
    normalised = {k: v for k, v in sorted(params.items()) if v is not None}
    key_string = f"{endpoint}:{json.dumps(normalised, sort_keys=True)}"
    return hashlib.md5(key_string.encode()).hexdigest()


# ---------------------------------------------------------------------------
# CacheStats
# ---------------------------------------------------------------------------


@dataclass
class CacheStats:
    """Statistics about cache usage."""

    total_queries: int
    total_records: int
    cache_hits: int
    cache_misses: int
    db_size_bytes: int
    db_path: str


# ---------------------------------------------------------------------------
# SQLiteCache
# ---------------------------------------------------------------------------


class SQLiteCache:
    """
    SQLite-backed persistent cache for FS API responses.

    Stores raw JSON so that Pydantic models re-validate on replay.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        default_ttl: int = 0,
        domain: str | None = None,
    ):
        """
        Initialise the cache.

        Args:
            cache_dir: Directory for cache databases.  Defaults to
                ``~/.fs-smartsheet/``.
            default_ttl: Default TTL in seconds.  0 = no cross-run caching.
            domain: Finite State domain (e.g. ``platform.finitestate.io``).
                Creates a domain-specific DB file.
        """
        self.default_ttl = default_ttl
        self.cache_hits = 0
        self.cache_misses = 0

        # Session start — TTL is checked against this, not wall-clock time,
        # so the cache cannot expire mid-sync.
        self.session_start_time = time.time()

        # Resolve cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".fs-smartsheet"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Domain-specific DB file
        if domain:
            safe = domain.replace("https://", "").replace("http://", "")
            # Strip everything except alphanumerics, dots, and hyphens so the
            # name is safe on all platforms (Windows reserved names, backslash
            # as separator, 260-char path limit, etc.).
            safe = re.sub(r"[^a-zA-Z0-9._-]", "_", safe)
            # Prevent Windows reserved device names (CON, PRN, NUL, …)
            if re.match(r"^(CON|PRN|AUX|NUL|COM\d|LPT\d)(\.|$)", safe, re.IGNORECASE):
                safe = f"_{safe}"
            # Clamp length to stay well within filesystem limits
            safe = safe[:200]
            self.db_path = self.cache_dir / f"{safe}.db"
        else:
            self.db_path = self.cache_dir / "cache.db"

        self._init_db()
        secure_file(self.db_path)
        logger.debug("SQLite cache initialised at %s", self.db_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        """Return a new connection with useful pragmas.

        NOTE: WAL journal mode requires shared-memory support and may not
        work reliably on network/SMB drives (Windows) or NFS mounts (Linux).
        If the cache directory is on such a filesystem the ``PRAGMA`` will
        silently fall back to ``DELETE`` mode, which is safe but slower under
        concurrent access.  For best performance keep the cache directory on
        a local filesystem.
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_cache_valid(
        self,
        endpoint: str,
        params: dict[str, Any],
        ttl: int | None = None,
    ) -> bool:
        """Return ``True`` if a completed, non-expired entry exists."""
        ttl = ttl if ttl is not None else self.default_ttl
        if ttl == 0:
            return False

        query_hash = generate_query_hash(endpoint, params)

        with self._conn() as conn:
            row = conn.execute(
                "SELECT created_at, completed_at FROM cache_meta WHERE query_hash = ?",
                (query_hash,),
            ).fetchone()

            if not row:
                return False
            if row["completed_at"] is None:
                logger.debug("Cache entry for %s is incomplete", endpoint)
                return False

            age = self.session_start_time - row["created_at"]
            if age > ttl:
                logger.debug("Cache for %s expired (age %.0fs > ttl %ds)", endpoint, age, ttl)
                return False

            logger.debug("Cache hit for %s (age %.0fs)", endpoint, age)
            return True

    def get_cached_data(self, endpoint: str, params: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Retrieve cached JSON records, or ``None`` on miss."""
        query_hash = generate_query_hash(endpoint, params)

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM cached_records WHERE query_hash = ? ORDER BY idx",
                (query_hash,),
            ).fetchall()

        if not rows:
            return None

        self.cache_hits += 1
        return [json.loads(r["data"]) for r in rows]

    def get_progress(self, endpoint: str, params: dict[str, Any]) -> int:
        """
        Return the number of records stored for an *incomplete* fetch.

        Used for crash recovery — returns 0 if no incomplete entry exists.
        """
        query_hash = generate_query_hash(endpoint, params)
        with self._conn() as conn:
            meta = conn.execute(
                "SELECT completed_at FROM cache_meta WHERE query_hash = ?",
                (query_hash,),
            ).fetchone()
            if not meta or meta["completed_at"] is not None:
                return 0

            count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM cached_records WHERE query_hash = ?",
                (query_hash,),
            ).fetchone()
            return count["cnt"] if count else 0

    def start_fetch(
        self,
        endpoint: str,
        params: dict[str, Any],
        ttl: int | None = None,
    ) -> str:
        """
        Begin tracking a new fetch.  Clears any stale data for this query.

        Returns the query hash.
        """
        query_hash = generate_query_hash(endpoint, params)
        ttl = ttl if ttl is not None else self.default_ttl

        with self._conn() as conn:
            conn.execute("DELETE FROM cached_records WHERE query_hash = ?", (query_hash,))
            conn.execute(
                """
                INSERT OR REPLACE INTO cache_meta
                (query_hash, endpoint, query_params, created_at, completed_at,
                 record_count, ttl_seconds)
                VALUES (?, ?, ?, ?, NULL, 0, ?)
                """,
                (query_hash, endpoint, json.dumps(params), time.time(), ttl),
            )
            conn.commit()

        self.cache_misses += 1
        return query_hash

    def store_records(
        self,
        query_hash: str,
        records: list[dict[str, Any]],
    ) -> int:
        """
        Append a batch of raw-JSON records to the cache.

        Returns the number stored.
        """
        if not records:
            return 0

        with self._conn() as conn:
            # Find current max idx
            row = conn.execute(
                "SELECT COALESCE(MAX(idx), -1) AS max_idx FROM cached_records WHERE query_hash = ?",
                (query_hash,),
            ).fetchone()
            next_idx = row["max_idx"] + 1

            stored = 0
            for i, record in enumerate(records):
                try:
                    conn.execute(
                        "INSERT INTO cached_records (query_hash, idx, data) VALUES (?, ?, ?)",
                        (query_hash, next_idx + i, json.dumps(record, default=str)),
                    )
                    stored += 1
                except sqlite3.IntegrityError:
                    logger.debug("Duplicate idx %d, skipping", next_idx + i)

            conn.execute(
                "UPDATE cache_meta SET record_count = record_count + ? WHERE query_hash = ?",
                (stored, query_hash),
            )
            conn.commit()

        return stored

    def complete_fetch(self, query_hash: str) -> None:
        """Mark a fetch as successfully completed."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE cache_meta SET completed_at = ? WHERE query_hash = ?",
                (time.time(), query_hash),
            )
            conn.commit()
        logger.debug("Fetch completed for %s", query_hash)

    def clear(self, endpoint: str | None = None) -> None:
        """
        Clear cached data.

        Args:
            endpoint: If given, only clear entries whose endpoint contains
                this substring.  Otherwise wipe everything.
        """
        with self._conn() as conn:
            if endpoint:
                hashes = [
                    r["query_hash"]
                    for r in conn.execute(
                        "SELECT query_hash FROM cache_meta WHERE endpoint LIKE ?",
                        (f"%{endpoint}%",),
                    ).fetchall()
                ]
                for qh in hashes:
                    conn.execute("DELETE FROM cached_records WHERE query_hash = ?", (qh,))
                    conn.execute("DELETE FROM cache_meta WHERE query_hash = ?", (qh,))
            else:
                conn.execute("DELETE FROM cached_records")
                conn.execute("DELETE FROM cache_meta")
            conn.commit()

        logger.info("Cache cleared%s", f" for {endpoint}" if endpoint else "")

    def get_stats(self) -> CacheStats:
        """Return current cache statistics."""
        with self._conn() as conn:
            total_q = conn.execute("SELECT COUNT(*) AS c FROM cache_meta").fetchone()["c"]
            total_r = conn.execute("SELECT COUNT(*) AS c FROM cached_records").fetchone()["c"]

        db_size = os.path.getsize(self.db_path) if self.db_path.exists() else 0

        return CacheStats(
            total_queries=total_q,
            total_records=total_r,
            cache_hits=self.cache_hits,
            cache_misses=self.cache_misses,
            db_size_bytes=db_size,
            db_path=str(self.db_path),
        )

    def cleanup_expired(self) -> int:
        """Remove completed entries whose TTL has elapsed.  Returns count removed."""
        now = time.time()
        removed = 0

        with self._conn() as conn:
            expired = conn.execute(
                """
                SELECT query_hash FROM cache_meta
                WHERE ttl_seconds > 0 AND (? - created_at) > ttl_seconds
                """,
                (now,),
            ).fetchall()

            for row in expired:
                qh = row["query_hash"]
                conn.execute("DELETE FROM cached_records WHERE query_hash = ?", (qh,))
                conn.execute("DELETE FROM cache_meta WHERE query_hash = ?", (qh,))
                removed += 1

            conn.commit()

        if removed:
            logger.info("Cleaned up %d expired cache entries", removed)
        return removed

    def cleanup_incomplete(self) -> int:
        """Remove entries from incomplete (crashed) fetches.  Returns count removed."""
        removed = 0

        with self._conn() as conn:
            incomplete = conn.execute(
                "SELECT query_hash FROM cache_meta WHERE completed_at IS NULL"
            ).fetchall()

            for row in incomplete:
                qh = row["query_hash"]
                conn.execute("DELETE FROM cached_records WHERE query_hash = ?", (qh,))
                conn.execute("DELETE FROM cache_meta WHERE query_hash = ?", (qh,))
                removed += 1

            conn.commit()

        if removed:
            logger.info("Cleaned up %d incomplete cache entries", removed)
        return removed
