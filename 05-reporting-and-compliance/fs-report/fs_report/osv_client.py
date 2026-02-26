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
OSV (Open Source Vulnerabilities) API client for fix version resolution.

Queries the OSV.dev API to resolve ecosystem-native fixed versions for
vulnerable packages identified by PURL.  Uses batch queries for efficiency
and SQLite caching to minimise redundant API calls.

No authentication required.  No documented rate limits.

See: https://google.github.io/osv.dev/api/
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"
OSV_QUERY_URL = f"{OSV_API_BASE}/query"
OSV_BATCH_URL = f"{OSV_API_BASE}/querybatch"

# Batch size limit per OSV docs
_MAX_BATCH_SIZE = 1000
_REQUEST_TIMEOUT = 30
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 2.0
# Default cache TTL: 12 hours (OSV data updates frequently)
_DEFAULT_CACHE_TTL = 43200


@dataclass
class OSVFixResult:
    """Fix version resolution result for a single package."""

    purl: str
    fixed_version: str = ""
    introduced_version: str = ""
    source_id: str = ""  # OSV/GHSA/CVE ID of the advisory
    ecosystem: str = ""
    all_fixed_versions: list[str] = field(default_factory=list)

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed_version)


class OSVClient:
    """OSV API client with SQLite-backed caching.

    Resolves ecosystem-native fixed versions for vulnerable packages
    identified by PURL.  Supports batch queries (up to 1000 per request)
    for efficient portfolio-scale resolution.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        cache_ttl: int = _DEFAULT_CACHE_TTL,
    ) -> None:
        self._cache_ttl = cache_ttl
        self._db_lock = threading.Lock()
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        self._request_count = 0
        self._cache_hits = 0

        # SQLite cache
        resolved_dir = Path(cache_dir) if cache_dir else Path.home() / ".fs-report"
        resolved_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = resolved_dir / "osv_cache.db"
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Create the SQLite cache table if it doesn't exist."""
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("""CREATE TABLE IF NOT EXISTS osv_fix_cache (
                purl TEXT PRIMARY KEY,
                data_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            )""")
        self._conn.commit()

    def close(self) -> None:
        """Close the persistent SQLite connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Cache operations
    # -----------------------------------------------------------------------

    def _get_cached(self, purl: str) -> OSVFixResult | None:
        """Retrieve a cached result, respecting TTL."""
        if not self._conn:
            return None
        with self._db_lock:
            try:
                row = self._conn.execute(
                    "SELECT data_json, fetched_at FROM osv_fix_cache WHERE purl = ?",
                    (purl,),
                ).fetchone()
                if row:
                    fetched_at = datetime.fromisoformat(row["fetched_at"])
                    if fetched_at.tzinfo is None:
                        fetched_at = fetched_at.replace(tzinfo=UTC)
                    age = (datetime.now(UTC) - fetched_at).total_seconds()
                    if age < self._cache_ttl:
                        data = json.loads(row["data_json"])
                        return OSVFixResult(**data)
                    logger.debug(f"OSV cache expired for {purl} ({age:.0f}s old)")
            except Exception as e:
                logger.debug(f"OSV cache read error for {purl}: {e}")
        return None

    def _save_cached(self, result: OSVFixResult) -> None:
        """Persist a result to SQLite cache."""
        if not self._conn:
            return
        with self._db_lock:
            try:
                data = {
                    "purl": result.purl,
                    "fixed_version": result.fixed_version,
                    "introduced_version": result.introduced_version,
                    "source_id": result.source_id,
                    "ecosystem": result.ecosystem,
                    "all_fixed_versions": result.all_fixed_versions,
                }
                self._conn.execute(
                    """INSERT OR REPLACE INTO osv_fix_cache
                       (purl, data_json, fetched_at) VALUES (?, ?, ?)""",
                    (result.purl, json.dumps(data), datetime.now(UTC).isoformat()),
                )
                self._conn.commit()
            except Exception as e:
                logger.debug(f"OSV cache write error for {result.purl}: {e}")

    def _save_batch_cached(self, results: list[OSVFixResult]) -> None:
        """Persist multiple results to SQLite cache in a single transaction."""
        if not self._conn or not results:
            return
        with self._db_lock:
            try:
                rows = []
                now = datetime.now(UTC).isoformat()
                for r in results:
                    data = {
                        "purl": r.purl,
                        "fixed_version": r.fixed_version,
                        "introduced_version": r.introduced_version,
                        "source_id": r.source_id,
                        "ecosystem": r.ecosystem,
                        "all_fixed_versions": r.all_fixed_versions,
                    }
                    rows.append((r.purl, json.dumps(data), now))
                self._conn.executemany(
                    """INSERT OR REPLACE INTO osv_fix_cache
                       (purl, data_json, fetched_at) VALUES (?, ?, ?)""",
                    rows,
                )
                self._conn.commit()
            except Exception as e:
                logger.debug(f"OSV batch cache write error: {e}")

    # -----------------------------------------------------------------------
    # API operations
    # -----------------------------------------------------------------------

    def query(self, purl: str) -> OSVFixResult:
        """Query OSV for a single package by PURL.

        Args:
            purl: Package URL (e.g. "pkg:npm/lodash@4.17.4").

        Returns:
            OSVFixResult with the resolved fix version(s).
        """
        cached = self._get_cached(purl)
        if cached is not None:
            self._cache_hits += 1
            return cached

        payload = {"package": {"purl": purl}}
        result = self._make_request(OSV_QUERY_URL, payload)
        fix_result = self._extract_fix_from_response(purl, result)
        self._save_cached(fix_result)
        return fix_result

    def batch_resolve(
        self,
        purls: list[str],
        progress_callback: Any | None = None,
    ) -> dict[str, OSVFixResult]:
        """Resolve fix versions for multiple packages in batch.

        Uses the OSV /v1/querybatch endpoint for efficiency.
        Results are cached individually.

        Args:
            purls: List of Package URLs to resolve.
            progress_callback: Optional callable(completed, total) for progress.

        Returns:
            Dict mapping PURL -> OSVFixResult.
        """
        results: dict[str, OSVFixResult] = {}
        uncached_purls: list[str] = []

        # Check cache first
        for purl in purls:
            if not purl:
                continue
            cached = self._get_cached(purl)
            if cached is not None:
                self._cache_hits += 1
                results[purl] = cached
            else:
                uncached_purls.append(purl)

        if not uncached_purls:
            logger.info(f"OSV: all {len(results)} PURLs resolved from cache")
            return results

        logger.info(f"OSV: {len(results)} cached, {len(uncached_purls)} to query")

        # Batch query in chunks of _MAX_BATCH_SIZE
        total = len(uncached_purls)
        completed = 0

        for i in range(0, total, _MAX_BATCH_SIZE):
            chunk = uncached_purls[i : i + _MAX_BATCH_SIZE]
            batch_results = self._batch_query(chunk)

            new_results = []
            for purl in chunk:
                fix_result = batch_results.get(purl, OSVFixResult(purl=purl))
                results[purl] = fix_result
                new_results.append(fix_result)

            # Cache this batch
            self._save_batch_cached(new_results)

            completed += len(chunk)
            if progress_callback:
                progress_callback(completed, total)

        logger.info(
            f"OSV resolution complete: {self._request_count} API calls, "
            f"{self._cache_hits} cache hits"
        )
        return results

    def _batch_query(self, purls: list[str]) -> dict[str, OSVFixResult]:
        """Execute a single batch query against OSV."""
        queries = [{"package": {"purl": purl}} for purl in purls]
        payload = {"queries": queries}

        response_data = self._make_request(OSV_BATCH_URL, payload)
        results: dict[str, OSVFixResult] = {}

        # Response format: {"results": [{"vulns": [...]}, {"vulns": [...]}, ...]}
        response_results = response_data.get("results", [])
        for idx, purl in enumerate(purls):
            if idx < len(response_results):
                vulns_data = response_results[idx]
                result = self._extract_fix_from_batch_entry(purl, vulns_data)
            else:
                result = OSVFixResult(purl=purl)
            results[purl] = result

        return results

    def _make_request(self, url: str, payload: dict) -> dict:
        """Make an HTTP request to OSV with retries."""
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._session.post(
                    url,
                    json=payload,
                    timeout=_REQUEST_TIMEOUT,
                )
                self._request_count += 1

                if resp.status_code == 200:
                    return dict(resp.json())
                elif resp.status_code == 429:
                    wait = _RETRY_BACKOFF_BASE * (2**attempt)
                    logger.warning(f"OSV rate limited, waiting {wait:.0f}s")
                    time.sleep(wait)
                    continue
                else:
                    logger.warning(
                        f"OSV API error {resp.status_code}: {resp.text[:200]}"
                    )
                    return {}
            except requests.RequestException as e:
                if attempt < _MAX_RETRIES - 1:
                    wait = _RETRY_BACKOFF_BASE * (2**attempt)
                    logger.warning(f"OSV request failed, retrying in {wait:.0f}s: {e}")
                    time.sleep(wait)
                else:
                    logger.error(
                        f"OSV request failed after {_MAX_RETRIES} attempts: {e}"
                    )
                    return {}
        return {}

    # -----------------------------------------------------------------------
    # Response parsing
    # -----------------------------------------------------------------------

    def _extract_fix_from_response(self, purl: str, response: dict) -> OSVFixResult:
        """Extract fix version(s) from a single-query OSV response."""
        vulns = response.get("vulns", [])
        return self._extract_fix_from_vulns(purl, vulns)

    def _extract_fix_from_batch_entry(self, purl: str, entry: dict) -> OSVFixResult:
        """Extract fix version(s) from a batch query response entry."""
        vulns = entry.get("vulns", [])
        return self._extract_fix_from_vulns(purl, vulns)

    def _extract_fix_from_vulns(self, purl: str, vulns: list[dict]) -> OSVFixResult:
        """Extract the best fix version from a list of OSV vulnerability records.

        Selects the highest fixed version across all advisories to ensure
        all known vulnerabilities are resolved.
        """
        if not vulns:
            return OSVFixResult(purl=purl)

        all_fixed: list[str] = []
        best_fix = ""
        best_source = ""
        introduced = ""
        ecosystem = ""

        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            for affected in vuln.get("affected", []):
                # Match by PURL or package name
                pkg = affected.get("package", {})
                pkg_purl = pkg.get("purl", "")
                pkg_ecosystem = pkg.get("ecosystem", "")

                if pkg_purl and pkg_purl != purl:
                    # Different package — skip
                    continue

                if pkg_ecosystem:
                    ecosystem = pkg_ecosystem

                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fix_ver = str(event["fixed"])
                            all_fixed.append(fix_ver)
                            # Use the latest fix version
                            if not best_fix or _version_gt(fix_ver, best_fix):
                                best_fix = fix_ver
                                best_source = vuln_id
                        elif "introduced" in event:
                            intro = str(event["introduced"])
                            if intro != "0":
                                introduced = intro

        return OSVFixResult(
            purl=purl,
            fixed_version=best_fix,
            introduced_version=introduced,
            source_id=best_source,
            ecosystem=ecosystem,
            all_fixed_versions=sorted(set(all_fixed)),
        )

    def batch_check_vulnerable(
        self,
        versioned_purls: list[str],
    ) -> dict[str, tuple[bool, list[str]]]:
        """Check whether specific versioned PURLs are themselves vulnerable.

        Queries OSV with each versioned PURL (e.g. ``pkg:npm/lodash@4.17.21``).
        If OSV returns any vulnerabilities for that version, the version is
        considered affected.

        Args:
            versioned_purls: List of versioned PURLs to check.

        Returns:
            Dict mapping PURL → (is_vulnerable, vuln_ids).
        """
        results: dict[str, tuple[bool, list[str]]] = {}
        if not versioned_purls:
            return results

        # Query OSV in batches
        for i in range(0, len(versioned_purls), _MAX_BATCH_SIZE):
            chunk = versioned_purls[i : i + _MAX_BATCH_SIZE]
            queries = [{"package": {"purl": purl}} for purl in chunk]
            payload = {"queries": queries}

            response_data = self._make_request(OSV_BATCH_URL, payload)
            response_results = response_data.get("results", [])

            for idx, purl in enumerate(chunk):
                if idx < len(response_results):
                    vulns = response_results[idx].get("vulns", [])
                    vuln_ids = [v.get("id", "") for v in vulns if v.get("id")]
                    results[purl] = (bool(vuln_ids), vuln_ids)
                else:
                    results[purl] = (False, [])

        return results

    def get_stats(self) -> dict[str, int]:
        """Return API call and cache statistics."""
        return {
            "api_calls": self._request_count,
            "cache_hits": self._cache_hits,
        }


def _version_gt(a: str, b: str) -> bool:
    """Heuristic version comparison: is *a* greater than *b*?

    Handles common versioning schemes (semver, date-based, etc.)
    by splitting on dots and comparing segments numerically where possible.
    """

    def _segments(v: str) -> list[int | str]:
        parts: list[int | str] = []
        for seg in v.split("."):
            # Strip pre-release suffixes for numeric comparison
            numeric = ""
            for ch in seg:
                if ch.isdigit():
                    numeric += ch
                else:
                    break
            if numeric:
                parts.append(int(numeric))
            else:
                parts.append(seg)
        return parts

    seg_a = _segments(a)
    seg_b = _segments(b)

    for sa, sb in zip(seg_a, seg_b, strict=False):
        if isinstance(sa, int) and isinstance(sb, int):
            if sa != sb:
                return sa > sb
        else:
            str_a, str_b = str(sa), str(sb)
            if str_a != str_b:
                return str_a > str_b

    return len(seg_a) > len(seg_b)
