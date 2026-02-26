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

"""API client for communicating with the Finite State REST API."""

import json
import json.decoder
import logging
import os
import random
import shutil
import tempfile
import time
from json.decoder import JSONDecodeError
from typing import Any, cast

import httpx
from httpx import HTTPStatusError
from tqdm import tqdm

from fs_report.data_cache import DataCache
from fs_report.models import Config, QueryConfig, QueryParams
from fs_report.sqlite_cache import SQLiteCache

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_PERMANENT_STATUS_CODES = frozenset({400, 401, 403, 404, 405, 409, 422})


def _is_retryable(status_code: int) -> bool:
    """Return True if the HTTP status code is transient and worth retrying."""
    if status_code in _RETRYABLE_STATUS_CODES:
        return True
    if status_code in _PERMANENT_STATUS_CODES:
        return False
    # Unknown 5xx → retryable; unknown 4xx → permanent
    return status_code >= 500


class APIClient:
    """Client for interacting with the Finite State REST API."""

    def __init__(
        self,
        config: Config,
        cache: DataCache | None = None,
        sqlite_cache: SQLiteCache | None = None,
        cache_ttl: int = 0,
    ) -> None:
        """
        Initialize the API client.

        Args:
            config: Application configuration
            cache: Legacy in-memory cache (for backwards compatibility)
            sqlite_cache: SQLite-based cache with TTL support [BETA]
            cache_ttl: Cache TTL in seconds. 0 = no cross-run caching (default)
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = cache or DataCache()
        self.cache_ttl = cache_ttl
        self.request_delay = getattr(config, "request_delay", 0.5)
        # Track retries in the most recent fetch call so callers (e.g. the
        # version-batching loop) can adapt cooldowns after server errors.
        self.last_fetch_retries: int = 0

        # Initialize SQLite cache if TTL is set or explicitly provided
        if sqlite_cache:
            self.sqlite_cache: SQLiteCache | None = sqlite_cache
        elif cache_ttl > 0:
            self.sqlite_cache = SQLiteCache(
                cache_dir=getattr(config, "cache_dir", None),
                default_ttl=cache_ttl,
                domain=config.domain,  # Domain-specific cache file
            )
        else:
            # No SQLite cache by default (for backwards compatibility)
            self.sqlite_cache = None

        # Suppress httpx HTTP request logging unless verbose
        if not config.verbose:
            logging.getLogger("httpx").setLevel(logging.WARNING)

        # Setup HTTP client
        self.base_url = f"https://{config.domain}/api"
        self.headers = {
            "X-Authorization": config.auth_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Initialize HTTP client with timeout and retry logic
        self.client = httpx.Client(
            timeout=httpx.Timeout(30.0),
            headers=self.headers,
        )

    def fetch_data(self, query: QueryConfig) -> list[dict[str, Any]]:
        """Fetch a single page of data from the API based on query configuration."""
        self.logger.debug(f"Fetching data from endpoint: {query.endpoint}")

        # Check cache first
        cached_data = self.cache.get(query)
        if cached_data is not None:
            self.logger.debug(
                f"Using cached data for {query.endpoint} ({len(cached_data)} records)"
            )
            return cached_data

        # Build URL
        url = f"{self.base_url}{query.endpoint}"

        # Prepare query parameters
        params: dict[str, str] = {}
        if query.params.filter:
            endpoint_str = getattr(query, "endpoint", "") or ""
            self.logger.debug(
                f"Substituting variables for endpoint: {endpoint_str}, filter: {query.params.filter}"
            )
            params["filter"] = self._substitute_variables(
                query.params.filter, endpoint_str
            )
        if query.params.sort:
            params["sort"] = query.params.sort
        if query.params.limit is not None:
            params["limit"] = str(query.params.limit)
        if query.params.offset is not None:
            params["offset"] = str(query.params.offset)
        if query.params.archived is not None:
            params["archived"] = str(query.params.archived).lower()
        if query.params.excluded is not None:
            params["excluded"] = str(query.params.excluded).lower()
        if query.params.finding_type:
            params["type"] = query.params.finding_type

        # Log the actual API request parameters
        self.logger.debug(f"Actual API request params: {params}")

        try:
            self.logger.debug(f"Making API request to {url} with params {params}")
            response = self.client.get(url, params=params, timeout=60)
            self.logger.debug(f"API response received for {url}")
            response.raise_for_status()
            data = response.json()

            # Handle different API response formats
            # Some endpoints return a list directly, others return {"items": [...]} or {"scans": [...]}
            if isinstance(data, list):
                # Filter out null/empty rows (can appear for archived/excluded items)
                data = [rec for rec in data if rec]
                self.logger.debug(
                    f"Retrieved {len(data)} records (single page, list format)"
                )
                # Cache the data for this page
                self.cache.put(query, data)
                return data
            elif isinstance(data, dict):
                # Check for common pagination response formats
                items = data.get("items") or data.get("scans") or data.get("data")
                if items and isinstance(items, list):
                    self.logger.debug(
                        f"Retrieved {len(items)} records (single page, object format with items/scans/data key)"
                    )
                    # Cache the data for this page
                    self.cache.put(query, items)
                    return cast(list[dict[str, Any]], items)
                else:
                    # Single record as dict
                    self.logger.debug("Retrieved single record (dict format)")
                    result = [data] if data else []
                    self.cache.put(query, result)
                    return result
            else:
                self.logger.debug("Retrieved single record")
                result = [data] if data else []
                self.cache.put(query, result)
                return result
        except HTTPStatusError as e:
            status_code = e.response.status_code
            if status_code == 401:
                raise ValueError(
                    f"Authentication failed: Check your API token. Response: {e.response.text}"
                ) from e
            elif status_code == 403:
                raise ValueError(
                    f"Access denied: You may not have permission to access this resource. Response: {e.response.text}"
                ) from e
            elif status_code == 429:
                raise ValueError(
                    f"Rate limit exceeded: Please wait and try again. Response: {e.response.text}"
                ) from e
            else:
                raise ValueError(
                    f"API request failed: {status_code} - {e.response.text}"
                ) from e
        except httpx.RequestError as e:
            raise ValueError(f"Network error: {e}") from e
        except Exception as e:
            self.logger.error(f"Error fetching data from {url}: {e}")
            raise

    def fetch_all_with_resume(
        self,
        query: Any,
        progress_file: str | None = None,
        max_retries: int = 8,
        show_progress: bool = True,
        skip_cache_store: bool = False,
    ) -> list[dict]:
        """
        Fetch all paginated results with robust retry, progress logging, and resume support.

        If SQLite cache is enabled (cache_ttl > 0), uses SQLite for efficient storage
        and crash recovery. Otherwise, falls back to JSON progress files.

        Args:
            query: Query configuration
            progress_file: Path to progress file for resume support (legacy, ignored with SQLite)
            max_retries: Maximum retry attempts
            show_progress: Whether to show tqdm progress bar (disable when nested in another progress bar)
            skip_cache_store: If True, bypass SQLite cache read/write entirely.
                            Used when the caller handles per-entity caching (e.g., per-version
                            storage after batch fetch) to avoid duplicating data in SQLite.
        """
        # Reset retry counter so callers can check after the fetch completes
        self.last_fetch_retries = 0

        # Use SQLite cache if available (unless caller is handling storage)
        if self.sqlite_cache is not None and not skip_cache_store:
            return self._fetch_all_with_sqlite(query, max_retries, show_progress)

        # Bypass SQLite: fetch from API with pagination and retry logic (no SQLite read/write)
        if self.sqlite_cache is not None and skip_cache_store:
            return self._fetch_all_no_cache(query, max_retries, show_progress)

        # Fall back to legacy JSON-based progress
        return self._fetch_all_with_json_progress(
            query, progress_file, max_retries, show_progress
        )

    def _fetch_all_with_sqlite(
        self, query: Any, max_retries: int = 8, show_progress: bool = True
    ) -> list[dict]:
        """
        Fetch all paginated results using SQLite cache for storage and crash recovery.

        [BETA] This method uses the new SQLite-based caching system.

        Args:
            query: Query configuration
            max_retries: Maximum retry attempts
            show_progress: Whether to show tqdm progress bar
        """
        assert self.sqlite_cache is not None, "SQLite cache must be initialized"
        endpoint = query.endpoint
        params = {
            "filter": query.params.filter,
            "sort": query.params.sort,
            "limit": query.params.limit,
            "archived": query.params.archived,
            "excluded": query.params.excluded,
            "finding_type": query.params.finding_type,
        }
        params = {k: v for k, v in params.items() if v is not None}

        # Check if we have valid cached data
        if self.sqlite_cache.is_cache_valid(endpoint, params, self.cache_ttl):
            cached_data = self.sqlite_cache.get_cached_data(endpoint, params)
            if cached_data:
                self.logger.info(
                    f"Using SQLite cached data for {endpoint} ({len(cached_data)} records)"
                )
                return cached_data

        # Check for incomplete fetch (crash recovery)
        existing_count = self.sqlite_cache.get_progress(endpoint, params)
        offset = existing_count

        if existing_count > 0:
            self.logger.info(
                f"Resuming from SQLite cache: {existing_count} records already fetched"
            )
            query_hash = self.sqlite_cache.start_fetch(endpoint, params, self.cache_ttl)
            # Don't clear existing data - we're resuming
        else:
            # Start a new fetch
            query_hash = self.sqlite_cache.start_fetch(endpoint, params, self.cache_ttl)

        # Fetch remaining data
        limit = getattr(query.params, "limit", 10000) or 10000
        consecutive_empty_pages = 0
        max_consecutive_empty = 3
        retry_count = 0
        total_stored = existing_count
        seen_ids: set[str] = set()  # Track IDs to detect duplicates

        bar_desc = f"           Fetching {endpoint}"
        pbar = tqdm(
            total=None,
            desc=bar_desc,
            ncols=100,
            bar_format="{desc} |{bar}| {n_fmt} records",
            disable=not show_progress,
            initial=existing_count,
        )

        fetch_completed = False
        try:
            while True:
                page_query = query.model_copy(deep=True)
                page_query.params.offset = offset

                self.logger.debug(f"Fetching: {endpoint} offset={offset} limit={limit}")

                try:
                    page = self._fetch_page_direct(page_query)
                    self.logger.debug(
                        f"Fetched page with {len(page) if page else 0} records at offset {offset}"
                    )
                except httpx.HTTPStatusError as e:
                    status = e.response.status_code
                    if not _is_retryable(status):
                        self.logger.error(
                            f"Permanent HTTP {status} at offset {offset}: {str(e)[:200]}. Not retrying."
                        )
                        break
                    retry_count += 1
                    self.last_fetch_retries += 1
                    retry_after = e.response.headers.get("Retry-After")
                    if retry_after:
                        try:
                            wait = float(retry_after)
                        except ValueError:
                            wait = min(30 * retry_count, 120)
                    elif status in (429, 500, 502, 503, 504):
                        # Server overloaded / rate limited: use longer backoff
                        wait = min(30 * retry_count, 120)
                    else:
                        wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                    label = (
                        "Rate limited (429)"
                        if status == 429
                        else f"Server error ({status})"
                    )
                    self.logger.warning(
                        f"{label} at offset {offset}. "
                        f"Waiting {wait:.0f}s (attempt {retry_count}/{max_retries})..."
                    )
                    if retry_count > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset} (last error: HTTP {status}). Aborting."
                        )
                        break
                    time.sleep(wait)
                    continue
                except Exception as e:
                    retry_count += 1
                    self.last_fetch_retries += 1
                    wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                    self.logger.warning(
                        f"Error at offset {offset}: {e}. "
                        f"Retrying in {wait:.1f}s (attempt {retry_count}/{max_retries})..."
                    )
                    if retry_count > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset}. Aborting."
                        )
                        break
                    time.sleep(wait)
                    continue

                retry_count = 0

                # Filter out null/empty rows (can appear for archived/excluded items)
                page = [rec for rec in page if rec] if page else page

                if not page:
                    consecutive_empty_pages += 1
                    self.logger.debug(
                        f"Empty page at offset {offset} (consecutive empty: {consecutive_empty_pages})"
                    )
                    if consecutive_empty_pages >= max_consecutive_empty:
                        self.logger.debug(
                            f"Stopping pagination after {consecutive_empty_pages} consecutive empty pages."
                        )
                        fetch_completed = True
                        break
                    offset += limit
                    continue

                consecutive_empty_pages = 0

                # Check for duplicate records — only stop when ALL are duplicates
                page_ids: set[str] = {
                    str(rec.get("id")) for rec in page if rec.get("id")
                }
                duplicates = page_ids & seen_ids
                if page_ids and duplicates == page_ids:
                    self.logger.debug(
                        f"All {len(page_ids)} records at offset {offset} are duplicates. Stopping pagination."
                    )
                    fetch_completed = True
                    break
                if duplicates:
                    self.logger.debug(
                        f"Found {len(duplicates)}/{len(page_ids)} duplicate record IDs at offset {offset}; continuing."
                    )

                seen_ids.update(page_ids)

                # Store records in SQLite cache (atomic, crash-safe)
                stored = self.sqlite_cache.store_records(query_hash, endpoint, page)
                total_stored += stored
                offset += limit

                pbar.update(stored)
                self.logger.debug(
                    f"Stored {stored} records in SQLite cache (total: {total_stored})"
                )

                # Throttle between pages to avoid overloading the server
                if self.request_delay > 0:
                    time.sleep(self.request_delay)

        finally:
            pbar.close()

        # Mark fetch as complete only on clean loop exits
        if fetch_completed:
            self.sqlite_cache.complete_fetch(query_hash)
        self.logger.debug(
            f"Fetch complete: {total_stored} records stored in SQLite cache"
        )

        # Return all records from cache
        return self.sqlite_cache.get_cached_data(endpoint, params) or []

    def _fetch_all_no_cache(
        self, query: Any, max_retries: int = 8, show_progress: bool = True
    ) -> list[dict]:
        """
        Fetch all paginated results from API without SQLite caching.

        Used when the caller handles entity-level caching (e.g., splitting batch
        results and storing per-version). Provides the same retry and pagination
        logic as _fetch_all_with_sqlite but skips all SQLite read/write.

        Args:
            query: Query configuration
            max_retries: Maximum retry attempts
            show_progress: Whether to show tqdm progress bar
        """
        endpoint = query.endpoint
        limit = getattr(query.params, "limit", 10000) or 10000
        offset = 0
        consecutive_empty_pages = 0
        max_consecutive_empty = 3
        retry_count = 0
        all_results = []
        seen_ids: set[str] = set()

        bar_desc = f"           Fetching {endpoint}"
        pbar = tqdm(
            total=None,
            desc=bar_desc,
            ncols=100,
            bar_format="{desc} |{bar}| {n_fmt} records",
            disable=not show_progress,
        )

        try:
            while True:
                page_query = query.model_copy(deep=True)
                page_query.params.offset = offset

                self.logger.debug(
                    f"Fetching (no-cache): {endpoint} offset={offset} limit={limit}"
                )

                try:
                    page = self._fetch_page_direct(page_query)
                    self.logger.debug(
                        f"Fetched page with {len(page) if page else 0} records at offset {offset}"
                    )
                except httpx.HTTPStatusError as e:
                    status = e.response.status_code
                    if not _is_retryable(status):
                        self.logger.error(
                            f"Permanent HTTP {status} at offset {offset}: {str(e)[:200]}. Not retrying."
                        )
                        break
                    retry_count += 1
                    self.last_fetch_retries += 1
                    retry_after = e.response.headers.get("Retry-After")
                    if retry_after:
                        try:
                            wait = float(retry_after)
                        except ValueError:
                            wait = min(30 * retry_count, 120)
                    elif status in (429, 500, 502, 503, 504):
                        # Server overloaded / rate limited: use longer backoff
                        wait = min(30 * retry_count, 120)
                    else:
                        wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                    label = (
                        "Rate limited (429)"
                        if status == 429
                        else f"Server error ({status})"
                    )
                    self.logger.warning(
                        f"{label} at offset {offset}. "
                        f"Waiting {wait:.0f}s (attempt {retry_count}/{max_retries})..."
                    )
                    if retry_count > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset} (last error: HTTP {status}). Aborting."
                        )
                        break
                    time.sleep(wait)
                    continue
                except Exception as e:
                    retry_count += 1
                    self.last_fetch_retries += 1
                    wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                    self.logger.warning(
                        f"Error at offset {offset}: {e}. "
                        f"Retrying in {wait:.1f}s (attempt {retry_count}/{max_retries})..."
                    )
                    if retry_count > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset}. Aborting."
                        )
                        break
                    time.sleep(wait)
                    continue

                retry_count = 0
                page = [rec for rec in page if rec] if page else page

                if not page:
                    consecutive_empty_pages += 1
                    self.logger.debug(
                        f"Empty page at offset {offset} (consecutive empty: {consecutive_empty_pages})"
                    )
                    if consecutive_empty_pages >= max_consecutive_empty:
                        break
                    offset += limit
                    continue

                consecutive_empty_pages = 0

                page_ids: set[str] = {
                    str(rec.get("id")) for rec in page if rec.get("id")
                }
                duplicates = page_ids & seen_ids
                if duplicates:
                    self.logger.debug(
                        f"Found {len(duplicates)} duplicate record IDs at offset {offset}. Stopping pagination."
                    )
                    break

                seen_ids.update(page_ids)
                all_results.extend(page)
                offset += limit

                pbar.update(len(page))

                if self.request_delay > 0:
                    time.sleep(self.request_delay)

        finally:
            pbar.close()

        self.logger.debug(f"Fetched {len(all_results)} records (no-cache mode)")
        return all_results

    def _fetch_page_direct(self, query: QueryConfig) -> list[dict[str, Any]]:
        """
        Fetch a single page of data directly from API (bypassing in-memory cache).

        Used by SQLite cache fetcher to avoid double-caching.
        """
        url = f"{self.base_url}{query.endpoint}"

        params: dict[str, str] = {}
        if query.params.filter:
            params["filter"] = self._substitute_variables(
                query.params.filter, query.endpoint
            )
        if query.params.sort:
            params["sort"] = query.params.sort
        if query.params.limit is not None:
            params["limit"] = str(query.params.limit)
        if query.params.offset is not None:
            params["offset"] = str(query.params.offset)
        if query.params.archived is not None:
            params["archived"] = str(query.params.archived).lower()
        if query.params.excluded is not None:
            params["excluded"] = str(query.params.excluded).lower()
        if query.params.finding_type:
            params["type"] = query.params.finding_type

        response = self.client.get(url, params=params, timeout=120)
        response.raise_for_status()
        data = response.json()

        # Handle different API response formats
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            items = data.get("items") or data.get("scans") or data.get("data")
            if items and isinstance(items, list):
                return cast(list[dict[str, Any]], items)
            return [data] if data else []
        return [data] if data else []

    def _fetch_all_with_json_progress(
        self,
        query: Any,
        progress_file: str | None = None,
        max_retries: int = 8,
        show_progress: bool = True,
    ) -> list[dict]:
        """
        Legacy fetch method using JSON progress files.

        DEPRECATED: This method will be removed in a future release.
        Use --cache-ttl to enable the new SQLite-based caching which provides:
        - ~80% smaller storage through field trimming
        - Better crash recovery
        - Optional cross-run caching with TTL

        Stores progress/results in a JSON file (progress_file). Resumes from last offset if interrupted.

        Args:
            query: Query configuration
            progress_file: Path to progress file for resume support
            max_retries: Maximum retry attempts
            show_progress: Whether to show tqdm progress bar
        """
        import warnings

        warnings.warn(
            "JSON progress files are deprecated. Use --cache-ttl to enable SQLite caching.",
            DeprecationWarning,
            stacklevel=2,
        )
        # Check cache first
        cached_data = self.cache.get(query)
        if cached_data is not None:
            self.logger.info(
                f"Using cached data for {query.endpoint} ({len(cached_data)} records)"
            )
            return cached_data

        # Only proceed with API calls if not using cache
        offset = 0
        all_results = []
        limit = getattr(query.params, "limit", 10000) or 10000
        consecutive_empty_pages = 0
        max_consecutive_empty = 3  # Stop after 3 consecutive empty pages
        self.logger.debug(
            f"fetch_all_with_resume called for endpoint: {getattr(query, 'endpoint', None)}, progress_file: {progress_file}"
        )
        if not progress_file:
            # Default: output/findings_progress.json or output/{endpoint}_progress.json
            endpoint = query.endpoint.strip("/").replace("/", "_")
            progress_file = os.path.join(
                self.config.output_dir, f"{endpoint}_progress.json"
            )
        # Resume support
        if os.path.exists(progress_file):
            try:
                with open(progress_file) as f:
                    progress = json.load(f)
                    offset = progress.get("offset", 0)
                    all_results = progress.get("results", [])
                self.logger.info(
                    f"Resuming from offset {offset}, {len(all_results)} records already fetched."
                )
            except JSONDecodeError as e:
                self.logger.warning(
                    f"Progress file {progress_file} is corrupted: {e}. Deleting and starting over."
                )
                os.remove(progress_file)
                offset = 0
                all_results = []
        retry_count = 0
        using_cache = False
        try:
            # TQDM progress bar setup (disabled when nested in another progress context)
            bar_desc = f"           Fetching {getattr(query, 'endpoint', '')}"
            pbar = tqdm(
                total=None,
                desc=bar_desc,
                ncols=100,
                bar_format="{desc} |{bar}| {n_fmt} records",
                disable=not show_progress,
            )

            while True:
                page_query = query.model_copy(deep=True)
                page_query.params.offset = offset
                self.logger.debug(
                    f"Fetching: {query.endpoint} offset={offset} limit={limit}"
                )
                try:
                    # Log query parameters
                    self.logger.debug(
                        f"Query params: {getattr(page_query, 'params', None)}"
                    )
                    self.logger.debug(
                        f"Actual API request params: {getattr(page_query, 'params', None)}"
                    )
                    self.logger.debug(
                        f"Making API request to {self.config.domain}{query.endpoint} with params {getattr(page_query, 'params', None)}"
                    )
                    # Check if this page will come from cache
                    cached_check = self.cache.get(page_query)
                    if cached_check is not None and not using_cache:
                        # Update progress bar to indicate cache usage
                        using_cache = True
                        pbar.set_description_str(
                            f"           Using cache for {getattr(query, 'endpoint', '')}"
                        )

                    page = self.fetch_data(page_query)
                    self.logger.debug(
                        f"API response received for {self.config.domain}{query.endpoint}"
                    )
                    self.logger.debug(
                        f"Fetched page with {len(page) if page else 0} records at offset {offset}"
                    )
                    # Log first 5 record IDs (if present)
                    if page and isinstance(page, list) and len(page) > 0:
                        ids = [rec.get("id", "<no id>") for rec in page[:5]]
                        self.logger.debug(
                            f"First 5 record IDs at offset {offset}: {ids}"
                        )
                except Exception as e:
                    # Handle rate limit (429) or network error - retry silently
                    wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                    self.logger.debug(
                        f"Transient error at offset {offset}: {e}. Retrying in {wait:.1f}s..."
                    )
                    time.sleep(wait)
                    retry_count += 1
                    self.last_fetch_retries += 1
                    if retry_count > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset}. Aborting."
                        )
                        break
                    continue
                retry_count = 0  # Reset on success
                # Filter out null/empty rows (can appear for archived/excluded items)
                page = [rec for rec in page if rec] if page else page
                if not page:
                    consecutive_empty_pages += 1
                    self.logger.debug(
                        f"Empty page at offset {offset} (consecutive empty: {consecutive_empty_pages})"
                    )
                    if consecutive_empty_pages >= max_consecutive_empty:
                        self.logger.debug(
                            f"Stopping pagination after {consecutive_empty_pages} consecutive empty pages."
                        )
                        break
                    offset += limit
                    continue

                consecutive_empty_pages = 0  # Reset on successful page

                # Check for duplicate records — only stop when ALL are duplicates
                if all_results and len(page) > 0:
                    page_ids = {rec.get("id") for rec in page if rec.get("id")}
                    existing_ids = {
                        rec.get("id") for rec in all_results if rec.get("id")
                    }
                    duplicates = page_ids & existing_ids
                    if page_ids and duplicates == page_ids:
                        self.logger.debug(
                            f"All {len(page_ids)} records at offset {offset} are duplicates. Stopping pagination."
                        )
                        break
                    if duplicates:
                        self.logger.debug(
                            f"Found {len(duplicates)}/{len(page_ids)} duplicate record IDs at offset {offset}; continuing."
                        )

                all_results.extend(page)
                offset += limit
                # Progress logging (atomic write)
                tempdir = os.path.dirname(progress_file) or "."
                with tempfile.NamedTemporaryFile("w", delete=False, dir=tempdir) as tf:
                    json.dump({"offset": offset, "results": all_results}, tf)
                    tempname = tf.name
                shutil.move(tempname, progress_file)
                pbar.update(len(page))
                self.logger.debug(
                    f"Fetched {len(all_results)} records so far (page had {len(page)} records). Progress saved to {progress_file}."
                )

                # Throttle between pages to avoid overloading the server
                if self.request_delay > 0:
                    time.sleep(self.request_delay)

                # Continue pagination until we get an empty page or duplicates
                # Don't stop just because a page has fewer than limit records - the API may return
                # fewer records on the last page, but we should continue to check for more
                # The loop will continue and check the next page, which will be empty if we've reached the end
        finally:
            pbar.close()
        self.logger.debug(f"Total records fetched: {len(all_results)}")
        # Clean up progress file after successful fetch
        if os.path.exists(progress_file):
            try:
                os.remove(progress_file)
                self.logger.debug(
                    f"Progress file {progress_file} removed after successful fetch."
                )
            except Exception as e:
                self.logger.warning(
                    f"Could not remove progress file {progress_file}: {e}"
                )
        return all_results

    def _substitute_variables(self, filter_expr: str, endpoint: str = "") -> str:
        """Substitute date variables in filter expressions."""
        from datetime import datetime

        # Convert date strings to UTC datetime format
        start_dt = datetime.fromisoformat(self.config.start_date).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        end_dt = datetime.fromisoformat(self.config.end_date).replace(
            hour=23, minute=59, second=59, microsecond=999999
        )

        # Format as UTC datetime strings
        # Findings endpoint expects format without Z suffix (e.g., "2025-02-25T14:23:00")
        # Other endpoints may require Z suffix
        # Check for findings endpoint (case-insensitive, handles /public/v0/findings or /findings)
        is_findings_endpoint = "/findings" in endpoint.lower() if endpoint else False
        if is_findings_endpoint:
            start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
            end_str = end_dt.strftime("%Y-%m-%dT%H:%M:%S")
            self.logger.debug(
                f"Formatting dates for findings endpoint (no Z): {start_str} to {end_str}"
            )
        else:
            # For other endpoints, use Z suffix
            start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
            end_str = end_dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
            self.logger.debug(
                f"Formatting dates for other endpoint (with Z): {start_str} to {end_str}, endpoint={endpoint}"
            )

        # Replace ${start} and ${end} with actual datetime strings
        result = filter_expr.replace("${start}", start_str)
        result = result.replace("${end}", end_str)

        # Replace ${baseline_version} and ${current_version} if present
        if "${baseline_version}" in result and self.config.baseline_version:
            result = result.replace("${baseline_version}", self.config.baseline_version)
        if "${current_version}" in result and self.config.current_version:
            result = result.replace("${current_version}", self.config.current_version)

        # Log the substitution for debugging
        if "${start}" in filter_expr or "${end}" in filter_expr:
            self.logger.debug(f"Date filter substitution: {filter_expr} -> {result}")
        if "${baseline_version}" in filter_expr or "${current_version}" in filter_expr:
            self.logger.debug(f"Version filter substitution: {filter_expr} -> {result}")

        return result

    def test_connection(self) -> bool:
        """Test the API connection and authentication."""
        try:
            # Try to fetch a small amount of data from a simple endpoint
            test_query = QueryConfig(
                endpoint="/public/v0/projects",
                params=QueryParams(limit=1),
            )
            self.fetch_data(test_query)
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        stats = self.cache.get_stats()
        if self.sqlite_cache:
            stats["sqlite_cache"] = self.sqlite_cache.get_stats()
        return stats

    def clear_cache(self) -> None:
        """Clear the data cache."""
        self.cache.clear()
        if self.sqlite_cache:
            self.sqlite_cache.clear()

    def fetch_sbom(
        self,
        project_version_id: int,
        sbom_format: str = "cyclonedx",
        include_vex: bool = True,
    ) -> dict[str, Any]:
        """Download a CycloneDX or SPDX SBOM for a project version.

        Args:
            project_version_id: Numeric project version ID.
            sbom_format: ``"cyclonedx"`` or ``"spdx"``.
            include_vex: Whether to include VEX vulnerability data.

        Returns:
            Parsed SBOM JSON as a Python dict.

        Raises:
            httpx.HTTPStatusError: If the API returns an error status.
        """
        url = f"{self.base_url}/public/v0/sboms/{sbom_format}/{project_version_id}"
        params: dict[str, str] = {}
        if include_vex:
            params["includeVex"] = "true"

        self.logger.debug(f"Fetching SBOM for version {project_version_id}")
        response = self.client.get(url, params=params, timeout=120)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        self.logger.debug(
            f"SBOM fetched for version {project_version_id}: "
            f"{len(data.get('components', []))} components"
        )
        return data

    def __enter__(self) -> "APIClient":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.client.close()

    def __del__(self) -> None:
        """Close the HTTP client if not already closed."""
        try:
            if hasattr(self, "client") and not self.client.is_closed:
                self.client.close()
        except Exception:
            pass
