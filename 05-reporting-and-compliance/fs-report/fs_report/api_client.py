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

import hashlib
import json
import json.decoder
import logging
import math
import os
import random
import shutil
import tempfile
import time
from json.decoder import JSONDecodeError
from typing import Any, NamedTuple, cast

import httpx
from httpx import HTTPStatusError
from tqdm import tqdm

from fs_report.data_cache import DataCache
from fs_report.models import Config, QueryConfig, QueryParams
from fs_report.sqlite_cache import CacheClaimLost, SQLiteCache

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_PERMANENT_STATUS_CODES = frozenset({400, 401, 403, 404, 405, 409, 422})


def _retry_wait(retry_after: str | None, retry_count: int) -> float:
    """Seconds to wait before re-asking a server that failed a retryable call.

    Honours the server's own ``Retry-After`` when it sent a usable one, else a
    30s/60s/90s ladder capped at 120s. Not exponential-from-1s: a gateway
    timeout takes ~30s to come back, so a 1s wait just re-asks a server that is
    still busy. An unusable header — non-numeric, negative, NaN, infinite — is
    ignored rather than fatal, and an extravagant one is clamped to the same
    ceiling the ladder obeys. Every paginator routes its pacing through here, so
    one header behaves the same way whatever the cache mode.
    """
    ladder = float(min(30 * (retry_count + 1), 120))
    if retry_after:
        try:
            requested = float(retry_after)
        except (TypeError, ValueError):
            return ladder
        # A server may ask for something unusable: negative, NaN, infinite, or
        # an hour. Honour the request only within the same bounds the ladder
        # obeys — an unusable value falls back rather than reaching time.sleep,
        # which would itself raise on a negative or non-finite wait.
        if not math.isfinite(requested) or requested < 0:
            return ladder
        return min(requested, 120.0)
    return ladder


# Page sizes a paginated fetch falls back through when the server reports it
# could not finish a page in time. The /findings 504 body is explicit about
# what it wants:
#     {"errors":[{"error":"Database query timed out. Try narrowing the
#      request or retrying."}]}
# Re-sending the SAME oversized page cannot satisfy that — the query costs what
# it costs however long we wait — so narrow first and only fall back on waiting
# once the ladder bottoms out.
_PAGE_SIZE_LADDER = (10000, 5000, 2000, 1000)

# Retries allowed once the page size is already at the ladder's floor. A DB
# timeout on a 1,000-row page may still be a genuinely transient blip, so give
# it a couple of paced attempts — but not the full 8-deep ladder, which spent
# 13 minutes on a query that was never going to complete.
_DB_TIMEOUT_FLOOR_RETRIES = 2

_DB_TIMEOUT_MARKER = "database query timed out"


def _is_db_timeout(body: str | None) -> bool:
    """True when a 5xx body says the backend's own query timed out.

    Distinguishes "this request is too expensive" from "this server is busy".
    The two need opposite responses: narrow the request vs. wait for load to
    pass, and treating the first as the second is what made a doomed fetch take
    13 minutes to fail.
    """
    if not body:
        return False
    return _DB_TIMEOUT_MARKER in body.lower()


def _narrow_page_size(limit: int) -> int | None:
    """Next page size strictly below ``limit``, or None at/below the floor.

    A caller-chosen size that is already smaller than the floor (e.g. a 100-row
    probe) has nothing to narrow to and returns None — if the backend cannot
    serve 100 rows, 1,000 will not help either.

    Only the ordering and the floor matter, never the top rung: a `limit` above
    every rung (a raised ``max_page_size``) still narrows, to the largest rung
    below it. So the ladder cannot silently stop working if the page-size cap
    moves.
    """
    for candidate in _PAGE_SIZE_LADDER:
        if candidate < limit:
            return candidate
    return None


class _PageRetryPlan(NamedTuple):
    """What to do about one failed page of a paginated fetch.

    ``action`` is one of:
      ``narrow``     — retry the same offset at ``limit``, immediately.
      ``wait``       — normal transient-load ladder; sleep ``wait`` and retry.
      ``wait_floor`` — DB timeout at the smallest page size; sleep and retry,
                       against the shorter floor budget.
      ``abort``      — give up and raise; ``message`` says why.
    """

    action: str
    limit: int
    wait: float
    message: str


def _plan_page_retry(
    *,
    status: int,
    body: str | None,
    retry_after: str | None,
    offset: int,
    limit: int,
    retry_count: int,
    db_floor_retries: int,
    max_retries: int,
) -> _PageRetryPlan:
    """Decide how a paginator should respond to a retryable page error.

    Pure so the policy can be tested without a server. ``retry_count`` and
    ``db_floor_retries`` are the counts BEFORE this failure, so the caller
    increments only for the branch the plan actually selects.

    Every paginated path routes its retry policy through here, so the SQLite,
    no-cache and legacy-JSON loops cannot drift apart on it.
    """
    # Narrowing is gated on a 5xx, not on the body alone. 429 means "you are
    # asking too often" — it must be paced, and pacing is the one thing
    # narrowing skips. A rate-limit body that happens to quote a database
    # timeout (a wrapped upstream message) would otherwise jump the ladder.
    if status >= 500 and _is_db_timeout(body):
        narrowed = _narrow_page_size(limit)
        if narrowed is not None:
            return _PageRetryPlan(
                action="narrow",
                limit=narrowed,
                wait=0.0,
                message=(
                    f"Server could not complete a {limit}-record page at offset "
                    f"{offset} (HTTP {status}: database query timed out). "
                    f"Narrowing to limit={narrowed} and retrying."
                ),
            )
        if db_floor_retries >= _DB_TIMEOUT_FLOOR_RETRIES:
            return _PageRetryPlan(
                action="abort",
                limit=limit,
                wait=0.0,
                message=(
                    f"Database query timed out at offset {offset} on the "
                    f"smallest page size (limit={limit}) after "
                    f"{_DB_TIMEOUT_FLOOR_RETRIES} retries. Narrowing the "
                    f"request did not help and waiting will not either. "
                    f"Aborting."
                ),
            )
        wait = _retry_wait(retry_after, db_floor_retries)
        return _PageRetryPlan(
            action="wait_floor",
            limit=limit,
            wait=wait,
            message=(
                f"Database query timed out at offset {offset} on the smallest "
                f"page size (limit={limit}). Waiting {wait:.0f}s (floor retry "
                f"{db_floor_retries + 1}/{_DB_TIMEOUT_FLOOR_RETRIES})..."
            ),
        )

    if retry_count >= max_retries:
        return _PageRetryPlan(
            action="abort",
            limit=limit,
            wait=0.0,
            message=(
                f"Max retries exceeded at offset {offset} "
                f"(last error: HTTP {status}). Aborting."
            ),
        )

    if retry_after or status == 429 or status >= 500:
        # Server overloaded / rate limited: honour its pacing request within
        # bounds, else the longer ladder. The condition tracks what
        # `_is_retryable` admits (429 plus ANY 5xx) rather than a literal list
        # of five codes — an odd-but-retryable 507/521/599 was dropping to the
        # ~2s exponential branch and re-asking a still-dead gateway.
        wait = _retry_wait(retry_after, retry_count)
    else:
        wait = (2 ** min(retry_count + 1, 6)) + random.uniform(0, 1)
    label = "Rate limited (429)" if status == 429 else f"Server error ({status})"
    return _PageRetryPlan(
        action="wait",
        limit=limit,
        wait=wait,
        message=(
            f"{label} at offset {offset}. Waiting {wait:.0f}s "
            f"(attempt {retry_count + 1}/{max_retries})..."
        ),
    )


class APIRequestError(ValueError):
    """An API request that failed with an HTTP status, after its own retries.

    Subclasses ``ValueError`` because that is what ``fetch_data`` has always
    raised and callers catch it by that type. The addition is ``status_code``:
    without it, a caller can only classify the failure by matching the message
    prefix, which cannot tell a permanent 4xx from a retryable 504 (CST-967).
    """

    def __init__(
        self, message: str, status_code: int, retry_after: str | None = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        # The server's own pacing request, when it sent one. Captured at the
        # raise site because the response object does not survive the raise.
        self.retry_after = retry_after


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
        cache_refresh: bool = False,
    ) -> None:
        """
        Initialize the API client.

        Args:
            config: Application configuration
            cache: Legacy in-memory cache (for backwards compatibility)
            sqlite_cache: SQLite-based cache with TTL support [BETA]
            cache_ttl: Cache TTL in seconds. 0 = no cross-run caching (default)
            cache_refresh: If True, bypass cache reads but still write fresh
                data to cache for future runs.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = cache or DataCache()
        self.cache_ttl = cache_ttl
        self.cache_refresh = cache_refresh
        self.request_delay = getattr(config, "request_delay", 0.5)
        # Track retries in the most recent fetch call so callers (e.g. the
        # version-batching loop) can adapt cooldowns after server errors.
        self.last_fetch_retries: int = 0
        # Page size this client has learned an endpoint cannot serve, per
        # endpoint, for the life of the run. A narrowing is otherwise a local
        # in one paginator call, and the version-batching loop issues ONE call
        # per batch — so a 140-batch fetch re-escalated to the full page size
        # and re-earned the same gateway timeout 140 times. Keyed on the
        # endpoint because the cost is a property of the endpoint and tenant,
        # not of the particular filter. Never widened, only narrowed.
        self._learned_page_size: dict[str, int] = {}

        # Initialize SQLite cache if TTL is set or explicitly provided
        if sqlite_cache:
            self.sqlite_cache: SQLiteCache | None = sqlite_cache
        elif cache_ttl > 0:
            self.sqlite_cache = SQLiteCache(
                cache_dir=getattr(config, "cache_dir", None),
                default_ttl=cache_ttl,
                domain=config.domain,  # Domain-specific cache file
                # Account identity. Without this the cache file is shared by
                # every tenant on this host, and a cached fetch from one account
                # is served to another (see fs_report/tenant_scope.py).
                auth_token=getattr(config, "auth_token", None),
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

        self.max_page_size: int = 10000

    def _apply_learned_page_size(self, endpoint: str, limit: int) -> int:
        """Start a fetch at a page size this run has already proven servable.

        Returns ``limit`` unchanged when nothing has been learned for the
        endpoint, or when what was learned is no smaller than what the caller
        asked for — the memory only ever narrows.
        """
        learned = self._learned_page_size.get(endpoint)
        if learned is not None and learned < limit:
            self.logger.debug(
                f"Starting {endpoint} at limit={learned}: this run already saw "
                f"the server fail to complete a larger page."
            )
            return learned
        return limit

    def _remember_page_size(self, endpoint: str, limit: int) -> None:
        """Record a page size that actually returned a page.

        Called on SUCCESS, never at the moment of narrowing: a fetch that walks
        the whole ladder and still aborts has proven nothing except that the
        endpoint is unservable, and recording the floor there would make every
        later fetch on it pay 10x the round trips for no benefit.
        """
        previous = self._learned_page_size.get(endpoint)
        if previous is None or limit < previous:
            self._learned_page_size[endpoint] = limit

    def fetch_data(
        self, query: QueryConfig, *, defer_db_timeout: bool = False
    ) -> list[dict[str, Any]]:
        """Fetch a single page of data from the API based on query configuration.

        Args:
            query: Query configuration.
            defer_db_timeout: Skip the inner retries for a backend
                query-timeout 5xx and raise at once, so a *paginating* caller
                can narrow the page instead — the one response that can help,
                which three same-size retries only delay. Off by default
                because it is a loss for every direct caller
                (``resolve_project``, ``test_connection``, per-component
                fan-outs): they have no page to narrow, so dropping their
                retries would just fail sooner.
        """
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
            params["limit"] = str(min(query.params.limit, self.max_page_size))
        if query.params.offset is not None:
            params["offset"] = str(query.params.offset)
        if query.params.archived is not None:
            params["archived"] = str(query.params.archived).lower()
        if query.params.excluded is not None:
            params["excluded"] = str(query.params.excluded).lower()
        if query.params.finding_type:
            params["type"] = query.params.finding_type
        if query.params.include_additional_details is not None:
            params["includeAdditionalDetails"] = str(
                query.params.include_additional_details
            ).lower()

        # Log the actual API request parameters
        self.logger.debug(f"Actual API request params: {params}")

        _max_retries = 3
        for _attempt in range(_max_retries + 1):
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
                    # Use sentinel to distinguish "key absent" from "key present but empty list"
                    _sentinel = object()
                    items = data.get("items", _sentinel)
                    if items is _sentinel:
                        items = data.get("scans", _sentinel)
                    if items is _sentinel:
                        items = data.get("data", _sentinel)
                    if items is not _sentinel and isinstance(items, list):
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
                if (
                    _is_retryable(status_code)
                    and _attempt < _max_retries
                    and not (
                        defer_db_timeout
                        and status_code >= 500
                        and _is_db_timeout(e.response.text)
                    )
                ):
                    # Transient error — back off and retry. A backend query
                    # timeout is excluded only for a paginating caller that
                    # asked to handle it (defer_db_timeout): narrowing the page
                    # is the one response that can help, and three same-size
                    # retries here only delay it. A direct caller keeps its
                    # retries — it has no page to narrow.
                    _wait = (2**_attempt) + random.uniform(0, 1)
                    self.logger.warning(
                        f"{status_code} on {query.endpoint}, "
                        f"retry {_attempt + 1}/{_max_retries} in {_wait:.1f}s"
                    )
                    time.sleep(_wait)
                    continue
                # Permanent error or retries exhausted. Every one of these
                # carries its status: a caller that can only read the message
                # cannot tell a permanent 401 from a retryable 429, which is
                # the defect this class exists to close (CST-967). Message text
                # is deliberately unchanged.
                retry_after = e.response.headers.get("Retry-After")
                if status_code == 401:
                    raise APIRequestError(
                        f"Authentication failed: Check your API token. Response: {e.response.text}",
                        status_code,
                        retry_after,
                    ) from e
                elif status_code == 403:
                    raise APIRequestError(
                        f"Access denied: You may not have permission to access this resource. Response: {e.response.text}",
                        status_code,
                        retry_after,
                    ) from e
                elif status_code == 429:
                    raise APIRequestError(
                        f"Rate limit exceeded: Please wait and try again. Response: {e.response.text}",
                        status_code,
                        retry_after,
                    ) from e
                else:
                    raise APIRequestError(
                        f"API request failed: {status_code} - {e.response.text}",
                        status_code,
                        retry_after,
                    ) from e
            except httpx.RequestError as e:
                raise ValueError(f"Network error: {e}") from e
            except Exception as e:
                self.logger.error(f"Error fetching data from {url}: {e}")
                raise
        # Should never reach here (loop always returns or raises), but satisfy type checker
        raise RuntimeError(f"fetch_data exhausted retries for {url}")

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

        If SQLite cache is enabled (cache_ttl > 0), uses SQLite: a fetch is cached
        only once it completes, and an interrupted one restarts from the first page
        (no mid-fetch resume). Otherwise, falls back to JSON progress files, which
        do resume from the last offset after an interruption.

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
        Fetch all paginated results using the SQLite cache. Caches only complete
        fetches; an interrupted one is refetched from page one (see start_fetch).

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

        # Check if we have valid cached data (skip when refreshing)
        if not self.cache_refresh and self.sqlite_cache.is_cache_valid(
            endpoint, params, self.cache_ttl
        ):
            cached_data = self.sqlite_cache.get_cached_data(endpoint, params)
            if cached_data:
                self.logger.info(
                    f"Using SQLite cached data for {endpoint} ({len(cached_data)} records)"
                )
                return cached_data

        # Claim the entry. If another run is fetching this query right now, the
        # claim fails and this run fetches on its own without touching that
        # run's rows. A claim always starts empty: an interrupted fetch is
        # re-run from the first page, never resumed (see start_fetch).
        query_hash = self.sqlite_cache.start_fetch(endpoint, params, self.cache_ttl)
        if query_hash is None:
            self.logger.info(
                f"Another run is fetching {endpoint}; fetching it without the cache"
            )
            return self._fetch_all_no_cache(query, max_retries, show_progress)
        offset = 0

        # Fetch remaining data
        limit = getattr(query.params, "limit", self.max_page_size) or self.max_page_size
        limit = min(limit, self.max_page_size)
        resolved_limit = limit
        narrowed_limit = self._apply_learned_page_size(endpoint, limit)
        # Pin an explicit wire `limit` ONLY once we have deliberately changed
        # the page size (a learned narrowing here, or a narrowing later in the
        # loop). Comparing against the RESOLVED limit, not the query's raw one:
        # a QueryParams with limit unset resolves to max_page_size internally
        # but previously sent NO limit param, and forcing one in would be a
        # silent wire change on a backend this client already documents as
        # 400ing on limit>1000.
        page_size_pinned = narrowed_limit != limit
        limit = narrowed_limit
        consecutive_empty_pages = 0
        max_consecutive_empty = 3
        retry_count = 0
        db_floor_retries = 0
        total_stored = 0
        seen_ids: set[str] = set()  # Track IDs to detect duplicates

        bar_desc = f"           Fetching {endpoint}"
        pbar = tqdm(
            total=None,
            desc=bar_desc,
            ncols=100,
            bar_format="{desc} |{bar}| {n_fmt} records",
            disable=not show_progress,
        )

        fetch_completed = False
        claim_lost = False
        try:
            while True:
                page_query = query.model_copy(deep=True)
                page_query.params.offset = offset
                # Make the loop's own `limit` authoritative for the request, so
                # a narrowed page size actually reaches the wire. The cache key
                # (`params`, resolved once above) deliberately keeps the
                # ORIGINAL limit: narrowing is a transport detail and must not
                # split one logical fetch across two cache entries.
                if page_size_pinned:
                    page_query.params.limit = limit

                self.logger.debug(f"Fetching: {endpoint} offset={offset} limit={limit}")

                try:
                    page = self._fetch_page_direct(page_query)
                    self.logger.debug(
                        f"Fetched page with {len(page) if page else 0} records at offset {offset}"
                    )
                except httpx.HTTPStatusError as e:
                    status = e.response.status_code
                    if not _is_retryable(status):
                        # Some endpoints (e.g. /versions/{vid}/components) signal
                        # end-of-pagination with HTTP 404 once offset exceeds the
                        # total count, instead of returning an empty page. Treat
                        # that as a clean stop rather than a permanent error.
                        if status == 404 and total_stored > 0:
                            self.logger.debug(
                                f"HTTP 404 at offset {offset} after {total_stored} records: "
                                f"treating as end-of-pagination."
                            )
                            fetch_completed = True
                            break
                        # Surface permanent client errors (e.g. helix's 400 on
                        # limit>1000) instead of silently returning the partial
                        # result fetched so far. Callers must see backend
                        # contract failures.
                        raise ValueError(
                            f"API request failed at offset {offset}: "
                            f"{status} - {str(e.response.text)[:500]}"
                        ) from e
                    plan = _plan_page_retry(
                        status=status,
                        body=e.response.text,
                        retry_after=e.response.headers.get("Retry-After"),
                        offset=offset,
                        limit=limit,
                        retry_count=retry_count,
                        db_floor_retries=db_floor_retries,
                        max_retries=max_retries,
                    )
                    if plan.action != "narrow":
                        # report_engine reads last_fetch_retries to decide the
                        # server is struggling and needs a sustained elevated
                        # inter-batch cooldown. A narrowing is request-cost
                        # adaptation, not load, so counting it there would slow
                        # every following batch for a condition that waiting
                        # does not fix.
                        self.last_fetch_retries += 1
                    if plan.action == "abort":
                        self.logger.error(plan.message)
                        # Same wire format as the permanent branch above, so
                        # callers written to the ValueError contract see this
                        # the same way whatever the cache mode.
                        raise APIRequestError(
                            f"API request failed at offset {offset}: "
                            f"{status} - {str(e.response.text)[:500]}",
                            status,
                        ) from e
                    # Warn only when a retry actually follows. The old order
                    # logged "Waiting 120s (attempt 9/8)" and then aborted in
                    # the same millisecond, so the last line of a failed fetch
                    # promised a wait that never happened.
                    self.logger.warning(plan.message)
                    # Keep the claim alive across retries, narrowing included:
                    # a quiet claim past FETCH_STALE_SECONDS can be taken over.
                    self.sqlite_cache.touch_fetch(query_hash)
                    if plan.action == "narrow":
                        # A smaller page is a different request, not another go
                        # at the same one — so both retry budgets reset.
                        limit = plan.limit
                        page_size_pinned = True
                        retry_count = 0
                        db_floor_retries = 0
                        continue
                    if plan.action == "wait_floor":
                        db_floor_retries += 1
                    else:
                        retry_count += 1
                    time.sleep(plan.wait)
                    continue
                except Exception as e:
                    self.last_fetch_retries += 1
                    wait = (2 ** min(retry_count + 1, 6)) + random.uniform(0, 1)
                    # Exhaustion checked BEFORE the warning, same as the
                    # status-bearing branch above: otherwise this path prints
                    # its own "attempt 9/8" promising a wait it never takes.
                    if retry_count + 1 > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset} "
                            f"(last error: {e}). Aborting."
                        )
                        break
                    retry_count += 1
                    self.logger.warning(
                        f"Error at offset {offset}: {e}. "
                        f"Retrying in {wait:.1f}s (attempt {retry_count}/{max_retries})..."
                    )
                    self.sqlite_cache.touch_fetch(query_hash)
                    time.sleep(wait)
                    continue

                # A page came back: both retry budgets reset. db_floor_retries
                # has to reset here too — left running, floor waits spent at an
                # early offset would abort a later one after fewer than its own
                # allowance, failing a long pagination because page 1 was slow.
                retry_count = 0
                db_floor_retries = 0
                # This size demonstrably works for this endpoint — record it so
                # sibling fetches in the same run skip the rungs that failed.
                if limit < resolved_limit:
                    self._remember_page_size(endpoint, limit)

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

        except CacheClaimLost:
            claim_lost = True
        except BaseException:
            # An error or Ctrl-C: release the claim so the next run starts clean
            # instead of waiting out FETCH_STALE_SECONDS. A cache failure here
            # must not replace the error the caller needs to see.
            try:
                self.sqlite_cache.abandon_fetch(query_hash, endpoint)
            except Exception as cleanup_error:
                self.logger.debug(f"Could not release cache claim: {cleanup_error}")
            raise
        finally:
            pbar.close()

        try:
            if claim_lost:
                raise CacheClaimLost(query_hash)
            if fetch_completed:
                # Marked complete and read back in one transaction.
                records = self.sqlite_cache.finish_fetch(query_hash, endpoint)
                self.logger.debug(
                    f"Fetch complete: {total_stored} records stored in SQLite cache"
                )
                return records
            # The loop gave up (retries exhausted): return what it fetched, as
            # before, but cache none of it.
            return self.sqlite_cache.get_cached_data(endpoint, params) or []
        except CacheClaimLost:
            # Another run took the entry over (this one went quiet past
            # FETCH_STALE_SECONDS); its rows are not this fetch's.
            self.logger.warning(
                f"Lost the cache entry for {endpoint} to another run; "
                "fetching it again without the cache"
            )
            return self._fetch_all_no_cache(query, max_retries, show_progress)
        finally:
            # A no-op once finished; a cache failure here must not replace the
            # records this function is returning.
            try:
                self.sqlite_cache.abandon_fetch(query_hash, endpoint)
            except Exception as cleanup_error:
                self.logger.debug(f"Could not release cache claim: {cleanup_error}")

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
        limit = getattr(query.params, "limit", self.max_page_size) or self.max_page_size
        limit = min(limit, self.max_page_size)
        resolved_limit = limit
        narrowed_limit = self._apply_learned_page_size(endpoint, limit)
        # See the SQLite paginator: pin a wire `limit` only once the page size
        # has deliberately changed from the resolved one.
        page_size_pinned = narrowed_limit != limit
        limit = narrowed_limit
        offset = 0
        consecutive_empty_pages = 0
        max_consecutive_empty = 3
        retry_count = 0
        db_floor_retries = 0
        all_results: list[dict] = []
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
                # See the SQLite paginator: the loop's `limit` must reach the
                # wire for page-size narrowing to do anything.
                if page_size_pinned:
                    page_query.params.limit = limit

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
                        # Some endpoints (e.g. /versions/{vid}/components) signal
                        # end-of-pagination with HTTP 404 once offset exceeds the
                        # total count, instead of returning an empty page. Treat
                        # that as a clean stop rather than a permanent error.
                        if status == 404 and len(all_results) > 0:
                            self.logger.debug(
                                f"HTTP 404 at offset {offset} after {len(all_results)} records: "
                                f"treating as end-of-pagination."
                            )
                            break
                        # Surface permanent client errors (e.g. helix's 400 on
                        # limit>1000) instead of silently returning the partial
                        # result fetched so far. Callers must see backend
                        # contract failures.
                        raise ValueError(
                            f"API request failed at offset {offset}: "
                            f"{status} - {str(e.response.text)[:500]}"
                        ) from e
                    plan = _plan_page_retry(
                        status=status,
                        body=e.response.text,
                        retry_after=e.response.headers.get("Retry-After"),
                        offset=offset,
                        limit=limit,
                        retry_count=retry_count,
                        db_floor_retries=db_floor_retries,
                        max_retries=max_retries,
                    )
                    if plan.action != "narrow":
                        # report_engine reads last_fetch_retries to decide the
                        # server is struggling and needs a sustained elevated
                        # inter-batch cooldown. A narrowing is request-cost
                        # adaptation, not load, so counting it there would slow
                        # every following batch for a condition that waiting
                        # does not fix.
                        self.last_fetch_retries += 1
                    if plan.action == "abort":
                        self.logger.error(plan.message)
                        # Same wire format as the permanent branch above, so
                        # callers written to the ValueError contract see this
                        # the same way whatever the cache mode.
                        raise APIRequestError(
                            f"API request failed at offset {offset}: "
                            f"{status} - {str(e.response.text)[:500]}",
                            status,
                        ) from e
                    # Warn only when a retry actually follows. The old order
                    # logged "Waiting 120s (attempt 9/8)" and then aborted in
                    # the same millisecond, so the last line of a failed fetch
                    # promised a wait that never happened.
                    self.logger.warning(plan.message)
                    if plan.action == "narrow":
                        # A smaller page is a different request, not another go
                        # at the same one — so both retry budgets reset.
                        limit = plan.limit
                        page_size_pinned = True
                        retry_count = 0
                        db_floor_retries = 0
                        continue
                    if plan.action == "wait_floor":
                        db_floor_retries += 1
                    else:
                        retry_count += 1
                    time.sleep(plan.wait)
                    continue
                except Exception as e:
                    self.last_fetch_retries += 1
                    wait = (2 ** min(retry_count + 1, 6)) + random.uniform(0, 1)
                    # Exhaustion checked BEFORE the warning, same as the
                    # status-bearing branch above: otherwise this path prints
                    # its own "attempt 9/8" promising a wait it never takes.
                    if retry_count + 1 > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset} "
                            f"(last error: {e}). Aborting."
                        )
                        break
                    retry_count += 1
                    self.logger.warning(
                        f"Error at offset {offset}: {e}. "
                        f"Retrying in {wait:.1f}s (attempt {retry_count}/{max_retries})..."
                    )
                    time.sleep(wait)
                    continue

                # A page came back: both retry budgets reset. db_floor_retries
                # has to reset here too — left running, floor waits spent at an
                # early offset would abort a later one after fewer than its own
                # allowance, failing a long pagination because page 1 was slow.
                retry_count = 0
                db_floor_retries = 0
                # This size demonstrably works for this endpoint — record it so
                # sibling fetches in the same run skip the rungs that failed.
                if limit < resolved_limit:
                    self._remember_page_size(endpoint, limit)
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
                # Same rule as the SQLite paginator: stop only when the whole
                # page is repeats, and keep a mixed page's new records. Stopping
                # at the first repeat dropped them, so a run on this path (e.g.
                # one that found another run fetching the same query) could get
                # fewer records than a cached run.
                duplicates = page_ids & seen_ids
                if page_ids and duplicates == page_ids:
                    self.logger.debug(
                        f"All {len(page_ids)} records at offset {offset} are duplicates. Stopping pagination."
                    )
                    break
                if duplicates:
                    self.logger.debug(
                        f"Found {len(duplicates)}/{len(page_ids)} duplicate record IDs at offset {offset}; continuing."
                    )
                    page = [
                        rec
                        for rec in page
                        if not rec.get("id") or str(rec.get("id")) not in seen_ids
                    ]

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
            params["limit"] = str(min(query.params.limit, self.max_page_size))
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
            _sentinel = object()
            items = data.get("items", _sentinel)
            if items is _sentinel:
                items = data.get("scans", _sentinel)
            if items is _sentinel:
                items = data.get("data", _sentinel)
            if items is not _sentinel and isinstance(items, list):
                return cast(list[dict[str, Any]], items)
            return [data] if data else []
        return [data] if data else []

    def _discard_progress(self, progress_file: str | None) -> None:
        """Delete a progress file we are abandoning as failed.

        Cleanup on the success path sits after the try/finally and is skipped
        when an exception propagates, so a failed fetch used to leave a file
        behind. A failed fetch now leaves no resumable state; an interrupted one
        (KeyboardInterrupt) still does, which is what resume is for.

        That file is only ever resumed by an identical query: the default name
        carries a hash of the query params, so a leftover file cannot be picked
        up by a differently-filtered fetch against the same endpoint.
        """
        if not progress_file:
            return
        try:
            if os.path.exists(progress_file):
                os.remove(progress_file)
                self.logger.debug(
                    f"Progress file {progress_file} discarded after a failed fetch."
                )
        except Exception as exc:  # pragma: no cover - best effort cleanup
            self.logger.warning(
                f"Could not discard progress file {progress_file}: {exc}"
            )

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
        - Safe interrupted and concurrent runs (complete fetches only)
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
        limit = getattr(query.params, "limit", self.max_page_size) or self.max_page_size
        limit = min(limit, self.max_page_size)
        resolved_limit = limit
        narrowed_limit = self._apply_learned_page_size(query.endpoint, limit)
        # See the SQLite paginator: pin a wire `limit` only once the page size
        # has deliberately changed from the resolved one.
        page_size_pinned = narrowed_limit != limit
        limit = narrowed_limit
        consecutive_empty_pages = 0
        max_consecutive_empty = 3  # Stop after 3 consecutive empty pages
        db_floor_retries = 0
        self.logger.debug(
            f"fetch_all_with_resume called for endpoint: {getattr(query, 'endpoint', None)}, progress_file: {progress_file}"
        )
        if not progress_file:
            # Default: output/{endpoint}-{query-hash}_progress.json.
            # The hash matters: a batched fetch issues hundreds of queries
            # against ONE endpoint, each with a different filter. Keyed on the
            # endpoint alone they all shared a file, so any run that left one
            # behind fed another batch's rows to the next run's first batch.
            endpoint = query.endpoint.strip("/").replace("/", "_")
            fingerprint = hashlib.sha256(
                repr(getattr(query, "params", None)).encode("utf-8")
            ).hexdigest()[:12]
            progress_file = os.path.join(
                self.config.output_dir, f"{endpoint}-{fingerprint}_progress.json"
            )
        # The progress file lives under config.output_dir, which the engine
        # does not create until render time (after the fetch). Ensure its
        # directory exists ONCE here so the atomic progress writes below don't
        # crash with FileNotFoundError on a fresh --output dir (regression:
        # `fs-report compare --output <new-dir>`).
        os.makedirs(os.path.dirname(progress_file) or ".", exist_ok=True)
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
                # See the SQLite paginator: the loop's `limit` must reach the
                # wire for page-size narrowing to do anything. This path caches
                # per page via `fetch_data`, so a narrowed page is simply a
                # different (correct) cache entry.
                if page_size_pinned:
                    page_query.params.limit = limit
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

                    # This paginator CAN narrow, so a backend query timeout
                    # should reach it rather than be retried in place.
                    page = self.fetch_data(page_query, defer_db_timeout=True)
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
                except ValueError as e:
                    # fetch_data raises ValueError for two distinct cases:
                    #   - Permanent backend contract failures
                    #     ("Authentication failed:", "Access denied:",
                    #     "API request failed: <4xx> - ..."). fetch_data has
                    #     already exhausted its internal retries; outer
                    #     retries won't help, and silently empty/partial
                    #     results would mask the failure. Surface these
                    #     loudly — this is the path that makes helix's
                    #     `400 limit ≤ 1000` fail-fast instead of producing
                    #     a blank report.
                    #   - Transient ("Network error: ...") and exhausted-
                    #     retry transient ("Rate limit exceeded: ..."). Let
                    #     the outer paginator's retry/back-off handle these.
                    msg = str(e)
                    # Endpoints like /versions/{vid}/components signal
                    # end-of-pagination with HTTP 404 once offset exceeds the
                    # total count. Treat that as a clean stop (same as the
                    # SQLite and no-cache paginators) — but only after we've
                    # accumulated some records, so a genuine 404-on-first-page
                    # still fails loud.
                    if "API request failed: 404" in msg and len(all_results) > 0:
                        self.logger.debug(
                            f"HTTP 404 at offset {offset} after "
                            f"{len(all_results)} records: treating as "
                            f"end-of-pagination."
                        )
                        break
                    # Classify on the STATUS, not the message. fetch_data
                    # flattens the status into the text, and the prefix
                    # "API request failed:" matches every exhausted status —
                    # so a 504 used to be re-raised as permanent, skipping the
                    # retry below, leaving last_fetch_retries at 0, and with it
                    # the server-recovery cooldown report_engine derives from
                    # that counter (CST-967).
                    status = getattr(e, "status_code", None)
                    if status is not None:
                        # Typed: the status decides, and the message never
                        # enters into it.
                        if not _is_retryable(status):
                            self._discard_progress(progress_file)
                            raise
                        retryable = True
                    else:
                        # Untyped ValueError from somewhere that does not carry
                        # a status. Fall back to the message prefixes.
                        retryable = False
                        permanent_prefixes = (
                            "Authentication failed:",
                            "Access denied:",
                            "API request failed:",
                        )
                        if msg.startswith(permanent_prefixes):
                            self._discard_progress(progress_file)
                            raise
                    # Fall through to transient-retry handling. Routed through
                    # the same planner as the other two paginators so the
                    # narrow-before-wait policy cannot drift between cache
                    # modes. `status` is None only on the untyped-and-transient
                    # path (e.g. "Network error: ..."), which has no HTTP status
                    # to plan on — 0 keeps it out of the 429/5xx pacing branch.
                    plan = _plan_page_retry(
                        status=status if status is not None else 0,
                        body=msg if retryable else None,
                        retry_after=getattr(e, "retry_after", None),
                        offset=offset,
                        limit=limit,
                        retry_count=retry_count,
                        db_floor_retries=db_floor_retries,
                        max_retries=max_retries,
                    )
                    if plan.action != "narrow":
                        # See the SQLite paginator: a narrowing is not a
                        # server-load signal and must not drive report_engine's
                        # elevated inter-batch cooldown.
                        self.last_fetch_retries += 1
                    if plan.action == "abort":
                        # Exhausted. This must stay LOUD whatever the error
                        # was: breaking here would return the rows fetched so
                        # far, i.e. a report silently missing data, presented
                        # as complete. Worse than failing.
                        self.logger.error(
                            plan.message
                            if status is not None
                            else (
                                f"Max retries exceeded at offset {offset} "
                                f"(last error: {msg}). Aborting."
                            )
                        )
                        self._discard_progress(progress_file)
                        raise
                    if plan.action == "narrow":
                        self.logger.warning(plan.message)
                        limit = plan.limit
                        page_size_pinned = True
                        retry_count = 0
                        db_floor_retries = 0
                        continue
                    if plan.action == "wait_floor":
                        self.logger.warning(plan.message)
                        db_floor_retries += 1
                    else:
                        retry_count += 1
                        # WARNING, not DEBUG. This is the default path
                        # (`--cache-ttl 0` attaches no SQLite cache), and at
                        # DEBUG an operator watching a stalled run during an
                        # incident saw nothing at all while the other two
                        # paginators logged every wait. An untyped error has
                        # no status for the planner's "Server error (N)" line,
                        # so it names the error itself.
                        self.logger.warning(
                            plan.message
                            if status is not None
                            else (
                                f"Transient error at offset {offset}: {msg}. "
                                f"Waiting {plan.wait:.0f}s "
                                f"(attempt {retry_count}/{max_retries})..."
                            )
                        )
                    time.sleep(plan.wait)
                    continue
                except Exception as e:
                    # Unhandled transient (e.g. JSON decode, unexpected) — retry
                    self.last_fetch_retries += 1
                    wait = (2 ** min(retry_count + 1, 6)) + random.uniform(0, 1)
                    # Exhaustion checked BEFORE sleeping and before the log
                    # line: this branch used to sleep out a full backoff and
                    # then give up, and announce a retry it never made.
                    if retry_count + 1 > max_retries:
                        self.logger.error(
                            f"Max retries exceeded at offset {offset} "
                            f"(last error: {e}). Aborting."
                        )
                        break
                    retry_count += 1
                    self.logger.warning(
                        f"Transient error at offset {offset}: {e}. "
                        f"Retrying in {wait:.1f}s (attempt {retry_count}/{max_retries})..."
                    )
                    time.sleep(wait)
                    continue
                # Reset BOTH budgets on success — see the SQLite paginator.
                retry_count = 0
                db_floor_retries = 0
                if limit < resolved_limit:
                    self._remember_page_size(query.endpoint, limit)
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
                # Progress logging (atomic write); the progress dir was
                # created once up-front (see above).
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

    def resolve_project(self, name_or_id: str | int) -> int | str | None:
        """Resolve a project name or ID to its API ID, preserving engine
        semantics from ReportEngine._resolve_project_name.

        Behavior (matches report_engine.py:860):
          - Empty input → None.
          - ID-shaped input (signed int, signed-int string, or UUID-like
            string) → returned as-is. The engine does not HEAD-validate;
            this helper doesn't either.
          - Name input → case-insensitive .lower() exact match against
            /public/v0/projects (limit=10000, archived=False, excluded=False).
            First match wins on duplicate names. Miss returns None and logs
            a "Did you mean?" close-match hint at INFO.

        Return type: int | str | None. Some FS tenants issue negative int64
        project IDs and others use UUID-like strings; both must pass through
        unchanged.

        Caches successful name lookups in self._project_resolve_cache so
        repeated lookups in a single run don't re-fetch /projects.
        """
        import re

        from fs_report.models import QueryConfig, QueryParams

        if name_or_id in (None, ""):
            return None

        if isinstance(name_or_id, int):
            return name_or_id

        value_str = str(name_or_id)
        if re.fullmatch(r"-?\d+", value_str):
            return value_str
        if re.match(r"^[0-9a-fA-F-]{32,36}$", value_str):
            return value_str

        cache: dict[str, int | str | None] = (
            getattr(self, "_project_resolve_cache", None) or {}
        )
        self._project_resolve_cache: dict[str, int | str | None] = cache
        key = value_str.strip().lower()
        if key in cache:
            return cache[key]

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        projects = self.fetch_data(projects_query)

        for p in projects:
            name = p.get("name", "") if isinstance(p, dict) else ""
            if name.lower() == key:
                project_id: int | str | None = (
                    p.get("id") if isinstance(p, dict) else None
                )
                cache[key] = project_id
                return project_id

        available = [
            p.get("name", "") for p in projects if isinstance(p, dict) and p.get("name")
        ]
        close = [n for n in available if key in n.lower()]
        if close:
            self.logger.info(f"Did you mean one of these? {close[:5]}")
        return None

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
        project_version_id: int | str,
        sbom_format: str = "cyclonedx",
        include_vex: bool = True,
    ) -> dict[str, Any]:
        """Download a CycloneDX or SPDX SBOM for a project version.

        Args:
            project_version_id: Project version ID (integer or UUID string).
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
