"""Finite State API client."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, TypeVar

import httpx
from pydantic import BaseModel

if TYPE_CHECKING:
    from fs_smartsheet.cache import SQLiteCache

from .models import (
    Component,
    Finding,
    FindingStatusUpdate,
    FolderDetail,
    Project,
    ProjectVersion,
    User,
)

T = TypeVar("T", bound=BaseModel)

logger = logging.getLogger(__name__)

# Retry configuration
RETRY_STATUS_CODES = {429, 502, 503, 504}
MAX_RETRIES = 8
MAX_RETRY_DELAY = 64


class FiniteStateError(Exception):
    """Base exception for Finite State API errors."""

    def __init__(self, message: str, status_code: int | None = None, response: Any = None):
        # Include response body in the message for debugging
        full_message = message
        if response:
            full_message = (
                f"{message} - Response: {response[:500] if len(str(response)) > 500 else response}"
            )
        super().__init__(full_message)
        self.status_code = status_code
        self.response = response


class FiniteStateClient:
    """Client for interacting with the Finite State API."""

    def __init__(
        self,
        domain: str,
        auth_token: str,
        timeout: float = 30.0,
        cache: SQLiteCache | None = None,
    ):
        """
        Initialize the Finite State client.

        Args:
            domain: Finite State domain (e.g., platform.finitestate.io)
            auth_token: API authentication token
            timeout: Request timeout in seconds
            cache: Optional SQLiteCache for persistent TTL-based caching.
                When provided, ``_paginate`` will serve results from the
                cache on hit and store fresh API pages on miss.
        """
        self.base_url = f"https://{domain}/api/public/v0"
        self.auth_token = auth_token
        self.timeout = timeout
        self.cache = cache
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"X-Authorization": self.auth_token},
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> FiniteStateClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        """Make an HTTP request to the API."""
        # Filter out None values from params
        if params:
            params = {k: v for k, v in params.items() if v is not None}

        response = await self.client.request(method, path, params=params, json=json)

        if response.status_code == 401:
            raise FiniteStateError("Unauthorized - check your API token", 401)
        if response.status_code == 403:
            raise FiniteStateError("Forbidden - insufficient permissions", 403)
        if response.status_code == 404:
            raise FiniteStateError(f"Not found: {path}", 404)
        if response.status_code >= 400:
            raise FiniteStateError(
                f"API error: {response.status_code}",
                response.status_code,
                response.text,
            )

        if response.status_code == 204:
            return None

        # Handle empty response bodies (e.g., 200 from /status/clear)
        if not response.content:
            return None

        return response.json()

    async def _request_with_retry(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        max_retries: int = MAX_RETRIES,
    ) -> Any:
        """
        Make an HTTP request with exponential backoff retry.

        Retries on 429 (rate limit), 502, 503, 504 (server errors).
        Uses exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 64s (capped)
        with random jitter of 0-1 seconds.

        Args:
            method: HTTP method
            path: API endpoint path
            params: Query parameters
            json: JSON body
            max_retries: Maximum number of retries

        Returns:
            API response

        Raises:
            FiniteStateError: If all retries fail or non-retryable error
        """
        for retry_count in range(max_retries):
            try:
                return await self._request(method, path, params=params, json=json)
            except FiniteStateError as e:
                # Only retry on specific status codes
                if e.status_code not in RETRY_STATUS_CODES:
                    raise

                if retry_count >= max_retries - 1:
                    raise

                # Exponential backoff with cap and jitter
                delay = min(2**retry_count, MAX_RETRY_DELAY) + random.uniform(0, 1)
                logger.warning(
                    f"Request failed ({e.status_code}), retry {retry_count + 1}/{max_retries} "
                    f"in {delay:.1f}s"
                )
                await asyncio.sleep(delay)

        # Should not reach here, but just in case
        raise FiniteStateError("Max retries exceeded", None)

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Make a GET request."""
        return await self._request("GET", path, params=params)

    async def _put(
        self, path: str, json: dict[str, Any] | None = None, params: dict[str, Any] | None = None
    ) -> Any:
        """Make a PUT request."""
        return await self._request("PUT", path, params=params, json=json)

    async def _post(
        self, path: str, json: dict[str, Any] | None = None, params: dict[str, Any] | None = None
    ) -> Any:
        """Make a POST request."""
        return await self._request("POST", path, params=params, json=json)

    async def _paginate(
        self,
        path: str,
        model: type[T],
        params: dict[str, Any] | None = None,
        limit: int = 1000,
        max_items: int | None = None,
    ) -> AsyncIterator[T]:
        """
        Paginate through API results.

        When a :class:`~fs_smartsheet.cache.SQLiteCache` is attached
        (``self.cache``), the paginator will:

        1. Check for a valid (completed, non-expired) cache entry.
        2. On **hit** — yield records from the cache (re-validated through
           ``model``).
        3. On **miss** — stream pages from the API as usual while buffering
           each page into the cache, then mark the entry complete.

        Args:
            path: API endpoint path
            model: Pydantic model class to parse results
            params: Additional query parameters
            limit: Items per page
            max_items: Maximum total items to return (None for all)

        Yields:
            Parsed model instances
        """
        params = params or {}

        # ── Cache-hit fast path ───────────────────────────────────────
        if self.cache is not None:
            # Build a *stable* copy of params for hashing (without the
            # pagination keys that _paginate itself mutates each page).
            cache_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}
            cache_params["_path"] = path  # include path in hash input

            if self.cache.is_cache_valid(path, cache_params):
                cached = self.cache.get_cached_data(path, cache_params)
                if cached is not None:
                    logger.info("Cache hit for %s (%d records)", path, len(cached))
                    items_returned = 0
                    for raw in cached:
                        if not raw:
                            continue
                        try:
                            yield model.model_validate(raw)
                            items_returned += 1
                            if max_items and items_returned >= max_items:
                                return
                        except Exception as ve:
                            logger.warning("Skipping invalid cached item: %s", ve)
                    return

            # Cache miss — start a new fetch entry
            query_hash = self.cache.start_fetch(path, cache_params)
        else:
            query_hash = None
            cache_params = None

        # ── Normal paginated fetch (with cache write-through) ─────────
        offset = 0
        items_returned = 0
        original_limit = limit

        while True:
            # Track what we actually request this page (for stop-condition)
            page_limit = limit
            params["limit"] = page_limit
            params["offset"] = offset

            try:
                data = await self._get(path, params)
            except FiniteStateError as e:
                # If we get a 400 error, try retrying with smaller page size
                # This might help if the issue is with a specific record in the batch
                if e.status_code == 400 and limit > 100:
                    logger.debug(
                        "API error at offset %d with limit %d, retrying smaller page...",
                        offset,
                        limit,
                    )
                    # Retry with smaller limit
                    retry_limit = min(limit // 2, 100)
                    page_limit = retry_limit
                    params["limit"] = retry_limit
                    try:
                        data = await self._get(path, params)
                        logger.info(f"Retry successful with limit {retry_limit}")
                        # Keep using smaller limit for subsequent pages
                        limit = retry_limit
                    except FiniteStateError:
                        # If retry also fails, try skipping ahead past the problematic range
                        logger.debug(
                            f"API error persists at offset {offset} even with smaller limit. "
                            f"Skipping past problematic offset range."
                        )
                        # Skip ahead by the original limit amount
                        offset += original_limit
                        # Reset limit for next iteration
                        limit = original_limit
                        continue
                else:
                    # For other errors or if already at small limit, just break
                    logger.debug(
                        f"API error during pagination (offset {offset}, limit {limit}): {e}. "
                        f"Stopping pagination with {items_returned} items fetched."
                    )
                    break
            else:
                # Success on first try — ramp limit back up for next page
                if limit < original_limit:
                    limit = original_limit

            if not data:
                break

            # Buffer raw page into cache (before Pydantic validation)
            if self.cache is not None and query_hash is not None:
                # Only store non-null items
                valid_items = [item for item in data if item]
                if valid_items:
                    self.cache.store_records(query_hash, valid_items)

            for item in data:
                # Skip null/empty rows (can appear for archived/excluded items)
                if not item:
                    continue
                try:
                    yield model.model_validate(item)
                    items_returned += 1
                    if max_items and items_returned >= max_items:
                        # Mark complete even on early exit so cache is usable
                        if self.cache is not None and query_hash is not None:
                            self.cache.complete_fetch(query_hash)
                        return
                except Exception as validation_error:
                    # Skip items that fail validation (bad data from API)
                    logger.warning(f"Skipping invalid item: {validation_error}")
                    continue

            # Stop when API returns fewer items than we asked for (last page)
            if len(data) < page_limit:
                break

            offset += page_limit
            logger.debug(f"Pagination: fetched {items_returned} items so far, next offset={offset}")

        # Mark fetch as complete so subsequent runs can reuse it
        if self.cache is not None and query_hash is not None:
            self.cache.complete_fetch(query_hash)

    # ==================== User ====================

    async def get_authenticated_user(self) -> User:
        """Get the currently authenticated user."""
        data = await self._get("/authUser")
        return User.model_validate(data)

    # ==================== Folders ====================

    async def get_folders(
        self,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[FolderDetail]:
        """
        Get a list of folders.

        Args:
            limit: Maximum number of folders to return
            offset: Offset for pagination
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        data = await self._get("/folders", params)
        return [FolderDetail.model_validate(f) for f in data]

    async def iter_folders(
        self,
        max_items: int | None = None,
    ) -> AsyncIterator[FolderDetail]:
        """Iterate through all folders with pagination."""
        async for folder in self._paginate("/folders", FolderDetail, {}, max_items=max_items):
            yield folder

    async def get_folder_tree(self) -> dict[str, FolderDetail]:
        """
        Fetch all folders and return a dict keyed by folder ID.

        This enables reconstructing the full folder tree using parentFolderId.
        """
        folders: dict[str, FolderDetail] = {}
        async for folder in self.iter_folders():
            folders[folder.id] = folder
        return folders

    # ==================== Projects ====================

    async def get_projects(
        self,
        limit: int = 1000,
        offset: int = 0,
        archived: bool | None = None,
    ) -> list[Project]:
        """
        Get a list of projects.

        Args:
            limit: Maximum number of projects to return
            offset: Offset for pagination
            archived: Filter by archived status
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if archived is not None:
            params["archived"] = archived

        data = await self._get("/projects", params)
        return [Project.model_validate(p) for p in data]

    async def iter_projects(
        self,
        archived: bool | None = None,
        max_items: int | None = None,
    ) -> AsyncIterator[Project]:
        """Iterate through all projects with pagination."""
        params: dict[str, Any] = {}
        if archived is not None:
            params["archived"] = archived

        async for project in self._paginate("/projects", Project, params, max_items=max_items):
            yield project

    async def get_project(self, project_id: str) -> Project:
        """Get a single project by ID."""
        data = await self._get(f"/projects/{project_id}")
        return Project.model_validate(data)

    # ==================== Versions ====================

    async def get_project_versions(
        self,
        project_id: str,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[ProjectVersion]:
        """Get versions for a project."""
        params = {"limit": limit, "offset": offset}
        data = await self._get(f"/projects/{project_id}/versions", params)
        return [ProjectVersion.model_validate(v) for v in data]

    async def iter_project_versions(
        self,
        project_id: str,
        max_items: int | None = None,
    ) -> AsyncIterator[ProjectVersion]:
        """Iterate through all versions for a project."""
        async for version in self._paginate(
            f"/projects/{project_id}/versions",
            ProjectVersion,
            max_items=max_items,
        ):
            yield version

    # ==================== Findings ====================

    @staticmethod
    def _build_rsql_filter(**conditions: str | None) -> str | None:
        """Build an RSQL filter string from keyword arguments.

        Each keyword maps to an RSQL attribute name and its value is used
        with the ``==`` operator.  ``None`` values are skipped.

        Returns:
            A semicolon-delimited RSQL filter string, or ``None`` if all
            values are ``None``.
        """
        parts = [f"{attr}=={val}" for attr, val in conditions.items() if val]
        return ";".join(parts) if parts else None

    async def get_findings(
        self,
        limit: int = 1000,
        offset: int = 0,
        project_id: str | None = None,
        project_version_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        finding_type: str | None = None,
        archived: bool = False,
        excluded: bool = False,
    ) -> list[Finding]:
        """
        Get a list of findings.

        Args:
            limit: Maximum number of findings to return
            offset: Offset for pagination
            project_id: Filter by project ID
            project_version_id: Filter by project version ID
            severity: Filter by severity (critical, high, medium, low)
            status: Filter by VEX status
            finding_type: Filter by finding type (cve, binary-sast, etc.)
            archived: Include archived findings (default False to match FS UI)
            excluded: Include excluded findings (default False to match FS UI)
        """
        params: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "archived": archived,
            "excluded": excluded,
        }
        # project, projectVersion, severity, status use the RSQL filter param
        rsql = self._build_rsql_filter(
            project=project_id,
            projectVersion=project_version_id,
            severity=severity,
            status=status,
        )
        if rsql:
            params["filter"] = rsql
        # type is a proper top-level query parameter
        if finding_type:
            params["type"] = finding_type

        data = await self._get("/findings", params)
        return [Finding.model_validate(f) for f in data]

    async def iter_findings(
        self,
        project_id: str | None = None,
        project_version_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        finding_type: str | None = None,
        archived: bool = False,
        excluded: bool = False,
        max_items: int | None = None,
    ) -> AsyncIterator[Finding]:
        """Iterate through all findings with pagination."""
        params: dict[str, Any] = {
            "archived": archived,
            "excluded": excluded,
        }
        # project, projectVersion, severity, status use the RSQL filter param
        rsql = self._build_rsql_filter(
            project=project_id,
            projectVersion=project_version_id,
            severity=severity,
            status=status,
        )
        if rsql:
            params["filter"] = rsql
        # type is a proper top-level query parameter
        if finding_type:
            params["type"] = finding_type

        async for finding in self._paginate("/findings", Finding, params, max_items=max_items):
            yield finding

    async def get_version_findings(
        self,
        project_version_id: str,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[Finding]:
        """Get findings for a specific version."""
        params = {"limit": limit, "offset": offset}
        data = await self._get(f"/versions/{project_version_id}/findings", params)
        return [Finding.model_validate(f) for f in data]

    async def update_finding_status(
        self,
        project_version_id: str,
        finding_id: str,
        status: str,
        justification: str | None = None,
        response: str | None = None,
        reason: str | None = None,
    ) -> None:
        """
        Update the VEX status of a finding.

        Note: finding_id here is the internal primary key (id), NOT the CVE ID.
        Example URL: PUT /findings/3456789012345678913/123456789012345678/status

        Args:
            project_version_id: The project version ID
            finding_id: The finding's internal ID (primary key)
            status: VEX status (EXPLOITABLE, RESOLVED, NOT_AFFECTED, etc.)
            justification: Required for NOT_AFFECTED status (API enum value)
            response: Required for EXPLOITABLE status (API enum value)
            reason: Optional reason/comment text
        """
        update = FindingStatusUpdate(
            status=status,
            justification=justification,
            response=response,
            reason=reason,
        )
        payload = update.model_dump(exclude_none=True)
        url = f"/findings/{project_version_id}/{finding_id}/status"
        logger.info(f"API Request: PUT {url}")
        logger.info(f"API Payload: {payload}")
        # Use retry logic for status updates
        await self._request_with_retry(
            "PUT",
            f"/findings/{project_version_id}/{finding_id}/status",
            json=payload,
        )

    async def clear_finding_status(
        self,
        project_version_id: str,
        finding_id: str,
    ) -> None:
        """
        Clear the VEX status of a finding (reset to null).

        Uses the undocumented /status/clear endpoint which accepts
        PUT with no body and returns 200.

        Args:
            project_version_id: The project version ID
            finding_id: The finding's internal ID (primary key)
        """
        url = f"/findings/{project_version_id}/{finding_id}/status/clear"
        logger.info(f"API Request: PUT {url}")
        await self._request_with_retry("PUT", url)

    # ==================== Components ====================

    async def get_components(
        self,
        limit: int = 1000,
        offset: int = 0,
        project_id: str | None = None,
        project_version_id: str | None = None,
        excluded: bool = False,
    ) -> list[Component]:
        """
        Get a list of components.

        Args:
            limit: Maximum number of components to return
            offset: Offset for pagination
            project_id: Filter by project ID
            project_version_id: Filter by project version ID
            excluded: Include excluded components (default False to match FS UI)
        """
        params: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "excluded": excluded,
        }
        # project and projectVersion use the RSQL filter param
        rsql = self._build_rsql_filter(
            project=project_id,
            projectVersion=project_version_id,
        )
        if rsql:
            params["filter"] = rsql

        data = await self._get("/components", params)
        return [Component.model_validate(c) for c in data if c]

    async def iter_components(
        self,
        project_id: str | None = None,
        project_version_id: str | None = None,
        excluded: bool = False,
        max_items: int | None = None,
    ) -> AsyncIterator[Component]:
        """Iterate through all components with pagination."""
        params: dict[str, Any] = {
            "excluded": excluded,
        }
        # project and projectVersion use the RSQL filter param
        rsql = self._build_rsql_filter(
            project=project_id,
            projectVersion=project_version_id,
        )
        if rsql:
            params["filter"] = rsql

        async for component in self._paginate(
            "/components", Component, params, max_items=max_items
        ):
            yield component

    async def get_version_components(
        self,
        project_version_id: str,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[Component]:
        """Get components for a specific version."""
        params = {"limit": limit, "offset": offset}
        data = await self._get(f"/versions/{project_version_id}/components", params)
        return [Component.model_validate(c) for c in data]
