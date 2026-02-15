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

"""Main report engine for orchestrating the reporting process."""

import gc
import hashlib
import logging
import platform
import resource
import time
from typing import Any

import pandas as pd
from rich.console import Console

from fs_report.api_client import APIClient
from fs_report.data_cache import DataCache
from fs_report.data_transformer import DataTransformer
from fs_report.models import Config, QueryConfig, Recipe, ReportData
from fs_report.recipe_loader import RecipeLoader
from fs_report.renderers import ReportRenderer
from fs_report.sqlite_cache import _trim_factors

# [REMOVED] All DuckDB-related logic and imports. Only pandas transformer is used.


def _log_memory(logger: logging.Logger, label: str) -> None:
    """Log current process memory usage (RSS) for diagnostics."""
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # macOS reports ru_maxrss in bytes; Linux reports in kilobytes
        if platform.system() == "Darwin":
            rss_mb = usage.ru_maxrss / (1024 * 1024)
        else:
            rss_mb = usage.ru_maxrss / 1024
        logger.info(f"[Memory] {label}: {rss_mb:.0f} MB peak RSS")
    except Exception:
        pass  # Don't let memory logging break the report


# Finding type/category mapping for --finding-types flag
CATEGORY_VALUES = {"credentials", "config_issues", "crypto_material", "sast_analysis"}
TYPE_VALUES = {"cve", "sast", "thirdparty", "binary_sca", "source_sca"}
CATEGORY_MAP = {
    "credentials": "CREDENTIALS",
    "config_issues": "CONFIG_ISSUES",
    "crypto_material": "CRYPTO_MATERIAL",
    "sast_analysis": "SAST_ANALYSIS",
    "cve": "CVE",
}
# Map simple type to API category/categories for multi-type requests (type=all + category filter).
# API uses BINARY_SCA / SOURCE_SCA for binary vs source SCA; SAST_ANALYSIS is legacy. We request
# both when user asks for "sast" so either API naming works.
TYPE_TO_CATEGORY = {
    "cve": ["CVE"],
    "sast": ["SAST_ANALYSIS", "BINARY_SCA"],
    "thirdparty": ["THIRDPARTY"],
    "binary_sca": ["BINARY_SCA"],
    "source_sca": ["SOURCE_SCA"],
}


def build_findings_type_params(finding_types: str) -> dict[str, str | None]:
    """
    Build API parameters for finding type/category filtering.

    Args:
        finding_types: Comma-separated finding types from config

    Returns:
        Dict with 'type' and optional 'category_filter' keys
    """
    values = [v.strip().lower() for v in finding_types.split(",")]

    # "all" means no filtering
    if "all" in values:
        return {"type": "all", "category_filter": None}

    # Separate into categories (need RSQL filter) and simple types (use type param)
    categories = [
        v for v in values if v in CATEGORY_VALUES
    ]  # credentials, config_issues, etc.
    simple_types = [v for v in values if v in TYPE_VALUES]  # cve, sast, thirdparty

    # CVE-only: use type=cve directly (most efficient)
    if simple_types == ["cve"] and not categories:
        return {"type": "cve", "category_filter": None}

    # Single non-CVE type: use type param directly (API accepts sast, thirdparty)
    if (
        len(simple_types) == 1
        and simple_types[0] in ("sast", "thirdparty")
        and not categories
    ):
        return {"type": simple_types[0], "category_filter": None}

    # Multiple types, or binary_sca/source_sca (category-only), or named categories
    if (
        categories
        or len(simple_types) > 1
        or set(simple_types) & {"binary_sca", "source_sca"}
    ):
        # Build category filter from simple_types + named categories (no duplicates)
        all_categories = []
        for t in simple_types:
            for cat in TYPE_TO_CATEGORY.get(t, []):
                if cat not in all_categories:
                    all_categories.append(cat)
        for c in categories:
            mapped_cat = CATEGORY_MAP.get(c)
            if mapped_cat and mapped_cat not in all_categories:
                all_categories.append(mapped_cat)

        if all_categories:
            category_filter = f"category=in=({','.join(all_categories)})"
            return {"type": "all", "category_filter": category_filter}
        else:
            return {"type": "all", "category_filter": None}

    # Default to cve only
    return {"type": "cve", "category_filter": None}


class ReportEngine:
    """Main engine for generating reports from recipes."""

    def __init__(
        self, config: Config, data_override: dict[str, Any] | None = None
    ) -> None:
        """Initialize the report engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize cache
        self.cache = DataCache()

        # Initialize components
        self.api_client = APIClient(
            config,
            cache=self.cache,
            cache_ttl=getattr(config, "cache_ttl", 0),
        )
        self.recipe_loader = RecipeLoader(config.recipes_dir)

        # Initialize transformer (only pandas is used)
        self.transformer = DataTransformer()
        # self.logger.info("Using Pandas transformer")

        self.renderer = ReportRenderer(
            config.output_dir, config, overwrite=getattr(config, "overwrite", False)
        )
        self.data_override = data_override

        # Cache for latest version IDs when current_version_only is enabled
        self._latest_version_ids: list[int] | None = None

        # In-memory cache: folder project IDs → latest version IDs (avoids re-resolving per report)
        self._folder_version_ids_cache: dict[str, list[int]] = {}

        # In-memory cache: findings data keyed by (endpoint, filter, finding_type, version_ids_hash)
        # Avoids redundant API fetches when multiple reports need the same data
        self._findings_cache: dict[str, list[dict]] = {}

        # In-memory cache: per-version findings keyed by (endpoint, version_id, finding_type)
        # Shared across Version Comparison within the same run
        self._version_findings_cache: dict[str, list[dict]] = {}

        # In-memory cache: per-project version lists from /projects/{id}/versions
        self._project_versions_cache: dict[str, list[dict]] = {}

        # Folder scoping state (populated by _resolve_folder_scope in run())
        self._folder_project_ids: set[str] | None = None
        self._project_folder_map: dict[str, str] = {}  # project_id -> folder_name
        self._folder_name: str | None = None
        self._folder_path: str | None = None  # e.g. "Division A / Medical Products"

    def _resolve_project_name(self, project_name: str) -> int | None:
        """
        Resolve a project name to its numeric API ID.

        Fetches the project list from the API and performs a case-insensitive
        name match.  Returns the numeric project ID, or None if not found.
        """
        from fs_report.models import QueryConfig, QueryParams

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        projects = self.api_client.fetch_data(projects_query)

        for p in projects:
            name = p.get("name", "")
            if name.lower() == project_name.lower():
                return p.get("id")

        # Fuzzy hint: show close matches
        available = [p.get("name", "") for p in projects if p.get("name")]
        close = [n for n in available if project_name.lower() in n.lower()]
        if close:
            self.logger.info(f"Did you mean one of these? {close[:5]}")

        return None

    def _fetch_all_folders(self) -> list[dict]:
        """Fetch all folders from the API."""
        from fs_report.models import QueryConfig, QueryParams

        folders_query = QueryConfig(
            endpoint="/public/v0/folders",
            params=QueryParams(limit=10000),
        )
        return self.api_client.fetch_data(folders_query)

    def _resolve_folder(self, folder_input: str) -> dict | None:
        """
        Resolve a folder name or ID to its API record.
        Returns the full folder dict, or None if not found.
        """
        folders = self._fetch_all_folders()

        # Try exact ID match first
        for f in folders:
            if str(f.get("id", "")) == folder_input:
                return f

        # Case-insensitive name match
        for f in folders:
            if f.get("name", "").lower() == folder_input.lower():
                return f

        # Fuzzy hint
        available = [f.get("name", "") for f in folders if f.get("name")]
        close = [n for n in available if folder_input.lower() in n.lower()]
        if close:
            self.logger.info(f"Did you mean one of these folders? {close[:5]}")

        return None

    def _collect_folder_tree(
        self, target_folder_id: str, all_folders: list[dict] | None = None
    ) -> tuple[set[str], dict[str, str], list[dict]]:
        """
        Walk the folder tree starting from *target_folder_id* and collect:
        1. All descendant folder IDs (including the target itself).
        2. project_id -> folder_name mapping for every project in those folders.
        3. The list of subfolder dicts (for logging/display).

        Returns (folder_ids, project_folder_map, subfolder_list).
        """
        if all_folders is None:
            all_folders = self._fetch_all_folders()

        folder_by_id: dict[str, dict] = {str(f["id"]): f for f in all_folders}
        children_map: dict[str, list[str]] = {}
        for f in all_folders:
            parent = f.get("parentFolderId")
            if parent:
                children_map.setdefault(str(parent), []).append(str(f["id"]))

        # BFS to collect all descendant folder IDs
        from collections import deque

        queue: deque[str] = deque([target_folder_id])
        all_folder_ids: set[str] = set()
        subfolder_list: list[dict] = []
        while queue:
            fid = queue.popleft()
            all_folder_ids.add(fid)
            if fid != target_folder_id:
                subfolder_list.append(folder_by_id.get(fid, {}))
            for child_id in children_map.get(fid, []):
                if child_id not in all_folder_ids:
                    queue.append(child_id)

        # For each folder, fetch its projects
        from fs_report.models import QueryConfig, QueryParams

        project_folder_map: dict[str, str] = {}
        all_project_ids: set[str] = set()

        for fid in all_folder_ids:
            folder_name = folder_by_id.get(fid, {}).get("name", "Unknown")
            try:
                projects_query = QueryConfig(
                    endpoint=f"/public/v0/folders/{fid}/projects",
                    params=QueryParams(limit=10000, archived=False, excluded=False),
                )
                projects = self.api_client.fetch_data(projects_query)
                for p in projects:
                    pid = str(p.get("id", ""))
                    if pid:
                        all_project_ids.add(pid)
                        project_folder_map[pid] = folder_name
            except Exception as e:
                self.logger.warning(
                    f"Error fetching projects for folder '{folder_name}' ({fid}): {e}"
                )

        self.logger.info(
            f"Folder tree: {len(all_folder_ids)} folder(s), "
            f"{len(all_project_ids)} project(s)"
        )

        return all_project_ids, project_folder_map, subfolder_list

    def _build_folder_path(
        self, folder_id: str, all_folders: list[dict] | None = None
    ) -> str:
        """Build a breadcrumb-style path for a folder, e.g. 'Division A / Medical Products'."""
        if all_folders is None:
            all_folders = self._fetch_all_folders()
        folder_by_id = {str(f["id"]): f for f in all_folders}

        parts: list[str] = []
        current_id: str | None = folder_id
        seen: set[str] = set()
        while current_id and current_id not in seen:
            seen.add(current_id)
            folder = folder_by_id.get(current_id)
            if not folder:
                break
            parts.append(folder.get("name", "Unknown"))
            parent = folder.get("parentFolderId")
            current_id = str(parent) if parent else None

        parts.reverse()
        return " / ".join(parts)

    def _resolve_folder_scope(self) -> bool:
        """
        Called from run() when config.folder_filter is set.
        Resolves folder, walks tree, collects project IDs & mapping.
        Returns True on success, False on failure.
        """
        folder_input = self.config.folder_filter
        if not folder_input:
            return True

        folder = self._resolve_folder(folder_input)
        if not folder:
            self.logger.error(
                f"Could not resolve folder '{folder_input}'. "
                "Use 'fs-report list-folders' to see available folders."
            )
            return False

        folder_id = str(folder["id"])
        self._folder_name = folder.get("name", folder_input)

        # Fetch all folders once (used for tree walk and path building)
        all_folders = self._fetch_all_folders()
        self._folder_path = self._build_folder_path(folder_id, all_folders)

        project_ids, project_folder_map, subfolders = self._collect_folder_tree(
            folder_id, all_folders
        )

        self._folder_project_ids = project_ids
        self._project_folder_map = project_folder_map

        self.logger.info(
            f"Folder scope: '{self._folder_path}' — "
            f"{len(subfolders)} subfolder(s), {len(project_ids)} project(s)"
        )

        # If --project is also specified, validate it's within the folder
        if self.config.project_filter:
            pid = str(self.config.project_filter)
            if pid not in project_ids:
                self.logger.error(
                    f"Project '{self.config.project_filter}' is not in folder "
                    f"'{self._folder_name}' or its subfolders."
                )
                return False

        return True

    def _build_project_folder_map_from_projects(self) -> dict[str, str]:
        """
        Build a project_id -> folder_name mapping by fetching projects.
        Used when --folder is not specified, to still populate folder_name
        from the ProjectV0.folder field.
        """
        from fs_report.models import QueryConfig, QueryParams

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        projects = self.api_client.fetch_data(projects_query)

        pf_map: dict[str, str] = {}
        for p in projects:
            pid = str(p.get("id", ""))
            folder = p.get("folder")
            if pid and folder and isinstance(folder, dict):
                pf_map[pid] = folder.get("name", "")
        return pf_map

    def _get_latest_version_ids(self) -> list[int]:
        """Fetch latest version IDs for all projects (cached)."""
        if self._latest_version_ids is not None:
            return self._latest_version_ids

        self.logger.info("Fetching latest version IDs for all projects...")

        # Fetch all projects — _get_latest_version_ids_for_projects will
        # also fetch them, but the DataCache / SQLite cache makes the
        # second call essentially free.
        from fs_report.models import QueryConfig, QueryParams

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        projects = self.api_client.fetch_all_with_resume(projects_query)
        self.logger.info(f"Found {len(projects)} projects")

        project_ids = [str(p["id"]) for p in projects if p.get("id")]

        # Try extracting version IDs from the data we already have.
        # This avoids a second fetch when the list response (or cache)
        # already includes defaultBranch.
        requested_set = set(project_ids)
        version_ids = self._extract_version_ids_from_projects(projects, requested_set)
        if not version_ids and project_ids:
            # Batch data lacked defaultBranch — delegate to the fallback
            # path which does per-project detail calls.
            version_ids = self._get_latest_version_ids_for_projects(project_ids)
        else:
            self.logger.info(f"Resolved {len(version_ids)} version IDs from batch data")

        self.logger.info(f"Found {len(version_ids)} latest version IDs")
        self._latest_version_ids = version_ids
        return version_ids

    def _get_latest_version_ids_for_projects(self, project_ids: list) -> list[int]:
        """Fetch the current (latest) version ID for each given project.

        Uses the project's defaultBranch.latestVersion.id which is the
        authoritative current version on the platform.

        Strategy:
        1. Try a single batch call to /public/v0/projects and extract
           defaultBranch.latestVersion.id for each requested project.
           This is fast and cache-friendly.
        2. If the batch response lacks defaultBranch data (some API versions
           omit it from list responses, or the SQLite cache may have been
           populated before this field was stored), fall back to individual
           /public/v0/projects/{id} calls with throttling.

        Results are cached in-memory so subsequent reports in the same run
        skip the API call entirely.
        """
        # Build a stable cache key from sorted project IDs
        cache_key = ",".join(str(pid) for pid in sorted(project_ids))
        if cache_key in self._folder_version_ids_cache:
            cached = self._folder_version_ids_cache[cache_key]
            self.logger.info(
                f"Using cached version IDs ({len(cached)} versions "
                f"for {len(project_ids)} projects)"
            )
            return cached

        from fs_report.models import QueryConfig, QueryParams

        # ------------------------------------------------------------------
        # Step 1: Try batch fetch
        # ------------------------------------------------------------------
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        all_projects = self.api_client.fetch_all_with_resume(
            projects_query, show_progress=True
        )
        self.logger.info(
            f"Resolving latest versions for {len(project_ids)} projects "
            f"(from {len(all_projects)} total projects)"
        )

        requested_ids = {str(pid) for pid in project_ids}
        version_ids = self._extract_version_ids_from_projects(
            all_projects, requested_ids
        )

        # ------------------------------------------------------------------
        # Step 2: Fallback — per-project detail calls when batch yields nothing
        # ------------------------------------------------------------------
        if not version_ids and project_ids:
            self.logger.info(
                "Batch project list did not include defaultBranch data; "
                "falling back to per-project API calls "
                f"({len(project_ids)} projects, "
                f"delay={self.config.request_delay}s)"
            )
            version_ids = self._fetch_version_ids_per_project(project_ids)

        self._folder_version_ids_cache[cache_key] = version_ids
        return version_ids

    # ------------------------------------------------------------------
    # Helpers for _get_latest_version_ids_for_projects
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_version_ids_from_projects(
        projects: list[dict], requested_ids: set[str]
    ) -> list[int]:
        """Extract defaultBranch.latestVersion.id from a list of project dicts."""
        version_ids: list[int] = []
        for project in projects:
            pid = str(project.get("id", ""))
            if pid not in requested_ids:
                continue
            default_branch = project.get("defaultBranch") or {}
            latest_version = (
                default_branch.get("latestVersion") or {}
                if isinstance(default_branch, dict)
                else {}
            )
            version_id = (
                latest_version.get("id") if isinstance(latest_version, dict) else None
            )
            if version_id:
                version_ids.append(version_id)
        return version_ids

    def _fetch_version_ids_per_project(self, project_ids: list) -> list[int]:
        """Fetch defaultBranch.latestVersion.id one project at a time.

        Used as a fallback when the batch /projects list doesn't include
        branch data. Respects --request-delay for throttling.
        """
        from tqdm import tqdm

        delay = max(0.5, self.config.request_delay)
        version_ids: list[int] = []
        for pid in tqdm(
            project_ids,
            desc="Fetching latest versions",
            unit=" projects",
            leave=True,
        ):
            try:
                url = f"/api/public/v0/projects/{pid}"
                resp = self.api_client.client.get(url)
                resp.raise_for_status()
                data = resp.json()
                default_branch = data.get("defaultBranch") or {}
                latest_version = (
                    default_branch.get("latestVersion") or {}
                    if isinstance(default_branch, dict)
                    else {}
                )
                vid = (
                    latest_version.get("id")
                    if isinstance(latest_version, dict)
                    else None
                )
                if vid:
                    version_ids.append(vid)
                else:
                    self.logger.debug(
                        f"No defaultBranch.latestVersion for project {pid}"
                    )
            except Exception:
                self.logger.warning(
                    f"Failed to fetch version for project {pid}",
                    exc_info=True,
                )
            time.sleep(delay)
        return version_ids

    def _split_and_cache_by_version(
        self,
        records: list[dict],
        entity_type: str,
        finding_type: str = "",
        category_filter: str | None = None,
        batch_version_ids: list[int] | None = None,
    ) -> None:
        """Split batch results by projectVersion.id and cache each version individually.

        Populates both the in-memory ``_version_findings_cache`` and, when a SQLite
        cache is available, creates per-version SQLite entries using the same hash
        that a ``projectVersion=={vid}`` query would produce.  This means a later
        per-version fetch from Version Comparison can hit the
        SQLite cache entry created by a batch fetch in an earlier run.

        When ``batch_version_ids`` is provided, versions that returned zero records
        are cached as empty lists.  Without this, empty versions would be re-fetched
        on every run (the cache only stored versions that had data).

        Args:
            records: Raw API records (findings or components).
            entity_type: 'findings' or 'components'.
            finding_type: API finding type (e.g. 'cve'). Only used for findings.
            category_filter: Optional RSQL category filter. Only used for findings.
            batch_version_ids: Version IDs that were queried in this batch.
                If provided, any IDs not present in the results are cached as empty.
        """
        from collections import defaultdict

        by_version: dict[str, list[dict]] = defaultdict(list)
        for rec in records:
            pv = rec.get("projectVersion") or {}
            vid = str(pv.get("id", ""))
            if vid:
                by_version[vid].append(rec)

        # If we know which version IDs were in the batch, add empty entries
        # for versions that returned no records so they are cached as "checked".
        if batch_version_ids is not None:
            for batch_vid in batch_version_ids:
                svid = str(batch_vid)
                if svid not in by_version:
                    by_version[svid] = []

        if entity_type == "findings":
            cache_prefix = "findings|"
            cache_suffix = f"|{finding_type}|{category_filter or ''}"
        else:
            cache_prefix = "components|"
            cache_suffix = ""

        stored_versions = 0
        for vid, version_records in by_version.items():
            cache_key = f"{cache_prefix}{vid}{cache_suffix}"
            if cache_key not in self._version_findings_cache:
                self._version_findings_cache[cache_key] = version_records
                stored_versions += 1

                # Warm SQLite cache with a per-version entry
                if self.api_client.sqlite_cache and self.api_client.cache_ttl > 0:
                    endpoint = f"/public/v0/{entity_type}"
                    # Build params that match what a per-version query would produce
                    filter_str = f"projectVersion=={vid}"
                    if category_filter:
                        filter_str = f"{filter_str};{category_filter}"
                    params: dict[str, Any] = {"filter": filter_str, "limit": 10000}
                    if entity_type == "findings" and finding_type:
                        params["finding_type"] = finding_type
                    if entity_type == "findings":
                        params["archived"] = False
                        params["excluded"] = False

                    if not self.api_client.sqlite_cache.is_cache_valid(
                        endpoint, params, self.api_client.cache_ttl
                    ):
                        qh = self.api_client.sqlite_cache.start_fetch(
                            endpoint, params, self.api_client.cache_ttl
                        )
                        self.api_client.sqlite_cache.store_records(
                            qh, endpoint, version_records
                        )
                        self.api_client.sqlite_cache.complete_fetch(qh)

        if stored_versions:
            self.logger.debug(
                f"Split batch into {stored_versions} per-version {entity_type} cache entries "
                f"(skipped {len(by_version) - stored_versions} already cached)"
            )

    def _check_version_in_cache(
        self,
        vid: str,
        entity_type: str,
        finding_type: str = "",
        category_filter: str | None = None,
    ) -> list[dict] | None:
        """Check both in-memory and SQLite caches for per-version data.

        Returns cached records or None if not found.
        """
        if entity_type == "findings":
            cache_key = f"findings|{vid}|{finding_type}|{category_filter or ''}"
        else:
            cache_key = f"components|{vid}"

        # 1. In-memory cache
        if cache_key in self._version_findings_cache:
            return self._version_findings_cache[cache_key]

        # 2. SQLite cache
        if self.api_client.sqlite_cache and self.api_client.cache_ttl > 0:
            endpoint = f"/public/v0/{entity_type}"
            filter_str = f"projectVersion=={vid}"
            if category_filter:
                filter_str = f"{filter_str};{category_filter}"
            params: dict[str, Any] = {"filter": filter_str, "limit": 10000}
            if entity_type == "findings" and finding_type:
                params["finding_type"] = finding_type
            if entity_type == "findings":
                params["archived"] = False
                params["excluded"] = False

            if self.api_client.sqlite_cache.is_cache_valid(
                endpoint, params, self.api_client.cache_ttl
            ):
                cached = self.api_client.sqlite_cache.get_cached_data(
                    endpoint, params, allow_empty=True
                )
                if cached is not None:
                    # Promote to in-memory cache for fast re-reads
                    self._version_findings_cache[cache_key] = cached
                    return cached

        return None

    def _get_findings_for_versions(
        self,
        version_ids: list,
        finding_type: str,
        category_filter: str | None = None,
        entity_type: str = "findings",
    ) -> list[dict]:
        """Reassemble data from per-version cache, fetching any missing versions first.

        This is the main entry point for findings-based reports to get data for a
        set of versions.  It checks in-memory and SQLite caches per-version, then
        batch-fetches any missing versions from the API.

        Args:
            version_ids: Version IDs to retrieve data for.
            finding_type: API finding type (e.g. 'cve').
            category_filter: Optional RSQL category filter.
            entity_type: 'findings' or 'components'.

        Returns:
            Merged list of records across all requested versions.
        """
        all_records: list[dict] = []
        missing: list[int] = []

        for vid in version_ids:
            cached = self._check_version_in_cache(
                str(vid), entity_type, finding_type, category_filter
            )
            if cached is not None:
                all_records.extend(cached)
            else:
                missing.append(vid)

        cached_count = len(version_ids) - len(missing)
        if missing:
            self.logger.info(
                f"{cached_count}/{len(version_ids)} versions from cache, "
                f"fetching {len(missing)} from API ({entity_type})"
            )
            from fs_report.models import QueryConfig, QueryParams

            # Build base query WITHOUT date filters — entity cache stores all data per version
            filters: list[str] = []
            if category_filter:
                filters.append(category_filter)
            combined_filter = ";".join(filters) if filters else None

            base_query = QueryConfig(
                endpoint=f"/public/v0/{entity_type}",
                params=QueryParams(
                    limit=10000,
                    filter=combined_filter,
                    finding_type=finding_type if entity_type == "findings" else None,
                    archived=False if entity_type == "findings" else None,
                    excluded=False if entity_type == "findings" else None,
                ),
            )
            if entity_type == "components":
                # Components need type!=file filter
                comp_filters = ["type!=file"]
                if combined_filter:
                    comp_filters.append(combined_filter)
                base_query.params.filter = ";".join(comp_filters)

            new_records = self._fetch_with_version_batching(
                base_query,
                sorted(missing),
                finding_type=finding_type,
                category_filter=category_filter,
                entity_type=entity_type,
            )
            all_records.extend(new_records)
        else:
            self.logger.info(
                f"All {len(version_ids)} versions served from cache ({entity_type})"
            )

        return all_records

    def _volume_based_cooldown(self, records_in_batch: int) -> float:
        """Return a cooldown duration (seconds) scaled by data volume."""
        if records_in_batch > 50_000:
            return max(90.0, self.config.request_delay * 15)
        if records_in_batch > 20_000:
            return max(45.0, self.config.request_delay * 10)
        if records_in_batch > 5_000:
            return max(15.0, self.config.request_delay * 5)
        return max(5.0, self.config.request_delay * 2)

    def _fetch_with_version_batching(
        self,
        base_query: "QueryConfig",
        version_ids: list[int],
        batch_size: int | None = None,
        finding_type: str = "",
        category_filter: str | None = None,
        entity_type: str = "findings",
    ) -> list[dict]:
        """Fetch data in batches, filtering by version IDs.

        Before each batch, filters out versions already in per-version cache.
        After each batch, splits results and stores per-version entries.
        Uses ``skip_cache_store=True`` to avoid duplicating batch-level SQLite
        entries (per-version storage handles it).

        batch_size defaults to ``self.config.batch_size`` (CLI: ``--batch-size``,
        default 5).  Kept small to avoid overloading the server on large
        instances.  Each batch is followed by an adaptive cooldown that scales
        with the number of records fetched.
        """
        if batch_size is None:
            batch_size = self.config.batch_size
        from tqdm import tqdm

        all_results = []

        # Filter out already-cached versions first
        uncached_ids = [
            v
            for v in version_ids
            if self._check_version_in_cache(
                str(v), entity_type, finding_type, category_filter
            )
            is None
        ]

        # Collect cached results
        cached_count = len(version_ids) - len(uncached_ids)
        if cached_count > 0:
            for vid in version_ids:
                cached = self._check_version_in_cache(
                    str(vid), entity_type, finding_type, category_filter
                )
                if cached is not None:
                    all_results.extend(cached)
            self.logger.debug(
                f"Version batching: {cached_count} versions served from cache"
            )

        if not uncached_ids:
            self.logger.debug("Version batching: all versions served from cache")
            return all_results

        total_batches = (len(uncached_ids) + batch_size - 1) // batch_size

        # Log the base filter being used
        self.logger.debug(
            f"Version batching with base filter: {base_query.params.filter}"
        )

        # Split uncached version IDs into batches with progress bar
        # Track elevated cooldown state: after server errors, keep cooldowns
        # elevated for several batches so the server gets sustained recovery.
        elevated_batches_remaining = 0
        elevated_cooldown = 0.0

        with tqdm(
            range(0, len(uncached_ids), batch_size),
            desc="Fetching version batches",
            unit=" batches",
            total=total_batches,
            leave=False,
        ) as pbar:
            for i in pbar:
                batch_ids = uncached_ids[i : i + batch_size]

                # Build version filter
                version_filter = (
                    f"projectVersion=in=({','.join(str(v) for v in batch_ids)})"
                )

                # Combine with existing filter (MUST preserve base filter like type!=file)
                if base_query.params.filter:
                    combined_filter = f"{base_query.params.filter};{version_filter}"
                else:
                    combined_filter = version_filter

                self.logger.debug(
                    f"Batch {i//batch_size + 1}/{total_batches} filter: {combined_filter[:100]}..."
                )

                # Create batch query
                from fs_report.models import QueryConfig, QueryParams

                batch_query = QueryConfig(
                    endpoint=base_query.endpoint,
                    params=QueryParams(
                        limit=base_query.params.limit,
                        filter=combined_filter,
                        finding_type=base_query.params.finding_type,
                        archived=False if entity_type == "findings" else None,
                        excluded=False if entity_type == "findings" else None,
                    ),
                )

                # Use skip_cache_store to avoid duplicating batch-level SQLite entries
                batch_results = self.api_client.fetch_all_with_resume(
                    batch_query,
                    show_progress=False,
                    skip_cache_store=True,
                )

                # Split and cache per-version (in-memory + SQLite).
                # Pass batch_ids so versions with 0 results are cached as
                # empty — otherwise they'd be re-fetched on every run.
                self._split_and_cache_by_version(
                    batch_results,
                    entity_type,
                    finding_type,
                    category_filter,
                    batch_version_ids=batch_ids,
                )

                # Trim factors in-memory to avoid OOM on large instances.
                # The full factors are already persisted (trimmed) in SQLite;
                # here we apply the same trim so the in-memory accumulation
                # doesn't hold multi-MB factors arrays per finding.
                for record in batch_results:
                    raw_factors = record.get("factors")
                    if isinstance(raw_factors, list) and raw_factors:
                        record["factors"] = _trim_factors(raw_factors)

                all_results.extend(batch_results)
                pbar.set_postfix({"records": len(all_results)})

                # Adaptive cooldown between batches — scale with data volume
                if i + batch_size < len(uncached_ids):
                    records_in_batch = len(batch_results)
                    # Check if the API client hit any retries during this batch
                    retries_in_batch = getattr(self.api_client, "last_fetch_retries", 0)
                    if retries_in_batch > 0:
                        # Server was struggling — give it a long recovery and
                        # keep cooldowns elevated for the next several batches
                        # so the server gets sustained breathing room.
                        cooldown = max(120.0, self.config.request_delay * 20)
                        elevated_cooldown = max(60.0, self.config.request_delay * 10)
                        elevated_batches_remaining = 5
                        self.logger.warning(
                            f"Server had {retries_in_batch} retries in batch; "
                            f"extended cooldown {cooldown:.0f}s "
                            f"(next {elevated_batches_remaining} batches "
                            f"will use ≥{elevated_cooldown:.0f}s)"
                        )
                    elif elevated_batches_remaining > 0:
                        # Still in recovery window from a previous retry event
                        elevated_batches_remaining -= 1
                        volume_cooldown = self._volume_based_cooldown(records_in_batch)
                        cooldown = max(volume_cooldown, elevated_cooldown)
                        self.logger.info(
                            f"Recovery cooldown {cooldown:.0f}s "
                            f"({elevated_batches_remaining} elevated batches left)"
                        )
                    else:
                        cooldown = self._volume_based_cooldown(records_in_batch)
                    batches_remaining = total_batches - (i // batch_size + 1)
                    est_minutes = (batches_remaining * cooldown) / 60
                    self.logger.info(
                        f"Batch {i // batch_size + 1}/{total_batches}: "
                        f"{records_in_batch:,} records. "
                        f"Cooling down {cooldown:.0f}s. "
                        f"~{est_minutes:.0f} min remaining"
                    )
                    time.sleep(cooldown)

        return all_results

    def run(self) -> bool:
        """Run the complete report generation process. Returns True if all recipes succeeded."""
        self.logger.info("Starting report generation...")

        # Load recipes
        recipes = self.recipe_loader.load_recipes()
        if not recipes:
            self.logger.warning("No recipes found in recipes directory")
            return False

        # Filter recipes if specific recipe is requested
        # Check both config.recipe_filter and recipe_loader.recipe_filter
        # (CLI sets recipe_loader.recipe_filter directly, not config.recipe_filter)
        explicit_recipe_requested = self.config.recipe_filter or getattr(
            self.recipe_loader, "recipe_filter", None
        )
        if self.config.recipe_filter:
            filtered_recipes = [
                r
                for r in recipes
                if r.name.lower() == self.config.recipe_filter.lower()
            ]
            if not filtered_recipes:
                self.logger.error(
                    f"Recipe '{self.config.recipe_filter}' not found. Available recipes: {[r.name for r in recipes]}"
                )
                return False
            recipes = filtered_recipes
            self.logger.info(f"Filtered to {len(recipes)} recipe(s)")
        elif not explicit_recipe_requested:
            # Exclude recipes with auto_run=False only when no specific recipe is requested
            auto_run_recipes = [r for r in recipes if getattr(r, "auto_run", True)]
            skipped = len(recipes) - len(auto_run_recipes)
            if skipped > 0:
                self.logger.info(
                    f"Skipping {skipped} recipe(s) with auto_run=false (use --recipe to run them)"
                )
            recipes = auto_run_recipes

        # Sort recipes by execution_order to maximize cache reuse
        # Lower order = runs first (e.g., Scan Analysis fetches scans that other reports reuse)
        recipes = sorted(recipes, key=lambda r: r.execution_order)

        self.logger.info(f"Loaded {len(recipes)} recipes")

        # Resolve folder scope first (may narrow down project set)
        if self.config.folder_filter and not self.data_override:
            if not self._resolve_folder_scope():
                return False

        # Resolve project name to numeric ID if needed (API filters require numeric IDs)
        if self.config.project_filter and not self.data_override:
            try:
                int(self.config.project_filter)
                # Already a numeric ID — no resolution needed
            except ValueError:
                resolved_id = self._resolve_project_name(self.config.project_filter)
                if resolved_id:
                    self.logger.info(
                        f"Resolved project '{self.config.project_filter}' to ID {resolved_id}"
                    )
                    self.config.project_filter = str(resolved_id)
                else:
                    self.logger.error(
                        f"Could not resolve project name '{self.config.project_filter}'. "
                        "Use 'fs-report list-projects' to see available projects."
                    )
                    return False

        # Process each recipe
        all_succeeded = True
        generated_files = []
        total = len(recipes)
        Console()
        for idx, recipe in enumerate(recipes, 1):
            try:
                self.logger.info(f"[{idx}/{total}] Generating: {recipe.name} ...")
                self.renderer.check_output_guard(recipe)
                report_data = self._process_recipe(recipe)
                if report_data:
                    files = self.renderer.render(recipe, report_data)
                    if files:
                        generated_files.extend(files)
                    # Collect extra files written by transforms (prompts, VEX JSON)
                    extra = report_data.metadata.get("additional_data", {}).get(
                        "_extra_generated_files", []
                    )
                    if extra:
                        generated_files.extend(extra)
                else:
                    self.logger.error(
                        f"No report data generated for recipe: {recipe.name}"
                    )
                    all_succeeded = False
            except Exception as e:
                self.logger.error(f"Failed to process recipe {recipe.name}: {e}")
                all_succeeded = False
                continue
        if generated_files:
            print("\nReports generated:")
            for f in generated_files:
                print(f"  - {f}")
        return all_succeeded

    # ------------------------------------------------------------------
    # Version Comparison: specialised data fetcher
    # ------------------------------------------------------------------

    def _fetch_version_comparison_data(self, recipe: Any) -> list[dict]:
        """
        Fetch findings for every version of every in-scope project so the
        transform can show a full version-over-version progression.

        Supports:
          * ``--folder``   → projects in that folder
          * ``--project``  → single project
          * (neither)      → entire portfolio

        Stores a list of per-project dicts in
        ``self._version_comparison_data["projects"]``.
        Each dict: ``{project_name, versions: [{id, name, created, findings, components}]}``.
        """
        from tqdm import tqdm as _tqdm

        from fs_report.models import QueryConfig, QueryParams

        type_params = build_findings_type_params(self.config.finding_types)
        finding_type = type_params.get("type") or "cve"
        category_filter = type_params.get("category_filter")

        def _fetch_findings(version_id: str) -> list[dict]:
            # Check both in-memory and SQLite caches
            cached = self._check_version_in_cache(
                version_id, "findings", finding_type, category_filter
            )
            if cached is not None:
                return cached
            version_filter = f"projectVersion=={version_id}"
            combined_filter = (
                f"{version_filter};{category_filter}"
                if category_filter
                else version_filter
            )
            q = QueryConfig(
                endpoint="/public/v0/findings",
                params=QueryParams(
                    limit=10000,
                    filter=combined_filter,
                    finding_type=finding_type,
                    archived=False,
                    excluded=False,
                ),
            )
            result = self.api_client.fetch_all_with_resume(q, show_progress=False)
            # Store per-version in both in-memory and SQLite caches
            cache_key = f"findings|{version_id}|{finding_type}|{category_filter or ''}"
            self._version_findings_cache[cache_key] = result
            # SQLite is already handled by fetch_all_with_resume when cache_ttl > 0
            return result

        def _fetch_components(version_id: str) -> list[dict]:
            # Check both in-memory and SQLite caches
            cached = self._check_version_in_cache(version_id, "components")
            if cached is not None:
                return cached
            q = QueryConfig(
                endpoint="/public/v0/components",
                params=QueryParams(
                    limit=10000,
                    filter=f"projectVersion=={version_id}",
                ),
            )
            result = self.api_client.fetch_all_with_resume(q, show_progress=False)
            cache_key = f"components|{version_id}"
            self._version_findings_cache[cache_key] = result
            return result

        # ── Validate --baseline-version / --current-version ─────────────
        bv = self.config.baseline_version
        cv = self.config.current_version
        if bool(bv) != bool(cv):
            raise ValueError(
                "Both --baseline-version and --current-version must be provided together. "
                "Use 'fs-report list-versions <project>' to find version IDs."
            )

        # ── Short-circuit: explicit version pair ──────────────────────
        if bv and cv:
            if bv == cv:
                raise ValueError(
                    "--baseline-version and --current-version must be different version IDs."
                )

            self.logger.info(
                "Version Comparison: explicit pair (baseline=%s, current=%s)",
                bv,
                cv,
            )

            # Fetch findings + components directly (version IDs are globally unique)
            pair_pbar = _tqdm(
                total=4,
                desc="Fetching version pair",
                unit=" requests",
                leave=False,
            )
            pair_pbar.set_postfix({"step": "Baseline findings"})
            baseline_findings = _fetch_findings(bv)
            pair_pbar.update(1)

            pair_pbar.set_postfix({"step": "Baseline components"})
            baseline_components = _fetch_components(bv)
            pair_pbar.update(1)

            pair_pbar.set_postfix({"step": "Current findings"})
            current_findings = _fetch_findings(cv)
            pair_pbar.update(1)

            pair_pbar.set_postfix({"step": "Current components"})
            current_components = _fetch_components(cv)
            pair_pbar.update(1)
            pair_pbar.close()

            # Resolve version metadata if --project is set
            baseline_name, baseline_created = bv, ""
            current_name, current_created = cv, ""
            project_name = "Version Comparison"

            if self.config.project_filter:
                pf = self.config.project_filter
                # Fetch the project list to resolve the project name and ID
                projects_query = QueryConfig(
                    endpoint="/public/v0/projects",
                    params=QueryParams(limit=10000, archived=False, excluded=False),
                )
                all_projects = self.api_client.fetch_all_with_resume(
                    projects_query,
                    show_progress=False,
                )
                for p in all_projects:
                    pid = str(p.get("id", ""))
                    pname = p.get("name", "")
                    if pid == pf or pname.lower() == pf.lower():
                        project_name = pname
                        # Fetch the version list to resolve names and dates
                        try:
                            url = (
                                f"{self.api_client.base_url}"
                                f"/public/v0/projects/{pid}/versions"
                            )
                            resp = self.api_client.client.get(url)
                            resp.raise_for_status()
                            versions_list = resp.json()
                            if isinstance(versions_list, list):
                                for v in versions_list:
                                    vid = str(v.get("id", ""))
                                    vname = v.get("version", v.get("name", vid))
                                    vcreated = v.get("created", "")
                                    if vid == bv:
                                        baseline_name = vname
                                        baseline_created = vcreated
                                    elif vid == cv:
                                        current_name = vname
                                        current_created = vcreated
                        except Exception as e:
                            self.logger.debug(
                                "Could not fetch version metadata for %s: %s",
                                project_name,
                                e,
                            )
                        break

            projects_data: list[dict] = [
                {
                    "project_name": project_name,
                    "versions": [
                        {
                            "id": bv,
                            "name": baseline_name,
                            "created": baseline_created,
                            "findings": baseline_findings,
                            "components": baseline_components,
                        },
                        {
                            "id": cv,
                            "name": current_name,
                            "created": current_created,
                            "findings": current_findings,
                            "components": current_components,
                        },
                    ],
                }
            ]

            self._version_comparison_data = {"projects": projects_data}
            return [{"_vc_placeholder": True}]

        # ── Discover projects ──────────────────────────────────────────
        project_ids_and_names: list[tuple[str, str]] = []  # (pid, pname)

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        all_projects = self.api_client.fetch_all_with_resume(
            projects_query,
            show_progress=False,
        )

        if self._folder_project_ids:
            self.logger.info(
                "Version Comparison: %d project(s) from folder '%s'",
                len(self._folder_project_ids),
                self._folder_name or "unknown",
            )
            for p in all_projects:
                pid = str(p.get("id", ""))
                if pid in self._folder_project_ids:
                    project_ids_and_names.append((pid, p.get("name", pid)))

        elif self.config.project_filter:
            self.logger.info(
                "Version Comparison: single project '%s'",
                self.config.project_filter,
            )
            pf = self.config.project_filter
            for p in all_projects:
                pid = str(p.get("id", ""))
                pname = p.get("name", "")
                if pid == pf or pname.lower() == pf.lower():
                    project_ids_and_names.append((pid, pname))
                    break
        else:
            self.logger.info("Version Comparison: all projects in portfolio")
            for p in all_projects:
                pid = str(p.get("id", ""))
                if pid:
                    project_ids_and_names.append((pid, p.get("name", pid)))

        if not project_ids_and_names:
            self.logger.warning("No projects found for version comparison")
            self._version_comparison_data = {}
            return []

        # ── Fetch version lists per project (with caching) ─────────────
        # Each entry: (pname, sorted_versions_list)
        project_version_lists: list[tuple[str, list[dict]]] = []

        self.logger.info(
            "Discovering versions for %d project(s)…",
            len(project_ids_and_names),
        )
        delay = getattr(self.config, "request_delay", 0.5)
        cache_hits = 0
        sqlite_cache = self.api_client.sqlite_cache
        cache_ttl = self.api_client.cache_ttl

        with _tqdm(
            project_ids_and_names,
            desc="Discovering versions",
            unit=" projects",
            leave=False,
        ) as pbar:
            for pid, pname in pbar:
                pbar.set_postfix({"project": pname[:30]})
                versions = None

                # 1. Check in-memory cache
                if pid in self._project_versions_cache:
                    versions = self._project_versions_cache[pid]
                    cache_hits += 1

                # 2. Check SQLite cache
                if versions is None and sqlite_cache and cache_ttl > 0:
                    cached = sqlite_cache.get_version_list(pid, cache_ttl)
                    if cached is not None:
                        versions = cached
                        self._project_versions_cache[pid] = versions
                        cache_hits += 1

                # 3. Fetch from API (only on cache miss)
                if versions is None:
                    try:
                        url = (
                            f"{self.api_client.base_url}"
                            f"/public/v0/projects/{pid}/versions"
                        )
                        resp = self.api_client.client.get(url)
                        resp.raise_for_status()
                        versions = resp.json()
                        if not isinstance(versions, list):
                            versions = []
                    except Exception as e:
                        self.logger.debug(
                            "Error fetching versions for %s (%s): %s",
                            pname,
                            pid,
                            e,
                        )
                        continue
                    finally:
                        # Only delay after actual API calls
                        if delay > 0:
                            time.sleep(delay)

                    # Store in both caches
                    self._project_versions_cache[pid] = versions
                    if sqlite_cache and cache_ttl > 0:
                        sqlite_cache.store_version_list(pid, versions)

                if len(versions) < 2:
                    self.logger.debug(
                        "%s has %d version(s) — skipping",
                        pname,
                        len(versions),
                    )
                    continue

                # Sort by created ascending
                versions.sort(
                    key=lambda v: v.get("created", v.get("id", "")),
                )
                project_version_lists.append((pname, versions))

        if cache_hits > 0:
            self.logger.info(
                "Version discovery: %d/%d projects served from cache",
                cache_hits,
                len(project_ids_and_names),
            )

        if not project_version_lists:
            self.logger.warning("No projects with ≥ 2 versions found")
            self._version_comparison_data = {}
            return []

        # ── Fetch findings & components for every version ──────────────
        total_versions = sum(len(vl) for _, vl in project_version_lists)
        self.logger.info(
            "Fetching findings for %d version(s) across %d project(s)…",
            total_versions,
            len(project_version_lists),
        )

        projects_data = []  # list[dict]
        with _tqdm(  # type: ignore[assignment]
            total=total_versions,
            desc="Fetching version data",
            unit=" versions",
            leave=False,
        ) as pbar:
            for pname, versions in project_version_lists:
                version_records: list[dict] = []
                for v in versions:
                    vid = str(v.get("id", ""))
                    vname = v.get("version", v.get("name", vid))
                    created = v.get("created", "")
                    pbar.set_postfix({"project": pname[:20], "version": vname[:20]})

                    findings = _fetch_findings(vid)
                    if delay > 0:
                        time.sleep(delay)
                    components = _fetch_components(vid)

                    version_records.append(
                        {
                            "id": vid,
                            "name": vname,
                            "created": created,
                            "findings": findings,
                            "components": components,
                        }
                    )
                    pbar.update(1)

                    # Throttle between versions to avoid overloading the server
                    if delay > 0:
                        time.sleep(delay)

                projects_data.append(
                    {
                        "project_name": pname,
                        "versions": version_records,
                    }
                )

        self._version_comparison_data = {"projects": projects_data}
        return [{"_vc_placeholder": True}]

    def _process_recipe(self, recipe: Recipe) -> ReportData | None:
        """Process a single recipe and return report data."""
        try:
            # Track whether entity-level caching was used (needs date post-filtering)
            needs_date_postfilter = False
            is_operational = False

            # Use override data if provided
            if self.data_override is not None:
                self.logger.info(
                    f"Using data from override file for recipe: {recipe.name}"
                )
                # For data override, we need to extract the main query data
                # The main query should match one of the keys in the override data
                endpoint = recipe.query.endpoint
                raw_data = None
                # Patch: if override is a list, use it directly
                if isinstance(self.data_override, list):  # type: ignore[unreachable]
                    raw_data = self.data_override  # type: ignore[unreachable]
                else:
                    self.logger.debug(
                        f"Override matching: endpoint={endpoint}, override keys={list(self.data_override.keys())}"
                    )
                    for key in self.data_override:
                        key_str = str(key)
                        endpoint_str = str(endpoint)
                        self.logger.debug(
                            f"Comparing key='{key_str}' to endpoint='{endpoint_str}'"
                        )
                        if key_str == endpoint_str or key_str.endswith(
                            endpoint_str.split("/")[-1]
                        ):
                            raw_data = self.data_override[key]
                            self.logger.debug(f"Override match found: key='{key_str}'")
                            break
                if raw_data is None:
                    self.logger.error(
                        f"Could not find data for endpoint {endpoint} in override data"
                    )
                    return None
            else:
                # Use robust pagination for all major findings-based reports
                if recipe.name in [
                    "Component Vulnerability Analysis (Pandas)",
                    "Component Vulnerability Analysis",
                    "Executive Summary",
                    "Scan Analysis",
                    "Findings by Project",
                    "Component List",
                    "User Activity",
                    "Triage Prioritization",
                    "Version Comparison",
                    "CVE Impact",
                ]:
                    from fs_report.models import QueryConfig, QueryParams

                    if recipe.name == "Version Comparison":
                        # --- Version Comparison: two-version parallel fetch ---
                        raw_data = self._fetch_version_comparison_data(recipe)
                    elif recipe.name == "User Activity":
                        # Build filter for audit endpoint using RSQL format
                        # The audit API supports: time=ge=START;time=le=END
                        # (The date=START,date=END format has parsing issues with commas in filter param)
                        audit_filter = f"time=ge={self.config.start_date}T00:00:00Z;time=le={self.config.end_date}T23:59:59Z"

                        unified_query = QueryConfig(
                            endpoint=recipe.query.endpoint,
                            params=QueryParams(
                                limit=recipe.query.params.limit, filter=audit_filter
                            ),
                        )
                        self.logger.info(
                            f"Fetching audit events for {recipe.name} with filter: {audit_filter}"
                        )
                        raw_data = self.api_client.fetch_all_with_resume(unified_query)
                    elif recipe.name == "Scan Analysis":
                        # Apply project and version filtering to scans
                        scan_query = self._apply_scan_filters(recipe.query)
                        # Use early termination to avoid fetching old scans
                        raw_data = self._fetch_scans_with_early_termination(scan_query)

                        # Fetch project data for new vs existing analysis
                        # Store in a variable that will be added to additional_data later
                        self._scan_analysis_project_data = None
                        if (
                            hasattr(recipe, "project_list_query")
                            and recipe.project_list_query
                        ):
                            self.logger.info("Fetching project data for Scan Analysis")
                            project_query = QueryConfig(
                                endpoint=recipe.project_list_query.endpoint,
                                params=QueryParams(
                                    limit=recipe.project_list_query.params.limit,
                                    offset=0,
                                    archived=False,
                                    excluded=False,
                                ),
                            )
                            self._scan_analysis_project_data = (
                                self.api_client.fetch_all_with_resume(project_query)
                            )
                            self.logger.info(
                                f"Fetched {len(self._scan_analysis_project_data)} projects for new/existing analysis"
                            )
                    elif recipe.name == "CVE Impact":
                        # CVE Impact uses the /public/v0/cves endpoint which
                        # returns data pre-aggregated by CVE ID. Simple pagination,
                        # no version batching needed.

                        # Scope guard: --cve is always required.
                        # A project-scoped query (--project without --cve)
                        # can return thousands of CVEs and overwhelm the
                        # report.  For a project with N CVEs the dossier
                        # enrichment alone would issue ~3*N API calls
                        # (e.g. 4 000 CVEs → ~12 000 requests).
                        # --project is still accepted as an optional
                        # narrowing filter alongside --cve.
                        if not self.config.cve_filter:
                            self.logger.error(
                                "CVE Impact requires --cve to specify which CVE(s) to analyse. "
                                "--project alone is not supported because it can return "
                                "thousands of CVEs (e.g. 4 000 CVEs → ~12 000 API calls for "
                                "dossier enrichment).  Examples:\n"
                                "  --cve CVE-2022-37434\n"
                                "  --cve CVE-2022-37434,CVE-2023-44487\n"
                                "  --cve CVE-2022-37434 --project openwrt"
                            )
                            raw_data = []
                        else:
                            cve_filters: list[str] = []

                            # Apply --cve filter at the API level
                            if self.config.cve_filter:
                                cve_ids = [
                                    c.strip()
                                    for c in self.config.cve_filter.split(",")
                                    if c.strip()
                                ]
                                if len(cve_ids) == 1:
                                    cve_filters.append(f"cveId=={cve_ids[0]}")
                                else:
                                    cve_filters.append(
                                        f"cveId=in=({','.join(cve_ids)})"
                                    )

                            # Apply --project filter
                            if self.config.project_filter:
                                try:
                                    project_id = int(self.config.project_filter)
                                    cve_filters.append(f"project=={project_id}")
                                except ValueError:
                                    # Resolve project name to ID
                                    resolved_id = self._resolve_project_name(
                                        self.config.project_filter
                                    )
                                    if resolved_id:
                                        cve_filters.append(f"project=={resolved_id}")

                            # Apply --detected-after
                            if getattr(self.config, "detected_after", None):
                                cve_filters.append(
                                    f"detectionDate>={self.config.detected_after}T00:00:00"
                                )

                            cve_query = QueryConfig(
                                endpoint="/public/v0/cves",
                                params=QueryParams(
                                    limit=10000,
                                    filter=";".join(cve_filters)
                                    if cve_filters
                                    else None,
                                ),
                            )
                            self.logger.info(
                                f"Fetching CVEs for {recipe.name}"
                                + (
                                    f" with filter: {cve_query.params.filter}"
                                    if cve_query.params.filter
                                    else ""
                                )
                            )
                            raw_data = self.api_client.fetch_all_with_resume(cve_query)

                            # In dossier mode, enrich with per-finding reachability,
                            # CVE descriptions, and exploit details
                            if self.config.cve_filter and raw_data:
                                (
                                    self._cve_impact_reachability,
                                    self._cve_impact_descriptions,
                                    self._cve_impact_exploit_details,
                                ) = self._fetch_cve_reachability(raw_data)

                    elif recipe.name == "Component List":
                        # Assessment report: shows current component inventory
                        # No date filtering by default (current state, not period-bound)
                        filters = []

                        # Exclude file type components (SAST placeholders without meaningful data)
                        filters.append("type!=file")

                        # Apply --detected-after if specified (opt-in period filtering)
                        if getattr(self.config, "detected_after", None):
                            filters.append(
                                f"created>={self.config.detected_after}T00:00:00"
                            )

                        if self.config.project_filter:
                            try:
                                project_id = int(self.config.project_filter)
                                filters.append(f"project=={project_id}")
                            except ValueError:
                                filters.append(f"project=={self.config.project_filter}")
                        elif self._folder_project_ids:
                            # Folder scoping — add project=in=() filter (sorted for deterministic cache keys)
                            folder_pids = sorted(self._folder_project_ids)
                            filters.append(
                                f"project=in=({','.join(str(pid) for pid in folder_pids)})"
                            )

                        if self.config.version_filter:
                            try:
                                version_id = int(self.config.version_filter)
                                filters.append(f"projectVersion=={version_id}")
                            except ValueError:
                                filters.append(
                                    f"projectVersion=={self.config.version_filter}"
                                )

                        combined_filter = ";".join(filters)

                        unified_query = QueryConfig(
                            endpoint=recipe.query.endpoint,
                            params=QueryParams(
                                limit=recipe.query.params.limit,
                                filter=combined_filter,
                                archived=False,
                                excluded=False,
                            ),
                        )

                        # Use batched version filtering if current_version_only is enabled
                        if (
                            self.config.current_version_only
                            and not self.config.version_filter
                        ):
                            # Scope version resolution to only the projects
                            # being queried — avoids fetching version IDs (and
                            # then components) for projects that the filter will
                            # exclude anyway.
                            if self.config.project_filter:
                                # Single project → resolve just that one version
                                version_ids = self._get_latest_version_ids_for_projects(
                                    [self.config.project_filter]
                                )
                            elif self._folder_project_ids:
                                # Folder scope → resolve only folder projects
                                version_ids = self._get_latest_version_ids_for_projects(
                                    list(self._folder_project_ids)
                                )
                            else:
                                # No project/folder filter → resolve all
                                version_ids = self._get_latest_version_ids()
                            self.logger.info(
                                f"Fetching components for {recipe.name} with --current-version-only ({len(version_ids)} versions), base filter: {combined_filter}"
                            )
                            raw_data = self._fetch_with_version_batching(
                                unified_query,
                                version_ids,
                                entity_type="components",
                            )
                        else:
                            self.logger.info(
                                f"Fetching components for {recipe.name} with filter: {combined_filter}"
                            )
                            raw_data = self.api_client.fetch_all_with_resume(
                                unified_query
                            )
                    elif recipe.name in [
                        "Component Vulnerability Analysis (Pandas)",
                        "Component Vulnerability Analysis",
                        "Executive Summary",
                        "Findings by Project",
                        "Triage Prioritization",
                    ]:
                        # Report category determines period behaviour:
                        #   Operational (Executive Summary): period filters findings by detected date
                        #   Assessment  (CVA, Findings by Project, Triage): shows current state, period ignored
                        is_operational = recipe.name == "Executive Summary"

                        # Build finding type parameters based on --finding-types flag
                        type_params = build_findings_type_params(
                            self.config.finding_types
                        )
                        finding_type = type_params.get("type") or "cve"
                        category_filter = type_params.get("category_filter")

                        # Whether we need to post-filter by date (set True when entity-
                        # level caching is used and date filters are NOT in the API query)
                        needs_date_postfilter = False

                        # Build filter list for non-entity-cached paths
                        # (entity-cached paths skip this and post-filter instead)
                        filters = []
                        if category_filter:
                            filters.append(category_filter)

                        # Operational reports: add detected date range filter
                        if is_operational:
                            filters.append(
                                f"detected>={self.config.start_date}T00:00:00"
                            )
                            filters.append(f"detected<={self.config.end_date}T23:59:59")

                        # Assessment reports: apply --detected-after if specified
                        if not is_operational and getattr(
                            self.config, "detected_after", None
                        ):
                            filters.append(
                                f"detected>={self.config.detected_after}T00:00:00"
                            )

                        if self.config.project_filter:
                            # Single project filter - get all findings for this project
                            try:
                                project_id = int(self.config.project_filter)
                                filters.append(f"project=={project_id}")
                            except ValueError:
                                filters.append(f"project=={self.config.project_filter}")
                            combined_filter = ";".join(filters) if filters else ""

                            unified_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    finding_type=finding_type,
                                    archived=False,
                                    excluded=False,
                                ),
                            )

                            if self.config.version_filter:
                                try:
                                    version_id = int(self.config.version_filter)
                                    filters.append(f"projectVersion=={version_id}")
                                except ValueError:
                                    filters.append(
                                        f"projectVersion=={self.config.version_filter}"
                                    )
                                combined_filter = ";".join(filters) if filters else ""
                                unified_query = QueryConfig(
                                    endpoint=recipe.query.endpoint,
                                    params=QueryParams(
                                        limit=recipe.query.params.limit,
                                        filter=combined_filter,
                                        finding_type=finding_type,
                                        archived=False,
                                        excluded=False,
                                    ),
                                )

                            self.logger.info(
                                f"Fetching findings for {recipe.name} with type={finding_type}, filter: {combined_filter}"
                            )
                            raw_data = self.api_client.fetch_all_with_resume(
                                unified_query
                            )
                        elif self._folder_project_ids:
                            # Folder scoping active — use folder's project set directly
                            # Sort for deterministic batching (ensures SQLite cache hits across runs)
                            folder_pids = sorted(self._folder_project_ids)
                            self.logger.info(
                                f"Fetching findings for {recipe.name} scoped to folder '{self._folder_name}' ({len(folder_pids)} projects)"
                            )

                            combined_filter = ";".join(filters) if filters else ""
                            unified_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    finding_type=finding_type,
                                    archived=False,
                                    excluded=False,
                                ),
                            )

                            if self.config.current_version_only:
                                # Entity-level caching: fetch per-version (shared across reports)
                                version_ids = sorted(
                                    self._get_latest_version_ids_for_projects(
                                        folder_pids
                                    )
                                )
                                self.logger.info(
                                    f"Fetching findings for {recipe.name} with --current-version-only "
                                    f"({len(version_ids)} latest versions)"
                                )
                                raw_data = self._get_findings_for_versions(
                                    version_ids, finding_type, category_filter
                                )
                                needs_date_postfilter = True
                            else:
                                # Batch by project IDs — all versions
                                # Build a cache key from the query signature
                                _pid_str = ",".join(str(p) for p in sorted(folder_pids))
                                _cache_parts = f"{recipe.query.endpoint}|{combined_filter or ''}|{finding_type}|pids:{_pid_str}"
                                _cache_key = hashlib.sha256(
                                    _cache_parts.encode()
                                ).hexdigest()[:16]

                                if _cache_key in self._findings_cache:
                                    raw_data = self._findings_cache[_cache_key]
                                    self.logger.info(
                                        f"Using in-memory cached findings for {recipe.name} "
                                        f"({len(raw_data)} records, same query as a previous report)"
                                    )
                                else:
                                    raw_data = []
                                    # Adaptive batch sizing: reduce batch size for large project counts
                                    batch_size = (
                                        15 if len(folder_pids) > 200 else 25
                                    )  # Keep URLs under server limits
                                    from tqdm import tqdm as _tqdm

                                    total_records = 0
                                    with _tqdm(
                                        range(0, len(folder_pids), batch_size),
                                        desc="Fetching folder findings",
                                        unit=" batches",
                                        leave=False,
                                    ) as pbar:
                                        for i in pbar:
                                            batch_ids = folder_pids[i : i + batch_size]
                                            project_filter_str = f"project=in=({','.join(str(pid) for pid in batch_ids)})"
                                            batch_filters = [
                                                project_filter_str
                                            ] + filters
                                            batch_combined = ";".join(batch_filters)

                                            batch_query = QueryConfig(
                                                endpoint=recipe.query.endpoint,
                                                params=QueryParams(
                                                    limit=recipe.query.params.limit,
                                                    filter=batch_combined,
                                                    finding_type=finding_type,
                                                    archived=False,
                                                    excluded=False,
                                                ),
                                            )
                                            batch_data = (
                                                self.api_client.fetch_all_with_resume(
                                                    batch_query, show_progress=False
                                                )
                                            )
                                            raw_data.extend(batch_data)
                                            total_records += len(batch_data)
                                            del batch_data  # Free batch memory immediately
                                            pbar.set_postfix({"records": total_records})

                                            # Inter-batch delay to reduce server load
                                            # Scales with --request-delay (minimum 1s between batches)
                                            if i + batch_size < len(folder_pids):
                                                time.sleep(
                                                    max(1.0, self.config.request_delay)
                                                )
                                    self._findings_cache[_cache_key] = raw_data

                            self.logger.info(
                                f"Fetched {len(raw_data)} findings for folder scope"
                            )
                        else:
                            # No project filter - get projects scanned in the period, then their findings
                            self.logger.info(
                                f"Finding projects scanned between {self.config.start_date} and {self.config.end_date}..."
                            )

                            # Fetch scans in the period to get project IDs
                            # Use the same early termination logic as Scan Analysis
                            # Apply folder/project filters for cache reuse with Scan Analysis
                            # Note: /scans endpoint has max limit of 100
                            scan_query = QueryConfig(
                                endpoint="/public/v0/scans",
                                params=QueryParams(limit=100, sort="created:desc"),
                            )
                            scan_query = self._apply_scan_filters(scan_query)
                            scans_in_period = self._fetch_scans_with_early_termination(
                                scan_query
                            )

                            # Extract unique project IDs and track latest version per project
                            scanned_project_ids = set()
                            # Track latest version per project: {project_id: (version_id, scan_created)}
                            project_latest_version: dict[str, tuple[str, str]] = {}

                            for scan in scans_in_period:
                                # Scan structure has 'project' and 'projectVersion' at top level
                                project = scan.get("project", {})
                                project_version = scan.get("projectVersion", {})
                                scan_created = scan.get("created", "")

                                # Extract project ID
                                if isinstance(project, dict) and project.get("id"):
                                    project_id = project["id"]
                                    scanned_project_ids.add(project_id)

                                    # Extract version ID
                                    version_id = None
                                    if isinstance(project_version, dict):
                                        version_id = project_version.get("id")

                                    if version_id:
                                        # Keep track of the most recently scanned version per project
                                        if project_id not in project_latest_version:
                                            project_latest_version[project_id] = (
                                                version_id,
                                                scan_created,
                                            )
                                        else:
                                            existing_created = project_latest_version[
                                                project_id
                                            ][1]
                                            if scan_created > existing_created:
                                                project_latest_version[project_id] = (
                                                    version_id,
                                                    scan_created,
                                                )

                            self.logger.info(
                                f"Found {len(scanned_project_ids)} unique projects scanned in the period"
                            )

                            if not scanned_project_ids:
                                self.logger.warning(
                                    "No projects found with scans in the specified period"
                                )
                                raw_data = []
                            elif self.config.current_version_only:
                                # Entity-level caching: fetch per-version (shared across reports)
                                version_ids = self._get_latest_version_ids_for_projects(
                                    list(scanned_project_ids)
                                )
                                self.logger.info(
                                    f"Fetching findings for {len(version_ids)} projects (true latest version each)"
                                )
                                raw_data = self._get_findings_for_versions(
                                    sorted(version_ids), finding_type, category_filter
                                )
                                needs_date_postfilter = True
                            else:
                                # Get findings for all scanned projects (all versions)
                                project_ids = list(scanned_project_ids)
                                self.logger.info(
                                    f"Fetching findings for {len(project_ids)} scanned projects (all versions)"
                                )

                                # Batch by project IDs to avoid URL length limits
                                # Adaptive batch sizing: reduce for large project counts to limit memory and server load
                                raw_data = []
                                batch_size = (
                                    20 if len(project_ids) > 200 else 50
                                )  # Projects per batch
                                from tqdm import tqdm

                                total_records = 0
                                _log_memory(
                                    self.logger,
                                    f"Before batch fetch ({len(project_ids)} projects, batch_size={batch_size})",
                                )
                                with tqdm(
                                    range(0, len(project_ids), batch_size),
                                    desc="Fetching project findings",
                                    unit=" batches",
                                    leave=False,
                                ) as pbar:
                                    for i in pbar:
                                        batch_ids = project_ids[i : i + batch_size]
                                        project_filter = f"project=in=({','.join(str(pid) for pid in batch_ids)})"

                                        batch_filters = [project_filter] + filters
                                        combined_filter = ";".join(batch_filters)

                                        batch_query = QueryConfig(
                                            endpoint=recipe.query.endpoint,
                                            params=QueryParams(
                                                limit=recipe.query.params.limit,
                                                filter=combined_filter,
                                                finding_type=finding_type,
                                                archived=False,
                                                excluded=False,
                                            ),
                                        )
                                        batch_data = (
                                            self.api_client.fetch_all_with_resume(
                                                batch_query, show_progress=False
                                            )
                                        )
                                        raw_data.extend(batch_data)
                                        total_records += len(batch_data)
                                        del batch_data  # Free batch memory immediately
                                        pbar.set_postfix({"records": total_records})

                                        # Inter-batch delay to reduce server load
                                        # Scales with --request-delay (minimum 1s between batches)
                                        if i + batch_size < len(project_ids):
                                            time.sleep(
                                                max(1.0, self.config.request_delay)
                                            )

                                _log_memory(
                                    self.logger,
                                    f"After batch fetch ({total_records} findings)",
                                )
                                self.logger.info(
                                    f"Fetched {total_records} total findings for scanned projects"
                                )
                else:
                    raw_data = self.api_client.fetch_data(recipe.query)

            # --- Date post-filtering for entity-cached paths ---
            # When _get_findings_for_versions was used, data is NOT date-filtered
            # at the API level (entity cache stores ALL findings per version).
            # Apply the date filter in-memory now.
            if needs_date_postfilter and raw_data:
                if is_operational:
                    start = f"{self.config.start_date}T00:00:00"
                    end = f"{self.config.end_date}T23:59:59"
                    before_count = len(raw_data)
                    raw_data = [
                        f
                        for f in raw_data
                        if f.get("detected", "") >= start
                        and f.get("detected", "") <= end
                    ]
                    self.logger.debug(
                        f"Date post-filter ({self.config.start_date} to {self.config.end_date}): "
                        f"{before_count} -> {len(raw_data)} findings"
                    )
                elif not is_operational and getattr(
                    self.config, "detected_after", None
                ):
                    before_count = len(raw_data)
                    raw_data = [
                        f
                        for f in raw_data
                        if f.get("detected", "")
                        >= f"{self.config.detected_after}T00:00:00"
                    ]
                    self.logger.debug(
                        f"Detected-after post-filter ({self.config.detected_after}): "
                        f"{before_count} -> {len(raw_data)} findings"
                    )

            if not raw_data:
                self.logger.warning(f"No data returned for recipe: {recipe.name}")
                raw_data = []

            # --- Apply flattening if needed ---
            if recipe.name == "Component Vulnerability Analysis":
                # Flatten nested structures if needed
                fields_to_flatten = ["component", "project", "finding"]
                if raw_data and isinstance(raw_data, list) and raw_data:
                    from fs_report.data_transformer import flatten_records

                    raw_data = flatten_records(
                        raw_data, fields_to_flatten=fields_to_flatten
                    )
            # --- Inject project_name if needed ---
            # Only do this if the recipe uses project-level grouping
            uses_project = any(
                (t.group_by and "project_name" in t.group_by)
                or (t.calc and t.calc.name == "project_name")
                for t in recipe.transform or []
            )
            if uses_project:
                # Fetch all projects and build mapping
                from fs_report.models import QueryConfig, QueryParams

                project_query = QueryConfig(
                    endpoint="/public/v0/projects",
                    params=QueryParams(
                        limit=1000, offset=0, archived=False, excluded=False
                    ),
                )
                projects = self.api_client.fetch_data(project_query)

                # Build project mapping, handling different ID formats
                project_map = {}
                for p in projects:
                    pid_val = p.get("id") or p.get("projectId")
                    project_name = p.get("name")
                    if pid_val and project_name:
                        # Convert project_id to string to ensure it's hashable
                        project_map[str(pid_val)] = project_name

                # Inject project_name into each finding
                for finding in raw_data:
                    # Handle different project field formats
                    project_field = finding.get("project") or finding.get("projectId")
                    if project_field:
                        if isinstance(project_field, dict):
                            # If project is a dict with id and name, use the name directly
                            project_name = project_field.get("name")
                            if project_name:
                                finding["project_name"] = project_name
                            else:
                                # Fallback to ID lookup
                                pid_str = str(project_field.get("id", project_field))
                                finding["project_name"] = project_map.get(
                                    pid_str, pid_str
                                )
                        else:
                            # If project is just an ID, look it up
                            pid_str = str(project_field)
                            finding["project_name"] = project_map.get(pid_str, pid_str)

            # --- Inject folder_name into raw records ---
            # Build the project-to-folder mapping (either from folder scope or from projects endpoint)
            if self._project_folder_map:
                # Folder scoping active — use the pre-built mapping
                pf_map = self._project_folder_map
            elif raw_data and isinstance(raw_data, list):
                # No folder scoping — try to extract folder from projects data
                pf_map = self._build_project_folder_map_from_projects()
            else:
                pf_map = {}

            if pf_map and raw_data and isinstance(raw_data, list):
                for record in raw_data:
                    # Extract project ID from various formats
                    project_field = record.get("project") or record.get("projectId")
                    pid = None
                    if isinstance(project_field, dict):
                        pid = str(project_field.get("id", ""))
                    elif project_field:
                        pid = str(project_field)

                    if pid and pid in pf_map:
                        record["folder_name"] = pf_map[pid]
                    else:
                        record["folder_name"] = ""

            # Handle additional data for multiple charts
            additional_data: dict[str, Any] = {}
            # Add config for pandas transform functions
            additional_data["config"] = self.config
            # Pass recipe parameters so transforms can access them
            if recipe.parameters:
                additional_data["recipe_parameters"] = recipe.parameters

            # Add project data for Scan Analysis (for new vs existing analysis)
            if (
                recipe.name == "Scan Analysis"
                and hasattr(self, "_scan_analysis_project_data")
                and self._scan_analysis_project_data
            ):
                additional_data["projects"] = self._scan_analysis_project_data

            # Inject CVE Impact reachability data, descriptions, and exploits
            if recipe.name == "CVE Impact":
                if (
                    hasattr(self, "_cve_impact_reachability")
                    and self._cve_impact_reachability
                ):
                    additional_data["reachability"] = self._cve_impact_reachability
                if (
                    hasattr(self, "_cve_impact_descriptions")
                    and self._cve_impact_descriptions
                ):
                    additional_data["cve_descriptions"] = self._cve_impact_descriptions
                if (
                    hasattr(self, "_cve_impact_exploit_details")
                    and self._cve_impact_exploit_details
                ):
                    additional_data[
                        "exploit_details"
                    ] = self._cve_impact_exploit_details

            # Inject Version Comparison data into additional_data
            if recipe.name == "Version Comparison" and hasattr(
                self, "_version_comparison_data"
            ):
                additional_data.update(self._version_comparison_data)

            if recipe.additional_queries:
                for query_name, query_config in recipe.additional_queries.items():
                    self.logger.debug(f"Fetching additional data for {query_name}")
                    self.logger.debug(f"Query config: {query_config}")

                    # Special handling for Component Vulnerability Analysis findings
                    if (
                        recipe.name == "Component Vulnerability Analysis"
                        and query_name == "findings"
                    ):
                        additional_raw_data = self._fetch_findings_with_status_workaround(  # type: ignore[attr-defined]
                            query_config
                        )
                    else:
                        additional_raw_data = self.api_client.fetch_data(query_config)

                    self.logger.debug(
                        f"Additional data for {query_name}: {len(additional_raw_data) if additional_raw_data else 0} records"
                    )

                    # Apply flattening to additional data if needed
                    if (
                        recipe.name == "Component Vulnerability Analysis"
                        and additional_raw_data
                    ):
                        from fs_report.data_transformer import flatten_records

                        self.logger.info(f"Applying flattening to {query_name} data")
                        additional_raw_data = flatten_records(
                            additional_raw_data,
                            fields_to_flatten=["component", "project", "finding"],
                        )

                    # Inject project names if needed
                    if additional_raw_data and uses_project:
                        for finding in additional_raw_data:
                            project_field = finding.get("project") or finding.get(
                                "projectId"
                            )
                            if project_field:
                                if isinstance(project_field, dict):
                                    project_name = project_field.get("name")
                                    if project_name:
                                        finding["project_name"] = project_name
                                    else:
                                        pid_str = str(
                                            project_field.get("id", project_field)
                                        )
                                        finding["project_name"] = project_map.get(
                                            pid_str, pid_str
                                        )
                                else:
                                    pid_str = str(project_field)
                                    finding["project_name"] = project_map.get(
                                        pid_str, pid_str
                                    )

                    # Apply specific transforms if available
                    if query_name == "open_issues" and recipe.open_issues_transform:
                        additional_data[query_name] = self.transformer.transform(
                            additional_raw_data,
                            recipe.open_issues_transform,
                            additional_data={"config": self.config},
                        )
                    elif (
                        query_name == "scan_frequency"
                        and recipe.scan_frequency_transform
                    ):
                        additional_data[query_name] = self.transformer.transform(
                            additional_raw_data,
                            recipe.scan_frequency_transform,
                            additional_data={"config": self.config},
                        )
                    else:
                        additional_data[query_name] = additional_raw_data

            # Add scan frequency data from main findings if transform is defined
            if recipe.scan_frequency_transform:
                self.logger.debug("Applying scan frequency transform to main data")
                additional_data["scan_frequency"] = self.transformer.transform(
                    raw_data,
                    recipe.scan_frequency_transform,
                    additional_data={"config": self.config},
                )

            # Add open issues data from main findings if transform is defined
            if recipe.open_issues_transform:
                self.logger.debug(
                    f"Applying open issues transform to {len(raw_data)} findings"
                )
                additional_data["open_issues"] = self.transformer.transform(
                    raw_data,
                    recipe.open_issues_transform,
                    additional_data={"config": self.config},
                )

            # Apply transformations (pass additional_data for join support)
            self.logger.debug(f"Applying transformations for recipe: {recipe.name}")
            self.logger.debug(f"Raw data count: {len(raw_data)}")
            if isinstance(raw_data, dict):
                self.logger.debug(f"Raw data keys: {list(raw_data.keys())}")
            else:
                self.logger.debug(
                    f"Raw data is a {type(raw_data).__name__}, not logging keys."
                )
            self.logger.debug(f"Additional data keys: {list(additional_data.keys())}")

            # Handle transform_function if present
            transforms_to_apply = recipe.transform
            if hasattr(recipe, "transform_function") and recipe.transform_function:
                from fs_report.models import Transform

                # Create a Transform object with the transform_function
                custom_transform = Transform(
                    transform_function=recipe.transform_function
                )
                transforms_to_apply = [custom_transform]
                self.logger.debug(
                    f"Using custom transform function: {recipe.transform_function}"
                )

            self.logger.debug(
                f"Transform count: {len(transforms_to_apply) if transforms_to_apply else 0}"
            )
            _log_memory(self.logger, f"Before transform ({recipe.name})")
            raw_data_count = len(raw_data) if hasattr(raw_data, "__len__") else 0
            transformed_data = self.transformer.transform(
                raw_data, transforms_to_apply, additional_data=additional_data
            )

            # Handle custom transform functions that return dictionaries with additional data
            if hasattr(recipe, "transform_function") and recipe.transform_function:
                # Check if transform returned a dictionary result in additional_data
                transform_result = additional_data.get("transform_result")
                if transform_result and isinstance(transform_result, dict):
                    self.logger.debug(
                        f"Processing transform result dictionary with keys: {list(transform_result.keys())}"
                    )
                    # Store all keys in additional_data
                    for key, value in transform_result.items():
                        additional_data[key] = value
                    self.logger.debug(
                        "Transform function returned dict with keys, merged into additional_data"
                    )

                    # Write VEX recommendations JSON for Triage Prioritization
                    if recipe.name == "Triage Prioritization":
                        vex_recs = transform_result.get("vex_recommendations", [])
                        if vex_recs:
                            import json
                            from pathlib import Path as _Path

                            # Use the same sanitized directory name as the report renderer
                            sanitized_name = (
                                recipe.name.replace("/", "_")
                                .replace("\\", "_")
                                .replace(":", "_")
                                .replace("*", "_")
                                .replace("?", "_")
                                .replace('"', "_")
                                .replace("<", "_")
                                .replace(">", "_")
                                .replace("|", "_")
                                .strip(" .")
                            )
                            vex_dir = _Path(self.config.output_dir) / sanitized_name
                            vex_dir.mkdir(parents=True, exist_ok=True)
                            vex_path = vex_dir / "vex_recommendations.json"
                            with open(vex_path, "w") as f:
                                json.dump(vex_recs, f, indent=2, default=str)
                            self.logger.info(
                                f"Wrote {len(vex_recs)} VEX recommendations to {vex_path}"
                            )
                            # Track for output listing
                            additional_data.setdefault(
                                "_extra_generated_files", []
                            ).append(str(vex_path))

            # When a transform returns a dict with a "main" key, extract the
            # main DataFrame as the primary report data.  The full dict is
            # already available via additional_data["transform_result"].
            if isinstance(transformed_data, dict) and "main" in transformed_data:
                self.logger.debug(
                    "Extracting 'main' DataFrame from transform result dict"
                )
                transformed_data = transformed_data["main"]

            # Apply portfolio transforms if available (for Component Vulnerability Analysis)
            portfolio_data = None
            if hasattr(recipe, "portfolio_transform") and recipe.portfolio_transform:
                self.logger.debug("Applying portfolio transforms")
                portfolio_data = self.transformer.transform(
                    raw_data,
                    recipe.portfolio_transform,
                    additional_data=additional_data,
                )
            # For CVA with transform_function, the result IS the portfolio data
            elif recipe.name == "Component Vulnerability Analysis" and hasattr(
                recipe, "transform_function"
            ):
                self.logger.debug("Setting CVA transform result as portfolio data")
                portfolio_data = transformed_data
                transformed_data = (
                    pd.DataFrame()
                )  # Empty for main data since we only need portfolio data

            # Free raw_data now that all transforms have consumed it.
            # (For folder-scoped paths, _findings_cache may still hold a reference
            # for cross-report reuse — that's fine; del here just drops this local ref.)
            del raw_data
            gc.collect()
            _log_memory(self.logger, f"After transforms + gc ({recipe.name})")

            # Create report data
            report_data = ReportData(
                recipe_name=recipe.name,
                data=transformed_data,
                metadata={
                    "raw_count": raw_data_count,
                    "transformed_count": len(transformed_data)
                    if hasattr(transformed_data, "__len__")
                    else 1,
                    "portfolio_data": portfolio_data,
                    "recipe": recipe.model_dump(),
                    "cache_stats": self.cache.get_stats(),
                    "additional_data": additional_data,
                    "start_date": self.config.start_date,
                    "end_date": self.config.end_date,
                    "project_filter": self.config.project_filter,
                    "folder_name": self._folder_name,
                    "folder_path": self._folder_path,
                    "folder_filter": self.config.folder_filter,
                    "domain": self.config.domain,
                },
            )

            return report_data

        except Exception as e:
            self.logger.error(f"Error processing recipe {recipe.name}: {e}")
            raise

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()

    def _fetch_cve_reachability(
        self, cve_records: list[dict]
    ) -> tuple[dict[str, list[dict]], dict[str, str], dict[str, list[dict]]]:
        """Fetch per-finding reachability from /findings for dossier mode.

        For each CVE in the records, queries the findings endpoint with
        ``findingId==<cveId>`` to retrieve reachability scores per finding.

        Also fetches CVE descriptions from ``/findings/{findingId}/cves``
        and exploit details from ``/findings/{findingId}/exploits`` for
        each CVE (using any finding's numeric ``id``).

        Returns:
            Tuple of:
            - reachability_map: cveId -> list of finding dicts
            - descriptions_map: cveId -> NVD description string
            - exploit_details_map: cveId -> list of exploit detail dicts
        """
        from fs_report.models import QueryConfig, QueryParams

        reachability_map: dict[str, list[dict]] = {}
        descriptions_map: dict[str, str] = {}
        exploit_details_map: dict[str, list[dict]] = {}

        # Collect unique CVE IDs from the data
        cve_ids: set[str] = set()
        for rec in cve_records:
            cve_id = rec.get("cveId") or rec.get("cve_id")
            if cve_id:
                cve_ids.add(cve_id)

        if not cve_ids:
            return reachability_map, descriptions_map, exploit_details_map

        self.logger.info(
            f"Enriching {len(cve_ids)} CVEs with reachability data from /findings"
        )

        for cve_id in sorted(cve_ids):
            finding_query = QueryConfig(
                endpoint="/public/v0/findings",
                params=QueryParams(
                    limit=10000,
                    filter=f"findingId=={cve_id}",
                ),
            )
            try:
                findings = self.api_client.fetch_all_with_resume(finding_query)
                reachability_map[cve_id] = findings
                self.logger.debug(
                    f"  {cve_id}: {len(findings)} findings with reachability"
                )

                # Fetch CVE description and exploit details using the
                # finding's numeric id and projectVersionId.
                if findings:
                    f0 = findings[0]
                    finding_numeric_id = f0.get("id")
                    # projectVersionId: nested dict or flat cache key
                    pv_obj = f0.get("projectVersion")
                    pv_id = (
                        pv_obj.get("id")
                        if isinstance(pv_obj, dict)
                        else f0.get("project_version_id")
                    )
                    if finding_numeric_id and pv_id:
                        fid = str(finding_numeric_id)
                        pvid = str(pv_id)
                        desc = self._fetch_cve_description(pvid, fid, cve_id)
                        if desc:
                            descriptions_map[cve_id] = desc
                        exploits = self._fetch_cve_exploits(pvid, fid, cve_id)
                        if exploits:
                            exploit_details_map[cve_id] = exploits
            except Exception as exc:
                self.logger.warning(f"Failed to fetch reachability for {cve_id}: {exc}")
                reachability_map[cve_id] = []

        return reachability_map, descriptions_map, exploit_details_map

    def _fetch_cve_description(
        self, project_version_id: str, finding_numeric_id: str, cve_id: str
    ) -> str:
        """Fetch CVE description from /findings/{pvId}/{findingId}/cves.

        The response is a nested dict keyed by CVE ID::

            {
              "CVE-XXXX": {
                "results": {
                  "results": [
                    {
                      "descriptions": [
                        {"lang": "en", "value": "..."},
                        {"lang": "es", "value": "..."}
                      ]
                    }
                  ]
                }
              }
            }

        Returns the English NVD description string, or empty string on failure.
        """
        import time

        url = (
            f"{self.api_client.base_url}/public/v0/findings"
            f"/{project_version_id}/{finding_numeric_id}/cves"
        )
        result = ""
        try:
            resp = self.api_client.client.get(url)
            resp.raise_for_status()
            data = resp.json()
            # Navigate the nested structure: data[cveId].results.results[0].descriptions
            if isinstance(data, dict):
                cve_entry = data.get(cve_id, {})
                if isinstance(cve_entry, dict):
                    results_outer = cve_entry.get("results", {})
                    if isinstance(results_outer, dict):
                        results_inner = results_outer.get("results", [])
                        if isinstance(results_inner, list) and results_inner:
                            descriptions = results_inner[0].get("descriptions", [])
                            # Prefer English description
                            for desc in descriptions:
                                if isinstance(desc, dict) and desc.get("lang") == "en":
                                    result = desc.get("value", "")
                                    break
                            # Fall back to first available description
                            if not result and descriptions:
                                first = descriptions[0]
                                if isinstance(first, dict):
                                    result = first.get("value", "")
            if result:
                self.logger.debug(
                    f"  {cve_id}: fetched description ({len(result)} chars)"
                )
        except Exception as exc:
            self.logger.warning(
                f"Could not fetch CVE description for {cve_id} "
                f"(pv={project_version_id}, finding={finding_numeric_id}): {exc}"
            )
        # Polite delay between API calls
        time.sleep(0.3)
        return result

    def _fetch_cve_exploits(
        self, project_version_id: str, finding_numeric_id: str, cve_id: str
    ) -> list[dict]:
        """Fetch exploit details from /findings/{pvId}/{findingId}/exploits.

        The response is a nested dict keyed by CVE ID::

            {
              "CVE-XXXX": {
                "request": {
                  "exploits": [
                    {
                      "url": "https://...",
                      "name": "exploit description",
                      "refsource": "github-exploits",
                      "exploit_maturity": "poc",
                      "exploit_type": "denial-of-service",
                      ...
                    }
                  ],
                  "counts": {"exploits": 5, ...},
                  "epss": {...}
                }
              }
            }

        Returns a list of exploit detail dicts, or empty list on failure.
        """
        import time

        url = (
            f"{self.api_client.base_url}/public/v0/findings"
            f"/{project_version_id}/{finding_numeric_id}/exploits"
        )
        result: list[dict] = []
        try:
            resp = self.api_client.client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict):
                # Navigate: data[cveId].request.exploits
                cve_entry = data.get(cve_id, {})
                if isinstance(cve_entry, dict):
                    request_obj = cve_entry.get("request", {})
                    if isinstance(request_obj, dict):
                        exploits_list = request_obj.get("exploits", [])
                        if isinstance(exploits_list, list):
                            result = exploits_list
            elif isinstance(data, list):
                result = data
            if result:
                self.logger.debug(f"  {cve_id}: fetched {len(result)} exploit details")
        except Exception as exc:
            self.logger.warning(
                f"Could not fetch exploit details for {cve_id} "
                f"(pv={project_version_id}, finding={finding_numeric_id}): {exc}"
            )
        # Polite delay between API calls
        time.sleep(0.3)
        return result

    def _fetch_scans_with_early_termination(
        self, query_config: "QueryConfig"
    ) -> list[dict]:
        """
        Fetch scans sorted by -created with early termination.
        Stops fetching when we've passed the start date (no more relevant scans).

        The scans endpoint does NOT support RSQL date filtering, so we must
        paginate manually and stop when scans are older than our window.

        Results are cached in-memory (same run) and SQLite (cross-run).

        Note: We extend the cutoff by 7 days to capture scans that were CREATED
        before the period but COMPLETED within it (e.g., long-running scans).
        The transform will do final filtering to include scans completed in range.
        """
        from datetime import datetime, timedelta

        from tqdm import tqdm

        # --- In-memory cache (shared across reports in the same run) ---
        _cache_parts = f"scans|{query_config.params.filter or ''}|{self.config.start_date}|{self.config.end_date}"
        _cache_key = hashlib.sha256(_cache_parts.encode()).hexdigest()[:16]
        if _cache_key in self._findings_cache:
            cached = self._findings_cache[_cache_key]
            self.logger.info(f"Using in-memory cached scans ({len(cached)} records)")
            return cached

        # --- SQLite cache (cross-run) ---
        sqlite_params = {
            "filter": query_config.params.filter or "",
            "sort": "created:desc",
            "start_date": self.config.start_date,
            "end_date": self.config.end_date,
        }
        if (
            self.api_client.sqlite_cache
            and self.api_client.cache_ttl > 0
            and self.api_client.sqlite_cache.is_cache_valid(
                "/public/v0/scans", sqlite_params, self.api_client.cache_ttl
            )
        ):
            sqlite_cached = self.api_client.sqlite_cache.get_cached_data(
                "/public/v0/scans", sqlite_params
            )
            if sqlite_cached is not None:
                self.logger.info(
                    f"Using SQLite cached scans ({len(sqlite_cached)} records)"
                )
                self._findings_cache[_cache_key] = sqlite_cached
                return sqlite_cached

        # --- Fetch from API with early termination ---
        # Parse start date for comparison
        # Extend by 7 days to capture scans that completed in range but started earlier
        actual_start = datetime.fromisoformat(f"{self.config.start_date}T00:00:00")
        start_date = actual_start - timedelta(days=7)

        # Ensure we're sorting by created:desc (newest first)
        from fs_report.models import QueryConfig, QueryParams

        sorted_query = QueryConfig(
            endpoint=query_config.endpoint,
            params=QueryParams(
                filter=query_config.params.filter,
                sort="created:desc",  # Force sort by newest first
                limit=query_config.params.limit or 100,
                offset=0,
            ),
        )

        all_scans = []
        offset = 0
        limit = sorted_query.params.limit or 100
        done = False
        consecutive_old_pages = 0
        old_page_threshold = (
            3  # Stop after N consecutive pages where majority of scans are old
        )

        self.logger.info(
            f"Fetching scans with early termination (extended to {start_date.date()} to capture completions in {self.config.start_date} - {self.config.end_date})"
        )

        import random

        max_retries = 8

        with tqdm(desc="Fetching scans", unit=" records", leave=False) as pbar:
            while not done:
                # Update query with current offset
                page_query = QueryConfig(
                    endpoint=sorted_query.endpoint,
                    params=QueryParams(
                        filter=sorted_query.params.filter,
                        sort=sorted_query.params.sort,
                        limit=limit,
                        offset=offset,
                    ),
                )

                # Fetch this page with retry logic
                page_data = None
                for retry_count in range(max_retries):
                    try:
                        page_data = self.api_client.fetch_data(page_query)
                        break
                    except Exception as e:
                        wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                        self.logger.debug(
                            f"Transient error at offset {offset}: {e}. Retrying in {wait:.1f}s..."
                        )
                        time.sleep(wait)
                        if retry_count >= max_retries - 1:
                            self.logger.error(
                                f"Max retries exceeded at offset {offset}. Aborting."
                            )
                            raise

                if not page_data:
                    break

                # Check each scan and count old vs new
                old_scans_in_page = 0
                new_scans_in_page = 0

                for scan in page_data:
                    scan_created = scan.get("created")
                    scan_in_range = True  # Assume in range unless proven otherwise

                    if scan_created:
                        try:
                            # Parse the scan created timestamp
                            if isinstance(scan_created, str):
                                # Handle various timestamp formats
                                scan_dt = datetime.fromisoformat(
                                    scan_created.replace("Z", "+00:00").split("+")[0]
                                )
                            else:
                                scan_dt = scan_created

                            # Check if scan is before our start date
                            if scan_dt < start_date:
                                scan_in_range = False
                                old_scans_in_page += 1
                            else:
                                new_scans_in_page += 1
                        except (ValueError, TypeError):
                            new_scans_in_page += (
                                1  # Include scans with unparseable dates
                            )
                    else:
                        new_scans_in_page += 1  # Include scans without dates

                    # Only include scans that are in our date range
                    if scan_in_range:
                        all_scans.append(scan)

                pbar.update(len(page_data))
                pbar.set_postfix({"total": len(all_scans), "old": old_scans_in_page})

                # Check if majority of this page is old scans
                total_in_page = old_scans_in_page + new_scans_in_page
                if total_in_page > 0 and old_scans_in_page > (total_in_page / 2):
                    consecutive_old_pages += 1
                    self.logger.debug(
                        f"Page at offset {offset}: {old_scans_in_page}/{total_in_page} old, consecutive_old={consecutive_old_pages}"
                    )
                    if consecutive_old_pages >= old_page_threshold:
                        self.logger.debug(
                            f"Stopping: {old_page_threshold} consecutive majority-old pages reached"
                        )
                        done = True
                else:
                    # Reset counter if we get a page with mostly new scans
                    if consecutive_old_pages > 0:
                        self.logger.debug(
                            f"Page at offset {offset}: {new_scans_in_page}/{total_in_page} new, resetting consecutive counter"
                        )
                    consecutive_old_pages = 0

                # Only stop on truly empty pages - some APIs return partial pages mid-stream
                if len(page_data) == 0:
                    self.logger.debug(f"Stopping: Empty page at offset {offset}")
                    break
                elif len(page_data) < limit:
                    self.logger.debug(
                        f"Partial page at offset {offset}: {len(page_data)} records (continuing)"
                    )

                offset += limit

        self.logger.info(
            f"Fetched {len(all_scans)} scans (early termination saved fetching older scans)"
        )

        # --- Store in caches ---
        self._findings_cache[_cache_key] = all_scans

        # Store in SQLite for cross-run reuse
        if self.api_client.sqlite_cache and self.api_client.cache_ttl > 0:
            qh = self.api_client.sqlite_cache.start_fetch(
                "/public/v0/scans", sqlite_params, self.api_client.cache_ttl
            )
            self.api_client.sqlite_cache.store_records(
                qh, "/public/v0/scans", all_scans
            )
            self.api_client.sqlite_cache.complete_fetch(qh)

        return all_scans

    def _apply_scan_filters(self, query_config: Any) -> Any:
        """Apply project, version, and folder filtering to scan queries."""
        from fs_report.models import QueryConfig, QueryParams

        # Start with the original filter
        original_filter = query_config.params.filter or ""

        # Build additional filters for project and version
        additional_filters = []

        if self.config.project_filter:
            try:
                project_id = int(self.config.project_filter)
                additional_filters.append(f"project=={project_id}")
                self.logger.debug(
                    f"Added project ID filter to scans: project=={project_id}"
                )
            except ValueError:
                # Not an integer, treat as project name
                additional_filters.append(f"project=={self.config.project_filter}")
                self.logger.debug(
                    f"Added project name filter to scans: project=={self.config.project_filter}"
                )
        elif self._folder_project_ids:
            # Folder scoping — add project=in=() filter for scans
            folder_pids = sorted(self._folder_project_ids)
            additional_filters.append(
                f"project=in=({','.join(str(pid) for pid in folder_pids)})"
            )
            self.logger.debug(
                f"Added folder project filter to scans: {len(folder_pids)} projects"
            )

        if self.config.version_filter:
            try:
                version_id = int(self.config.version_filter)
                additional_filters.append(f"projectVersion=={version_id}")
                self.logger.debug(
                    f"Added version ID filter to scans: projectVersion=={version_id}"
                )
            except ValueError:
                # Not an integer, treat as version name
                additional_filters.append(
                    f"projectVersion=={self.config.version_filter}"
                )
                self.logger.debug(
                    f"Added version name filter to scans: projectVersion=={self.config.version_filter}"
                )

        # Combine filters
        if additional_filters:
            combined_filter = ";".join(additional_filters)
            if original_filter:
                final_filter = f"{original_filter};{combined_filter}"
            else:
                final_filter = combined_filter

            # Create new query config with filters
            return QueryConfig(
                endpoint=query_config.endpoint,
                params=QueryParams(
                    filter=final_filter,
                    sort=query_config.params.sort,
                    limit=query_config.params.limit,
                    offset=query_config.params.offset,
                ),
            )

        # No additional filters, return original query
        return query_config

    def clear_cache(self) -> None:
        """Clear the data cache."""
        self.cache.clear()
        self.logger.info("Cache cleared")
