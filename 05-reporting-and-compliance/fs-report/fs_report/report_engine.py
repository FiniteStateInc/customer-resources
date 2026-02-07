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

import logging
from typing import Any

import pandas as pd
from rich.console import Console

from fs_report.api_client import APIClient
from fs_report.data_cache import DataCache
from fs_report.models import Config, Recipe, ReportData
from fs_report.recipe_loader import RecipeLoader
from fs_report.renderers import ReportRenderer
from fs_report.data_transformer import DataTransformer
# [REMOVED] All DuckDB-related logic and imports. Only pandas transformer is used.


# Finding type/category mapping for --finding-types flag
CATEGORY_VALUES = {"credentials", "config_issues", "crypto_material", "sast_analysis"}
TYPE_VALUES = {"cve", "sast", "thirdparty"}
CATEGORY_MAP = {
    "credentials": "CREDENTIALS",
    "config_issues": "CONFIG_ISSUES",
    "crypto_material": "CRYPTO_MATERIAL",
    "sast_analysis": "SAST_ANALYSIS",
    "cve": "CVE",
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
    categories = [v for v in values if v in CATEGORY_VALUES]  # credentials, config_issues, etc.
    simple_types = [v for v in values if v in TYPE_VALUES]    # cve, sast, thirdparty
    
    # CVE-only: use type=cve directly (most efficient)
    if simple_types == ["cve"] and not categories:
        return {"type": "cve", "category_filter": None}
    
    # Single non-CVE type: use type param directly
    if len(simple_types) == 1 and simple_types[0] != "cve" and not categories:
        return {"type": simple_types[0], "category_filter": None}
    
    # Multiple types or categories specified: need type=all with category filter
    if categories or len(simple_types) > 1:
        # Build category filter including CVE if specified
        all_categories = []
        if "cve" in simple_types:
            all_categories.append("CVE")
        all_categories.extend([CATEGORY_MAP[c] for c in categories])
        
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
            cache_ttl=getattr(config, 'cache_ttl', 0),
        )
        self.recipe_loader = RecipeLoader(config.recipes_dir)
        
        # Initialize transformer (only pandas is used)
        self.transformer = DataTransformer()
        # self.logger.info("Using Pandas transformer")
            
        self.renderer = ReportRenderer(config.output_dir, config)
        self.data_override = data_override
        
        # Cache for latest version IDs when current_version_only is enabled
        self._latest_version_ids: list[int] | None = None
        
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
                self.logger.warning(f"Error fetching projects for folder '{folder_name}' ({fid}): {e}")

        self.logger.info(
            f"Folder tree: {len(all_folder_ids)} folder(s), "
            f"{len(all_project_ids)} project(s)"
        )

        return all_project_ids, project_folder_map, subfolder_list

    def _build_folder_path(self, folder_id: str, all_folders: list[dict] | None = None) -> str:
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
        
        # Fetch all projects
        from fs_report.models import QueryConfig, QueryParams
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False)
        )
        projects = self.api_client.fetch_all_with_resume(projects_query)
        self.logger.info(f"Found {len(projects)} projects")
        
        project_ids = [p["id"] for p in projects if p.get("id")]
        version_ids = self._get_latest_version_ids_for_projects(project_ids)
        
        self.logger.info(f"Found {len(version_ids)} latest version IDs")
        self._latest_version_ids = version_ids
        return version_ids

    def _get_latest_version_ids_for_projects(self, project_ids: list) -> list[int]:
        """Fetch the current (latest) version ID for each given project.

        Uses the project's defaultBranch.latestVersion.id which is the
        authoritative current version on the platform.
        """
        from tqdm import tqdm
        version_ids = []

        with tqdm(project_ids, desc="Fetching latest versions", unit=" projects", leave=False) as pbar:
            for project_id in pbar:
                try:
                    url = f"{self.api_client.base_url}/public/v0/projects/{project_id}"
                    response = self.api_client.client.get(url)
                    response.raise_for_status()
                    project = response.json()

                    # Extract defaultBranch.latestVersion.id
                    default_branch = project.get("defaultBranch") or {}
                    latest_version = default_branch.get("latestVersion") or {}
                    version_id = latest_version.get("id")
                    if version_id:
                        version_ids.append(version_id)
                    else:
                        self.logger.debug(f"No defaultBranch.latestVersion for project {project_id}")
                except Exception as e:
                    self.logger.debug(f"Error fetching project {project_id}: {e}")

        return version_ids

    def _fetch_with_version_batching(
        self, 
        base_query: "QueryConfig", 
        version_ids: list[int],
        batch_size: int = 100
    ) -> list[dict]:
        """Fetch data in batches, filtering by version IDs."""
        from tqdm import tqdm
        all_results = []
        
        total_batches = (len(version_ids) + batch_size - 1) // batch_size
        
        # Log the base filter being used
        self.logger.debug(f"Version batching with base filter: {base_query.params.filter}")
        
        # Split version IDs into batches with progress bar
        with tqdm(range(0, len(version_ids), batch_size), 
                  desc="Fetching version batches", 
                  unit=" batches",
                  total=total_batches,
                  leave=False) as pbar:
            for i in pbar:
                batch_ids = version_ids[i:i + batch_size]
                
                # Build version filter
                version_filter = f"projectVersion=in=({','.join(str(v) for v in batch_ids)})"
                
                # Combine with existing filter (MUST preserve base filter like type!=file)
                if base_query.params.filter:
                    combined_filter = f"{base_query.params.filter};{version_filter}"
                else:
                    combined_filter = version_filter
                
                self.logger.debug(f"Batch {i//batch_size + 1}/{total_batches} filter: {combined_filter[:100]}...")
                
                # Create batch query
                from fs_report.models import QueryConfig, QueryParams
                batch_query = QueryConfig(
                    endpoint=base_query.endpoint,
                    params=QueryParams(
                        limit=base_query.params.limit,
                        filter=combined_filter,
                        finding_type=base_query.params.finding_type,
                        archived=False,
                        excluded=False,
                    )
                )
                
                batch_results = self.api_client.fetch_all_with_resume(batch_query, show_progress=False)
                all_results.extend(batch_results)
                pbar.set_postfix({"records": len(all_results)})
        
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
        explicit_recipe_requested = (
            self.config.recipe_filter
            or getattr(self.recipe_loader, 'recipe_filter', None)
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
            auto_run_recipes = [r for r in recipes if getattr(r, 'auto_run', True)]
            skipped = len(recipes) - len(auto_run_recipes)
            if skipped > 0:
                self.logger.info(f"Skipping {skipped} recipe(s) with auto_run=false (use --recipe to run them)")
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
        console = Console()
        indent = " " * 11  # (or whatever is appropriate for your logs)
        for idx, recipe in enumerate(recipes, 1):
            try:
                self.logger.info(f"[{idx}/{total}] Generating: {recipe.name} ...")
                # Removed rich spinner: rely on tqdm for progress during data fetch
                report_data = self._process_recipe(recipe)
                if report_data:
                    files = self.renderer.render(recipe, report_data)
                    if files:
                        generated_files.extend(files)
                else:
                    self.logger.error(f"No report data generated for recipe: {recipe.name}")
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


    def _process_recipe(self, recipe: Recipe) -> ReportData | None:
        """Process a single recipe and return report data."""
        try:
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
                if isinstance(self.data_override, list):
                    raw_data = self.data_override
                else:
                    self.logger.debug(f"Override matching: endpoint={endpoint}, override keys={list(self.data_override.keys())}")
                    for key in self.data_override:
                        key_str = str(key)
                        endpoint_str = str(endpoint)
                        self.logger.debug(f"Comparing key='{key_str}' to endpoint='{endpoint_str}'")
                        if key_str == endpoint_str or key_str.endswith(endpoint_str.split("/")[-1]):
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
                ]:
                    from fs_report.models import QueryConfig, QueryParams
                    if recipe.name == "User Activity":
                        # Build filter for audit endpoint using RSQL format
                        # The audit API supports: time=ge=START;time=le=END
                        # (The date=START,date=END format has parsing issues with commas in filter param)
                        audit_filter = f"time=ge={self.config.start_date}T00:00:00Z;time=le={self.config.end_date}T23:59:59Z"
                        
                        unified_query = QueryConfig(
                            endpoint=recipe.query.endpoint,
                            params=QueryParams(
                                limit=recipe.query.params.limit,
                                filter=audit_filter
                            )
                        )
                        self.logger.info(f"Fetching audit events for {recipe.name} with filter: {audit_filter}")
                        raw_data = self.api_client.fetch_all_with_resume(unified_query)
                    elif recipe.name == "Scan Analysis":
                        # Apply project and version filtering to scans
                        scan_query = self._apply_scan_filters(recipe.query)
                        # Use early termination to avoid fetching old scans
                        raw_data = self._fetch_scans_with_early_termination(scan_query)
                        
                        # Fetch project data for new vs existing analysis
                        # Store in a variable that will be added to additional_data later
                        self._scan_analysis_project_data = None
                        if hasattr(recipe, 'project_list_query') and recipe.project_list_query:
                            self.logger.info("Fetching project data for Scan Analysis")
                            project_query = QueryConfig(
                                endpoint=recipe.project_list_query.endpoint,
                                params=QueryParams(
                                    limit=recipe.project_list_query.params.limit,
                                    offset=0,
                                    archived=False,
                                    excluded=False,
                                )
                            )
                            self._scan_analysis_project_data = self.api_client.fetch_all_with_resume(project_query)
                            self.logger.info(f"Fetched {len(self._scan_analysis_project_data)} projects for new/existing analysis")
                    elif recipe.name == "Component List":
                        # Assessment report: shows current component inventory
                        # No date filtering by default (current state, not period-bound)
                        filters = []
                        
                        # Exclude file type components (SAST placeholders without meaningful data)
                        filters.append("type!=file")
                        
                        # Apply --detected-after if specified (opt-in period filtering)
                        if getattr(self.config, 'detected_after', None):
                            filters.append(f"created>={self.config.detected_after}T00:00:00")
                        
                        if self.config.project_filter:
                            try:
                                project_id = int(self.config.project_filter)
                                filters.append(f"project=={project_id}")
                            except ValueError:
                                filters.append(f"project=={self.config.project_filter}")
                        elif self._folder_project_ids:
                            # Folder scoping — add project=in=() filter
                            folder_pids = list(self._folder_project_ids)
                            filters.append(f"project=in=({','.join(str(pid) for pid in folder_pids)})")
                        
                        if self.config.version_filter:
                            try:
                                version_id = int(self.config.version_filter)
                                filters.append(f"projectVersion=={version_id}")
                            except ValueError:
                                filters.append(f"projectVersion=={self.config.version_filter}")
                        
                        combined_filter = ";".join(filters)
                        
                        unified_query = QueryConfig(
                            endpoint=recipe.query.endpoint,
                            params=QueryParams(
                                limit=recipe.query.params.limit,
                                filter=combined_filter,
                                archived=False,
                                excluded=False,
                            )
                        )
                        
                        # Use batched version filtering if current_version_only is enabled
                        if self.config.current_version_only and not self.config.version_filter:
                            version_ids = self._get_latest_version_ids()
                            self.logger.info(f"Fetching components for {recipe.name} with --current-version-only ({len(version_ids)} versions), base filter: {combined_filter}")
                            raw_data = self._fetch_with_version_batching(unified_query, version_ids)
                        else:
                            self.logger.info(f"Fetching components for {recipe.name} with filter: {combined_filter}")
                            raw_data = self.api_client.fetch_all_with_resume(unified_query)
                    elif recipe.name in ["Component Vulnerability Analysis (Pandas)", "Component Vulnerability Analysis", "Executive Summary", "Findings by Project", "Triage Prioritization"]:
                        # Report category determines period behaviour:
                        #   Operational (Executive Summary): period filters findings by detected date
                        #   Assessment  (CVA, Findings by Project, Triage): shows current state, period ignored
                        is_operational = recipe.name == "Executive Summary"
                        
                        # Build finding type parameters based on --finding-types flag
                        type_params = build_findings_type_params(self.config.finding_types)
                        finding_type = type_params.get("type", "cve")
                        category_filter = type_params.get("category_filter")
                        
                        # Start with category filter if specified
                        filters = []
                        if category_filter:
                            filters.append(category_filter)
                        
                        # Operational reports: add detected date range filter
                        if is_operational:
                            filters.append(f"detected>={self.config.start_date}T00:00:00")
                            filters.append(f"detected<={self.config.end_date}T23:59:59")
                        
                        # Assessment reports: apply --detected-after if specified
                        if not is_operational and getattr(self.config, 'detected_after', None):
                            filters.append(f"detected>={self.config.detected_after}T00:00:00")
                        
                        if self.config.project_filter:
                            # Single project filter - get all findings for this project
                            try:
                                project_id = int(self.config.project_filter)
                                filters.append(f"project=={project_id}")
                            except ValueError:
                                filters.append(f"project=={self.config.project_filter}")
                            combined_filter = ";".join(filters) if filters else None
                            
                            unified_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    finding_type=finding_type,
                                    archived=False,
                                    excluded=False,
                                )
                            )
                            
                            if self.config.version_filter:
                                try:
                                    version_id = int(self.config.version_filter)
                                    filters.append(f"projectVersion=={version_id}")
                                except ValueError:
                                    filters.append(f"projectVersion=={self.config.version_filter}")
                                combined_filter = ";".join(filters) if filters else None
                                unified_query = QueryConfig(
                                    endpoint=recipe.query.endpoint,
                                    params=QueryParams(
                                        limit=recipe.query.params.limit,
                                        filter=combined_filter,
                                        finding_type=finding_type,
                                        archived=False,
                                        excluded=False,
                                    )
                                )
                            
                            self.logger.info(f"Fetching findings for {recipe.name} with type={finding_type}, filter: {combined_filter}")
                            raw_data = self.api_client.fetch_all_with_resume(unified_query)
                        elif self._folder_project_ids:
                            # Folder scoping active — use folder's project set directly
                            folder_pids = list(self._folder_project_ids)
                            self.logger.info(f"Fetching findings for {recipe.name} scoped to folder '{self._folder_name}' ({len(folder_pids)} projects)")
                            
                            combined_filter = ";".join(filters) if filters else None
                            unified_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    finding_type=finding_type,
                                    archived=False,
                                    excluded=False,
                                )
                            )
                            
                            if self.config.current_version_only:
                                # Get the true latest version for each folder project
                                version_ids = self._get_latest_version_ids_for_projects(folder_pids)
                                self.logger.info(f"Fetching findings for folder with --current-version-only ({len(version_ids)} latest versions)")
                                raw_data = self._fetch_with_version_batching(unified_query, version_ids)
                            else:
                                # Batch by project IDs — all versions
                                raw_data = []
                                batch_size = 50
                                from tqdm import tqdm as _tqdm
                                with _tqdm(range(0, len(folder_pids), batch_size),
                                           desc=f"Fetching folder findings",
                                           unit=" batches", leave=False) as pbar:
                                    for i in pbar:
                                        batch_ids = folder_pids[i:i + batch_size]
                                        project_filter_str = f"project=in=({','.join(str(pid) for pid in batch_ids)})"
                                        batch_filters = [project_filter_str] + filters
                                        batch_combined = ";".join(batch_filters)
                                        
                                        batch_query = QueryConfig(
                                            endpoint=recipe.query.endpoint,
                                            params=QueryParams(
                                                limit=recipe.query.params.limit,
                                                filter=batch_combined,
                                                finding_type=finding_type,
                                                archived=False,
                                                excluded=False,
                                            )
                                        )
                                        batch_data = self.api_client.fetch_all_with_resume(batch_query, show_progress=False)
                                        raw_data.extend(batch_data)
                                        pbar.set_postfix({"records": len(raw_data)})
                            
                            self.logger.info(f"Fetched {len(raw_data)} findings for folder scope")
                        else:
                            # No project filter - get projects scanned in the period, then their findings
                            self.logger.info(f"Finding projects scanned between {self.config.start_date} and {self.config.end_date}...")
                            
                            # Fetch scans in the period to get project IDs
                            # Use the same early termination logic as Scan Analysis
                            # Note: /scans endpoint has max limit of 100
                            scan_query = QueryConfig(
                                endpoint="/public/v0/scans",
                                params=QueryParams(
                                    limit=100,
                                    sort="created:desc"
                                )
                            )
                            scans_in_period = self._fetch_scans_with_early_termination(scan_query)
                            
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
                                            project_latest_version[project_id] = (version_id, scan_created)
                                        else:
                                            existing_created = project_latest_version[project_id][1]
                                            if scan_created > existing_created:
                                                project_latest_version[project_id] = (version_id, scan_created)
                            
                            self.logger.info(f"Found {len(scanned_project_ids)} unique projects scanned in the period")
                            
                            if not scanned_project_ids:
                                self.logger.warning("No projects found with scans in the specified period")
                                raw_data = []
                            elif self.config.current_version_only:
                                # Use the TRUE latest version per project (queried from API),
                                # not just the latest version scanned within the period.
                                # Scans only determine which projects to include.
                                version_ids = self._get_latest_version_ids_for_projects(list(scanned_project_ids))
                                self.logger.info(f"Fetching findings for {len(version_ids)} projects (true latest version each)")
                                
                                combined_filter = ";".join(filters) if filters else None
                                unified_query = QueryConfig(
                                    endpoint=recipe.query.endpoint,
                                    params=QueryParams(
                                        limit=recipe.query.params.limit,
                                        filter=combined_filter,
                                        finding_type=finding_type,
                                        archived=False,
                                        excluded=False,
                                    )
                                )
                                raw_data = self._fetch_with_version_batching(unified_query, version_ids)
                            else:
                                # Get findings for all scanned projects (all versions)
                                project_ids = list(scanned_project_ids)
                                self.logger.info(f"Fetching findings for {len(project_ids)} scanned projects (all versions)")
                                
                                # Batch by project IDs to avoid URL length limits
                                raw_data = []
                                batch_size = 50  # Projects per batch
                                from tqdm import tqdm
                                
                                with tqdm(range(0, len(project_ids), batch_size),
                                          desc="Fetching project findings",
                                          unit=" batches",
                                          leave=False) as pbar:
                                    for i in pbar:
                                        batch_ids = project_ids[i:i + batch_size]
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
                                            )
                                        )
                                        batch_data = self.api_client.fetch_all_with_resume(batch_query, show_progress=False)
                                        raw_data.extend(batch_data)
                                        pbar.set_postfix({"records": len(raw_data)})
                                
                                self.logger.info(f"Fetched {len(raw_data)} total findings for scanned projects")
                else:
                    raw_data = self.api_client.fetch_data(recipe.query)

            if not raw_data:
                self.logger.warning(f"No data returned for recipe: {recipe.name}")
                return None

            # --- Apply flattening if needed ---
            if recipe.name == "Component Vulnerability Analysis":
                # Flatten nested structures if needed 
                fields_to_flatten = ["component", "project", "finding"]
                if raw_data and isinstance(raw_data, list) and raw_data:
                    from fs_report.data_transformer import flatten_records
                    raw_data = flatten_records(raw_data, fields_to_flatten=fields_to_flatten)
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
                    params=QueryParams(limit=1000, offset=0, archived=False, excluded=False),
                )
                projects = self.api_client.fetch_data(project_query)

                # Build project mapping, handling different ID formats
                project_map = {}
                for p in projects:
                    project_id = p.get("id") or p.get("projectId")
                    project_name = p.get("name")
                    if project_id and project_name:
                        # Convert project_id to string to ensure it's hashable
                        project_map[str(project_id)] = project_name

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
            additional_data['config'] = self.config
            
            # Add project data for Scan Analysis (for new vs existing analysis)
            if recipe.name == "Scan Analysis" and hasattr(self, '_scan_analysis_project_data') and self._scan_analysis_project_data:
                additional_data['projects'] = self._scan_analysis_project_data
            if recipe.additional_queries:
                for query_name, query_config in recipe.additional_queries.items():
                    self.logger.debug(f"Fetching additional data for {query_name}")
                    self.logger.debug(f"Query config: {query_config}")
                    
                    # Special handling for Component Vulnerability Analysis findings
                    if recipe.name == "Component Vulnerability Analysis" and query_name == "findings":
                        additional_raw_data = self._fetch_findings_with_status_workaround(query_config)
                    else:
                        additional_raw_data = self.api_client.fetch_data(query_config)
                    
                    self.logger.debug(
                        f"Additional data for {query_name}: {len(additional_raw_data) if additional_raw_data else 0} records"
                    )

                    # Apply flattening to additional data if needed
                    if recipe.name == "Component Vulnerability Analysis" and additional_raw_data:
                        from fs_report.data_transformer import flatten_records
                        self.logger.info(f"Applying flattening to {query_name} data")
                        additional_raw_data = flatten_records(additional_raw_data, fields_to_flatten=["component", "project", "finding"])

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
                            additional_raw_data, recipe.open_issues_transform, additional_data={'config': self.config}
                        )
                    elif (
                        query_name == "scan_frequency"
                        and recipe.scan_frequency_transform
                    ):
                        additional_data[query_name] = self.transformer.transform(
                            additional_raw_data, recipe.scan_frequency_transform, additional_data={'config': self.config}
                        )
                    else:
                        additional_data[query_name] = additional_raw_data

            # Add scan frequency data from main findings if transform is defined
            if recipe.scan_frequency_transform:
                self.logger.debug("Applying scan frequency transform to main data")
                additional_data["scan_frequency"] = self.transformer.transform(
                    raw_data, recipe.scan_frequency_transform, additional_data={'config': self.config}
                )

            # Add open issues data from main findings if transform is defined
            if recipe.open_issues_transform:
                self.logger.debug(f"Applying open issues transform to {len(raw_data)} findings")
                additional_data["open_issues"] = self.transformer.transform(
                    raw_data, recipe.open_issues_transform, additional_data={'config': self.config}
                )

            # Apply transformations (pass additional_data for join support)
            self.logger.debug(f"Applying transformations for recipe: {recipe.name}")
            self.logger.debug(f"Raw data count: {len(raw_data)}")
            if isinstance(raw_data, dict):
                self.logger.debug(f"Raw data keys: {list(raw_data.keys())}")
            else:
                self.logger.debug(f"Raw data is a {type(raw_data).__name__}, not logging keys.")
            self.logger.debug(f"Additional data keys: {list(additional_data.keys())}")
            
            # Handle transform_function if present
            transforms_to_apply = recipe.transform
            if hasattr(recipe, 'transform_function') and recipe.transform_function:
                from fs_report.models import Transform
                # Create a Transform object with the transform_function
                custom_transform = Transform(transform_function=recipe.transform_function)
                transforms_to_apply = [custom_transform]
                self.logger.debug(f"Using custom transform function: {recipe.transform_function}")
            
            self.logger.debug(
                f"Transform count: {len(transforms_to_apply) if transforms_to_apply else 0}"
            )
            transformed_data = self.transformer.transform(
                raw_data, transforms_to_apply, additional_data=additional_data
            )
            # print(f"DEBUG: transformed_data type: {type(transformed_data)}")
            # if isinstance(transformed_data, dict):
            #     print(f"DEBUG: transformed_data keys: {list(transformed_data.keys())}")
            # else:
            #     print(f"DEBUG: transformed_data is not a dict")

            # Handle custom transform functions that return dictionaries with additional data
            if hasattr(recipe, 'transform_function') and recipe.transform_function:
                # Check if transform returned a dictionary result in additional_data
                transform_result = additional_data.get('transform_result')
                if transform_result and isinstance(transform_result, dict):
                    self.logger.debug(f"Processing transform result dictionary with keys: {list(transform_result.keys())}")
                    # Store all keys in additional_data
                    for key, value in transform_result.items():
                        additional_data[key] = value
                    self.logger.debug(f"Transform function returned dict with keys, merged into additional_data")

                    # Write VEX recommendations JSON for Triage Prioritization
                    if recipe.name == "Triage Prioritization":
                        vex_recs = transform_result.get('vex_recommendations', [])
                        if vex_recs:
                            import json
                            from pathlib import Path as _Path
                            # Use the same sanitized directory name as the report renderer
                            sanitized_name = recipe.name.replace("/", "_").replace("\\", "_").replace(":", "_").replace("*", "_").replace("?", "_").replace('"', "_").replace("<", "_").replace(">", "_").replace("|", "_").strip(" .")
                            vex_dir = _Path(self.config.output_dir) / sanitized_name
                            vex_dir.mkdir(parents=True, exist_ok=True)
                            vex_path = vex_dir / "vex_recommendations.json"
                            with open(vex_path, "w") as f:
                                json.dump(vex_recs, f, indent=2, default=str)
                            self.logger.info(f"Wrote {len(vex_recs)} VEX recommendations to {vex_path}")

            # Apply portfolio transforms if available (for Component Vulnerability Analysis)
            portfolio_data = None
            if hasattr(recipe, 'portfolio_transform') and recipe.portfolio_transform:
                self.logger.debug("Applying portfolio transforms")
                portfolio_data = self.transformer.transform(
                    raw_data, recipe.portfolio_transform, additional_data=additional_data
                )
            # For CVA with transform_function, the result IS the portfolio data
            elif recipe.name == "Component Vulnerability Analysis" and hasattr(recipe, 'transform_function'):
                self.logger.debug("Setting CVA transform result as portfolio data")
                portfolio_data = transformed_data
                transformed_data = pd.DataFrame()  # Empty for main data since we only need portfolio data

            # Create report data
            report_data = ReportData(
                recipe_name=recipe.name,
                data=transformed_data,
                metadata={
                    "raw_count": len(raw_data),
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

    def _fetch_scans_with_early_termination(self, query_config: "QueryConfig") -> list[dict]:
        """
        Fetch scans sorted by -created with early termination.
        Stops fetching when we've passed the start date (no more relevant scans).
        
        Note: We extend the cutoff by 7 days to capture scans that were CREATED
        before the period but COMPLETED within it (e.g., long-running scans).
        The transform will do final filtering to include scans completed in range.
        """
        from datetime import datetime, timedelta
        from tqdm import tqdm
        
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
                offset=0
            )
        )
        
        all_scans = []
        offset = 0
        limit = sorted_query.params.limit
        done = False
        consecutive_old_pages = 0
        old_page_threshold = 3  # Stop after N consecutive pages where majority of scans are old
        
        self.logger.info(f"Fetching scans with early termination (extended to {start_date.date()} to capture completions in {self.config.start_date} - {self.config.end_date})")
        
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
                        offset=offset
                    )
                )
                
                # Fetch this page with retry logic
                page_data = None
                for retry_count in range(max_retries):
                    try:
                        page_data = self.api_client.fetch_data(page_query)
                        break
                    except Exception as e:
                        wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                        self.logger.debug(f"Transient error at offset {offset}: {e}. Retrying in {wait:.1f}s...")
                        import time
                        time.sleep(wait)
                        if retry_count >= max_retries - 1:
                            self.logger.error(f"Max retries exceeded at offset {offset}. Aborting.")
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
                                scan_dt = datetime.fromisoformat(scan_created.replace("Z", "+00:00").split("+")[0])
                            else:
                                scan_dt = scan_created
                            
                            # Check if scan is before our start date
                            if scan_dt < start_date:
                                scan_in_range = False
                                old_scans_in_page += 1
                            else:
                                new_scans_in_page += 1
                        except (ValueError, TypeError):
                            new_scans_in_page += 1  # Include scans with unparseable dates
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
                    self.logger.debug(f"Page at offset {offset}: {old_scans_in_page}/{total_in_page} old, consecutive_old={consecutive_old_pages}")
                    if consecutive_old_pages >= old_page_threshold:
                        self.logger.debug(f"Stopping: {old_page_threshold} consecutive majority-old pages reached")
                        done = True
                else:
                    # Reset counter if we get a page with mostly new scans
                    if consecutive_old_pages > 0:
                        self.logger.debug(f"Page at offset {offset}: {new_scans_in_page}/{total_in_page} new, resetting consecutive counter")
                    consecutive_old_pages = 0
                
                # Only stop on truly empty pages - some APIs return partial pages mid-stream
                if len(page_data) == 0:
                    self.logger.debug(f"Stopping: Empty page at offset {offset}")
                    break
                elif len(page_data) < limit:
                    self.logger.debug(f"Partial page at offset {offset}: {len(page_data)} records (continuing)")
                
                offset += limit
        
        self.logger.info(f"Fetched {len(all_scans)} scans (early termination saved fetching older scans)")
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
                self.logger.debug(f"Added project ID filter to scans: project=={project_id}")
            except ValueError:
                # Not an integer, treat as project name
                additional_filters.append(f"project=={self.config.project_filter}")
                self.logger.debug(f"Added project name filter to scans: project=={self.config.project_filter}")
        elif self._folder_project_ids:
            # Folder scoping — add project=in=() filter for scans
            folder_pids = list(self._folder_project_ids)
            additional_filters.append(f"project=in=({','.join(str(pid) for pid in folder_pids)})")
            self.logger.debug(f"Added folder project filter to scans: {len(folder_pids)} projects")
        
        if self.config.version_filter:
            try:
                version_id = int(self.config.version_filter)
                additional_filters.append(f"projectVersion=={version_id}")
                self.logger.debug(f"Added version ID filter to scans: projectVersion=={version_id}")
            except ValueError:
                # Not an integer, treat as version name
                additional_filters.append(f"projectVersion=={self.config.version_filter}")
                self.logger.debug(f"Added version name filter to scans: projectVersion=={self.config.version_filter}")
        
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
                    offset=query_config.params.offset
                )
            )
        
        # No additional filters, return original query
        return query_config

    def clear_cache(self) -> None:
        """Clear the data cache."""
        self.cache.clear()
        self.logger.info("Cache cleared")
