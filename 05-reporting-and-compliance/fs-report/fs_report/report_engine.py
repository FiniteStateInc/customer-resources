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
        self.api_client = APIClient(config, cache=self.cache)
        self.recipe_loader = RecipeLoader(config.recipes_dir)
        
        # Initialize transformer (only pandas is used)
        self.transformer = DataTransformer()
        # self.logger.info("Using Pandas transformer")
            
        self.renderer = ReportRenderer(config.output_dir, config)
        self.data_override = data_override

    def run(self) -> bool:
        """Run the complete report generation process. Returns True if all recipes succeeded."""
        self.logger.info("Starting report generation...")

        # Load recipes
        recipes = self.recipe_loader.load_recipes()
        if not recipes:
            self.logger.warning("No recipes found in recipes directory")
            return False

        # Filter recipes if specific recipe is requested
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

        self.logger.info(f"Loaded {len(recipes)} recipes")

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
                    "User Activity"
                ]:
                    from fs_report.models import QueryConfig, QueryParams
                    if recipe.name == "User Activity":
                        # Build filter for audit endpoint using its specific date format
                        # Format: date=START,date=END (two separate date params)
                        audit_filter = f"date={self.config.start_date}T00:00:00,date={self.config.end_date}T23:59:59"
                        
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
                        raw_data = self.api_client.fetch_all_with_resume(scan_query)
                        
                        # Fetch project data for new vs existing analysis
                        # Store in a variable that will be added to additional_data later
                        self._scan_analysis_project_data = None
                        if hasattr(recipe, 'project_list_query') and recipe.project_list_query:
                            self.logger.info("Fetching project data for Scan Analysis")
                            project_query = QueryConfig(
                                endpoint=recipe.project_list_query.endpoint,
                                params=QueryParams(
                                    limit=recipe.project_list_query.params.limit,
                                    offset=0
                                )
                            )
                            self._scan_analysis_project_data = self.api_client.fetch_all_with_resume(project_query)
                            self.logger.info(f"Fetched {len(self._scan_analysis_project_data)} projects for new/existing analysis")
                    elif recipe.name == "Component List":
                        # Build filter for components endpoint (no date filter)
                        filters = []
                        if self.config.project_filter:
                            try:
                                project_id = int(self.config.project_filter)
                                filters.append(f"project=={project_id}")
                            except ValueError:
                                filters.append(f"project=={self.config.project_filter}")
                        
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
                                filter=combined_filter
                            )
                        )
                        self.logger.info(f"Fetching components for {recipe.name} with filter: {combined_filter}")
                        raw_data = self.api_client.fetch_all_with_resume(unified_query)
                    elif recipe.name in ["Component Vulnerability Analysis (Pandas)", "Component Vulnerability Analysis", "Executive Summary", "Findings by Project"]:
                        # Build consistent base filter for cache key matching
                        base_filter = "detected>=${start};detected<=${end}"
                        if self.config.project_filter:
                            try:
                                project_id = int(self.config.project_filter)
                                base_filter += f";project=={project_id}"
                            except ValueError:
                                base_filter += f";project=={self.config.project_filter}"
                        
                        if self.config.version_filter:
                            try:
                                version_id = int(self.config.version_filter)
                                base_filter += f";projectVersion=={version_id}"
                            except ValueError:
                                base_filter += f";projectVersion=={self.config.version_filter}"
                        
                        # All findings-based reports need ALL findings (no status filter) for complete data
                        # Use just the base filter (date + project + version) for all reports
                        combined_filter = base_filter
                        
                        unified_query = QueryConfig(
                            endpoint=recipe.query.endpoint,
                            params=QueryParams(
                                limit=recipe.query.params.limit,
                                filter=combined_filter
                            )
                        )
                        self.logger.info(f"Fetching findings for {recipe.name} with filter: {combined_filter}")
                        raw_data = self.api_client.fetch_all_with_resume(unified_query)
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
                    params=QueryParams(limit=1000, offset=0),
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
                self.logger.debug("Applying open issues transform to main data")
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
                    self.logger.debug(f"Scan analysis: Daily metrics in main data, raw_data available for additional files")

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
                },
            )

            return report_data

        except Exception as e:
            self.logger.error(f"Error processing recipe {recipe.name}: {e}")
            raise

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()

    def _apply_scan_filters(self, query_config: Any) -> Any:
        """Apply project and version filtering to scan queries."""
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
