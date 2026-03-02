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

"""Pydantic models for recipe validation and configuration."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class ChartType(StrEnum):
    """Supported chart types for visualization."""

    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    SCATTER = "scatter"
    PARETO = "pareto"
    BUBBLE = "bubble"
    HEATMAP = "heatmap"
    RADAR = "radar"


class TransformType(StrEnum):
    """Supported transform types."""

    GROUP_BY = "group_by"
    CALC = "calc"
    FILTER = "filter"
    SORT = "sort"
    STRING_AGG = "string_agg"


class CalcOperation(StrEnum):
    """Supported calculation operations."""

    MEAN = "mean"
    SUM = "sum"
    COUNT = "count"
    MIN = "min"
    MAX = "max"
    MEDIAN = "median"


class QueryParams(BaseModel):
    """API query parameters."""

    filter: str | None = None
    sort: str | None = None
    limit: int | None = Field(None, ge=1, le=10000)
    offset: int | None = Field(None, ge=0)
    archived: bool | None = None
    excluded: bool | None = None
    finding_type: str | None = Field(
        None, description="Finding type filter: cve, sast, thirdparty, or all"
    )

    @field_validator("filter")
    @classmethod
    def validate_filter(cls, v: str | None) -> str | None:
        """Validate filter parameter contains valid RSQL syntax."""
        if v is None:
            return v
        # Basic RSQL validation - could be enhanced with a proper RSQL parser
        if ";" in v and "and" in v:
            raise ValueError("Cannot mix ';' and 'and' operators in filter")
        return v


class QueryConfig(BaseModel):
    """API query configuration."""

    endpoint: str = Field(..., description="API endpoint path")
    params: QueryParams = Field(
        default_factory=lambda: QueryParams(limit=None, offset=None)
    )


class GroupByConfig(BaseModel):
    """Group by transform configuration with support for aggregations."""

    keys: list[str] = Field(..., description="Columns to group by")
    aggs: dict[str, str] | None = Field(
        None,
        description="Column aggregations (e.g., {'finding_count': 'SUM', 'risk_score': 'SUM'})",
    )


class StringAggTransform(BaseModel):
    """String aggregation transform configuration."""

    name: str = Field(..., description="Name of the output column")
    column: str = Field(..., description="Column to aggregate")
    separator: str = Field(", ", description="Separator for aggregated values")
    distinct: bool = Field(True, description="Whether to use distinct values only")


class CalcTransform(BaseModel):
    """Calculation transform configuration."""

    name: str = Field(..., description="Name of the calculated column")
    expr: str = Field(..., description="Calculation expression")
    operation: CalcOperation | None = Field(None, description="Aggregation operation")


class FilterTransform(BaseModel):
    """Filter transform configuration."""

    filter: str = Field(..., description="Filter expression")


class SortTransform(BaseModel):
    """Sort transform configuration."""

    sort: list[str] = Field(..., description="Columns to sort by")
    ascending: bool = Field(True, description="Sort direction")


class PivotTransform(BaseModel):
    """Pivot transform configuration."""

    index: str = Field(..., description="Column to use as index (rows)")
    columns: str = Field(..., description="Column to use as columns")
    values: str = Field(..., description="Column to use as values")


class JoinTransform(BaseModel):
    """Join transform configuration."""

    right: str = Field(
        ..., description="Name of the right dataframe (e.g., additional_data key)"
    )
    left_on: list[str] = Field(
        ..., description="Columns in the left dataframe to join on"
    )
    right_on: list[str] = Field(
        ..., description="Columns in the right dataframe to join on"
    )
    how: str = Field("left", description="Type of join: left, right, inner, outer")


class SelectTransform(BaseModel):
    """Column selection transform configuration."""

    columns: list[str] = Field(
        ..., description="Columns to select and their display names"
    )
    # Format: [{"source": "total_risk", "display": "Total Risk Score"}, ...]


class RenameTransform(BaseModel):
    """Rename transform configuration."""

    columns: dict[str, str] = Field(
        ..., description="Column mapping from old name to new name"
    )


class FillnaTransform(BaseModel):
    """Configuration for fillna transform."""

    column: str = Field(..., description="Column to fill null values in")
    value: str | int | float = Field(..., description="Value to fill nulls with")


class Transform(BaseModel):
    """Transform configuration."""

    group_by: list[str] | GroupByConfig | None = None
    string_agg: StringAggTransform | None = None
    calc: CalcTransform | None = None
    filter: str | None = None
    sort: SortTransform | None = None
    pivot: PivotTransform | None = None
    join: JoinTransform | None = None
    select: SelectTransform | None = None
    flatten: list[str] | dict[str, Any] | None = None
    rename: RenameTransform | None = None
    fillna: FillnaTransform | None = None
    transform_function: str | None = None

    @field_validator("*", mode="before")
    @classmethod
    def validate_single_transform(cls, v: Any, info: Any) -> Any:
        """Ensure only one transform type is specified."""
        if info.field_name == "group_by" and v is not None:
            return v
        if info.field_name == "calc" and v is not None:
            return v
        if info.field_name == "filter" and v is not None:
            return v
        if info.field_name == "sort" and v is not None:
            return v
        if info.field_name == "transform_function" and v is not None:
            return v
        return v


class ChartConfig(BaseModel):
    """Individual chart configuration."""

    name: str = Field(..., description="Chart name/identifier")
    chart: ChartType = Field(..., description="Chart type")
    title: str | None = Field(None, description="Chart title")
    description: str | None = Field(None, description="Chart description")
    stacked: bool | None = Field(None, description="Stacked option for bar charts")
    x_column: str | None = Field(None, description="X-axis column name")
    y_columns: list[str] | None = Field(None, description="Y-axis column names")
    labels: dict[str, str] | None = Field(None, description="Custom labels for columns")


class OutputConfig(BaseModel):
    """Output configuration."""

    chart: (ChartType | dict[str, Any]) | None = (
        None  # Legacy single chart support (string or dict)
    )
    charts: list[ChartConfig] | None = None  # Multiple charts support
    table: bool = Field(False, description="Include table in output")
    slide_title: str | None = None
    stacked: bool | None = Field(
        None, description="Stacked bar chart option for bar charts"
    )
    formats: list[str] | None = Field(
        default=None,
        description="List of output formats to generate (e.g., ['csv', 'xlsx', 'html'])",
    )


class Recipe(BaseModel):
    """Recipe configuration for generating reports."""

    name: str = Field(..., description="Recipe name")
    category: str | None = Field(
        None,
        description="Report category: 'assessment' (current state, period ignored) "
        "or 'operational' (period-bound, shows trends over time).",
    )
    execution_order: int = Field(
        50,
        description="Order in which to run this recipe (lower = earlier). "
        "Reports that fetch base data (scans, projects) should run first "
        "so dependent reports can use cached data. "
        "Default: 50. Recommended: 10=scans, 20=findings, 30=components, 40=audit",
    )
    auto_run: bool = Field(
        True,
        description="Whether to include in default runs. "
        "If false, only runs when explicitly requested with --recipe.",
    )
    template: str | None = Field(None, description="HTML template to use for rendering")
    description: str | None = Field(None, description="Recipe description")
    parameters: dict[str, Any] | None = Field(
        None, description="Recipe parameters for customization"
    )
    query: QueryConfig = Field(..., description="API query configuration")
    project_list_query: QueryConfig | None = Field(
        None,
        description="Query for fetching project data (for new vs existing analysis)",
    )
    additional_queries: dict[str, QueryConfig] | None = Field(
        None, description="Additional queries for multiple charts"
    )
    transform: list[Transform] = Field(
        default_factory=list, description="Data transforms"
    )
    transform_function: str | None = Field(
        None, description="Custom transform function name"
    )
    portfolio_transform: list[Transform] | None = Field(
        None, description="Transforms for portfolio analysis chart"
    )
    open_issues_transform: list[Transform] | None = Field(
        None, description="Transforms for open issues chart"
    )
    scan_frequency_transform: list[Transform] | None = Field(
        None, description="Transforms for scan frequency chart"
    )
    requires_project: bool = Field(
        False,
        description="Whether this recipe requires a --project filter. "
        "When true, the engine will refuse to run without one.",
    )
    output: OutputConfig = Field(..., description="Output configuration")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate recipe name."""
        if not v.strip():
            raise ValueError("Recipe name cannot be empty")
        return v.strip()


class Config(BaseModel):
    """Application configuration."""

    auth_token: str = Field(..., description="Finite State API token")
    domain: str = Field(..., description="Finite State domain")
    recipes_dir: str | None = Field(
        None,
        description="Optional external recipes directory (--recipes). "
        "Bundled recipes are always loaded unless --no-bundled-recipes is set.",
    )
    use_bundled_recipes: bool = Field(
        True,
        description="Load bundled recipes from fs_report.recipes package. "
        "Set to False via --no-bundled-recipes to disable.",
    )
    output_dir: str = Field("./output", description="Output directory for reports")
    start_date: str = Field(..., description="Start date in ISO8601 format")
    end_date: str = Field(..., description="End date in ISO8601 format")
    verbose: bool = Field(False, description="Enable verbose logging")
    recipe_filter: str | None = Field(
        None, description="Name of specific recipe to run"
    )
    project_filter: str | None = Field(
        None,
        description="Filter by project (name, ID, or version ID). Use 'list' to see available projects.",
    )
    folder_filter: str | None = Field(
        None,
        description="Scope reports to a folder (name or ID). Includes subfolders. Use 'list-folders' to see available folders.",
    )
    version_filter: str | None = Field(
        None,
        description="Filter by project version (version ID or name). Use 'list-versions' to see available versions.",
    )
    finding_types: str = Field(
        "cve",
        description="Finding types to include. Types: cve, sast, thirdparty, binary_sca, source_sca. Categories: credentials, config_issues, crypto_material. Use 'all' for everything. Comma-separated for multiple.",
    )
    scan_types: str | None = Field(
        None,
        description="Scan types to include (e.g. SCA,SOURCE_SCA,SAST). Comma-separated.",
    )
    scan_statuses: str | None = Field(
        None,
        description="Scan statuses to include (e.g. COMPLETED,ERROR). Comma-separated.",
    )
    low_memory: bool = Field(
        False,
        description="Reduce peak memory for large findings reports. "
        "Drops heavy intermediate columns after per-batch scoring.",
    )
    current_version_only: bool = Field(
        True,
        description="Only include latest version per project (default for performance). Use --all-versions for full history.",
    )
    # SQLite cache options
    cache_ttl: int = Field(
        0,
        description="Cache TTL in seconds. 0 disables cross-run caching (default). "
        "Use --cache-ttl flag to enable persistent cache.",
    )
    cache_dir: str | None = Field(
        None, description="Directory for SQLite cache. Defaults to ~/.fs-report/"
    )
    # Optional date filter for assessment reports
    detected_after: str | None = Field(
        None,
        description="Only include findings detected on or after this date (ISO8601). "
        "Applies to Assessment reports (CVA, Findings by Project, Triage, Component List).",
    )
    # AI remediation guidance options
    ai: bool = Field(
        False,
        description="Enable AI remediation guidance (requires ANTHROPIC_AUTH_TOKEN, OPENAI_API_KEY, or GITHUB_TOKEN)",
    )
    ai_provider: str | None = Field(
        None,
        description="LLM provider override (anthropic, openai, copilot). "
        "Auto-detected from environment variables if not set.",
    )
    ai_model_high: str | None = Field(
        None,
        description="LLM model for summaries (high-capability tier). "
        "Overrides the built-in default for the active provider.",
    )
    ai_model_low: str | None = Field(
        None,
        description="LLM model for per-component guidance (fast/cheap tier). "
        "Overrides the built-in default for the active provider.",
    )
    ai_depth: str = Field(
        "summary",
        description="AI depth: 'summary' (portfolio/project) or 'full' (+ Critical/High components)",
    )
    ai_prompts: bool = Field(
        False,
        description="Export AI prompts to file and HTML for use with any LLM (no API key required)",
    )
    ai_analysis: bool = Field(
        False,
        description="Generate deep AI analysis per action using the summary model. "
        "Produces detailed markdown remediation analysis embedded in the report. "
        "Expensive — uses the high-capability model. Implies ai_prompts.",
    )
    context_file: str | None = Field(
        None,
        description="Path to deployment context YAML file for AI prompt customization.",
    )
    product_type: str | None = Field(
        None,
        description="Product type for AI prompts (firmware, web_app, container, etc.).",
    )
    network_exposure: str | None = Field(
        None,
        description="Network exposure level (air_gapped, internal_only, internet_facing, etc.).",
    )
    nvd_api_key: str | None = Field(
        None,
        description="NVD API key for faster fix-version lookups. "
        "Free from https://nvd.nist.gov/developers/request-an-api-key. "
        "Also reads NVD_API_KEY env var. Increases rate limit from 5 to 50 req/30s.",
    )
    # Version comparison / progress options
    baseline_date: str | None = Field(
        None,
        description="Baseline date for Security Progress report (YYYY-MM-DD). "
        "Overrides the default behaviour of using the earliest version in the period window.",
    )
    baseline_version: str | None = Field(
        None, description="Baseline version ID for Version Comparison report."
    )
    current_version: str | None = Field(
        None, description="Current version ID for Version Comparison report."
    )
    version_sort: str = Field(
        "created",
        description="Sort key for Version Comparison versions: 'created' (chronological) or 'name' (lexicographic).",
    )
    version_sort_desc: bool = Field(
        False,
        description="Reverse version sort order (newest/last first).",
    )
    open_only: bool = Field(
        False,
        description="Only count open findings (exclude NOT_AFFECTED, FALSE_POSITIVE, RESOLVED, RESOLVED_WITH_PEDIGREE). "
        "Applies to Security Progress report.",
    )
    request_delay: float = Field(
        0.5,
        description="Delay in seconds between API requests to avoid overloading the server. "
        "Increase for large portfolios, decrease (e.g. 0.1) for small runs.",
    )
    batch_size: int = Field(
        5,
        description="Number of project versions to fetch per API batch. "
        "Lower values reduce server load (use 3 for very large instances). "
        "Higher values are faster but may overload smaller servers (max 25).",
    )
    cve_filter: str | None = Field(
        None,
        description="Comma-separated CVE IDs to filter (e.g. CVE-2024-1234,CVE-2024-5678). "
        "Used by CVE Impact (dossiers) and Remediation Package (scoped remediation).",
    )
    component_filter: str | None = Field(
        None,
        description="Comma-separated component names (e.g. busybox@1.36.1-r2,dropbear). "
        "Use name@version for exact match, name alone for all versions. "
        "Used by Remediation Package to scope remediation to specific components.",
    )
    scoring_file: str | None = Field(
        None,
        description="Path to a YAML file with custom scoring weights for Triage Prioritization. "
        "Overrides weights defined in the recipe parameters.",
    )
    vex_override: bool = Field(
        False,
        description="Overwrite existing VEX statuses when generating triage recommendations. "
        "By default, findings with an existing VEX status are skipped.",
    )
    apply_vex_triage: str | None = Field(
        None,
        description="Path to vex_recommendations.json to apply to the platform. "
        "Runs VEX application only (no report generation).",
    )
    autotriage: bool = Field(
        False,
        description="Auto-apply VEX recommendations after Triage Prioritization "
        "report completes.",
    )
    overwrite: bool = Field(
        False,
        description="Overwrite existing report files. Without this flag, the CLI refuses "
        "to write into a recipe output directory that already has files.",
    )
    logo: str | None = Field(
        None,
        description="Logo image filename (resolved against ~/.fs-report/logos/) or absolute path.",
    )
    # Cross-server version comparison (hidden flags)
    compare_domain: str | None = Field(
        None,
        description="Secondary server domain for cross-server Version Comparison.",
    )
    compare_auth_token: str | None = Field(
        None,
        description="API token for the secondary server.",
    )
    compare_project: str | None = Field(
        None,
        description="Project name or ID on the secondary server.",
    )
    compare_version: str | None = Field(
        None,
        description="Version ID on the secondary server (optional; defaults to latest).",
    )

    @field_validator("compare_domain", mode="before")
    @classmethod
    def validate_compare_domain(cls, v: str | None) -> str | None:
        """Clean up compare_domain the same way as domain."""
        if v is None:
            return v
        domain = v.strip().lower()
        if not domain:
            return None
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://", 1)[1]
        if domain.endswith("/"):
            domain = domain[:-1]
        return domain

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format."""
        if not v.strip():
            raise ValueError("Domain cannot be empty")
        # Remove protocol and trailing slash if present
        domain = v.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://", 1)[1]
        if domain.endswith("/"):
            domain = domain[:-1]
        return domain

    @field_validator("start_date", "end_date")
    @classmethod
    def validate_date_format(cls, v: str) -> str:
        """Validate date format is ISO8601."""
        try:
            from datetime import datetime

            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError as e:
            raise ValueError(
                f"Invalid date format: {v}. Expected ISO8601 format."
            ) from e

    @model_validator(mode="after")
    def validate_version_requires_project(self) -> "Config":
        """Ensure version_filter is only set when project_filter is also set."""
        if self.version_filter and not self.project_filter:
            raise ValueError(
                "version_filter requires project_filter to be set. "
                "Use --project to specify the project first."
            )
        return self


class ReportData(BaseModel):
    """Report data structure."""

    recipe_name: str
    data: Any
    metadata: dict[str, Any] = Field(default_factory=dict)
