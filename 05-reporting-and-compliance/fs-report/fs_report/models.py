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
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


def normalize_domain(value: str) -> str:
    """Normalize a Finite State domain: lowercase, strip scheme + trailing /.

    Single source of truth for ``Config.domain`` / ``Config.compare_domain``
    validation and the ``fs-report doctor`` preflight, so a user-supplied
    ``https://tenant.example.com/`` never produces a doubled-scheme URL.
    """
    domain = value.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    if domain.endswith("/"):
        domain = domain[:-1]
    return domain


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
    DOUGHNUT = "doughnut"


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
    include_additional_details: bool | None = Field(
        None,
        description="Include additional details (description, remediation, mitigation) in findings response",
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
    y_column: str | None = Field(
        None,
        description="Single Y-axis column (used by line, scatter, heatmap, bar charts that plot a single series)",
    )
    value_column: str | None = Field(
        None,
        description="Numeric value column for pie/doughnut/heatmap charts",
    )
    label_column: str | None = Field(
        None,
        description="Label column for pie/doughnut charts",
    )
    labels: dict[str, str] | None = Field(None, description="Custom labels for columns")


class ColumnSchema(BaseModel):
    """Per-column documentation surfaced in the rendered report itself.

    Renderers (xlsx Schema sheet, HTML/MD column-reference banner) source
    these descriptions so customers can answer "what does this column
    mean?" without leaving the report file. Added 2026-05-26 after a
    customer column-confusion incident showed the meta-bug: report-output
    semantics shouldn't require reading fs-report source.
    """

    name: str = Field(
        ...,
        description="Column header exactly as it appears in the rendered output.",
    )
    source: str = Field(
        ...,
        description="How this column is derived — API field path, computed-from-X, etc.",
    )
    description: str = Field(
        ...,
        description="One- or two-sentence plain-language explanation for the customer.",
    )


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
    columns: list[ColumnSchema] | None = Field(
        default=None,
        description=(
            "Per-column documentation. When set, xlsx output gains a Schema "
            "sheet and HTML/MD output gains a column-reference banner."
        ),
    )
    has_inline_charts: bool = Field(
        False,
        description=(
            "True if the template emits <canvas> + new Chart(...) calls "
            "outside the output.charts declaration list. Read by the "
            "Playwright PDFRenderer to decide whether to wait on the "
            "window.fsReportReady beacon before page.pdf()."
        ),
    )
    pdf_footer_template: str | None = Field(
        None,
        description=(
            "Optional HTML snippet injected into the PDF as a page footer "
            "via Playwright's footer_template parameter. Recipes that "
            "previously relied on CSS @page @bottom-center { content: ... } "
            "must migrate that content here — Chromium does not honor "
            "the CSS margin-box property. The snippet is plain HTML; "
            "Chromium supports a small set of substitution tokens like "
            "<span class='pageNumber'></span> and <span class='date'></span>."
        ),
    )
    pdf_header_template_id: str | None = Field(
        None,
        description=(
            "DOM id of a <template> element in the rendered HTML "
            "containing the PDF header HTML. PDFRenderer extracts the "
            "innerHTML via page.evaluate() and passes it to Chromium's "
            "page.pdf(header_template=...). Lets the recipe template's "
            "Jinja context populate header content (project name, "
            "version, date, base64 logo) — Chromium's header_template "
            "parameter has no template engine, so we render through "
            "Jinja inside the page first, then extract."
        ),
    )
    pdf_margin: dict[str, str] | None = Field(
        None,
        description=(
            "Optional per-recipe PDF page-margin override (dict with keys "
            "'top'/'right'/'bottom'/'left', values as CSS lengths). When "
            "set, Playwright applies these margins via page.pdf(margin=...) "
            "and overrides CSS @page margins. When unset, Chromium honors "
            "CSS @page { margin: ... } declarations from the template. "
            "Use sparingly — the default (CSS @page) is correct for most "
            "recipes."
        ),
    )

    @field_validator("pdf_margin")
    @classmethod
    def _validate_pdf_margin_keys(
        cls, v: dict[str, str] | None
    ) -> dict[str, str] | None:
        if v is None:
            return v
        allowed = {"top", "right", "bottom", "left"}
        bad = set(v.keys()) - allowed
        if bad:
            raise ValueError(
                f"pdf_margin keys must be subset of {sorted(allowed)}; "
                f"got unknown keys {sorted(bad)}"
            )
        return v


class Recipe(BaseModel):
    """Recipe configuration for generating reports."""

    name: str = Field(..., description="Recipe name")
    category: str | None = Field(
        None,
        description="Report category: 'assessment' (current state, period ignored), "
        "'operational' (period-bound, shows trends over time), or 'compound' "
        "(reserved — must be constructed as a CompoundRecipe; see the "
        "compound-reports design spec § 3).",
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
    audience: str | None = Field(
        None,
        description="Consumer audience for this recipe. None = standard user-facing. "
        "Set automatically from the recipe's subdirectory name (e.g., 'forge', 'fs_cli'). "
        "Audience recipes are hidden from 'list recipes' by default.",
    )
    nav_category: (
        Literal[
            "Executive",
            "Investigation",
            "Remediation",
            "Compliance",
            "Exploitability Evidence",
        ]
        | None
    ) = Field(
        None,
        description="UI grouping for --serve and report-server sidebars. "
        "Values: Executive | Investigation | Remediation | Compliance | "
        "Exploitability Evidence. "
        "Distinct from `audience` (consumer subdir) and `category` "
        "(assessment | operational | compound).",
    )
    chart_libraries: list[
        Literal["chartjs", "datalabels", "echarts", "marked", "dompurify"]
    ] = Field(
        default_factory=list,
        description="Third-party JS libraries the recipe's template loads "
        "from a CDN via <head> <script src=...> tags. Consumed by the "
        "compound assembler's _compound_libs.html partial, which emits the "
        "deduplicated union of these libraries across all children in a "
        "bundle. Per the compound-reports design spec § 2, derivation is "
        "explicit (not inferred from output.charts) so template-only deps "
        "like `marked` / `dompurify` are captured. Empty default — B1's "
        "per-template audit populates the field for every existing recipe "
        "by inspecting the template's <script src=...> tags. "
        "NOT a place to declare first-party readiness helpers "
        "(fsEChartsInit, fsReportNewChart, window.fsReportReady beacon) — "
        "those live in template-resident partials (_chart_ready.html, "
        "_echarts_ready.html) that the compound shell includes directly "
        "per spec § 5; they are not CDN-loaded.",
    )
    template: str | None = Field(None, description="HTML template to use for rendering")
    description: str | None = Field(None, description="Recipe description")
    card_description: str | None = Field(
        None,
        description="Short one-line summary for the --serve launcher card front "
        "face (B10 #23). Keeps the full `description` for report subtitles, "
        "tooltips, and `list recipes` while the card stays compact. Falls back "
        "to `description` when unset.",
    )
    parameters: dict[str, Any] | None = Field(
        None, description="Recipe parameters for customization"
    )
    query: QueryConfig | None = Field(None, description="API query configuration")
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
    transform_input: Literal["object"] | None = Field(
        default=None,
        description="When 'object', the recipe's data (data-file override or query result) "
        "is delivered to its transform_function as the raw object, bypassing "
        "DataTransformer's pd.DataFrame coercion. Used by query-less recipes whose "
        "transform consumes a whole {meta,coverage,results}-shaped dict.",
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
    exploit_signals_transform: list[Transform] | None = Field(
        None, description="Transforms for the Exploit Signals gauge chart"
    )
    exploits_over_time_transform: list[Transform] | None = Field(
        None, description="Transforms for the Exploits Over Time line chart"
    )
    requires_project: bool = Field(
        False,
        description="Whether this recipe requires a --project filter. "
        "When true, the engine will refuse to run without one.",
    )
    requires_cve: bool = Field(
        False,
        description="Whether this recipe requires a --cve filter. "
        "When true, the engine will refuse to run without one.",
    )
    requires_project_or_folder: bool = Field(
        False,
        description="Whether this recipe requires --project or --folder to be set.",
    )
    requires_component: bool = Field(
        False,
        description="Whether this recipe requires a --component filter. "
        "When true, the engine refuses to run (and the web launcher routes to "
        "configure) without one — e.g. Component Impact / Component Remediation "
        "Package, whose component IS the primary input.",
    )
    output: OutputConfig = Field(..., description="Output configuration")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate recipe name."""
        if not v.strip():
            raise ValueError("Recipe name cannot be empty")
        return v.strip()

    @field_validator("chart_libraries")
    @classmethod
    def _dedupe_chart_libraries(cls, v: list[str]) -> list[str]:
        """Drop duplicates while preserving declaration order.

        The compound assembler's _compound_libs.html partial emits one
        <script> tag per library; duplicates here would produce duplicate
        <script src=...> tags downstream. Dedup at the model layer keeps
        every downstream consumer simple.
        """
        seen: set[str] = set()
        out: list[str] = []
        for lib in v:
            if lib not in seen:
                seen.add(lib)
                out.append(lib)
        return out

    @field_validator("category")
    @classmethod
    def _validate_category(cls, v: str | None) -> str | None:
        """Constrain category to a known value.

        Allowed values on the base ``Recipe``: ``assessment``, ``operational``.
        The ``compound`` value is reserved for ``CompoundRecipe`` (which
        overrides this field with a ``Literal["compound"]`` type). A bare
        ``Recipe`` cannot declare ``category: compound`` because it
        lacks the required compound-specific fields (title, sections).
        The ``comparison`` value is reserved for ``ComparisonRecipe`` (which
        overrides this field with a ``Literal["comparison"]`` type). A bare
        ``Recipe`` cannot declare ``category: comparison`` because it lacks
        the required comparison-specific fields (needs_component_inventory).
        Empty (``None``) is tolerated so legacy recipes without an
        explicit category still load.

        See the compound-reports design spec § 3 and the meta-compare design
        spec § 1.
        """
        if v is None:
            return v
        # CompoundRecipe overrides this field with Literal["compound"], so
        # Pydantic still enforces that level for subclasses; this validator
        # runs to also reject `category="compound"` on the bare Recipe
        # itself, which lacks the compound-only fields (`title`, `sections`).
        # Structural check (does this class declare `title` as a field?)
        # is robust against renames or class hierarchy changes — the only
        # invariant is that subclasses meant to be compound-capable add
        # the compound fields.
        is_compound_capable = (
            "title" in cls.model_fields and "sections" in cls.model_fields
        )
        # ComparisonRecipe overrides this field with Literal["comparison"].
        # A bare Recipe lacking `needs_component_inventory` cannot declare
        # category: comparison.
        is_comparison_capable = "needs_component_inventory" in cls.model_fields
        allowed_on_base = {"assessment", "operational"}
        if not is_compound_capable and v == "compound":
            raise ValueError(
                "Recipe.category='compound' is not valid on the base Recipe; "
                "use CompoundRecipe (the loader dispatches YAML with "
                "category: compound to the right subclass automatically)."
            )
        if not is_comparison_capable and v == "comparison":
            raise ValueError(
                "Recipe.category='comparison' is not valid on the base Recipe; "
                "use ComparisonRecipe (the loader dispatches YAML with "
                "category: comparison to the right subclass automatically)."
            )
        if v not in allowed_on_base and v not in {"compound", "comparison"}:
            raise ValueError(
                f"Recipe.category must be one of "
                f"{sorted(allowed_on_base | {'compound', 'comparison'})}; "
                f"got {v!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Compound Recipe model — B1.3
# ---------------------------------------------------------------------------
#
# CoverConfig, SectionRef, CompoundOutputConfig, CompoundRecipe, and
# SectionResult implement the compound-recipe contract from the
# compound-reports design spec § 3-5. CompoundRecipe is a Pydantic
# subclass of Recipe, dispatched by the loader on category == "compound".


class CoverConfig(BaseModel):
    """Cover-page metadata for a compound recipe.

    Substitution variables (``{{project_name}}``, ``{{period}}``,
    ``{{title}}``, ``{{generated_at}}``) are resolved by the compound
    assembler at render time — this model just holds the literal field
    values from YAML.

    All fields are optional. Field-level absence has explicit semantics:
    ``subtitle`` falls back to the assembler's default template prose;
    ``logo`` falls back to no logo image on the cover; ``classification``
    falls back to an empty badge. The cover page itself only appears
    when ``CompoundRecipe.cover`` is not ``None`` — see that field's
    docstring for the cover-omission contract.
    """

    subtitle: str | None = Field(
        None,
        description=(
            "Subtitle line under the cover title. Whitelisted substitution "
            "variables: {{project_name}}, {{period}}, {{title}}, {{generated_at}}."
        ),
    )
    logo: str | None = Field(
        None,
        description=(
            "Logo image path. Bare filenames resolve under "
            "~/.fs-report/logos/ via the existing report_engine helper; "
            "absolute paths are honored as-is. PNG (≥144dpi for crisp "
            "PDF) or SVG."
        ),
    )
    classification: str | None = Field(
        None,
        description=(
            "Classification text — appears in the cover badge (lower-right) "
            "and in the @page footer of subsequent pages."
        ),
    )


class SectionRef(BaseModel):
    """One entry in a compound recipe's ``sections:`` list.

    The minimal shape is ``{recipe: "<recipe-name>"}`` referencing a
    child recipe by its canonical ``name`` value (e.g.,
    ``"Executive Summary"``). The optional ``overrides`` dict carries
    per-section engine-config overrides (scope, finding-types, AI, date),
    restricted to the whitelist enforced at the Builder save-route and
    applied at execution by ``_process_compound``. A bare YAML string
    section parses to ``{recipe: ...}`` with ``overrides=None``.
    """

    recipe: str = Field(
        ...,
        description=(
            "The canonical ``recipe.name`` of the child recipe to include "
            '(e.g., "Executive Summary"). The compound assembler resolves '
            "this against the loaded recipe corpus by slug; argv tokens "
            "from the CLI go through the same normalization."
        ),
    )
    overrides: dict[str, Any] | None = Field(
        None,
        description=(
            "Optional per-section engine-config overrides applied to THIS "
            "child only (e.g. ``{project_filter: 'BN85', ai_depth: 'full'}``). "
            "Keys are restricted to a safe whitelist "
            "(``fs_report.compound_overrides.COMPOUND_OVERRIDE_WHITELIST``) "
            "enforced by the Builder save-route; destructive / workflow-only "
            "keys are rejected. None ⇒ the child runs under the bundle's "
            "effective config unchanged."
        ),
    )


class CompoundOutputConfig(OutputConfig):
    """Output config for compound recipes.

    Adds compound-specific fields the assembler reads (``toc``,
    ``page_numbers``). Inherits ``pdf_header_template_id`` /
    ``pdf_footer_template`` so a compound recipe can opt into a custom
    PDF header/footer the same way a standalone recipe does (the shell
    template ships a sensible default — see compound-reports design
    spec § 5).
    """

    toc: bool = Field(
        True,
        description=(
            "Whether to emit the TOC block at compound assembly. Defaults "
            "True; set False for a cover-then-sections deliverable without "
            "an index page."
        ),
    )
    page_numbers: bool = Field(
        True,
        description=(
            "Whether the default <template id='compound-footer'> includes "
            "the <span class='pageNumber'></span> / <span class='totalPages'></span> "
            "placeholders. Defaults True; set False for cover-only "
            "deliverables that suppress the footer entirely."
        ),
    )
    # Override OutputConfig.formats: CSV / XLSX make no sense for a
    # compound bundle (it has no tabular data of its own), and YAML
    # authors should not have to remember to set formats explicitly for
    # the common case. A compound that omits ``formats`` gets HTML+PDF
    # by default. Setting ``formats: []`` is still respected as "no
    # deliverables, just run the children" — the dispatch logs a
    # warning in that case so the YAML choice is visible. (PR #100
    # round-2 multi-review M2-1 / M1-3.)
    formats: list[str] | None = Field(
        default_factory=lambda: ["html", "pdf"],
        description=(
            "Output formats — defaults to ['html', 'pdf'] for compounds "
            "(unlike OutputConfig which defaults to None and lets each "
            "renderer pick). Explicit ``formats: []`` is honored and "
            "produces no deliverables."
        ),
    )


# ---------------------------------------------------------------------------
# AxisConfig — B3.1
# ---------------------------------------------------------------------------
#
# Defined BEFORE CompoundRecipe so the type annotation on
# CompoundRecipe.axis can reference it without a forward reference.


class AxisConfig(BaseModel):
    """Optional pinned scope-references for the two sides of a comparison.

    Both fields are optional.  When ``left`` / ``right`` are ``None``, the
    engine expects the caller to supply the scope at run time via the
    ``--left`` / ``--right`` CLI flags (wired on both ``fs-report compare``
    and ``fs-report run``). Runtime flags override any pinned axis value.

    A ``CompoundRecipe`` with ``axis`` present is a **meta-compare bundle**;
    a compound without ``axis`` is a plain bundle.  The loader enforces the
    invariant that all children of an axis-bearing compound are
    ``ComparisonRecipe`` instances (and that non-axis compounds contain no
    ``ComparisonRecipe`` children).

    Values are raw strings — parse/resolve via :mod:`fs_report.scope_ref`
    at engine dispatch time.
    """

    left: str | None = Field(
        None,
        description=(
            "Scope-ref string for the left/baseline side of the comparison "
            "(e.g., 'project:My Device@v1'). None = caller supplies at run time."
        ),
    )
    right: str | None = Field(
        None,
        description=(
            "Scope-ref string for the right/current side of the comparison "
            "(e.g., 'project:My Device@v2'). None = caller supplies at run time."
        ),
    )


class CompoundRecipe(Recipe):
    """A compound recipe — composes multiple child recipes into one bundle.

    See the compound-reports design spec § 3 for the full contract.
    Constructed by ``RecipeLoader`` when a YAML declares
    ``category: compound``.

    Differences from plain ``Recipe``:

    - ``category`` is constrained to the literal ``"compound"``.
    - ``title`` and ``sections`` are required.
    - ``cover`` is optional (compound can ship without a cover page).
    - ``output`` is typed as ``CompoundOutputConfig`` (carries TOC +
      page-numbers fields).
    - ``auto_run`` defaults to ``False`` so a bare ``fs-report run``
      does not implicitly execute saved bundles.
    - Fields that don't apply to compounds (``transform_function``,
      ``query``, ``project_list_query``, ``chart_libraries``, etc.) are
      rejected at validation time — those concepts belong to the child
      recipes, not the bundle.
    """

    category: Literal["compound"] = Field(
        "compound",
        description="Always 'compound' for a CompoundRecipe.",
    )
    title: str = Field(
        ...,
        description="Cover-page title for the compound deliverable.",
    )
    cover: CoverConfig | None = Field(
        None,
        description="Cover-page metadata; if omitted, the assembler emits no cover.",
    )
    sections: list[SectionRef] = Field(
        ...,
        min_length=1,
        description=(
            "Ordered list of child recipes to include. Each entry "
            "references a recipe by its canonical name (see SectionRef)."
        ),
    )
    output: CompoundOutputConfig = Field(
        default_factory=CompoundOutputConfig,
        description="Compound-specific output configuration.",
    )
    auto_run: bool = Field(
        False,
        description=(
            "Compounds default to False so bare `fs-report run` doesn't "
            "implicitly execute saved bundles; they only run when named "
            "explicitly via --recipe."
        ),
    )
    axis: AxisConfig | None = Field(
        None,
        description=(
            "When present, marks this compound as a meta-compare bundle. "
            "Optionally pins the left/right scope-ref strings for both "
            "sides of the comparison (see AxisConfig). If absent, this "
            "compound is a plain (non-comparison) bundle."
        ),
    )
    global_: dict[str, Any] | None = Field(
        None,
        alias="global",
        description=(
            "Optional authored bundle-wide config block. A normalized dict "
            "mirroring the workflow global "
            "(``fs_report.compound_overrides.normalize_compound_global``): "
            "scope, finding-types, current-version-only, AI, and date mode "
            "(period XOR start/end, with the period_touched / range_touched / "
            "target_agnostic intent flags). None ⇒ the bundle inherits the "
            "run-level config with no authored global. Stored as a normalized "
            "dict (not a typed model) so it shares the workflow's date-mode "
            "semantics verbatim. The YAML key is ``global`` (a Python keyword), "
            "exposed here as ``global_`` via the field alias."
        ),
    )

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _reject_recipe_only_fields(self) -> "CompoundRecipe":
        """Reject fields that don't apply to a compound recipe.

        The compound recipe has no data of its own — query, transform,
        chart-library, and template declarations all belong to the child
        recipes. Pydantic accepts these fields because we inherit from
        Recipe, so a post-init check rejects any non-empty/non-default
        values. ``output.chart`` and ``output.charts`` on the compound's
        own ``output`` block are also rejected.
        """
        forbidden = {
            "transform_function": self.transform_function,
            "query": self.query,
            "project_list_query": self.project_list_query,
            "chart_libraries": self.chart_libraries,
            "transform": self.transform,
            "template": self.template,
            "additional_queries": self.additional_queries,
            "portfolio_transform": self.portfolio_transform,
            "open_issues_transform": self.open_issues_transform,
            "scan_frequency_transform": self.scan_frequency_transform,
            "exploit_signals_transform": self.exploit_signals_transform,
            "exploits_over_time_transform": self.exploits_over_time_transform,
        }
        bad: dict[str, Any] = {
            k: v for k, v in forbidden.items() if v not in (None, [], {}, "")
        }
        # output.chart / output.charts on the compound's own output block
        # are equally invalid — charts belong on children, not the bundle.
        if self.output.chart is not None:
            bad["output.chart"] = self.output.chart
        if self.output.charts:
            bad["output.charts"] = self.output.charts
        if bad:
            raise ValueError(
                f"CompoundRecipe cannot declare {sorted(bad)} — those fields "
                "belong on child recipes. Move them to the relevant child "
                "in the `sections:` list."
            )
        return self


# ---------------------------------------------------------------------------
# ComparisonRecipe — B3.1
# ---------------------------------------------------------------------------
#
# A comparison recipe fetches data for ONE side (left or right) of a
# meta-compare bundle.  The compound assembler runs it twice — once per side
# — and diffs the results.  The loader dispatches YAML with
# category: comparison to this subclass.


class ComparisonRecipe(Recipe):
    """A comparison recipe — fetches one side of a meta-compare report.

    See the meta-compare design spec § 1, § 2.  Constructed by
    ``RecipeLoader`` when a YAML declares ``category: comparison``.

    Differences from plain ``Recipe``:

    - ``category`` is constrained to the literal ``"comparison"``.
    - ``query`` and ``transform_function`` are required.
    - ``additional_queries`` is rejected (v1: one query per side).
    - ``query.endpoint`` must be ``/public/v0/findings`` or
      ``/public/v0/components`` (v1 scope-injection contract).
    - ``auto_run`` defaults to ``False`` so bare ``fs-report run`` does not
      execute comparison recipes outside of a meta-compare bundle.
    - ``needs_component_inventory`` enables the engine to also fetch each
      side's component inventory for fix-evidence classification.
    """

    category: Literal["comparison"] = Field(
        "comparison",
        description="Always 'comparison' for a ComparisonRecipe.",
    )
    auto_run: bool = Field(
        False,
        description=(
            "Comparison recipes default to False so bare `fs-report run` "
            "doesn't implicitly run them outside a meta-compare bundle; "
            "they only run when named explicitly via --recipe or invoked "
            "as a child of an axis-bearing CompoundRecipe."
        ),
    )
    needs_component_inventory: bool = Field(
        False,
        description=(
            "When True, the engine also fetches each side's component "
            "inventory for fix-evidence classification alongside the "
            "primary findings/components query."
        ),
    )

    _ALLOWED_ENDPOINTS: frozenset[str] = frozenset(
        {"/public/v0/findings", "/public/v0/components"}
    )

    @model_validator(mode="after")
    def _validate_comparison_fields(self) -> "ComparisonRecipe":
        """Enforce comparison-specific field contracts."""
        # query is required
        if self.query is None:
            raise ValueError(
                "ComparisonRecipe requires 'query' to be set "
                "(the endpoint that fetches one side's data)."
            )
        # transform_function is required
        if not self.transform_function:
            raise ValueError(
                "ComparisonRecipe requires 'transform_function' to be set "
                "(the function that diffs the two sides' data)."
            )
        # additional_queries is rejected: v1 is one query per side
        if self.additional_queries:
            raise ValueError(
                "ComparisonRecipe cannot declare 'additional_queries'; "
                "v1 supports exactly one query per side. "
                "Remove additional_queries from this recipe."
            )
        # endpoint must be findings or components
        if self.query.endpoint not in self._ALLOWED_ENDPOINTS:
            raise ValueError(
                f"ComparisonRecipe.query.endpoint must be one of "
                f"{sorted(self._ALLOWED_ENDPOINTS)} (v1 scope-injection "
                f"contract); got {self.query.endpoint!r}."
            )
        return self


# ---------------------------------------------------------------------------
# SectionResult — the engine→assembler contract
# ---------------------------------------------------------------------------
#
# ``_process_compound`` builds a list of these per-child during dispatch.
# The compound assembler iterates the list to produce TOC entries +
# body blocks. Both variants carry ``slug`` (bare recipe slug; the
# section id is always ``fs-section-{slug}`` computed where needed)
# and ``title`` (recipe.name or output.slide_title).


class RenderedFragment(BaseModel):
    """A successfully-rendered child recipe fragment."""

    slug: str = Field(
        ...,
        description=(
            "Bare recipe slug (e.g., 'executive-summary'). The section id "
            "and CSS scope class are computed as ``fs-section-{slug}``."
        ),
    )
    title: str = Field(
        ...,
        description="Display title for the TOC + section divider.",
    )
    html: str = Field(
        ...,
        description="Pre-assembled fragment HTML (output of render_fragment).",
    )
    summary: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Child transform summary dict (comparison facets), for the "
            "compound exec overview. None for non-comparison children."
        ),
    )
    rows: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Per-facet row lists from the child transform (comparison facets), "
            "for the compound exec Action Plan. Carries the keys "
            "``port_fixes_left_to_right``, ``port_fixes_right_to_left``, "
            "``version_skew``, ``triaged_left_untriaged_right``, "
            "``triaged_right_untriaged_left``, ``status_divergence`` when the "
            "child emits them. None for non-comparison children."
        ),
    )


class FailedSection(BaseModel):
    """A child recipe that failed to render — placeholder for the assembler."""

    slug: str = Field(
        ...,
        description=(
            "Bare recipe slug. Same id-computation rule as RenderedFragment "
            "so TOC links to a failed section still resolve."
        ),
    )
    title: str = Field(
        ...,
        description="Display title for the TOC entry + failure callout.",
    )
    error: str = Field(
        ...,
        description=(
            "Human-readable error message (exception str, or "
            "'no report data' for a None return from _process_recipe)."
        ),
    )


SectionResult = RenderedFragment | FailedSection


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
    period_explicit: bool = Field(
        False,
        description="True when the user passed --period, --start, or --end. "
        "When False, start_date/end_date reflect internal defaults (30-day "
        "window) that some consumers treat as 'not requested'.",
    )
    detailed_mode: bool = Field(
        False,
        description="Executive Dashboard: True opts into the legacy "
        "findings-fetch pipeline (per-finding detection histograms, "
        "Critical/High severity-over-time lines). Default False uses "
        "summary-count endpoints for <10 min portfolio runs.",
    )
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
        description="Finding types to include. Types: cve, sast, thirdparty. Categories: credentials, config_issues, crypto_material. Use 'all' for everything. Comma-separated for multiple. (binary_sca/source_sca are deprecated and stripped — they're scan types, not finding-type filters.)",
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
    standalone: bool = Field(
        False,
        description="Skip project dependency resolution. When True, only "
        "include direct findings for the target project (no dependency traversal).",
    )
    current_version_only: bool = Field(
        True,
        description="Only include latest version per project (default for performance). Use --all-versions for full history.",
    )
    # Theme for HTML output
    theme: Literal["light", "dark", "auto"] = Field(
        "auto",
        description="HTML theme: 'auto' (default — defer to the viewer's "
        "localStorage / ?theme= override / prefers-color-scheme, falling "
        "back to light), 'light', or 'dark'. Explicit 'light' or 'dark' is "
        "authoritative on initial render and skips viewer preference. "
        "PDF exports always render in light theme regardless of this value.",
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
    cache_refresh: bool = Field(
        False,
        description="Force fresh API fetch, bypassing cache reads. "
        "Fresh data is still written to cache for future runs.",
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
        description="Enable AI remediation guidance (requires ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, or GITHUB_TOKEN)",
    )
    ai_provider: str | None = Field(
        None,
        description="LLM provider override (anthropic, openai, copilot, gemini). "
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
    ai_export: str | None = Field(
        None,
        description="Export AI prompts to a JSON file for offline/airgapped LLM processing. "
        "Each prompt includes an ID, system prompt, user prompt, and context.",
    )
    ai_import: str | None = Field(
        None,
        description="Import AI responses from a JSON file (produced by processing --ai-export "
        "output through an LLM). Maps prompt IDs to response text.",
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
    regulatory: str | None = Field(
        None,
        description="Regulatory frameworks for AI prompts (e.g. 'IEC-62443, FDA').",
    )
    deployment_notes: str | None = Field(
        None,
        description="Free-text deployment notes for AI prompts (max 500 chars).",
    )
    threat_context: str | None = Field(
        None,
        description="Free-text threat/vulnerability context for Component Remediation "
        "Package. Describes what is known about the zero-day or threat scenario. "
        "Injected into AI prompts to produce more targeted guidance.",
    )
    nvd_api_key: str | None = Field(
        None,
        description="NVD API key (optional). A hosted mirror is used by default for "
        "NVD lookups. Only needed as fallback if the mirror is unavailable. "
        "Also reads NVD_API_KEY env var.",
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
        "Used by Remediation Package, Findings by Project, Triage Prioritization, "
        "and Component Vulnerability Analysis to scope to specific components.",
    )
    component_match: Literal["contains", "exact"] = Field(
        "contains",
        description="Match mode for --component: 'contains' (default, case-insensitive "
        "substring) or 'exact' (exact name match). name@version specs always use exact.",
    )
    component_version: str | None = Field(
        None,
        description="Version range filter for Component Impact report (e.g. '<2.0', '>=1.0,<2.0', '1.36.1'). "
        "Used with --component to scope impact to specific version ranges.",
    )
    license_filter: str | None = Field(
        None,
        description="Comma-separated license name(s) to filter the License Report "
        "(case-insensitive substring match, e.g. 'GPL,AGPL'). "
        "Restricts the report to components/projects whose declared license matches.",
    )
    skip_nvd: bool = Field(
        False,
        description="Skip NVD enrichment entirely. Useful for faster runs when NVD "
        "data is not needed.",
    )
    scoring_file: str | None = Field(
        None,
        description="Path to a YAML file with custom scoring weights for Triage Prioritization. "
        "Overrides weights defined in the recipe parameters.",
    )
    tp_gate: str | None = Field(
        None,
        description="Triage Prioritization gate filter. Restricts findings to a specific "
        "gate tier: GATE_1 (critical), GATE_2 (high), or NONE (additive only). "
        "Applied after gate assignment, before rendering.",
    )
    top: int = Field(
        0,
        description="Limit Triage Prioritization output to the top N findings by score. "
        "0 = show all (default).",
    )
    triage: int = Field(
        0,
        description="Limit Triage Prioritization VEX recommendations to the top N findings "
        "by score. The full findings list is still displayed. 0 = all eligible (default).",
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
    autotriage: str | None = Field(
        None,
        description="Auto-apply VEX recommendations after report completes. "
        "Levels: 'high' (mechanical only), 'medium' (+ AI high confidence), "
        "'all' (all candidates). Default when flag given without value: 'high'.",
    )
    autotriage_status: list[str] | None = Field(
        None,
        description="Filter autotriage/apply-vex-triage to specific VEX statuses. "
        "Comma-separated list of statuses to apply (e.g. 'NOT_AFFECTED' for "
        "unreachables only, 'IN_TRIAGE,NOT_AFFECTED' for both). "
        "When not set, all recommended statuses are applied.",
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

    # ---- Meta-compare axis scopes (B3.6) ----
    # Runtime scope-ref strings for the two sides of a comparison. When set
    # they override any pinned axis.left / axis.right on a saved meta-compare
    # CompoundRecipe. Parsed via fs_report.scope_ref.parse and resolved by
    # ReportEngine._resolve_scope at dispatch time. CLI flag wiring
    # (--left / --right on run/compare) lands in B3.7.
    # See docs/superpowers/specs/2026-05-11-meta-compare-design.md § 4-5,
    # decisions #1, #14.
    left_scope: str | None = Field(
        None,
        description=(
            "Scope-ref string for the left/baseline side of a meta-compare "
            "(e.g. 'project:BN85@v3'). Overrides a saved bundle's pinned "
            "axis.left. None = use the pinned value or fail fast if neither."
        ),
    )
    right_scope: str | None = Field(
        None,
        description=(
            "Scope-ref string for the right/current side of a meta-compare "
            "(e.g. 'project:BE65@v2'). Overrides a saved bundle's pinned "
            "axis.right. None = use the pinned value or fail fast if neither."
        ),
    )

    # ---- CRA Compliance morning-queue (added 2026-05-24, spec step 3) ----
    since: str = Field(
        "24h",
        description="CRA Compliance --since window: duration (e.g. '24h', '7d'), ISO 8601 datetime, or 'last-run'.",
    )
    exploit_maturity_threshold: list[str] | None = Field(
        None,
        description="CRA tier set above threshold. Values: kev, weaponized, poc, ransomware, threat_actor, botnet, commercial, reported. None defers to the recipe YAML default (kev, ransomware, threat_actor, weaponized, botnet); poc/commercial/reported are recognized but opt-in.",
    )
    include_status: list[str] | None = Field(
        None,
        description="Statuses to include in CRA Fetch A. None defers to recipe YAML (OPEN, NO_STATUS, UNKNOWN, IN_TRIAGE — matches _OPEN_STATUSES used elsewhere).",
    )
    exclude_status: list[str] | None = Field(
        None,
        description="Statuses to exclude from Fetch A even when included. None defers to recipe YAML (FALSE_POSITIVE, NOT_AFFECTED, RESOLVED, RESOLVED_WITH_PEDIGREE).",
    )
    reachable_only: bool = Field(
        False,
        description="CRA Compliance: filter output to reachability_label==REACHABLE.",
    )
    with_triage_age: bool = Field(
        False,
        description="CRA Compliance: enable per-finding /activity fan-out to compute triage_age_days for the ⏰ section. Off by default to avoid the per-finding API cost.",
    )
    kev_due_date_source: str = Field(
        "cisa",
        description="CRA Compliance: source for the Article 14 notification clock. 'cisa' (default) joins on the public CISA KEV catalog. 'none' disables CISA enrichment and suppresses the 🔥 SLA-Breach section (useful for tenants without CISA KEV coverage). 'api' is reserved for a future platform-side due-date endpoint (wishlist #14) and currently raises.",
    )
    unfilterable_tier_strategy: str = Field(
        "wide-fetch",
        description="CRA Compliance: how to handle tiers (ransomware, threat_actor, botnet, commercial, reported) that the /findings API cannot filter directly. 'wide-fetch' (default): drop the threshold filter from Fetch A and narrow client-side. 'drop-tier': warn and omit the unfilterable tiers from the effective threshold. 'require-rsql': abort with a clear error.",
    )
    snapshot_diff: str = Field(
        "on",
        description="CRA Compliance snapshot-diff mode. 'on' (default): fetch the status-agnostic baseline, persist new state after a successful run, detect KEV and exploitInfo-token crossings (ransomware / threat_actor / botnet / commercial / reported). 'read-only': read prior state but do not write a new one. 'off': skip Fetch C entirely; crossings will not be reported.",
    )

    @field_validator("kev_due_date_source")
    @classmethod
    def validate_kev_due_date_source(cls, v: str) -> str:
        valid = {"cisa", "none", "api"}
        if v not in valid:
            raise ValueError(
                f"kev_due_date_source must be one of {sorted(valid)}; got {v!r}"
            )
        if v == "api":
            raise ValueError(
                "kev_due_date_source='api' is not yet implemented (waiting on "
                "platform wishlist #14 — a /cve/{id}/due-date endpoint). Use "
                "'cisa' for CISA KEV joins, or 'none' to disable the "
                "🔥 SLA-Breach section."
            )
        return v

    @field_validator("compare_domain", mode="before")
    @classmethod
    def validate_compare_domain(cls, v: str | None) -> str | None:
        """Clean up compare_domain the same way as domain."""
        if v is None:
            return v
        return normalize_domain(v) or None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format."""
        if not v.strip():
            raise ValueError("Domain cannot be empty")
        return normalize_domain(v)

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
