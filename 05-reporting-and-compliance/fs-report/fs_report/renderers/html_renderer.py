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

"""HTML renderer using Jinja2 templates."""

import importlib.resources
import json
import logging
import math
import re
from pathlib import Path
from typing import Any, cast

import numpy as np
import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from fs_report.models import Recipe, ReportData
from fs_report.renderers.chart_palette import (
    FS_CHART_PALETTE,
    FS_FONT_BODY,
    FS_FONT_DISPLAY,
    FS_HAIRLINE,
    FS_INK,
    FS_INK_DIM,
    FS_NAV_PALETTE,
    FS_SEV_PALETTE,
    SLACK_LINK_COLOR,
)
from fs_report.renderers.fragment_extractor import extract_fragment
from fs_report.renderers.render_mode import RenderMode
from fs_report.scope_resolution import compute_effective_scope
from fs_report.slug import slug

logger = logging.getLogger(__name__)


def _recipe_scope_class(recipe: Recipe) -> str:
    """Derive the ``.fs-section-<slug>`` class used for fragment scoping.

    Uses the canonical :func:`fs_report.slug.slug` function so the scope
    class matches the compound-report TOC anchor (`#fs-section-<slug>`),
    DOM id, output directory name, and CLI argv resolution. See the
    compound-reports design spec § 7 "Canonical slug() function".
    """
    name = (recipe.name or "section").strip() or "section"
    return f"fs-section-{slug(name)}"


def _slack_mrkdwn_to_html(text: str) -> str:
    """Convert Slack mrkdwn formatting to HTML.

    Handles: *bold*, _italic_, ~strikethrough~, <url|label> links,
    and newlines → <br>.  Returns a Markup string (safe for Jinja2).
    """

    from markupsafe import Markup

    # Escape HTML entities first
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    h = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Slack links: <url|label> → <a href="url">label</a>
    # Color comes from chart_palette.SLACK_LINK_COLOR (resolved hex, not a
    # CSS var — inline style="..." attrs don't reliably resolve var()
    # across arbitrary DOM contexts).
    h = re.sub(
        r"&lt;(https?://[^|&]+)\|([^&]+)&gt;",
        rf'<a href="\1" style="color:{SLACK_LINK_COLOR};">\2</a>',
        h,
    )
    # Bare Slack links: <url> → <a href="url">url</a>
    h = re.sub(
        r"&lt;(https?://[^&]+)&gt;",
        rf'<a href="\1" style="color:{SLACK_LINK_COLOR};">\1</a>',
        h,
    )

    # Bold: *text* (not preceded/followed by space inside)
    h = re.sub(r"\*([^\*\n]+)\*", r"<strong>\1</strong>", h)
    # Italic: _text_
    h = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"<em>\1</em>", h)
    # Strikethrough: ~text~
    h = re.sub(r"~([^~\n]+)~", r"<s>\1</s>", h)
    # Newlines
    h = h.replace("\n", "<br>")

    return Markup(h)


def convert_to_native_types(obj: Any, _depth: int = 0) -> Any:
    """
    Recursively convert pandas/numpy objects to native Python types.
    This helps prevent ambiguous truth value errors in Jinja2 templates.

    NaN / NA sentinels are normalised to ``None`` so that Jinja2 templates
    can use simple truthiness checks (``if value``) and type tests
    (``value is string``) without stumbling on ``float('nan')``.
    """
    if _depth > 100:
        # Safety valve — avoid hitting Python's recursion limit on
        # unexpectedly deep / circular structures.
        return obj
    if obj is None:
        return None
    # Normalise all NA-like sentinels to None *before* checking concrete
    # types so that np.float64('nan') doesn't slip through as float(nan).
    if obj is pd.NaT:
        return None
    try:
        if obj is pd.NA:
            return None
    except AttributeError:
        pass  # Very old pandas without pd.NA
    if isinstance(obj, float) and math.isnan(obj):
        return None
    if isinstance(obj, pd.Series):
        return [convert_to_native_types(v, _depth + 1) for v in obj.tolist()]
    elif isinstance(obj, pd.DataFrame):
        return [
            convert_to_native_types(row, _depth + 1) for row in obj.to_dict("records")
        ]
    elif isinstance(obj, np.ndarray):
        return [convert_to_native_types(v, _depth + 1) for v in obj.tolist()]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        v = float(obj)
        return None if math.isnan(v) else v
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, dict):
        return {
            key: convert_to_native_types(value, _depth + 1)
            for key, value in obj.items()
        }
    elif isinstance(obj, list):
        return [convert_to_native_types(item, _depth + 1) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_to_native_types(item, _depth + 1) for item in obj)
    else:
        return obj


def scan_for_pandas_objects(obj: Any, path: str = "root", _depth: int = 0) -> None:
    """
    Recursively scan for pandas/numpy objects and log them.
    This helps identify variables that might cause ambiguous truth value errors.
    """
    if _depth > 50:
        return  # Safety valve — stop recursing into very deep structures
    import logging

    logger = logging.getLogger(__name__)

    if isinstance(
        obj,
        pd.Series | pd.DataFrame | np.ndarray | np.integer | np.floating | np.bool_,
    ):
        logger.warning(f"Found pandas/numpy object at {path}: {type(obj)}")
    elif isinstance(obj, dict):
        for key, value in obj.items():
            scan_for_pandas_objects(value, f"{path}.{key}", _depth + 1)
    elif isinstance(obj, list | tuple):
        # Only scan first few items to avoid O(n) traversal on large lists
        for i, item in enumerate(obj[:10]):
            scan_for_pandas_objects(item, f"{path}[{i}]", _depth + 1)


class HTMLRenderer:
    """Renderer for HTML output format using Jinja2 templates."""

    def __init__(self) -> None:
        """Initialize the HTML renderer."""
        self.logger = logging.getLogger(__name__)

        # Setup Jinja2 environment — discover bundled templates via
        # importlib.resources so the package works when installed as a wheel.
        template_dir = str(importlib.resources.files("fs_report.templates"))
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.env.filters["slack_mrkdwn"] = _slack_mrkdwn_to_html
        # ``short_scope`` aliases long folder labels (e.g. "folder TeamEdward
        # (3 projects)" → "TeamEdward") in repeated comparison table headers /
        # chips so they don't clip the PDF. Single source of truth lives in
        # compound_assembler; the assembler env registers the same filter.
        from fs_report.compound_assembler import short_scope

        self.env.filters["short_scope"] = short_scope

        # Read canonical tokens.css once at init time so standalone reports
        # and PDFs (which can't fetch /static/canonical/css/tokens.css)
        # inline the same source content via _tokens_inline.html.
        try:
            tokens_path = importlib.resources.files("fs_report").joinpath(
                "static/css/tokens.css"
            )
            self._tokens_inline_css = tokens_path.read_text(encoding="utf-8")
        except Exception as exc:
            self.logger.warning(
                "Failed to load canonical tokens.css; reports will fall back to "
                "browser-default styling for design tokens: %s",
                exc,
            )
            self._tokens_inline_css = ""

        # Pre-serialize palette literals once — server-side emit into
        # _standalone_shell.html's Chart.js bootstrap.
        self._chart_palette_json = json.dumps(list(FS_CHART_PALETTE))
        self._sev_palette_json = json.dumps(dict(FS_SEV_PALETTE))
        self._nav_palette_json = json.dumps(dict(FS_NAV_PALETTE))

    def render(
        self,
        recipe: Recipe,
        report_data: ReportData,
        output_path: Path,
        render_mode: RenderMode = RenderMode.HTML,
        theme: str = "light",
    ) -> None:
        """Render the report to HTML.

        ``render_mode`` controls template branching:
        - ``RenderMode.HTML`` (default): standalone HTML for browser viewing.
        - ``RenderMode.PDF``: HTML intermediate for Playwright; charts
          render via Chart.js in Chromium, no pre-rendered SVG. The PDF
          mode is exposed to templates as ``pdf_mode = True`` so
          ``_theme_init.html`` can skip the localStorage / URL /
          prefers-color-scheme checks and honor the server-rendered
          ``theme`` exactly — keeping PDF output deterministic.
        - ``RenderMode.FRAGMENT``: bundle fragment; charts pre-render to
          server-side SVG (fragment_extractor strips <script>).

        ``theme`` is the server-side default theme (``"light"``, ``"dark"``,
        or ``"auto"``). It is injected into the Jinja context so templates
        can use it for chart palettes and as the fallback when the browser
        cannot read localStorage / prefers-color-scheme. The client-side
        ``_theme_init.html`` script overrides this at runtime if the user
        has a stored preference. PDFs (rendered via Playwright) skip the
        runtime script and use this server-side value.
        """
        try:
            template_name = getattr(recipe, "template", None)
            if template_name:
                template = self.env.get_template(template_name)
            elif (
                recipe.output.charts
                and len(recipe.output.charts) > 1
                and recipe.name
                in (
                    "Executive Summary",
                    "Executive Dashboard",
                    "Component Vulnerability Analysis",
                )
            ):
                template = self._get_template("executive_summary", recipe.name)
            else:
                chart_type = None
                if hasattr(recipe.output, "chart") and isinstance(
                    recipe.output.chart, dict
                ):
                    chart_type = recipe.output.chart.get("type", "line")
                else:
                    chart_type = recipe.output.chart
                    if chart_type is not None and hasattr(chart_type, "value"):
                        chart_type = chart_type.value
                template = self._get_template(
                    str(chart_type) if chart_type else None, recipe.name
                )

            template_data = self._prepare_template_data(
                recipe,
                report_data,
                render_mode=render_mode,
                heading_depth=1,
            )

            self.logger.debug("Scanning template_data for pandas/numpy objects...")
            scan_for_pandas_objects(template_data)
            self.logger.debug("Converting template_data to native types...")
            template_data = convert_to_native_types(template_data)
            self.logger.debug("Conversion complete.")

            # Inject the server-side theme default so that _theme_init.html
            # can use it as the FOUC-safe fallback when localStorage and
            # prefers-color-scheme are both unset. The runtime script
            # overrides this for HTML viewers who have a stored preference.
            # pdf_mode tells _theme_init.html to skip the runtime checks
            # entirely so PDF rendering is deterministic.
            #
            # Direct assignment (not setdefault) — these are renderer-owned
            # render options and must not be overridable by transform data
            # that happens to use the same keys.
            template_data["theme"] = theme
            template_data["pdf_mode"] = render_mode == RenderMode.PDF
            # Expose the package version so templates can surface the build
            # that produced an exported HTML file (e.g. in status bars).
            from fs_report import __version__ as _fs_report_version

            template_data["fs_report_version"] = _fs_report_version

            self.logger.debug("Rendering HTML template...")
            html_content = template.render(**template_data)
            self.logger.debug("HTML rendering complete.")
            output_path.write_text(html_content, encoding="utf-8")
        except Exception as e:
            self.logger.error(f"Error generating HTML: {e}")
            import traceback

            self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            raise

    def render_fragment(
        self,
        recipe: Recipe,
        report_data: ReportData,
        heading_depth: int = 2,
        *,
        fragment_scripts_enabled: bool = False,
        suppress_section_title: bool = False,
    ) -> str:
        """Render the recipe as an embeddable HTML fragment.

        Returns inline HTML with no ``<html>`` / ``<head>`` / ``<body>``
        tags — selectors are prefixed with ``.fs-section-<slug>`` so styles
        don't bleed across sections, and the top-level heading is rendered
        at ``heading_depth`` (default ``<h2>`` for compound bundles).

        Document-shell stripping, CSS scoping, heading promotion, and
        ``<script>``/``<style>`` removal happen as a post-render pass in
        ``fragment_extractor.extract_fragment`` — recipe templates do
        not need to branch on ``render_mode == RenderMode.FRAGMENT`` for
        those concerns.

        ``fragment_scripts_enabled`` (default False): when True, body
        ``<script>`` blocks are preserved through extraction AND the value
        is injected into the template context so chart partials can emit
        live ``<canvas>`` / ``<div>`` containers instead of pre-rendered
        SVGs. Only the compound assembler sets it True; this is the
        Option X pathway from the compound-reports design spec § 2.

        ``suppress_section_title`` (default False): when True, the
        post-shift body has its single ``data-fs-section-title``-marked
        element removed. Recipe templates opt in by adding the attribute
        to their section-title element; templates without the marker are
        unaffected (no-op). The compound assembler uses this so the
        section divider's title doesn't duplicate the in-fragment title.

        Per-recipe chrome behavior depends on the template's own
        render_mode gating. Templates that wrap their <header>/<footer>/
        metadata in ``{% if render_mode != 'fragment' %}`` (e.g., briefing
        recipes that extend ``_briefing_shell.html``) emit NO chrome in
        fragment mode. Console recipes today still emit per-recipe header/
        metadata/footer inside the fragment; B1's in-body chrome audit
        extends the gate to ``fs.topbar`` / ``fs.status_bar`` macros.
        """
        # Reuse the template selection from `render` so single-recipe
        # standalone and fragment-mode go through identical paths.
        template_name = getattr(recipe, "template", None)
        if template_name:
            template = self.env.get_template(template_name)
        elif (
            recipe.output.charts
            and len(recipe.output.charts) > 1
            and recipe.name
            in (
                "Executive Summary",
                "Executive Dashboard",
                "Component Vulnerability Analysis",
            )
        ):
            template = self._get_template("executive_summary", recipe.name)
        else:
            chart_type = None
            if hasattr(recipe.output, "chart") and isinstance(
                recipe.output.chart, dict
            ):
                chart_type = recipe.output.chart.get("type", "line")
            else:
                chart_type = recipe.output.chart
                if chart_type is not None and hasattr(chart_type, "value"):
                    chart_type = chart_type.value
            template = self._get_template(
                str(chart_type) if chart_type else None, recipe.name
            )

        template_data = self._prepare_template_data(
            recipe,
            report_data,
            render_mode=RenderMode.FRAGMENT,
            heading_depth=heading_depth,
            fragment_scripts_enabled=fragment_scripts_enabled,
        )
        # Populated by _prepare_template_data (T0b § item 3).
        scope_class = template_data["fragment_scope_class"]
        scan_for_pandas_objects(template_data)
        template_data = convert_to_native_types(template_data)
        rendered: str = template.render(**template_data)
        nav_slug = template_data.get("nav_category_slug") or None
        return extract_fragment(
            rendered,
            scope_class,
            heading_depth=heading_depth,
            nav_category_slug=nav_slug,
            fragment_scripts_enabled=fragment_scripts_enabled,
            suppress_section_title=suppress_section_title,
        )

    def _get_template(
        self, chart_type: str | None, recipe_name: str | None = None
    ) -> Any:
        """Get the appropriate template for the chart type."""
        # Handle special template names
        if recipe_name == "Component Vulnerability Analysis":
            template_name = "component_vulnerability_analysis.html"
        elif chart_type == "executive_summary":
            template_name = "executive_summary.html"
        elif chart_type == "bar":
            template_name = "bar_chart.html"
        elif chart_type == "line":
            template_name = "line_chart.html"
        elif chart_type == "pie":
            template_name = "pie_chart.html"
        elif chart_type == "scatter":
            template_name = "scatter_chart.html"
        else:
            template_name = "table.html"

        return self.env.get_template(template_name)

    def _prepare_template_data(
        self,
        recipe: Recipe,
        report_data: ReportData,
        *,
        render_mode: RenderMode = RenderMode.HTML,
        heading_depth: int = 1,
        fragment_scripts_enabled: bool = False,
    ) -> dict[str, Any]:
        """Prepare data for template rendering.

        ``render_mode`` selects between standalone HTML, Playwright PDF
        intermediate, and bundle-fragment outputs (see RenderMode docs).
        ``heading_depth`` is passed through for templates that render at
        a specific level; the fragment extractor also performs a
        post-render heading shift based on this value.
        """
        # Convert data to DataFrame if needed.
        # Custom-transform recipes (e.g. CRA Compliance) return a dict of
        # named DataFrames rather than a single flat DataFrame.  In that case
        # we take the "main" sub-frame for column-inspection purposes; the
        # actual section data is extracted later by _build_cra_context.
        if isinstance(report_data.data, pd.DataFrame):
            df = report_data.data
        elif isinstance(report_data.data, dict):
            main_val = report_data.data.get("main")
            if isinstance(main_val, pd.DataFrame):
                df = main_val
            elif main_val is not None:
                df = pd.DataFrame(main_val)
            else:
                df = pd.DataFrame()
        else:
            df = pd.DataFrame(report_data.data)

        # Check if this is an MTTR chart (has avg_mttr_days)
        is_mttr_chart = "avg_mttr_days" in df.columns

        # Check if this should be stacked
        is_stacked = getattr(recipe.output, "stacked", False)

        # Debug logging
        self.logger.debug(f"Recipe output charts: {recipe.output.charts}")
        self.logger.debug(
            f"Additional data keys: {list(report_data.metadata.get('additional_data', {}).keys())}"
        )

        # Handle multiple charts for Executive Summary and Component Vulnerability Analysis
        if recipe.output.charts:
            self.logger.debug(
                f"Processing multiple charts: {[chart.name for chart in recipe.output.charts]}"
            )
            chart_data: dict[str, Any] = {}

            # Component Vulnerability Analysis charts
            if "Component Vulnerability Analysis" in recipe.name:
                # Individual project risk chart
                if "individual_project_risk" in [
                    chart.name for chart in recipe.output.charts
                ]:
                    self.logger.debug("Preparing individual project risk chart")
                    chart_data["individual_project_risk"] = (
                        self._prepare_bar_chart_data(df, is_stacked=False)
                    )

                # Portfolio risk chart
                if "portfolio_risk" in [chart.name for chart in recipe.output.charts]:
                    self.logger.debug("Preparing portfolio risk chart")
                    portfolio_data = report_data.metadata.get("portfolio_data")
                    if portfolio_data is not None and not (
                        isinstance(portfolio_data, pd.DataFrame)
                        and len(portfolio_data) == 0
                    ):
                        if isinstance(portfolio_data, pd.DataFrame):
                            portfolio_df = portfolio_data
                        else:
                            portfolio_df = pd.DataFrame(portfolio_data)
                        chart_data["portfolio_risk"] = self._prepare_bar_chart_data(
                            portfolio_df,
                            is_stacked=False,
                            y_col="portfolio_composite_risk",
                        )
                    else:
                        self.logger.debug("No portfolio data found")
                        chart_data["portfolio_risk"] = {
                            "labels": [],
                            "datasets": [
                                {
                                    "data": [],
                                    "backgroundColor": "rgba(54, 162, 235, 0.8)",
                                }
                            ],
                        }

                # Add the specialized CVA charts using portfolio data
                portfolio_data = report_data.metadata.get("portfolio_data")
                if portfolio_data is not None and not (
                    isinstance(portfolio_data, pd.DataFrame)
                    and len(portfolio_data) == 0
                ):
                    if isinstance(portfolio_data, pd.DataFrame):
                        portfolio_df = portfolio_data
                    else:
                        portfolio_df = pd.DataFrame(portfolio_data)
                    chart_data["pareto_chart"] = self._prepare_pareto_chart_data(
                        portfolio_df, recipe
                    )
                    chart_data["bubble_matrix"] = self._prepare_bubble_matrix_data(
                        portfolio_df
                    )
                else:
                    # Fallback to main data if portfolio data not available
                    chart_data["pareto_chart"] = self._prepare_pareto_chart_data(
                        df, recipe
                    )
                    chart_data["bubble_matrix"] = self._prepare_bubble_matrix_data(df)

            # Executive Summary charts
            else:
                # Main project breakdown chart
                if "project_breakdown" in [
                    chart.name for chart in recipe.output.charts
                ]:
                    self.logger.debug("Preparing project breakdown chart")
                    chart_data["project_breakdown"] = self._prepare_bar_chart_data(
                        df, is_stacked=True
                    )

                # Open issues distribution chart
                if "open_issues_distribution" in [
                    chart.name for chart in recipe.output.charts
                ]:
                    self.logger.debug("Preparing open issues distribution chart")
                    open_issues_data = report_data.metadata.get(
                        "additional_data", {}
                    ).get("open_issues")
                    if open_issues_data is not None and not (
                        isinstance(open_issues_data, pd.DataFrame)
                        and len(open_issues_data) == 0
                    ):
                        self.logger.debug(
                            f"Open issues data type: {type(open_issues_data)}"
                        )
                        if isinstance(open_issues_data, pd.DataFrame):
                            open_issues_df = open_issues_data
                        else:
                            open_issues_df = pd.DataFrame(open_issues_data)
                        chart_data["open_issues_distribution"] = (
                            self._prepare_pie_chart_data(open_issues_df)
                        )
                    else:
                        self.logger.debug("No open issues data found")
                        chart_data["open_issues_distribution"] = {
                            "labels": [],
                            "datasets": [{"data": [], "backgroundColor": []}],
                        }

                # Scan frequency chart
                if "scan_frequency" in [chart.name for chart in recipe.output.charts]:
                    self.logger.debug("Preparing scan frequency chart")
                    scan_frequency_data = report_data.metadata.get(
                        "additional_data", {}
                    ).get("scan_frequency")
                    period_label = "Month"  # Default fallback
                    if scan_frequency_data is not None and not (
                        isinstance(scan_frequency_data, pd.DataFrame)
                        and len(scan_frequency_data) == 0
                    ):
                        self.logger.debug(
                            f"Scan frequency data type: {type(scan_frequency_data)}"
                        )
                        if isinstance(scan_frequency_data, pd.DataFrame):
                            scan_frequency_df = scan_frequency_data
                        else:
                            scan_frequency_df = pd.DataFrame(scan_frequency_data)
                        # Get period_label if present
                        period_label = getattr(
                            scan_frequency_df, "period_label", "Month"
                        )
                        chart_data["scan_frequency"] = self._prepare_line_chart_data(
                            scan_frequency_df
                        )
                    else:
                        self.logger.debug("No scan frequency data found")
                        chart_data["scan_frequency"] = {
                            "labels": [],
                            "datasets": [
                                {
                                    "data": [],
                                    "borderColor": "rgb(75, 192, 192)",
                                    "backgroundColor": "rgba(75, 192, 192, 0.2)",
                                }
                            ],
                        }
                    # Pass period_label to template context
                    chart_data["scan_frequency_period_label"] = period_label

                # Exploit Signals gauge (C1) — flat (label, count) bar shape,
                # prepared DIRECTLY from the 3-row DataFrame. Deliberately NOT
                # routed through _prepare_pie_chart_data, which emits a
                # {labels, datasets:[{data}]} pie shape the horizontal-bar
                # template doesn't consume.
                if "exploit_signals" in [chart.name for chart in recipe.output.charts]:
                    self.logger.debug("Preparing exploit signals chart")
                    exploit_signals_data = report_data.metadata.get(
                        "additional_data", {}
                    ).get("exploit_signals")
                    if exploit_signals_data is not None and not (
                        isinstance(exploit_signals_data, pd.DataFrame)
                        and len(exploit_signals_data) == 0
                    ):
                        if isinstance(exploit_signals_data, pd.DataFrame):
                            exploit_signals_df = exploit_signals_data
                        else:
                            exploit_signals_df = pd.DataFrame(exploit_signals_data)
                        chart_data["exploit_signals"] = {
                            "labels": (
                                exploit_signals_df["label"].tolist()
                                if "label" in exploit_signals_df.columns
                                else []
                            ),
                            "data": (
                                exploit_signals_df["count"].tolist()
                                if "count" in exploit_signals_df.columns
                                else []
                            ),
                        }
                    else:
                        self.logger.debug("No exploit signals data found")
                        chart_data["exploit_signals"] = {"labels": [], "data": []}

                # Exploits Over Time line (C2) — same line shape + period_label
                # contract as scan_frequency.
                if "exploits_over_time" in [
                    chart.name for chart in recipe.output.charts
                ]:
                    self.logger.debug("Preparing exploits over time chart")
                    exploits_over_time_data = report_data.metadata.get(
                        "additional_data", {}
                    ).get("exploits_over_time")
                    exploits_over_time_period_label = "Month"  # Default fallback
                    if exploits_over_time_data is not None and not (
                        isinstance(exploits_over_time_data, pd.DataFrame)
                        and len(exploits_over_time_data) == 0
                    ):
                        if isinstance(exploits_over_time_data, pd.DataFrame):
                            exploits_over_time_df = exploits_over_time_data
                        else:
                            exploits_over_time_df = pd.DataFrame(
                                exploits_over_time_data
                            )
                        exploits_over_time_period_label = getattr(
                            exploits_over_time_df, "period_label", "Month"
                        )
                        chart_data["exploits_over_time"] = (
                            self._prepare_line_chart_data(exploits_over_time_df)
                        )
                    else:
                        self.logger.debug("No exploits over time data found")
                        chart_data["exploits_over_time"] = {
                            "labels": [],
                            "datasets": [
                                {
                                    "data": [],
                                    "borderColor": "rgb(124, 58, 237)",
                                    "backgroundColor": "rgba(124, 58, 237, 0.2)",
                                }
                            ],
                        }
                    chart_data["exploits_over_time_period_label"] = (
                        exploits_over_time_period_label
                    )
        else:
            # Legacy single chart support
            self.logger.debug("Using legacy single chart support")
            chart_config = None
            if hasattr(recipe.output, "chart") and isinstance(
                recipe.output.chart, dict
            ):
                chart_config = recipe.output.chart
                chart_type = chart_config.get("type", "line")
            else:
                chart_type = recipe.output.chart
            chart_data = {
                "main": self._prepare_chart_data(
                    df, chart_type, is_stacked, chart_config
                )
            }
            # Do not serialize chart_data to JSON here; do it below for all charts

        # Prepare table data with user-friendly column names
        table_data = self._prepare_table_data(df)

        # Prepare portfolio table data if available
        portfolio_table_data = None
        if "Component Vulnerability Analysis" in recipe.name:
            portfolio_data = report_data.metadata.get("portfolio_data")
            if portfolio_data is not None and not (
                isinstance(portfolio_data, pd.DataFrame) and len(portfolio_data) == 0
            ):
                if isinstance(portfolio_data, pd.DataFrame):
                    portfolio_df = portfolio_data
                else:
                    portfolio_df = pd.DataFrame(portfolio_data)
                portfolio_table_data = self._prepare_table_data(portfolio_df)
                # Debug: Print columns and first few rows for portfolio data
                if "portfolio_risk_score" in portfolio_df.columns:
                    pass

        # Calculate Y-axis max for charts
        y_axis_max = None
        if "composite_risk_score" in df.columns:
            # For component vulnerability analysis, use composite risk score
            max_score = df["composite_risk_score"].max()
            if max_score > 0:
                # Round up to the next multiple of 25 for better scale
                y_axis_max = ((max_score // 25) + 1) * 25
        elif "finding_count" in df.columns:
            # For finding count charts
            max_findings = df["finding_count"].max()
            if max_findings > 0:
                # Round up to the next multiple of 5 for better scale
                y_axis_max = ((max_findings // 5) + 1) * 5

        # Serialize each chart data to JSON for template
        chart_data_json = {}
        chart_data_objects = {}
        for key, value in chart_data.items():
            # Keep original objects for template conditions
            chart_data_objects[key] = value
            # Convert chart data to JSON strings for template consumption
            # The template uses safeParseJSON to parse these strings
            chart_data_json[key] = json.dumps(value, default=self._json_serializer)

        # Ensure table_data is a dict of native types
        if isinstance(table_data, pd.DataFrame):  # type: ignore[unreachable]
            table_data = table_data.to_dict(orient="records")  # type: ignore[unreachable]
        elif isinstance(table_data, pd.Series):  # type: ignore[unreachable]
            table_data = table_data.tolist()  # type: ignore[unreachable]

        # Ensure portfolio_table_data is a dict of native types
        if portfolio_table_data is not None:
            if isinstance(portfolio_table_data, pd.DataFrame):  # type: ignore[unreachable]
                portfolio_table_data = portfolio_table_data.to_dict(orient="records")  # type: ignore[unreachable]
            elif isinstance(portfolio_table_data, pd.Series):  # type: ignore[unreachable]
                portfolio_table_data = portfolio_table_data.tolist()  # type: ignore[unreachable]

        # Build a slim metadata dict for the template — avoid passing the
        # full report_data.metadata (which embeds DataFrames, Config objects,
        # and the entire recipe dump) through convert_to_native_types, as its
        # recursive traversal can exceed Python's default recursion limit.
        slim_metadata = {
            "start_date": report_data.metadata.get("start_date", ""),
            "end_date": report_data.metadata.get("end_date", ""),
            "raw_count": report_data.metadata.get("raw_count", 0),
            "transformed_count": report_data.metadata.get("transformed_count", 0),
            "project_filter": report_data.metadata.get("project_filter", ""),
            # Human-readable project name resolved by the engine. The engine
            # overwrites config.project_filter with the numeric ID before
            # transforms run (API filters need IDs), so any template that
            # displays project_filter shows the raw ID — the 2026-06-06
            # visual QA pass caught this in five recipes' topbars.
            "project_name": report_data.metadata.get("project_name", "") or "",
            "folder_name": report_data.metadata.get("folder_name", ""),
            "folder_path": report_data.metadata.get("folder_path", ""),
            "folder_filter": report_data.metadata.get("folder_filter", ""),
            "domain": report_data.metadata.get("domain", ""),
            "logo_path": report_data.metadata.get("logo_path"),
        }

        template_data = {
            "recipe_name": recipe.name,
            # Pre-extracted per-column schema for the in-output column
            # reference banner. None when the recipe doesn't define
            # output.columns (most recipes today). Single source of
            # truth: recipes/<name>.yaml's `output.columns` block.
            "columns_schema": (
                [
                    {
                        "name": col.name,
                        "source": col.source,
                        "description": col.description,
                    }
                    for col in recipe.output.columns
                ]
                if recipe.output.columns
                else None
            ),
            "slide_title": recipe.output.slide_title or recipe.name,
            "chart_data": chart_data_objects,  # Original objects for template conditions
            "chart_data_json": chart_data_json,  # JSON strings for JavaScript
            "charts": recipe.output.charts or [],
            "table_data": table_data,
            "portfolio_table_data": portfolio_table_data,
            "metadata": slim_metadata,
            "generated_at": pd.Timestamp.now(tz="UTC").strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            "stacked": is_stacked,
            "is_mttr_chart": is_mttr_chart,
            "y_axis_max": y_axis_max,
            "start_date": slim_metadata["start_date"],
            "end_date": slim_metadata["end_date"],
            "project_filter": slim_metadata["project_filter"],
            "project_name": slim_metadata["project_name"],
            # Canonical display string for project scope: the resolved
            # name when the engine knows it, else the raw filter value.
            # Templates should render THIS in topbars/status bars/chips,
            # never project_filter (which is the resolved numeric ID).
            "project_label": (
                slim_metadata["project_name"] or slim_metadata["project_filter"]
            ),
            "folder_name": slim_metadata["folder_name"],
            "folder_path": slim_metadata["folder_path"],
            "folder_filter": slim_metadata["folder_filter"],
            "domain": slim_metadata["domain"],
            "logo_path": slim_metadata["logo_path"],
            # Add period label for scan frequency chart
            "scan_frequency_period_label": chart_data.get(
                "scan_frequency_period_label", "Month"
            ),
            # Parallel period label for the Exploits Over Time line (C2).
            "exploits_over_time_period_label": chart_data.get(
                "exploits_over_time_period_label", "Month"
            ),
        }

        # B1 #15: effective scope for the report-shell topbar (Scope meta +
        # active-filter chips), via the shared resolver so the in-report chrome,
        # the run canvas, the Running Reports monitor, and the command palette
        # all agree. Built from the RESOLVED display metadata: the engine
        # overwrites project_filter with the numeric ID, so the display name
        # (project_name) is passed as the project identity; folder_name is the
        # pre-resolved folder label. A portfolio-wide report (nothing pinned)
        # honestly reports "Portfolio" instead of a blank topbar.
        template_data["effective_scope"] = compute_effective_scope(
            {
                "project_filter": (
                    slim_metadata["project_name"] or slim_metadata["project_filter"]
                ),
                "folder_filter": slim_metadata["folder_filter"],
                "folder_label": slim_metadata["folder_name"],
                # Prefer the resolved version NAME; fall back to the raw
                # version_filter so a version-scoped run keeps its "@ version"
                # indicator even when the engine didn't resolve a display name.
                "version_filter": (
                    report_data.metadata.get("version_name")
                    or report_data.metadata.get("version_filter")
                    or ""
                ),
                "component_filter": report_data.metadata.get("component_filter", ""),
                "component_version": report_data.metadata.get("component_version", ""),
                "cve_filter": report_data.metadata.get("cve_filter", ""),
            }
        )

        # Add raw data for templates that need it (like findings by project)
        if isinstance(report_data.data, pd.DataFrame):
            template_data["data"] = report_data.data.to_dict(orient="records")
        else:
            template_data["data"] = report_data.data

        # Merge additional_data into template context.  Convert DataFrames
        # and Series to native Python types up-front so that the later
        # convert_to_native_types pass doesn't recurse through large tables.
        _reserved_keys = frozenset(
            {
                "recipe_name",
                "slide_title",
                "chart_data",
                "chart_data_json",
                "charts",
                "table_data",
                "portfolio_table_data",
                "metadata",
                "generated_at",
                "stacked",
                "is_mttr_chart",
                "y_axis_max",
                "start_date",
                "end_date",
                "data",
                # B1 #15: the report-shell scope chrome must not be silently
                # overwritten by a transform's additional_data key.
                "effective_scope",
            }
        )
        additional_data = report_data.metadata.get("additional_data", {})
        if additional_data:
            for key, value in additional_data.items():
                if key == "config":
                    continue  # Config object is not template-safe
                if key in _reserved_keys:
                    self.logger.warning(
                        f"additional_data key '{key}' collides with reserved "
                        f"template variable — skipping"
                    )
                    continue
                # Convert top-level DataFrames/Series to native types
                if isinstance(value, pd.DataFrame):
                    value = value.to_dict("records")
                elif isinstance(value, pd.Series):
                    value = value.tolist()
                # For nested dicts (e.g. transform_result), convert any
                # DataFrame/Series values so templates can consume them.
                elif isinstance(value, dict):
                    value = {
                        k: (
                            v.to_dict("records")
                            if isinstance(v, pd.DataFrame)
                            else v.tolist() if isinstance(v, pd.Series) else v
                        )
                        for k, v in value.items()
                    }
                template_data[key] = value
        # For recipes with custom templates, the transform result may contain
        # a "charts" dict that should override the recipe's ChartConfig list.
        # The reserved-key guard above blocks this, so apply it explicitly.
        if recipe.template and additional_data:
            for key in (
                "charts",
                "summary",
                "cve_updates",
                "cve_update_summary",
                "dossiers",
                "actions",
                "suppressed",
                "ai_prompts",
                "coverage",
                "cra_findings",
                "mode",
            ):
                if key in additional_data:
                    template_data[key] = additional_data[key]

        # If the main data is a dict (custom transform), merge all keys into template_data
        if isinstance(report_data.data, dict):
            for key, value in report_data.data.items():
                if key == "raw_ttr_data":
                    template_data["table_data"] = value
                else:
                    template_data[key] = value

        # ── Recipe-specific context builders ────────────────────────────────
        # CRA Compliance: build cra_sections, KPIs, metadata labels.
        recipe_name = getattr(recipe, "name", "") or ""
        if recipe_name == "CRA Compliance":
            self._build_cra_context(recipe, report_data, template_data)

        # ── Phase 1 additions: fragment-mode, server-side SVGs, tokens ──
        # getattr defends against tests that mock Recipe with a fixed spec
        # (pydantic Field-declared attrs don't appear in dir(Recipe) and
        # so don't make it onto MagicMock(spec=Recipe) instances).
        nav_category = getattr(recipe, "nav_category", None)
        template_data["nav_category"] = nav_category
        template_data["nav_category_slug"] = (
            nav_category.lower() if isinstance(nav_category, str) else ""
        )
        template_data["render_mode"] = render_mode
        template_data["heading_depth"] = heading_depth
        # B1 / Option X: chart partials branch on this flag so live-canvas
        # paths fire under compound assembly. Default False keeps single-
        # recipe FRAGMENT renders on the server-SVG path.
        template_data["fragment_scripts_enabled"] = fragment_scripts_enabled
        # Fragment-scope class is populated for every render mode (T0b
        # spec § item 3). Recipe templates reference {{ fragment_scope_class }}
        # for chart container IDs and section wrappers; the same ID scheme
        # is used in HTML, PDF, and FRAGMENT modes so chart-init code
        # doesn't branch on render_mode. The fragment_extractor wraps the
        # body in <div class="{{ fragment_scope_class }}"> in fragment mode,
        # but the ID lookup itself doesn't depend on that wrapper.
        template_data["fragment_scope_class"] = _recipe_scope_class(recipe)
        template_data["tokens_inline_css"] = self._tokens_inline_css
        template_data["chart_palette_json"] = self._chart_palette_json
        template_data["sev_palette_json"] = self._sev_palette_json
        template_data["nav_palette_json"] = self._nav_palette_json
        template_data["fs_ink"] = FS_INK
        template_data["fs_ink_dim"] = FS_INK_DIM
        template_data["fs_hairline"] = FS_HAIRLINE
        template_data["fs_font_body"] = FS_FONT_BODY
        template_data["fs_font_display"] = FS_FONT_DISPLAY

        # Server-side chart SVGs for fragment targets. Charts not
        # declared in recipe.output.charts (inline-only charts) stay browser-
        # only; their templates must check render_mode and either
        # render a placeholder or omit themselves.
        #
        # Under Option X (fragment_scripts_enabled=True, set only by the
        # compound assembler), chart partials emit live <canvas>/<div>
        # containers and the matplotlib SVG path is not used — skip the
        # generation to save the compound run that work.
        server_svgs: dict[str, str] = {}
        if (
            render_mode == RenderMode.FRAGMENT
            and not fragment_scripts_enabled
            and recipe.output.charts
        ):
            try:
                from fs_report.renderers.chart_renderer import ChartRenderer

                renderer = ChartRenderer()
                main_df = (
                    report_data.data
                    if isinstance(report_data.data, pd.DataFrame)
                    else (
                        pd.DataFrame(report_data.data)
                        if not isinstance(report_data.data, dict)
                        else pd.DataFrame()
                    )
                )
                additional = report_data.metadata.get("additional_data", {}) or {}
                for spec in recipe.output.charts:
                    # Resolve a DataFrame for this specific chart by name —
                    # multi-chart recipes put per-chart frames in
                    # metadata['additional_data'][name]. For specs whose
                    # name ends in "_distribution" we also try the
                    # suffix-stripped form on a miss (the report engine
                    # writes some of those under the shorter key — e.g.
                    # additional_data["open_issues"] for chart spec
                    # "open_issues_distribution").
                    #
                    # Scope notes (deliberate; debated across the plan
                    # multi-review rounds):
                    #   * Fallback fires ONLY when the exact key is
                    #     literally None — present-but-empty values
                    #     (empty DataFrame, [], {}) suppress the
                    #     fallback. Handling those would require
                    #     inspecting candidate shape before deciding,
                    #     which is a broader design choice than this
                    #     minimal fix targets.
                    #   * The downstream list/dict coercion branch
                    #     below is preserved from existing renderer
                    #     behavior — the fallback may newly route a
                    #     list/dict under the suffix-stripped key
                    #     through that branch, but the coercion logic
                    #     itself is unchanged.
                    #   * Suffix-stripping applies to every chart spec
                    #     ending in "_distribution"; an audit of the
                    #     repo's other such specs (band_distribution,
                    #     staleness_distribution, unpack_rating_distribution)
                    #     confirmed their suffix-stripped keys are not
                    #     written to additional_data anywhere today,
                    #     so the fallback is a no-op for them. See
                    #     PR #74 audit table.
                    candidate = additional.get(spec.name)
                    if candidate is None and spec.name.endswith("_distribution"):
                        candidate = additional.get(
                            spec.name.removesuffix("_distribution")
                        )
                    if candidate is None:
                        # Final fallback: recipes like scan_quality nest their per-chart
                        # payloads under additional_data["charts"][<name>]. Descend into
                        # that dict so the dispatch finds the data instead of falling
                        # through to main_df (round-1 B.1 multi-review M1-1 / M2-1 / M3-1).
                        # Mirror the `_distribution` suffix-strip retry inside the
                        # nested dict too — B.1 PR review M1-2 / M3-2 / M2-2 (round 1).
                        nested_charts = additional.get("charts")
                        if isinstance(nested_charts, dict):
                            candidate = nested_charts.get(spec.name)
                            if candidate is None and spec.name.endswith(
                                "_distribution"
                            ):
                                candidate = nested_charts.get(
                                    spec.name.removesuffix("_distribution")
                                )
                    if isinstance(candidate, pd.DataFrame):
                        df_for_chart = candidate
                    elif isinstance(candidate, list | dict) and candidate:
                        try:
                            df_for_chart = pd.DataFrame(candidate)
                        except Exception:
                            df_for_chart = main_df
                    else:
                        df_for_chart = main_df
                    if df_for_chart is None or len(df_for_chart) == 0:
                        # Empty data → emit a placeholder so the chart slot
                        # in the template doesn't silently collapse to
                        # nothing. Differentiates "no data" from "render
                        # failed" for downstream debugging.
                        server_svgs[spec.name] = (
                            '<div class="chart-unavailable">'
                            f"No data available for chart '{spec.name}'"
                            "</div>"
                        )
                        continue
                    chart_type = spec.chart
                    if hasattr(chart_type, "value"):
                        chart_type = chart_type.value
                    try:
                        # render_chart_svg is attached to ChartRenderer via a
                        # mixin at module import time; mypy can't see dynamic
                        # attribute assignment, so the attr-defined ignore is
                        # required until the mixin is folded into the class
                        # body (Phase 2 refactor).
                        server_svgs[spec.name] = renderer.render_chart_svg(  # type: ignore[attr-defined]
                            df_for_chart, str(chart_type), spec.model_dump()
                        )
                    except Exception as exc:
                        self.logger.warning(
                            "Failed to render server SVG for chart %r: %s",
                            spec.name,
                            exc,
                        )
            except Exception as exc:
                self.logger.warning(
                    "Server-side SVG rendering pipeline failed: %s", exc
                )
        template_data["server_svgs"] = server_svgs

        # Convert all data to native Python types to prevent ambiguous truth value errors
        converted_data = convert_to_native_types(template_data)
        return cast(dict[str, Any], converted_data)

    # ── CRA Compliance context builder ───────────────────────────────────

    # Per-section column specs: (column_key, display_label) pairs.
    _CRA_SLA_COLS: list[tuple[str, str]] = [
        ("cve_id", "CVE"),
        ("component", "Component"),
        ("severity", "Severity"),
        ("exploit_maturity", "Maturity"),
        ("reachability_label", "Reachability"),
        ("kev_source", "KEV Source"),
        ("breach_status", "Breach Status"),
        ("hours_until_cra_due", "Hours Until Due"),
        ("cra_notification_deadline", "Notification Deadline"),
        ("cisa_remediation_due", "CISA Remediation Due"),
        # Threat Actors trails everything else — VulnCheck rows can list 30+
        # actors so the cell is wide; keeping the breach-clock columns near
        # the start preserves at-a-glance triage data.
        ("threat_actor_names", "Threat Actors"),
    ]
    _CRA_NEWLY_ABOVE_COLS: list[tuple[str, str]] = [
        ("cve_id", "CVE"),
        ("component", "Component"),
        ("severity", "Severity"),
        ("cvss_score", "CVSS"),
        ("crossed_to", "Crossed To"),
        ("crossing_source", "Source"),
        ("breach_status", "Breach Status"),
        ("hours_until_cra_due", "Hours Until Due"),
        ("cra_notification_deadline", "Notification Deadline"),
        ("threat_actor_names", "Threat Actors"),
    ]
    _CRA_RE_EMERGED_COLS: list[tuple[str, str]] = [
        ("cve_id", "CVE"),
        ("component", "Component"),
        ("previous_resolution", "Previous Resolution"),
        ("resolution_date", "Resolution Date"),
        ("crossed_to", "Crossed To"),
        ("breach_status", "Breach Status"),
        ("hours_until_cra_due", "Hours Until Due"),
        ("cra_notification_deadline", "Notification Deadline"),
        ("threat_actor_names", "Threat Actors"),
    ]
    _CRA_STILL_IN_TRIAGE_COLS: list[tuple[str, str]] = [
        ("cve_id", "CVE"),
        ("component", "Component"),
        ("severity", "Severity"),
        ("triage_age_days", "Triage Age (days)"),
        ("epss_percentile", "EPSS"),
        ("breach_status", "Breach Status"),
        ("hours_until_cra_due", "Hours Until Due"),
        ("cra_notification_deadline", "Notification Deadline"),
    ]
    _CRA_FULL_SNAPSHOT_COLS: list[tuple[str, str]] = [
        ("cve_id", "CVE"),
        ("component", "Component"),
        ("severity", "Severity"),
        ("cvss_score", "CVSS"),
        ("exploit_maturity", "Maturity"),
        ("reachability_label", "Reachability"),
        ("status", "Status"),
        ("breach_status", "Breach Status"),
        ("cra_notification_deadline", "Notification Deadline"),
    ]

    # Section label map (emoji + text matching md_renderer)
    _CRA_SECTION_LABELS: dict[str, str] = {
        "sla_breach": "🔥 SLA-Breach Risk",
        "newly_above": "🆕 Newly Above Threshold",
        "re_emerged": "🔁 Re-emerged",
        "still_in_triage": "⏰ Still in Triage",
        "full_snapshot": "📋 Full Snapshot",
    }

    # Maximum rows rendered for full_snapshot (others show all)
    _FULL_SNAPSHOT_MAX_ROWS = 500

    @staticmethod
    def _get_cra_section_dfs(report_data: "Any") -> "dict[str, Any]":
        """Return the CRA section DataFrames keyed by section name.

        The pandas transform dispatcher (data_transformer.py:
        _apply_pandas_transform_function) unwraps a dict return value:
        it stuffs the full dict into
        ``additional_data["transform_result"]`` and returns only the
        "main" DataFrame as the function return.  By the time
        ``ReportData`` is constructed, ``report_data.data`` may therefore
        be ``main_df`` (a DataFrame) rather than the ``{main, sla_breach,
        ...}`` dict the renderer expects.

        This helper checks both locations and always returns a dict with
        all 6 expected keys, each guaranteed to be a DataFrame.
        """
        import pandas as pd

        _KEYS = (
            "main",
            "sla_breach",
            "newly_above",
            "re_emerged",
            "still_in_triage",
            "full_snapshot",
        )
        data = report_data.data
        if isinstance(data, dict):
            section_dict: dict[str, Any] = data
        else:
            # Engine unwrapped to main_df — sections live in additional_data.
            meta = getattr(report_data, "metadata", {}) or {}
            ad = meta.get("additional_data", {}) or {}
            section_dict = ad.get("transform_result", {}) or {}
            if not isinstance(section_dict, dict):
                section_dict = {}

        result: dict[str, Any] = {}
        for key in _KEYS:
            v = section_dict.get(key, pd.DataFrame())
            result[key] = v if isinstance(v, pd.DataFrame) else pd.DataFrame()

        # Fallback: if "main" is empty but report_data.data is a non-empty
        # DataFrame, that DataFrame IS main.
        if result["main"].empty and isinstance(data, pd.DataFrame) and not data.empty:
            result["main"] = data

        return result

    @staticmethod
    def _format_cra_row(row: dict[str, Any]) -> dict[str, Any]:
        """Apply cosmetic formatting to a single CRA section row dict.

        Fixes applied:
        - hours_until_cra_due: float → rounded int + "h" suffix (e.g. "-570h")
        - None / NaN / "None" / "nan" values → empty string
        - cra_notification_deadline / cisa_remediation_due: strip "T00:00:00Z"
          suffix so ISO datetimes display as date-only strings
        """
        import math

        _DATE_COLS = ("cra_notification_deadline", "cisa_remediation_due")
        out: dict[str, Any] = {}
        for k, v in row.items():
            # Treat None / NaN / "None" / "nan" as empty
            if v is None:
                out[k] = ""
                continue
            if isinstance(v, float) and math.isnan(v):
                out[k] = ""
                continue
            if isinstance(v, str) and v.lower() in ("none", "nan"):
                out[k] = ""
                continue

            # hours_until_cra_due: format as integer hours
            if k == "hours_until_cra_due":
                try:
                    out[k] = f"{int(round(float(v)))}h"
                except (ValueError, TypeError):
                    out[k] = str(v)
                continue

            # Date columns: strip T00:00:00Z / T00:00:00+00:00 suffixes
            if k in _DATE_COLS and isinstance(v, str):
                # "2026-05-02T00:00:00Z" → "2026-05-02"
                out[k] = v.split("T")[0] if "T" in v else v
                continue

            out[k] = v
        return out

    def _build_cra_context(
        self,
        recipe: "Any",
        report_data: "Any",
        template_data: dict[str, Any],
    ) -> None:
        """Populate CRA-specific template context vars in-place.

        Reads ``report_data.data`` (a dict of DataFrames keyed by section
        name, or a DataFrame with sections in additional_data) and writes
        the following keys into *template_data*:

        - ``sla_breach_count`` — int, drives the notification-obligation banner
        - ``kpi_total`` — total finding count
        - ``kpi_overdue`` — 🔥 rows with breach_status==OVERDUE
        - ``kpi_due_soon`` — 🔥 rows with breach_status==DUE_SOON
        - ``kpi_unknown_clock`` — 🔥 rows with breach_status==UNKNOWN (typically VcKEV)
        - ``kpi_reachable`` — main_df rows with reachability_label==REACHABLE
        - ``kpi_in_triage`` — main_df rows with status==IN_TRIAGE
        - ``scope_label`` — human-readable scope string (folder > project > All)
        - ``threshold_label`` — comma-joined threshold tiers from recipe_params
        - ``since_label`` — since-window label from metadata
        - ``cra_sections`` — list of 5 section dicts for the Jinja template

        All values are native Python types (the outer convert_to_native_types
        pass will clean any survivors).
        """
        import pandas as pd

        # ── Extract DataFrames ──────────────────────────────────────────
        def _to_df(val: Any) -> "pd.DataFrame":
            if isinstance(val, pd.DataFrame):
                return val
            if isinstance(val, list):
                return pd.DataFrame(val) if val else pd.DataFrame()
            return pd.DataFrame()

        section_dfs = self._get_cra_section_dfs(report_data)
        main_df = _to_df(section_dfs.get("main"))
        sla_df = _to_df(section_dfs.get("sla_breach"))
        newly_df = _to_df(section_dfs.get("newly_above"))
        re_df = _to_df(section_dfs.get("re_emerged"))
        triage_df = _to_df(section_dfs.get("still_in_triage"))
        snapshot_df = _to_df(section_dfs.get("full_snapshot"))

        # ── SLA breach count (drives banner) ───────────────────────────
        sla_count = len(sla_df) if not sla_df.empty else 0
        template_data["sla_breach_count"] = sla_count

        # ── KPIs from main_df ───────────────────────────────────────────
        total = len(main_df) if not main_df.empty else 0
        template_data["kpi_total"] = total

        def _col_count(df: "pd.DataFrame", col: str, val: Any) -> int:
            if df.empty or col not in df.columns:
                return 0
            return int((df[col] == val).sum())

        # Action-driven KPIs (replaces P1/P2/P3 + KEV which were low signal):
        #   OVERDUE      — past their CRA notification deadline (act NOW)
        #   DUE_SOON     — within 24h of the deadline (act today)
        #   Unknown Clock — no awareness timestamp (can't compute deadline)
        #   Reachable    — `reachability_label == "REACHABLE"` (binary scans only)
        #   In Triage    — `status == IN_TRIAGE` (kept from prior set)
        #
        # KPIs read from `main_df` (queue-section concat + finding-row-id
        # dedup, queue assignment wins over 📋) — so they reflect what the
        # operator actually sees in the highest-priority table for each
        # row. Round 4 review M1-2 / M2-1 caught the earlier scoping to
        # `sla_df` only: UX-10 spread breach_status into 🆕/🔁/⏰/📋 but
        # the KPIs hadn't been updated to roll those in.
        template_data["kpi_overdue"] = _col_count(main_df, "breach_status", "OVERDUE")
        template_data["kpi_due_soon"] = _col_count(main_df, "breach_status", "DUE_SOON")
        template_data["kpi_unknown_clock"] = _col_count(
            main_df, "breach_status", "UNKNOWN"
        )
        template_data["kpi_in_triage"] = _col_count(main_df, "status", "IN_TRIAGE")

        # Reachability detection: the FS platform only runs reachability on
        # binary scans. Source-code-scanned projects return UNKNOWN on every
        # row → suppress the KPI card and the 📋 column. Single source of
        # truth in cra.sections.has_reachability_data so HTML and MD can't
        # diverge on the heuristic.
        from fs_report.cra.sections import has_reachability_data

        has_reachability = has_reachability_data(
            (main_df, sla_df, newly_df, re_df, triage_df, snapshot_df)
        )
        template_data["has_reachability"] = has_reachability
        if has_reachability:
            template_data["kpi_reachable"] = _col_count(
                main_df, "reachability_label", "REACHABLE"
            )

        # ── Metadata labels ─────────────────────────────────────────────
        meta = report_data.metadata or {}
        additional_data = meta.get("additional_data", {}) or {}
        recipe_params: dict[str, Any] = additional_data.get("recipe_parameters") or {}

        # Period KPI — humanized --since window so the customer sees the
        # report's time span at a glance ("24h", "7d", "30d"). Falls back
        # from additional_data to top-level metadata (matches the
        # since_label code path below).
        from fs_report.cra.sections import format_since_period_label

        _since_start = (
            additional_data.get("since_start", "") or meta.get("since_start", "") or ""
        )
        _since_end = (
            additional_data.get("since_end", "") or meta.get("since_end", "") or ""
        )
        template_data["kpi_period"] = format_since_period_label(
            _since_start, _since_end
        )

        # scope_label: prefer folder > project > All
        # For project_filter, prefer the human-readable name stored in
        # metadata["project_name"] (if set) over the raw filter value which
        # may be a numeric ID when the user passed --project <numeric-id>.
        folder = meta.get("folder_name", "") or meta.get("folder_filter", "") or ""
        project_name = meta.get("project_name", "") or ""
        project = meta.get("project_filter", "") or ""
        scope_project = project_name or project
        if folder:
            template_data.setdefault("scope_label", f"folder: {folder}")
        elif scope_project:
            template_data.setdefault("scope_label", f"project: {scope_project}")
        else:
            template_data.setdefault("scope_label", "All projects")

        # threshold_label — prefer the effective threshold the transform
        # actually used (reflects CLI override + unfilterable-tier strategy
        # resolution); fall back to recipe_params for the YAML default.
        threshold = additional_data.get("effective_threshold") or recipe_params.get(
            "exploit_maturity_threshold", []
        )
        if threshold:
            template_data.setdefault(
                "threshold_label", ", ".join(str(t) for t in threshold)
            )
        else:
            template_data.setdefault("threshold_label", "—")

        # since_label: prefer metadata window strings
        since_start = meta.get("since_start", "") or additional_data.get(
            "since_start", ""
        )
        since_end = meta.get("since_end", "") or additional_data.get("since_end", "")
        if since_start and since_end:
            template_data.setdefault("since_label", f"{since_start} → {since_end}")
        elif since_start:
            template_data.setdefault("since_label", f"From {since_start}")
        else:
            template_data.setdefault("since_label", "24h")

        # ── Build the 5 section dicts ────────────────────────────────────
        # Strip reachability columns from 📋 Full Snapshot when the project
        # type (source-code scan) doesn't populate them. Keeps the table
        # informative for binary scans, removes empty noise for everything
        # else. Same filter applies to 🔥 SLA-Breach because reachability is
        # a high-signal triage column on actively-exploited rows.
        from fs_report.cra.sections import filter_reachability_cols

        def _f(cols: list[tuple[str, str]]) -> list[tuple[str, str]]:
            return filter_reachability_cols(cols, has_reachability=has_reachability)

        section_specs: list[
            tuple[str, pd.DataFrame, list[tuple[str, str]], int | None]
        ] = [
            ("sla_breach", sla_df, _f(self._CRA_SLA_COLS), None),
            ("newly_above", newly_df, self._CRA_NEWLY_ABOVE_COLS, None),
            ("re_emerged", re_df, self._CRA_RE_EMERGED_COLS, None),
            ("still_in_triage", triage_df, self._CRA_STILL_IN_TRIAGE_COLS, None),
            (
                "full_snapshot",
                snapshot_df,
                _f(self._CRA_FULL_SNAPSHOT_COLS),
                self._FULL_SNAPSHOT_MAX_ROWS,
            ),
        ]

        cra_sections: list[dict[str, Any]] = []
        for key, df, col_specs, max_rows in section_specs:
            n = len(df) if not df.empty else 0
            # Subset to columns that actually exist in the DataFrame
            available_cols = [
                {"key": col, "display": label}
                for col, label in col_specs
                if df.empty or col in df.columns
            ]
            # If no spec'd columns exist, fall back to first 6 raw columns
            if not available_cols and not df.empty:
                available_cols = [
                    {"key": c, "display": c} for c in list(df.columns)[:6]
                ]

            truncated = max_rows is not None and n > max_rows
            shown = min(n, max_rows) if max_rows is not None else n

            if not df.empty and n > 0:
                display_df = df.head(shown) if max_rows is not None else df
                col_keys = [c["key"] for c in available_cols]
                raw_rows: list[dict[str, Any]] = display_df[  # type: ignore[assignment]
                    [c for c in col_keys if c in display_df.columns]
                ].to_dict(orient="records")
                rows = [self._format_cra_row(r) for r in raw_rows]
            else:
                rows = []

            cra_sections.append(
                {
                    "key": key,
                    "label": self._CRA_SECTION_LABELS.get(key, key),
                    "count": n,
                    "shown": shown,
                    "truncated": truncated,
                    "columns": available_cols,
                    "rows": rows,
                }
            )

        template_data["cra_sections"] = cra_sections

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer to handle numpy types and booleans."""
        import numpy as np

        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            value = float(obj)
            if math.isnan(value) or math.isinf(value):
                return None
            return value
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, bool):
            return obj  # Python bools are correctly serialized to JSON
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def _prepare_chart_data(
        self,
        df: pd.DataFrame,
        chart_type: str | None,
        is_stacked: bool = False,
        chart_config: dict | None = None,
    ) -> dict[str, Any]:
        """Prepare data for chart rendering."""
        if df.empty:
            return {"labels": [], "datasets": []}

        if chart_type == "line":
            y_columns = chart_config.get("y_columns") if chart_config else None
            labels = chart_config.get("labels") if chart_config else None
            return self._prepare_line_chart_data(df, y_columns, labels)
        elif chart_type == "bar":
            return self._prepare_bar_chart_data(df, is_stacked)
        elif chart_type == "pie":
            return self._prepare_pie_chart_data(df)
        elif chart_type == "scatter":
            return self._prepare_scatter_chart_data(df)
        else:
            return {"labels": [], "datasets": []}

    def _prepare_line_chart_data(
        self,
        df: pd.DataFrame,
        y_columns: list[str] | None = None,
        labels: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Prepare data for line chart."""
        # Convert DataFrame to native types to avoid ambiguous truth value errors
        if isinstance(df, pd.DataFrame):
            # Check if DataFrame is empty using native Python bool
            if len(df) == 0:
                return {"labels": [], "datasets": []}
        else:
            # If it's already converted to native types, check if it's empty
            if not df or len(df) == 0:  # type: ignore[unreachable]
                return {"labels": [], "datasets": []}

        # For line charts, we typically need x and y values
        if len(df.columns) >= 2:
            x_col = df.columns[0]

            # If y_columns is specified, use those; otherwise use the second column
            if y_columns:
                y_cols = y_columns
            else:
                y_cols = [df.columns[1]]

            datasets = []
            colors = [
                ("rgb(75, 192, 192)", "rgba(75, 192, 192, 0.2)"),  # Teal
                ("rgb(255, 99, 132)", "rgba(255, 99, 132, 0.2)"),  # Red
                ("rgb(54, 162, 235)", "rgba(54, 162, 235, 0.2)"),  # Blue
                ("rgb(255, 205, 86)", "rgba(255, 205, 86, 0.2)"),  # Yellow
                ("rgb(153, 102, 255)", "rgba(153, 102, 255, 0.2)"),  # Purple
            ]

            for i, y_col in enumerate(y_cols):
                if y_col in df.columns:
                    color_pair = colors[i % len(colors)]
                    # Create user-friendly label
                    if labels and y_col in labels:
                        label = labels[y_col]
                    else:
                        friendly_label_map = {
                            "finding_count": "Findings",
                            "composite_risk_score": "Risk Score",
                            "portfolio_composite_risk": "Portfolio Risk",
                            "avg_risk_score": "Average Risk",
                            "total_risk": "Total Risk",
                            "project_count": "Projects",
                            "severity": "Severity",
                            "resolution_count": "Resolutions",
                        }
                        label = friendly_label_map.get(
                            y_col, y_col.replace("_", " ").title()
                        )

                    datasets.append(
                        {
                            "label": label,
                            "data": df[y_col].tolist(),
                            "borderColor": color_pair[0],
                            "backgroundColor": color_pair[1],
                            "fill": False,
                        }
                    )

            return {"labels": df[x_col].tolist(), "datasets": datasets}
        return {"labels": [], "datasets": []}

    def _prepare_bar_chart_data(
        self, df: pd.DataFrame, is_stacked: bool = False, y_col: str | None = None
    ) -> dict[str, Any]:
        """Prepare bar chart data for CVA and other reports."""
        try:
            # Convert DataFrame to native types to avoid ambiguous truth value errors
            if isinstance(df, pd.DataFrame):
                # Check if DataFrame is empty using native Python bool
                if len(df) == 0:
                    return {"labels": [], "datasets": []}
                self.logger.debug(
                    f"DataFrame shape: {df.shape}, columns: {list(df.columns)}"
                )
            else:
                # If it's already converted to native types, check if it's empty
                if not df or len(df) == 0:  # type: ignore[unreachable]
                    return {"labels": [], "datasets": []}
                self.logger.debug(
                    f"Data is not DataFrame, type: {type(df)}, length: {len(df) if hasattr(df, '__len__') else 'N/A'}"
                )

            # Use the first column as x, and y_col if provided, else first numeric column after x
            if isinstance(df, pd.DataFrame):
                x_col = df.columns[0]
                actual_y_col: str | None
                if y_col is not None and y_col in df.columns:
                    actual_y_col = y_col
                else:
                    # Try to find the first numeric column after x_col
                    numeric_cols = [
                        col
                        for col in df.columns
                        if col != x_col and pd.api.types.is_numeric_dtype(df[col])
                    ]
                    actual_y_col = (
                        numeric_cols[0]
                        if numeric_cols
                        else (df.columns[1] if len(df.columns) > 1 else None)
                    )
                self.logger.debug(
                    f"Using DataFrame columns: x_col={x_col}, y_col={actual_y_col}"
                )

                # Create labels with versions if available
                labels = []
                for _, row in df.iterrows():
                    name = str(row.get(x_col, "Unknown"))
                    # Check if version column exists and add it to the label
                    if "version" in df.columns:
                        version = str(row.get("version", ""))
                        if version and version != "nan":
                            labels.append(f"{name} ({version})")
                        else:
                            labels.append(name)
                    else:
                        labels.append(name)

                data = df[actual_y_col].tolist() if actual_y_col else []
            else:
                # Handle case where df is already a list of dictionaries
                if df and len(df) > 0:  # type: ignore[unreachable]
                    first_item = df[0]
                    keys = list(first_item.keys())
                    x_col = keys[0]
                    if y_col is not None and y_col in keys:
                        actual_y_col = y_col
                    else:
                        # Try to find the first numeric key after x_col
                        numeric_keys = [
                            k
                            for k in keys
                            if k != x_col and isinstance(first_item[k], int | float)
                        ]
                        actual_y_col = (
                            numeric_keys[0]
                            if numeric_keys
                            else (keys[1] if len(keys) > 1 else None)
                        )
                    self.logger.debug(
                        f"Using dict keys: x_col={x_col}, y_col={actual_y_col}"
                    )

                    # Create labels with versions if available
                    labels = []
                    for item in df:
                        name = str(item.get(x_col, "Unknown"))
                        # Check if version key exists and add it to the label
                        if "version" in item:
                            version = str(item.get("version", ""))
                            if version and version != "nan":
                                labels.append(f"{name} ({version})")
                            else:
                                labels.append(name)
                        else:
                            labels.append(name)

                    data = [item[actual_y_col] for item in df] if actual_y_col else []
                else:
                    return {"labels": [], "datasets": []}
            self.logger.debug(
                f"Generated labels count: {len(labels)}, data count: {len(data)}"
            )
            # Create user-friendly label for the dataset
            friendly_label_map = {
                "finding_count": "Findings",
                "composite_risk_score": "Risk Score",
                "portfolio_composite_risk": "Portfolio Risk",
                "avg_risk_score": "Average Risk",
                "total_risk": "Total Risk",
                "project_count": "Projects",
                "severity": "Severity",
                "resolution_count": "Resolutions",
            }
            if actual_y_col is not None:
                friendly_label = friendly_label_map.get(
                    actual_y_col, actual_y_col.replace("_", " ").title()
                )
            else:
                friendly_label = "Value"

            return {
                "labels": list(labels),
                "datasets": [
                    {
                        "label": friendly_label,
                        "data": list(data),
                        "backgroundColor": "rgba(54, 162, 235, 0.8)",
                        "stack": is_stacked,
                    }
                ],
            }
        except Exception as e:
            self.logger.error(f"Error in _prepare_bar_chart_data: {e}")
            self.logger.error(f"DataFrame type: {type(df)}")
            if isinstance(df, pd.DataFrame):
                self.logger.error(f"DataFrame shape: {df.shape}")
                self.logger.error(f"DataFrame columns: {list(df.columns)}")
            raise

    def _prepare_pie_chart_data(self, df: pd.DataFrame) -> dict[str, Any]:
        """Prepare data for pie chart."""
        # Convert DataFrame to native types to avoid ambiguous truth value errors
        if isinstance(df, pd.DataFrame):
            # Check if DataFrame is empty using native Python bool
            if len(df) == 0:
                return {"labels": [], "datasets": []}
            # For pie charts, we need labels and values
            if len(df.columns) >= 2:
                labels = df.iloc[:, 0].tolist()
                # Prefer 'finding_count' column if present (group_by adds extra columns like avg_risk_score)
                if "finding_count" in df.columns:
                    values = df["finding_count"].tolist()
                else:
                    values = df.iloc[:, 1].tolist()
                return {
                    "labels": labels,
                    "datasets": [
                        {
                            "data": values,
                            "backgroundColor": [
                                "#FF6384",
                                "#36A2EB",
                                "#FFCE56",
                                "#4BC0C0",
                                "#9966FF",
                                "#FF9F40",
                                "#FF6384",
                                "#C9CBCF",
                            ],
                        }
                    ],
                }
        else:
            # Handle case where df is already a list of dictionaries
            if df and len(df) > 0:  # type: ignore[unreachable]
                first_item = df[0]
                keys = list(first_item.keys())
                if len(keys) >= 2:
                    labels = [item[keys[0]] for item in df]
                    # Prefer 'finding_count' if present
                    if "finding_count" in first_item:
                        values = [item["finding_count"] for item in df]
                    else:
                        values = [item[keys[1]] for item in df]
                    return {
                        "labels": labels,
                        "datasets": [
                            {
                                "data": values,
                                "backgroundColor": [
                                    "#FF6384",
                                    "#36A2EB",
                                    "#FFCE56",
                                    "#4BC0C0",
                                    "#9966FF",
                                    "#FF9F40",
                                    "#FF6384",
                                    "#C9CBCF",
                                ],
                            }
                        ],
                    }
        return {"labels": [], "datasets": []}

    def _prepare_scatter_chart_data(self, df: pd.DataFrame) -> dict[str, Any]:
        """Prepare data for scatter chart."""
        # Convert DataFrame to native types to avoid ambiguous truth value errors
        if isinstance(df, pd.DataFrame):
            # Check if DataFrame is empty using native Python bool
            if len(df) == 0:
                return {"datasets": []}
            # For scatter charts, we need x and y coordinates
            if len(df.columns) >= 2:
                x_col = df.columns[0]
                y_col = df.columns[1]
                data = [
                    {"x": x, "y": y} for x, y in zip(df[x_col], df[y_col], strict=False)
                ]
                return {
                    "datasets": [
                        {
                            "label": f"{x_col} vs {y_col}",
                            "data": data,
                            "backgroundColor": "rgba(255, 99, 132, 0.8)",
                        }
                    ]
                }
        else:
            # Handle case where df is already a list of dictionaries
            if df and len(df) > 0:  # type: ignore[unreachable]
                first_item = df[0]
                keys = list(first_item.keys())
                if len(keys) >= 2:
                    x_col = keys[0]
                    y_col = keys[1]
                    data = [{"x": item[x_col], "y": item[y_col]} for item in df]
                    return {
                        "datasets": [
                            {
                                "label": f"{x_col} vs {y_col}",
                                "data": data,
                                "backgroundColor": "rgba(255, 99, 132, 0.8)",
                            }
                        ]
                    }
        return {"datasets": []}

    def _prepare_table_data(self, df: pd.DataFrame) -> dict[str, Any]:
        """Prepare data for table rendering.

        Returns rows as list of dicts for named access in templates.
        Templates should use row.column_name or row['column_name'] syntax.
        """
        # Convert DataFrame to native types to avoid ambiguous truth value errors
        if not isinstance(df, pd.DataFrame):
            # If it's already converted to native types, return as is
            if df and len(df) > 0:  # type: ignore[unreachable]
                # Already a list of dictionaries - perfect!
                first_item = df[0]
                headers = [col.replace("_", " ").title() for col in first_item.keys()]
                columns = list(first_item.keys())
                return {
                    "headers": headers,
                    "columns": columns,
                    "rows": df,  # Already list of dicts
                    "row_count": len(df),
                }
            else:
                return {
                    "headers": [],
                    "columns": [],
                    "rows": [],
                    "row_count": 0,
                }

        # Check if DataFrame is empty using native Python bool
        if len(df) == 0:
            return {
                "headers": [],
                "columns": [],
                "rows": [],
                "row_count": 0,
            }

        # Work on a copy so we never mutate the caller's DataFrame.
        df = df.copy()

        # Identify likely numeric columns (exclude label/name columns that
        # happen to contain a numeric keyword, e.g. "reachability_label").
        _numeric_keywords = {"score", "count", "risk", "epss"}
        _label_keywords = {"label", "name", "id", "version", "band", "assignment"}
        numeric_cols = [
            col
            for col in df.columns
            if any(key in col.lower() for key in _numeric_keywords)
            and not any(key in col.lower() for key in _label_keywords)
        ]
        for col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        # Remove duplicate columns
        seen = set()
        unique_cols = []
        for col in df.columns:
            if col not in seen:
                unique_cols.append(col)
                seen.add(col)
        df = df[unique_cols]
        # Convert all boolean columns to Python bools
        for col in df.columns:
            if df[col].dtype == "bool" or str(df[col].dtype).startswith("bool"):
                df[col] = df[col].apply(bool)

        # Create user-friendly column names mapping
        friendly_names = {
            "name": "Component Name",
            "version": "Version",
            "type": "Type",
            "project.name": "Project",
            "composite_risk_score": "Composite Risk Score",
            "portfolio_risk_score": "Portfolio Risk Score",
            "portfolio_composite_risk": "Portfolio Composite Risk",
            "normalized_risk_score": "Normalized Risk Score",
            "finding_count": "Finding Count",
            "findings_count": "Findings Count",
            "project_count": "Project Count",
            "has_kev": "Has KEV",
            "has_exploits": "Has Exploits",
        }

        # Build friendly headers while preserving original column names
        friendly_headers = []
        columns = list(df.columns)

        for col in columns:
            if col in friendly_names:
                friendly_headers.append(friendly_names[col])
            else:
                friendly_headers.append(col.replace("_", " ").title())

        # Clean and format the data as list of dicts
        cleaned_rows = []
        for _, row in df.iterrows():
            cleaned_row = {}
            for col in columns:
                value = row[col]

                # Handle case where value might be a pandas Series or numpy array
                if hasattr(value, "__len__") and not isinstance(value, str | bytes):
                    # Convert to scalar if it's an array-like object
                    if len(value) == 1:
                        value = value.iloc[0] if hasattr(value, "iloc") else value[0]
                    else:
                        # If it's a list/array with multiple values, join them
                        value = str(
                            value.tolist() if hasattr(value, "tolist") else list(value)
                        )

                # Clean the value
                cleaned_value: Any
                if col in ["has_kev", "has_exploits"]:
                    # Keep as boolean for template logic
                    if pd.isna(value):
                        cleaned_value = False
                    elif isinstance(value, bool):
                        cleaned_value = value
                    elif isinstance(value, str):
                        cleaned_value = value.lower() == "true"
                    else:
                        cleaned_value = bool(value)
                elif col in ["finding_count", "findings_count", "project_count"]:
                    cleaned_value = int(value) if pd.notna(value) else 0
                elif col in [
                    "portfolio_composite_risk",
                    "normalized_risk_score",
                    "composite_risk_score",
                ]:
                    # Always convert risk scores to integers
                    cleaned_value = int(value) if pd.notna(value) else 0
                elif pd.isna(value):
                    cleaned_value = ""
                elif isinstance(value, int | float):
                    if math.isinf(value) or math.isnan(value):
                        cleaned_value = str(value)
                    elif value == int(value):
                        cleaned_value = int(value)
                    else:
                        cleaned_value = round(value, 1)
                else:
                    cleaned_value = value

                cleaned_row[col] = cleaned_value
            cleaned_rows.append(cleaned_row)

        return {
            "headers": friendly_headers,
            "columns": columns,  # Original column names for reference
            "rows": cleaned_rows,  # List of dicts with original column names as keys
            "row_count": len(df),
        }

    def _prepare_pareto_chart_data(
        self, df: pd.DataFrame, recipe: Recipe | None = None
    ) -> dict[str, Any]:
        """Prepare Pareto chart data for CVA - shows cumulative risk contribution with KEV/exploit styling."""
        # Get pareto chart limit from recipe parameters, default to 20
        pareto_limit = 20
        if recipe and recipe.parameters and "pareto_chart_limit" in recipe.parameters:
            pareto_limit = recipe.parameters["pareto_chart_limit"]

        # Convert DataFrame to native types to avoid ambiguous truth value errors
        if not isinstance(df, pd.DataFrame):
            # If it's already converted to native types, handle as list of dictionaries
            if not df or len(df) == 0:  # type: ignore[unreachable]
                return {"labels": [], "datasets": [], "markers": {}}
            # Convert back to DataFrame for processing
            df = pd.DataFrame(df)
        else:
            # Check if DataFrame is empty using native Python bool
            if len(df) == 0:
                return {"labels": [], "datasets": [], "markers": {}}

        # Check for either composite_risk_score (main data) or portfolio_composite_risk (portfolio data)
        risk_column = (
            "portfolio_composite_risk"
            if "portfolio_composite_risk" in df.columns
            else "composite_risk_score"
        )
        if risk_column not in df.columns:
            return {"labels": [], "datasets": [], "markers": {}}

        # Sort by risk score descending
        df_sorted = df.sort_values(risk_column, ascending=False)

        # Take top N components based on parameter
        df_top = df_sorted.head(pareto_limit)

        # Create labels with versions
        labels = []
        for _, row in df_top.iterrows():
            name = str(row.get("name", "Unknown"))
            version = str(row.get("version", ""))
            if version and version != "nan":
                labels.append(f"{name} ({version})")
            else:
                labels.append(name)

        risk_scores = [int(score) for score in df_top[risk_column].tolist()]

        # Calculate cumulative percentage
        total_risk = float(sum(risk_scores))
        cumulative_percentages = []
        cumulative = 0.0
        for score in risk_scores:
            cumulative += float(score)
            cumulative_percentages.append(
                (cumulative / total_risk) * 100 if total_risk > 0 else 0
            )

        # Prepare markers and colors for KEV and exploit flags
        kev_markers = []
        exploit_markers = []
        background_colors = []
        border_colors = []

        # Calculate min and max risk scores for gradient scaling
        min_risk = float(min(risk_scores)) if risk_scores else 1
        max_risk = float(max(risk_scores)) if risk_scores else 1

        def get_risk_color(risk_score: float) -> str:
            """Get color based on logarithmic risk score (green to red)"""
            # Use logarithmic scale for color mapping
            log_min = math.log(max(1, min_risk))
            log_max = math.log(max(1, max_risk))
            log_value = math.log(max(1, risk_score))

            # Handle case where log_max == log_min (single data point or same values)
            if log_max == log_min:
                ratio = 0.5  # Use middle color (orange) for single data point
            else:
                ratio = max(0, min(1, (log_value - log_min) / (log_max - log_min)))

            return f"hsl({120 - ratio * 120}, 70%, 50%)"  # Green to red

        for _, row in df_top.iterrows():
            has_kev = bool(row.get("has_kev", False))
            has_exploit = bool(row.get("has_exploits", False))
            kev_markers.append(has_kev)
            exploit_markers.append(has_exploit)

            # Get risk score for this component
            risk_score = float(row[risk_column])

            # Color bars based on logarithmic risk score (green to red)
            background_colors.append(get_risk_color(risk_score))

            # Border colors based on KEV and exploit status
            if has_kev and has_exploit:
                border_colors.append("#000000")  # Black border for KEV + Exploit
            elif has_exploit:
                border_colors.append("#FF0000")  # Red border for Has Exploit
            else:
                border_colors.append(
                    get_risk_color(risk_score)
                )  # Matching border for standard risk
        return {
            "labels": list(labels),
            "datasets": [
                {
                    "label": "Composite Risk Score",
                    "data": list(risk_scores),
                    "backgroundColor": list(background_colors),
                    "borderColor": list(border_colors),
                    "borderWidth": 3,
                    "yAxisID": "y",
                },
                {
                    "label": "Cumulative Percentage",
                    "data": list(cumulative_percentages),
                    "type": "line",
                    "borderColor": "#FF6B35",
                    "backgroundColor": "rgba(255, 107, 53, 0.2)",
                    "borderWidth": 3,
                    "pointBackgroundColor": "white",
                    "pointBorderColor": "#FF6B35",
                    "pointRadius": 6,
                    "pointBorderWidth": 2,
                    "yAxisID": "y1",
                },
            ],
            "markers": {"kev": list(kev_markers), "exploit": list(exploit_markers)},
        }

    def _prepare_bubble_matrix_data(self, df: pd.DataFrame) -> dict[str, Any]:
        """Prepare bubble matrix data for CVA - risk vs scope visualization with proper colors and integer counts."""
        # Convert DataFrame to native types to avoid ambiguous truth value errors
        if not isinstance(df, pd.DataFrame):
            # If it's already converted to native types, handle as list of dictionaries
            if not df or len(df) == 0:  # type: ignore[unreachable]
                return {"data": []}
            # Convert back to DataFrame for processing
            df = pd.DataFrame(df)
        else:
            # Check if DataFrame is empty using native Python bool
            if len(df) == 0:
                return {"data": []}

        # Check for either composite_risk_score (main data) or portfolio_composite_risk (portfolio data)
        risk_column = (
            "portfolio_composite_risk"
            if "portfolio_composite_risk" in df.columns
            else "composite_risk_score"
        )
        if risk_column not in df.columns:
            return {"data": []}
        # Handle portfolio data (already aggregated) vs main data (needs aggregation)
        if "portfolio_composite_risk" in df.columns:
            # Portfolio data is already aggregated by component
            component_data = []
            finding_counts = []

            # First pass: collect all finding counts for scaling
            for _, row in df.iterrows():
                finding_count = int(row.get("findings_count", 1))
                finding_counts.append(finding_count)

            # Calculate size scaling factors
            min_findings = min(finding_counts) if finding_counts else 1
            max_findings = max(finding_counts) if finding_counts else 1
            size_range = max_findings - min_findings

            for _, row in df.iterrows():
                risk_score = float(row[risk_column])
                projects_affected = int(row.get("project_count", 1))
                finding_count = int(row.get("findings_count", 1))
                has_exploit = bool(row.get("has_exploits", False))
                in_kev = bool(row.get("has_kev", False))

                # Calculate bubble size with better scaling
                if size_range > 0:
                    normalized_size = (finding_count - min_findings) / size_range
                    bubble_size = 10 + (normalized_size * 40)  # Range from 10 to 50
                else:
                    bubble_size = 30

                # Create label with version
                name = str(row.get("name", "Unknown"))
                version = str(row.get("version", ""))
                if version and version != "nan":
                    label = f"{name} ({version})"
                else:
                    label = name

                component_data.append(
                    {
                        "x": int(risk_score),  # Risk score on x-axis (as integer)
                        "y": projects_affected,  # Projects affected on y-axis
                        "r": bubble_size,
                        "component": label,
                        "findingCount": finding_count,
                        "hasExploit": has_exploit,
                        "inKev": in_kev,
                    }
                )
            return {"data": component_data}
        else:
            # Main data needs aggregation by component
            if "name" in df.columns:
                component_data = []
                finding_counts = []
                # First pass: collect all finding counts for scaling
                for component_name in df["name"].unique():
                    component_rows = df[df["name"] == component_name]
                    finding_count = int(
                        component_rows["finding_count"].sum()
                        if "finding_count" in component_rows.columns
                        else len(component_rows)
                    )
                    finding_counts.append(finding_count)
                # Calculate size scaling factors
                min_findings = min(finding_counts) if finding_counts else 1
                max_findings = max(finding_counts) if finding_counts else 1
                size_range = max_findings - min_findings
                for component_name in df["name"].unique():
                    component_rows = df[df["name"] == component_name]
                    # Aggregate data for this component
                    risk_score = float(component_rows[risk_column].max())
                    projects_affected = int(len(component_rows))  # Ensure integer
                    finding_count = int(
                        component_rows["finding_count"].sum()
                        if "finding_count" in component_rows.columns
                        else len(component_rows)
                    )
                    has_exploit = (
                        bool(component_rows["has_exploits"].any())
                        if "has_exploits" in component_rows.columns
                        and not component_rows["has_exploits"].empty
                        else False
                    )
                    in_kev = (
                        bool(component_rows["has_kev"].any())
                        if "has_kev" in component_rows.columns
                        and not component_rows["has_kev"].empty
                        else False
                    )
                    # Calculate bubble size with better scaling
                    if size_range > 0:
                        normalized_size = (finding_count - min_findings) / size_range
                        bubble_size = 10 + (normalized_size * 40)  # Range from 10 to 50
                    else:
                        bubble_size = 30

                    # Create label with version
                    version = (
                        str(component_rows["version"].iloc[0])
                        if "version" in component_rows.columns
                        else ""
                    )
                    if version and version != "nan":
                        label = f"{component_name} ({version})"
                    else:
                        label = component_name

                    component_data.append(
                        {
                            "x": int(risk_score),  # Risk score on x-axis (as integer)
                            "y": projects_affected,  # Projects affected on y-axis
                            "r": bubble_size,
                            "component": label,
                            "findingCount": finding_count,
                            "hasExploit": has_exploit,
                            "inKev": in_kev,
                        }
                    )
                return {"data": component_data}
        return {"data": []}
