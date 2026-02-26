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
from pathlib import Path
from typing import Any, cast

import numpy as np
import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape

from fs_report.models import Recipe, ReportData

logger = logging.getLogger(__name__)


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

    def render(
        self, recipe: Recipe, report_data: ReportData, output_path: Path
    ) -> None:
        """Render the report to HTML."""
        try:
            # Use template from recipe if specified
            template_name = getattr(recipe, "template", None)
            if template_name:
                template = self.env.get_template(template_name)
            elif recipe.output.charts and len(recipe.output.charts) > 1:
                # Use executive summary template for multiple charts
                template = self._get_template("executive_summary", recipe.name)
            else:
                # Use default template for single chart
                chart_type = None
                if hasattr(recipe.output, "chart") and isinstance(
                    recipe.output.chart, dict
                ):
                    chart_type = recipe.output.chart.get("type", "line")
                else:
                    chart_type = recipe.output.chart
                    # Convert enum to string if needed
                    if chart_type is not None and hasattr(chart_type, "value"):
                        chart_type = chart_type.value
                template = self._get_template(
                    str(chart_type) if chart_type else None, recipe.name
                )

            # Prepare template data
            template_data = self._prepare_template_data(recipe, report_data)

            # Scan for any remaining pandas/numpy objects before rendering
            self.logger.debug("Scanning template_data for pandas/numpy objects...")
            scan_for_pandas_objects(template_data)

            # Convert all data to native types to prevent ambiguous truth value errors
            self.logger.debug("Converting template_data to native types...")
            template_data = convert_to_native_types(template_data)
            self.logger.debug("Conversion complete.")

            # Render the template
            self.logger.debug("Rendering HTML template...")
            html_content = template.render(**template_data)
            self.logger.debug("HTML rendering complete.")

            # Write to file
            output_path.write_text(html_content, encoding="utf-8")

            # self.logger.info(f"Generated HTML: {output_path}")

        except Exception as e:
            self.logger.error(f"Error generating HTML: {e}")
            import traceback

            self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            raise

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
        self, recipe: Recipe, report_data: ReportData
    ) -> dict[str, Any]:
        """Prepare data for template rendering."""
        # Convert data to DataFrame if needed
        if isinstance(report_data.data, pd.DataFrame):
            df = report_data.data
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
            "folder_name": report_data.metadata.get("folder_name", ""),
            "folder_path": report_data.metadata.get("folder_path", ""),
            "folder_filter": report_data.metadata.get("folder_filter", ""),
            "domain": report_data.metadata.get("domain", ""),
            "logo_path": report_data.metadata.get("logo_path"),
        }

        template_data = {
            "recipe_name": recipe.name,
            "slide_title": recipe.output.slide_title or recipe.name,
            "chart_data": chart_data_objects,  # Original objects for template conditions
            "chart_data_json": chart_data_json,  # JSON strings for JavaScript
            "charts": recipe.output.charts or [],
            "table_data": table_data,
            "portfolio_table_data": portfolio_table_data,
            "metadata": slim_metadata,
            "generated_at": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "stacked": is_stacked,
            "is_mttr_chart": is_mttr_chart,
            "y_axis_max": y_axis_max,
            "start_date": slim_metadata["start_date"],
            "end_date": slim_metadata["end_date"],
            "project_filter": slim_metadata["project_filter"],
            "folder_name": slim_metadata["folder_name"],
            "folder_path": slim_metadata["folder_path"],
            "folder_filter": slim_metadata["folder_filter"],
            "domain": slim_metadata["domain"],
            "logo_path": slim_metadata["logo_path"],
            # Add period label for scan frequency chart
            "scan_frequency_period_label": chart_data.get(
                "scan_frequency_period_label", "Month"
            ),
        }

        # Add raw data for templates that need it (like findings by project)
        if isinstance(report_data.data, pd.DataFrame):
            template_data["data"] = report_data.data.to_dict(orient="records")
        else:
            template_data["data"] = report_data.data

        # Merge additional_data into template context.  Convert DataFrames
        # and Series to native Python types up-front so that the later
        # convert_to_native_types pass doesn't recurse through large tables.
        additional_data = report_data.metadata.get("additional_data", {})
        if additional_data:
            for key, value in additional_data.items():
                if key == "config":
                    continue  # Config object is not template-safe
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
        # If the main data is a dict (custom transform), merge all keys into template_data
        if isinstance(report_data.data, dict):
            for key, value in report_data.data.items():
                if key == "raw_ttr_data":
                    template_data["table_data"] = value
                else:
                    template_data[key] = value
        # Convert all data to native Python types to prevent ambiguous truth value errors
        converted_data = convert_to_native_types(template_data)
        return cast(dict[str, Any], converted_data)

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
            if col not in seen and not col.endswith(" 2"):
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
            log_max = math.log(max_risk)
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
