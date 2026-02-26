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

"""Chart renderer for generating static PNG images from pandas DataFrames."""

from __future__ import annotations

import logging
import warnings
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd

# Set matplotlib style for better-looking charts
plt.style.use("default")
plt.rcParams["font.size"] = 10
plt.rcParams["axes.titlesize"] = 12
plt.rcParams["axes.labelsize"] = 10
plt.rcParams["xtick.labelsize"] = 9
plt.rcParams["ytick.labelsize"] = 9
plt.rcParams["legend.fontsize"] = 9
plt.rcParams["figure.titlesize"] = 14

# Suppress matplotlib warnings
warnings.filterwarnings("ignore", category=UserWarning, module="matplotlib")
warnings.filterwarnings("ignore", category=UserWarning, module="matplotlib.category")
warnings.filterwarnings(
    "ignore", message="Using categorical units to plot a list of strings"
)
warnings.filterwarnings("ignore", message=".*categorical units.*")
warnings.filterwarnings("ignore", message=".*parsable as floats or dates.*")

# Suppress matplotlib category logger INFO messages
logging.getLogger("matplotlib.category").setLevel(logging.WARNING)


class ChartRenderer:
    """Renderer for generating static chart images."""

    def __init__(self) -> None:
        """Initialize the chart renderer with modern styling."""
        self.logger = logging.getLogger(__name__)

        # Modern color palette - colorblind-friendly and visually appealing
        self.colors = ["#2E86AB", "#A23B72", "#F18F01", "#C73E1D", "#6B5B95", "#88B04B"]

        # Set modern matplotlib style
        plt.style.use("default")
        plt.rcParams.update(
            {
                "font.family": "sans-serif",
                "font.sans-serif": ["Arial", "DejaVu Sans", "Liberation Sans"],
                "font.size": 10,
                "axes.titlesize": 14,
                "axes.labelsize": 12,
                "xtick.labelsize": 10,
                "ytick.labelsize": 10,
                "legend.fontsize": 10,
                "figure.titlesize": 16,
                "axes.spines.top": False,
                "axes.spines.right": False,
                "axes.grid": True,
                "grid.alpha": 0.3,
                "grid.linestyle": "--",
                "figure.facecolor": "white",
                "axes.facecolor": "#f8f9fa",
            }
        )

    def _ensure_categorical_data(
        self, data: pd.Series | pd.Index[Any]
    ) -> pd.Series | pd.Index[Any]:
        """Ensure data is treated as categorical strings to prevent parsing warnings."""
        # Convert to string and ensure it's treated as categorical
        return data.astype(str)

    def render_bar_chart(
        self,
        df: pd.DataFrame,
        output_path: Path,
        title: str = "",
        x_column: str | None = None,
        y_columns: list[str] | None = None,
        stacked: bool = False,
    ) -> None:
        """Render a bar chart as PNG."""
        try:
            plt.figure(figsize=(8, 5))

            if x_column and y_columns:
                # Use specified columns
                x_data = self._ensure_categorical_data(df[x_column])
                for i, y_col in enumerate(y_columns):
                    if y_col in df.columns:
                        plt.bar(
                            x_data,
                            df[y_col],
                            label=y_col,
                            color=self.colors[i % len(self.colors)],
                        )
            else:
                # Use first column as x-axis, numeric columns as y-axis
                x_col = df.columns[0]
                numeric_cols = df.select_dtypes(include=["number"]).columns

                if len(numeric_cols) > 0:
                    x_data = self._ensure_categorical_data(df[x_col])
                    for i, col in enumerate(numeric_cols):
                        plt.bar(
                            x_data,
                            df[col],
                            label=col,
                            color=self.colors[i % len(self.colors)],
                        )
                else:
                    # Simple count plot
                    value_counts = df[x_col].value_counts()
                    if len(value_counts) > 0:
                        # Ensure index is treated as categorical strings
                        x_labels = self._ensure_categorical_data(value_counts.index)
                        plt.bar(x_labels, value_counts.values, color=self.colors[0])  # type: ignore[arg-type]

            if title:
                plt.title(title, fontweight="bold")
            plt.xlabel(x_column or df.columns[0])
            plt.ylabel("Count" if not y_columns else "Value")

            if y_columns and len(y_columns) > 1:
                plt.legend()

            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.savefig(output_path, dpi=150, bbox_inches="tight")

            self.logger.debug(f"Bar chart saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Error rendering bar chart: {e}")
            raise
        finally:
            plt.close()

    def render_line_chart(
        self,
        df: pd.DataFrame,
        output_path: Path,
        title: str = "",
        x_column: str | None = None,
        y_columns: list[str] | None = None,
    ) -> None:
        """Render a line chart as PNG."""
        try:
            plt.figure(figsize=(8, 5))

            if x_column and y_columns:
                # Use specified columns
                x_data = self._ensure_categorical_data(df[x_column])
                for i, y_col in enumerate(y_columns):
                    if y_col in df.columns:
                        plt.plot(
                            x_data,
                            df[y_col],
                            marker="o",
                            label=y_col,
                            color=self.colors[i % len(self.colors)],
                        )
            else:
                # Use first column as x-axis, numeric columns as y-axis
                x_col = df.columns[0]
                numeric_cols = df.select_dtypes(include=["number"]).columns

                if len(numeric_cols) > 0:
                    x_data = self._ensure_categorical_data(df[x_col])
                    for i, col in enumerate(numeric_cols):
                        plt.plot(
                            x_data,
                            df[col],
                            marker="o",
                            label=col,
                            color=self.colors[i % len(self.colors)],
                        )
                else:
                    # Simple line plot of counts
                    value_counts = df[x_col].value_counts().sort_index()
                    if len(value_counts) > 0:
                        # Ensure index is treated as categorical strings
                        x_labels = self._ensure_categorical_data(value_counts.index)
                        plt.plot(
                            x_labels,
                            value_counts.values,  # type: ignore[arg-type]
                            marker="o",
                            color=self.colors[0],
                        )

            if title:
                plt.title(title, fontweight="bold")
            plt.xlabel(x_column or df.columns[0])
            plt.ylabel("Count" if not y_columns else "Value")

            if y_columns and len(y_columns) > 1:
                plt.legend()

            plt.xticks(rotation=45, ha="right")
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(output_path, dpi=150, bbox_inches="tight")

            self.logger.debug(f"Line chart saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Error rendering line chart: {e}")
            raise
        finally:
            plt.close()

    def render_pie_chart(
        self,
        df: pd.DataFrame,
        output_path: Path,
        title: str = "",
        value_column: str | None = None,
        label_column: str | None = None,
    ) -> None:
        """Render a pie chart as PNG."""
        try:
            plt.figure(figsize=(8, 6))

            if value_column and label_column:
                # Use specified columns
                labels = self._ensure_categorical_data(df[label_column])
                values = df[value_column]
            else:
                # Use first column for labels, second for values
                if len(df.columns) >= 2:
                    labels = self._ensure_categorical_data(df.iloc[:, 0])
                    values = df.iloc[:, 1]
                else:
                    # Simple value counts
                    value_counts = df.iloc[:, 0].value_counts()
                    labels = self._ensure_categorical_data(value_counts.index)
                    values = value_counts.values  # type: ignore[assignment]

            # Filter out zero values
            non_zero_mask = values > 0
            labels = labels[non_zero_mask]
            values = values[non_zero_mask]

            if len(values) > 0 and len(labels) > 0:
                plt.pie(
                    values,
                    labels=labels,  # type: ignore[arg-type]
                    autopct="%1.1f%%",
                    colors=self.colors[: len(values)],
                )

            if title:
                plt.title(title, fontweight="bold")

            plt.axis("equal")
            plt.tight_layout()
            plt.savefig(output_path, dpi=150, bbox_inches="tight")

            self.logger.debug(f"Pie chart saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Error rendering pie chart: {e}")
            raise
        finally:
            plt.close()

    def render_pareto_chart(
        self,
        df: pd.DataFrame,
        output_path: Path,
        title: str = "",
        x_column: str | None = None,
        y_columns: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Render a Pareto chart (bar + cumulative line) as PNG."""
        try:
            fig, ax1 = plt.subplots(figsize=(14, 8))

            # Get data
            if x_column and y_columns and len(y_columns) >= 2:
                x_data = self._ensure_categorical_data(df[x_column])
                risk_scores = df[y_columns[0]]
                cumulative_data = df[y_columns[1]]
            else:
                x_data = self._ensure_categorical_data(df.iloc[:, 0])
                risk_scores = df.iloc[:, 1]
                total_risk = risk_scores.sum()
                cumulative_data = (
                    (risk_scores.cumsum() / total_risk * 100)
                    if total_risk > 0
                    else risk_scores * 0
                )

            # Create bar chart with enhanced styling
            bar_colors = []
            bar_edges = []
            bar_alphas = []

            for i in range(len(x_data)):
                kev = df.iloc[i].get("has_kev_findings", False)
                exp = df.iloc[i].get("has_exploit_findings", False)

                if kev and exp:
                    bar_colors.append("#DC143C")  # Crimson red
                    bar_edges.append("#8A2BE2")  # Blue violet
                    bar_alphas.append(0.9)
                elif kev:
                    bar_colors.append("#FF4500")  # Orange red
                    bar_edges.append("#2F4F4F")  # Dark slate gray
                    bar_alphas.append(0.85)
                elif exp:
                    bar_colors.append("#4169E1")  # Royal blue
                    bar_edges.append("#8A2BE2")  # Blue violet
                    bar_alphas.append(0.8)
                else:
                    bar_colors.append("#4682B4")  # Steel blue
                    bar_edges.append("#2F4F4F")  # Dark slate gray
                    bar_alphas.append(0.7)

            # Create bars with gradient effect
            bars = ax1.bar(
                range(len(x_data)),
                risk_scores,
                color=bar_colors,
                edgecolor=bar_edges,
                linewidth=2,
                alpha=0.8,
                label="Risk Score",
                width=0.7,
                zorder=1,
            )

            # Add subtle gradient effect to bars
            for i, bar in enumerate(bars):
                bar.set_hatch("///")
                bar.set_alpha(bar_alphas[i])

            # Enhanced styling
            ax1.set_xlabel("Component", fontweight="bold", fontsize=12)
            ax1.set_ylabel(
                "Composite Risk Score", color="#2F4F4F", fontweight="bold", fontsize=12
            )
            ax1.tick_params(axis="y", labelcolor="#2F4F4F")
            ax1.set_xticks(range(len(x_data)))
            ax1.set_xticklabels(x_data, rotation=45, ha="right", fontsize=10)

            # Add subtle grid
            ax1.grid(True, alpha=0.2, linestyle="-", linewidth=0.5, zorder=0)

            # Cumulative line with enhanced styling - ensure it's on top
            ax2 = ax1.twinx()
            ax2.plot(
                range(len(x_data)),
                cumulative_data,
                color="#FF6B35",
                marker="o",
                linewidth=3,
                markersize=6,
                label="Cumulative %",
                markerfacecolor="white",
                markeredgecolor="#FF6B35",
                markeredgewidth=2,
                zorder=10,
            )
            ax2.set_ylabel(
                "Cumulative Percentage (%)",
                color="#FF6B35",
                fontweight="bold",
                fontsize=12,
            )
            ax2.tick_params(axis="y", labelcolor="#FF6B35")
            ax2.set_ylim(0, 100)

            # Enhanced legend
            from matplotlib.lines import Line2D
            from matplotlib.patches import Patch

            legend_elements = [
                Patch(
                    facecolor="#FF4500", edgecolor="#2F4F4F", label="KEV", alpha=0.85
                ),
                Patch(
                    facecolor="#4169E1", edgecolor="#8A2BE2", label="Exploit", alpha=0.8
                ),
                Patch(
                    facecolor="#DC143C",
                    edgecolor="#8A2BE2",
                    label="KEV + Exploit",
                    alpha=0.9,
                ),
                Patch(
                    facecolor="#4682B4", edgecolor="#2F4F4F", label="Other", alpha=0.7
                ),
                Line2D(
                    [0],
                    [0],
                    color="#FF6B35",
                    marker="o",
                    linewidth=3,
                    markersize=6,
                    markerfacecolor="white",
                    markeredgecolor="#FF6B35",
                    markeredgewidth=2,
                    label="Cumulative %",
                ),
            ]
            ax1.legend(
                handles=legend_elements,
                loc="lower right",
                bbox_to_anchor=(1.15, -0.5),
                frameon=True,
                fancybox=True,
                shadow=True,
                fontsize=10,
            )

            # Enhanced title
            if title:
                plt.title(
                    title, fontweight="bold", pad=30, fontsize=16, color="#2F4F4F"
                )

            # Add subtle background
            ax1.set_facecolor("#FAFAFA")
            ax2.set_facecolor("#FAFAFA")

            plt.tight_layout()
            plt.savefig(
                output_path,
                dpi=300,
                bbox_inches="tight",
                facecolor="white",
                edgecolor="none",
            )

            self.logger.debug(f"Pareto chart saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Error rendering Pareto chart: {e}")
            raise
        finally:
            plt.close()

    def render_bubble_chart(
        self,
        df: pd.DataFrame,
        output_path: Path,
        title: str = "",
        x_column: str | None = None,
        y_column: str | None = None,
        size_column: str | None = None,
        color_column: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Render a bubble chart (scatter plot with variable sizes) as PNG."""
        try:
            fig, ax = plt.subplots(figsize=(12, 8))

            if x_column and y_column:
                x_data = df[x_column]
                y_data = df[y_column]
            else:
                numeric_cols = df.select_dtypes(include=["number"]).columns
                if len(numeric_cols) >= 2:
                    x_data = df[numeric_cols[0]]
                    y_data = df[numeric_cols[1]]
                else:
                    raise ValueError("Need at least 2 numeric columns for bubble chart")

            sizes: Any
            if size_column and size_column in df.columns:
                sizes = df[size_column] * 200  # Scale up for better visibility
            else:
                sizes = 200

            # Enhanced color logic based on risk levels and exploit status
            colors = []
            for _i, row in df.iterrows():
                has_exploit = row.get("has_exploit_findings", False)
                in_kev = row.get("has_kev_findings", False)
                risk_score = row.get("composite_risk_score", 0)
                if has_exploit and in_kev:
                    colors.append("#8B0000")  # Dark red for KEV + Exploit
                elif has_exploit:
                    colors.append("#DC143C")  # Red for exploit
                elif in_kev:
                    colors.append("#FF4500")  # Orange for KEV
                elif risk_score >= 400:
                    colors.append("#FF6347")  # Tomato for very high risk
                elif risk_score >= 300:
                    colors.append("#FF8C00")  # Dark orange for high risk
                elif risk_score >= 200:
                    colors.append("#FFD700")  # Gold for medium-high risk
                elif risk_score >= 100:
                    colors.append("#90EE90")  # Light green for medium risk
                else:
                    colors.append("#4682B4")  # Steel blue for low risk

            ax.scatter(
                x_data,
                y_data,
                s=sizes,
                c=colors,
                alpha=0.7,
                edgecolors="white",
                linewidth=1.5,
            )

            from matplotlib.patches import Patch

            legend_elements = [
                Patch(facecolor="#8B0000", label="KEV + Exploit", alpha=0.7),
                Patch(facecolor="#DC143C", label="Has Exploit", alpha=0.7),
                Patch(facecolor="#FF4500", label="In KEV", alpha=0.7),
                Patch(facecolor="#FF6347", label="Very High Risk (400+)", alpha=0.7),
                Patch(facecolor="#FF8C00", label="High Risk (300-399)", alpha=0.7),
                Patch(
                    facecolor="#FFD700", label="Medium-High Risk (200-299)", alpha=0.7
                ),
                Patch(facecolor="#90EE90", label="Medium Risk (100-199)", alpha=0.7),
                Patch(facecolor="#4682B4", label="Low Risk (<100)", alpha=0.7),
            ]
            ax.legend(
                handles=legend_elements,
                loc="upper left",
                bbox_to_anchor=(1.05, 1),
                frameon=True,
                fancybox=True,
                shadow=True,
                fontsize=9,
            )

            # Label more bubbles - top 10 by composite risk score
            if "composite_risk_score" in df.columns and "name" in df.columns:
                # Sort by risk score and get top 10
                sorted_df = df.sort_values(
                    "composite_risk_score", ascending=False
                ).head(10)

                for i, (_, row) in enumerate(sorted_df.iterrows()):
                    x = row[x_column] if x_column else row.iloc[0]
                    y = row[y_column] if y_column else row.iloc[1]
                    name = row["name"]

                    # Truncate long names
                    if len(name) > 25:
                        name = name[:22] + "..."

                    # Position labels to avoid overlap
                    if i < 5:
                        # Top 5: alternate above/below
                        xytext = (8, 25 if i % 2 == 0 else -35)
                    else:
                        # Next 5: use different positions
                        positions = [
                            (15, 15),
                            (-15, 15),
                            (15, -25),
                            (-15, -25),
                            (0, 40),
                        ]
                        xytext = positions[i - 5]

                    # Enhanced annotation styling
                    ax.annotate(
                        f"{name}\n({int(y)} proj)",
                        (x, y),
                        xytext=xytext,
                        textcoords="offset points",
                        fontsize=8,
                        alpha=0.9,
                        fontweight="bold",
                        bbox={
                            "boxstyle": "round,pad=0.3",
                            "facecolor": "white",
                            "alpha": 0.95,
                            "edgecolor": "#2F4F4F",
                            "linewidth": 1,
                        },
                        arrowprops={
                            "arrowstyle": "->",
                            "connectionstyle": "arc3,rad=0.1",
                            "color": "#2F4F4F",
                            "alpha": 0.7,
                        },
                    )

            # Enhanced styling
            if title:
                ax.set_title(
                    title, fontweight="bold", fontsize=16, pad=20, color="#2F4F4F"
                )
            ax.set_xlabel(
                "Composite Risk Score", fontweight="bold", fontsize=12, color="#2F4F4F"
            )
            ax.set_ylabel(
                "Project Count", fontweight="bold", fontsize=12, color="#2F4F4F"
            )

            # Enhanced grid
            ax.grid(True, alpha=0.2, linestyle="-", linewidth=0.5)

            # Add subtle background
            ax.set_facecolor("#FAFAFA")

            plt.tight_layout()
            plt.savefig(
                output_path,
                dpi=300,
                bbox_inches="tight",
                facecolor="white",
                edgecolor="none",
            )

            self.logger.debug(f"Bubble chart saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Error rendering bubble chart: {e}")
            raise
        finally:
            plt.close()

    def render_heatmap(
        self,
        df: pd.DataFrame,
        output_path: Path,
        title: str = "",
        x_column: str | None = None,
        y_column: str | None = None,
        value_column: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Render a project-component heatmap as PNG."""
        try:
            import numpy as np
            import seaborn as sns

            fig, ax = plt.subplots(figsize=(14, 10))

            # Prepare data for heatmap
            if x_column and y_column and value_column:
                # Pivot the data for heatmap format
                heatmap_data = df.pivot_table(
                    values=value_column,
                    index=y_column,
                    columns=x_column,
                    aggfunc="first",
                ).fillna(0)
            else:
                raise ValueError(
                    "Need x_column, y_column, and value_column for heatmap"
                )

            # Create heatmap with enhanced styling - only show cells with data
            # Filter out zero values to avoid showing empty cells
            heatmap_data_filtered = heatmap_data.replace(0, np.nan)

            # Use a custom color palette that emphasizes risk differences
            custom_cmap = sns.color_palette(
                "RdYlGn_r", n_colors=10
            )  # Red to Green, reversed

            sns.heatmap(
                heatmap_data_filtered,
                annot=True,
                fmt=".1f",
                cmap=custom_cmap,  # type: ignore[arg-type]
                cbar_kws={"label": "Risk Score", "shrink": 0.8},
                ax=ax,
                linewidths=0.5,
                linecolor="white",
                square=False,
                annot_kws={"size": 8, "weight": "bold"},
                mask=heatmap_data_filtered.isna(),
            )  # Mask NaN values

            # Enhanced styling
            ax.set_title(title, fontweight="bold", fontsize=16, pad=20, color="#2F4F4F")
            ax.set_xlabel("Projects", fontweight="bold", fontsize=12, color="#2F4F4F")
            ax.set_ylabel("Components", fontweight="bold", fontsize=12, color="#2F4F4F")

            # Rotate x-axis labels for better readability
            plt.xticks(rotation=45, ha="right")
            plt.yticks(rotation=0)

            # Add subtle background
            ax.set_facecolor("#FAFAFA")

            plt.tight_layout()
            plt.savefig(
                output_path,
                dpi=300,
                bbox_inches="tight",
                facecolor="white",
                edgecolor="none",
            )

            self.logger.debug(f"Heatmap saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Error rendering heatmap: {e}")
            raise
        finally:
            plt.close()

    def render_chart(
        self,
        df: pd.DataFrame,
        chart_type: str,
        output_path: Path,
        title: str = "",
        **kwargs: Any,
    ) -> None:
        """Render a chart based on type."""
        if chart_type.lower() == "bar":
            self.render_bar_chart(df, output_path, title, **kwargs)
        elif chart_type.lower() == "line":
            self.render_line_chart(df, output_path, title, **kwargs)
        elif chart_type.lower() == "pie":
            self.render_pie_chart(df, output_path, title, **kwargs)
        elif chart_type.lower() == "pareto":
            self.render_pareto_chart(df, output_path, title, **kwargs)
        elif chart_type.lower() == "bubble":
            self.render_bubble_chart(df, output_path, title, **kwargs)

        elif chart_type.lower() == "heatmap":
            self.render_heatmap(df, output_path, title, **kwargs)
        else:
            raise ValueError(f"Unsupported chart type: {chart_type}")

    def render_chart_to_file(
        self,
        df: pd.DataFrame,
        chart_type: str,
        chart_config: dict,
        output_dir: Path,
        filename: str,
    ) -> Path | None:
        """
        Render a chart to a file and return the path.
        This method is used by the PDF renderer.
        """
        try:
            output_path = output_dir / filename

            # Extract chart configuration
            title = chart_config.get("title", "")
            x_column = chart_config.get("x_column")
            y_columns = chart_config.get("y_columns")
            value_column = chart_config.get("value_column")
            label_column = chart_config.get("label_column")
            stacked = chart_config.get("stacked", False)
            size_column = chart_config.get("size_column")
            color_column = chart_config.get("color_column")

            # Render based on chart type
            if chart_type.lower() == "bar":
                self.render_bar_chart(
                    df,
                    output_path,
                    title,
                    x_column=x_column,
                    y_columns=y_columns,
                    stacked=stacked,
                )
            elif chart_type.lower() == "line":
                self.render_line_chart(
                    df, output_path, title, x_column=x_column, y_columns=y_columns
                )
            elif chart_type.lower() == "pie":
                self.render_pie_chart(
                    df,
                    output_path,
                    title,
                    value_column=value_column,
                    label_column=label_column,
                )
            elif chart_type.lower() == "pareto":
                self.render_pareto_chart(
                    df, output_path, title, x_column=x_column, y_columns=y_columns
                )
            elif chart_type.lower() == "bubble":
                self.render_bubble_chart(
                    df,
                    output_path,
                    title,
                    x_column=x_column,
                    y_column=y_columns[0] if y_columns else None,
                    size_column=size_column,
                    color_column=color_column,
                )
            elif chart_type.lower() == "heatmap":
                self.render_heatmap(
                    df,
                    output_path,
                    title,
                    x_column=x_column,
                    y_column=y_columns[0] if y_columns else None,
                    value_column=value_column,
                )
            else:
                self.logger.warning(f"Unsupported chart type: {chart_type}")
                return None

            return output_path

        except Exception as e:
            self.logger.error(f"Failed to render chart {filename}: {e}")
            return None


def get_severity_color(severity: str) -> str:
    # Return a color for each severity (customize as needed)
    colors = {
        "critical": "#d62728",
        "high": "#ff7f0e",
        "medium": "#ffbb78",
        "low": "#1f77b4",
        "none": "#2ca02c",
    }
    return colors.get(severity, "#888888")
