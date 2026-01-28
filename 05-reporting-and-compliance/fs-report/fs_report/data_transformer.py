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

"""Data transformation module using pandas and DuckDB."""

import importlib
import logging
from typing import Any, Dict, List, Optional

import pandas as pd

from fs_report.models import Transform


def flatten_dict(d: dict[str, Any], parent_key: str = '', sep: str = '.') -> dict[str, Any]:
    """Flatten a nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def flatten_records(records: list[dict[str, Any]], fields_to_flatten: list[str] | None = None) -> list[dict[str, Any]]:
    """Flatten nested dictionaries in a list of records."""
    flat_records = []
    for rec in records:
        rec_flat = rec.copy()
        if fields_to_flatten:
            for field in fields_to_flatten:
                if field in rec and isinstance(rec[field], dict):
                    flat = flatten_dict(rec[field], parent_key=field)
                    rec_flat.update(flat)
                    del rec_flat[field]
        else:
            # Flatten all nested dicts at top level
            for k, v in list(rec_flat.items()):
                if isinstance(v, dict):
                    flat = flatten_dict(v, parent_key=k)
                    rec_flat.update(flat)
                    del rec_flat[k]
        flat_records.append(rec_flat)
    return flat_records


class DataTransformer:
    """Transform data using pandas and DuckDB."""

    def __init__(self) -> None:
        """Initialize the data transformer."""
        self.logger = logging.getLogger(__name__)

    def transform(
        self,
        data: list[dict[str, Any]],
        transforms: list[Transform],
        additional_data: dict[str, Any] | None = None,
    ) -> pd.DataFrame | dict[str, Any]:
        """Apply a series of transforms to the data. Optionally use additional_data for joins."""
        if not data:
            self.logger.warning("No data to transform")
            return pd.DataFrame()

        # Convert to DataFrame
        df = pd.DataFrame(data)
        self.logger.debug(f"Starting transformation with {len(df)} rows")
        self.logger.debug(f"DataFrame shape: {df.shape}")
        self.logger.debug(f"DataFrame columns: {list(df.columns)}")

        # Apply each transform in sequence
        for i, transform in enumerate(transforms):
            self.logger.debug(f"Applying transform {i+1}: {transform}")
            try:
                # Check if this is a pandas transform function
                if hasattr(transform, 'transform_function') and transform.transform_function:
                    self.logger.debug(f"Applying pandas transform function: {transform.transform_function}")
                    df = self._apply_pandas_transform_function(df, transform.transform_function, additional_data)
                elif hasattr(transform, "join") and transform.join is not None:
                    self.logger.debug(f"Applying join transform: {transform.join}")
                    if additional_data is not None:
                        df = self._apply_join(df, transform.join, additional_data)
                    else:
                        self.logger.warning(
                            "Join transform requested but no additional_data provided"
                        )
                else:
                    self.logger.debug(f"Applying regular transform: {transform}")
                    df = self._apply_transform(df, transform)
            except Exception as e:
                self.logger.error(f"Error in transform {i+1}: {e}")
                raise

        # Final cleanup: handle problematic columns that slipped through from DuckDB failures
        if "i_d" in df.columns:
            if "finding_count" in df.columns:
                # If both exist, drop the unwanted i_d column
                self.logger.debug("Dropping duplicate 'i_d' column in favor of 'finding_count'")
                df = df.drop(columns=["i_d"])
            else:
                # If only i_d exists, rename it to finding_count
                self.logger.debug("Renaming 'i_d' column to 'finding_count' for better readability")
                df = df.rename(columns={"i_d": "finding_count"})

        return df

    def _apply_transform(self, df: pd.DataFrame, transform: Transform) -> pd.DataFrame:
        """Apply a single transform to the DataFrame."""
        try:
            if transform.group_by is not None:
                return self._apply_group_by(df, transform.group_by)
            elif transform.string_agg is not None:
                return self._apply_string_agg(df, transform.string_agg)
            elif transform.calc is not None:
                return self._apply_calc(df, transform.calc)
            elif transform.filter is not None:
                return self._apply_filter(df, transform.filter)
            elif transform.sort is not None:
                return self._apply_sort(df, transform.sort)
            elif transform.pivot is not None:
                return self._apply_pivot(df, transform.pivot)
            elif transform.select is not None:
                return self._apply_select(df, transform.select)
            elif transform.flatten is not None:
                return self._apply_flatten(df, transform.flatten)
            elif transform.rename is not None:
                return self._apply_rename(df, transform.rename)
            else:
                self.logger.warning("No valid transform found")
                return df
        except Exception as e:
            self.logger.error(f"Error applying transform: {e}")
            raise ValueError("Error applying transform") from e  # noqa: B904

    def _apply_group_by(self, df: pd.DataFrame, group_by_config: list[str] | dict[str, Any]) -> pd.DataFrame:
        """Apply group by transformation with comprehensive aggregations."""
        # Handle both legacy list format and new GroupByConfig format
        if isinstance(group_by_config, list):
            # Legacy format: just a list of column names
            columns = group_by_config
            custom_aggs = None
        else:
            # New format: GroupByConfig with keys and aggs
            # Access attributes directly since it's a Pydantic model
            columns = group_by_config.keys if hasattr(group_by_config, 'keys') else []
            custom_aggs = group_by_config.aggs if hasattr(group_by_config, 'aggs') else None
        
        self.logger.debug(f"Grouping by columns: {columns}")
        self.logger.debug(f"Custom aggregations: {custom_aggs}")
        self.logger.debug(f"Available columns: {list(df.columns)}")

        # Debug logging for data before processing
        self.logger.debug("DataFrame info before group_by:")
        self.logger.debug(f"  Shape: {df.shape}")
        self.logger.debug(f"  Data types: {df.dtypes.to_dict()}")
        for col in columns:
            if col in df.columns:
                self.logger.debug(f"  Column '{col}':")
                self.logger.debug(f"    Data type: {df[col].dtype}")
                self.logger.debug(f"    Null count: {df[col].isnull().sum()}")
                self.logger.debug(f"    Sample values: {df[col].head(5).tolist()}")

        # Validate columns exist
        missing_cols = [col for col in columns if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Columns not found in data: {missing_cols}")

        # Clean the data before grouping - handle null/missing values and non-scalars
        df_clean = df.copy()

        # Clean all columns that might be used in the query
        all_columns = columns + [
            "risk",
            "status",
            "component",
            "severity",
            "month_year",
        ]
        # Add custom aggregation columns to the cleaning list
        if custom_aggs and isinstance(custom_aggs, dict):
            all_columns.extend(custom_aggs.keys())
        
        for col in all_columns:
            if col in df_clean.columns:
                # Fill missing values appropriately by dtype
                if pd.api.types.is_numeric_dtype(df_clean[col]):
                    df_clean[col] = df_clean[col].fillna(0)
                else:
                    df_clean[col] = df_clean[col].fillna("Unknown")
                # Convert dict/list to string
                df_clean[col] = df_clean[col].apply(
                    lambda x: str(x) if isinstance(x, dict | list) else x
                )
                # Convert any non-string values to strings for group-by columns
                if col in columns:
                    df_clean[col] = df_clean[col].astype(str)
                # For numeric columns like 'risk', try to convert to float, fallback to 0
                elif col == "risk":
                    df_clean[col] = pd.to_numeric(
                        df_clean[col], errors="coerce"
                    ).fillna(0)

        # Debug logging to see what we're working with
        self.logger.debug(f"After cleaning - DataFrame shape: {df_clean.shape}")
        self.logger.debug(
            f"Group-by columns data types: {df_clean[columns].dtypes.to_dict()}"
        )
        self.logger.debug("Sample values for group-by columns:")
        for col in columns:
            if col in df_clean.columns:
                self.logger.debug(f"  {col}: {df_clean[col].head(3).tolist()}")

        # Only use pandas fallback aggregation logic for group by operations
        agg_dict = {}
        # Add custom aggregations to pandas fallback
        if custom_aggs:
            for col, agg_func in custom_aggs.items():
                # Parse aggregation functions like "sum:risk", "COUNT_DISTINCT:project_name", etc.
                if ":" in agg_func:
                    func_name, column_name = agg_func.split(":", 1)
                    func_name = func_name.strip().upper()
                    column_name = column_name.strip()
                    if column_name in df_clean.columns:
                        if func_name == "SUM":
                            agg_dict[column_name] = "sum"
                        elif func_name == "AVG":
                            agg_dict[column_name] = "mean"
                        elif func_name == "COUNT":
                            agg_dict[column_name] = "count"
                        elif func_name == "COUNT_DISTINCT":
                            agg_dict[column_name] = pd.Series.nunique
                        elif func_name == "LIST_DISTINCT":
                            agg_dict[column_name] = lambda x: list(pd.unique(x))
                        elif func_name == "MIN":
                            agg_dict[column_name] = "min"
                        elif func_name == "MAX":
                            agg_dict[column_name] = "max"
                        elif func_name == "ANY":
                            agg_dict[column_name] = lambda x: x.any()
                    else:
                        self.logger.warning(f"Column '{column_name}' not found for aggregation '{agg_func}'")
                else:
                    # Handle simple function names
                    if col in df_clean.columns:
                        if agg_func.upper() == "SUM":
                            agg_dict[col] = "sum"
                        elif agg_func.upper() == "AVG":
                            agg_dict[col] = "mean"
                        elif agg_func.upper() == "COUNT":
                            agg_dict[col] = "count"
                        elif agg_func.upper() == "MIN":
                            agg_dict[col] = "min"
                        elif agg_func.upper() == "MAX":
                            agg_dict[col] = "max"
        else:
            # Default aggregations for backward compatibility
            if "risk" in df_clean.columns and df_clean["risk"].dtype in [
                "int64",
                "float64",
            ]:
                agg_dict["risk"] = ["mean", "sum"]

        if agg_dict:
            grouped = df_clean.groupby(columns).agg(agg_dict)  # type: ignore[arg-type]
            # Flatten column names
            grouped.columns = [
                "_".join(col).strip() for col in grouped.columns.values
            ]
            grouped = grouped.reset_index()
            # Rename columns to match expected names and convert to integers
            if "risk_mean" in grouped.columns:
                grouped = grouped.rename(columns={"risk_mean": "avg_risk_score"})
                grouped["avg_risk_score"] = (
                    grouped["avg_risk_score"].round().astype(int)
                )
            if "risk_sum" in grouped.columns:
                grouped = grouped.rename(columns={"risk_sum": "total_risk"})
                grouped["total_risk"] = grouped["total_risk"].astype(int)
            # Add finding count
            count_series = df_clean.groupby(columns).size()
            grouped["finding_count"] = count_series.values.astype(int)
            return grouped
        else:
            # If no aggregations, just return the grouped DataFrame
            return df_clean.groupby(columns).size().reset_index(name="finding_count")

    def _apply_string_agg(
        self, df: pd.DataFrame, string_agg_config: Any
    ) -> pd.DataFrame:
        """Apply string aggregation transformation."""
        self.logger.debug(
            f"Applying string aggregation: {string_agg_config.name} = {string_agg_config.column}"
        )
        self.logger.debug(f"Available columns: {list(df.columns)}")
        self.logger.debug(f"DataFrame shape: {df.shape}")

        try:
            df_copy = df.copy()

            # Handle nested field references like 'project_y.name'
            if "." in string_agg_config.column:
                base_col, nested_field = string_agg_config.column.split(".", 1)
                self.logger.debug(f"Extracting nested field: {base_col}.{nested_field}")

                if base_col not in df_copy.columns:
                    self.logger.error(
                        f"Base column '{base_col}' not found in DataFrame"
                    )
                    raise ValueError(f"Base column '{base_col}' not found in DataFrame")

                # Extract the nested field
                df_copy[string_agg_config.column] = df_copy[base_col].apply(
                    lambda x: x.get(nested_field) if isinstance(x, dict) else None
                )
                self.logger.debug(
                    f"Extracted {string_agg_config.column} from {base_col}"
                )
                self.logger.debug(
                    f"Sample values: {df_copy[string_agg_config.column].head(5).tolist()}"
                )

            # Validate column exists
            if string_agg_config.column not in df_copy.columns:
                self.logger.error(
                    f"Column '{string_agg_config.column}' not found in DataFrame"
                )
                raise ValueError(
                    f"Column '{string_agg_config.column}' not found in DataFrame"
                )

            # For now, since we're after a group_by operation, just create a simple aggregation
            # that shows we have project information
            if string_agg_config.column in df_copy.columns:
                # Check if we have any non-null values
                non_null_values = df_copy[string_agg_config.column].dropna()
                if len(non_null_values) > 0:
                    # Get unique values
                    unique_values = non_null_values.unique()
                    aggregated_value = string_agg_config.separator.join(
                        str(val) for val in unique_values
                    )
                    df_copy[string_agg_config.name] = aggregated_value
                    self.logger.debug(f"Successfully aggregated: {aggregated_value}")
                else:
                    df_copy[string_agg_config.name] = "No Project Data"
                    self.logger.debug("No non-null values found")
            else:
                df_copy[string_agg_config.name] = "Column Not Found"
                self.logger.debug("Column not found after extraction")

            return df_copy

        except Exception as e:
            self.logger.error(f"String aggregation failed: {e}")
            # Fallback: add a placeholder value
            df_copy[string_agg_config.name] = f"Error: {str(e)}"
            return df_copy

    def _apply_calc(self, df: pd.DataFrame, calc_config: Any) -> pd.DataFrame:
        """Apply calculation transformation."""
        self.logger.debug(
            f"Applying calculation: {calc_config.name} = {calc_config.expr}"
        )

        try:
            df_copy = df.copy()

            # Special handling for date extraction
            if calc_config.name == "month_year" and "detected" in calc_config.expr:
                try:
                    # Use pandas string operations for date extraction
                    df_copy = df.copy()

                    # Debug logging for detected column
                    self.logger.debug("Detected column before extraction:")
                    self.logger.debug(f"  Data type: {df_copy['detected'].dtype}")
                    self.logger.debug(
                        f"  Sample values: {df_copy['detected'].head(10).tolist()}"
                    )
                    self.logger.debug(
                        f"  Unique values count: {df_copy['detected'].nunique()}"
                    )

                    # Extract year-month from detected column using string operations
                    df_copy["month_year"] = df_copy["detected"].astype(str).str[:7]

                    # Debug logging for month_year column
                    self.logger.debug("Month_year column after extraction:")
                    self.logger.debug(f"  Data type: {df_copy['month_year'].dtype}")
                    self.logger.debug(
                        f"  Sample values: {df_copy['month_year'].head(10).tolist()}"
                    )
                    self.logger.debug(
                        f"  Value counts: {df_copy['month_year'].value_counts().to_dict()}"
                    )

                    return df_copy
                except Exception as e:
                    self.logger.error(f"Error in month_year extraction: {e}")
                    raise

            # Special handling for CASE WHEN statements
            elif "CASE WHEN" in calc_config.expr.upper():
                return self._apply_case_when(df_copy, calc_config)

            # Special handling for DATEDIFF
            elif "DATEDIFF" in calc_config.expr.upper():
                return self._apply_datediff(df_copy, calc_config)

            # Try DuckDB first
            try:
                # Build the SELECT clause with aggregations
                select_parts = [f'"{col}"' for col in df_copy.columns]
                select_parts.append(f'{calc_config.expr} as {calc_config.name}')

                query = f"""
                SELECT {', '.join(select_parts)}
                FROM df
                """

                self.logger.debug(f"Executing DuckDB query: {query}")
                result = pd.read_sql_query(query, df_copy.to_sql("df"))

                return result

            except Exception as e:
                self.logger.error(f"DuckDB calculation failed: {e}")

                # Fallback to pandas eval
                try:
                    df_copy[calc_config.name] = df_copy.eval(calc_config.expr)
                    return df_copy
                except Exception as e2:
                    self.logger.error(f"Pandas eval also failed: {e2}")
                    
                    # Final fallback: handle specific expressions manually
                    if calc_config.name == "month_year" and "detected" in calc_config.expr:
                        # Extract year-month from detected column
                        df_copy[calc_config.name] = df_copy["detected"].astype(str).str[:7]
                        return df_copy
                    elif "CASE WHEN" in calc_config.expr.upper():
                        return self._apply_case_when(df_copy, calc_config)
                    elif "DATEDIFF" in calc_config.expr.upper():
                        return self._apply_datediff(df_copy, calc_config)
                    else:
                        raise ValueError(f"Calculation failed: {calc_config.expr}")

        except Exception as e:
            self.logger.error(f"Error applying transform: {e}")
            raise ValueError("Error applying transform") from e  # noqa: B904

    def _apply_case_when(self, df: pd.DataFrame, calc_config: Any) -> pd.DataFrame:
        """Apply CASE WHEN logic using pandas operations."""
        self.logger.debug(f"Applying CASE WHEN: {calc_config.expr}")

        # Debug: print unique status values before applying logic
        if "status" in df.columns:
            unique_statuses = df["status"].unique().tolist()
            self.logger.debug(
                f"Unique status values before CASE WHEN: {unique_statuses}"
            )

        # Parse the CASE WHEN statement
        expr = calc_config.expr.upper()

        # Initialize the result column
        df_copy = df.copy()
        df_copy[calc_config.name] = "Other"  # Default value

        # Handle different resolution categories
        if "RESOLVED" in expr or "RESOLVED_WITH_PEDIGREE" in expr:
            mask = df_copy["status"].isin(["RESOLVED", "RESOLVED_WITH_PEDIGREE"])
            df_copy.loc[mask, calc_config.name] = "Resolved"

        if "NOT_AFFECTED" in expr or "FALSE_POSITIVE" in expr:
            mask = df_copy["status"].isin(["NOT_AFFECTED", "FALSE_POSITIVE"])
            df_copy.loc[mask, calc_config.name] = "Triaged"

        if "IN_TRIAGE" in expr or "EXPLOITABLE" in expr:
            mask = df_copy["status"].isin(["IN_TRIAGE", "EXPLOITABLE"])
            df_copy.loc[mask, calc_config.name] = "Open"

        return df_copy

    def _apply_datediff(self, df: pd.DataFrame, calc_config: Any) -> pd.DataFrame:
        """Apply DATEDIFF logic using pandas operations."""
        self.logger.debug(f"Applying DATEDIFF: {calc_config.expr}")

        df_copy = df.copy()

        # Parse DATEDIFF('day', detected, updated) or DATEDIFF('day', detected, NOW())
        if "DATEDIFF('DAY', DETECTED, UPDATED)" in calc_config.expr.upper():
            # Calculate days between detected and updated
            df_copy["detected"] = pd.to_datetime(df_copy["detected"])
            df_copy["updated"] = pd.to_datetime(df_copy["updated"])
            df_copy[calc_config.name] = (
                df_copy["updated"] - df_copy["detected"]
            ).dt.days.astype(int)
        elif "DATEDIFF('DAY', DETECTED, NOW())" in calc_config.expr.upper():
            # Calculate days between detected and now
            df_copy["detected"] = pd.to_datetime(df_copy["detected"])
            # Convert detected to timezone-naive to match pd.Timestamp.now()
            df_copy["detected"] = df_copy["detected"].dt.tz_localize(None)
            now = pd.Timestamp.now()
            df_copy[calc_config.name] = (
                df_copy["detected"]
                .apply(lambda d: (now - d).total_seconds() / 86400)
                .astype(int)
            )

        return df_copy

    def _apply_filter(self, df: pd.DataFrame, filter_expr: str) -> pd.DataFrame:
        """Apply filter transformation."""
        self.logger.debug(f"Applying filter: {filter_expr}")

        # Check if this is a simple string comparison that DuckDB might struggle with
        if self._is_simple_string_filter(filter_expr):
            return self._apply_simple_string_filter(df, filter_expr)

        try:
            # Use DuckDB for complex filtering
            # con = duckdb.connect(":memory:")
            # con.register("df", df)

            # query = f"SELECT * FROM df WHERE {filter_expr}"
            # result = con.execute(query).df()

            # con.close()
            # return result
            return df.query(filter_expr)

        except Exception as e:
            self.logger.error(f"Error in filter: {e}")
            # Fallback to pandas query with better error handling
            try:
                # Handle common DuckDB casting issues by using pandas query
                # Replace DuckDB-style string literals with pandas-compatible ones
                pandas_expr = filter_expr.replace("'", "'").replace('"', '"')
                return df.query(pandas_expr)
            except Exception as e2:
                self.logger.error(f"Pandas query also failed: {e2}")
                # Final fallback: try to handle the specific case of string comparison
                return self._apply_simple_string_filter(df, filter_expr)

    def _is_simple_string_filter(self, filter_expr: str) -> bool:
        """Check if this is a simple string comparison filter."""
        # Check for simple string comparisons that DuckDB might struggle with
        simple_patterns = [
            "!=" in filter_expr and "'" in filter_expr,  # severity != 'none'
            "==" in filter_expr and "'" in filter_expr,  # severity == 'high'
            "=in=" in filter_expr and "(" in filter_expr,  # status=in=(open,closed)
        ]
        return any(simple_patterns)

    def _apply_simple_string_filter(self, df: pd.DataFrame, filter_expr: str) -> pd.DataFrame:
        """Apply simple string filters using pandas operations."""
        self.logger.debug(f"Applying simple string filter: {filter_expr}")
        
        try:
            # Handle severity != 'none'
            if "!=" in filter_expr and "'" in filter_expr:
                parts = filter_expr.split("!=")
                if len(parts) == 2:
                    col = parts[0].strip()
                    val = parts[1].strip().strip("'\"")
                    if col in df.columns:
                        # Handle NULL values properly
                        return df[df[col].notna() & (df[col] != val)]
            
            # Handle severity == 'high'
            elif "==" in filter_expr and "'" in filter_expr:
                parts = filter_expr.split("==")
                if len(parts) == 2:
                    col = parts[0].strip()
                    val = parts[1].strip().strip("'\"")
                    if col in df.columns:
                        return df[df[col] == val]
            
            # Handle status=in=(open,closed)
            elif "=in=" in filter_expr and "(" in filter_expr:
                # Extract column name and values
                col_part = filter_expr.split("=in=")[0].strip()
                values_part = filter_expr.split("=in=")[1].strip()
                if values_part.startswith("(") and values_part.endswith(")"):
                    values = [v.strip().strip("'\"") for v in values_part[1:-1].split(",")]
                    if col_part in df.columns:
                        return df[df[col_part].isin(values)]
            
            # If we can't handle it, try pandas query as last resort
            pandas_expr = filter_expr.replace("'", "'").replace('"', '"')
            return df.query(pandas_expr)
            
        except Exception as e:
            self.logger.error(f"Simple string filter failed: {e}")
            raise ValueError(f"Filter failed: {filter_expr}") from e

    def _apply_sort(self, df: pd.DataFrame, sort_config: Any) -> pd.DataFrame:
        """Apply sort transformation."""
        self.logger.debug(f"Sorting by columns: {sort_config.sort}")

        # Validate columns exist
        missing_cols = [col for col in sort_config.sort if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Sort columns not found in data: {missing_cols}")

        # Handle custom severity ordering
        if "severity" in sort_config.sort:
            df_copy = df.copy()
            # Create a custom severity order mapping
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            # Add a temporary column for sorting
            df_copy["_severity_order"] = (
                df_copy["severity"].map(severity_order).fillna(99)
            )

            # Replace 'severity' with '_severity_order' in the sort list
            sort_cols = []
            for col in sort_config.sort:
                if col == "severity":
                    sort_cols.append("_severity_order")
                else:
                    sort_cols.append(col)

            # Sort the DataFrame
            result = df_copy.sort_values(sort_cols, ascending=sort_config.ascending)

            # Remove the temporary column
            result = result.drop("_severity_order", axis=1)

            return result
        else:
            # Regular sorting for non-severity columns
            return df.sort_values(sort_config.sort, ascending=sort_config.ascending)

    def _apply_pivot(self, df: pd.DataFrame, pivot_config: Any) -> pd.DataFrame:
        """Apply pivot transformation."""
        self.logger.debug(
            f"Pivoting data: index={pivot_config.index}, columns={pivot_config.columns}, values={pivot_config.values}"
        )

        # Validate columns exist
        required_cols = [pivot_config.index, pivot_config.columns, pivot_config.values]
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Pivot columns not found in data: {missing_cols}")

        # Handle missing values in the pivot
        df_clean = df.copy()
        df_clean[pivot_config.values] = df_clean[pivot_config.values].fillna(0)

        # Perform the pivot
        try:
            pivoted = df_clean.pivot_table(
                index=pivot_config.index,
                columns=pivot_config.columns,
                values=pivot_config.values,
                aggfunc="sum",  # Sum the values for each combination
                fill_value=0,  # Fill missing combinations with 0
            )

            # Reset index to make the index column a regular column
            pivoted = pivoted.reset_index()

            # Reorder severity columns for stacked bar chart
            severity_order = ["low", "medium", "high", "critical"]
            cols = list(pivoted.columns)
            idx_col = pivoted.columns[0]
            # Find which severity columns are present
            present = [s for s in severity_order if s in cols]
            # Any other columns (e.g., 'none', unexpected severities)
            others = [c for c in cols if c not in present and c != idx_col]
            new_order = [idx_col] + present + others
            pivoted = pivoted.reindex(columns=new_order)

            self.logger.debug(f"Pivot result shape: {pivoted.shape}")
            self.logger.debug(f"Pivot result columns: {list(pivoted.columns)}")

            return pivoted

        except Exception as e:
            self.logger.error(f"Pivot failed: {e}")
            # Fallback: return original data with warning
            self.logger.warning("Pivot failed, returning original data")
            return df

    def _apply_select(self, df: pd.DataFrame, select_config: Any) -> pd.DataFrame:
        """Apply column selection transform."""
        self.logger.debug(f"Selecting columns: {select_config.columns}")

        # Check which columns exist in the DataFrame
        available_columns = list(df.columns)
        selected_columns = []

        for col in select_config.columns:
            if col in available_columns:
                selected_columns.append(col)
            else:
                self.logger.warning(
                    f"Column '{col}' not found in DataFrame. Available columns: {available_columns}"
                )

        if not selected_columns:
            self.logger.error("No valid columns found for selection")
            return df

        result = df[selected_columns]
        self.logger.debug(
            f"Selected {len(selected_columns)} columns: {selected_columns}"
        )
        return result

    def aggregate_by_severity(self, df: pd.DataFrame) -> pd.DataFrame:
        """Aggregate findings by severity level."""
        if "severity" not in df.columns:
            raise ValueError("Data must contain 'severity' column")

        return (
            df.groupby("severity")
            .agg({"id": "count", "risk": ["mean", "min", "max"], "inKev": "sum"})
            .round(2)
        )

    def calculate_mttr(self, df: pd.DataFrame) -> float:
        """Calculate Mean Time to Remediate."""
        if "detected" not in df.columns or "resolved_time" not in df.columns:
            raise ValueError("Data must contain 'detected' and 'resolved_time' columns")

        # Convert to datetime
        df["detected"] = pd.to_datetime(df["detected"])
        df["resolved_time"] = pd.to_datetime(df["resolved_time"])

        # Calculate time difference in days
        df["resolution_time"] = (
            df["resolved_time"] - df["detected"]
        ).dt.total_seconds() / 86400

        return float(df["resolution_time"].mean())

    def _apply_join(
        self, df: pd.DataFrame, join_config: Any, additional_data: dict[str, Any]
    ) -> pd.DataFrame:
        """Apply a join transformation using pandas.merge."""
        self.logger.debug(f"Applying join: {join_config}")
        self.logger.debug(f"Left DataFrame shape: {df.shape}")
        self.logger.debug(f"Left DataFrame columns: {list(df.columns)}")

        if additional_data is None or join_config.right not in additional_data:
            self.logger.error(
                f"Right dataframe '{join_config.right}' not found in additional_data for join."
            )
            return df

        right_df = pd.DataFrame(additional_data[join_config.right])
        self.logger.debug(f"Right DataFrame shape: {right_df.shape}")
        self.logger.debug(f"Right DataFrame columns: {list(right_df.columns)}")

        # Handle nested field access (e.g., component.id)
        left_on_cols = []
        right_on_cols = []

        for col in join_config.left_on:
            if col not in df.columns:
                self.logger.error(f"Left join column '{col}' not in DataFrame.")
                return df
            left_on_cols.append(col)

        for col in join_config.right_on:
            # If the full column name exists, use it directly
            if col in right_df.columns:
                right_on_cols.append(col)
            elif "." in col:
                base_col, nested_field = col.split(".", 1)
                if base_col in right_df.columns:
                    # Extract the nested field if the base column is a dict
                    right_df[col] = right_df[base_col].apply(
                        lambda x, nested_field=nested_field: x.get(nested_field)
                        if isinstance(x, dict)
                        else None
                    )
                    self.logger.debug(f"Extracted {col} from {base_col}")
                    right_on_cols.append(col)
                else:
                    self.logger.error(
                        f"Base column '{base_col}' not in right DataFrame and '{col}' not found as flat column."
                    )
                    return df
            else:
                self.logger.error(
                    f"Right join column '{col}' not in right DataFrame."
                )
                return df

        self.logger.debug(
            f"Join columns - Left: {left_on_cols}, Right: {right_on_cols}"
        )

        try:
            merged = pd.merge(
                df,
                right_df,
                left_on=left_on_cols,
                right_on=right_on_cols,
                how=join_config.how,
            )
            self.logger.debug(f"Join result shape: {merged.shape}")
            return merged
        except Exception as e:
            self.logger.error(f"Join failed: {e}")
            self.logger.debug("Left DataFrame sample:")
            self.logger.debug(df[left_on_cols].head())
            self.logger.debug("Right DataFrame sample:")
            self.logger.debug(right_df[right_on_cols].head())
            raise

    def _apply_flatten(self, df: pd.DataFrame, flatten_config: Any) -> pd.DataFrame:
        """Apply flatten transform to handle nested data structures."""
        self.logger.debug(f"Applying flatten transform: {flatten_config}")
        
        # Convert DataFrame back to records for flattening
        records = df.to_dict('records')
        
        # Determine fields to flatten
        fields_to_flatten = None
        if isinstance(flatten_config, dict) and 'fields' in flatten_config:
            fields_to_flatten = flatten_config['fields']
        elif isinstance(flatten_config, list):
            fields_to_flatten = flatten_config
        
        # Flatten the records
        flat_records = flatten_records(records, fields_to_flatten)
        
        # Debug: print columns and a sample row after flattening
        if flat_records:
            sample_row = flat_records[0]
            if isinstance(sample_row, dict):
                self.logger.debug(f"[DEBUG] Columns after flatten: {list(sample_row.keys())}")
                self.logger.debug(f"[DEBUG] Sample row after flatten: {sample_row}")
            else:
                self.logger.info(f"[DEBUG] Sample row is not a dict: {type(sample_row)}")
        else:
            self.logger.info("[DEBUG] No records after flatten.")
        
        # Convert back to DataFrame
        return pd.DataFrame(flat_records)

    def _apply_rename(self, df: pd.DataFrame, rename_config: Any) -> pd.DataFrame:
        """Apply rename transform to rename DataFrame columns."""
        self.logger.debug(f"Applying rename transform: {rename_config}")
        
        # Handle RenameTransform object
        if hasattr(rename_config, 'columns'):
            columns_mapping = rename_config.columns
        elif isinstance(rename_config, dict) and 'columns' in rename_config:
            columns_mapping = rename_config['columns']
        else:
            columns_mapping = rename_config
        
        self.logger.debug(f"Renaming columns: {columns_mapping}")
        self.logger.debug(f"Available columns before rename: {list(df.columns)}")
        
        # Create a mapping of old names to new names
        rename_mapping = {}
        for old_name, new_name in columns_mapping.items():
            if old_name in df.columns:
                rename_mapping[old_name] = new_name
                self.logger.debug(f"Will rename '{old_name}' to '{new_name}'")
            else:
                self.logger.warning(f"Column '{old_name}' not found for renaming to '{new_name}'")
        
        if rename_mapping:
            result = df.rename(columns=rename_mapping)
            self.logger.debug(f"Available columns after rename: {list(result.columns)}")
            return result
        else:
            self.logger.warning("No valid columns found for renaming")
            return df

    def _apply_pandas_transform_function(
        self, 
        df: pd.DataFrame, 
        transform_function_name: str,
        additional_data: dict[str, Any] | None = None
    ) -> pd.DataFrame:
        """Apply a pandas transform function dynamically imported from transforms.pandas module."""
        try:
            # Try different import paths
            module_name_variants = []
            
            # Handle different function naming patterns
            if transform_function_name.endswith('_pandas_transform'):
                # For functions like findings_by_project_pandas_transform
                base_name = transform_function_name.replace('_pandas_transform', '')
                module_name_variants.extend([base_name, transform_function_name])
            elif transform_function_name.endswith('_transform'):
                # For functions like scan_analysis_transform
                base_name = transform_function_name.replace('_transform', '')
                module_name_variants.extend([base_name, transform_function_name])
            else:
                # For other patterns
                module_name_variants.append(transform_function_name)
            
            import_paths = []
            for variant in module_name_variants:
                import_paths.extend([
                    f"fs_report.transforms.pandas.{variant}",
                    f"transforms.pandas.{variant}",
                ])
            
            module = None
            for module_path in import_paths:
                try:
                    self.logger.debug(f"Trying to import {transform_function_name} from {module_path}")
                    module = importlib.import_module(module_path)
                    self.logger.debug(f"Successfully imported from {module_path}")
                    break
                except ImportError as e:
                    self.logger.debug(f"Failed to import from {module_path}: {e}")
                    continue
            
            if module is None:
                raise ImportError(f"Could not import transform function {transform_function_name} from any known location")
                    
            transform_func = getattr(module, transform_function_name)
            
            # Convert DataFrame to list of dicts for the transform function
            data_list = df.to_dict('records')
            
            # Prepare additional DataFrames if available
            df_projects = additional_data.get('projects') if additional_data else None
            df_components = additional_data.get('components') if additional_data else None
            
            # Call the transform function with proper arguments
            self.logger.debug(f"Calling pandas transform function: {transform_function_name}")
            
            # Try different calling patterns based on function signature
            try:
                # First try with config and additional_data (newest style for transforms needing extra data)
                result = transform_func(data_list, config=additional_data.get('config'), additional_data=additional_data)
            except TypeError:
                try:
                    # Try with config parameter only (standard style)
                    result = transform_func(data_list, config=additional_data.get('config'))
                except TypeError:
                    # Fallback to older style without config
                    result = transform_func(data_list)
            
            # Handle both DataFrame and dictionary returns
            if isinstance(result, dict):
                self.logger.debug(f"Pandas transform returned dictionary with keys: {list(result.keys())}")
                # Store the full result in additional_data for later use
                if additional_data is not None:
                    additional_data['transform_result'] = result
                # Return the main dataset (usually daily_metrics for primary table)
                main_result = result.get('daily_metrics', result.get('main', list(result.values())[0]))
                self.logger.debug(f"Main result shape: {main_result.shape}")
                return main_result  # Return the main DataFrame, not the dictionary
            else:
                self.logger.debug(f"Pandas transform completed. Result shape: {result.shape}")
                self.logger.debug(f"Result columns: {list(result.columns)}")
                return result
            
        except Exception as e:
            self.logger.error(f"Error applying pandas transform function {transform_function_name}: {e}")
            self.logger.exception("Full traceback:")
            raise
