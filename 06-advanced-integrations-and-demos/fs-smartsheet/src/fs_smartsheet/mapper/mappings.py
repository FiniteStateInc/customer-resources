"""Data transformation between Finite State and Smartsheet."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from ..smartsheet_client.schemas import ColumnSchema, SheetSchema, api_value_to_display


class FieldMapping(BaseModel):
    """Mapping configuration for a single field."""

    fs_field: str = Field(description="Dot-notation path to FS field (e.g., 'component.name')")
    ss_column: str = Field(description="Smartsheet column title")
    type: str = Field(default="string", description="Field type for conversion")
    writeback: bool = Field(default=False, description="Whether changes sync back to FS")
    transform: str | None = Field(default=None, description="Transform function name")
    primary: bool = Field(default=False, description="Whether this is the primary key")
    options: list[str] | None = Field(default=None, description="Picklist options")


class DataMapper:
    """
    Maps data between Finite State API responses and Smartsheet row format.

    Supports:
    - Nested field extraction (e.g., 'component.name')
    - Type conversions (datetime, boolean, etc.)
    - Transforms (count, join, etc.)
    - Bidirectional mapping for write-back
    """

    def __init__(self, schema: SheetSchema):
        """
        Initialize the mapper with a sheet schema.

        Args:
            schema: SheetSchema defining the field mappings
        """
        self.schema = schema
        self._build_mappings()

    def _build_mappings(self) -> None:
        """Build internal mapping structures."""
        self.fs_to_ss: dict[str, ColumnSchema] = {}
        self.ss_to_fs: dict[str, ColumnSchema] = {}

        for col in self.schema.columns:
            if col.fs_field:
                self.fs_to_ss[col.fs_field] = col
                self.ss_to_fs[col.title] = col

    def fs_to_smartsheet(self, fs_data: dict[str, Any] | BaseModel) -> dict[str, Any]:
        """
        Transform a Finite State record to Smartsheet row format.

        Args:
            fs_data: FS API response data (dict or Pydantic model)

        Returns:
            Dictionary mapping Smartsheet column titles to values
        """
        if isinstance(fs_data, BaseModel):
            fs_data = fs_data.model_dump(by_alias=True)

        row_data: dict[str, Any] = {}

        for col in self.schema.columns:
            if not col.fs_field:
                continue

            # Extract value using dot notation
            value = self._get_nested_value(fs_data, col.fs_field)

            # Apply transform if specified
            if col.transform:
                value = self._apply_transform(value, col.transform)

            # Convert to Smartsheet-compatible type
            value = self._convert_type(value, col)

            # Convert API enum values to human-friendly display values
            if col.fs_field:
                value = api_value_to_display(col.fs_field, value)

            row_data[col.title] = value

        return row_data

    def smartsheet_to_fs(
        self,
        ss_data: dict[str, Any],
        writeback_only: bool = True,
    ) -> dict[str, Any]:
        """
        Transform Smartsheet row data to Finite State format.

        Args:
            ss_data: Smartsheet row data (column title -> value)
            writeback_only: Only include fields marked for write-back

        Returns:
            Dictionary with FS field paths as keys
        """
        fs_data: dict[str, Any] = {}

        for title, value in ss_data.items():
            if title.startswith("_"):
                continue

            col = self.ss_to_fs.get(title)
            if not col or not col.fs_field:
                continue

            if writeback_only and not col.writeback:
                continue

            # Convert value back to FS format
            fs_value = self._convert_to_fs_type(value, col)
            fs_data[col.fs_field] = fs_value

        return fs_data

    def get_primary_key_value(self, fs_data: dict[str, Any] | BaseModel) -> str | None:
        """
        Extract the primary key value from FS data.

        Args:
            fs_data: FS API response data

        Returns:
            Primary key value as string, or None if not found
        """
        if isinstance(fs_data, BaseModel):
            fs_data = fs_data.model_dump(by_alias=True)

        primary_col = self.schema.get_primary_column()
        if not primary_col or not primary_col.fs_field:
            return None

        value = self._get_nested_value(fs_data, primary_col.fs_field)
        return str(value) if value is not None else None

    def get_writeback_fields(self) -> list[str]:
        """Get list of FS field paths that support write-back."""
        return [col.fs_field for col in self.schema.columns if col.writeback and col.fs_field]

    def _get_nested_value(self, data: dict[str, Any], path: str) -> Any:
        """
        Extract a value from nested dict using dot notation.

        Args:
            data: Source dictionary
            path: Dot-separated path (e.g., 'component.name')

        Returns:
            Value at path, or None if not found
        """
        parts = path.split(".")
        current = data

        for part in parts:
            if current is None:
                return None
            if isinstance(current, dict):
                current = current.get(part)  # type: ignore[assignment]
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None

        return current

    def _set_nested_value(self, data: dict[str, Any], path: str, value: Any) -> None:
        """
        Set a value in nested dict using dot notation.

        Args:
            data: Target dictionary (modified in place)
            path: Dot-separated path
            value: Value to set
        """
        parts = path.split(".")
        current = data

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    def _apply_transform(self, value: Any, transform: str) -> Any:
        """
        Apply a named transform to a value.

        Args:
            value: Input value
            transform: Transform name ('count', 'join', 'first', etc.)

        Returns:
            Transformed value
        """
        if value is None:
            return None

        if transform == "count":
            if isinstance(value, (list, tuple)):
                return len(value)
            return 0

        if transform == "join":
            if isinstance(value, (list, tuple)):
                return ", ".join(str(v) for v in value if v)
            return str(value) if value else ""

        if transform == "first":
            if isinstance(value, (list, tuple)) and value:
                return value[0]
            return value

        if transform == "bool":
            return bool(value)

        if transform == "upper":
            return str(value).upper() if value else ""

        if transform == "lower":
            return str(value).lower() if value else ""

        return value

    def _convert_type(self, value: Any, col: ColumnSchema) -> Any:
        """
        Convert a value to the appropriate type for Smartsheet.

        Args:
            value: Input value
            col: Column schema with type information

        Returns:
            Converted value
        """
        if value is None:
            return None

        col_type = col.type.value if hasattr(col.type, "value") else str(col.type)

        if col_type == "CHECKBOX":
            return bool(value)

        if col_type in ("DATE", "DATETIME"):
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, str):
                return value
            return None

        if col_type == "PICKLIST":
            str_value = str(value) if value is not None else ""
            # Validate against options if provided
            if col.options and str_value and str_value not in col.options:
                # Try case-insensitive match
                for opt in col.options:
                    if opt.lower() == str_value.lower():
                        return opt
            return str_value

        if col_type == "TEXT_NUMBER":
            if isinstance(value, (int, float)):
                return value
            if isinstance(value, bool):
                return value
            if isinstance(value, list):
                return ", ".join(str(v) for v in value)
            return str(value) if value is not None else ""

        return str(value) if value is not None else None

    def _convert_to_fs_type(self, value: Any, col: ColumnSchema) -> Any:
        """
        Convert a Smartsheet value back to FS format.

        Args:
            value: Smartsheet cell value
            col: Column schema

        Returns:
            Value in FS format
        """
        if value is None or value == "":
            return None

        col_type = col.type.value if hasattr(col.type, "value") else str(col.type)

        if col_type == "CHECKBOX":
            return bool(value)

        if col_type in ("DATE", "DATETIME"):
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return value
            return value

        return value


def create_mapper_from_config(config: dict[str, Any]) -> DataMapper:
    """
    Create a DataMapper from a configuration dictionary.

    Args:
        config: Configuration dict with 'columns' list

    Returns:
        Configured DataMapper instance
    """
    from ..smartsheet_client.schemas import ColumnType

    columns = []
    for col_config in config.get("columns", []):
        col_type = col_config.get("type", "string").upper()
        if col_type == "STRING":
            col_type = "TEXT_NUMBER"
        elif col_type == "NUMBER":
            col_type = "TEXT_NUMBER"
        elif col_type == "DATETIME":
            col_type = "DATE"  # DATETIME not supported for sheet creation
        elif col_type == "CHECKBOX":
            col_type = "CHECKBOX"
        elif col_type == "PICKLIST":
            col_type = "PICKLIST"
        else:
            col_type = "TEXT_NUMBER"

        columns.append(
            ColumnSchema(
                title=col_config.get("ss_column", ""),
                fs_field=col_config.get("fs_field"),
                type=ColumnType(col_type),
                primary=col_config.get("primary", False),
                writeback=col_config.get("writeback", False),
                transform=col_config.get("transform"),
                options=col_config.get("options"),
            )
        )

    schema = SheetSchema(
        name=config.get("name", "Sheet"),
        fs_endpoint=config.get("fs_endpoint"),
        columns=columns,
    )

    return DataMapper(schema)
