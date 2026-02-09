"""Smartsheet schema definitions."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ColumnType(str, Enum):
    """Smartsheet column types."""

    TEXT_NUMBER = "TEXT_NUMBER"
    DATE = "DATE"  # Use DATE for all date/datetime columns (DATETIME causes API errors)
    CONTACT_LIST = "CONTACT_LIST"
    CHECKBOX = "CHECKBOX"
    PICKLIST = "PICKLIST"
    DURATION = "DURATION"
    PREDECESSOR = "PREDECESSOR"


class ColumnSchema(BaseModel):
    """Schema definition for a Smartsheet column."""

    title: str
    type: ColumnType = ColumnType.TEXT_NUMBER
    primary: bool = False
    options: list[str] | None = None
    width: int = 150
    locked: bool = False

    # Mapping information
    fs_field: str | None = Field(default=None, description="Finite State field path")
    writeback: bool = Field(default=False, description="Whether to sync changes back to FS")
    transform: str | None = Field(default=None, description="Transform to apply (e.g., 'count')")

    def to_smartsheet_column(self) -> dict[str, Any]:
        """Convert to Smartsheet API column definition."""
        col: dict[str, Any] = {
            "title": self.title,
            "type": self.type.value,
            "primary": self.primary,
            "width": self.width,
            "locked": self.locked,
        }
        if self.options and self.type == ColumnType.PICKLIST:
            col["options"] = self.options
        return col


class SheetSchema(BaseModel):
    """Schema definition for a Smartsheet sheet."""

    name: str
    columns: list[ColumnSchema]
    fs_endpoint: str | None = Field(default=None, description="Finite State API endpoint")

    def with_name(self, new_name: str) -> "SheetSchema":
        """Return a copy of this schema with a different name."""
        return self.model_copy(update={"name": new_name})

    def get_primary_column(self) -> ColumnSchema | None:
        """Get the primary column (used as row identifier)."""
        for col in self.columns:
            if col.primary:
                return col
        return None

    def get_writeback_columns(self) -> list[ColumnSchema]:
        """Get columns that support write-back to FS."""
        return [col for col in self.columns if col.writeback]

    def get_column_by_title(self, title: str) -> ColumnSchema | None:
        """Find a column by its title."""
        for col in self.columns:
            if col.title == title:
                return col
        return None

    def get_column_by_fs_field(self, fs_field: str) -> ColumnSchema | None:
        """Find a column by its Finite State field mapping."""
        for col in self.columns:
            if col.fs_field == fs_field:
                return col
        return None

    def to_smartsheet_sheet(self) -> dict[str, Any]:
        """Convert to Smartsheet API sheet definition."""
        return {
            "name": self.name,
            "columns": [col.to_smartsheet_column() for col in self.columns],
        }


# Pre-defined schemas for standard sheets
PROJECTS_SCHEMA = SheetSchema(
    name="FS Projects",
    fs_endpoint="/projects",
    columns=[
        ColumnSchema(title="Project ID", fs_field="id", primary=True),
        ColumnSchema(title="Name", fs_field="name"),
        ColumnSchema(title="Description", fs_field="description"),
        ColumnSchema(title="Created", fs_field="created", type=ColumnType.DATE),
        ColumnSchema(title="Type", fs_field="type"),
        ColumnSchema(title="Created By", fs_field="createdBy"),
        ColumnSchema(title="Findings", fs_field="defaultBranch.latestVersion.findings"),
        ColumnSchema(title="Components", fs_field="defaultBranch.latestVersion.components"),
        ColumnSchema(title="Violations", fs_field="defaultBranch.latestVersion.violations"),
        ColumnSchema(title="Warnings", fs_field="defaultBranch.latestVersion.warnings"),
    ],
)

# VEX Status constants
VEX_STATUSES = [
    "EXPLOITABLE",
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
    "IN_TRIAGE",
    "FALSE_POSITIVE",
    "NOT_AFFECTED",
]

# VEX Response values - Smartsheet display -> API value
VEX_RESPONSES = [
    "Can Not Fix",
    "Will Not Fix",
    "Update",
    "Rollback",
    "Workaround Available",
]

# Mapping from Smartsheet display values to API enum values
VEX_RESPONSE_TO_API = {
    "Can Not Fix": "CAN_NOT_FIX",
    "Will Not Fix": "WILL_NOT_FIX",
    "Update": "UPDATE",
    "Rollback": "ROLLBACK",
    "Workaround Available": "WORKAROUND_AVAILABLE",
}

VEX_JUSTIFICATIONS = [
    "Code Not Present",
    "Code Not Reachable",
    "Requires Configuration",
    "Requires Dependency",
    "Requires Environment",
    "Protected By Compiler",
    "Protected At Runtime",
    "Protected At Perimeter",
    "Protected By Mitigating Control",
]

# Default API values for fields the API requires but aren't semantically needed.
# Workaround for API bug: all statuses require response + justification.
# See Jira ticket for details.
DEFAULT_API_RESPONSE = "WILL_NOT_FIX"
DEFAULT_API_JUSTIFICATION = "CODE_NOT_PRESENT"

# Mapping from Smartsheet display values to API enum values
VEX_JUSTIFICATION_TO_API = {
    "Code Not Present": "CODE_NOT_PRESENT",
    "Code Not Reachable": "CODE_NOT_REACHABLE",
    "Requires Configuration": "REQUIRES_CONFIGURATION",
    "Requires Dependency": "REQUIRES_DEPENDENCY",
    "Requires Environment": "REQUIRES_ENVIRONMENT",
    "Protected By Compiler": "PROTECTED_BY_COMPILER",
    "Protected At Runtime": "PROTECTED_AT_RUNTIME",
    "Protected At Perimeter": "PROTECTED_AT_PERIMETER",
    "Protected By Mitigating Control": "PROTECTED_BY_MITIGATING_CONTROL",
}

# Reverse mappings: API enum values -> Smartsheet display values
API_TO_VEX_RESPONSE = {v: k for k, v in VEX_RESPONSE_TO_API.items()}
API_TO_VEX_JUSTIFICATION = {v: k for k, v in VEX_JUSTIFICATION_TO_API.items()}


def api_value_to_display(field: str, value: str | None) -> str | None:
    """Convert an API enum value to its Smartsheet display value.

    Handles response and justification fields. Returns the value unchanged
    if it's already a display value or not a mapped field.
    """
    if value is None:
        return None
    if field in ("response",):
        return API_TO_VEX_RESPONSE.get(value, value)
    if field in ("justification",):
        return API_TO_VEX_JUSTIFICATION.get(value, value)
    return value


def display_value_to_api(field: str, value: str | None) -> str | None:
    """Convert a Smartsheet display value to its API enum value.

    Accepts both display values and raw API values (passthrough).
    """
    if value is None:
        return None
    if field in ("response",):
        return VEX_RESPONSE_TO_API.get(value, value)
    if field in ("justification",):
        return VEX_JUSTIFICATION_TO_API.get(value, value)
    return value


FINDINGS_SCHEMA = SheetSchema(
    name="FS Findings",
    fs_endpoint="/findings",
    columns=[
        ColumnSchema(title="Finding ID", fs_field="id", primary=True),
        ColumnSchema(title="CVE ID", fs_field="findingId"),
        ColumnSchema(title="Title", fs_field="title", width=300),
        ColumnSchema(title="Severity", fs_field="severity"),
        ColumnSchema(
            title="Status",
            fs_field="status",
            type=ColumnType.PICKLIST,
            options=VEX_STATUSES,
            writeback=True,
        ),
        ColumnSchema(
            title="Response",
            fs_field="response",
            type=ColumnType.PICKLIST,
            options=VEX_RESPONSES,
            writeback=True,
        ),
        ColumnSchema(
            title="Justification",
            fs_field="justification",
            type=ColumnType.PICKLIST,
            options=VEX_JUSTIFICATIONS,
            writeback=True,
        ),
        ColumnSchema(
            title="Reason",
            fs_field="reason",
            type=ColumnType.TEXT_NUMBER,
            writeback=True,
            width=200,
        ),
        ColumnSchema(title="Risk Score", fs_field="risk"),
        ColumnSchema(title="EPSS Score", fs_field="epssScore"),
        ColumnSchema(title="EPSS Percentile", fs_field="epssPercentile"),
        ColumnSchema(title="In KEV", fs_field="inKev", type=ColumnType.CHECKBOX),
        ColumnSchema(title="Component", fs_field="component.name"),
        ColumnSchema(title="Component Version", fs_field="component.version"),
        ColumnSchema(title="Project", fs_field="project.name"),
        ColumnSchema(title="Project Version", fs_field="projectVersion.version"),
        ColumnSchema(title="Detected", fs_field="detected", type=ColumnType.DATE),
        ColumnSchema(title="Attack Vector", fs_field="attackVector"),
        ColumnSchema(title="Finding Type", fs_field="type"),
    ],
)

COMPONENTS_SCHEMA = SheetSchema(
    name="FS Components",
    fs_endpoint="/components",
    columns=[
        ColumnSchema(title="Component ID", fs_field="id", primary=True),
        ColumnSchema(title="Name", fs_field="name", width=300),
        ColumnSchema(title="Component Version", fs_field="version"),
        ColumnSchema(title="Type", fs_field="type"),
        ColumnSchema(title="Supplier", fs_field="supplier"),
        ColumnSchema(title="Declared Licenses", fs_field="declaredLicenses"),
        ColumnSchema(title="Concluded Licenses", fs_field="concludedLicenses"),
        ColumnSchema(title="Findings", fs_field="findings"),
        ColumnSchema(title="Violations", fs_field="violations"),
        ColumnSchema(title="Warnings", fs_field="warnings"),
        ColumnSchema(title="Project", fs_field="project.name"),
        ColumnSchema(title="Project Version", fs_field="projectVersion.version"),
        ColumnSchema(title="Source", fs_field="source", transform="join"),
    ],
)

# Registry of all standard schemas
STANDARD_SCHEMAS = {
    "projects": PROJECTS_SCHEMA,
    "findings": FINDINGS_SCHEMA,
    "components": COMPONENTS_SCHEMA,
}
