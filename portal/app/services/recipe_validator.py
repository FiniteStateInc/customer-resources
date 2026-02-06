"""Recipe validation service."""

from typing import Any

import yaml


# Required fields in a recipe
REQUIRED_FIELDS = ["name", "query", "output"]

# Valid API endpoints
VALID_ENDPOINTS = [
    "/public/v0/findings",
    "/public/v0/components",
    "/public/v0/projects",
    "/public/v0/scans",
    "/public/v0/audit",
]

# Valid chart types
VALID_CHART_TYPES = ["bar", "line", "pie", "scatter"]

# Valid output formats
VALID_OUTPUT_FORMATS = ["csv", "xlsx", "html"]


def validate_recipe(yaml_content: str) -> tuple[bool, list[str]]:
    """
    Validate a YAML recipe against the schema.

    Returns (is_valid, list_of_errors)
    """
    errors = []

    # Parse YAML
    try:
        recipe = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return False, [f"Invalid YAML syntax: {str(e)}"]

    if not isinstance(recipe, dict):
        return False, ["Recipe must be a YAML dictionary"]

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in recipe:
            errors.append(f"Missing required field: {field}")

    # Validate name
    if "name" in recipe:
        if not isinstance(recipe["name"], str) or not recipe["name"].strip():
            errors.append("'name' must be a non-empty string")

    # Validate query section
    if "query" in recipe:
        query = recipe["query"]
        if not isinstance(query, dict):
            errors.append("'query' must be a dictionary")
        else:
            # Check endpoint
            if "endpoint" not in query:
                errors.append("'query.endpoint' is required")
            elif query["endpoint"] not in VALID_ENDPOINTS:
                errors.append(f"Invalid endpoint. Must be one of: {', '.join(VALID_ENDPOINTS)}")

    # Validate transform section (optional)
    if "transform" in recipe:
        transform = recipe["transform"]
        if not isinstance(transform, list):
            errors.append("'transform' must be a list of operations")

    # Validate output section
    if "output" in recipe:
        output = recipe["output"]
        if not isinstance(output, dict):
            errors.append("'output' must be a dictionary")
        else:
            # Validate formats
            if "formats" in output:
                formats = output["formats"]
                if not isinstance(formats, list):
                    errors.append("'output.formats' must be a list")
                else:
                    for fmt in formats:
                        if fmt not in VALID_OUTPUT_FORMATS:
                            errors.append(f"Invalid format '{fmt}'. Must be one of: {', '.join(VALID_OUTPUT_FORMATS)}")

            # Validate chart type
            if "chart" in output:
                if output["chart"] not in VALID_CHART_TYPES:
                    errors.append(f"Invalid chart type. Must be one of: {', '.join(VALID_CHART_TYPES)}")

            # Validate charts array
            if "charts" in output:
                charts = output["charts"]
                if not isinstance(charts, list):
                    errors.append("'output.charts' must be a list")
                else:
                    for i, chart in enumerate(charts):
                        if not isinstance(chart, dict):
                            errors.append(f"Chart {i} must be a dictionary")
                        elif "chart" in chart and chart["chart"] not in VALID_CHART_TYPES:
                            errors.append(f"Invalid chart type in chart {i}")

    return len(errors) == 0, errors


def parse_recipe(yaml_content: str) -> dict[str, Any]:
    """Parse YAML content into a dictionary."""
    return yaml.safe_load(yaml_content)


def format_recipe(recipe: dict[str, Any]) -> str:
    """Format a recipe dictionary as YAML."""
    return yaml.dump(recipe, default_flow_style=False, sort_keys=False)
