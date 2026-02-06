"""Tool registry for discovering and managing available tools."""

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel

from app.config import get_settings


class ToolParameter(BaseModel):
    """Definition of a tool parameter."""

    name: str
    type: str  # text, select, date, number, file, checkbox, project_select, version_select
    label: str
    required: bool = False
    placeholder: Optional[str] = None
    default: Optional[Any] = None
    options: Optional[list[dict[str, str]]] = None
    options_source: Optional[str] = None  # e.g., 'recipes' for dynamic options
    show_if: Optional[dict[str, str]] = None  # Conditional display
    depends_on: Optional[str] = None  # For version_select: which project_select to depend on
    linked_version: Optional[str] = None  # For project_select: which version_select to trigger


class ToolOutput(BaseModel):
    """Definition of a tool output."""

    type: str  # file, console
    pattern: Optional[str] = None
    label: str


class ToolDefinition(BaseModel):
    """Complete definition of a tool."""

    name: str
    display_name: str
    description: str
    category: str
    source_path: str
    parameters: list[ToolParameter] = []
    command_template: str
    outputs: list[ToolOutput] = []
    supports_ai_recipes: bool = False
    recipe_template_path: Optional[str] = None


class ToolRegistry:
    """Registry of available tools."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._loaded = False

    def _load_tools(self) -> None:
        """Load tool definitions from YAML files."""
        if self._loaded:
            return

        settings = get_settings()
        tools_dir = settings.tools_dir

        if not tools_dir.exists():
            tools_dir.mkdir(parents=True, exist_ok=True)
            return

        for yaml_file in tools_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r") as f:
                    data = yaml.safe_load(f)
                    if data:
                        tool = ToolDefinition(**data)
                        self._tools[tool.name] = tool
            except Exception as e:
                print(f"Error loading tool definition {yaml_file}: {e}")

        self._loaded = True

    def get_all_tools(self) -> list[ToolDefinition]:
        """Get all registered tools."""
        self._load_tools()
        return list(self._tools.values())

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Get a specific tool by name."""
        self._load_tools()
        return self._tools.get(name)

    def get_tools_by_category(self) -> dict[str, list[ToolDefinition]]:
        """Get tools grouped by category."""
        self._load_tools()
        categories: dict[str, list[ToolDefinition]] = {}
        for tool in self._tools.values():
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool)
        return categories

    def get_tool_summary(self) -> str:
        """Get a summary of all tools for AI context."""
        self._load_tools()
        lines = ["Available Tools:"]
        for tool in self._tools.values():
            lines.append(f"\n## {tool.display_name} ({tool.name})")
            lines.append(f"Category: {tool.category}")
            lines.append(f"Description: {tool.description}")
            if tool.parameters:
                lines.append("Parameters:")
                for param in tool.parameters:
                    req = " (required)" if param.required else ""
                    lines.append(f"  - {param.name}: {param.label}{req}")
        return "\n".join(lines)

    def reload(self) -> None:
        """Reload tool definitions."""
        self._tools.clear()
        self._loaded = False
        self._load_tools()


# Global registry instance
_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
