"""Canonical MCP-tool metadata constant for the Workflow Builder (Pass 3).

Single source of truth shared by:
- the library UI (``_builder_library.html`` renders the six cards)
- ``runnable_locally`` derivation (``kind == "recipe"`` — MCP steps are always
  export-only)
- the right inspector (editable ``params`` for each MCP-tool step)
- all four exporters (CLI, Forge YAML, GitHub Action, Forge MCP)

Keeping everything here ensures none of those consumers can drift.

This module is **pure** — no FastAPI, no I/O.  It is safe to import at
module-import time from the store, exporters, and routers.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Canonical MCP-tool library — the six tools from the prototype LIB.
#
# Each entry is a dict with keys:
#   id     — the MCP tool id (matches the forge-MCP tool name)
#   title  — display label shown in the UI
#   icon   — lucide icon name
#   params — dict[param_key, param_spec] where each spec has:
#              required (bool, default False)
#              default  (Any, optional — the value materialized into a step's
#                        ``params`` when the key is absent, by the store's
#                        normalizer.  A ``required`` param MAY carry a default:
#                        the default is then the MECHANISM that satisfies the
#                        requirement — normalization fills it so save/run/export
#                        all serialize a concrete value, and validation passes
#                        because the key is now present.  e.g. priority:
#                        {required: True, default: "P0"} and poll: {default: True}.)
#              domain   (list[str], optional — allowed values)
#              type     (type object, optional — for open-ended types)
# ---------------------------------------------------------------------------

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "id": "get_scan_status",
        "title": "Await Scans",
        "icon": "radar",
        "params": {
            "poll": {"required": False, "default": True},
        },
    },
    {
        "id": "get_findings_summary",
        "title": "Findings Summary",
        "icon": "sigma",
        "params": {},
    },
    {
        "id": "get_action_cards_by_priority",
        "title": "Action Cards · P0/P1",
        "icon": "list-checks",
        "params": {
            "priority": {
                "required": True,
                "default": "P0",
                "domain": ["P0", "P1", "P2", "P3"],
            },
        },
    },
    {
        "id": "search_components",
        "title": "Component Search",
        "icon": "search-code",
        "params": {
            "name": {"required": True, "type": str},
        },
    },
    {
        "id": "generate_report",
        "title": "Workflow Summary",
        "icon": "receipt-text",
        "params": {},
    },
    {
        "id": "checkpoint_session",
        "title": "Checkpoint Session",
        "icon": "save",
        "params": {},
    },
]

# Build a lookup dict for O(1) access.
_MCP_BY_ID: dict[str, dict[str, Any]] = {t["id"]: t for t in MCP_TOOLS}


def get_mcp_tool(tool_id: str) -> dict[str, Any] | None:
    """Return the tool metadata dict for *tool_id*, or ``None`` if unknown."""
    return _MCP_BY_ID.get(tool_id)


def fill_mcp_defaults(tool_id: str, params: dict[str, Any]) -> dict[str, Any]:
    """Return *params* with every declared default-carrying key materialized.

    For each param in the tool's canonical spec that declares a ``default`` and
    is absent from *params*, fill it with that default.  This is the single
    mechanism that makes MCP-tool defaults concrete: an inline / hand-authored
    model with ``params: {}`` still serializes ``priority: "P0"`` /
    ``poll: True`` into save, run, and every export, and the requirement on a
    ``required``-with-``default`` param is satisfied because the key becomes
    present.  Required params that declare NO default stay absent (validation
    catches them).  Returns a NEW dict; does not mutate *params*.  Unknown
    ``tool_id`` ⇒ a shallow copy of *params* (nothing to fill).
    """
    tool = _MCP_BY_ID.get(tool_id)
    out = dict(params)
    if tool is None:
        return out
    spec: dict[str, dict[str, Any]] = tool["params"]
    for key, param_spec in spec.items():
        if key not in out and "default" in param_spec:
            out[key] = param_spec["default"]
    return out


def validate_mcp_params(tool_id: str, params: dict[str, Any]) -> list[str]:
    """Validate *params* against the declared spec for *tool_id*.

    Returns a list of human-readable error strings (empty ⇒ valid).

    Rules enforced:
    - Unknown keys → rejected (one error per unknown key).
    - Required keys that are absent or ``None`` → rejected.
    - Domain-constrained keys whose value is not in the declared domain →
      rejected.

    ``tool_id`` must be a known MCP-tool id; if not, a single error is
    returned without inspecting ``params``.
    """
    tool = _MCP_BY_ID.get(tool_id)
    if tool is None:
        return [f"unknown MCP tool id {tool_id!r}"]

    spec: dict[str, dict[str, Any]] = tool["params"]
    errors: list[str] = []

    # Reject unknown keys.
    for key in params:
        if key not in spec:
            errors.append(f"unknown param {key!r} for MCP tool {tool_id!r}")

    # Check required keys and domain constraints.
    for key, param_spec in spec.items():
        value = params.get(key)
        is_required = param_spec.get("required", False)
        param_type = param_spec.get("type")
        # Treat an empty/whitespace-only string as missing for required str params.
        is_blank_str = (
            param_type is str and isinstance(value, str) and not value.strip()
        )
        if is_required and (key not in params or value is None or is_blank_str):
            errors.append(f"required param {key!r} is missing for MCP tool {tool_id!r}")
        if key in params and value is not None and not is_blank_str:
            domain = param_spec.get("domain")
            if domain is not None and value not in domain:
                errors.append(
                    f"param {key!r} value {value!r} for MCP tool {tool_id!r}"
                    f" must be one of {domain!r}"
                )

    return errors
