"""
Airgapped AI two-phase workflow.

Phase 1 (Export): ``--ai-export prompts.json`` — generate a JSON file with
prompt ID, system prompt, user prompt, and context for each AI call.

Phase 2 (Import): ``--ai-import responses.json`` — read a JSON file mapping
prompt IDs to AI response text, and inject into the report pipeline.

Export format::

    [
      {
        "id": "tp-portfolio",
        "scope": "portfolio",
        "system_prompt": "...",
        "user_prompt": "...",
        "context": { ... }
      },
      {
        "id": "tp-project-RouterFirmware",
        "scope": "project",
        "system_prompt": "...",
        "user_prompt": "...",
        "context": { "project_name": "Router Firmware" }
      },
      ...
    ]

Import format::

    {
      "tp-portfolio": "AI response text...",
      "tp-project-RouterFirmware": "AI response text...",
      ...
    }
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _safe_id(name: str) -> str:
    """Make a string safe for use as a prompt ID."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", name)


def export_prompts(
    output_path: str,
    *,
    portfolio_prompt: str = "",
    project_prompts: dict[str, str] | None = None,
    component_prompts: dict[str, str] | None = None,
    finding_prompts: list[tuple[str, str]] | None = None,
    system_prompt: str = "",
    metadata: dict[str, Any] | None = None,
) -> str:
    """Export AI prompts to a JSON file for offline processing.

    Args:
        output_path: Path to write the JSON prompts file.
        portfolio_prompt: Portfolio-level prompt text.
        project_prompts: Dict mapping project_name -> prompt text.
        component_prompts: Dict mapping component_key -> prompt text.
        finding_prompts: List of (finding_id, prompt_text) tuples.
        system_prompt: Shared system prompt for all calls.
        metadata: Optional metadata (dates, scope, etc.).

    Returns:
        The path to the written file.
    """
    prompts: list[dict[str, Any]] = []

    if portfolio_prompt:
        prompts.append(
            {
                "id": "tp-portfolio",
                "scope": "portfolio",
                "system_prompt": system_prompt,
                "user_prompt": portfolio_prompt,
                "context": metadata or {},
            }
        )

    for name, prompt in (project_prompts or {}).items():
        prompts.append(
            {
                "id": f"tp-project-{_safe_id(name)}",
                "scope": "project",
                "system_prompt": system_prompt,
                "user_prompt": prompt,
                "context": {"project_name": name},
            }
        )

    for key, prompt in (component_prompts or {}).items():
        prompts.append(
            {
                "id": f"tp-component-{_safe_id(key)}",
                "scope": "component",
                "system_prompt": system_prompt,
                "user_prompt": prompt,
                "context": {"component_key": key},
            }
        )

    for finding_id, prompt in finding_prompts or []:
        prompts.append(
            {
                "id": f"tp-finding-{_safe_id(finding_id)}",
                "scope": "finding",
                "system_prompt": system_prompt,
                "user_prompt": prompt,
                "context": {"finding_id": finding_id},
            }
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(prompts, f, indent=2, ensure_ascii=False)

    logger.info(f"Exported {len(prompts)} AI prompts to {path}")
    return str(path)


def import_responses(import_path: str) -> dict[str, str]:
    """Import AI responses from a JSON file.

    Expected format: ``{ "prompt_id": "response text", ... }``

    Args:
        import_path: Path to the JSON responses file.

    Returns:
        Dict mapping prompt IDs to response text.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not valid JSON or not a dict.
    """
    path = Path(import_path)
    if not path.exists():
        raise FileNotFoundError(f"AI responses file not found: {import_path}")

    with open(path) as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(
            f"AI responses file must be a JSON object (dict), got {type(data).__name__}"
        )

    logger.info(f"Imported {len(data)} AI responses from {path}")
    return {str(k): str(v) for k, v in data.items()}


def resolve_imported_responses(
    responses: dict[str, str],
) -> dict[str, dict[str, str]]:
    """Resolve imported responses into structured data by scope.

    Returns:
        Dict with keys ``portfolio``, ``projects``, ``components``, ``findings``,
        each containing the relevant responses.
    """
    result: dict[str, dict[str, str]] = {
        "portfolio": {},
        "projects": {},
        "components": {},
        "findings": {},
    }

    for prompt_id, response_text in responses.items():
        if prompt_id == "tp-portfolio":
            result["portfolio"]["summary"] = response_text
        elif prompt_id.startswith("tp-project-"):
            project_key = prompt_id[len("tp-project-") :]
            result["projects"][project_key] = response_text
        elif prompt_id.startswith("tp-component-"):
            component_key = prompt_id[len("tp-component-") :]
            result["components"][component_key] = response_text
        elif prompt_id.startswith("tp-finding-"):
            finding_id = prompt_id[len("tp-finding-") :]
            result["findings"][finding_id] = response_text
        else:
            logger.warning(f"Unknown prompt ID format: {prompt_id}")

    return result
