"""Shared value coercion: YAML / form booleans and platform licence fields.

A leaf module: it imports nothing from ``fs_report``, so the store, the
engine and the web layer can all use it without an import cycle.
"""

from __future__ import annotations

import math
from typing import Any


def coerce_bool(value: Any) -> bool:
    """Coerce *value* to a real bool using the run path's truthy semantics.

    A value is True only if it is already ``True`` (a real bool) or its string
    form (stripped, lowercased) is one of ``"true"`` / ``"on"`` / ``"1"`` /
    ``"yes"``.  Everything else — including the strings ``"false"`` / ``"0"`` /
    ``"no"`` — is False (never the truthy ``bool("false")``).

    This single shared helper is the home for the coercion the run path
    (``run._coerce_touched_flag``), the export path
    (``workflow_export._coerce_bool``), and the ``target_agnostic`` strip
    (``workflow_store`` + those modules) all use, so a hand-edited / inline
    YAML string boolean such as ``"false"`` is read consistently everywhere.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "on", "1", "yes")


def coerce_license_value(val: Any) -> str:
    """Normalise a license field value into a comma-joined SPDX string.

    Handles four real-world shapes returned by /public/v0/components:
      - plain string ("Sleepycat", "MIT OR Apache-2.0")
      - list of strings (["MIT", "Apache-2.0"])
      - list of dicts with `spdx` / `license` / `name` keys
        (e.g. [{"spdx": "Sleepycat", "name": "Sleepycat License"}])
      - None / NaN / non-iterable scalars → ""
    """
    if val is None:
        return ""
    if isinstance(val, float):
        if math.isnan(val):
            return ""
        return str(val).strip()
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, list):
        parts: list[str] = []
        for item in val:
            if isinstance(item, str):
                if item.strip():
                    parts.append(item.strip())
            elif isinstance(item, dict):
                # Match the precedence used by component_list.extract_licenses_summary
                # plus a `name` fallback for the {"name": "Sleepycat"} shape.
                spdx = item.get("spdx") or item.get("license") or item.get("name") or ""
                if isinstance(spdx, str) and spdx.strip():
                    parts.append(spdx.strip())
        return ", ".join(parts)
    return str(val).strip()
