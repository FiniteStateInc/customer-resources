"""Shared truthy-coercion for hand-edited YAML / form booleans.

A leaf module: it imports nothing from ``fs_report``, so the store, the
engine and the web layer can all use it without an import cycle.
"""

from __future__ import annotations

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
