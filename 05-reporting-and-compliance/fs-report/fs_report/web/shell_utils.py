"""Shared shell-quoting utilities for fs-report web serializers.

Extracted from ``workflow_export`` and ``routers.command_center`` so both
modules share a single implementation.
"""

from __future__ import annotations

import re


def _strip_control_chars(value: str) -> str:
    """Replace C0 control characters and DEL with spaces."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", value)


def shquote(value: str) -> str:
    """Shell-quote *value* using double quotes (POSIX-safe).

    - Strips control characters so newlines can't break the single-line command.
    - Wraps in double quotes.
    - Backslash-escapes ``"`` ``\\`` ``$`` `` ` `` (chars double-quoting
      doesn't neutralise).
    """
    escaped = (
        _strip_control_chars(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
    )
    return f'"{escaped}"'
