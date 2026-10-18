"""``--include-versions`` / ``--exclude-versions``: version-name glob filtering.

Matching mirrors the ``--project`` glob (``ReportEngine._resolve_project_glob``):
a case-insensitive ``fnmatch`` against the WHOLE version name, so a pattern
with no wildcard is an exact (case-insensitive) match — ``checkpoint`` matches
only a version literally named "checkpoint"; ``*checkpoint*`` is the substring
form. Include patterns are OR'd; a version must match one of them when any are
given. Exclude patterns are OR'd and always win over include.

Explicit single-version targets (``--version``, ``--baseline-version`` /
``--current-version``, compare ``@version``) are never filtered: callers apply
this only where a report covers more than one version.

No helper mutates its input. Version lists are shared with explicit-target
resolution and persisted in the SQLite cache, so filtering one in place would
leak this run's filter into lookups (and runs) that must not see it. An ACTIVE
filter always returns new lists; ``filter_records`` hands an inactive filter's
input straight back, so treat every result as read-only.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any


def _clean(patterns: Iterable[str] | None) -> tuple[str, ...]:
    return tuple(p.strip() for p in (patterns or ()) if p and p.strip())


@dataclass(frozen=True)
class VersionNameFilter:
    """Include/exclude glob sets over version names. Empty = inactive."""

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "include", _clean(self.include))
        object.__setattr__(self, "exclude", _clean(self.exclude))

    @classmethod
    def from_config(cls, config: Any) -> VersionNameFilter:
        return cls(
            include=tuple(getattr(config, "include_versions", None) or ()),
            exclude=tuple(getattr(config, "exclude_versions", None) or ()),
        )

    @property
    def active(self) -> bool:
        return bool(self.include or self.exclude)

    def allows(self, name: str | None) -> bool:
        # Lowercase both sides and use fnmatchcase so the result does not
        # depend on the platform's normcase (fnmatch is case-insensitive on
        # Windows only).
        lowered = (name or "").lower()
        if self.include and not any(
            fnmatchcase(lowered, p.lower()) for p in self.include
        ):
            return False
        return not any(fnmatchcase(lowered, p.lower()) for p in self.exclude)

    def excluded_by_pattern(self, name: str | None) -> bool:
        """True when an EXCLUDE pattern matches ``name`` (include ignored)."""
        lowered = (name or "").lower()
        return any(fnmatchcase(lowered, p.lower()) for p in self.exclude)

    def label(self) -> str:
        """Display string for report disclosure; empty when inactive."""
        parts: list[str] = []
        if self.include:
            parts.append("include " + ", ".join(self.include))
        if self.exclude:
            parts.append("exclude " + ", ".join(self.exclude))
        return " · ".join(parts)


def split_patterns(value: str | Iterable[str] | object | None) -> list[str] | None:
    """Comma-separated pattern text (web form / workflow YAML) -> pattern list.

    The web carries multi-value fields as comma-joined text. A comma inside a
    ``[...]`` character class belongs to the pattern, so it is not a
    separator. A list (hand-edited YAML) passes through cleaned. Blank -> None.
    """
    if value is None:
        return None
    if isinstance(value, str):
        parts: list[str] = []
        start = i = 0
        n = len(value)
        while i < n:
            ch = value[i]
            if ch == "[":
                # fnmatch.translate's class rule: an optional "!", then a "]"
                # that is the first member is literal; the class closes at the
                # next "]". No close at all -> the "[" itself is a literal.
                j = i + 1
                if j < n and value[j] == "!":
                    j += 1
                if j < n and value[j] == "]":
                    j += 1
                while j < n and value[j] != "]":
                    j += 1
                i = j + 1 if j < n else i + 1
                continue
            if ch == ",":
                parts.append(value[start:i])
                start = i + 1
            i += 1
        parts.append(value[start:])
    elif isinstance(value, Iterable):
        parts = [str(p) for p in value]
    else:
        # A non-string scalar (e.g. a number in a JSON bridge payload) is one
        # pattern, not a crash inside the run thread.
        parts = [str(value)]
    cleaned = [p.strip() for p in parts if p and p.strip()]
    return cleaned or None


@dataclass
class FilterStats:
    """What the filter did to ONE recipe's data, for its end-of-recipe report.

    ``projects_emptied`` names projects that had two or more versions before
    the filter and fewer after it — the case where a multi-version report has
    nothing left to compare because of the filter, not because of the data.
    """

    rows_seen: int = 0
    rows_dropped: int = 0
    unnamed_rows: int = 0
    versions_seen: int = 0
    versions_dropped: int = 0
    exclude_hits: int = 0
    projects_emptied: list[str] = field(default_factory=list)


def version_entry_name(version: dict[str, Any]) -> str | None:
    """Name of a ``/projects/{id}/versions`` (or ``/versions``) entry."""
    name = version.get("version") or version.get("name")
    return str(name) if name else None


def record_version_name(record: dict[str, Any]) -> str | None:
    """Version name carried by a finding / component / scan record."""
    pv = record.get("projectVersion")
    if isinstance(pv, dict):
        name = pv.get("version") or pv.get("name")
    else:
        name = record.get("projectVersion.version")
    return str(name) if name else None


def filter_versions(
    versions: Sequence[dict[str, Any]], flt: VersionNameFilter
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split version-list entries into ``(kept, dropped)`` new lists."""
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for v in versions:
        (kept if flt.allows(version_entry_name(v)) else dropped).append(v)
    return kept, dropped


def filter_records(
    records: list[dict[str, Any]], flt: VersionNameFilter
) -> tuple[list[dict[str, Any]], set[str]]:
    """Drop records from disallowed versions.

    Returns ``(kept, dropped_version_names)``. An inactive filter returns the
    input list itself (no copy) so the hot fetch paths pay nothing when the
    flags are unset.
    """
    if not flt.active:
        return records, set()
    kept: list[dict[str, Any]] = []
    dropped: set[str] = set()
    for rec in records:
        name = record_version_name(rec)
        if flt.allows(name):
            kept.append(rec)
        else:
            dropped.add(name or "")
    return kept, dropped
