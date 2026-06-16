# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""scope_ref — pure string parsing for scope references.

A scope reference identifies what to fetch data for.  Supported grammar::

    project:<target>[@<version>]   # specific project, optional version
    folder:<target>                # folder tree (recursive), latest versions
    <target>[@<version>]           # bare form — always inferred as project:

All parsing is pure string manipulation — no I/O, no engine imports, no
name→ID resolution (that is a later stage, B3.6).

See docs/superpowers/specs/2026-05-11-meta-compare-design.md § 1.

Raises
------
ScopeRefError
    A subclass of ``ValueError``.  Raised on any ill-formed input such as
    an empty target, a ``folder:`` form with a ``@version`` suffix, an
    ``@version`` token with no leading target, or a trailing ``@`` with an
    empty version (e.g. ``project:X@``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


class ScopeRefError(ValueError):
    """Raised when a scope-reference string cannot be parsed.

    Inherits from ``ValueError`` so callers that catch ``ValueError`` pick
    it up without changes.
    """


@dataclass(frozen=True)
class ScopeRef:
    """A parsed scope reference.

    Attributes
    ----------
    kind:
        ``"project"`` or ``"folder"``.
    target:
        The project/folder name or ID.  Opaque string — no resolution.
    version:
        Version name or ID when a ``@<version>`` suffix was present;
        ``None`` otherwise.  Always ``None`` for ``kind="folder"`` (folders
        have no version concept; a ``folder:X@v`` input raises
        ``ScopeRefError`` at parse time).
    """

    kind: Literal["project", "folder"]
    target: str
    version: str | None


@dataclass(frozen=True)
class ResolvedScope:
    """A fully-resolved scope — the output of ``ReportEngine._resolve_scope``.

    This is pure data: no I/O, no engine imports.  The engine produces it
    after authentication by resolving a :class:`ScopeRef` against the API
    (project/version/folder lookups), and the comparison dispatch path
    consumes it to fetch per-version data.

    See docs/superpowers/specs/2026-05-11-meta-compare-design.md § 1
    (resolve stage), § 4, decision #6 (provenance).

    Attributes
    ----------
    label:
        Human-readable scope label echoed in the cover metadata grid and
        passed to comparison transforms as ``left_label`` / ``right_label``.
        Examples: ``"BN85 @ v3.2.1"``, ``"folder Router-Family-EU (4 projects)"``.
    version_ids:
        The resolved project-version IDs to fetch data for.  One entry for a
        single-project scope; one-per-project for a folder scope.
    project_names:
        Mapping of ``version_id -> project display name``.  Used to backfill
        a ``project_name`` provenance column on returned rows (decision #6).
    version_displays:
        Mapping of ``version_id -> version display name`` (e.g. ``"v3.2.1"``).
        Resolved during the resolve stage so the components fetch path can
        backfill ``projectVersion.version`` with the *version* display name
        (not the project name) on rows from the version-scoped endpoint,
        which omits ``projectVersion``.  May be empty / partial; callers
        fall back to ``str(version_id)`` for any missing entry.
    """

    label: str
    version_ids: list[str]
    project_names: dict[str, str]
    version_displays: dict[str, str] = field(default_factory=dict)


def parse(text: str) -> ScopeRef:
    """Parse *text* into a :class:`ScopeRef`.

    Parameters
    ----------
    text:
        A scope-reference string in one of the supported grammar forms.

    Returns
    -------
    ScopeRef
        A frozen dataclass carrying ``kind``, ``target``, and ``version``.

    Raises
    ------
    ScopeRefError
        On malformed input — empty string, whitespace-only, empty target,
        ``folder:X@v`` / ``folder:X@`` form, ``@version`` with no target, or a
        trailing ``@`` with an empty version (e.g. ``project:X@``, ``X@``).
    """
    if not text or not text.strip():
        raise ScopeRefError("Scope reference must not be empty or whitespace-only")

    text = text.strip()

    # Determine kind and strip prefix.
    if text.startswith("project:"):
        kind: Literal["project", "folder"] = "project"
        rest = text[len("project:") :]
    elif text.startswith("folder:"):
        kind = "folder"
        rest = text[len("folder:") :]
    else:
        # Bare form — always a project.
        kind = "project"
        rest = text

    # Split version suffix on the FIRST '@'.  We use the first occurrence (not
    # the last) because versions may themselves contain '@' (e.g. git SHAs or
    # semver build metadata).  A single bare '@' at position 0 (e.g. "@v1")
    # produces an empty target, which we catch below.
    if "@" in rest:
        at_idx = rest.index("@")
        raw_target = rest[:at_idx]
        raw_version = rest[at_idx + 1 :]
    else:
        raw_target = rest
        raw_version = None

    # Validate target.
    target = raw_target.strip()
    if not target:
        if raw_version is not None:
            raise ScopeRefError(
                f"Scope reference has a version (@{raw_version!r}) but no target; "
                "expected <target>@<version>"
            )
        raise ScopeRefError(
            f"Scope reference {text!r} has an empty target after the "
            f"'{kind}:' prefix"
        )

    # Validate version.
    if raw_version is not None:
        # Folders must not carry a version (checked before the empty-version
        # check so ``folder:X@`` keeps surfacing the folder-specific error).
        if kind == "folder":
            raise ScopeRefError(
                f"Folder scope references do not support a version suffix; "
                f"got folder:{target!r}@{raw_version!r}. "
                "Remove the '@...' part or use project: instead."
            )
        version: str | None = raw_version.strip() or None
        # An '@' with no version after it (e.g. ``project:X@`` or ``X@``) is a
        # malformed reference — reject it rather than silently treating it as a
        # bare project with no version (PR review E).
        if version is None:
            raise ScopeRefError(f"empty version after '@' in scope reference {text!r}")
    else:
        version = None

    return ScopeRef(kind=kind, target=target, version=version)
