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

"""Shared YAML serializer for compound and meta-compare (comparison) recipes.

Both the CLI (``fs_report.cli.bundle_cmd`` / ``fs_report.cli.compare_cmd``) and
the future Builder web save-route call these helpers, ensuring the on-disk YAML
is always byte-identical regardless of call site.

Key contracts:

* ``build_compound_yaml_dict`` — emits **no** ``axis`` key (plain compound).
* ``build_comparison_yaml_dict`` — always emits an ``axis`` mapping; with
  default ``left=None, right=None`` the YAML carries
  ``axis: {left: null, right: null}`` matching today's CLI output.
* ``write_compound_yaml`` / ``write_comparison_yaml`` — write with distinct
  header comments (the compare header documents the meta-compare runtime
  contract).
* ``existing_recipe_category`` / ``UNREADABLE_RECIPE`` — the Decision-6
  guard used by ``compare_cmd`` (and the future Builder save-route) to
  classify an on-disk recipe before overwriting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

# Returned by existing_recipe_category when the target file cannot be
# confirmed as a genuine meta-compare (unreadable / corrupt / non-dict /
# parse error). The caller maps this to the "not a readable meta-compare
# recipe" refusal message.
UNREADABLE_RECIPE = "__unreadable__"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _cover_and_formats(
    cover_subtitle: str | None,
    logo: str | None,
    classification: str | None,
    formats: list[str] | None,
) -> tuple[dict, list[str]]:
    """Build the cover dict and materialise the formats list.

    Single source of truth shared by ``build_compound_yaml_dict`` and
    ``build_comparison_yaml_dict`` so the cover schema cannot drift.
    """
    cover: dict = {}
    if cover_subtitle is not None:
        cover["subtitle"] = cover_subtitle
    if logo is not None:
        cover["logo"] = logo
    if classification is not None:
        cover["classification"] = classification
    return cover, formats if formats is not None else ["html", "pdf"]


def _normalize_sections_for_yaml(
    sections: list[str] | list[dict[str, Any]] | list[Any],
) -> list[dict[str, Any]]:
    """Normalize ``sections`` entries to ``{recipe[, overrides]}`` dicts.

    Each entry may be a bare recipe name (string) — back-compat, becomes
    ``{recipe: <name>}`` with NO overrides — or a ``{recipe, overrides?}``
    dict.  An empty / falsy ``overrides`` is OMITTED entirely (no
    ``overrides: null`` noise), keeping the YAML clean + back-compatible.
    """
    out: list[dict[str, Any]] = []
    for s in sections:
        if isinstance(s, dict):
            entry: dict[str, Any] = {"recipe": s.get("recipe", "")}
            overrides = s.get("overrides")
            if overrides:  # non-empty dict only
                entry["overrides"] = overrides
            out.append(entry)
        else:
            out.append({"recipe": s})
    return out


# ---------------------------------------------------------------------------
# Dict builders
# ---------------------------------------------------------------------------


def build_compound_yaml_dict(
    *,
    name: str,
    title: str,
    sections: list[str] | list[dict[str, Any]] | list[Any],
    cover_subtitle: str | None = None,
    logo: str | None = None,
    classification: str | None = None,
    formats: list[str] | None = None,
    toc: bool = True,
    page_numbers: bool = True,
    description: str | None = None,
    nav_category: str | None = None,
    global_block: dict[str, Any] | None = None,
) -> dict:
    """Construct the YAML-serializable dict for a plain CompoundRecipe.

    Emits **no** ``axis`` key — distinguishing it from a meta-compare.
    Defaults reproduce today's CLI output byte-for-byte.

    ``formats`` defaults to ``["html", "pdf"]`` when ``None``; pass
    ``None`` (the default) to get the standard output set. A mutable
    default is intentionally avoided.

    ``sections`` entries may be bare recipe names (string, back-compat) or
    ``{recipe, overrides?}`` dicts; an empty ``overrides`` is omitted so the
    YAML stays clean. ``global_block`` (the authored bundle-wide config) is
    emitted as a ``global:`` key ONLY when non-empty.

    ``description`` / ``nav_category`` (#20) are omitted when falsy so CLI
    output is unchanged; the Builder passes them so authored compounds carry a
    description + nav grouping (fixing the #22 ``nav_category`` warning).
    """
    cover, effective_formats = _cover_and_formats(
        cover_subtitle, logo, classification, formats
    )

    data: dict = {"name": name, "category": "compound", "title": title}
    if description:
        data["description"] = description
    if nav_category:
        data["nav_category"] = nav_category
    if global_block:  # non-empty only — omit the key entirely otherwise
        data["global"] = global_block
    data["sections"] = _normalize_sections_for_yaml(sections)
    data["output"] = {
        "formats": effective_formats,
        "toc": toc,
        "page_numbers": page_numbers,
    }
    if cover:
        data["cover"] = cover
    return data


def build_comparison_yaml_dict(
    *,
    name: str,
    title: str,
    sections: list[str] | list[dict[str, Any]] | list[Any],
    left: str | None = None,
    right: str | None = None,
    cover_subtitle: str | None = None,
    logo: str | None = None,
    classification: str | None = None,
    formats: list[str] | None = None,
    toc: bool = True,
    page_numbers: bool = True,
    description: str | None = None,
    nav_category: str | None = None,
) -> dict:
    """Construct the YAML-serializable dict for a meta-compare CompoundRecipe.

    Always emits an ``axis`` mapping.  With the defaults (``left=None``,
    ``right=None``) the YAML carries ``axis: {left: null, right: null}``,
    reproducing the CLI's behaviour.  The Builder passes resolved scope-ref
    strings when pinning defaults.

    Spec § 6 shape: an axis-bearing compound with nulls marks this compound
    as a meta-compare while leaving the scope refs unpinned — runtime
    ``--left`` / ``--right`` are required when invoking via ``fs-report run``.
    A user may pin a default by hand-editing ``axis.left`` / ``axis.right``.

    Scope refs are intentionally NOT persisted by the CLI (the resolved
    ``--left`` / ``--right`` values are runtime-only).
    """
    cover, effective_formats = _cover_and_formats(
        cover_subtitle, logo, classification, formats
    )

    data: dict = {"name": name, "category": "compound", "title": title}
    if description:
        data["description"] = description
    if nav_category:
        data["nav_category"] = nav_category
    # axis block (spec § 6) — nulls by default; caller may pass resolved
    # scope-ref strings to pin defaults.
    data["axis"] = {"left": left, "right": right}
    # Route through the shared section normalizer so the on-disk section shape
    # matches the compound path. Comparison callers pass canonical name strings
    # (no per-section overrides today), so this is a no-op for them — but it
    # keeps a single section-shape source of truth.
    data["sections"] = _normalize_sections_for_yaml(sections)
    data["output"] = {
        "formats": effective_formats,
        "toc": toc,
        "page_numbers": page_numbers,
    }
    if cover:
        data["cover"] = cover
    return data


# ---------------------------------------------------------------------------
# YAML writers
# ---------------------------------------------------------------------------


def write_compound_yaml(target_path: Path, data: dict) -> None:
    """Write a plain-compound YAML with stable key ordering + header comment.

    The header comment makes the file human-readable + diff-friendly when
    checked into a team-shared recipes dir.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Compound recipe generated by `fs-report bundle --save-as`.\n"
        "# Generated YAML is human-readable + human-editable.\n"
        "# Scope flags (project/folder/period/...) are NOT persisted —\n"
        f"# pass them at run time: fs-report run --recipe \"{data['name']}\" ...\n"
        "#\n"
    )
    body = yaml.safe_dump(
        data, sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    target_path.write_text(header + body, encoding="utf-8")


def write_comparison_yaml(target_path: Path, data: dict) -> None:
    """Write a meta-compare YAML with a compare-specific header comment.

    The header documents the meta-compare contract (spec § 6): scope refs
    are NOT persisted — runtime ``--left`` / ``--right`` are required — and
    a default can be pinned by hand-editing ``axis.left`` / ``axis.right``.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Meta-compare recipe generated by `fs-report compare --save-as`.\n"
        "# Generated YAML is human-readable + human-editable.\n"
        "# The `axis:` block marks this as a meta-compare bundle. Scope refs\n"
        "# are NOT persisted — pass them at run time:\n"
        f"#   fs-report run --recipe \"{data['name']}\" "
        "--left <scope> --right <scope>\n"
        "# To pin default scopes, hand-edit axis.left / axis.right below\n"
        "# (e.g. axis.left: 'project:BN85@v3'); runtime --left/--right still\n"
        "# override any pinned value.\n"
        "#\n"
    )
    body = yaml.safe_dump(
        data, sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    target_path.write_text(header + body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Overwrite guard
# ---------------------------------------------------------------------------


def existing_recipe_category(target_path: Path) -> str | None:
    """Classify an existing on-disk recipe for the --overwrite guard (M1-5).

    Returns ``None`` ONLY when the existing file is a confirmed meta-compare:
    a YAML dict with ``category == "compound"`` AND a NON-NULL ``axis``
    mapping — those may be overwritten.  M1-8: ``axis: null`` (or missing)
    deserializes to ``CompoundRecipe.axis=None``, which the loader/runtime
    treat as a PLAIN (non-meta) compound — so this gate must NOT treat
    ``axis: null`` as an overwritable meta-compare.  Only a present, non-null
    ``axis`` (a dict/mapping such as ``{}`` or ``{left: null, right: null}``)
    marks the meta-compare, matching runtime: ``axis: {}`` both-unpinned IS
    a meta-compare; ``axis: null`` is NOT.

    Everything else REFUSES the overwrite (safer — M1-4/M3-2):

    * a readable non-meta-compare recipe (including ``axis: null``) → returns
      its category label (or ``"non-meta-compare"``), so the caller names
      what it would clobber;
    * an unreadable / corrupt / non-dict / parse-error file → returns the
      :data:`UNREADABLE_RECIPE` sentinel so the caller refuses with a "not a
      readable meta-compare recipe" message.  A corrupt file is NOT silently
      overwritten — refusing protects against destroying a hand-edited recipe
      that merely failed to parse.
    """
    try:
        existing = yaml.safe_load(target_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return UNREADABLE_RECIPE
    if not isinstance(existing, dict):
        return UNREADABLE_RECIPE
    category = existing.get("category")
    category_str = category.strip() if isinstance(category, str) else ""
    # Confirmed meta-compare: compound category AND a NON-NULL axis mapping.
    # ``axis: null`` (CompoundRecipe.axis=None at runtime) is a plain compound,
    # not a meta-compare — only a present, non-null axis dict qualifies.  Only
    # then is the overwrite permitted.
    if category_str == "compound" and isinstance(existing.get("axis"), dict):
        return None
    # A readable but non-meta-compare recipe → name its category so the refusal
    # message tells the user exactly what they'd destroy.
    if category_str:
        return category_str
    return "non-meta-compare"
