"""Builder recipe CRUD router — compound + comparison docs.

Endpoints
---------
GET    /api/builder/recipes          → list user compound/comparison docs
GET    /api/builder/recipes/{slug}   → load a user doc for the editor
POST   /api/builder/recipes          → save (create or overwrite) a doc
DELETE /api/builder/recipes/{slug}   → delete a user doc

This router is SEPARATE from ``GET /api/recipes`` (recipes.py), which
returns all recipe metadata for launcher consumers and is left untouched.

Decision-6 collision guard:
* Bundled-name collision → always 409.
* User-file kind-aware guard: a compound save may overwrite an existing
  plain compound, but refuses to clobber a comparison (and vice-versa).

Taxonomy: the single discriminator is ``axis`` presence in the YAML.
* Comparison doc  = CompoundRecipe with a present, non-null ``axis`` mapping.
* Compound doc    = CompoundRecipe with no ``axis`` key (axis is None/absent).
* Comparison facet recipe (``category: comparison``) is a building block —
  never listed or opened here.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Generator
from pathlib import Path

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from fs_report.paths import get_user_recipes_dir
from fs_report.recipe_loader import RecipeLoader
from fs_report.recipe_serializer import (
    UNREADABLE_RECIPE,
    build_comparison_yaml_dict,
    build_compound_yaml_dict,
    existing_recipe_category,
    write_comparison_yaml,
    write_compound_yaml,
)
from fs_report.slug import slug as _slug

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/builder", tags=["builder-recipes"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_yaml_as_doc(path: Path) -> dict | None:
    """Read a YAML file; return the dict or ``None`` if unreadable / non-dict."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None


@functools.cache
def _bundled_slugs() -> set[str]:
    """Return the set of slugs for all bundled recipes.

    Bundled recipes are immutable package data, so the result is cached
    permanently via ``lru_cache``.  The defensive ``except`` is preserved
    for environments where the package data is missing or corrupt.
    """
    try:
        recipes = RecipeLoader(use_bundled=True, scan_user_recipes=False).load_recipes()
        return {_slug(r.name) for r in recipes}
    except Exception:  # pragma: no cover — defensive
        return set()


def _iter_user_recipe_files(
    recipes_dir: Path,
) -> Generator[tuple[Path, dict], None, None]:
    """Yield (path, data) for every readable YAML in ``recipes_dir``."""
    if not recipes_dir.exists():
        return
    for path in sorted(recipes_dir.glob("*.yaml")):
        if not path.is_file():
            continue
        data = _read_yaml_as_doc(path)
        if data is None:
            continue
        yield path, data


def _doc_kind(data: dict) -> str:
    """Derive editor kind from data: 'comparison' if axis is a dict, else 'compound'."""
    axis = data.get("axis")
    return "comparison" if isinstance(axis, dict) else "compound"


# #20 (B6): the allowed nav_category values (matches models.Recipe.nav_category).
_NAV_CATEGORIES = (
    "Executive",
    "Investigation",
    "Remediation",
    "Compliance",
    "Exploitability Evidence",
)
# Keyed by ``.lower()`` (no hyphenation): this map is consumed ONLY by
# ``_canon_nav_category`` to validate / canonicalize an incoming display-name
# value back to its exact casing — it never builds a slug/token — so a
# space-containing key ("exploitability evidence") is correct and harmless here.
_NAV_BY_LOWER = {c.lower(): c for c in _NAV_CATEGORIES}


def _canon_nav_category(raw: object) -> str | None:
    """Canonicalize *raw* to its exact-cased nav_category (case-insensitive
    match against the allowed values).

    Empty / ``None`` → the default ``"Executive"``.  Returns ``None`` for an
    unrecognized value (a non-string or an unknown label) so the save path can
    reject it while the load path can fall back to the default.
    """
    if raw is None:
        return "Executive"
    if not isinstance(raw, str):
        return None
    key = raw.strip().lower()
    if not key:
        return "Executive"
    return _NAV_BY_LOWER.get(key)


def _overwrite_refusal(kind: str, existing_cat: str | None) -> str | None:
    """Return a refusal message if a ``kind`` save may NOT overwrite an existing
    user recipe classified as ``existing_cat`` (per ``existing_recipe_category``),
    or ``None`` if the overwrite is permitted.

    Decision-6: a compound save overwrites ONLY a plain compound
    (``existing_cat == "compound"``); a comparison save overwrites ONLY a
    confirmed meta-compare (``existing_cat is None``).  Anything else is
    refused.

    ``existing_cat`` semantics (from ``existing_recipe_category``):
    * ``None``              — confirmed meta-compare (axis is a dict)
    * ``"compound"``        — plain compound (no axis key, or axis is null)
    * any other string      — some other recipe category
    * ``UNREADABLE_RECIPE`` — file could not be parsed
    """
    if kind == "compound" and existing_cat != "compound":
        what = (
            "a meta-compare (comparison) recipe"
            if existing_cat is None
            else (
                f"an existing {existing_cat!r} recipe"
                if existing_cat != UNREADABLE_RECIPE
                else "an unreadable recipe file"
            )
        )
        return (
            f"it is {what}. Use a different name or delete the existing recipe first."
        )
    if kind == "comparison" and existing_cat is not None:
        what = (
            f"an existing {existing_cat!r} recipe"
            if existing_cat != UNREADABLE_RECIPE
            else "an unreadable recipe file"
        )
        return (
            f"it is {what}. Use a different name or delete the existing recipe first."
        )
    return None


# ---------------------------------------------------------------------------
# GET /api/builder/recipes — list
# ---------------------------------------------------------------------------


@router.get("/recipes")
async def list_builder_recipes() -> JSONResponse:
    """Return a list of user compound and comparison docs for the Builder.

    Only returns ``category: compound`` documents. Excludes ``category: comparison``
    facet recipes and any other category. Skips unreadable files silently.
    Returns ``[]`` if the dir doesn't exist.
    """
    recipes_dir = get_user_recipes_dir()
    items: list[dict] = []
    for _path, data in _iter_user_recipe_files(recipes_dir):
        cat = data.get("category")
        if not isinstance(cat, str) or cat.strip() != "compound":
            continue
        name = data.get("name")
        if name is None:
            # GET/DELETE match on the YAML `name` (slug(name) == recipe_slug);
            # a doc without one cannot be opened or deleted through those
            # endpoints, so don't surface a phantom picker entry that 404s.
            # The Builder always writes `name`, so this only skips malformed /
            # hand-authored files.
            continue
        kind = _doc_kind(data)
        title = data.get("title") or name
        items.append(
            {
                "name": name,
                "slug": _slug(str(name)),
                "kind": kind,
                "title": title,
            }
        )
    return JSONResponse(items)


# ---------------------------------------------------------------------------
# GET /api/builder/recipes/{slug} — load
# ---------------------------------------------------------------------------


@router.get("/recipes/{recipe_slug}")
async def get_builder_recipe(recipe_slug: str) -> JSONResponse:
    """Load a user compound or comparison doc for the editor.

    Matches on ``slug(name)`` of the YAML's ``name`` field.  Returns 404 if:
    * No matching file is found.
    * The file is not a ``category: compound`` doc.
    * The recipe only exists as a bundled recipe (user docs only here).

    Returns the doc as JSON with at minimum:
    ``{name, slug, kind, title, sections, axis, output, cover}``.
    """
    recipes_dir = get_user_recipes_dir()
    matched_data: dict | None = None

    for _path, data in _iter_user_recipe_files(recipes_dir):
        name = data.get("name")
        if name is not None and _slug(str(name)) == recipe_slug:
            matched_data = data
            break

    if matched_data is None:
        return JSONResponse(
            {"error": f"Recipe not found: {recipe_slug!r}"},
            status_code=404,
        )

    cat = matched_data.get("category")
    if not isinstance(cat, str) or cat.strip() != "compound":
        return JSONResponse(
            {"error": f"Recipe not found: {recipe_slug!r}"},
            status_code=404,
        )

    name = matched_data.get("name") or recipe_slug
    kind = _doc_kind(matched_data)
    title = matched_data.get("title") or name

    # Normalise sections.
    #
    # Compound sections are returned as ``{recipe, overrides}`` OBJECTS so saved
    # per-section overrides survive a load→edit→save round-trip (a bare-string
    # section migrates to ``{recipe}`` on read; an absent/empty overrides comes
    # back as ``{recipe}`` with no overrides key). The save serializer,
    # validation, and this load response all agree on the object shape.
    #
    # Comparison sections stay a list[str] of SLUGS: the facet rail keys its
    # checkboxes by SLUG (builder.html `model.sections.indexOf('{{ r.slug }}')`),
    # but a CLI-authored meta-compare (`compare --save-as`) persists canonical
    # recipe NAMES — slug-normalize so the editor's :checked bindings match.
    raw_sections = matched_data.get("sections") or []
    sections: list  # list[dict] for compound, list[str] for comparison
    if kind == "comparison":
        _names: list[str] = []
        for s in raw_sections:
            if isinstance(s, dict):
                _names.append(str(s.get("recipe", "")))
            elif isinstance(s, str):
                _names.append(s)
        sections = [_slug(s) for s in _names if s]
    else:
        _objs: list[dict] = []
        for s in raw_sections:
            if isinstance(s, dict):
                _ref = str(s.get("recipe", ""))
                _ov = s.get("overrides")
                _entry: dict = {"recipe": _ref}
                if isinstance(_ov, dict) and _ov:
                    _entry["overrides"] = _ov
                _objs.append(_entry)
            elif isinstance(s, str):
                # Bare-string section → migrate to {recipe} on read.
                _objs.append({"recipe": s})
        sections = _objs

    axis = matched_data.get("axis")  # dict or None
    output = matched_data.get("output") or {}
    cover = matched_data.get("cover")
    # Authored bundle-wide global block (compound only) — surfaced so the editor
    # repopulates it on load. None when absent / not a mapping.
    global_block = matched_data.get("global")
    global_out = global_block if isinstance(global_block, dict) else None
    # #20 (B6): surface Description + Type so the editor repopulates them on load.
    # Canonicalize nav_category (case-insensitive; unknown → default) so the
    # editor's <select> always lands on a valid option and a load→save round-trip
    # doesn't 400 on a differently-cased legacy value.
    description = matched_data.get("description") or ""
    nav_category = _canon_nav_category(matched_data.get("nav_category")) or "Executive"

    return JSONResponse(
        {
            "name": name,
            "slug": _slug(str(name)),
            "kind": kind,
            "title": title,
            "description": description if isinstance(description, str) else "",
            "nav_category": nav_category,
            "sections": sections,
            "axis": axis if isinstance(axis, dict) else None,
            "global": global_out,
            "output": output,
            "cover": cover,
        }
    )


# ---------------------------------------------------------------------------
# POST /api/builder/recipes — save
# ---------------------------------------------------------------------------


@router.post("/recipes")
async def save_builder_recipe(request: Request) -> JSONResponse:
    """Save (create or overwrite) a compound or comparison doc.

    Expected JSON body fields:
    * ``kind`` — "compound" | "comparison"  (required)
    * ``name`` — non-empty string            (required)
    * ``title`` — string                     (required)
    * ``sections`` — non-empty list[str]     (required, min 1)
    * ``left`` / ``right`` — str|null        (comparison only)
    * ``cover_subtitle`` / ``logo`` / ``classification`` — optional
    * ``output`` — optional {formats, toc, page_numbers}

    CSRF-guarded by ``CSRFMiddleware`` (header ``X-FS-Session`` required).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Request body must be valid JSON"}, status_code=400
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "Request body must be a JSON object"}, status_code=400
        )

    # ── Validate required fields ─────────────────────────────────────────────

    kind = body.get("kind")
    if kind not in {"compound", "comparison"}:
        return JSONResponse(
            {"error": "kind must be 'compound' or 'comparison'"}, status_code=400
        )

    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        return JSONResponse(
            {"error": "name must be a non-empty string"}, status_code=400
        )
    name = name.strip()

    title = body.get("title")
    if not isinstance(title, str):
        return JSONResponse({"error": "title must be a string"}, status_code=400)

    # #20 (B6): authored compounds/comparisons carry a Description + Type
    # (nav_category) so they aren't all defaulted to "Executive" and so the
    # serializer emits nav_category (root of the #22 warning).
    description = body.get("description")
    if description is None:
        description = ""
    if not isinstance(description, str):
        return JSONResponse({"error": "description must be a string"}, status_code=400)
    description = description.strip()

    # Case-insensitive accept + canonicalize so a legacy/hand-authored doc with a
    # differently-cased value round-trips (load → save) instead of 400-ing.
    nav_category = _canon_nav_category(body.get("nav_category"))
    if nav_category is None:
        return JSONResponse(
            {"error": f"nav_category must be one of {list(_NAV_CATEGORIES)}"},
            status_code=400,
        )

    sections = body.get("sections")
    # Sections may be bare strings (back-compat) OR ``{recipe, overrides?}``
    # objects (Builder compound authoring). Parse to a uniform
    # ``[(token, overrides_dict_or_None), ...]`` shape; a bare string ⇒
    # ``(token, None)``.
    if not isinstance(sections, list) or len(sections) == 0:
        return JSONResponse(
            {"error": "sections must be a non-empty list"}, status_code=400
        )
    parsed_sections: list[tuple[str, dict | None]] = []
    for _raw in sections:
        if isinstance(_raw, str):
            parsed_sections.append((_raw, None))
        elif isinstance(_raw, dict):
            _ref = _raw.get("recipe")
            if not isinstance(_ref, str) or not _ref.strip():
                return JSONResponse(
                    {
                        "error": (
                            "each section object must carry a non-empty "
                            "'recipe' string"
                        )
                    },
                    status_code=400,
                )
            _ov = _raw.get("overrides")
            if _ov is not None and not isinstance(_ov, dict):
                return JSONResponse(
                    {"error": "section 'overrides' must be an object"},
                    status_code=400,
                )
            parsed_sections.append((_ref, _ov))
        else:
            return JSONResponse(
                {
                    "error": (
                        "sections must be a list of recipe names or "
                        "{recipe, overrides} objects"
                    )
                },
                status_code=400,
            )

    # ── Fix #2: Corpus validation for sections ───────────────────────────────
    # Build a slug→recipe map from all bundled + user recipes so we can
    # validate each section name.  Inline import mirrors the pattern used for
    # invalidate_recipe_meta_cache (avoids import-cycle risk).
    from fs_report.compound_overrides import (  # noqa: PLC0415
        COMPOUND_OVERRIDE_WHITELIST,
    )
    from fs_report.models import ComparisonRecipe, CompoundRecipe  # noqa: PLC0415

    try:
        _corpus_recipes = RecipeLoader(
            use_bundled=True, scan_user_recipes=True
        ).load_recipes()
    except Exception:  # pragma: no cover — defensive
        _corpus_recipes = []
    _corpus: dict[str, object] = {_slug(r.name): r for r in _corpus_recipes}

    # Canonical recipe names for the section tokens the client sent (the
    # comparison facet rail sends SLUGS).  Used for COMPARISON persistence so
    # Builder-written YAML matches ``compare --save-as`` (which writes canonical
    # names) — resolving the on-disk slug/name divergence (M1-5).  The GET
    # endpoint slug-normalizes comparison sections back for the facet rail, so
    # the round-trip is lossless.
    canonical_sections: list[str] = []
    # Compound section objects ({recipe: <canonical-name>, overrides?}) handed to
    # the serializer.  Each carries the section's canonical recipe name plus its
    # whitelist-validated overrides (omitted by the serializer when empty/None).
    compound_section_objs: list[dict] = []

    for _sec, _sec_overrides in parsed_sections:
        _sec_slug = _slug(_sec)
        _target = _corpus.get(_sec_slug)
        if _target is None:
            return JSONResponse(
                {
                    "error": (
                        f"Unknown section {_sec!r}: no recipe with that name exists "
                        "in the corpus. Check spelling or create the recipe first."
                    )
                },
                status_code=400,
            )
        _canonical_name = str(getattr(_target, "name", _sec))
        canonical_sections.append(_canonical_name)
        # Per-section overrides — RESTRICTED whitelist (compound only). Reject
        # any key outside the safe subset with a clear 400 so a section can never
        # carry a destructive / workflow-only key (autotriage, error_policy, …).
        if _sec_overrides:
            _bad_keys = sorted(set(_sec_overrides) - COMPOUND_OVERRIDE_WHITELIST)
            if _bad_keys:
                return JSONResponse(
                    {
                        "error": (
                            f"Section {_sec!r} override key(s) {_bad_keys} are not "
                            "allowed. A section may override only "
                            f"{sorted(COMPOUND_OVERRIDE_WHITELIST)}."
                        )
                    },
                    status_code=400,
                )
        compound_section_objs.append(
            {"recipe": _canonical_name, "overrides": _sec_overrides or None}
        )
        if kind == "compound":
            # Decision 10: no nesting — compound docs, comparison docs, and
            # comparison facet recipes (category:comparison) may not be children
            # of a compound.  Mirror the editor palette's exclusion.
            if isinstance(_target, CompoundRecipe):
                _what = "comparison" if _target.axis is not None else "compound"
                return JSONResponse(
                    {
                        "error": (
                            f"Section {_sec!r} is a {_what} recipe and cannot be "
                            "nested inside a compound report. Use plain recipes only."
                        )
                    },
                    status_code=400,
                )
            if isinstance(_target, ComparisonRecipe):
                return JSONResponse(
                    {
                        "error": (
                            f"Section {_sec!r} is a comparison facet recipe "
                            "(category: comparison) and cannot be used as a compound "
                            "section. Use plain recipes only."
                        )
                    },
                    status_code=400,
                )
        elif kind == "comparison":
            # Comparison docs may only reference category:comparison facet recipes.
            if not isinstance(_target, ComparisonRecipe):
                return JSONResponse(
                    {
                        "error": (
                            f"Section {_sec!r} is not a comparison facet recipe "
                            "(category: comparison). Comparison reports may only "
                            "include comparison facets."
                        )
                    },
                    status_code=400,
                )

    # ── Optional fields ──────────────────────────────────────────────────────

    # PR3.1 — comparison scope baking.
    # ``left`` / ``right`` can be either:
    #   a) A scope-ref string (legacy / direct YAML round-trip): used as-is.
    #   b) A name-component dict {project, folder, version}: baked via
    #      _build_scope_ref (the single source of truth for the scope-ref
    #      grammar + grammar hard-block validation).
    # Hard-block validation (400) happens here for comparison kind only:
    #   - malformed grammar (``@`` in a name, etc.) → 400 with _build_scope_ref note
    #   - incomplete side (no project, no folder) → 400
    #   - self-comparison (left_ref == right_ref) → 400
    #   - empty sections → already guarded above
    left_raw = body.get("left")
    right_raw = body.get("right")
    left: str | None = None
    right: str | None = None
    if kind == "comparison":
        # Inline import to avoid a potential import cycle between builder_recipes
        # and command_center (command_center imports recipe_loader et al.; the
        # inline import pattern is used elsewhere in this codebase for the same
        # reason — e.g. invalidate_recipe_meta_cache below).
        from fs_report.web.routers.command_center import (  # noqa: PLC0415
            _build_scope_ref as _bsr,
        )

        def _resolve_side(raw: object) -> tuple[str | None, str | None]:
            """Resolve one side to (canonical_ref, error_message).

            Returns (canonical_ref, None) on success, (None, msg) on hard failure.
            The canonical_ref is always the output of _bsr (e.g. "project:X@v1")
            so that self-comparison checks compare like-for-like regardless of how
            the input was formed.
            """
            if raw is None:
                return None, None  # incomplete — no project, no folder
            if isinstance(raw, str):
                # Already a scope-ref string — validate by re-baking through
                # _build_scope_ref so we get a canonical form for the self-
                # comparison check.  Only project: and folder: prefixes are
                # accepted; unknown prefixes are rejected (Fix #4).
                s = raw.strip()
                if not s:
                    return None, None  # treated as incomplete
                if s.startswith("project:"):
                    rest = s[len("project:") :]
                    at = rest.find("@")
                    if at >= 0:
                        project_name = rest[:at]
                        version_name = rest[at + 1 :]
                    else:
                        project_name = rest
                        version_name = ""
                    side_dict: dict[str, str] = {
                        "project": project_name,
                        "version": version_name,
                    }
                    return _bsr(side_dict)
                elif s.startswith("folder:"):
                    side_dict = {"folder": s[len("folder:") :]}
                    return _bsr(side_dict)
                else:
                    # Fix #4: reject unknown-prefix scope-ref strings rather than
                    # passing them through.  The editor always sends dict left/right;
                    # this is defense-in-depth for direct API callers.
                    return (
                        None,
                        (
                            f"scope-ref string {s!r} has an unknown prefix; "
                            "expected 'project:' or 'folder:'"
                        ),
                    )
            if isinstance(raw, dict):
                return _bsr(raw)
            return (
                None,
                "left/right must be a scope-ref string or a {project, folder, version} dict",
            )

        left_ref, left_err = _resolve_side(left_raw)
        right_ref, right_err = _resolve_side(right_raw)

        # Hard-block: grammar errors
        if left_err is not None:
            return JSONResponse({"error": f"Left scope: {left_err}"}, status_code=400)
        if right_err is not None:
            return JSONResponse({"error": f"Right scope: {right_err}"}, status_code=400)

        # Hard-block: incomplete sides
        if left_ref is None or right_ref is None:
            return JSONResponse(
                {"error": "Set both Left and Right scopes before saving"},
                status_code=400,
            )

        # Hard-block: self-comparison — compare canonical refs (Fix #4 ensures
        # the string path also produces canonical forms, so "project:X@v1" sent
        # as a string and {"project": "X", "version": "v1"} sent as a dict both
        # produce the same canonical ref and are correctly caught here).
        if left_ref == right_ref:
            return JSONResponse(
                {"error": "Left and Right scopes are identical (self-comparison)"},
                status_code=400,
            )

        left = left_ref
        right = right_ref
    else:
        # Compound — left/right are IGNORED/dropped; they only apply to comparison.
        # Any left/right values sent by the client for a compound save are discarded
        # here and will not appear in the saved YAML.
        left = left_raw if isinstance(left_raw, str) else None
        right = right_raw if isinstance(right_raw, str) else None

    cover_subtitle: str | None = body.get("cover_subtitle") or None
    logo: str | None = body.get("logo") or None
    classification: str | None = body.get("classification") or None

    output_raw = body.get("output") or {}
    formats: list[str] | None = None
    toc: bool = True
    page_numbers: bool = True
    if isinstance(output_raw, dict):
        if "formats" in output_raw:
            # Fix #3: formats must be a non-empty list of strings, each in {html, pdf}.
            _fmts = output_raw["formats"]
            if not isinstance(_fmts, list) or len(_fmts) == 0:
                return JSONResponse(
                    {"error": "output.formats must be a non-empty list"},
                    status_code=400,
                )
            _bad_fmts = [f for f in _fmts if f not in {"html", "pdf"}]
            if _bad_fmts:
                return JSONResponse(
                    {
                        "error": (
                            f"output.formats contains unsupported value(s) "
                            f"{_bad_fmts!r}; allowed values are 'html' and 'pdf'"
                        )
                    },
                    status_code=400,
                )
            formats = _fmts
        if "toc" in output_raw:
            # Fix #3: toc must be a real bool (don't coerce strings like "false").
            _toc_val = output_raw["toc"]
            if not isinstance(_toc_val, bool):
                return JSONResponse(
                    {
                        "error": (
                            f"output.toc must be a boolean (true/false), "
                            f"got {type(_toc_val).__name__!r}"
                        )
                    },
                    status_code=400,
                )
            toc = _toc_val
        if "page_numbers" in output_raw:
            # Fix #3: page_numbers must be a real bool (don't coerce strings).
            _pn_val = output_raw["page_numbers"]
            if not isinstance(_pn_val, bool):
                return JSONResponse(
                    {
                        "error": (
                            f"output.page_numbers must be a boolean (true/false), "
                            f"got {type(_pn_val).__name__!r}"
                        )
                    },
                    status_code=400,
                )
            page_numbers = _pn_val

    # ── Authored global block (compound only) ────────────────────────────────
    # A compound may carry a bundle-wide ``global`` config block (scope, AI,
    # date mode). Validate its keys against the same RESTRICTED whitelist (plus
    # the date-mode intent flags that steer per-section precedence), then
    # normalize via the shared compound-normalize step so it shares the
    # workflow's period↔range semantics. Comparison docs ignore ``global``.
    global_block: dict | None = None
    if kind == "compound":
        _global_raw = body.get("global")
        if _global_raw is not None and not isinstance(_global_raw, dict):
            return JSONResponse({"error": "global must be an object"}, status_code=400)
        if _global_raw:
            from fs_report.compound_overrides import (  # noqa: PLC0415
                COMPOUND_OVERRIDE_WHITELIST,
                normalize_compound_global,
            )

            # The intent flags are persisted bools that steer precedence — they
            # are valid global keys even though they are NOT engine override
            # keys (mirrors the workflow global).
            _allowed_global = COMPOUND_OVERRIDE_WHITELIST | {
                "period_touched",
                "range_touched",
                "target_agnostic",
            }
            _bad_global = sorted(set(_global_raw) - _allowed_global)
            if _bad_global:
                return JSONResponse(
                    {
                        "error": (
                            f"global key(s) {_bad_global} are not allowed. The "
                            f"global block may set only {sorted(_allowed_global)}."
                        )
                    },
                    status_code=400,
                )
            global_block = normalize_compound_global(_global_raw)

    # ── Compute slug + path ──────────────────────────────────────────────────

    target_slug = _slug(name)
    recipes_dir = get_user_recipes_dir()
    target_path = recipes_dir / f"{target_slug}.yaml"

    # ── Decision-6: collision guard ──────────────────────────────────────────

    # a) Bundled-name block: always 409 regardless of kind.
    if target_slug in _bundled_slugs():
        return JSONResponse(
            {
                "error": (
                    f"Cannot save {name!r}: collides with a bundled recipe. "
                    "Choose a different name."
                )
            },
            status_code=409,
        )

    # b) User-file kind-aware guard (Decision-6).
    if target_path.exists():
        existing_cat = existing_recipe_category(target_path)
        refusal = _overwrite_refusal(kind, existing_cat)
        if refusal is not None:
            return JSONResponse(
                {"error": f"Cannot overwrite {name!r}: {refusal}"},
                status_code=409,
            )

    # ── Build + write ────────────────────────────────────────────────────────

    if kind == "compound":
        data = build_compound_yaml_dict(
            name=name,
            title=title,
            # Section objects ({recipe: <canonical-name>, overrides?}). Using the
            # canonical names (not raw client tokens) keeps the on-disk shape
            # consistent with the comparison path and with `bundle --save-as`;
            # the serializer omits an empty `overrides` key.
            sections=compound_section_objs,
            cover_subtitle=cover_subtitle,
            logo=logo,
            classification=classification,
            formats=formats,
            toc=toc,
            page_numbers=page_numbers,
            description=description,
            nav_category=nav_category,
            global_block=global_block,
        )
        write_compound_yaml(target_path, data)
    else:
        data = build_comparison_yaml_dict(
            name=name,
            title=title,
            sections=canonical_sections,
            left=left,
            right=right,
            cover_subtitle=cover_subtitle,
            logo=logo,
            classification=classification,
            formats=formats,
            toc=toc,
            page_numbers=page_numbers,
            description=description,
            nav_category=nav_category,
        )
        write_comparison_yaml(target_path, data)

    # Bust the recipe-meta memo so the new bundle's category/icon resolves
    # immediately on the next request without a server restart.
    from fs_report.web.recipe_meta import invalidate_recipe_meta_cache

    invalidate_recipe_meta_cache()

    return JSONResponse({"slug": target_slug, "kind": kind, "status": "saved"})


# ---------------------------------------------------------------------------
# DELETE /api/builder/recipes/{slug} — delete
# ---------------------------------------------------------------------------


@router.delete("/recipes/{recipe_slug}")
async def delete_builder_recipe(recipe_slug: str) -> JSONResponse:
    """Delete the user recipe matching *recipe_slug*.

    User docs only — never touches bundled recipes.
    Returns 404 if no matching user file is found.

    CSRF-guarded by ``CSRFMiddleware`` (header ``X-FS-Session`` required).
    """
    recipes_dir = get_user_recipes_dir()
    matched_path: Path | None = None

    for path, data in _iter_user_recipe_files(recipes_dir):
        name = data.get("name")
        if name is None or _slug(str(name)) != recipe_slug:
            continue
        # Category guard (parity with GET/list): this endpoint owns ONLY
        # compound/comparison docs (``category: compound``).  A slug that
        # happens to match a different category — a ``category: comparison``
        # facet recipe, or any other custom user recipe — is not ours to
        # delete.  Treat it as not-found so a crafted or buggy caller can't
        # unlink an unrelated recipe file by slug collision.
        cat = data.get("category")
        if not isinstance(cat, str) or cat.strip() != "compound":
            continue
        matched_path = path
        break

    if matched_path is None:
        return JSONResponse(
            {"error": f"Recipe not found: {recipe_slug!r}"},
            status_code=404,
        )

    try:
        matched_path.unlink()
    except OSError as exc:
        logger.warning("Failed to delete recipe %r: %s", recipe_slug, exc)
        return JSONResponse(
            {"error": f"Failed to delete recipe: {exc}"},
            status_code=500,
        )

    # Bust the recipe-meta memo so the deleted bundle no longer resolves.
    from fs_report.web.recipe_meta import invalidate_recipe_meta_cache

    invalidate_recipe_meta_cache()

    return JSONResponse({"slug": recipe_slug, "status": "deleted"})
