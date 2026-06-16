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

"""``fs-report compare`` CLI subcommand (B3.7).

Builds an in-memory meta-compare ``CompoundRecipe`` (``axis=AxisConfig()``)
from two scope references (``--left`` / ``--right``) plus a list of
comparison-category child recipes, then executes it through the standard
engine path. Unlike ``bundle`` (which only persists), ``compare`` ALWAYS
executes (decision #10); ``--save-as`` additionally persists the
configuration for reuse via ``fs-report run --recipe <name> --left ...
--right ...``.

See docs/superpowers/specs/2026-05-11-meta-compare-design.md § 4-6 and
resolved decisions #10, #15.

Scope comes EXCLUSIVELY from ``--left`` / ``--right``. ``--project`` /
``--folder`` / ``--period`` do not exist on ``compare`` — passing an
undefined option is rejected natively by typer.

Usage::

    fs-report compare \\
      component_diff finding_diff \\
      --left  "project:BN85@v3.2.1" \\
      --right "project:BE65@v2.4.0" \\
      --title "BN85 vs BE65 — Security Sync Review"

Argv resolution mirrors ``bundle`` (slug-matched, exact-equality), but the
candidate set is restricted to ``category == "comparison"`` recipes — a
non-comparison token is rejected up front.
"""

from __future__ import annotations

import logging
import shlex
from pathlib import Path
from typing import Union

import typer

from fs_report.cli.common import console, setup_logging
from fs_report.cli.run import create_config
from fs_report.models import CompoundRecipe
from fs_report.paths import get_user_recipes_dir
from fs_report.recipe_loader import RecipeLoader, RecipeSlugCollision
from fs_report.recipe_serializer import (
    UNREADABLE_RECIPE as _UNREADABLE_RECIPE_SHARED,
)
from fs_report.recipe_serializer import (
    build_comparison_yaml_dict as _shared_build_comparison,
)
from fs_report.recipe_serializer import (
    existing_recipe_category as _shared_existing_recipe_category,
)
from fs_report.recipe_serializer import (
    write_comparison_yaml as _shared_write_comparison,
)
from fs_report.renderers.pdf_renderer import cleanup_pdf_engines
from fs_report.report_engine import ReportEngine
from fs_report.scope_ref import ScopeRefError
from fs_report.scope_ref import parse as parse_scope_ref
from fs_report.slug import slug

logger = logging.getLogger(__name__)

compare_app = typer.Typer(
    name="compare",
    help="Compare two scopes across diff facets (meta-compare).",
    add_completion=False,
    # ``allow_interspersed_args`` so options can come AFTER the positional
    # recipe list — matches the documented invocation form and mirrors
    # bundle_cmd. Without it, Click's variadic positional (``nargs=-1``)
    # greedily consumes trailing option flags.
    context_settings={"allow_interspersed_args": True},
)


def _resolve_comparison_argv_to_names(
    argv_tokens: list[str], loader: RecipeLoader
) -> list[str]:
    """Resolve CLI argv tokens to canonical comparison-recipe names.

    Mirrors ``bundle_cmd._resolve_argv_to_names`` but restricts the
    candidate set to ``category == "comparison"`` recipes (spec § 6).
    Each token is slug-normalized and matched exact-equality against the
    loaded corpus. Resolution failures raise ``typer.Exit(1)`` with a
    clear, spec-mandated message:

    * unknown token → lists the available comparison recipes (bundle style);
    * known-but-non-comparison token → ``Recipe 'X' is not a comparison
      recipe. Run 'fs-report list recipes' to see the Comparison group.``;
    * duplicate token → rejected (each recipe at most once).
    """
    recipes = loader.load_recipes()
    by_slug: dict[str, str] = {}
    comparison_slugs: set[str] = set()
    for r in recipes:
        s = slug(r.name)
        by_slug[s] = r.name
        if getattr(r, "category", None) == "comparison":
            comparison_slugs.add(s)

    resolved: list[str] = []
    unknown: list[str] = []
    non_comparison: list[str] = []
    duplicates: list[str] = []
    seen_slugs: set[str] = set()
    for token in argv_tokens:
        s = slug(token)
        if s not in by_slug:
            unknown.append(token)
        elif s not in comparison_slugs:
            non_comparison.append(by_slug[s])
        elif s in seen_slugs:
            duplicates.append(token)
        else:
            seen_slugs.add(s)
            resolved.append(by_slug[s])

    if unknown:
        available = sorted(
            (by_slug[s] for s in comparison_slugs),
            key=str.lower,
        )
        console.print(
            f"[red]Error: unknown recipe(s): {unknown}.[/red] "
            f"Available comparison recipes:\n  - " + "\n  - ".join(available)
        )
        raise typer.Exit(1)
    if non_comparison:
        # Spec § 6: non-comparison tokens are rejected. Collect and report
        # ALL offenders in one error (not just the first) so a user fixing a
        # multi-recipe argv doesn't have to rerun once per bad token. (M1-9.)
        if len(non_comparison) == 1:
            subject = f"Recipe '{non_comparison[0]}' is not a comparison recipe."
        else:
            joined = ", ".join(f"'{name}'" for name in non_comparison)
            subject = f"Recipes {joined} are not comparison recipes."
        console.print(
            f"[red]Error: {subject}[/red] "
            "Run 'fs-report list recipes' to see the Comparison group."
        )
        raise typer.Exit(1)
    if duplicates:
        console.print(
            f"[red]Error: duplicate child recipe(s) in argv: {duplicates}.[/red] "
            "Each comparison recipe can appear at most once."
        )
        raise typer.Exit(1)

    return resolved


def _build_compare_yaml_dict(
    *,
    compare_name: str,
    title: str,
    sections: list[str],
    cover_subtitle: Union[str, None],
    logo: Union[str, None],
    classification: Union[str, None],
) -> dict:
    """Thin re-export alias kept for backward-compat with tests + importers.

    Delegates to
    ``fs_report.recipe_serializer.build_comparison_yaml_dict`` with the
    same keyword API (``compare_name`` mapped to ``name``; ``left``/``right``
    default to ``None`` preserving the existing ``axis: {left: null, right:
    null}`` behaviour).
    """
    data = _shared_build_comparison(
        name=compare_name,
        title=title,
        sections=sections,
        cover_subtitle=cover_subtitle,
        logo=logo,
        classification=classification,
    )
    # A meta-compare always renders a cover (title page + Left/Right
    # Leader/Behind roles + scope spine). The shared serializer omits an
    # empty cover; force one here so `compare` always emits the title page —
    # an empty CoverConfig still produces the cover, and the assembler fills
    # the comparison-specific rows.
    data.setdefault("cover", {})
    return data


# Sentinel re-exported from the shared module under the original private name
# so tests / importers that do
#   ``from fs_report.cli.compare_cmd import _UNREADABLE_RECIPE``
# keep working unchanged.
_UNREADABLE_RECIPE = _UNREADABLE_RECIPE_SHARED


def _existing_recipe_category(target_path: Path) -> Union[str, None]:
    """Thin re-export alias kept for backward-compat with tests + importers.

    Delegates to
    ``fs_report.recipe_serializer.existing_recipe_category``.
    """
    return _shared_existing_recipe_category(target_path)


def _write_compare_yaml(target_path: Path, data: dict) -> None:
    """Thin re-export alias kept for backward-compat with tests + importers.

    Delegates to ``fs_report.recipe_serializer.write_comparison_yaml``.
    """
    _shared_write_comparison(target_path, data)


@compare_app.callback(invoke_without_command=True)
def compare_command(
    ctx: typer.Context,
    recipes_argv: list[str] = typer.Argument(
        None,
        metavar="RECIPE [RECIPE ...]",
        help=(
            "Comparison recipe argv tokens (slug-matched, e.g. 'component_diff', "
            "'Finding Diff'). Only comparison-category recipes are accepted — "
            "run 'fs-report list recipes' to see the Comparison group."
        ),
    ),
    left: Union[str, None] = typer.Option(
        None,
        "--left",
        help=(
            "Left/baseline scope reference (REQUIRED). "
            "E.g. 'project:BN85@v3.2.1', 'project:My Device', 'folder:EU-Routers'."
        ),
    ),
    right: Union[str, None] = typer.Option(
        None,
        "--right",
        help=(
            "Right/current scope reference (REQUIRED). " "E.g. 'project:BE65@v2.4.0'."
        ),
    ),
    finding_types: str = typer.Option(
        "cve",
        "--finding-types",
        "-ft",
        help="Finding types to include. Types: cve, sast, thirdparty. Categories: "
        "credentials, config_issues, crypto_material. Use 'all' for everything. "
        "Comma-separated for multiple (e.g. cve,sast). Note: thirdparty cannot be "
        "combined with other types in one query — pass it alone or use 'all'.",
    ),
    title: Union[str, None] = typer.Option(
        None, "--title", help="Cover-page title for the comparison."
    ),
    cover_subtitle: Union[str, None] = typer.Option(
        None,
        "--cover-subtitle",
        help=(
            "Subtitle line under the cover title. Whitelisted substitution "
            "variables: {{project_name}}, {{period}}, {{title}}, "
            "{{generated_at}}, {{left_scope}}, {{right_scope}}."
        ),
    ),
    logo: Union[str, None] = typer.Option(
        None,
        "--logo",
        help=(
            "Cover-page logo image path. Bare filenames resolve under "
            "~/.fs-report/logos/; absolute paths honored as-is."
        ),
    ),
    classification: Union[str, None] = typer.Option(
        None,
        "--classification",
        help="Classification badge text shown in cover + page footers.",
    ),
    save_as: Union[str, None] = typer.Option(
        None,
        "--save-as",
        help=(
            "Persist this comparison as a saved meta-compare recipe in the "
            "user-recipes directory (~/.fs-report/recipes/<slug>.yaml). Re-run "
            "later via 'fs-report run --recipe <NAME> --left ... --right ...'. "
            "The YAML is written BEFORE the report runs, so a failed run still "
            "leaves the saved recipe on disk."
        ),
    ),
    save_to: Union[Path, None] = typer.Option(
        None,
        "--save-to",
        help=(
            "Override save location for --save-as (e.g., a team-shared "
            "recipes dir). Requires --save-as to also be set."
        ),
        dir_okay=True,
        file_okay=False,
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help=(
            "Replace an existing saved meta-compare YAML (governs the saved "
            "recipe ONLY). The output/deliverable directory is always "
            "regenerated on a compare run — it is never gated by this flag."
        ),
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        "-t",
        help="Finite State API token (or set FINITE_STATE_AUTH_TOKEN).",
        hide_input=True,
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (e.g., customer.finitestate.io).",
    ),
    output: Union[Path, None] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for the comparison deliverable.",
        dir_okay=True,
        file_okay=False,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging.",
    ),
) -> None:
    """Compare two scopes across one or more diff facets.

    Scope comes EXCLUSIVELY from ``--left`` / ``--right`` — there are no
    ``--project`` / ``--folder`` / ``--period`` flags on ``compare``.
    ``compare`` always executes; add ``--save-as`` to ALSO persist the
    configuration for reuse via ``fs-report run --recipe <NAME> --left ...
    --right ...``.
    """
    # ── 1. Argument validation ─────────────────────────────────────
    if save_to is not None and save_as is None:
        console.print("[red]Error: --save-to requires --save-as to also be set.[/red]")
        raise typer.Exit(1)

    if not recipes_argv:
        console.print(
            "[red]Error: at least one comparison recipe is required.[/red]\n"
            "Example: fs-report compare component_diff finding_diff "
            '--left project:A --right project:B --title "A vs B"'
        )
        raise typer.Exit(1)

    if left is None:
        console.print(
            "[red]Error: --left is required.[/red] "
            "Provide the left/baseline scope (e.g. --left project:BN85@v3)."
        )
        raise typer.Exit(1)
    if right is None:
        console.print(
            "[red]Error: --right is required.[/red] "
            "Provide the right/current scope (e.g. --right project:BE65@v2)."
        )
        raise typer.Exit(1)

    # Parse-validate the scope refs immediately so malformed input fails
    # fast with a clean message (before any corpus load / network).
    # Exit code 2 for a malformed scope ref (M1-8): a usage error, matching
    # `run`'s convention (run.py raises typer.Exit(code=2) on scope-parse
    # failures).
    try:
        parse_scope_ref(left)
    except ScopeRefError as exc:
        console.print(f"[red]Error: invalid --left scope reference: {exc}[/red]")
        raise typer.Exit(2) from exc
    try:
        parse_scope_ref(right)
    except ScopeRefError as exc:
        console.print(f"[red]Error: invalid --right scope reference: {exc}[/red]")
        raise typer.Exit(2) from exc

    # ── 2. Output name derivation (decision #15) ───────────────────
    # Validate individual fields first (reject empty/whitespace-only),
    # then combine: slug(--save-as) else slug(--title) else reject.
    if save_as is not None and not save_as.strip():
        console.print(
            "[red]Error: --save-as cannot be empty / whitespace-only.[/red] "
            "The name becomes the recipe identifier."
        )
        raise typer.Exit(1)
    if title is not None and not title.strip():
        console.print("[red]Error: --title cannot be empty / whitespace-only.[/red]")
        raise typer.Exit(1)

    name_source = (save_as or "").strip() or (title or "").strip()
    if not name_source:
        console.print(
            "[red]Error: a name is required — pass --save-as NAME or --title.[/red] "
            "The name identifies the comparison (and becomes the saved recipe "
            "identifier when --save-as is used)."
        )
        raise typer.Exit(1)

    compare_name = name_source
    effective_title = (title or compare_name).strip()
    target_slug = slug(compare_name)

    # Whether this run persists to the saved-recipe namespace. Only --save-as
    # writes a recipe whose NAME is a durable identifier that must be unique.
    is_persistent = save_as is not None

    # ── 3. Block built-in name collisions (ALL paths) ──────────────
    # Built-in collisions are unconditionally rejected (cannot be overridden
    # even with --overwrite) on EVERY path — including an execute-only --title.
    # M1-6: the meta-compare slug would shadow a bundled recipe of the same
    # slug, and the bundled recipe set INCLUDES the comparison children this
    # compound itself uses (e.g. "Component Diff", "Finding Diff"). Naming the
    # compound after one of those children would make it shadow a recipe it
    # depends on — so the check must stay. The message explains WHY and points
    # at the right fix (a different --title / --save-as name).
    builtin_loader = RecipeLoader(use_bundled=True, scan_user_recipes=False)
    builtin_slugs = {slug(r.name): r.name for r in builtin_loader.load_recipes()}
    if target_slug in builtin_slugs:
        collided = builtin_slugs[target_slug]
        name_flag = "--save-as" if is_persistent else "--title"
        console.print(
            f"[red]Error: name {compare_name!r} collides with the built-in "
            f"recipe '{collided}'.[/red] A meta-compare named this would shadow "
            f"that bundled recipe by slug — and the comparison children a "
            f"compare uses (e.g. 'Component Diff', 'Finding Diff') are "
            f"themselves built-in recipes, so a compare must never take one of "
            f"their names. This holds even with --overwrite. Pick a distinct "
            f"{name_flag} name (e.g. {compare_name!r} → "
            f"{compare_name + ' Comparison'!r})."
        )
        raise typer.Exit(1)

    # ── 4. User-recipe collision check — ONLY for the persistent path ──
    # --save-as writes a recipe whose NAME is a persistent identifier that must
    # be unique, so a slug already taken by a user recipe is rejected (unless
    # --overwrite). An execute-only run is transient: it writes nothing, and the
    # engine merges the in-memory compound with OVERRIDE semantics over any
    # same-slug disk recipe (extra wins), so a --title slug matching an
    # unrelated saved recipe is harmless and this check is skipped. (M1-3/M3-3.)
    #
    # M3-1: the collision check must look at the ACTUAL write location. When
    # --save-to DIR is set, scan DIR (the real target) instead of the default
    # ~/.fs-report/recipes — a name that collides only in the default dir must
    # NOT block a write to a different custom dir, and a name colliding in the
    # TARGET dir must be gated by --overwrite.
    if is_persistent:
        if save_to is not None:
            full_loader = RecipeLoader(use_bundled=True, recipes_dir=str(save_to))
        else:
            full_loader = RecipeLoader(use_bundled=True, scan_user_recipes=True)
        full_recipes = full_loader.load_recipes()
        full_slugs = {r.name: r for r in full_recipes}
        existing_by_slug = {slug(name): r for name, r in full_slugs.items()}
        if target_slug in existing_by_slug and target_slug not in builtin_slugs:
            existing_recipe = existing_by_slug[target_slug]
            existing = existing_recipe.name
            if overwrite:
                # --save-as --overwrite is allowed to replace the YAML; the
                # persistence guard (§ 6) handles the on-disk file.
                pass
            else:
                # M1-1: keep the collision hint aligned with the overwrite
                # guard (§ 7 `_existing_recipe_category`). The guard ONLY lets
                # --overwrite replace a confirmed meta-compare (an axis-bearing
                # compound); it refuses to clobber a non-axis recipe even WITH
                # --overwrite. So:
                #   * axis-bearing collision → it's re-runnable AND
                #     overwritable: show the `run --recipe ... --left ...
                #     --right ...` rerun form + the --overwrite path.
                #   * non-axis collision → --overwrite would be refused by the
                #     guard, so DON'T suggest it; tell the user to pick a
                #     different --save-as name.
                # Scope refs are shell-quoted so scopes with spaces (e.g.
                # 'project:My Device') produce copy-pasteable commands.
                if getattr(existing_recipe, "axis", None) is not None:
                    rerun_cmd = (
                        f'fs-report run --recipe "{existing}" '
                        f"--left {shlex.quote(left)} --right {shlex.quote(right)}"
                    )
                    hint = (
                        f"To re-run the existing comparison: {rerun_cmd}. "
                        "To replace the saved recipe, add --overwrite"
                    )
                else:
                    hint = (
                        "Choose a different --save-as name (the existing recipe "
                        "is not a meta-compare, so --overwrite will not replace "
                        "it)"
                    )
                console.print(
                    f"[red]Error: name {compare_name!r} collides with the "
                    f"existing saved recipe '{existing}'.[/red] {hint}."
                )
                raise typer.Exit(1)

    # ── 5. Resolve argv tokens → canonical comparison-recipe names ──
    # Scan user recipes too (round-4 item 1): a user may DEFINE a
    # ``category: comparison`` recipe in ~/.fs-report/recipes/, and it must
    # resolve as a `compare` token (and later as a compound child). The bundled
    # comparison recipes plus any user-defined ones make up the candidate set.
    argv_loader = RecipeLoader(use_bundled=True, scan_user_recipes=True)
    sections = _resolve_comparison_argv_to_names(recipes_argv, argv_loader)

    # ── 6. Build the in-memory meta-compare CompoundRecipe ─────────
    # The dict carries axis={left: None, right: None} (AxisConfig with both
    # sides None) — its presence marks this compound as a meta-compare;
    # runtime scopes flow via Config.left_scope / right_scope below. The
    # same dict is reused for persistence so the saved YAML and the executed
    # recipe are guaranteed identical.
    data = _build_compare_yaml_dict(
        compare_name=compare_name,
        title=effective_title,
        sections=sections,
        cover_subtitle=cover_subtitle,
        logo=logo,
        classification=classification,
    )
    compound = CompoundRecipe.model_validate(data)

    # ── 7. Persist FIRST (decision: save then execute) ─────────────
    # A failed run still leaves the saved recipe behind.
    if save_as is not None:
        target_dir = Path(save_to) if save_to else get_user_recipes_dir()
        target_path = target_dir / f"{target_slug}.yaml"
        if target_path.exists() and not overwrite:
            console.print(
                f"[red]Error: a saved meta-compare already exists at "
                f"{target_path}.[/red]\nUse --overwrite to replace it."
            )
            raise typer.Exit(1)
        # M1-5 (round-4 item 4): --overwrite may ONLY replace an existing
        # meta-compare (an axis-bearing compound). Refuse to clobber a
        # non-axis recipe (assessment / operational / plain-compound user
        # recipe) even with --overwrite — overwriting it with a meta-compare
        # would silently destroy an unrelated saved recipe.
        if target_path.exists() and overwrite:
            existing_category = _existing_recipe_category(target_path)
            if existing_category == _UNREADABLE_RECIPE:
                # M1-4/M3-2: the target is not a confirmed meta-compare
                # (unreadable / corrupt / non-dict). Refuse rather than clobber
                # — overwriting a file we can't classify risks destroying a
                # hand-edited recipe that merely failed to parse.
                console.print(
                    f"[red]Error: existing file at {target_path} is not a "
                    "readable meta-compare recipe; refusing to overwrite.[/red] "
                    "Inspect or remove it, or choose a different --save-as name."
                )
                raise typer.Exit(1)
            if existing_category is not None:
                console.print(
                    f"[red]Error: {compare_name!r} exists as a "
                    f"{existing_category} recipe at {target_path}; refusing to "
                    "overwrite it with a meta-compare.[/red] Choose a different "
                    "--save-as name."
                )
                raise typer.Exit(1)
        try:
            _write_compare_yaml(target_path, data)
        except (PermissionError, OSError) as exc:
            # Unwritable path / read-only filesystem / missing parent we can't
            # create — surface a clean, actionable CLI error instead of a raw
            # traceback. (M3-1.)
            console.print(
                f"[red]Error: could not write saved meta-compare to "
                f"{target_path}: {exc}[/red] Check the path is writable (or pass "
                "--save-to a writable directory)."
            )
            raise typer.Exit(1) from exc
        console.print(f"[green]Saved meta-compare:[/green] {target_path}")

    # ── 8. Build Config + execute (decision #10 — always run) ──────
    # M1-3: match `run`'s PDF-engine + logging lifecycle. `run_reports` calls
    # setup_logging() up front and cleanup_pdf_engines() in a finally block so
    # repeated runs in one process release Chromium engines and share the same
    # observability. compare_cmd calls ReportEngine.run() directly, so it must
    # do the same: configure logging here, and clean up PDF engines in the
    # finally below regardless of success / failure.
    setup_logging(verbose)
    # Config.recipe_filter is a single string (legacy) and is unused here —
    # the engine selects the compound via the loader's list-typed
    # recipe_filter, set below (mirrors run.py).
    # M1-3: --overwrite governs ONLY the saved-YAML replacement (handled in
    # § 7 above). It is intentionally NOT forwarded to the config's output-dir
    # guard — a compare ALWAYS executes and regenerates its deliverable, so the
    # axis-compound path force-overwrites its output directory regardless. Pass
    # overwrite=False so a saved meta-compare re-run via the same code path is
    # never blocked by, nor needs, --overwrite for output regeneration.
    config = create_config(
        output=output,
        token=token,
        domain=domain,
        verbose=verbose,
        recipe=None,
        recipes=None,
        logo=logo,
        finding_types=finding_types,
        overwrite=False,
        left_scope=left,
        right_scope=right,
    )

    # Pre-create the output directory before running, mirroring run_reports
    # (run.py). The engine otherwise doesn't create it until render time —
    # after the fetch — and fetch-time writes under output_dir (the resume
    # progress file) would fail on a fresh --output dir. fetch_all_with_resume
    # now also self-heals its own progress dir, but creating it here keeps the
    # compare and run entrypoints consistent and covers any other fetch-time
    # write under output_dir.
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)

    # UNIFIED run path (round-4 item 1): ALWAYS inject the in-memory compound
    # via extra_recipes AND keep scan_user_recipes=True, for BOTH save-as and
    # execute-only. The engine merges extras with OVERRIDE semantics, so:
    #   * --save-as → the on-disk copy (just written to the scanned user dir or
    #     a --save-to dir) and the extra share a slug → the extra overrides the
    #     loaded copy → no collision; the report runs regardless of WHERE the
    #     YAML landed (so --save-to a non-scanned dir still executes via extra).
    #   * execute-only → nothing on disk to override; the extra simply runs.
    # Keeping scan_user_recipes=True restores discovery of user-DEFINED
    # comparison recipes (so they resolve as both tokens AND compound children)
    # — round-3 suppressed this and broke that path. The compound's comparison
    # children come from the corpus by slug, so extra_recipes stays limited to
    # the compound ITSELF (B3.6 invariant): no comparison child ever lands in
    # the post-filter recipes list.
    #
    # Wrap engine construction + run so collisions / validation / file errors —
    # and any auth/network/API failure during scope resolution or fetch —
    # surface as clean CLI messages instead of bare tracebacks (M1-3/M1-4),
    # mirroring run_reports' handler chain (run.py).
    try:
        engine = ReportEngine(
            config=config,
            extra_recipes=[compound],
            scan_user_recipes=True,
        )
        engine.recipe_loader.recipe_filter = [compound.name]
        run_result = engine.run()
    except typer.Exit:
        raise
    except RecipeSlugCollision as exc:
        console.print(
            f"[red]Error: {compare_name!r} collides with an existing recipe.[/red] "
            "Choose a different name (--title / --save-as), or re-run with "
            "--save-as <name> --overwrite to replace a saved recipe."
        )
        raise typer.Exit(1) from exc
    # M1-4: no FileExistsError handler. The axis (meta-compare) path always
    # passes force_overwrite=True to _compound_output_guard and create_config is
    # called with overwrite=False, so the output-dir guard can never raise
    # FileExistsError on this path. The broad `except Exception` below would
    # catch one anyway if a future change reintroduced it.
    except ValueError as exc:
        console.print(f"[red]Validation error: {exc}[/red]")
        raise typer.Exit(1) from exc
    except Exception as exc:
        # Broad fallback (M1-3/M1-4): auth / network / API failures during scope
        # resolution or fetch must not surface as raw tracebacks. Mirror
        # run_reports' `except Exception` (run.py). The specific handlers above
        # give nicer messages; this is the last-resort clean exit.
        logger.exception("Unexpected error during compare run")
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc
    finally:
        # M1-3: release pooled Chromium PDF engines so repeated compare runs in
        # one process match `run`'s lifecycle (run_reports' finally block). Runs
        # on success, failure, and clean Exit alike.
        cleanup_pdf_engines()

    if not run_result.success:
        # Surface the engine's actionable message (axis scope-flag check,
        # axis-compound missing-scope precheck, or a partial-failure summary
        # naming the failed sections) instead of the generic banner. Fall back
        # to the generic text only when no specific message is set. (M1-1.)
        engine_msg = getattr(run_result, "error_message", None)
        if engine_msg:
            console.print(f"[red]Error: {engine_msg}[/red]")
        else:
            console.print("[red]Comparison report generation failed![/red]")
        raise typer.Exit(1)

    console.print("[green]Comparison report generation completed successfully![/green]")
