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

"""``fs-report bundle`` CLI subcommand.

Builds a compound recipe from CLI args (a list of child-recipe argv
tokens plus title / cover / classification options) and persists it
as a YAML in the user-recipes directory. Saved bundles are then
runnable via the standard ``fs-report run --recipe <name>`` path,
which dispatches through the compound code path landed in B1.4.

See the compound-reports design spec § 7 for the full contract.

Usage:

    fs-report bundle executive_summary cra_compliance triage_prioritization \\
        --save-as "Monthly Brief" \\
        --cover-subtitle "{{project_name}} — {{period}}" \\
        --classification "Confidential"

Then run the saved bundle:

    fs-report run --recipe "Monthly Brief" --project FOO --period 90d

CLI argv-resolution rule (spec § 7): every argv token goes through
``slug()`` and is matched against the same-keyed corpus index. Matching
is exact-equality only — partial / prefix / fuzzy matches are not
accepted. The generated YAML uses each recipe's canonical ``name``
value (not the slug).

NOT YET SUPPORTED (deferred from this subcommand's scope):

- Inline execute path (``fs-report bundle ... --title "X" --project FOO``
  without ``--save-as``). Save first, then run.
- ``--keep-sections`` per-child standalone output (spec § 7). Saved
  bundle's run path produces the combined HTML + PDF; per-child
  artifacts come from ``fs-report run --recipe <child>`` separately.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Union

import typer

from fs_report.cli.common import console
from fs_report.paths import get_user_recipes_dir
from fs_report.recipe_loader import RecipeLoader
from fs_report.recipe_serializer import (
    build_compound_yaml_dict as _shared_build_compound,
)
from fs_report.recipe_serializer import (
    write_compound_yaml as _shared_write_compound,
)
from fs_report.slug import slug

logger = logging.getLogger(__name__)

bundle_app = typer.Typer(
    name="bundle",
    help="Build a compound report bundle from child recipes.",
    add_completion=False,
    # ``allow_interspersed_args`` so options can come AFTER the positional
    # recipe list — matches the documented invocation form and standard
    # CLI conventions:
    #   fs-report bundle executive_summary cra_compliance --save-as "X"
    # Without this, Click's default behavior for variadic positionals
    # (``nargs=-1``) greedily consumes every trailing token including
    # ``--save-as``, leaving the option unset and failing the
    # title/save-as validation. (Round-1 multi-review M1-1 — 3/3 critical.)
    context_settings={"allow_interspersed_args": True},
)


def _resolve_argv_to_names(argv_tokens: list[str], loader: RecipeLoader) -> list[str]:
    """Resolve CLI argv tokens to canonical recipe names.

    Each token is passed through ``slug()``; the result is looked up
    against a slug→name index built from the loaded corpus. Unknown
    tokens raise a typer.Exit with the list of available recipe names
    so the user can correct the argv.

    Compound recipes are excluded from the lookup target (nested
    compounds are forbidden in v1, per spec § 3). A compound argv
    that resolves to an existing compound surfaces a clear error
    rather than silently producing an invalid bundle.
    """
    recipes = loader.load_recipes()
    by_slug: dict[str, str] = {}
    compound_slugs: set[str] = set()
    comparison_slugs: set[str] = set()
    for r in recipes:
        s = slug(r.name)
        by_slug[s] = r.name
        category = getattr(r, "category", None)
        if category == "compound":
            compound_slugs.add(s)
        elif category == "comparison":
            comparison_slugs.add(s)

    resolved: list[str] = []
    unknown: list[str] = []
    nested: list[str] = []
    comparison: list[str] = []
    duplicates: list[str] = []
    seen_slugs: set[str] = set()
    for token in argv_tokens:
        s = slug(token)
        if s not in by_slug:
            unknown.append(token)
        elif s in compound_slugs:
            nested.append(token)
        elif s in comparison_slugs:
            comparison.append(by_slug[s])
        elif s in seen_slugs:
            duplicates.append(token)
        else:
            seen_slugs.add(s)
            resolved.append(by_slug[s])

    if unknown:
        # Sort the available names for stable, scannable error output.
        # Comparison recipes are excluded too — they belong to `fs-report
        # compare`, never a plain bundle.
        available = sorted(
            (
                n
                for s, n in by_slug.items()
                if s not in compound_slugs and s not in comparison_slugs
            ),
            key=str.lower,
        )
        console.print(
            f"[red]Error: unknown recipe(s): {unknown}.[/red] "
            f"Available recipes:\n  - " + "\n  - ".join(available)
        )
        raise typer.Exit(1)
    if nested:
        console.print(
            f"[red]Error: cannot bundle a compound recipe (nested compounds "
            f"are not supported in v1): {nested}[/red]"
        )
        raise typer.Exit(1)
    if comparison:
        # Comparison recipes are invalid as plain-bundle children: the loader
        # drops them from a non-axis compound. Reject up front with a pointer
        # to the meta-compare path. (M1-5.)
        console.print(
            f"[red]Error: cannot bundle a comparison recipe: {comparison}.[/red] "
            "Comparison recipes run via 'fs-report compare <name> --left <scope> "
            "--right <scope>', not 'fs-report bundle'."
        )
        raise typer.Exit(1)
    if duplicates:
        # Spec § Error Handling: duplicate child names in ``sections:``
        # are rejected at load time. Catch them earlier at CLI time so
        # the user gets a clear error instead of a YAML that the loader
        # silently drops with only a warning. (Round-1 multi-review M1-4.)
        console.print(
            f"[red]Error: duplicate child recipe(s) in argv: {duplicates}.[/red] "
            "Each recipe can appear at most once in a bundle. Same-recipe-"
            "twice-with-different-scope is a future enhancement (spec § "
            "Out of Scope)."
        )
        raise typer.Exit(1)

    return resolved


def _build_compound_yaml_dict(
    *,
    bundle_name: str,
    title: str,
    sections: list[str],
    cover_subtitle: Union[str, None],
    logo: Union[str, None],
    classification: Union[str, None],
) -> dict:
    """Thin re-export alias kept for backward-compat with tests + importers.

    Delegates to ``fs_report.recipe_serializer.build_compound_yaml_dict``
    with the same keyword API (``bundle_name`` mapped to ``name``).
    """
    return _shared_build_compound(
        name=bundle_name,
        title=title,
        sections=sections,
        cover_subtitle=cover_subtitle,
        logo=logo,
        classification=classification,
    )


def _write_compound_yaml(target_path: Path, data: dict) -> None:
    """Thin re-export alias kept for backward-compat with tests + importers.

    Delegates to ``fs_report.recipe_serializer.write_compound_yaml``.
    """
    _shared_write_compound(target_path, data)


@bundle_app.callback(invoke_without_command=True)
def bundle_command(
    ctx: typer.Context,
    recipes_argv: list[str] = typer.Argument(
        None,
        metavar="RECIPE [RECIPE ...]",
        help=(
            "Child recipe argv tokens (slug-matched, e.g. 'executive_summary', "
            "'CRA Compliance', 'triage-prioritization')."
        ),
    ),
    title: Union[str, None] = typer.Option(
        None, "--title", help="Cover-page title for the bundle."
    ),
    cover_subtitle: Union[str, None] = typer.Option(
        None,
        "--cover-subtitle",
        help=(
            "Subtitle line under the cover title. Whitelisted substitution "
            "variables: {{project_name}}, {{period}}, {{title}}, "
            "{{generated_at}}."
        ),
    ),
    logo: Union[str, None] = typer.Option(
        None,
        "--logo",
        help=(
            "Cover-page logo image path. Bare filenames resolve under "
            "~/.fs-report/logos/ via the existing helper; absolute paths "
            "honored as-is."
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
            "Persist this configuration as a saved recipe in the user-recipes "
            "directory (~/.fs-report/recipes/<slug>.yaml). Use the recipe "
            "later via 'fs-report run --recipe <NAME>'."
        ),
    ),
    save_to: Union[Path, None] = typer.Option(
        None,
        "--save-to",
        help=(
            "Override save location for --save-as (e.g., a team-shared "
            "recipes dir checked into git). Requires --save-as to also "
            "be set — --save-to alone does not imply a bundle name."
        ),
        dir_okay=True,
        file_okay=False,
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Required to overwrite an existing saved bundle YAML.",
    ),
) -> None:
    """Build a compound report bundle from a list of child recipes.

    See ``fs-report bundle --help`` and the compound-reports design
    spec § 7 for the full flag list. Scope flags (project / folder /
    period / ...) for executing the bundle at the SAME time as building
    it are not part of this subcommand's surface — save the bundle
    with ``--save-as`` and then run it with ``fs-report run --recipe
    <NAME>``. This keeps the bundle build / run paths cleanly
    separated.
    """
    # ── 1. Argument validation ─────────────────────────────────────
    # At least one recipe is required.
    if not recipes_argv:
        console.print(
            "[red]Error: at least one child recipe is required.[/red]\n"
            "Example: fs-report bundle executive_summary cra_compliance "
            '--save-as "Monthly Brief"'
        )
        raise typer.Exit(1)

    # --save-as is required for persist (the only supported mode today).
    # Inline execute (build + run without persist) is a deferred path —
    # tell users to --save-as and then run via the standard recipe path.
    # (Round-1 multi-review M1-5, M3-3 — clarify the deferral.)
    if save_as is None:
        if title is not None:
            console.print(
                "[red]Error: inline execute (--title without --save-as) is not yet "
                "supported.[/red] To run a bundle, save it first then invoke via "
                f"the standard recipe path:\n  fs-report bundle <recipes...> "
                f'--save-as "{title}"\n  fs-report run --recipe "{title}" '
                "--project <name> --period <window>"
            )
        else:
            console.print(
                "[red]Error: --save-as is required.[/red] "
                "Bundles must be persisted with a name; that name becomes the "
                "recipe identifier used by `fs-report run --recipe`. Add "
                '--title "..." for a separate cover-page title; otherwise the '
                "saved name doubles as the title."
            )
        raise typer.Exit(1)

    # --save-to without --save-as is unsupported (M1-8): --save-to only
    # overrides the LOCATION of the saved YAML; the bundle name still
    # comes from --save-as. Validated above (--save-as is required), so
    # any --save-to invocation reaches here with a non-None --save-as.

    # Reject empty / whitespace-only --save-as / --title. The canonical
    # slug() falls back to "section" for empty strings, which would write
    # section.yaml with empty ``name`` and ``title`` fields — a broken
    # saved recipe the loader rejects later with a confusing error.
    # (Round-1 multi-review M1-2 / M2-2 / M3-2 — 3/3 critical.)
    bundle_name = (save_as or "").strip()
    if not bundle_name:
        console.print(
            "[red]Error: --save-as cannot be empty / whitespace-only.[/red] "
            "The bundle name becomes the recipe identifier."
        )
        raise typer.Exit(1)
    if title is not None and not title.strip():
        console.print("[red]Error: --title cannot be empty / whitespace-only.[/red]")
        raise typer.Exit(1)

    effective_title = (title or save_as).strip()

    # ── 2. Block --save-as name collisions with built-in recipes ───
    # Spec § Error Handling: --save-as collision with a built-in recipe
    # is rejected regardless of --overwrite. The user-recipes-dir merge
    # would otherwise replace the bundled recipe at load time.
    # (Round-1 multi-review M1-3.)
    builtin_loader = RecipeLoader(use_bundled=True, scan_user_recipes=False)
    builtin_slugs = {slug(r.name): r.name for r in builtin_loader.load_recipes()}
    target_slug = slug(bundle_name)
    if target_slug in builtin_slugs:
        console.print(
            f"[red]Error: --save-as {bundle_name!r} collides with the built-in "
            f"recipe '{builtin_slugs[target_slug]}'.[/red] Saved bundles cannot "
            "override built-in recipe names even with --overwrite — choose a "
            "distinct name."
        )
        raise typer.Exit(1)

    # ── 3. Resolve argv tokens → canonical recipe names ────────────
    # Use the FULL corpus (built-in + user-saved) so a user-saved
    # compound argv triggers the nested-compound rejection cleanly, and
    # user-saved single recipes are valid section candidates.
    full_loader = RecipeLoader(use_bundled=True, scan_user_recipes=True)
    sections = _resolve_argv_to_names(recipes_argv, full_loader)

    # ── 4. Build YAML + write ──────────────────────────────────────
    data = _build_compound_yaml_dict(
        bundle_name=bundle_name,
        title=effective_title,
        sections=sections,
        cover_subtitle=cover_subtitle,
        logo=logo,
        classification=classification,
    )

    target_dir = Path(save_to) if save_to else get_user_recipes_dir()
    target_path = target_dir / f"{target_slug}.yaml"

    if target_path.exists() and not overwrite:
        console.print(
            f"[red]Error: a saved bundle already exists at {target_path}.[/red]\n"
            f"Use --overwrite to replace it."
        )
        raise typer.Exit(1)

    _write_compound_yaml(target_path, data)
    console.print(f"[green]Saved bundle:[/green] {target_path}")
    console.print(
        f'Run it with: [cyan]fs-report run --recipe "{bundle_name}"'
        " --project <name> --period <window>[/cyan]"
    )
