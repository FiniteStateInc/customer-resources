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

"""Recipe loader for parsing YAML recipe files.

Supports two recipe sources with merge behaviour:

1. **Bundled recipes** – shipped inside the ``fs_report.recipes`` package and
   discovered via :mod:`importlib.resources` (zero filesystem assumptions).
2. **External recipes** – loaded from a user-supplied directory via the
   ``--recipes`` CLI flag.

When both sources are active the loader applies *bundled-first* semantics:
bundled recipes are loaded, then external recipes layer on top.  An external
recipe whose *name* (case-insensitive) matches a bundled one **overrides** it.

The ``--no-bundled-recipes`` escape-hatch (``use_bundled=False``) disables
bundled discovery entirely so only external recipes are used.
"""

import importlib.resources
import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from fs_report.models import ComparisonRecipe, CompoundRecipe, Recipe
from fs_report.paths import get_user_recipes_dir
from fs_report.slug import slug

# B13 #22: recipe names already warned about a missing nav_category. The loader
# runs on every --serve render, so this de-dupes the warning to once per recipe
# per process instead of flooding the console on every request.
_WARNED_NO_NAV_CATEGORY: set[str] = set()


class RecipeSlugCollision(ValueError):
    """Two or more recipes normalize to the same slug.

    Raised at ``RecipeLoader`` startup so the program never reaches
    CLI argv parsing under a colliding configuration. See the
    compound-reports design spec § 7 "Slug-collision handling".
    """


def _validate_recipe_data(yaml_data: dict, file_label: str) -> Recipe:
    """Construct a Recipe or CompoundRecipe based on category.

    Dispatched on ``yaml_data["category"]``: ``"compound"`` picks the
    CompoundRecipe variant; everything else (including missing /
    ``"assessment"`` / ``"operational"``) constructs a plain Recipe.
    On ValidationError, the exception is re-raised wrapped with the
    ``file_label`` prepended so error messages identify the source file.
    """
    category = isinstance(yaml_data, dict) and yaml_data.get("category")
    if category == "compound":
        cls: type[Recipe] = CompoundRecipe
    elif category == "comparison":
        cls = ComparisonRecipe
    else:
        cls = Recipe
    try:
        return cls.model_validate(yaml_data)
    except ValidationError as exc:
        # Wrap so error logs / re-raises point at the source file.
        raise ValidationError.from_exception_data(
            title=f"{cls.__name__}[{file_label}]",
            line_errors=exc.errors(),  # type: ignore[arg-type]
        ) from exc


class RecipeLoader:
    """Loader for YAML recipe files."""

    # Storage for compounds that failed section validation. Keyed by
    # slug(name); value is the human-readable problem list. Populated by
    # _validate_compound_sections_and_drop_broken; consumed by the
    # recipe_filter path so an explicit --recipe request for a broken
    # compound surfaces the enumerated errors instead of "not found".
    _dropped_compounds: dict[str, list[str]]

    def __init__(
        self,
        recipes_dir: str | None = None,
        *,
        use_bundled: bool = True,
        scan_user_recipes: bool = False,
    ) -> None:
        """Initialize the recipe loader.

        Parameters
        ----------
        recipes_dir:
            Optional filesystem path to an external recipes directory.  When
            provided the loader scans this directory (recursively) for YAML
            recipe files and layers them on top of the bundled set. Takes
            precedence over ``scan_user_recipes``.
        use_bundled:
            If ``True`` (the default), bundled recipes shipped inside the
            ``fs_report.recipes`` package are loaded first.  Set to ``False``
            to disable bundled recipe discovery (``--no-bundled-recipes``).
        scan_user_recipes:
            If ``True`` and ``recipes_dir`` is not explicitly set, the
            loader also scans the user-recipes directory resolved via
            ``fs_report.paths.get_user_recipes_dir`` (typically
            ``~/.fs-report/recipes/``). Saved compound bundles
            (``--save-as``) land there. **Default False** — opt-in by
            the CLI entrypoint that wants user-recipe discovery, so
            programmatic / test consumers of RecipeLoader aren't
            coupled to local user state.
        """
        self.recipes_dir: Path | None = Path(recipes_dir) if recipes_dir else None
        self.use_bundled = use_bundled
        self.scan_user_recipes = scan_user_recipes
        self.logger = logging.getLogger(__name__)
        self.recipe_filter: list[str] | None = None
        self._dropped_compounds = {}

    def load_recipes(self) -> list[Recipe]:
        """Load recipes with merge + validation behavior.

        1. If ``use_bundled`` is ``True``, bundled recipes load first.
           Within-source slug collisions raise ``RecipeSlugCollision``
           immediately so the responsible source is identified.
        2. If ``recipes_dir`` is set and exists, external recipes load
           and override by slug (the bundled→external precedence chain).
           Cross-source slug equality is treated as override (later
           wins), not collision.
        3. Otherwise, if ``scan_user_recipes`` is ``True`` and
           ``fs_report.paths.get_user_recipes_dir()`` exists, scan that
           directory for user-saved recipes (saved compound bundles,
           etc.). Within-source check applied.
        4. Defensive cross-source slug-collision guard on the merged
           corpus (should never fire after slug-based dedup, but
           remains as belt-and-braces — see compound-reports design
           spec § 7).
        5. Compound-section validation: every ``CompoundRecipe`` whose
           sections resolve cleanly is kept; broken compounds are
           **dropped with a WARNING log** (not raised) so a single
           bad user-saved bundle can't abort unrelated commands. Their
           problems are tracked in ``_dropped_compounds`` so an
           explicit filter request for one surfaces the enumerated
           errors (round-2 PR #99 review M1-1).
        6. ``recipe_filter`` is applied last. Slug-based matching;
           argv tokens like ``executive_summary`` / ``executive-summary``
           / ``Executive Summary`` all resolve to the same recipe.
        """
        # Reset stateful side-channels at the start of every load so a
        # second call doesn't surface stale dropped-compound errors from
        # a previous run (PR #99 round-3 multi-review ⚠️ 3/3 finding).
        self._dropped_compounds = {}

        # Two-phase merge with slug-collision detection:
        #
        # Phase 1: load each source (bundled, external, user) independently.
        #   Within a single source, two recipes with the same slug indicate
        #   a real authoring bug — raise RecipeSlugCollision immediately
        #   so the user sees the conflicting pair from one source.
        # Phase 2: merge sources by slug (later source overrides earlier).
        #   bundled → external → user is the precedence chain. Cross-source
        #   slug equality is treated as override (a saved user bundle named
        #   the same as a bundled recipe replaces it), not collision.
        recipes_by_slug: dict[str, Recipe] = {}

        # --- 1. Bundled recipes (lowest priority) ---
        if self.use_bundled:
            bundled = self._load_bundled_recipes()
            self._check_slug_collisions_in_source(bundled, "bundled")
            for recipe in bundled:
                recipes_by_slug[slug(recipe.name)] = recipe

        # --- 2. External / overlay recipes (highest priority) ---
        if self.recipes_dir is not None:
            external = self._load_directory_recipes(self.recipes_dir)
            self._check_slug_collisions_in_source(
                external, f"directory {self.recipes_dir}"
            )
            for recipe in external:
                recipes_by_slug[slug(recipe.name)] = recipe
        elif self.scan_user_recipes:
            # Default user-recipes dir (`~/.fs-report/recipes/` unless overridden
            # via config.yaml's `recipes_dir` field). Saved compound bundles
            # land there. Silent-skip if the directory doesn't exist — most
            # users won't have one.
            user_dir = get_user_recipes_dir()
            if user_dir.exists() and user_dir.is_dir():
                user = self._load_directory_recipes(user_dir, optional=True)
                self._check_slug_collisions_in_source(
                    user, f"user recipes dir {user_dir}"
                )
                for recipe in user:
                    recipes_by_slug[slug(recipe.name)] = recipe

        recipes = list(recipes_by_slug.values())

        # --- Post-load validation ---
        # Slug-collision is a hard-fail (the bijective name→slug invariant
        # the argv-resolution path depends on, per § 7). After slug-based
        # dedup above this should be a no-op for any reasonable corpus,
        # but the check remains as a defensive guard.
        self._check_slug_collisions(recipes)
        # Compound-section validation is non-fatal: a broken user-saved
        # compound logs a warning and is dropped from the returned list
        # rather than aborting every fs-report command. The user can run
        # other recipes; their broken bundle isn't runnable until fixed.
        recipes = self._validate_compound_sections_and_drop_broken(recipes)

        # --- 3. Apply recipe_filter if set ---
        if self.recipe_filter:
            # Slug-based matching: argv tokens like "executive_summary",
            # "Executive Summary", and "executive-summary" all resolve to
            # the same recipe via the canonical slug() helper. See the
            # compound-reports design spec § 7.
            filter_set = {slug(r) for r in self.recipe_filter}
            filtered_recipes = [r for r in recipes if slug(r.name) in filter_set]

            # If the user explicitly asked for a compound we previously
            # dropped (validation-broken), surface the enumerated problems
            # instead of "not found" — spec § Error Handling expects load-
            # time failure with all unknown names enumerated. (Round-2 PR
            # #99 review M1-1.)
            broken_requested = filter_set & set(self._dropped_compounds.keys())
            if broken_requested:
                broken_details = "; ".join(
                    f"{s!r}: {'; '.join(self._dropped_compounds[s])}"
                    for s in sorted(broken_requested)
                )
                raise ValueError(
                    f"Requested compound recipe(s) failed validation and were "
                    f"dropped at load time: {broken_details}. "
                    f"Fix the YAML in the user-recipes directory or pass "
                    f"--recipes to override the load path."
                )

            if not filtered_recipes:
                available = sorted(r.name for r in recipes)
                unmatched = sorted(filter_set - {slug(r.name) for r in recipes})
                self.logger.error(
                    f"Recipe(s) not found: {unmatched}. "
                    f"Available recipes: {available}"
                )
            else:
                self.logger.info(
                    f"Filtered recipes: {[r.name for r in filtered_recipes]}"
                )
            return filtered_recipes

        return recipes

    # ------------------------------------------------------------------
    # Bundled recipes (importlib.resources)
    # ------------------------------------------------------------------

    def _warn_if_missing_nav_category(self, recipe: Recipe) -> None:
        """Log a warning if a recipe has no nav_category set.

        nav_category controls --serve sidebar grouping. Recipes without it
        still load and run, but they won't surface in the grouped UI.
        Warning-only; never blocks loading.

        B13 #22: de-duped per recipe name across the process. The loader runs on
        every --serve page render, so without this a user-authored compound with
        no nav_category re-warned on every request and flooded the console.
        """
        if recipe.nav_category is None and recipe.name not in _WARNED_NO_NAV_CATEGORY:
            _WARNED_NO_NAV_CATEGORY.add(recipe.name)
            self.logger.warning(
                "Recipe %r has no nav_category; will not appear under any "
                "--serve sidebar group (valid values: Executive, Investigation, "
                "Remediation, Compliance)",
                recipe.name,
            )

    def _load_bundled_recipes(self) -> list[Recipe]:
        """Discover and load recipes bundled inside ``fs_report.recipes``."""
        recipes: list[Recipe] = []
        try:
            package = importlib.resources.files("fs_report.recipes")
        except (ModuleNotFoundError, TypeError):
            self.logger.warning("Bundled recipes package not found")
            return recipes

        for item in package.iterdir():
            name = str(item.name)
            if item.is_dir() and not name.startswith("_"):
                # Consumer subdirectory — load recipes and tag with audience
                audience = name
                for subitem in item.iterdir():
                    subname = str(subitem.name)
                    if not (subname.endswith(".yaml") or subname.endswith(".yml")):
                        continue
                    if subname.startswith("_"):
                        self.logger.debug(f"Skipping template/example file: {subname}")
                        continue
                    try:
                        text = subitem.read_text(encoding="utf-8")
                        yaml_data = yaml.safe_load(text)
                        if not yaml_data:
                            self.logger.warning(
                                f"Empty bundled recipe file: {audience}/{subname}"
                            )
                            continue
                        recipe = _validate_recipe_data(yaml_data, str(subitem))
                        recipe.audience = audience
                        self._warn_if_missing_nav_category(recipe)
                        self.logger.debug(
                            f"Loaded bundled recipe: {recipe.name} (audience={audience})"
                        )
                        recipes.append(recipe)
                    except Exception as e:
                        self.logger.error(
                            f"Failed to load bundled recipe {audience}/{subname}: {e}"
                        )
                        continue
            elif name.endswith((".yaml", ".yml")) and not name.startswith("_"):
                try:
                    text = item.read_text(encoding="utf-8")
                    yaml_data = yaml.safe_load(text)
                    if not yaml_data:
                        self.logger.warning(f"Empty bundled recipe file: {name}")
                        continue
                    recipe = _validate_recipe_data(yaml_data, str(item))
                    self._warn_if_missing_nav_category(recipe)
                    self.logger.debug(f"Loaded bundled recipe: {recipe.name}")
                    recipes.append(recipe)
                except Exception as e:
                    self.logger.error(f"Failed to load bundled recipe {name}: {e}")
                    continue

        return recipes

    # ------------------------------------------------------------------
    # Filesystem recipes
    # ------------------------------------------------------------------

    def _load_directory_recipes(
        self, directory: Path, *, optional: bool = False
    ) -> list[Recipe]:
        """Load all recipe YAML files from a filesystem directory.

        ``optional=True`` marks the default user-recipes scan
        (``~/.fs-report/recipes/``), where an empty or missing directory is the
        NORMAL case — most users have no saved bundles. There it logs at DEBUG
        instead of WARNING so a stock install doesn't spew "No YAML recipe files
        found" into the console on every recipe load. An EXPLICIT ``recipes_dir``
        (``optional=False``) keeps the WARNING: the user pointed us at it on
        purpose, so an empty/missing dir is worth surfacing.
        """
        recipes: list[Recipe] = []

        _empty_log = self.logger.debug if optional else self.logger.warning

        if not directory.exists():
            _empty_log(f"Recipes directory does not exist: {directory}")
            return recipes

        yaml_files = list(directory.rglob("*.yaml")) + list(directory.rglob("*.yml"))

        if not yaml_files:
            _empty_log(f"No YAML recipe files found in: {directory}")
            return recipes

        for yaml_file in yaml_files:
            if yaml_file.name.startswith("_"):
                self.logger.debug(f"Skipping template/example file: {yaml_file}")
                continue

            try:
                recipe = self._load_recipe_file(yaml_file)
                if recipe:
                    # Derive audience from subdirectory (one level deep only)
                    rel = yaml_file.relative_to(directory)
                    if len(rel.parts) == 2 and not rel.parts[0].startswith("_"):
                        recipe.audience = rel.parts[0]
                    recipes.append(recipe)
            except Exception as e:
                self.logger.error(f"Failed to load recipe from {yaml_file}: {e}")
                continue

        return recipes

    def _load_recipe_file(self, file_path: Path) -> Recipe | None:
        """Load a single recipe file."""
        self.logger.debug(f"Loading recipe from: {file_path}")

        try:
            with open(file_path, encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)

            if not yaml_data:
                self.logger.warning(f"Empty recipe file: {file_path}")
                return None

            # Parse the YAML data into a Recipe / CompoundRecipe object
            recipe = _validate_recipe_data(yaml_data, str(file_path))

            self._warn_if_missing_nav_category(recipe)
            self.logger.debug(f"Successfully loaded recipe: {recipe.name}")
            return recipe

        except yaml.YAMLError as e:
            self.logger.error(f"YAML parsing error in {file_path}: {e}")
            raise
        except ValidationError as e:
            missing = [
                err["loc"][-1]
                for err in e.errors()
                if err["type"] == "missing" and err.get("loc")
            ]
            msg = f"Invalid recipe YAML in {file_path}"
            if missing:
                msg += (
                    f" — missing required fields: {', '.join(str(f) for f in missing)}"
                )
            self.logger.error(msg)
            self.logger.error(
                "A minimal custom recipe YAML requires:\n"
                "\n"
                '  name: "My Report"\n'
                "  query:\n"
                '    endpoint: "/public/v0/findings"\n'
                "    params:\n"
                "      limit: 10000\n"
                "  transform_function: my_transform_function\n"
                "  output:\n"
                "    table: true\n"
                "    charts: []\n"
                '    formats: ["csv", "html"]\n'
            )
            raise
        except Exception as e:
            self.logger.error(f"Error loading recipe from {file_path}: {e}")
            raise

    def _check_slug_collisions(self, recipes: list[Recipe]) -> None:
        """Fail at startup if any two recipes normalize to the same slug.

        Slug-based argv resolution depends on a bijective name→slug map.
        Two recipes named "Foo Bar" and "Foo-Bar" would normalize to
        the same slug and make argv matching nondeterministic. Catching
        the collision at startup means the program never reaches the
        CLI argv-parse step under a colliding configuration. See the
        compound-reports design spec § 7.

        This check operates on the FINAL merged recipe list (post-
        cross-source dedup). Within-source collisions are caught earlier
        in load_recipes() via _check_slug_collisions_in_source so the
        error message points at the responsible source. This pass is a
        defensive guard against any future logic that could introduce a
        post-merge collision.
        """
        by_slug: dict[str, list[str]] = {}
        for r in recipes:
            by_slug.setdefault(slug(r.name), []).append(r.name)
        collisions = {s: names for s, names in by_slug.items() if len(names) > 1}
        if collisions:
            details = "; ".join(
                f"slug={s!r} shared by {names}" for s, names in collisions.items()
            )
            raise RecipeSlugCollision(
                f"Recipe names normalize to the same slug: {details}. "
                "Rename one recipe so each name maps to a unique slug "
                "(see compound-reports design spec § 7)."
            )

    def _check_slug_collisions_in_source(
        self, recipes: list[Recipe], source_label: str
    ) -> None:
        """Detect slug collisions WITHIN a single source (bundled / external / user).

        Cross-source slug equality is treated as override (later source
        wins). Within-source collisions are real authoring bugs — raise
        immediately with the source label so the user knows where to
        look.
        """
        by_slug: dict[str, list[str]] = {}
        for r in recipes:
            by_slug.setdefault(slug(r.name), []).append(r.name)
        collisions = {s: names for s, names in by_slug.items() if len(names) > 1}
        if collisions:
            details = "; ".join(
                f"slug={s!r} shared by {names}" for s, names in collisions.items()
            )
            raise RecipeSlugCollision(
                f"Slug collision within {source_label}: {details}. "
                "Rename one recipe so each name maps to a unique slug "
                "(see compound-reports design spec § 7)."
            )

    def _validate_compound_sections_and_drop_broken(
        self, recipes: list[Recipe]
    ) -> list[Recipe]:
        """Validate every CompoundRecipe's sections list — warn and drop on failure.

        Per the compound-reports design spec § 3:
        - Every sections[].recipe must resolve to a known recipe name.
        - No child can be a compound (no nesting in v1).
        - No duplicate child names in a single compound's sections list.

        Slug-based matching on both sides. A broken compound is removed
        from the returned list and a WARNING is logged so the user sees
        why it's missing — but unrelated commands (e.g. running a
        non-compound recipe) still work. Hard-failing every load on a
        single broken saved bundle was too aggressive (round-1 PR #99
        multi-review M2-2 / M3-1).
        """
        by_slug: dict[str, Recipe] = {slug(r.name): r for r in recipes}
        kept: list[Recipe] = []

        for r in recipes:
            if not isinstance(r, CompoundRecipe):
                kept.append(r)
                continue

            seen_slugs: set[str] = set()
            duplicate_in_compound: list[str] = []
            unresolved: list[str] = []
            nested_compounds: list[str] = []
            # Axis cross-validation (B3.1):
            # axis-bearing → all children must be ComparisonRecipe
            # non-axis      → no child may be a ComparisonRecipe
            non_comparison_in_axis: list[str] = []
            comparison_in_non_axis: list[str] = []

            is_axis = r.axis is not None

            for section_ref in r.sections:
                section_slug = slug(section_ref.recipe)
                if section_slug in seen_slugs:
                    duplicate_in_compound.append(section_ref.recipe)
                    continue
                seen_slugs.add(section_slug)

                target = by_slug.get(section_slug)
                if target is None:
                    unresolved.append(section_ref.recipe)
                elif isinstance(target, CompoundRecipe):
                    nested_compounds.append(section_ref.recipe)
                elif is_axis and not isinstance(target, ComparisonRecipe):
                    non_comparison_in_axis.append(section_ref.recipe)
                elif not is_axis and isinstance(target, ComparisonRecipe):
                    comparison_in_non_axis.append(section_ref.recipe)

            problems: list[str] = []
            if unresolved:
                problems.append(
                    f"unresolved sections {unresolved} (no loaded recipe matches)"
                )
            if nested_compounds:
                problems.append(
                    f"nested compounds {nested_compounds} "
                    f"(compound-containing-compound is rejected in v1)"
                )
            if duplicate_in_compound:
                problems.append(
                    f"duplicate sections {duplicate_in_compound} "
                    f"(same recipe listed more than once)"
                )
            if non_comparison_in_axis:
                problems.append(
                    f"axis-bearing compound contains non-comparison child "
                    f"recipe(s) {non_comparison_in_axis} "
                    f"(all children of a meta-compare bundle must be "
                    f"ComparisonRecipe)"
                )
            if comparison_in_non_axis:
                problems.append(
                    f"non-axis compound contains comparison child recipe(s) "
                    f"{comparison_in_non_axis} "
                    f"(comparison recipes must be children of an axis-bearing "
                    f"CompoundRecipe, not a plain bundle)"
                )

            if problems:
                self.logger.warning(
                    "Compound recipe %r has %d problem(s) and was dropped: %s",
                    r.name,
                    len(problems),
                    "; ".join(problems),
                )
                # Track the dropped compound so an explicit --recipe filter
                # request for it surfaces the enumerated errors instead of
                # a confusing "not found" (M1-1, round-2 PR #99 review).
                self._dropped_compounds[slug(r.name)] = problems
                continue

            kept.append(r)

        return kept

    def validate_recipe(self, recipe: Recipe) -> bool:
        """Validate a recipe configuration."""
        try:
            # Basic validation
            if not recipe.name:
                self.logger.error("Recipe name is required")
                return False

            if recipe.query is None or not recipe.query.endpoint:
                self.logger.error("Query endpoint is required")
                return False

            # Validate endpoint format
            if not recipe.query.endpoint.startswith("/"):
                self.logger.error("Query endpoint must start with '/'")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Recipe validation error: {e}")
            return False
