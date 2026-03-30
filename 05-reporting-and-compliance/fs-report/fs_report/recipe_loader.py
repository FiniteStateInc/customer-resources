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

from fs_report.models import Recipe


class RecipeLoader:
    """Loader for YAML recipe files."""

    def __init__(
        self,
        recipes_dir: str | None = None,
        *,
        use_bundled: bool = True,
    ) -> None:
        """Initialize the recipe loader.

        Parameters
        ----------
        recipes_dir:
            Optional filesystem path to an external recipes directory.  When
            provided the loader scans this directory (recursively) for YAML
            recipe files and layers them on top of the bundled set.
        use_bundled:
            If ``True`` (the default), bundled recipes shipped inside the
            ``fs_report.recipes`` package are loaded first.  Set to ``False``
            to disable bundled recipe discovery (``--no-bundled-recipes``).
        """
        self.recipes_dir: Path | None = Path(recipes_dir) if recipes_dir else None
        self.use_bundled = use_bundled
        self.logger = logging.getLogger(__name__)
        self.recipe_filter: list[str] | None = None

    def load_recipes(self) -> list[Recipe]:
        """Load recipes with merge behaviour.

        1. If ``use_bundled`` is ``True``, bundled recipes are loaded first.
        2. If ``recipes_dir`` is set and exists, external recipes are loaded
           and layered on top (same-name overrides bundled).
        3. ``recipe_filter`` is applied last.
        """
        recipes_by_name: dict[str, Recipe] = {}

        # --- 1. Bundled recipes (lowest priority) ---
        if self.use_bundled:
            for recipe in self._load_bundled_recipes():
                recipes_by_name[recipe.name.lower()] = recipe

        # --- 2. External / overlay recipes (highest priority) ---
        if self.recipes_dir is not None:
            for recipe in self._load_directory_recipes(self.recipes_dir):
                recipes_by_name[recipe.name.lower()] = recipe

        recipes = list(recipes_by_name.values())

        # --- 3. Apply recipe_filter if set ---
        if self.recipe_filter:
            filter_set = {r.lower() for r in self.recipe_filter}
            filtered_recipes = [r for r in recipes if r.name.lower() in filter_set]
            if not filtered_recipes:
                available = sorted(r.name for r in recipes)
                unmatched = sorted(filter_set - {r.name.lower() for r in recipes})
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
                        recipe = Recipe.model_validate(yaml_data)
                        recipe.audience = audience
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
                    recipe = Recipe.model_validate(yaml_data)
                    self.logger.debug(f"Loaded bundled recipe: {recipe.name}")
                    recipes.append(recipe)
                except Exception as e:
                    self.logger.error(f"Failed to load bundled recipe {name}: {e}")
                    continue

        return recipes

    # ------------------------------------------------------------------
    # Filesystem recipes
    # ------------------------------------------------------------------

    def _load_directory_recipes(self, directory: Path) -> list[Recipe]:
        """Load all recipe YAML files from a filesystem directory."""
        recipes: list[Recipe] = []

        if not directory.exists():
            self.logger.warning(f"Recipes directory does not exist: {directory}")
            return recipes

        yaml_files = list(directory.rglob("*.yaml")) + list(directory.rglob("*.yml"))

        if not yaml_files:
            self.logger.warning(f"No YAML recipe files found in: {directory}")
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

            # Parse the YAML data into a Recipe object
            recipe = Recipe.model_validate(yaml_data)

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
