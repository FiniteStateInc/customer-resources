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
            self.logger.info(f"Filtered recipes: {[r.name for r in filtered_recipes]}")
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
            if not (name.endswith(".yaml") or name.endswith(".yml")):
                continue
            if name.startswith("_"):
                self.logger.debug(f"Skipping template/example file: {name}")
                continue

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

            if not recipe.query.endpoint:
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
