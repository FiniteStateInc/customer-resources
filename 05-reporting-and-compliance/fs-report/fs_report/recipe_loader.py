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

"""Recipe loader for parsing YAML recipe files."""

import logging
from pathlib import Path

import yaml

from fs_report.models import Recipe


class RecipeLoader:
    """Loader for YAML recipe files."""

    def __init__(self, recipes_dir: str) -> None:
        """Initialize the recipe loader."""
        self.recipes_dir = Path(recipes_dir)
        self.logger = logging.getLogger(__name__)
        self.recipe_filter: list[str] | None = None  # List of lower-case recipe names to include

    def load_recipes(self) -> list[Recipe]:
        """Load all recipe files from the recipes directory, applying recipe_filter if set."""
        recipes: list[Recipe] = []

        if not self.recipes_dir.exists():
            self.logger.warning(f"Recipes directory does not exist: {self.recipes_dir}")
            return recipes

        # Find all YAML files in the recipes directory and subdirectories
        yaml_files = list(self.recipes_dir.rglob("*.yaml")) + list(
            self.recipes_dir.rglob("*.yml")
        )

        if not yaml_files:
            self.logger.warning(f"No YAML recipe files found in: {self.recipes_dir}")
            return recipes

        for yaml_file in yaml_files:
            try:
                recipe = self._load_recipe_file(yaml_file)
                if recipe:
                    recipes.append(recipe)
            except Exception as e:
                self.logger.error(f"Failed to load recipe from {yaml_file}: {e}")
                continue

        # Apply recipe_filter if set
        if self.recipe_filter:
            filter_set = set(r.lower() for r in self.recipe_filter)
            filtered_recipes = [r for r in recipes if r.name.lower() in filter_set]
            self.logger.info(f"Filtered recipes: {[r.name for r in filtered_recipes]}")
            return filtered_recipes
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
