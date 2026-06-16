"""Shared recipe → (category, icon) metadata.

Single source of truth for the recipe/category iconography used by the
Report History page AND the Run canvas. Both consumers import the public
surface here so there is exactly ONE icon map — no second copy.
"""

import logging

logger = logging.getLogger(__name__)


# ── Recipe → (category, icon) metadata ──
#
# Categorization keys on a NORMALIZED recipe name so both serve display names
# ("Executive Dashboard") and the CLI's lowercased slugs ("executive dashboard"
# / "executive_dashboard") resolve to the same entry.
RECIPE_ICONS: dict[str, str] = {
    "executive dashboard": "gauge",
    "triage prioritization": "target",
    "cra assessment": "landmark",
    "cra compliance": "landmark",
    "version comparison": "git-compare",
    "component list": "package",
    "remediation package": "wrench",
    "component remediation package": "wrench",
    "false positive analysis": "shield-check",
    "findings by project": "folder-tree",
    "scan quality": "activity",
    "security progress": "trending-up",
    "component impact": "crosshair",
    "component vulnerability analysis": "bug",
}

CATEGORY_ICONS: dict[str, str] = {
    "Executive": "gauge",
    "Investigation": "target",
    "Remediation": "wrench",
    "Compliance": "landmark",
    "Uncategorized": "file-text",
}

_RECIPE_META_CACHE: dict[str, str | None] | None = None


def normalize_recipe_name(name: str) -> str:
    """Normalize a recipe name for category/icon lookup."""
    return name.strip().lower().replace("_", " ")


def recipe_category_map() -> dict[str, str | None]:
    """Return a memoized {normalized recipe name → nav_category} map.

    Built once (lazily) from the bundled recipe definitions; guards load
    failures to an empty map so the page never raises on a bad recipe load.
    (Under serve's worker threads two requests could both build the map before
    either caches it — benign: the build is idempotent and last-writer-wins.)
    """
    global _RECIPE_META_CACHE
    if _RECIPE_META_CACHE is not None:
        return _RECIPE_META_CACHE

    meta: dict[str, str | None] = {}
    try:
        from fs_report.recipe_loader import RecipeLoader

        for r in RecipeLoader(use_bundled=True, scan_user_recipes=True).load_recipes():
            meta[normalize_recipe_name(r.name)] = r.nav_category
    except Exception:
        # Do NOT cache on failure — a transient load error would otherwise pin
        # every report to "Uncategorized" for the whole process lifetime.
        # Returning uncached lets the next request retry.
        logger.warning("Failed to load recipe metadata", exc_info=True)
        return {}

    _RECIPE_META_CACHE = meta
    return meta


def invalidate_recipe_meta_cache() -> None:
    """Reset the in-process recipe-meta memo.

    Call after any user-recipe mutation (save / delete) so the next call to
    ``recipe_category_map()`` rescans the user recipes dir and picks up the
    newly-saved or removed bundle without a server restart.
    """
    global _RECIPE_META_CACHE
    _RECIPE_META_CACHE = None


def icon_for(recipe_name: str | None, category: str | None) -> str:
    """Return a Lucide icon id via the recipe → category → default chain.

    Prefers a recipe-name-specific icon; falls back to the category default;
    finally to a generic ``file-text``. Null-safe: either arg may be ``None``
    or empty.
    """
    if recipe_name:
        recipe_icon = RECIPE_ICONS.get(normalize_recipe_name(recipe_name))
        if recipe_icon:
            return recipe_icon
    if category:
        category_icon = CATEGORY_ICONS.get(category)
        if category_icon:
            return category_icon
    return "file-text"


def categorize(recipe: str) -> tuple[str, str, str]:
    """Return (category, cat_slug, icon) for a recorded recipe name."""
    norm = normalize_recipe_name(recipe)
    category = recipe_category_map().get(norm) or "Uncategorized"
    icon = icon_for(recipe, category)
    return category, category.lower(), icon
