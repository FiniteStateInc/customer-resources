"""Recipe listing API router."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from fs_report.recipe_loader import RecipeLoader

router = APIRouter(prefix="/api", tags=["recipes"])


@router.get("/recipes")
async def list_recipes() -> JSONResponse:
    """Return all available recipes as JSON."""
    loader = RecipeLoader(use_bundled=True, scan_user_recipes=True)
    try:
        recipe_list = loader.load_recipes()
    except Exception:
        recipe_list = []

    recipes = [
        {
            "name": r.name,
            "category": r.category or "Uncategorized",
            "description": r.description or "",
            "auto_run": r.auto_run,
            "requires_project": r.requires_project,
            "requires_project_or_folder": r.requires_project_or_folder,
            "requires_cve": r.requires_cve,
        }
        # Consumer-audience recipes (e.g. the forge-driven CRA notifications and the
        # forge customer briefs) are hidden from the web catalog, matching the CLI
        # default (`fs-report list recipes` shows only `audience is None`).
        for r in recipe_list
        if r.audience is None
    ]
    return JSONResponse(recipes)
