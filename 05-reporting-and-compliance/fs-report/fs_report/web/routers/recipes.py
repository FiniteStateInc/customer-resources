"""Recipe listing API router."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from fs_report.recipe_loader import RecipeLoader

router = APIRouter(prefix="/api", tags=["recipes"])


@router.get("/recipes")
async def list_recipes() -> JSONResponse:
    """Return all available recipes as JSON."""
    loader = RecipeLoader(use_bundled=True)
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
        }
        for r in recipe_list
    ]
    return JSONResponse(recipes)
