"""Dashboard page router."""

from fastapi import APIRouter, Depends, Request

from fs_report.cli.common import redact_token
from fs_report.recipe_loader import RecipeLoader
from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.state import WebAppState

router = APIRouter(tags=["pages"])

WORKFLOWS = [
    {
        "id": "executive",
        "title": "Executive Dashboard",
        "icon": "📊",
        "description": "Operational reports: summary, scan analysis, user activity",
        "recipes": ["executive summary", "scan analysis", "user activity"],
    },
    {
        "id": "cve",
        "title": "CVE Investigation",
        "icon": "🔍",
        "description": "Deep-dive into specific CVEs across your portfolio",
        "recipes": ["cve impact"],
    },
    {
        "id": "triage",
        "title": "Triage Project",
        "icon": "🎯",
        "description": "AI-prioritized findings for a single project",
        "recipes": ["triage prioritization"],
    },
    {
        "id": "findings",
        "title": "Export Findings",
        "icon": "📋",
        "description": "Export all findings for selected projects",
        "recipes": ["findings by project"],
    },
    {
        "id": "components",
        "title": "Export Components",
        "icon": "📦",
        "description": "Export components and licenses for a project",
        "recipes": ["component list"],
    },
    {
        "id": "compare",
        "title": "Compare Versions",
        "icon": "🔀",
        "description": "What changed between two firmware versions?",
        "recipes": ["version comparison"],
    },
]


@router.get("/")
async def dashboard(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the main dashboard page."""
    # Redirect to setup if not configured
    if not state.has_config:
        from starlette.responses import RedirectResponse

        return RedirectResponse(url="/setup")

    # Load recipes
    loader = RecipeLoader(use_bundled=True)
    try:
        recipe_list = loader.load_recipes()
    except Exception:
        recipe_list = []

    recipes = [
        {
            "name": r.name,
            "category": r.category or "Uncategorized",
            "auto_run": r.auto_run,
            "description": r.description or "",
        }
        for r in recipe_list
    ]

    token_display = redact_token(state.token) if state.token else "(not set)"

    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/dashboard.html",
        {
            "request": request,
            "nonce": nonce,
            "state": state,
            "token_display": token_display,
            "workflows": WORKFLOWS,
            "recipes": recipes,
        },
    )
