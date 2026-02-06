"""Home/Dashboard route."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.config import get_settings
from app.services.tool_registry import get_tool_registry

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the dashboard page."""
    settings = get_settings()
    registry = get_tool_registry()
    tools = registry.get_all_tools()
    tools_by_category = registry.get_tools_by_category()

    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "active_page": "home",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": settings.ai_configured,
            "tools": tools,
            "tools_by_category": tools_by_category,
            "total_tools": len(tools),
        },
    )
