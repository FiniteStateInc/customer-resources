"""Dashboard page router — Command Center."""

from fastapi import APIRouter, Depends, Request

from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.shell_context import build_shell_context
from fs_report.web.state import WebAppState

router = APIRouter(tags=["pages"])


@router.get("/")
async def dashboard(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the Command Center page."""
    # Redirect to setup if not configured
    if not state.has_config:
        from starlette.responses import RedirectResponse

        return RedirectResponse(url="/setup")

    # Build the shared shell contract
    ctx = build_shell_context(
        state, nonce, crumb="Command Center", active_view="command-center"
    )

    # configure= query param: read and pass through for command-center.js
    configure = request.query_params.get("configure", "")
    ctx["configure"] = configure

    # state object needed by some template helpers
    ctx["state"] = state

    templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/dashboard.html", ctx)
