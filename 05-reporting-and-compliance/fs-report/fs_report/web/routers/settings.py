"""Settings page and API router."""

import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from fs_report.cli.common import redact_token
from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.state import WebAppState

router = APIRouter(tags=["settings"])


def _get_cache_info(state: WebAppState) -> dict[str, Any]:
    """Gather cache database stats."""
    cache_dir = Path(
        state.get("cache_dir", "") or str(Path.home() / ".fs-report" / "cache")
    )
    info: dict[str, Any] = {"location": str(cache_dir)}

    db_path = cache_dir / "cache.db"
    if db_path.is_file():
        info["size_mb"] = round(db_path.stat().st_size / (1024 * 1024), 1)
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            info["entries"] = cursor.fetchone()[0]
            conn.close()
        except Exception:
            info["entries"] = -1
    else:
        info["size_mb"] = 0
        info["entries"] = 0

    ai_db = cache_dir / "ai_cache.db"
    if ai_db.is_file():
        info["ai_size_mb"] = round(ai_db.stat().st_size / (1024 * 1024), 1)
    else:
        info["ai_size_mb"] = 0

    return info


@router.get("/settings")
async def settings_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the settings page."""
    token_display = redact_token(state.token) if state.token else "(not set)"
    cache_info = _get_cache_info(state)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/settings.html",
        {
            "request": request,
            "nonce": nonce,
            "state": state,
            "token_display": token_display,
            "cache_info": cache_info,
        },
    )


@router.get("/api/settings")
async def get_settings(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Return current settings as JSON."""
    data = state.to_dict()
    # Never expose token
    data.pop("token", None)
    return JSONResponse(data)


@router.post("/api/settings")
async def save_settings(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Save settings from form submission."""
    form = await request.form()

    for key in (
        "output_dir",
        "period",
        "cache_ttl",
        "project_filter",
        "folder_filter",
        "version_filter",
        "finding_types",
        "ai_depth",
    ):
        val = form.get(key)
        if val is not None:
            state[key] = str(val)

    for key in (
        "overwrite",
        "verbose",
        "current_version_only",
        "ai",
        "ai_prompts",
    ):
        val = form.get(key)
        state[key] = str(val).lower() in ("true", "on", "1", "yes") if val else False

    state.save()
    return JSONResponse({"status": "saved"})


@router.get("/api/settings/cache")
async def cache_stats(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Return cache stats."""
    return JSONResponse(_get_cache_info(state))


@router.delete("/api/settings/cache/api")
async def clear_api_cache(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Clear the API cache."""
    cache_dir = Path(
        state.get("cache_dir", "") or str(Path.home() / ".fs-report" / "cache")
    )
    target = cache_dir / "cache.db"
    if target.is_file():
        target.unlink()
        return JSONResponse({"status": "cleared", "type": "api"})
    return JSONResponse({"status": "not_found", "type": "api"})


@router.delete("/api/settings/cache/ai")
async def clear_ai_cache(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Clear the AI cache."""
    cache_dir = Path(
        state.get("cache_dir", "") or str(Path.home() / ".fs-report" / "cache")
    )
    target = cache_dir / "ai_cache.db"
    if target.is_file():
        target.unlink()
        return JSONResponse({"status": "cleared", "type": "ai"})
    return JSONResponse({"status": "not_found", "type": "ai"})
