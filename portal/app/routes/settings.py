"""Settings route - configuration and data management."""

import os
import shutil
from pathlib import Path

from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session, Settings as DBSettings, Job, ChatMessage, Recipe

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


@router.get("/", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Render the settings page."""
    settings = get_settings()

    # Get stored settings from DB
    result = await session.execute(select(DBSettings).where(DBSettings.id == 1))
    db_settings = result.scalar_one_or_none()

    # Count data
    jobs_result = await session.execute(select(Job))
    jobs_count = len(jobs_result.scalars().all())

    messages_result = await session.execute(select(ChatMessage))
    messages_count = len(messages_result.scalars().all())

    recipes_result = await session.execute(select(Recipe))
    recipes_count = len(recipes_result.scalars().all())

    # Calculate output directory size
    output_dir = settings.output_dir
    output_size = 0
    if output_dir.exists():
        for f in output_dir.rglob("*"):
            if f.is_file():
                output_size += f.stat().st_size

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "active_page": "settings",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": settings.ai_configured,
            "ai_provider": settings.ai_provider,
            "db_settings": db_settings,
            "fs_domain": settings.finite_state_domain,
            "jobs_count": jobs_count,
            "messages_count": messages_count,
            "recipes_count": recipes_count,
            "output_size_mb": round(output_size / (1024 * 1024), 2),
        },
    )


@router.post("/", response_class=HTMLResponse)
async def save_settings(
    request: Request,
    session: AsyncSession = Depends(get_session),
    theme: str = Form("system"),
    ai_api_key: str = Form(None),
    ai_provider: str = Form(None),
):
    """Save user settings."""
    # Get or create settings record
    result = await session.execute(select(DBSettings).where(DBSettings.id == 1))
    db_settings = result.scalar_one_or_none()

    if not db_settings:
        db_settings = DBSettings(id=1)
        session.add(db_settings)

    # Update settings
    db_settings.theme = theme
    if ai_provider:
        db_settings.ai_provider = ai_provider
    if ai_api_key:
        # In production, encrypt this key
        db_settings.ai_api_key_encrypted = ai_api_key

    await session.commit()

    # Redirect back to settings page
    return RedirectResponse(url="/settings?saved=true", status_code=303)


@router.post("/clear-data", response_class=JSONResponse)
async def clear_data(
    request: Request,
    session: AsyncSession = Depends(get_session),
    confirmation: str = Form(...),
):
    """Clear all stored data after confirmation."""
    if confirmation != "DELETE":
        raise HTTPException(status_code=400, detail="Invalid confirmation")

    settings = get_settings()

    # Delete all jobs
    jobs_result = await session.execute(select(Job))
    jobs = jobs_result.scalars().all()
    for job in jobs:
        await session.delete(job)

    # Delete all chat messages
    messages_result = await session.execute(select(ChatMessage))
    messages = messages_result.scalars().all()
    for msg in messages:
        await session.delete(msg)

    # Delete all recipes
    recipes_result = await session.execute(select(Recipe))
    recipes = recipes_result.scalars().all()
    for recipe in recipes:
        await session.delete(recipe)

    # Reset settings
    db_settings_result = await session.execute(select(DBSettings).where(DBSettings.id == 1))
    db_settings = db_settings_result.scalar_one_or_none()
    if db_settings:
        db_settings.ai_api_key_encrypted = None
        db_settings.ai_provider = None

    await session.commit()

    # Delete output files
    output_dir = settings.output_dir
    if output_dir.exists():
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)

    return {"status": "cleared", "message": "All data has been erased"}


@router.post("/test-connection", response_class=JSONResponse)
async def test_connection():
    """Test the Finite State API connection."""
    settings = get_settings()

    if not settings.finite_state_configured:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Finite State credentials not configured"},
        )

    try:
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://{settings.finite_state_domain}/api/v0/projects",
                headers={"X-Authorization": settings.finite_state_auth_token},
                params={"limit": 1},
                timeout=10.0,
            )

            if response.status_code == 200:
                return {"status": "success", "message": "Connection successful"}
            elif response.status_code == 401:
                return {"status": "error", "message": "Invalid authentication token"}
            else:
                return {"status": "error", "message": f"API returned status {response.status_code}"}

    except httpx.TimeoutException:
        return {"status": "error", "message": "Connection timed out"}
    except Exception as e:
        return {"status": "error", "message": f"Connection failed: {str(e)}"}
