"""Chat route - AI assistant interface."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session, ChatMessage, Recipe
from app.services.ai_assistant import format_response_html

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")

# Register custom filter for formatting AI responses
templates.env.filters["format_ai_response"] = format_response_html


@router.get("/", response_class=HTMLResponse)
async def chat_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Render the chat interface."""
    settings = get_settings()

    if not settings.ai_configured:
        return templates.TemplateResponse(
            "chat.html",
            {
                "request": request,
                "active_page": "chat",
                "fs_connected": settings.finite_state_configured,
                "ai_enabled": False,
                "messages": [],
                "error": "AI assistant requires an API key. Configure it in Settings.",
            },
        )

    # Get recent chat history
    result = await session.execute(
        select(ChatMessage).order_by(ChatMessage.created_at).limit(50)
    )
    messages = result.scalars().all()

    return templates.TemplateResponse(
        "chat.html",
        {
            "request": request,
            "active_page": "chat",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": True,
            "ai_provider": settings.ai_provider,
            "messages": messages,
        },
    )


@router.post("/message", response_class=HTMLResponse)
async def send_message(
    request: Request,
    message: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    """Send a message to the AI assistant."""
    settings = get_settings()

    if not settings.ai_configured:
        raise HTTPException(status_code=400, detail="AI not configured")

    # Save user message
    user_msg = ChatMessage(
        role="user",
        content=message,
        created_at=datetime.utcnow(),
    )
    session.add(user_msg)
    await session.commit()

    # Get AI response
    from app.services.ai_assistant import get_ai_response, format_response_html

    response_text = await get_ai_response(message, session)

    # Save assistant message
    assistant_msg = ChatMessage(
        role="assistant",
        content=response_text,
        created_at=datetime.utcnow(),
    )
    session.add(assistant_msg)
    await session.commit()

    # Return both messages as HTML partials
    return templates.TemplateResponse(
        "components/chat_messages.html",
        {
            "request": request,
            "messages": [user_msg, assistant_msg],
        },
    )


@router.post("/generate-recipe", response_class=HTMLResponse)
async def generate_recipe(
    request: Request,
    description: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    """Generate a YAML recipe based on description."""
    settings = get_settings()

    if not settings.ai_configured:
        raise HTTPException(status_code=400, detail="AI not configured")

    from app.services.ai_assistant import generate_recipe_yaml
    from app.services.recipe_validator import validate_recipe

    # Generate recipe
    recipe_yaml = await generate_recipe_yaml(description)

    # Validate recipe
    is_valid, errors = validate_recipe(recipe_yaml)

    # Save recipe if valid
    if is_valid:
        recipe = Recipe(
            name=f"Generated Recipe - {datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            description=description,
            yaml_content=recipe_yaml,
            source="ai_generated",
            created_at=datetime.utcnow(),
        )
        session.add(recipe)
        await session.commit()

    return templates.TemplateResponse(
        "components/recipe_result.html",
        {
            "request": request,
            "recipe_yaml": recipe_yaml,
            "is_valid": is_valid,
            "errors": errors,
            "description": description,
        },
    )


@router.delete("/history", response_class=HTMLResponse)
async def clear_history(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Clear chat history."""
    result = await session.execute(select(ChatMessage))
    messages = result.scalars().all()

    for msg in messages:
        await session.delete(msg)

    await session.commit()

    # Return the empty state HTML
    return templates.TemplateResponse(
        "components/chat_empty_state.html",
        {"request": request},
    )
