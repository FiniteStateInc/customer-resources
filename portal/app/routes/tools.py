"""Tools route - browsing and execution."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request, Form, Depends, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session, Job
from app.services.tool_registry import get_tool_registry
from app.services.tool_executor import execute_tool

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


@router.get("/", response_class=HTMLResponse)
async def list_tools(request: Request):
    """List all available tools."""
    settings = get_settings()
    registry = get_tool_registry()
    tools_by_category = registry.get_tools_by_category()

    return templates.TemplateResponse(
        "tools/list.html",
        {
            "request": request,
            "active_page": "tools",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": settings.ai_configured,
            "tools_by_category": tools_by_category,
        },
    )


@router.get("/{tool_name}", response_class=HTMLResponse)
async def tool_detail(request: Request, tool_name: str):
    """Show tool detail and configuration form."""
    settings = get_settings()
    registry = get_tool_registry()
    tool = registry.get_tool(tool_name)

    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    return templates.TemplateResponse(
        "tools/detail.html",
        {
            "request": request,
            "active_page": "tools",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": settings.ai_configured,
            "tool": tool,
        },
    )


@router.post("/{tool_name}/execute", response_class=HTMLResponse)
async def execute_tool_endpoint(
    request: Request,
    tool_name: str,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
):
    """Execute a tool with provided parameters."""
    settings = get_settings()
    registry = get_tool_registry()
    tool = registry.get_tool(tool_name)

    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    # Get form data
    form_data = await request.form()
    parameters = {key: value for key, value in form_data.items() if value}

    # Create job record
    job = Job(
        id=str(uuid.uuid4()),
        tool_name=tool_name,
        parameters=json.dumps(parameters),
        status="pending",
        created_at=datetime.utcnow(),
    )
    session.add(job)
    await session.commit()

    # Start execution in background
    background_tasks.add_task(execute_tool, job.id, tool, parameters)

    # Return execution status partial for HTMX
    return templates.TemplateResponse(
        "tools/execute.html",
        {
            "request": request,
            "active_page": "tools",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": settings.ai_configured,
            "job": job,
            "tool": tool,
        },
    )
