"""API routes for fetching data from Finite State."""

from html import escape
from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings

router = APIRouter()


async def fetch_from_fs(endpoint: str, params: Optional[dict] = None) -> dict:
    """Fetch data from the Finite State API."""
    settings = get_settings()

    if not settings.finite_state_configured:
        raise HTTPException(status_code=503, detail="Finite State API not configured")

    url = f"https://{settings.finite_state_domain}/api{endpoint}"
    headers = {"X-Authorization": settings.finite_state_auth_token}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, params=params, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=str(e))
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"API request failed: {str(e)}")


@router.get("/projects")
async def list_projects(
    request: Request,
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    search: Optional[str] = None,
):
    """
    List all projects from Finite State.

    Returns a simplified list for dropdown selection.
    """
    params = {"limit": limit, "offset": offset}

    # Add search filter if provided
    if search:
        params["filter"] = f"name=ilike=*{search}*"

    data = await fetch_from_fs("/public/v0/projects", params)

    # Extract just what we need for dropdowns
    projects = []
    items = data.get("data", data) if isinstance(data, dict) else data
    for project in items if isinstance(items, list) else []:
        projects.append({
            "id": project.get("id"),
            "name": project.get("name"),
            "type": project.get("type"),
        })

    return {"projects": projects}


@router.get("/projects/options", response_class=HTMLResponse)
async def list_projects_html(
    limit: int = Query(500, le=1000),
    search: Optional[str] = None,
):
    """
    List all projects as HTML <option> elements.
    """
    params = {"limit": limit, "sort": "name:asc"}

    if search:
        params["filter"] = f"name=ilike=*{search}*"

    try:
        data = await fetch_from_fs("/public/v0/projects", params)
    except HTTPException as e:
        return HTMLResponse(
            content=f'<option value="">Error: {escape(str(e.detail))}</option>',
            media_type="text/html"
        )

    items = data.get("data", data) if isinstance(data, dict) else data
    projects = items if isinstance(items, list) else []

    # Sort alphabetically by name (case-insensitive)
    projects = sorted(projects, key=lambda p: (p.get("name") or "").lower())

    if not projects:
        return HTMLResponse(
            content='<option value="">No projects found</option>',
            media_type="text/html"
        )

    html = '<option value="">Choose a project...</option>\n'
    for project in projects:
        project_id = project.get("id", "")
        project_name = escape(project.get("name") or "Unknown")
        html += f'<option value="{project_id}">{project_name}</option>\n'

    return HTMLResponse(content=html, media_type="text/html")


@router.get("/projects/{project_id}")
async def get_project(project_id: str):
    """Get a single project by ID."""
    data = await fetch_from_fs(f"/public/v0/projects/{project_id}")
    return data


@router.get("/projects/{project_id}/versions")
async def list_project_versions(project_id: str):
    """
    List all versions for a project.

    Returns a simplified list for dropdown selection.
    """
    data = await fetch_from_fs(f"/public/v0/projects/{project_id}/versions")

    # Extract just what we need for dropdowns
    versions = []
    items = data.get("data", data) if isinstance(data, dict) else data

    for version in items if isinstance(items, list) else []:
        versions.append({
            "id": version.get("id"),
            "name": version.get("version") or version.get("name"),
            "created": version.get("created"),
        })

    return {"versions": versions}


@router.get("/projects/{project_id}/versions/options", response_class=HTMLResponse)
async def list_versions_html(project_id: str):
    """
    List all versions for a project as HTML <option> elements for HTMX.
    """
    if not project_id or project_id == "undefined" or project_id == "none":
        return HTMLResponse(
            content='<option value="">Select a project first...</option>',
            media_type="text/html"
        )

    try:
        data = await fetch_from_fs(f"/public/v0/projects/{project_id}/versions")
    except HTTPException as e:
        return HTMLResponse(
            content=f'<option value="">Error: {escape(str(e.detail))}</option>',
            media_type="text/html"
        )

    items = data.get("data", data) if isinstance(data, dict) else data
    versions = items if isinstance(items, list) else []

    if not versions:
        return HTMLResponse(
            content='<option value="">No versions found</option>',
            media_type="text/html"
        )

    # Sort alphabetically by name (case-insensitive)
    # Note: API returns "version" field for version name, not "name"
    versions = sorted(versions, key=lambda v: (v.get("version") or v.get("name") or "").lower())

    html = '<option value="">Choose a version...</option>\n'
    for version in versions:
        version_id = version.get("id", "")
        version_name = escape(version.get("version") or version.get("name") or "Unknown")
        html += f'<option value="{version_id}">{version_name}</option>\n'

    return HTMLResponse(content=html, media_type="text/html")
