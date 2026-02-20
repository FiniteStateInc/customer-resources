"""API proxy router — forwards /fsapi/* to the Finite State API.

Ports the proxy logic from ``fs_report/server.py`` to async httpx.
"""

import logging

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.state import WebAppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fsapi", tags=["proxy"])

_ALLOWED_PREFIX = "/public/v0/"


@router.get("/session")
async def session(
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> JSONResponse:
    """Return session info (no CSRF required).

    When the server already holds credentials, ping the Jira tracker
    endpoint so HTML reports can show accurate Jira availability.
    Reloads config on every call so domain/token changes take effect
    without a server restart.
    """
    state.reload()
    jira_available = False
    jira_projects: list[dict[str, object]] = []
    if state.token and state.domain:
        ping_url = f"https://{state.domain}/api/public/v0/tracker/tickets/ping"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    ping_url,
                    headers={
                        "X-Authorization": state.token,
                        "Content-Type": "application/json",
                    },
                    content=b"{}",
                )
                if resp.status_code == 200:
                    jira_available = True
                    try:
                        ping_data = resp.json()
                        jira_projects = ping_data.get("projects", [])
                    except Exception:
                        pass
                else:
                    logger.warning(
                        "Jira ping returned %s for %s: %s",
                        resp.status_code,
                        ping_url,
                        resp.text[:200],
                    )
        except Exception as exc:
            logger.warning("Jira ping failed for %s: %s", ping_url, exc)

    return JSONResponse(
        {
            "connected": bool(state.token),
            "domain": state.domain,
            "nonce": nonce,
            "jiraAvailable": jira_available,
            "jiraProjects": jira_projects,
        }
    )


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT"])
async def proxy(
    path: str,
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Proxy requests to the Finite State API with token injection."""
    upstream_path = f"/{path}"

    # Validate path prefix
    if not upstream_path.startswith(_ALLOWED_PREFIX):
        return JSONResponse(
            {"error": "Proxy only allows /public/v0/ paths"},
            status_code=403,
        )

    if not state.domain:
        return JSONResponse(
            {"error": "No domain configured"},
            status_code=400,
        )

    upstream_url = f"https://{state.domain}/api{upstream_path}"

    # Include query string
    if request.url.query:
        upstream_url += f"?{request.url.query}"

    # Build forwarded headers
    fwd_headers: dict[str, str] = {}
    if state.token:
        fwd_headers["X-Authorization"] = state.token
    for h in ("Content-Type", "Accept"):
        val = request.headers.get(h)
        if val:
            fwd_headers[h] = val

    # Read request body
    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method=request.method,
                url=upstream_url,
                headers=fwd_headers,
                content=body if body else None,
            )
            ct = resp.headers.get("content-type", "")
            if ct.startswith("application/json") and resp.text.strip():
                try:
                    content = resp.json()
                except Exception:
                    content = {"raw": resp.text}
            elif resp.text.strip():
                content = {"raw": resp.text}
            else:
                content = {"ok": True}
            return JSONResponse(content=content, status_code=resp.status_code)
    except httpx.HTTPStatusError as e:
        return JSONResponse(
            content={"error": str(e)},
            status_code=e.response.status_code,
        )
    except Exception as e:
        logger.exception("Proxy error")
        return JSONResponse(
            content={"error": str(e)},
            status_code=502,
        )
