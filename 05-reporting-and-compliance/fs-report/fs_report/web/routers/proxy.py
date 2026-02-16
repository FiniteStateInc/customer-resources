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
    """Return session info (no CSRF required)."""
    return JSONResponse(
        {
            "connected": bool(state.token),
            "domain": state.domain,
            "nonce": nonce,
        }
    )


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT"])
async def proxy(
    path: str,
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Proxy requests to the Finite State API with token injection."""
    # Strip the /fsapi prefix — path is everything after it
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
            return JSONResponse(
                content=resp.json()
                if resp.headers.get("content-type", "").startswith("application/json")
                else {"raw": resp.text},
                status_code=resp.status_code,
            )
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
