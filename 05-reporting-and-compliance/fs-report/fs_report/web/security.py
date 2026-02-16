"""Security middleware for the web UI.

- CSRF nonce validation on mutating requests
- Localhost-only guard
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp


def generate_nonce() -> str:
    """Generate a CSRF nonce."""
    return secrets.token_urlsafe(32)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Validate CSRF nonce on mutating requests (POST/PUT/DELETE).

    The nonce is injected into templates and must be sent back via
    ``X-FS-Session`` header or ``_csrf`` form field.
    """

    def __init__(self, app: ASGIApp, *, nonce: str) -> None:
        super().__init__(app)
        self.nonce = nonce

    async def dispatch(self, request: Request, call_next: object) -> Response:
        if request.method in ("POST", "PUT", "DELETE"):
            # Skip CSRF for SSE and session endpoints
            path = request.url.path
            if path.startswith("/fsapi/session") or "/events" in path:
                return await call_next(request)  # type: ignore[operator, no-any-return]

            # Check header first, then form field
            req_nonce = request.headers.get("X-FS-Session", "")
            if not req_nonce:
                # Try to get from form data (for regular form submissions)
                content_type = request.headers.get("content-type", "")
                if "form" in content_type:
                    form = await request.form()
                    req_nonce = str(form.get("_csrf", ""))

            if req_nonce != self.nonce:
                return JSONResponse(
                    {"error": "Invalid session nonce"},
                    status_code=403,
                )

        return await call_next(request)  # type: ignore[operator, no-any-return]


class LocalhostGuardMiddleware(BaseHTTPMiddleware):
    """Reject requests that don't originate from localhost.

    Defense-in-depth: Uvicorn binds to 127.0.0.1, so non-local
    traffic should never arrive. This is a safety net.
    """

    _ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}

    async def dispatch(self, request: Request, call_next: object) -> Response:
        client = request.client
        if client and client.host not in self._ALLOWED_HOSTS:
            return JSONResponse(
                {"error": "Only localhost access is allowed"},
                status_code=403,
            )
        return await call_next(request)  # type: ignore[operator, no-any-return]
