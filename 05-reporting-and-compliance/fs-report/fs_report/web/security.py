"""Security middleware for the web UI.

Pure ASGI middleware (no BaseHTTPMiddleware) to avoid starlette
ExceptionGroup issues with task-group–based dispatch.

- CSRF nonce validation on mutating requests
- Localhost-only guard
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


def generate_nonce() -> str:
    """Generate a CSRF nonce."""
    return secrets.token_urlsafe(32)


class CSRFMiddleware:  # pragma: no cover
    """Validate CSRF nonce on mutating requests (POST/PUT/DELETE).

    The nonce is injected into templates and must be sent back via
    ``X-FS-Session`` header or ``_csrf`` form field.
    """

    def __init__(self, app: ASGIApp, *, nonce: str) -> None:
        self.app = app
        self.nonce = nonce

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        if method not in ("POST", "PUT", "DELETE"):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if path.startswith("/fsapi/session") or "/events" in path:
            await self.app(scope, receive, send)
            return

        # Extract headers (names are lowercase bytes in ASGI)
        raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        header_map = dict(raw_headers)

        req_nonce = header_map.get(b"x-fs-session", b"").decode()

        if not req_nonce:
            content_type = header_map.get(b"content-type", b"").decode()
            if "urlencoded" in content_type:
                # Read body, extract _csrf, then replay for downstream
                body = await self._read_body(receive)
                params = parse_qs(body.decode("utf-8", errors="replace"))
                csrf_values = params.get("_csrf", [])
                req_nonce = csrf_values[0] if csrf_values else ""

                if req_nonce != self.nonce:
                    resp = JSONResponse(
                        {"error": "Invalid session nonce"}, status_code=403
                    )
                    await resp(scope, receive, send)
                    return

                await self.app(scope, self._replay_receive(body), send)
                return

        if req_nonce != self.nonce:
            resp = JSONResponse({"error": "Invalid session nonce"}, status_code=403)
            await resp(scope, receive, send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _read_body(receive: Receive) -> bytes:
        parts: list[bytes] = []
        while True:
            message = await receive()
            parts.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        return b"".join(parts)

    @staticmethod
    def _replay_receive(body: bytes) -> Receive:
        sent = False

        async def _receive() -> dict:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        return _receive


class LocalhostGuardMiddleware:  # pragma: no cover
    """Reject requests that don't originate from localhost.

    Defense-in-depth: Uvicorn binds to 127.0.0.1, so non-local
    traffic should never arrive. This is a safety net.
    """

    _ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        if client and client[0] not in self._ALLOWED_HOSTS:
            resp = JSONResponse(
                {"error": "Only localhost access is allowed"}, status_code=403
            )
            await resp(scope, receive, send)
            return

        await self.app(scope, receive, send)
