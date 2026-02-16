"""FastAPI dependency injection helpers."""

from starlette.requests import Request

from fs_report.web.state import WebAppState


def get_state(request: Request) -> WebAppState:
    """Retrieve the shared ``WebAppState`` from the application."""
    return request.app.state.app_state  # type: ignore[no-any-return]


def get_nonce(request: Request) -> str:
    """Retrieve the CSRF nonce from the application."""
    return request.app.state.nonce  # type: ignore[no-any-return]
