"""FastAPI application factory."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.cors import CORSMiddleware

from fs_report.web.security import (
    CSRFMiddleware,
    LocalhostGuardMiddleware,
    generate_nonce,
)
from fs_report.web.state import WebAppState


def create_app(*, port: int = 8321) -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title="Finite State Report Kit",
        docs_url=None,
        redoc_url=None,
    )

    # ── State ─────────────────────────────────────────────────────
    state = WebAppState()
    nonce = generate_nonce()
    app.state.app_state = state
    app.state.nonce = nonce
    app.state.port = port

    # ── Middleware (order matters: last added = outermost) ────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            f"http://localhost:{port}",
            f"http://127.0.0.1:{port}",
        ],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["X-FS-Session", "Content-Type", "Accept"],
    )
    app.add_middleware(CSRFMiddleware, nonce=nonce)
    app.add_middleware(LocalhostGuardMiddleware)

    # ── Static files ──────────────────────────────────────────────
    web_package = importlib.resources.files("fs_report.web")
    static_dir = Path(str(web_package.joinpath("static")))
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Mount output directory for serving generated reports
    output_dir = Path(state.get("output_dir", "./output")).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    app.mount(
        "/output", StaticFiles(directory=str(output_dir), html=True), name="output"
    )

    # ── Templates ─────────────────────────────────────────────────
    templates_dir = Path(str(web_package.joinpath("templates")))
    templates = Jinja2Templates(directory=str(templates_dir))
    app.state.templates = templates

    # ── Routers ───────────────────────────────────────────────────
    from fs_report.web.routers.dashboard import router as dashboard_router
    from fs_report.web.routers.proxy import router as proxy_router
    from fs_report.web.routers.recipes import router as recipes_router
    from fs_report.web.routers.reports import router as reports_router
    from fs_report.web.routers.run import router as run_router
    from fs_report.web.routers.settings import router as settings_router

    app.include_router(dashboard_router)
    app.include_router(recipes_router)
    app.include_router(run_router)
    app.include_router(settings_router)
    app.include_router(reports_router)
    app.include_router(proxy_router)

    return app
