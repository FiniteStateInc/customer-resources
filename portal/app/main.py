"""FastAPI application entry point."""

import uvicorn
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database import init_db


settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    await init_db()
    yield
    # Shutdown (cleanup if needed)


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files
static_path = Path(__file__).parent / "static"
static_path.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_path), name="static")

# Setup templates
templates_path = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=templates_path)


# Make settings and templates available to routes
def get_templates():
    """Get Jinja2 templates instance."""
    return templates


# Include routers
from app.routes import home, tools, jobs, settings as settings_route, chat, api

app.include_router(home.router)
app.include_router(tools.router, prefix="/tools", tags=["tools"])
app.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
app.include_router(settings_route.router, prefix="/settings", tags=["settings"])
app.include_router(chat.router, prefix="/chat", tags=["chat"])
app.include_router(api.router, prefix="/api", tags=["api"])


@app.get("/health")
async def health_check():
    """Health check endpoint for Docker."""
    return {
        "status": "healthy",
        "finite_state_configured": settings.finite_state_configured,
        "ai_configured": settings.ai_configured,
    }


def run():
    """Run the application."""
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    run()
