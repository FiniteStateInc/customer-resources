"""Database setup and models using SQLModel."""

import uuid
from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel, create_engine, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.config import get_settings


# =============================================================================
# Models
# =============================================================================


class Settings(SQLModel, table=True):
    """User settings (single row for local deployment)."""

    __tablename__ = "settings"

    id: int = Field(default=1, primary_key=True)
    ai_api_key_encrypted: Optional[str] = None
    ai_provider: Optional[str] = None  # 'openai' or 'anthropic'
    theme: str = Field(default="system")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Job(SQLModel, table=True):
    """Job execution history."""

    __tablename__ = "jobs"

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    tool_name: str
    parameters: Optional[str] = None  # JSON string
    status: str = Field(default="pending")  # pending, running, completed, failed
    output_path: Optional[str] = None
    logs: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ChatMessage(SQLModel, table=True):
    """Chat history for AI assistant."""

    __tablename__ = "chat_messages"

    id: Optional[int] = Field(default=None, primary_key=True)
    role: str  # 'user' or 'assistant'
    content: str
    tool_calls: Optional[str] = None  # JSON string
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Recipe(SQLModel, table=True):
    """Custom and AI-generated recipes."""

    __tablename__ = "recipes"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    yaml_content: str
    source: str = Field(default="user")  # 'user' or 'ai_generated'
    created_at: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Database Engine
# =============================================================================

settings = get_settings()
settings.ensure_directories()

# Async engine for FastAPI
async_engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    future=True,
)

# Async session factory
async_session = sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Initialize database tables."""
    async with async_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def get_session() -> AsyncSession:
    """Get async database session."""
    async with async_session() as session:
        yield session
