"""Configuration management for the portal."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application settings
    app_name: str = "Customer Resources Portal"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8080

    # Finite State API credentials (required)
    finite_state_auth_token: Optional[str] = None
    finite_state_domain: Optional[str] = None

    # AI API keys (optional)
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None

    # Paths
    base_dir: Path = Path(__file__).parent.parent
    data_dir: Path = Path(__file__).parent.parent / "data"
    tools_dir: Path = Path(__file__).parent.parent / "tool_definitions"
    output_dir: Path = Path(__file__).parent.parent / "data" / "outputs"

    # Tool source path prefix (for Docker vs local)
    # In Docker: /app/tools, locally: .. (relative to portal dir)
    tool_path_prefix: Optional[str] = None

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/portal.db"

    # Encryption key for sensitive data (auto-generated if not provided)
    encryption_key: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    @property
    def finite_state_configured(self) -> bool:
        """Check if Finite State credentials are configured."""
        return bool(self.finite_state_auth_token and self.finite_state_domain)

    @property
    def ai_configured(self) -> bool:
        """Check if any AI provider is configured."""
        return bool(self.openai_api_key or self.anthropic_api_key)

    @property
    def ai_provider(self) -> Optional[str]:
        """Get the configured AI provider."""
        if self.anthropic_api_key:
            return "anthropic"
        if self.openai_api_key:
            return "openai"
        return None

    @property
    def finite_state_api_url(self) -> Optional[str]:
        """Get the Finite State API base URL."""
        if self.finite_state_domain:
            return f"https://{self.finite_state_domain}/api/v0"
        return None

    def ensure_directories(self) -> None:
        """Ensure required directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    settings.ensure_directories()
    return settings
