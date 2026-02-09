"""Configuration management for FS-Smartsheet integration."""

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class FiniteStateConfig(BaseSettings):
    """Finite State API configuration."""

    model_config = SettingsConfigDict(env_prefix="FINITE_STATE_")

    domain: str = Field(description="Finite State domain (e.g., platform.finitestate.io)")
    auth_token: str = Field(description="Finite State API token")

    @property
    def base_url(self) -> str:
        """Get the full API base URL."""
        return f"https://{self.domain}/api/public/v0"


class SmartsheetConfig(BaseSettings):
    """Smartsheet API configuration."""

    model_config = SettingsConfigDict(env_prefix="SMARTSHEET_")

    access_token: str = Field(description="Smartsheet API access token")
    workspace_id: int | None = Field(default=None, description="Optional workspace ID")
    workspace_name: str = Field(
        default="Finite State",
        description="Workspace name (created if not exists)",
    )


class SyncConfig(BaseSettings):
    """Sync behavior configuration."""

    model_config = SettingsConfigDict(env_prefix="SYNC_")

    interval_minutes: int = Field(default=60, description="Sync interval in minutes")
    batch_size: int = Field(default=100, description="Number of records per batch")
    state_file: Path = Field(
        default=Path(".fs-smartsheet-state.json"),
        description="Path to sync state file",
    )
    cache_dir: str | None = Field(
        default=None,
        description="Directory for SQLite cache databases (default: ~/.fs-smartsheet/)",
    )


class AppConfig(BaseSettings):
    """Main application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    finite_state: FiniteStateConfig = Field(default_factory=FiniteStateConfig)  # type: ignore[arg-type]
    smartsheet: SmartsheetConfig = Field(default_factory=SmartsheetConfig)  # type: ignore[arg-type]
    sync: SyncConfig = Field(default_factory=SyncConfig)

    @classmethod
    def from_yaml(cls, path: Path) -> "AppConfig":
        """Load configuration from a YAML file."""
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(**data)


class SheetMappingConfig:
    """Configuration for sheet field mappings loaded from YAML."""

    def __init__(self, config_path: Path | None = None):
        self.mappings: dict[str, Any] = {}
        if config_path and config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
                self.mappings = data.get("sync", {}).get("sheets", {})

    def get_sheet_config(self, sheet_name: str) -> dict[str, Any]:
        """Get configuration for a specific sheet."""
        return self.mappings.get(sheet_name, {})

    def get_columns(self, sheet_name: str) -> list[dict[str, Any]]:
        """Get column mappings for a specific sheet."""
        return self.get_sheet_config(sheet_name).get("columns", [])


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load application configuration from environment and optional YAML file."""
    if config_path:
        return AppConfig.from_yaml(config_path)
    return AppConfig()
