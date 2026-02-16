"""Shared CLI helpers: logging, auth, config file loading."""

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Union

import typer
import yaml
from rich.console import Console
from rich.logging import RichHandler

console = Console()

# Config file search order: CWD first, then ~/.fs-report/
_CONFIG_FILENAMES = [".fs-report.yaml", ".fs-report.yml"]
_GLOBAL_CONFIG_DIR = Path.home() / ".fs-report"
_GLOBAL_CONFIG_FILENAMES = ["config.yaml", "config.yml"]


def setup_logging(verbose: bool) -> None:
    """Configure logging with RichHandler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
        force=True,
    )


def get_default_dates() -> tuple[str, str]:
    """Return default date range (30 days back to today)."""
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=30)
    return start_date.isoformat(), end_date.isoformat()


def redact_token(token: str) -> str:
    """Redact token for display (shows first 4 and last 4 chars)."""
    if len(token) <= 8:
        return "*" * len(token)
    return token[:4] + "*" * (len(token) - 8) + token[-4:]


def resolve_auth(
    token: Union[str, None] = None,
    domain: Union[str, None] = None,
    *,
    allow_empty: bool = False,
) -> tuple[str, str]:
    """Resolve auth token and domain from args, config file, then env vars.

    Returns (auth_token, domain_value).
    Raises typer.Exit(2) if required values are missing and *allow_empty* is False.
    """
    cfg = load_config_file()

    auth_token = str(
        token or os.getenv("FINITE_STATE_AUTH_TOKEN") or cfg.get("token", "") or ""
    )
    domain_value = str(
        domain or os.getenv("FINITE_STATE_DOMAIN") or cfg.get("domain", "") or ""
    )

    if not allow_empty:
        if not auth_token:
            console.print(
                "[red]Error: API token required. Set FINITE_STATE_AUTH_TOKEN "
                "environment variable or use --token.[/red]"
            )
            raise typer.Exit(2)
        if not domain_value:
            console.print(
                "[red]Error: Domain required. Set FINITE_STATE_DOMAIN "
                "environment variable or use --domain.[/red]"
            )
            raise typer.Exit(2)

    return auth_token, domain_value


# ── Config file loading ─────────────────────────────────────────────


def find_config_file() -> Path | None:
    """Locate the config file: CWD first, then ~/.fs-report/."""
    cwd = Path.cwd()
    for name in _CONFIG_FILENAMES:
        candidate = cwd / name
        if candidate.is_file():
            return candidate

    for name in _GLOBAL_CONFIG_FILENAMES:
        candidate = _GLOBAL_CONFIG_DIR / name
        if candidate.is_file():
            return candidate

    return None


def load_config_file() -> dict[str, Any]:
    """Load and return the config file as a dict, or empty dict if none found."""
    path = find_config_file()
    if path is None:
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def merge_config(
    cli_value: Any,
    env_var: str | None = None,
    config_key: str | None = None,
    default: Any = None,
    config_data: dict[str, Any] | None = None,
) -> Any:
    """Resolve a single config value: CLI flag > env var > config file > default."""
    if cli_value is not None:
        return cli_value
    if env_var:
        env_val = os.getenv(env_var)
        if env_val is not None:
            return env_val
    if config_key and config_data:
        cfg_val = config_data.get(config_key)
        if cfg_val is not None:
            return cfg_val
    return default


def deprecation_warning(old: str, new: str) -> None:
    """Print a deprecation warning for a renamed command/flag."""
    console.print(
        f"[yellow]Deprecation: '{old}' is deprecated. Use '{new}' instead.[/yellow]"
    )
