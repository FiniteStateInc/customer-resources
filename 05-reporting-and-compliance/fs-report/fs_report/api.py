"""Public Python API for programmatic access to fs-report.

This module exposes thin wrappers around the core engine so that external
consumers (the customer portal, custom scripts, tests) can import and call
fs-report without going through the CLI.

Example::

    from fs_report.api import run_report, list_recipes

    recipes = list_recipes()
    run_report(
        domain="customer.finitestate.io",
        auth_token="...",
        recipe="Triage Prioritization",
        project="openwrt",
        period="30d",
        output_dir="./output",
    )
"""

from pathlib import Path
from typing import Any

from fs_report.models import Config, Recipe
from fs_report.recipe_loader import RecipeLoader


def list_recipes(
    recipes_dir: str | None = None,
    *,
    use_bundled: bool = True,
) -> list[Recipe]:
    """Return all available recipes.

    Parameters
    ----------
    recipes_dir:
        Optional external recipes directory.
    use_bundled:
        If True, include bundled recipes.
    """
    loader = RecipeLoader(recipes_dir, use_bundled=use_bundled)
    return loader.load_recipes()


def list_projects(
    auth_token: str,
    domain: str,
) -> list[dict[str, Any]]:
    """Fetch all non-archived projects from the Finite State API."""
    from fs_report.api_client import APIClient
    from fs_report.models import QueryConfig, QueryParams

    config = Config(
        auth_token=auth_token,
        domain=domain,
        output_dir="./output",
        start_date="2025-01-01",
        end_date="2025-01-31",
    )
    client = APIClient(config)
    return client.fetch_data(
        QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=1000, archived=False, excluded=False),
        )
    )


def run_report(
    auth_token: str,
    domain: str,
    *,
    recipe: str | None = None,
    recipes_dir: str | None = None,
    output_dir: str = "./output",
    period: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    project: str | None = None,
    folder: str | None = None,
    finding_types: str = "cve",
    current_version_only: bool = True,
    cache_ttl: int = 0,
    overwrite: bool = False,
    **kwargs: Any,
) -> bool:
    """Run the report generation engine and return True on success.

    Parameters
    ----------
    auth_token:
        Finite State API token.
    domain:
        Finite State domain (e.g., customer.finitestate.io).
    recipe:
        Name of a specific recipe to run. None = all auto_run recipes.
    output_dir:
        Output directory for generated reports.
    period:
        Time period (e.g., '30d', '1m', 'Q1').
    project:
        Filter by project name or ID.
    folder:
        Scope to folder name or ID.
    **kwargs:
        Additional Config fields (ai, ai_depth, cve_filter, etc.).
    """
    from fs_report.cli.run import create_config
    from fs_report.report_engine import ReportEngine

    config = create_config(
        output=Path(output_dir),
        start=start_date,
        end=end_date,
        period=period,
        token=auth_token,
        domain=domain,
        recipe=None,
        project_filter=project,
        folder_filter=folder,
        finding_types=finding_types,
        current_version_only=current_version_only,
        cache_ttl=cache_ttl,
        recipes=Path(recipes_dir) if recipes_dir else None,
        overwrite=overwrite,
        **{k: v for k, v in kwargs.items() if v is not None},
    )

    engine = ReportEngine(config)
    if recipe:
        engine.recipe_loader.recipe_filter = [recipe.lower()]

    return engine.run()
