# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""CLI entry point for the Finite State Reporting Kit."""

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Union

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from fs_report.models import Config
from fs_report.period_parser import PeriodParser
from fs_report.recipe_loader import RecipeLoader
from fs_report.report_engine import ReportEngine
from fs_report.sqlite_cache import SQLiteCache, parse_ttl

console = Console()
app = typer.Typer(
    name="fs-report",
    help="Finite State Stand-Alone Reporting Kit",
    add_completion=False,
)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
        force=True,
    )


def get_default_dates() -> tuple[str, str]:
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=30)
    return start_date.isoformat(), end_date.isoformat()


def redact_token(token: str) -> str:
    if len(token) <= 8:
        return "*" * len(token)
    return token[:4] + "*" * (len(token) - 8) + token[-4:]


def create_config(
    recipes: Union[Path, None] = None,
    output: Union[Path, None] = None,
    start: Union[str, None] = None,
    end: Union[str, None] = None,
    period: Union[str, None] = None,
    token: Union[str, None] = None,
    domain: Union[str, None] = None,
    verbose: bool = False,
    recipe: Union[str, None] = None,
    data_file: Union[str, None] = None,
    project_filter: Union[str, None] = None,
    version_filter: Union[str, None] = None,
    folder_filter: Union[str, None] = None,
    finding_types: str = "cve",
    current_version_only: bool = True,
    cache_ttl: int = 0,
    cache_dir: Union[str, None] = None,
    detected_after: Union[str, None] = None,
    ai: bool = False,
    ai_provider: Union[str, None] = None,
    ai_depth: str = "summary",
    ai_prompts: bool = False,
    nvd_api_key: Union[str, None] = None,
    baseline_date: Union[str, None] = None,
    baseline_version: Union[str, None] = None,
    current_version: Union[str, None] = None,
    open_only: bool = False,
    request_delay: float = 0.5,
    batch_size: int = 5,
    cve_filter: Union[str, None] = None,
    scoring_file: Union[str, None] = None,
    vex_override: bool = False,
    overwrite: bool = False,
) -> Config:
    # Handle period parameter
    if period:
        try:
            start, end = PeriodParser.parse_period(period)
        except ValueError as e:
            console.print(f"[red]Error parsing period '{period}': {e}[/red]")
            console.print(PeriodParser.get_help_text())
            raise typer.Exit(1)
    elif start is None or end is None:
        default_start, default_end = get_default_dates()
        start = start or default_start
        end = end or default_end

    # If using data file, make token and domain optional
    if data_file:
        auth_token: str = token or os.getenv("FINITE_STATE_AUTH_TOKEN") or "dummy_token"
        domain_value: str = (
            domain or os.getenv("FINITE_STATE_DOMAIN") or "test.finitestate.io"
        )
    else:
        auth_token = str(token or os.getenv("FINITE_STATE_AUTH_TOKEN") or "")
        if not auth_token:
            console.print(
                "[red]Error: API token required. Set FINITE_STATE_AUTH_TOKEN environment variable or use --token.[/red]"
            )
            raise typer.Exit(2)
        domain_value = str(domain or os.getenv("FINITE_STATE_DOMAIN") or "")
        if not domain_value:
            console.print(
                "[red]Error: Domain required. Set FINITE_STATE_DOMAIN environment variable or use --domain.[/red]"
            )
            raise typer.Exit(2)
    # Validate finding_types
    valid_finding_types = {
        "cve",
        "sast",
        "thirdparty",
        "binary_sca",
        "source_sca",
        "credentials",
        "config_issues",
        "crypto_material",
        "all",
    }
    if finding_types:
        types_list = [t.strip().lower() for t in finding_types.split(",")]
        invalid_types = set(types_list) - valid_finding_types
        if invalid_types:
            console.print(
                f"[red]Error: Invalid finding type(s): {', '.join(invalid_types)}[/red]"
            )
            console.print(
                f"[yellow]Valid types: {', '.join(sorted(valid_finding_types))}[/yellow]"
            )
            raise typer.Exit(1)

    # Validate AI options
    if ai:
        _ai_env_vars = ["ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN"]
        has_any_key = any(os.getenv(v) for v in _ai_env_vars)
        if not has_any_key:
            console.print(
                "[red]Error: --ai requires one of these environment variables: "
                + ", ".join(_ai_env_vars)
                + "[/red]"
            )
            raise typer.Exit(2)
        if ai_provider and ai_provider not in ("anthropic", "openai", "copilot"):
            console.print(
                f"[red]Error: --ai-provider must be 'anthropic', 'openai', or 'copilot', got '{ai_provider}'[/red]"
            )
            raise typer.Exit(1)
        if ai_depth not in ("summary", "full"):
            console.print(
                f"[red]Error: --ai-depth must be 'summary' or 'full', got '{ai_depth}'[/red]"
            )
            raise typer.Exit(1)

    # Validate baseline_date format
    if baseline_date:
        try:
            datetime.fromisoformat(baseline_date)
        except ValueError:
            console.print(
                f"[red]Error: --baseline-date must be YYYY-MM-DD format, got '{baseline_date}'[/red]"
            )
            raise typer.Exit(1)

    return Config(
        auth_token=auth_token,
        domain=domain_value,
        recipes_dir=str(recipes or Path("./recipes")),
        output_dir=str(Path(output or "./output").expanduser()),
        start_date=start,
        end_date=end,
        verbose=verbose,
        recipe_filter=recipe,
        project_filter=project_filter,
        version_filter=version_filter,
        folder_filter=folder_filter,
        finding_types=finding_types,
        current_version_only=current_version_only,
        cache_ttl=cache_ttl,
        cache_dir=cache_dir,
        detected_after=detected_after,
        ai=ai,
        ai_provider=ai_provider,
        ai_depth=ai_depth,
        ai_prompts=ai_prompts,
        nvd_api_key=nvd_api_key,
        baseline_date=baseline_date,
        baseline_version=baseline_version,
        current_version=current_version,
        open_only=open_only,
        request_delay=request_delay,
        batch_size=batch_size,
        cve_filter=cve_filter,
        scoring_file=scoring_file,
        vex_override=vex_override,
        overwrite=overwrite,
    )


@app.command()
def show_periods() -> None:
    """Show help for period specifications."""
    console.print("[bold cyan]Period Specifications[/bold cyan]")
    console.print(PeriodParser.get_help_text())


@app.command()
def list_recipes(
    recipes: Union[Path, None] = typer.Option(
        None,
        "--recipes",
        "-r",
        help="Path to recipes directory",
        dir_okay=True,
        file_okay=False,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """List all available recipes."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    recipes_dir = recipes or Path("./recipes")
    loader = RecipeLoader(str(recipes_dir))

    try:
        recipes_list = loader.load_recipes()

        if not recipes_list:
            console.print(f"[yellow]No recipes found in: {recipes_dir}[/yellow]")
            return

        # Create a rich table to display recipes
        table = Table(title=f"Available Recipes ({len(recipes_list)} found)")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("File", style="dim")

        for recipe in recipes_list:
            # Get the filename from the recipe name (assuming it's the same)
            filename = f"{recipe.name.lower().replace(' ', '_')}.yaml"
            table.add_row(recipe.name, filename)

        console.print(table)

    except Exception as e:
        logger.exception("Error loading recipes")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


@app.command()
def list_projects(
    recipes: Union[Path, None] = typer.Option(
        None,
        "--recipes",
        "-r",
        help="Path to recipes directory",
        dir_okay=True,
        file_okay=False,
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        "-t",
        help="Finite State API token",
        hide_input=True,
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (e.g., customer.finitestate.io)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """List all available projects."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    try:
        # Create minimal config for API access
        auth_token = str(token or os.getenv("FINITE_STATE_AUTH_TOKEN") or "")
        if not auth_token:
            console.print(
                "[red]Error: API token required. Set FINITE_STATE_AUTH_TOKEN environment variable or use --token.[/red]"
            )
            raise typer.Exit(2)
        domain_value = str(domain or os.getenv("FINITE_STATE_DOMAIN") or "")
        if not domain_value:
            console.print(
                "[red]Error: Domain required. Set FINITE_STATE_DOMAIN environment variable or use --domain.[/red]"
            )
            raise typer.Exit(2)

        config = Config(
            auth_token=auth_token,
            domain=domain_value,
            recipes_dir=str(recipes or Path("./recipes")),
            output_dir="./output",
            start_date="2025-01-01",
            end_date="2025-01-31",
            verbose=verbose,
        )

        console.print("[bold cyan]Fetching available projects...[/bold cyan]")

        from fs_report.api_client import APIClient
        from fs_report.models import QueryConfig, QueryParams

        api_client = APIClient(config)
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=1000, archived=False, excluded=False),
        )
        projects = api_client.fetch_data(projects_query)

        if not projects:
            console.print("[yellow]No projects found.[/yellow]")
            return

        # Create a rich table to display projects
        table = Table(title=f"Available Projects ({len(projects)} found)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Folder", style="yellow")
        table.add_column("Archived", style="dim")

        for project in projects:
            project_id = project.get("id", "N/A")
            project_name = project.get("name", "Unknown")
            folder = project.get("folder")
            folder_name = folder.get("name", "") if isinstance(folder, dict) else ""
            archived = "Yes" if project.get("archived", False) else "No"
            table.add_row(str(project_id), project_name, folder_name, archived)

        console.print(table)
        console.print(
            "\n[dim]Use --project with project name or ID to filter reports.[/dim]"
        )
        console.print(
            "[dim]Use --folder with folder name or ID to scope reports to a folder.[/dim]"
        )

    except Exception as e:
        logger.exception("Error fetching projects")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


@app.command()
def list_folders(
    recipes: Union[Path, None] = typer.Option(
        None,
        "--recipes",
        "-r",
        help="Path to recipes directory",
        dir_okay=True,
        file_okay=False,
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        "-t",
        help="Finite State API token",
        hide_input=True,
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (e.g., customer.finitestate.io)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """List all available folders with hierarchy."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    try:
        # Create minimal config for API access
        auth_token = str(token or os.getenv("FINITE_STATE_AUTH_TOKEN") or "")
        if not auth_token:
            console.print(
                "[red]Error: API token required. Set FINITE_STATE_AUTH_TOKEN environment variable or use --token.[/red]"
            )
            raise typer.Exit(2)
        domain_value = str(domain or os.getenv("FINITE_STATE_DOMAIN") or "")
        if not domain_value:
            console.print(
                "[red]Error: Domain required. Set FINITE_STATE_DOMAIN environment variable or use --domain.[/red]"
            )
            raise typer.Exit(2)

        config = Config(
            auth_token=auth_token,
            domain=domain_value,
            recipes_dir=str(recipes or Path("./recipes")),
            output_dir="./output",
            start_date="2025-01-01",
            end_date="2025-01-31",
            verbose=verbose,
        )

        console.print("[bold cyan]Fetching available folders...[/bold cyan]")

        from fs_report.api_client import APIClient
        from fs_report.models import QueryConfig, QueryParams

        api_client = APIClient(config)
        folders_query = QueryConfig(
            endpoint="/public/v0/folders",
            params=QueryParams(limit=1000),
        )
        folders = api_client.fetch_data(folders_query)

        if not folders:
            console.print("[yellow]No folders found.[/yellow]")
            return

        # Build parent-child hierarchy
        folder_by_id: dict[str, dict] = {}
        children_map: dict[str | None, list[dict]] = {}
        for folder in folders:
            fid = str(folder.get("id", ""))
            folder_by_id[fid] = folder
            parent_id = folder.get("parentFolderId")
            parent_key = str(parent_id) if parent_id else None
            children_map.setdefault(parent_key, []).append(folder)

        from rich.tree import Tree

        tree = Tree("[bold cyan]Folders[/bold cyan]")

        def _add_children(parent_node: Tree, parent_id: str | None) -> None:
            children = children_map.get(parent_id, [])
            children.sort(key=lambda f: f.get("name", ""))
            for child in children:
                cid = str(child.get("id", ""))
                name = child.get("name", "Unknown")
                count = child.get("projectCount", 0)
                label = f"[green]{name}[/green]  [dim](ID: {cid}, {count} project{'s' if count != 1 else ''})[/dim]"
                child_node = parent_node.add(label)
                _add_children(child_node, cid)

        _add_children(tree, None)

        console.print(tree)
        console.print(
            f"\n[dim]Total: {len(folders)} folder(s). Use --folder with folder name or ID to scope reports.[/dim]"
        )

    except Exception as e:
        logger.exception("Error fetching folders")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


@app.command()
def list_versions(
    project: Union[str, None] = typer.Argument(
        None,
        help="Project name or ID to list versions for (omit to list all versions across portfolio)",
    ),
    show_top: int = typer.Option(
        0,
        "--top",
        "-n",
        help="Only show top N projects by version count (0 = show all)",
        min=0,
    ),
    folder_filter: Union[str, None] = typer.Option(
        None,
        "--folder",
        "-f",
        help="Only include projects in this folder (name or ID). Use 'fs-report list-folders' to see options. Cuts down API calls when you only need a subset.",
    ),
    recipes: Union[Path, None] = typer.Option(
        None,
        "--recipes",
        "-r",
        help="Path to recipes directory",
        dir_okay=True,
        file_okay=False,
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        "-t",
        help="Finite State API token",
        hide_input=True,
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (e.g., customer.finitestate.io)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """List all versions for a specific project, or all versions across the portfolio."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    try:
        # Create minimal config for API access
        auth_token = str(token or os.getenv("FINITE_STATE_AUTH_TOKEN") or "")
        if not auth_token:
            console.print(
                "[red]Error: API token required. Set FINITE_STATE_AUTH_TOKEN environment variable or use --token.[/red]"
            )
            raise typer.Exit(2)
        domain_value = str(domain or os.getenv("FINITE_STATE_DOMAIN") or "")
        if not domain_value:
            console.print(
                "[red]Error: Domain required. Set FINITE_STATE_DOMAIN environment variable or use --domain.[/red]"
            )
            raise typer.Exit(2)

        config = Config(
            auth_token=auth_token,
            domain=domain_value,
            recipes_dir=str(recipes or Path("./recipes")),
            output_dir="./output",
            start_date="2025-01-01",
            end_date="2025-01-31",
            verbose=verbose,
        )

        import httpx

        from fs_report.api_client import APIClient
        from fs_report.models import QueryConfig, QueryParams

        api_client = APIClient(config)

        # Resolve project list: either from folder (fewer API calls) or all projects
        if folder_filter and not project:
            # Scope to folder: fetch folder tree and projects in it (no need to pull all projects)
            from collections import deque

            folders = api_client.fetch_data(
                QueryConfig(
                    endpoint="/public/v0/folders", params=QueryParams(limit=10000)
                )
            )
            if not folders:
                console.print("[yellow]No folders found.[/yellow]")
                return
            {str(f["id"]): f for f in folders}
            children_map: dict[str, list[str]] = {}
            for f in folders:
                parent = f.get("parentFolderId")
                if parent:
                    children_map.setdefault(str(parent), []).append(str(f["id"]))
            # Resolve folder by name or ID
            target_folder = None
            for f in folders:
                if str(f.get("id", "")) == folder_filter or (
                    f.get("name", "").lower() == folder_filter.lower()
                ):
                    target_folder = f
                    break
            if not target_folder:
                console.print(
                    f"[red]Folder not found: '{folder_filter}'. Use 'fs-report list-folders' to see options.[/red]"
                )
                raise typer.Exit(2)
            folder_id = str(target_folder["id"])
            queue = deque([folder_id])
            all_folder_ids = set()
            while queue:
                fid = queue.popleft()
                all_folder_ids.add(fid)
                for cid in children_map.get(fid, []):
                    if cid not in all_folder_ids:
                        queue.append(cid)
            # Collect (id, name) from each folder's projects (dedupe by id)
            projects_by_id = {}
            for fid in all_folder_ids:
                try:
                    folder_projects = api_client.fetch_data(
                        QueryConfig(
                            endpoint=f"/public/v0/folders/{fid}/projects",
                            params=QueryParams(
                                limit=10000, archived=False, excluded=False
                            ),
                        )
                    )
                    for p in folder_projects:
                        pid = p.get("id")
                        if pid and str(pid) not in projects_by_id:
                            projects_by_id[str(pid)] = {
                                "id": pid,
                                "name": p.get("name", str(pid)),
                            }
                except Exception as e:
                    logger.debug("Error fetching projects for folder %s: %s", fid, e)
            projects = list(projects_by_id.values())
            console.print(
                f"[dim]Scoped to folder '{target_folder.get('name', folder_filter)}': {len(projects)} project(s)[/dim]"
            )
        else:
            # Fetch all projects using pagination to get beyond 1000 limit
            projects_query = QueryConfig(
                endpoint="/public/v0/projects",
                params=QueryParams(
                    limit=1000, archived=False
                ),  # Exclude archived projects
            )
            projects = api_client.fetch_all_with_resume(projects_query)

        if project:
            # Single project mode - existing behavior
            console.print(
                f"[bold cyan]Fetching versions for project: {project}[/bold cyan]"
            )

            # Find the project by name or ID
            target_project = None
            try:
                # Try to parse as project ID first
                project_id = int(project)
                target_project = next(
                    (p for p in projects if p.get("id") == project_id), None
                )
            except ValueError:
                # Not an integer, search by name (case-insensitive)
                target_project = next(
                    (
                        p
                        for p in projects
                        if p.get("name", "").lower() == project.lower()
                    ),
                    None,
                )

            if not target_project:
                console.print(f"[red]Error: Project '{project}' not found.[/red]")
                console.print(
                    "[yellow]Use 'fs-report list-projects' to see available projects.[/yellow]"
                )
                raise typer.Exit(1)

            project_id = target_project["id"]
            project_name = target_project["name"]

            console.print(
                f"[green]Found project: {project_name} (ID: {project_id})[/green]"
            )

            # Get the default branch from the project data
            default_branch = target_project.get("defaultBranch")
            if not default_branch:
                console.print(
                    f"[yellow]No default branch found for project '{project_name}'.[/yellow]"
                )
                return

            branch_id = default_branch.get("id")
            branch_name = default_branch.get("name", "Unknown")

            if not branch_id:
                console.print(
                    f"[yellow]No valid default branch found for project '{project_name}'.[/yellow]"
                )
                return

            console.print(
                f"[green]Using default branch: {branch_name} (ID: {branch_id})[/green]"
            )

            # Now fetch versions for this project (using the new endpoint)
            console.print(f"[dim]Fetching versions for project: {project_name}[/dim]")
            try:
                # Use the new project versions endpoint (returns all versions, no pagination)
                url = f"https://{config.domain}/api/public/v0/projects/{project_id}/versions"

                headers = {"X-Authorization": config.auth_token}

                with httpx.Client(timeout=30.0) as client:
                    response = client.get(url, headers=headers)
                    response.raise_for_status()
                    versions = response.json()

                    if not isinstance(versions, list):
                        versions = []

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    console.print(
                        f"[red]Error: Rate limit exceeded while fetching versions for '{project_name}'.[/red]"
                    )
                    console.print(
                        "[yellow]Please wait a moment and try again.[/yellow]"
                    )
                elif e.response.status_code in (502, 503, 504):
                    console.print(
                        f"[red]Error: Server timeout (HTTP {e.response.status_code}) for '{project_name}'.[/red]"
                    )
                else:
                    console.print(
                        f"[red]Error fetching versions: HTTP {e.response.status_code}[/red]"
                    )
                raise typer.Exit(1) from e
            except httpx.TimeoutException:
                console.print(
                    f"[red]Error: Request timeout for '{project_name}'.[/red]"
                )
                raise typer.Exit(1)
            except Exception as e:
                console.print(f"[red]Error fetching versions: {e}[/red]")
                raise typer.Exit(1) from e

            if not versions:
                console.print(
                    f"[yellow]No versions found for project '{project_name}' in branch '{branch_name}'.[/yellow]"
                )
                return

            # Debug: Show the first version's structure
            if versions and config.verbose:
                console.print(
                    f"[dim]Debug: First version structure: {versions[0]}[/dim]"
                )

            # Create a rich table to display versions
            table = Table(
                title=f"Versions for '{project_name}' - Branch: '{branch_name}' ({len(versions)} found)"
            )
            table.add_column("ID", style="cyan", no_wrap=True)
            table.add_column("Name", style="green")
            table.add_column("Created", style="dim")

            for version in versions:
                version_id = version.get("id", "N/A")
                version_name = version.get(
                    "version", "N/A"
                )  # Use "version" field, not "name"
                created = version.get("created", "N/A")

                # Format the created date if it exists
                if created and created != "N/A":
                    try:
                        # Parse ISO date and format it nicely
                        from datetime import datetime

                        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        created = dt.strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        pass

                table.add_row(str(version_id), version_name, created)

            console.print(table)

            console.print(
                "\n[dim]Use --version <ID> to filter reports to a specific version.[/dim]"
            )

        else:
            # Portfolio mode - list version counts across all projects (parallel fetch)
            console.print(
                "[bold cyan]Fetching version counts across all projects...[/bold cyan]"
            )

            if not projects:
                console.print("[yellow]No projects found.[/yellow]")
                return

            import time
            from concurrent.futures import ThreadPoolExecutor, as_completed

            rate_limit_backoff = 5.0
            max_retries = 3
            max_workers = 10  # parallel requests; avoid hammering the API

            def fetch_version_count(
                proj: dict,
            ) -> tuple[str, int, str] | tuple[str, None, str]:
                """Fetch versions for one project; return (name, version_count, id) or (name, None, id) on error."""
                proj_id = proj.get("id")
                proj_name = proj.get("name", "Unknown")
                headers = {"X-Authorization": config.auth_token}
                for attempt in range(max_retries):
                    try:
                        with httpx.Client(timeout=30.0) as client:
                            url = f"https://{config.domain}/api/public/v0/projects/{proj_id}/versions"
                            response = client.get(url, headers=headers)
                            response.raise_for_status()
                            versions = response.json()
                        if not isinstance(versions, list):
                            versions = []
                        return (proj_name, len(versions), str(proj_id))
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code == 429 and attempt < max_retries - 1:
                            time.sleep(rate_limit_backoff * (attempt + 1))
                            continue
                    except (httpx.TimeoutException, Exception):
                        if attempt < max_retries - 1:
                            time.sleep(2.0)
                            continue
                    return (proj_name, None, str(proj_id))
                return (proj_name, None, str(proj_id))

            from tqdm import tqdm

            project_version_counts = []
            skipped_projects = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(fetch_version_count, proj): proj
                    for proj in projects
                }
                for future in tqdm(
                    as_completed(futures),
                    total=len(futures),
                    desc="Fetching version counts",
                    unit="project",
                ):
                    name, count, pid = future.result()
                    if count is not None:
                        project_version_counts.append(
                            {
                                "project_name": name,
                                "project_id": pid,
                                "version_count": count,
                            }
                        )
                    else:
                        skipped_projects.append(name)

            # Display summary table
            total_versions = sum(p["version_count"] for p in project_version_counts)  # type: ignore[misc]
            projects_with_versions = sum(
                1  # type: ignore[misc]
                for p in project_version_counts
                if p["version_count"] > 0  # type: ignore[operator]
            )

            console.print(
                f"\n[bold green]Portfolio Summary: {total_versions} versions across {projects_with_versions} projects[/bold green]"
            )
            if skipped_projects:
                console.print(
                    f"[yellow]({len(skipped_projects)} project(s) skipped due to errors)[/yellow]"
                )

            # Sort by version count descending
            project_version_counts.sort(key=lambda x: x["version_count"], reverse=True)  # type: ignore[arg-type, return-value]

            # Apply --top filter if specified
            display_counts = project_version_counts
            if show_top > 0:
                display_counts = project_version_counts[:show_top]

            # Create summary table
            title = f"Versions by Project ({len(project_version_counts)} projects)"
            if show_top > 0 and len(project_version_counts) > show_top:
                title = f"Top {show_top} Projects by Version Count (of {len(project_version_counts)} total)"
            table = Table(title=title)
            table.add_column("Project", style="cyan")
            table.add_column("Versions", style="green", justify="right")
            table.add_column("Project ID", style="dim")

            for pvc in display_counts:
                table.add_row(
                    str(pvc["project_name"]),
                    str(pvc["version_count"]),
                    str(pvc["project_id"]),
                )

            console.print(table)

            if show_top > 0 and len(project_version_counts) > show_top:
                console.print(
                    f"\n[dim]Showing top {show_top} of {len(project_version_counts)} projects. Remove --top to see all.[/dim]"
                )

            console.print(
                "\n[dim]Use 'fs-report list-versions <project>' to see detailed versions for a specific project.[/dim]"
            )

    except Exception as e:
        logger.exception("Error fetching versions")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


def run_reports(
    recipes: Union[Path, None],
    recipe: Union[list[str], None],
    output: Union[Path, None],
    start: Union[str, None],
    end: Union[str, None],
    period: Union[str, None],
    token: Union[str, None],
    domain: Union[str, None],
    verbose: bool,
    data_file: Union[str, None],
    project_filter: Union[str, None],
    version_filter: Union[str, None],
    folder_filter: Union[str, None] = None,
    finding_types: str = "cve",
    current_version_only: bool = True,
    cache_ttl: int = 0,
    cache_dir: Union[str, None] = None,
    detected_after: Union[str, None] = None,
    ai: bool = False,
    ai_provider: Union[str, None] = None,
    ai_depth: str = "summary",
    ai_prompts: bool = False,
    nvd_api_key: Union[str, None] = None,
    baseline_date: Union[str, None] = None,
    baseline_version: Union[str, None] = None,
    current_version: Union[str, None] = None,
    open_only: bool = False,
    request_delay: float = 0.5,
    batch_size: int = 5,
    cve_filter: Union[str, None] = None,
    scoring_file: Union[str, None] = None,
    vex_override: bool = False,
    overwrite: bool = False,
) -> None:
    setup_logging(verbose)
    logger = logging.getLogger(__name__)
    try:
        data_override = None
        if data_file:
            with open(data_file) as f:
                data_override = json.load(f)
        config = create_config(
            recipes=recipes,
            output=output,
            start=start,
            end=end,
            period=period,
            token=token,
            domain=domain,
            verbose=verbose,
            recipe=None,  # We'll handle filtering below
            data_file=data_file,
            project_filter=project_filter,
            version_filter=version_filter,
            folder_filter=folder_filter,
            finding_types=finding_types,
            current_version_only=current_version_only,
            cache_ttl=cache_ttl,
            cache_dir=cache_dir,
            detected_after=detected_after,
            ai=ai,
            ai_provider=ai_provider,
            ai_depth=ai_depth,
            ai_prompts=ai_prompts,
            nvd_api_key=nvd_api_key,
            baseline_date=baseline_date,
            baseline_version=baseline_version,
            current_version=current_version,
            open_only=open_only,
            request_delay=request_delay,
            batch_size=batch_size,
            cve_filter=cve_filter,
            scoring_file=scoring_file,
            vex_override=vex_override,
            overwrite=overwrite,
        )
        logger.info("Configuration:")
        logger.info(f"  Domain: {config.domain}")
        logger.info(f"  Token: {redact_token(config.auth_token)}")
        logger.info(f"  Recipes directory: {config.recipes_dir}")
        logger.info(f"  Output directory: {config.output_dir}")
        logger.info(f"  Date range: {config.start_date} to {config.end_date}")
        logger.info(f"  Finding types: {config.finding_types}")
        if config.current_version_only:
            logger.info("  Current version only: Yes (filtering to latest versions)")
        if config.cache_ttl > 0:
            logger.info(f"  [BETA] SQLite cache: Enabled (TTL: {config.cache_ttl}s)")
        if config.folder_filter:
            logger.info(f"  Folder scope: {config.folder_filter}")
        if config.cve_filter:
            logger.info(f"  CVE filter: {config.cve_filter}")
        if config.ai:
            provider_info = (
                f", provider: {config.ai_provider}" if config.ai_provider else ""
            )
            logger.info(
                f"  AI remediation: Enabled (depth: {config.ai_depth}{provider_info})"
            )
        output_path = Path(config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        engine = ReportEngine(config, data_override=data_override)
        # Patch API client if using data_override
        if data_override is not None:

            class MockAPIClient:
                def __init__(self, data: dict[str, Any]) -> None:
                    self.data = data

                def fetch_data(self, query_config: Any) -> list[dict[str, Any]]:
                    endpoint = query_config.endpoint
                    for key in self.data:
                        if key in endpoint or key in getattr(query_config, "name", ""):
                            data = self.data[key]
                            if isinstance(data, list):
                                return data
                            else:
                                return [data] if data else []
                    if len(self.data) == 1:
                        data = list(self.data.values())[0]
                        if isinstance(data, list):
                            return data
                        else:
                            return [data] if data else []
                    return []

            engine.api_client = MockAPIClient(data_override)  # type: ignore[assignment]
        # Run the engine and check if any recipes failed
        # Filter recipes if recipe argument is provided
        if recipe:
            if isinstance(recipe, str):  # type: ignore[unreachable]
                recipe_list = [recipe]  # type: ignore[unreachable]
            else:
                recipe_list = recipe
            engine.recipe_loader.recipe_filter = [r.lower() for r in recipe_list]
        success = engine.run()
        if success:
            console.print("[green]Report generation completed successfully![/green]")
        else:
            console.print("[red]Report generation failed![/red]")
            raise typer.Exit(1)
    except typer.Exit:
        raise  # Let controlled exits pass through cleanly
    except FileExistsError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    except ValueError as e:
        console.print(f"[red]Validation error: {e}[/red]")
        raise typer.Exit(1) from e
    except Exception as e:
        logger.exception("Unexpected error occurred")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    recipes: Union[Path, None] = typer.Option(
        None,
        "--recipes",
        "-r",
        help="Path to recipes directory",
        dir_okay=True,
        file_okay=False,
    ),
    recipe: list[str] = typer.Option(
        None,
        "--recipe",
        help="Name of specific recipe(s) to run (can be specified multiple times)",
    ),
    output: Union[Path, None] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory for reports",
        dir_okay=True,
        file_okay=False,
    ),
    start: Union[str, None] = typer.Option(
        None,
        "--start",
        "-s",
        help="Start date (ISO8601 format, e.g., 2025-01-01)",
    ),
    end: Union[str, None] = typer.Option(
        None,
        "--end",
        "-e",
        help="End date (ISO8601 format, e.g., 2025-01-31)",
    ),
    period: Union[str, None] = typer.Option(
        None,
        "--period",
        "-p",
        help="Time period (e.g., '7d', '1m', 'Q1', '2024', 'monday', 'january-2024')",
    ),
    token: Union[str, None] = typer.Option(
        None,
        "--token",
        "-t",
        help="Finite State API token",
        hide_input=True,
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (e.g., customer.finitestate.io)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
    data_file: Union[str, None] = typer.Option(
        None,
        "--data-file",
        "-df",
        help="Path to local JSON file to use as data source",
    ),
    project_filter: Union[str, None] = typer.Option(
        None,
        "--project",
        "-pr",
        help="Filter by project (name or ID). Use 'fs-report list-projects' to see available projects.",
    ),
    folder_filter: Union[str, None] = typer.Option(
        None,
        "--folder",
        "-fl",
        help="Scope reports to a folder (name or ID, includes subfolders). Use 'fs-report list-folders' to see available folders.",
    ),
    version_filter: Union[str, None] = typer.Option(
        None,
        "--version",
        "-V",
        help="Filter by project version (version ID or name). Use 'fs-report list-versions <project>' to see available versions.",
    ),
    finding_types: str = typer.Option(
        "cve",
        "--finding-types",
        "-ft",
        help="Finding types to include: cve (default), sast, binary_sca, source_sca, thirdparty, credentials, config_issues, crypto_material, or 'all'. Comma-separated for multiple.",
    ),
    current_version_only: bool = typer.Option(
        True,
        "--current-version-only/--all-versions",
        "-cvo/-av",
        help="Latest version only (default, fast) or all versions (slow, includes historical data)",
    ),
    cache_ttl: Union[str, None] = typer.Option(
        None,
        "--cache-ttl",
        help="[BETA] Enable persistent SQLite cache with TTL (e.g., '4' for 4 hours, '30m', '1d'). "
        "Bare numbers are hours. Default: disabled (fresh data each run).",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Force fresh data fetch, ignore any cached data.",
    ),
    clear_cache: bool = typer.Option(
        False,
        "--clear-cache",
        help="Delete all cached API data and exit.",
    ),
    clear_ai_cache: bool = typer.Option(
        False,
        "--clear-ai-cache",
        help="Delete cached AI remediation guidance and exit.",
    ),
    detected_after: Union[str, None] = typer.Option(
        None,
        "--detected-after",
        help="Only include findings detected on or after this date (YYYY-MM-DD). "
        "Applies to Assessment reports (CVA, Findings by Project, Triage, Component List).",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enable AI remediation guidance for Triage Prioritization and CVE Impact "
        "(requires ANTHROPIC_AUTH_TOKEN, OPENAI_API_KEY, or GITHUB_TOKEN)",
    ),
    ai_provider: Union[str, None] = typer.Option(
        None,
        "--ai-provider",
        help="LLM provider: 'anthropic', 'openai', or 'copilot'. Auto-detected from env vars if not set.",
    ),
    ai_depth: str = typer.Option(
        "summary",
        "--ai-depth",
        help="AI depth: 'summary' (portfolio/project only) or 'full' (+ Critical/High component guidance)",
    ),
    ai_prompts: bool = typer.Option(
        False,
        "--ai-prompts",
        help="Export AI prompts to file and HTML for use with any LLM. No API key required. Can be combined with --ai.",
    ),
    nvd_api_key: Union[str, None] = typer.Option(
        None,
        "--nvd-api-key",
        envvar="NVD_API_KEY",
        help="NVD API key for faster fix-version lookups (10x rate limit). "
        "Free from https://nvd.nist.gov/developers/request-an-api-key. "
        "Also reads NVD_API_KEY env var. "
        "Per NVD terms, keys must not be shared with other individuals or organisations.",
    ),
    baseline_date: Union[str, None] = typer.Option(
        None,
        "--baseline-date",
        help="Baseline date (YYYY-MM-DD) for Security Progress report. "
        "Overrides the default of using the earliest version in the period window.",
    ),
    baseline_version: Union[str, None] = typer.Option(
        None,
        "--baseline-version",
        help="Baseline version ID for Version Comparison report.",
    ),
    current_version: Union[str, None] = typer.Option(
        None,
        "--current-version",
        help="Current version ID for Version Comparison report.",
    ),
    open_only: bool = typer.Option(
        False,
        "--open-only",
        help="Only count open findings in Security Progress (exclude NOT_AFFECTED, FALSE_POSITIVE, RESOLVED, RESOLVED_WITH_PEDIGREE).",
    ),
    request_delay: float = typer.Option(
        0.5,
        "--request-delay",
        help="Delay in seconds between API requests to avoid overloading the server. "
        "Increase for large portfolios (e.g. 1.0), decrease for small runs (e.g. 0.1).",
    ),
    batch_size: int = typer.Option(
        5,
        "--batch-size",
        help="Number of project versions to fetch per API batch. "
        "Lower values reduce server load (use 3 for very large instances). "
        "Higher values are faster but may overload smaller servers (default 5, max 25).",
        min=1,
        max=25,
    ),
    cve_filter: Union[str, None] = typer.Option(
        None,
        "--cve",
        help="CVE(s) to analyse in the CVE Impact report (required). "
        "Comma-separated (e.g. CVE-2024-1234,CVE-2024-5678). "
        "Produces detailed dossiers for the specified CVEs. "
        "Optionally combine with --project to narrow results to one project.",
    ),
    scoring_file: Union[str, None] = typer.Option(
        None,
        "--scoring-file",
        help="Path to a YAML file with custom scoring weights for Triage Prioritization. "
        "Overrides the default weights in the recipe.",
    ),
    vex_override: bool = typer.Option(
        False,
        "--vex-override",
        help="Overwrite existing VEX statuses when generating triage recommendations. "
        "By default, findings that already have a VEX status are skipped.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing report files. Without this flag, the CLI refuses "
        "to write into a recipe output directory that already has files.",
    ),
    serve: bool = typer.Option(
        False,
        "--serve",
        help="After generating reports, start a local HTTP server on the output directory. "
        "This is needed when using interactive Jira/triage buttons if CORS blocks file:// requests. "
        "Opens http://localhost:8080 in your browser.",
    ),
    serve_port: int = typer.Option(
        8080,
        "--serve-port",
        help="Port for the local HTTP server (used with --serve).",
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return

    # Handle --clear-cache and/or --clear-ai-cache
    if clear_cache or clear_ai_cache:
        if clear_cache:
            cache_domain = domain or os.getenv("FINITE_STATE_DOMAIN")
            cache = SQLiteCache(domain=cache_domain)
            cache.clear()
            console.print("[green]API data cache cleared successfully.[/green]")
            console.print(f"[dim]Cache location: {cache.db_path}[/dim]")
            if cache_domain:
                console.print(f"[dim]Domain: {cache_domain}[/dim]")

        if clear_ai_cache:
            ai_cache_dir = Path.home() / ".fs-report"
            ai_cache_db = ai_cache_dir / "cache.db"
            if ai_cache_db.exists():
                ai_cache_db.unlink()
                console.print(
                    "[green]AI remediation cache cleared successfully.[/green]"
                )
            else:
                console.print("[yellow]No AI cache found (nothing to clear).[/yellow]")
            console.print(f"[dim]Cache location: {ai_cache_db}[/dim]")

        raise typer.Exit(0)

    # Parse cache TTL
    cache_ttl_seconds = 0
    if no_cache:
        cache_ttl_seconds = 0
    elif cache_ttl:
        try:
            cache_ttl_seconds = parse_ttl(cache_ttl)
            if cache_ttl_seconds > 0:
                console.print(
                    f"[cyan][BETA] SQLite cache enabled with TTL: {cache_ttl} ({cache_ttl_seconds} seconds)[/cyan]"
                )
        except ValueError as e:
            console.print(f"[red]Error: Invalid cache TTL format: {e}[/red]")
            raise typer.Exit(1)

    run_reports(
        recipes=recipes,
        recipe=recipe,
        output=output,
        start=start,
        end=end,
        period=period,
        token=token,
        domain=domain,
        verbose=verbose,
        data_file=data_file,
        project_filter=project_filter,
        version_filter=version_filter,
        folder_filter=folder_filter,
        finding_types=finding_types,
        current_version_only=current_version_only,
        cache_ttl=cache_ttl_seconds,
        cache_dir=str(Path.home() / ".fs-report") if cache_ttl_seconds > 0 else None,
        detected_after=detected_after,
        ai=ai,
        ai_provider=ai_provider,
        ai_depth=ai_depth,
        ai_prompts=ai_prompts,
        nvd_api_key=nvd_api_key,
        baseline_date=baseline_date,
        baseline_version=baseline_version,
        current_version=current_version,
        open_only=open_only,
        request_delay=request_delay,
        batch_size=batch_size,
        cve_filter=cve_filter,
        scoring_file=scoring_file,
        vex_override=vex_override,
        overwrite=overwrite,
    )

    # Launch local HTTP server if requested (helps with CORS for interactive buttons)
    if serve:
        _serve_reports(output or Path("output"), serve_port)


def _serve_reports(output_dir: Path, port: int) -> None:
    """Start a local HTTP server that serves reports and proxies API calls.

    Static files are served from *output_dir*.  Requests to ``/fsapi/``
    are proxied to the Finite State API (the target domain is read from
    the ``X-FS-Domain`` request header).  This avoids CORS issues because
    the browser only talks to ``localhost`` and the server-to-server
    forwarding isn't subject to browser same-origin policy.
    """
    import http.server
    import socketserver
    import threading
    import urllib.error
    import urllib.request
    import webbrowser

    output_dir = Path(output_dir).expanduser().resolve()
    if not output_dir.exists():
        console.print(f"[red]Output directory not found: {output_dir}[/red]")
        raise typer.Exit(1)

    serve_dir = str(output_dir)

    class ProxyHandler(http.server.SimpleHTTPRequestHandler):
        """Serves static files and proxies /fsapi/ requests."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=serve_dir, **kwargs)

        # --- API proxy ------------------------------------------------

        def _is_proxy(self) -> bool:
            return self.path.startswith("/fsapi/")

        def _proxy(self) -> None:
            domain = self.headers.get("X-FS-Domain", "")
            if not domain:
                self._send_json(400, {"error": "Missing X-FS-Domain header"})
                return

            # Build upstream URL: /fsapi/public/v0/... -> https://domain/api/public/v0/...
            upstream_path = self.path[len("/fsapi") :]  # strip /fsapi prefix
            upstream_url = f"https://{domain}/api{upstream_path}"

            # Read request body (for POST/PUT)
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            # Forward headers (auth token, content type)
            fwd_headers: dict[str, str] = {}
            for h in ("X-Authorization", "Content-Type", "Accept"):
                val = self.headers.get(h)
                if val:
                    fwd_headers[h] = val

            try:
                req = urllib.request.Request(
                    upstream_url,
                    data=body,
                    headers=fwd_headers,
                    method=self.command,
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp_body = resp.read()
                    self.send_response(resp.status)
                    self.send_header(
                        "Content-Type",
                        resp.headers.get("Content-Type", "application/json"),
                    )
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(resp_body)
            except urllib.error.HTTPError as e:
                error_body = e.read()
                self.send_response(e.code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(error_body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(error_body)
            except Exception as e:
                msg = json.dumps({"error": str(e)}).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(msg)

        def _send_json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        # --- HTTP method overrides ------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            if self._is_proxy():
                self._proxy()
            else:
                super().do_GET()

        def do_POST(self) -> None:  # noqa: N802
            if self._is_proxy():
                self._proxy()
            else:
                self.send_error(405, "POST not supported for static files")

        def do_PUT(self) -> None:  # noqa: N802
            if self._is_proxy():
                self._proxy()
            else:
                self.send_error(405, "PUT not supported for static files")

        def do_OPTIONS(self) -> None:  # noqa: N802
            """Handle CORS preflight requests."""
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "X-Authorization, X-FS-Domain, Content-Type, Accept",
            )
            self.send_header("Access-Control-Max-Age", "86400")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            """Suppress noisy per-request logs; show clean proxy summary."""
            if self._is_proxy():
                # Show a short, readable summary instead of full URLs
                path = self.path
                if "/authUser" in path:
                    label = "Authenticating..."
                elif "/tracker/tickets/ping" in path:
                    label = "Checking Jira integration..."
                elif "/findings" in path and "/status/clear" in path:
                    label = "Clearing finding status..."
                elif "/findings" in path and "/status" in path:
                    label = "Updating finding status..."
                elif "/findings" in path and "filter=" in path:
                    label = "Refreshing finding statuses..."
                elif "/findings" in path:
                    label = "Fetching findings..."
                else:
                    label = f"{self.command} ...{path.split('/')[-1][:40]}"
                console.print(f"[dim]  {label}[/dim]")

    console.print(f"\n[cyan]Starting local server on http://localhost:{port}[/cyan]")
    console.print(f"[dim]Serving: {output_dir}[/dim]")
    console.print("[dim]API proxy: /fsapi/* → Finite State API[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    # Find the first HTML report to open directly
    html_files = sorted(
        output_dir.rglob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    if html_files:
        # Use the most recently modified HTML file, build a relative URL
        open_path = html_files[0].relative_to(output_dir)
        open_url = f"http://localhost:{port}/{open_path}"
    else:
        open_url = f"http://localhost:{port}"
    console.print(f"[cyan]Opening: {open_url}[/cyan]")

    # Open browser after a short delay
    def _open_browser() -> None:
        import time as _time

        _time.sleep(0.5)
        webbrowser.open(open_url)

    threading.Thread(target=_open_browser, daemon=True).start()

    with socketserver.TCPServer(("", port), ProxyHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow]Server stopped.[/yellow]")


if __name__ == "__main__":
    app(prog_name="fs-report")
