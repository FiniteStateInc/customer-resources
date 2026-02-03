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
from typing import Any, Union, List

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
    finding_types: str = "cve",
    current_version_only: bool = True,
    cache_ttl: int = 0,
    cache_dir: Union[str, None] = None,
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
    valid_finding_types = {"cve", "sast", "thirdparty", "credentials", "config_issues", "crypto_material", "all"}
    if finding_types:
        types_list = [t.strip().lower() for t in finding_types.split(",")]
        invalid_types = set(types_list) - valid_finding_types
        if invalid_types:
            console.print(f"[red]Error: Invalid finding type(s): {', '.join(invalid_types)}[/red]")
            console.print(f"[yellow]Valid types: {', '.join(sorted(valid_finding_types))}[/yellow]")
            raise typer.Exit(1)
    
    return Config(
        auth_token=auth_token,
        domain=domain_value,
        recipes_dir=str(recipes or Path("./recipes")),
        output_dir=str(output or Path("./output")),
        start_date=start,
        end_date=end,
        verbose=verbose,
        recipe_filter=recipe,
        project_filter=project_filter,
        version_filter=version_filter,
        finding_types=finding_types,
        current_version_only=current_version_only,
        cache_ttl=cache_ttl,
        cache_dir=cache_dir,
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
            params=QueryParams(limit=1000, archived=False)
        )
        projects = api_client.fetch_data(projects_query)
        
        if not projects:
            console.print("[yellow]No projects found.[/yellow]")
            return
        
        # Create a rich table to display projects
        table = Table(title=f"Available Projects ({len(projects)} found)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Archived", style="dim")
        
        for project in projects:
            project_id = project.get("id", "N/A")
            project_name = project.get("name", "Unknown")
            archived = "Yes" if project.get("archived", False) else "No"
            table.add_row(str(project_id), project_name, archived)
        
        console.print(table)
        console.print("\n[dim]Use --project with project name or ID to filter reports.[/dim]")

    except Exception as e:
        logger.exception("Error fetching projects")
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
        
        from fs_report.api_client import APIClient
        from fs_report.models import QueryConfig, QueryParams
        import httpx
        
        api_client = APIClient(config)
        
        # Fetch all projects using pagination to get beyond 1000 limit
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=1000, archived=False)  # Exclude archived projects
        )
        projects = api_client.fetch_all_with_resume(projects_query)
        
        if project:
            # Single project mode - existing behavior
            console.print(f"[bold cyan]Fetching versions for project: {project}[/bold cyan]")
            
            # Find the project by name or ID
            target_project = None
            try:
                # Try to parse as project ID first
                project_id = int(project)
                target_project = next((p for p in projects if p.get("id") == project_id), None)
            except ValueError:
                # Not an integer, search by name (case-insensitive)
                target_project = next((p for p in projects if p.get("name", "").lower() == project.lower()), None)
            
            if not target_project:
                console.print(f"[red]Error: Project '{project}' not found.[/red]")
                console.print("[yellow]Use 'fs-report list-projects' to see available projects.[/yellow]")
                raise typer.Exit(1)
            
            project_id = target_project["id"]
            project_name = target_project["name"]
            
            console.print(f"[green]Found project: {project_name} (ID: {project_id})[/green]")
            
            # Get the default branch from the project data
            default_branch = target_project.get("defaultBranch")
            if not default_branch:
                console.print(f"[yellow]No default branch found for project '{project_name}'.[/yellow]")
                return
            
            branch_id = default_branch.get("id")
            branch_name = default_branch.get("name", "Unknown")
            
            if not branch_id:
                console.print(f"[yellow]No valid default branch found for project '{project_name}'.[/yellow]")
                return
            
            console.print(f"[green]Using default branch: {branch_name} (ID: {branch_id})[/green]")
            
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
                    console.print(f"[red]Error: Rate limit exceeded while fetching versions for '{project_name}'.[/red]")
                    console.print("[yellow]Please wait a moment and try again.[/yellow]")
                elif e.response.status_code in (502, 503, 504):
                    console.print(f"[red]Error: Server timeout (HTTP {e.response.status_code}) for '{project_name}'.[/red]")
                else:
                    console.print(f"[red]Error fetching versions: HTTP {e.response.status_code}[/red]")
                raise typer.Exit(1) from e
            except httpx.TimeoutException:
                console.print(f"[red]Error: Request timeout for '{project_name}'.[/red]")
                raise typer.Exit(1)
            except Exception as e:
                console.print(f"[red]Error fetching versions: {e}[/red]")
                raise typer.Exit(1) from e
            
            if not versions:
                console.print(f"[yellow]No versions found for project '{project_name}' in branch '{branch_name}'.[/yellow]")
                return
            
            # Debug: Show the first version's structure
            if versions and config.verbose:
                console.print(f"[dim]Debug: First version structure: {versions[0]}[/dim]")
            
            # Create a rich table to display versions
            table = Table(title=f"Versions for '{project_name}' - Branch: '{branch_name}' ({len(versions)} found)")
            table.add_column("ID", style="cyan", no_wrap=True)
            table.add_column("Name", style="green")
            table.add_column("Created", style="dim")
            
            for version in versions:
                version_id = version.get("id", "N/A")
                version_name = version.get("version", "N/A")  # Use "version" field, not "name"
                created = version.get("created", "N/A")
                
                # Format the created date if it exists
                if created and created != "N/A":
                    try:
                        # Parse ISO date and format it nicely
                        from datetime import datetime
                        dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        created = dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        pass
                
                table.add_row(str(version_id), version_name, created)
            
            console.print(table)
            
            console.print(f"\n[dim]Use --version <ID> to filter reports to a specific version.[/dim]")
        
        else:
            # Portfolio mode - list all versions across all projects
            console.print("[bold cyan]Fetching versions across all projects...[/bold cyan]")
            
            if not projects:
                console.print("[yellow]No projects found.[/yellow]")
                return
            
            console.print(f"[dim]Found {len(projects)} projects. Fetching versions for each (this may take a while)...[/dim]")
            
            # Collect all versions with project info
            import time
            from tqdm import tqdm
            
            all_versions = []
            project_version_counts = []
            skipped_projects = []
            headers = {"X-Authorization": config.auth_token}
            
            # Rate limiting settings
            request_delay = 0.1  # 100ms between requests to avoid rate limiting
            rate_limit_backoff = 5.0  # seconds to wait after rate limit
            max_retries = 3
            
            with httpx.Client(timeout=30.0) as client:
                for proj in tqdm(projects, desc="Fetching versions", unit="project"):
                    proj_id = proj.get("id")
                    proj_name = proj.get("name", "Unknown")
                    
                    # Retry logic for rate limiting
                    for attempt in range(max_retries):
                        try:
                            url = f"https://{config.domain}/api/public/v0/projects/{proj_id}/versions"
                            
                            response = client.get(url, headers=headers)
                            response.raise_for_status()
                            versions = response.json()
                            
                            if not isinstance(versions, list):
                                versions = []
                            
                            version_count = len(versions)
                            project_version_counts.append({
                                "project_name": proj_name,
                                "project_id": proj_id,
                                "version_count": version_count,
                            })
                            
                            # Add project info to each version
                            for v in versions:
                                v["_project_name"] = proj_name
                                v["_project_id"] = proj_id
                                all_versions.append(v)
                            
                            # Small delay to avoid rate limiting
                            time.sleep(request_delay)
                            break  # Success, exit retry loop
                                
                        except httpx.HTTPStatusError as e:
                            if e.response.status_code == 429:
                                if attempt < max_retries - 1:
                                    # Rate limited - wait and retry
                                    time.sleep(rate_limit_backoff * (attempt + 1))
                                    continue
                                else:
                                    skipped_projects.append(proj_name)
                            elif e.response.status_code in (502, 503, 504):
                                if attempt < max_retries - 1:
                                    time.sleep(2.0)  # Brief wait for server errors
                                    continue
                                else:
                                    skipped_projects.append(proj_name)
                            else:
                                skipped_projects.append(proj_name)
                                break  # Don't retry other errors
                        except httpx.TimeoutException:
                            if attempt < max_retries - 1:
                                continue
                            else:
                                skipped_projects.append(proj_name)
                        except Exception as e:
                            skipped_projects.append(proj_name)
                            break
            
            # Display summary table
            total_versions = sum(p["version_count"] for p in project_version_counts)
            projects_with_versions = sum(1 for p in project_version_counts if p["version_count"] > 0)
            
            console.print(f"\n[bold green]Portfolio Summary: {total_versions} versions across {projects_with_versions} projects[/bold green]")
            if skipped_projects:
                console.print(f"[yellow]({len(skipped_projects)} project(s) skipped due to errors)[/yellow]")
            
            # Sort by version count descending
            project_version_counts.sort(key=lambda x: x["version_count"], reverse=True)
            
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
                table.add_row(pvc["project_name"], str(pvc["version_count"]), str(pvc["project_id"]))
            
            console.print(table)
            
            if show_top > 0 and len(project_version_counts) > show_top:
                console.print(f"\n[dim]Showing top {show_top} of {len(project_version_counts)} projects. Remove --top to see all.[/dim]")
            
            console.print(f"\n[dim]Use 'fs-report list-versions <project>' to see detailed versions for a specific project.[/dim]")

    except Exception as e:
        logger.exception("Error fetching versions")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


def run_reports(
    recipes: Union[Path, None],
    recipe: Union[List[str], None],
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
    finding_types: str = "cve",
    current_version_only: bool = True,
    cache_ttl: int = 0,
    cache_dir: Union[str, None] = None,
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
            finding_types=finding_types,
            current_version_only=current_version_only,
            cache_ttl=cache_ttl,
            cache_dir=cache_dir,
        )
        logger.info("Configuration:")
        logger.info(f"  Domain: {config.domain}")
        logger.info(f"  Token: {redact_token(config.auth_token)}")
        logger.info(f"  Recipes directory: {config.recipes_dir}")
        logger.info(f"  Output directory: {config.output_dir}")
        logger.info(f"  Date range: {config.start_date} to {config.end_date}")
        logger.info(f"  Finding types: {config.finding_types}")
        if config.current_version_only:
            logger.info(f"  Current version only: Yes (filtering to latest versions)")
        if config.cache_ttl > 0:
            logger.info(f"  [BETA] SQLite cache: Enabled (TTL: {config.cache_ttl}s)")
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
            if isinstance(recipe, str):
                recipe_list = [recipe]
            else:
                recipe_list = recipe
            engine.recipe_loader.recipe_filter = [r.lower() for r in recipe_list]
        success = engine.run()
        if success:
            console.print("[green]Report generation completed successfully![/green]")
        else:
            console.print("[red]Report generation failed![/red]")
            raise typer.Exit(1)
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
    recipe: List[str] = typer.Option(
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
    version_filter: Union[str, None] = typer.Option(
        None,
        "--version",
        "-v",
        help="Filter by project version (version ID or name). Use 'fs-report list-versions <project>' to see available versions.",
    ),
    finding_types: str = typer.Option(
        "cve",
        "--finding-types",
        "-ft",
        help="Finding types to include: cve (default), sast, thirdparty, credentials, config_issues, crypto_material, or 'all'. Comma-separated for multiple.",
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
        help="[BETA] Enable persistent SQLite cache with TTL (e.g., '1h', '30m', '1d'). "
             "Default: disabled (fresh data each run).",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Force fresh data fetch, ignore any cached data.",
    ),
    clear_cache: bool = typer.Option(
        False,
        "--clear-cache",
        help="Delete all cached data and exit.",
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    
    # Handle --clear-cache
    if clear_cache:
        cache = SQLiteCache()
        cache.clear()
        console.print("[green]Cache cleared successfully.[/green]")
        console.print(f"[dim]Cache location: {cache.db_path}[/dim]")
        raise typer.Exit(0)
    
    # Parse cache TTL
    cache_ttl_seconds = 0
    if no_cache:
        cache_ttl_seconds = 0
    elif cache_ttl:
        try:
            cache_ttl_seconds = parse_ttl(cache_ttl)
            if cache_ttl_seconds > 0:
                console.print(f"[cyan][BETA] SQLite cache enabled with TTL: {cache_ttl} ({cache_ttl_seconds} seconds)[/cyan]")
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
        finding_types=finding_types,
        current_version_only=current_version_only,
        cache_ttl=cache_ttl_seconds,
        cache_dir=None,
    )


if __name__ == "__main__":
    app(prog_name="fs-report")
