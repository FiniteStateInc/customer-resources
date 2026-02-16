"""The 'list' command group: projects, recipes, folders, versions."""

import json
import logging
from pathlib import Path
from typing import Union

import typer
from rich.console import Console
from rich.table import Table

from fs_report.cli.common import resolve_auth, setup_logging
from fs_report.models import Config
from fs_report.recipe_loader import RecipeLoader

console = Console()

list_app = typer.Typer(
    name="list",
    help="List available resources (projects, recipes, folders, versions).",
    add_completion=False,
)


@list_app.command()
def recipes(
    recipes_dir: Union[Path, None] = typer.Option(
        None,
        "--recipes",
        "-r",
        help="Path to recipes directory",
        dir_okay=True,
        file_okay=False,
    ),
    no_bundled_recipes: bool = typer.Option(
        False,
        "--no-bundled-recipes",
        help="Disable bundled recipes shipped with the package.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON for programmatic consumption.",
    ),
) -> None:
    """List all available recipes."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    dir_str = str(recipes_dir) if recipes_dir else None
    loader = RecipeLoader(dir_str, use_bundled=not no_bundled_recipes)

    try:
        recipes_list = loader.load_recipes()

        if not recipes_list:
            if output_json:
                console.print("[]")
            else:
                console.print("[yellow]No recipes found[/yellow]")
            return

        if output_json:
            data = [
                {
                    "name": r.name,
                    "category": r.category,
                    "description": r.description,
                    "auto_run": r.auto_run,
                    "execution_order": r.execution_order,
                }
                for r in recipes_list
            ]
            console.print(json.dumps(data, indent=2))
            return

        table = Table(title=f"Available Recipes ({len(recipes_list)} found)")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("File", style="dim")

        for recipe in recipes_list:
            filename = f"{recipe.name.lower().replace(' ', '_')}.yaml"
            table.add_row(recipe.name, filename)

        console.print(table)

    except Exception as e:
        logger.exception("Error loading recipes")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


@list_app.command()
def projects(
    recipes_dir: Union[Path, None] = typer.Option(
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
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON for programmatic consumption.",
    ),
) -> None:
    """List all available projects."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    try:
        auth_token, domain_value = resolve_auth(token, domain)

        config = Config(
            auth_token=auth_token,
            domain=domain_value,
            recipes_dir=str(recipes_dir) if recipes_dir else None,
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
        projects_data = api_client.fetch_data(projects_query)

        if not projects_data:
            if output_json:
                console.print("[]")
            else:
                console.print("[yellow]No projects found.[/yellow]")
            return

        if output_json:
            data = [
                {
                    "id": p.get("id"),
                    "name": p.get("name", "Unknown"),
                    "folder": (
                        p.get("folder", {}).get("name", "")
                        if isinstance(p.get("folder"), dict)
                        else ""
                    ),
                    "archived": p.get("archived", False),
                }
                for p in projects_data
            ]
            console.print(json.dumps(data, indent=2))
            return

        table = Table(title=f"Available Projects ({len(projects_data)} found)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Folder", style="yellow")
        table.add_column("Archived", style="dim")

        for project in projects_data:
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


@list_app.command()
def folders(
    recipes_dir: Union[Path, None] = typer.Option(
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
        auth_token, domain_value = resolve_auth(token, domain)

        config = Config(
            auth_token=auth_token,
            domain=domain_value,
            recipes_dir=str(recipes_dir) if recipes_dir else None,
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
        folders_data = api_client.fetch_data(folders_query)

        if not folders_data:
            console.print("[yellow]No folders found.[/yellow]")
            return

        folder_by_id: dict[str, dict] = {}
        children_map: dict[str | None, list[dict]] = {}
        for folder in folders_data:
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
                label = (
                    f"[green]{name}[/green]  "
                    f"[dim](ID: {cid}, {count} project"
                    f"{'s' if count != 1 else ''})[/dim]"
                )
                child_node = parent_node.add(label)
                _add_children(child_node, cid)

        _add_children(tree, None)

        console.print(tree)
        console.print(
            f"\n[dim]Total: {len(folders_data)} folder(s). "
            f"Use --folder with folder name or ID to scope reports.[/dim]"
        )

    except Exception as e:
        logger.exception("Error fetching folders")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


@list_app.command()
def versions(
    project: Union[str, None] = typer.Argument(
        None,
        help="Project name or ID to list versions for "
        "(omit to list all versions across portfolio)",
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
        help="Only include projects in this folder (name or ID).",
    ),
    recipes_dir: Union[Path, None] = typer.Option(
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
    """List versions for a project, or all versions across the portfolio."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    try:
        auth_token, domain_value = resolve_auth(token, domain)

        config = Config(
            auth_token=auth_token,
            domain=domain_value,
            recipes_dir=str(recipes_dir) if recipes_dir else None,
            output_dir="./output",
            start_date="2025-01-01",
            end_date="2025-01-31",
            verbose=verbose,
        )

        from fs_report.api_client import APIClient
        from fs_report.models import QueryConfig, QueryParams

        api_client = APIClient(config)

        # Resolve project list
        if folder_filter and not project:
            from collections import deque

            all_folders = api_client.fetch_data(
                QueryConfig(
                    endpoint="/public/v0/folders",
                    params=QueryParams(limit=10000),
                )
            )
            if not all_folders:
                console.print("[yellow]No folders found.[/yellow]")
                return

            children_map: dict[str, list[str]] = {}
            for f in all_folders:
                parent = f.get("parentFolderId")
                if parent:
                    children_map.setdefault(str(parent), []).append(str(f["id"]))

            target_folder = None
            for f in all_folders:
                if str(f.get("id", "")) == folder_filter or (
                    f.get("name", "").lower() == folder_filter.lower()
                ):
                    target_folder = f
                    break
            if not target_folder:
                console.print(
                    f"[red]Folder not found: '{folder_filter}'. "
                    f"Use 'fs-report list folders' to see options.[/red]"
                )
                raise typer.Exit(2)

            folder_id = str(target_folder["id"])
            queue = deque([folder_id])
            all_folder_ids: set[str] = set()
            while queue:
                fid = queue.popleft()
                all_folder_ids.add(fid)
                for cid in children_map.get(fid, []):
                    if cid not in all_folder_ids:
                        queue.append(cid)

            projects_by_id: dict[str, dict] = {}
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

            all_projects = list(projects_by_id.values())
            console.print(
                f"[dim]Scoped to folder "
                f"'{target_folder.get('name', folder_filter)}': "
                f"{len(all_projects)} project(s)[/dim]"
            )
        else:
            projects_query = QueryConfig(
                endpoint="/public/v0/projects",
                params=QueryParams(limit=1000, archived=False),
            )
            all_projects = api_client.fetch_all_with_resume(projects_query)

        if project:
            _list_single_project_versions(
                project, all_projects, config, console, logger
            )
        else:
            _list_portfolio_versions(all_projects, config, console, logger, show_top)

    except typer.Exit:
        raise
    except Exception as e:
        logger.exception("Error fetching versions")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e


def _list_single_project_versions(
    project: str,
    all_projects: list[dict],
    config: Config,
    console: Console,
    logger: logging.Logger,
) -> None:
    """List versions for a single project."""
    import httpx

    console.print(f"[bold cyan]Fetching versions for project: {project}[/bold cyan]")

    target_project = None
    try:
        project_id = int(project)
        target_project = next(
            (p for p in all_projects if p.get("id") == project_id), None
        )
    except ValueError:
        target_project = next(
            (p for p in all_projects if p.get("name", "").lower() == project.lower()),
            None,
        )

    if not target_project:
        console.print(f"[red]Error: Project '{project}' not found.[/red]")
        console.print(
            "[yellow]Use 'fs-report list projects' to see available projects.[/yellow]"
        )
        raise typer.Exit(1)

    project_id = target_project["id"]
    project_name = target_project["name"]

    console.print(f"[green]Found project: {project_name} (ID: {project_id})[/green]")

    default_branch = target_project.get("defaultBranch")
    if not default_branch:
        console.print(
            f"[yellow]No default branch found for project "
            f"'{project_name}'.[/yellow]"
        )
        return

    branch_id = default_branch.get("id")
    branch_name = default_branch.get("name", "Unknown")

    if not branch_id:
        console.print(
            f"[yellow]No valid default branch found for project "
            f"'{project_name}'.[/yellow]"
        )
        return

    console.print(
        f"[green]Using default branch: {branch_name} (ID: {branch_id})[/green]"
    )

    console.print(f"[dim]Fetching versions for project: {project_name}[/dim]")
    try:
        url = (
            f"https://{config.domain}/api/public/v0/projects/" f"{project_id}/versions"
        )
        headers = {"X-Authorization": config.auth_token}

        with httpx.Client(timeout=30.0) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            version_list = response.json()
            if not isinstance(version_list, list):
                version_list = []

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            console.print(
                f"[red]Error: Rate limit exceeded while fetching versions "
                f"for '{project_name}'.[/red]"
            )
            console.print("[yellow]Please wait a moment and try again.[/yellow]")
        elif e.response.status_code in (502, 503, 504):
            console.print(
                f"[red]Error: Server timeout "
                f"(HTTP {e.response.status_code}) for '{project_name}'.[/red]"
            )
        else:
            console.print(
                f"[red]Error fetching versions: " f"HTTP {e.response.status_code}[/red]"
            )
        raise typer.Exit(1) from e
    except httpx.TimeoutException:
        console.print(f"[red]Error: Request timeout for '{project_name}'.[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error fetching versions: {e}[/red]")
        raise typer.Exit(1) from e

    if not version_list:
        console.print(
            f"[yellow]No versions found for project '{project_name}' "
            f"in branch '{branch_name}'.[/yellow]"
        )
        return

    if version_list and config.verbose:
        console.print(f"[dim]Debug: First version structure: {version_list[0]}[/dim]")

    table = Table(
        title=(
            f"Versions for '{project_name}' - Branch: '{branch_name}' "
            f"({len(version_list)} found)"
        )
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Created", style="dim")

    for version in version_list:
        version_id = version.get("id", "N/A")
        version_name = version.get("version", "N/A")
        created = version.get("created", "N/A")

        if created and created != "N/A":
            try:
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


def _list_portfolio_versions(
    all_projects: list[dict],
    config: Config,
    console: Console,
    logger: logging.Logger,
    show_top: int,
) -> None:
    """List version counts across all projects (parallel fetch)."""
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    import httpx
    from tqdm import tqdm

    console.print(
        "[bold cyan]Fetching version counts across all projects...[/bold cyan]"
    )

    if not all_projects:
        console.print("[yellow]No projects found.[/yellow]")
        return

    rate_limit_backoff = 5.0
    max_retries = 3
    max_workers = 10

    def fetch_version_count(
        proj: dict,
    ) -> tuple[str, int, str] | tuple[str, None, str]:
        proj_id = proj.get("id")
        proj_name = proj.get("name", "Unknown")
        headers = {"X-Authorization": config.auth_token}
        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=30.0) as client:
                    url = (
                        f"https://{config.domain}/api/public/v0/projects/"
                        f"{proj_id}/versions"
                    )
                    response = client.get(url, headers=headers)
                    response.raise_for_status()
                    ver = response.json()
                if not isinstance(ver, list):
                    ver = []
                return (proj_name, len(ver), str(proj_id))
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

    project_version_counts: list[dict] = []
    skipped_projects: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(fetch_version_count, proj): proj for proj in all_projects
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

    total_versions = sum(p["version_count"] for p in project_version_counts)
    projects_with_versions = sum(
        1 for p in project_version_counts if p["version_count"] > 0
    )

    console.print(
        f"\n[bold green]Portfolio Summary: {total_versions} versions "
        f"across {projects_with_versions} projects[/bold green]"
    )
    if skipped_projects:
        console.print(
            f"[yellow]({len(skipped_projects)} project(s) skipped due to errors)[/yellow]"
        )

    project_version_counts.sort(key=lambda x: x["version_count"], reverse=True)

    display_counts = project_version_counts
    if show_top > 0:
        display_counts = project_version_counts[:show_top]

    title = f"Versions by Project ({len(project_version_counts)} projects)"
    if show_top > 0 and len(project_version_counts) > show_top:
        title = (
            f"Top {show_top} Projects by Version Count "
            f"(of {len(project_version_counts)} total)"
        )
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
            f"\n[dim]Showing top {show_top} of {len(project_version_counts)} "
            f"projects. Remove --top to see all.[/dim]"
        )

    console.print(
        "\n[dim]Use 'fs-report list versions <project>' to see detailed "
        "versions for a specific project.[/dim]"
    )
