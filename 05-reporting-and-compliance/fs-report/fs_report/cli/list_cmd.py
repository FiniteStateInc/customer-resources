"""The 'list' command group: projects, recipes, folders, versions."""

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Union

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
    audience: Union[str, None] = typer.Option(
        None,
        "--audience",
        help=(
            "Show recipes for a specific consumer audience (e.g., 'forge'). "
            "Use 'all' to show every recipe regardless of audience."
        ),
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
        all_recipes = loader.load_recipes()

        # Apply audience filter
        if audience is None:
            recipes_list = [r for r in all_recipes if r.audience is None]
        elif audience == "all":
            recipes_list = all_recipes
        else:
            recipes_list = [r for r in all_recipes if r.audience == audience]

        if not recipes_list:
            if output_json:
                print("[]")
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
                    "audience": r.audience,
                    "requires_project": r.requires_project,
                    "requires_project_or_folder": r.requires_project_or_folder,
                    "requires_cve": r.requires_cve,
                }
                for r in recipes_list
            ]
            print(json.dumps(data, indent=2))
            return

        table = Table(title=f"Available Recipes ({len(recipes_list)} found)")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Scope", style="yellow", no_wrap=True)
        if audience == "all":
            table.add_column("Audience", style="magenta", no_wrap=True)

        def _scope(r: object) -> str:
            if getattr(r, "requires_cve", False):
                return "--cve"
            if getattr(r, "requires_project", False):
                return "--project"
            if getattr(r, "requires_project_or_folder", False):
                return "--project or --folder"
            if getattr(r, "category", None) == "operational":
                return "--period"
            return ""

        # Group: operational first, then assessment
        operational = sorted(
            [r for r in recipes_list if r.category == "operational"],
            key=lambda r: r.execution_order,
        )
        assessment = sorted(
            [r for r in recipes_list if r.category != "operational"],
            key=lambda r: r.execution_order,
        )

        def _add_group(label: str, group: list) -> None:
            if not group:
                return
            table.add_row(f"[bold]{label}[/bold]", "")
            for recipe in group:
                scope = _scope(recipe)
                if audience == "all":
                    table.add_row(f"  {recipe.name}", scope, recipe.audience or "")
                else:
                    table.add_row(f"  {recipe.name}", scope)
            table.add_section()

        _add_group("Operational", operational)
        _add_group("Assessment", assessment)

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
    sort: Union[str, None] = typer.Option(
        None,
        "--sort",
        help=(
            "Sort field and direction "
            "(e.g. findings:desc, name:asc, lastScan:desc, created:asc)."
        ),
    ),
    limit: Union[int, None] = typer.Option(
        None,
        "--limit",
        help="Maximum number of projects to return. Default: all.",
        min=1,
    ),
    offset: Union[int, None] = typer.Option(
        None,
        "--offset",
        help="Skip this many projects before returning results (pagination).",
        min=0,
    ),
    filter_str: Union[str, None] = typer.Option(
        None,
        "--filter",
        help="RSQL filter string passed to the API (e.g. name==*portal*, archived==false).",
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
            output_dir=tempfile.gettempdir(),
            start_date="2025-01-01",
            end_date="2025-01-31",
            verbose=verbose,
        )

        if not output_json:
            console.print("[bold cyan]Fetching available projects...[/bold cyan]")

        from fs_report.api_client import APIClient
        from fs_report.models import QueryConfig, QueryParams

        api_client = APIClient(config)
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(
                limit=limit if limit is not None else 1000,
                offset=offset,
                archived=False,
                excluded=False,
                sort=sort,
                filter=filter_str,
            ),
        )
        projects_data = api_client.fetch_data(projects_query)

        if not projects_data:
            if output_json:
                print("[]")
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
            print(json.dumps(data, indent=2))
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
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON for programmatic consumption.",
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
            output_dir=tempfile.gettempdir(),
            start_date="2025-01-01",
            end_date="2025-01-31",
            verbose=verbose,
        )

        if not output_json:
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
            if output_json:
                print("[]")
            else:
                console.print("[yellow]No folders found.[/yellow]")
            return

        if output_json:
            data = [
                {
                    "id": f.get("id"),
                    "name": f.get("name", "Unknown"),
                    "parentFolderId": f.get("parentFolderId"),
                    "projectCount": f.get("projectCount", 0),
                }
                for f in folders_data
            ]
            print(json.dumps(data, indent=2))
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
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON instead of a table.",
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
            output_dir=tempfile.gettempdir(),
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
                project, all_projects, config, console, logger, json_output
            )
        else:
            _list_portfolio_versions(
                all_projects, config, console, logger, show_top, json_output
            )

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
    json_output: bool = False,
) -> None:
    """List versions for a single project."""
    import httpx

    if not json_output:
        console.print(
            f"[bold cyan]Fetching versions for project: {project}[/bold cyan]"
        )

    import difflib

    target_project = None
    try:
        project_id = int(project)
        target_project = next(
            (p for p in all_projects if p.get("id") == project_id), None
        )
    except ValueError:
        # Exact match first, then case-insensitive fallback
        target_project = next(
            (p for p in all_projects if p.get("name", "") == project), None
        )
        if target_project is None:
            target_project = next(
                (
                    p
                    for p in all_projects
                    if p.get("name", "").lower() == project.lower()
                ),
                None,
            )

    if not target_project:
        console.print(f"[red]Error: No project found matching '{project}'.[/red]")
        all_names = [p.get("name", "") for p in all_projects if p.get("name")]
        close = difflib.get_close_matches(project, all_names, n=1, cutoff=0.4)
        if close:
            console.print(f"[yellow]Did you mean '{close[0]}'?[/yellow]")
        console.print(
            "[yellow]Use 'fs-report list projects' to see available projects.[/yellow]"
        )
        raise typer.Exit(1)

    project_id = target_project["id"]
    project_name = target_project["name"]

    if not json_output:
        console.print(
            f"[green]Found project: {project_name} (ID: {project_id})[/green]"
        )

    default_branch = target_project.get("defaultBranch")
    if not default_branch:
        console.print(
            f"[yellow]No default branch found for project "
            f"'{project_name}'.[/yellow]"
        )
        return

    branch_id = default_branch.get("id")
    branch_name = default_branch.get("name", "Unknown")
    latest_version_id = (default_branch.get("latestVersion") or {}).get("id")

    if not branch_id:
        console.print(
            f"[yellow]No valid default branch found for project "
            f"'{project_name}'.[/yellow]"
        )
        return

    if not json_output:
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

    if json_output:
        import json as json_mod
        from datetime import datetime

        output = []
        for version in version_list:
            created = version.get("created", None)
            if created:
                try:
                    dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    created = dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pass
            vid = version.get("id")
            output.append(
                {
                    "id": vid,
                    "name": version.get("version", "N/A"),
                    "created": created,
                    "project": project_name,
                    "project_id": project_id,
                    "latest": vid is not None
                    and latest_version_id is not None
                    and str(vid) == str(latest_version_id),
                }
            )
        print(json_mod.dumps(output, indent=2))
        return

    table = Table(
        title=(
            f"Versions for '{project_name}' - Branch: '{branch_name}' "
            f"({len(version_list)} found)"
        )
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Created", style="dim")
    table.add_column("Latest", style="bold yellow", no_wrap=True)

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

        is_latest = (
            version_id != "N/A"
            and latest_version_id is not None
            and str(version_id) == str(latest_version_id)
        )
        table.add_row(str(version_id), version_name, created, "✓" if is_latest else "")

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
    json_output: bool = False,
) -> None:
    """List version counts across all projects (parallel fetch)."""
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    import httpx
    from tqdm import tqdm

    if not json_output:
        console.print(
            "[bold cyan]Fetching version counts across all projects...[/bold cyan]"
        )

    if not all_projects:
        if not json_output:
            console.print("[yellow]No projects found.[/yellow]")
        else:
            print("[]")
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
            disable=json_output,
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

    project_version_counts.sort(key=lambda x: x["version_count"], reverse=True)

    if json_output:
        import json as json_mod

        display_counts = project_version_counts
        if show_top > 0:
            display_counts = project_version_counts[:show_top]
        print(json_mod.dumps(display_counts, indent=2))
        return

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


@list_app.command()
def components(
    project: str = typer.Argument(
        ...,
        help="Project name or ID to list components for.",
    ),
    search: Union[str, None] = typer.Option(
        None,
        "--search",
        "-s",
        help="Filter components by substring (case-insensitive, matches name or purl).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON array.",
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
    """List software components (SBOM) for a project's latest version."""
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    try:
        auth_token, domain_value = resolve_auth(token, domain)

        config = Config(
            auth_token=auth_token,
            domain=domain_value,
            output_dir=tempfile.gettempdir(),
            start_date="2025-01-01",
            end_date="2025-01-31",
            verbose=verbose,
        )

        from fs_report.api_client import APIClient
        from fs_report.models import QueryConfig, QueryParams

        api_client = APIClient(config)

        # Resolve project
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=1000, archived=False),
        )
        all_projects = api_client.fetch_all_with_resume(projects_query)

        target_project = None
        try:
            project_id = int(project)
            target_project = next(
                (p for p in all_projects if p.get("id") == project_id), None
            )
        except ValueError:
            target_project = next(
                (
                    p
                    for p in all_projects
                    if p.get("name", "").lower() == project.lower()
                ),
                None,
            )

        if not target_project:
            console.print(f"[red]Error: Project '{project}' not found.[/red]")
            console.print(
                "[yellow]Use 'fs-report list projects' to see available projects.[/yellow]"
            )
            raise typer.Exit(1)

        proj_id = target_project["id"]
        proj_name = target_project["name"]

        # Get latest version
        import httpx

        url = f"https://{config.domain}/api/public/v0/projects/{proj_id}/versions"
        headers = {"X-Authorization": config.auth_token}

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                version_list = response.json()
        except httpx.TimeoutException:
            console.print("[red]Timed out fetching versions. Try again later.[/red]")
            raise typer.Exit(1)
        except httpx.HTTPStatusError as e:
            console.print(
                f"[red]Failed to fetch versions: {e.response.status_code}[/red]"
            )
            raise typer.Exit(1)

        if not isinstance(version_list, list) or not version_list:
            console.print(
                f"[yellow]No versions found for project '{proj_name}'.[/yellow]"
            )
            return

        # Sort by created date (newest first) and take the first
        version_list.sort(key=lambda v: v.get("created", ""), reverse=True)
        latest_version = version_list[0]
        version_id = latest_version.get("id")
        version_name = latest_version.get("version", "Unknown")

        if not json_output:
            console.print(
                f"[bold cyan]Components for {proj_name} "
                f"(version: {version_name})[/bold cyan]"
            )

        # Fetch components via /public/v0/components with version filter
        components_query = QueryConfig(
            endpoint="/public/v0/components",
            params=QueryParams(
                limit=10000,
                filter=f"projectVersion=={version_id}",
            ),
        )
        raw_components = api_client.fetch_data(components_query)

        # Parse component list
        component_list: list[dict[str, Any]] = []
        for item in raw_components:
            license_name = (
                item.get("declaredLicenses")
                or item.get("declaredLicense")
                or item.get("license")
                or ""
            )
            if isinstance(license_name, float):
                license_name = ""
            comp: dict[str, Any] = {
                "name": item.get("name", item.get("component_name", "Unknown")),
                "version": item.get("version", item.get("component_version", "")),
                "purl": item.get("purl", ""),
                "license": str(license_name).strip(),
                "findings": item.get("findings", 0) or 0,
            }
            component_list.append(comp)

        # Apply search filter
        if search:
            search_lower = search.lower()
            component_list = [
                c
                for c in component_list
                if search_lower in c["name"].lower()
                or search_lower in c.get("purl", "").lower()
            ]

        # Sort by name
        component_list.sort(key=lambda c: c["name"].lower())

        if json_output:
            import json as json_mod

            print(json_mod.dumps(component_list, indent=2))
            return

        if not component_list:
            msg = "No components found"
            if search:
                msg += f" matching '{search}'"
            console.print(f"[yellow]{msg}.[/yellow]")
            return

        table = Table(title=f"Components ({len(component_list)} found)")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("License", style="yellow")
        table.add_column("Findings", style="red", justify="right")
        table.add_column("PURL", style="dim", max_width=50)

        for comp in component_list:
            findings = comp.get("findings", 0)
            findings_str = str(findings) if findings else ""
            table.add_row(
                comp["name"],
                comp["version"],
                comp.get("license", ""),
                findings_str,
                comp.get("purl", ""),
            )

        console.print(table)
        console.print(
            f"\n[dim]Use --component '{component_list[0]['name']}' with 'fs-report run' "
            f"to filter reports to this component.[/dim]"
        )

    except typer.Exit:
        raise
    except Exception as e:
        logger.exception("Error fetching components")
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1) from e
