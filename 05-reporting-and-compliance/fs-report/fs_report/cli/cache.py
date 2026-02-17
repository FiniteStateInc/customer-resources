"""The 'cache' command group: clear, status."""

from pathlib import Path
from typing import Union

import typer
from rich.console import Console

from fs_report.sqlite_cache import SQLiteCache

console = Console()

cache_app = typer.Typer(
    name="cache",
    help="Manage cached API data and AI guidance.",
    add_completion=False,
)


@cache_app.command()
def clear(
    api: bool = typer.Option(
        True,
        "--api/--no-api",
        help="Clear API data cache.",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Clear AI remediation guidance cache.",
    ),
    nvd: bool = typer.Option(
        False,
        "--nvd",
        help="Clear NVD CVE description cache.",
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (for domain-scoped API cache).",
    ),
) -> None:
    """Delete cached data."""
    import os

    cleared_something = False

    if api:
        cache_domain = domain or os.getenv("FINITE_STATE_DOMAIN")
        cache = SQLiteCache(domain=cache_domain)
        cache.clear()
        console.print("[green]API data cache cleared successfully.[/green]")
        console.print(f"[dim]Cache location: {cache.db_path}[/dim]")
        if cache_domain:
            console.print(f"[dim]Domain: {cache_domain}[/dim]")
        cleared_something = True

    if ai:
        ai_cache_dir = Path.home() / ".fs-report"
        ai_cache_db = ai_cache_dir / "cache.db"
        if ai_cache_db.exists():
            ai_cache_db.unlink()
            console.print("[green]AI remediation cache cleared successfully.[/green]")
        else:
            console.print("[yellow]No AI cache found (nothing to clear).[/yellow]")
        console.print(f"[dim]Cache location: {ai_cache_db}[/dim]")
        cleared_something = True

    if nvd:
        nvd_cache_db = Path.home() / ".fs-report" / "nvd_cache.db"
        if nvd_cache_db.exists():
            nvd_cache_db.unlink()
            console.print("[green]NVD CVE cache cleared successfully.[/green]")
        else:
            console.print("[yellow]No NVD cache found (nothing to clear).[/yellow]")
        console.print(f"[dim]Cache location: {nvd_cache_db}[/dim]")
        cleared_something = True

    if not cleared_something:
        console.print(
            "[yellow]Nothing to clear. Use --api, --ai, and/or --nvd.[/yellow]"
        )


@cache_app.command()
def status(
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (for domain-scoped API cache).",
    ),
) -> None:
    """Show cache location, size, and age."""
    import os

    from rich.table import Table

    cache_domain = domain or os.getenv("FINITE_STATE_DOMAIN")
    cache = SQLiteCache(domain=cache_domain)

    table = Table(title="Cache Status")
    table.add_column("Cache", style="cyan")
    table.add_column("Location", style="dim")
    table.add_column("Size", style="green")
    table.add_column("Exists", style="yellow")

    # API cache
    api_path = Path(cache.db_path)
    api_exists = api_path.exists()
    api_size = f"{api_path.stat().st_size / 1024:.1f} KB" if api_exists else "—"
    table.add_row(
        "API data",
        str(api_path),
        api_size,
        "Yes" if api_exists else "No",
    )

    # AI cache
    ai_path = Path.home() / ".fs-report" / "cache.db"
    ai_exists = ai_path.exists()
    ai_size = f"{ai_path.stat().st_size / 1024:.1f} KB" if ai_exists else "—"
    table.add_row(
        "AI guidance",
        str(ai_path),
        ai_size,
        "Yes" if ai_exists else "No",
    )

    # NVD cache
    nvd_path = Path.home() / ".fs-report" / "nvd_cache.db"
    nvd_exists = nvd_path.exists()
    nvd_size = f"{nvd_path.stat().st_size / 1024:.1f} KB" if nvd_exists else "—"
    table.add_row(
        "NVD CVE data",
        str(nvd_path),
        nvd_size,
        "Yes" if nvd_exists else "No",
    )

    console.print(table)
    if cache_domain:
        console.print(f"[dim]Domain: {cache_domain}[/dim]")
