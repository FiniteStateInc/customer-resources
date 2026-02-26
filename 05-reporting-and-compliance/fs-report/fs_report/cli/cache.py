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


def _get_cache_paths(domain: Union[str, None] = None) -> dict:
    """Return a dict of cache name → (path, description) for all caches."""
    import os

    cache_domain = domain or os.getenv("FINITE_STATE_DOMAIN")
    cache = SQLiteCache(domain=cache_domain)
    return {
        "api": (Path(cache.db_path), "API data", cache_domain),
        "ai": (Path.home() / ".fs-report" / "cache.db", "AI guidance", None),
        "nvd": (Path.home() / ".fs-report" / "nvd_cache.db", "NVD CVE data", None),
    }


def _print_status_table(domain: Union[str, None] = None) -> None:
    """Print the cache status table."""
    from rich.table import Table

    paths = _get_cache_paths(domain)

    table = Table(title="Cache Status")
    table.add_column("Cache", style="cyan")
    table.add_column("Location", style="dim")
    table.add_column("Size", style="green")
    table.add_column("Exists", style="yellow")

    for _key, (path, label, _extra) in paths.items():
        exists = path.exists()
        size = f"{path.stat().st_size / 1024:.1f} KB" if exists else "—"
        table.add_row(label, str(path), size, "Yes" if exists else "No")

    console.print(table)
    cache_domain = paths["api"][2]
    if cache_domain:
        console.print(f"[dim]Domain: {cache_domain}[/dim]")


@cache_app.command()
def clear(
    api: bool = typer.Option(
        False,
        "--api",
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
    all_caches: bool = typer.Option(
        False,
        "--all",
        help="Clear all caches.",
    ),
    domain: Union[str, None] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Finite State domain (for domain-scoped API cache).",
    ),
) -> None:
    """Delete cached data.

    With no flags, shows cache status. Use --api, --ai, --nvd to clear
    specific caches, or --all to clear everything.
    """
    import os

    if all_caches:
        api = ai = nvd = True

    # No flags → show status and usage hint
    if not api and not ai and not nvd:
        _print_status_table(domain)
        console.print()
        console.print(
            "To clear caches, use [bold]--api[/bold], [bold]--ai[/bold], "
            "[bold]--nvd[/bold] (any combination), or [bold]--all[/bold]."
        )
        return

    if api:
        cache_domain = domain or os.getenv("FINITE_STATE_DOMAIN")
        cache = SQLiteCache(domain=cache_domain)
        cache.clear()
        console.print("[green]API data cache cleared successfully.[/green]")
        console.print(f"[dim]Cache location: {cache.db_path}[/dim]")
        if cache_domain:
            console.print(f"[dim]Domain: {cache_domain}[/dim]")

    if ai:
        ai_cache_db = Path.home() / ".fs-report" / "cache.db"
        if ai_cache_db.exists():
            ai_cache_db.unlink()
            console.print("[green]AI remediation cache cleared successfully.[/green]")
        else:
            console.print("[yellow]No AI cache found (nothing to clear).[/yellow]")
        console.print(f"[dim]Cache location: {ai_cache_db}[/dim]")

    if nvd:
        nvd_cache_db = Path.home() / ".fs-report" / "nvd_cache.db"
        if nvd_cache_db.exists():
            nvd_cache_db.unlink()
            console.print("[green]NVD CVE cache cleared successfully.[/green]")
        else:
            console.print("[yellow]No NVD cache found (nothing to clear).[/yellow]")
        console.print(f"[dim]Cache location: {nvd_cache_db}[/dim]")


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
    _print_status_table(domain)
