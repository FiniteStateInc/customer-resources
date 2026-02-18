"""The 'config' command group: init, show."""

from pathlib import Path

import typer
import yaml
from rich.console import Console

from fs_report.cli.common import find_config_file, load_config_file

console = Console()

config_app = typer.Typer(
    name="config",
    help="Manage fs-report configuration.",
    add_completion=False,
)


@config_app.command()
def init() -> None:
    """Interactively create a config file at ~/.fs-report/config.yaml."""
    config_dir = Path.home() / ".fs-report"
    config_path = config_dir / "config.yaml"

    if config_path.exists():
        overwrite = typer.confirm(
            f"Config file already exists at {config_path}. Overwrite?",
            default=False,
        )
        if not overwrite:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(0)

    console.print("[bold cyan]Finite State Report Kit — Configuration[/bold cyan]\n")

    domain = typer.prompt(
        "Finite State domain (e.g., customer.finitestate.io)",
        default="",
    )
    output_dir = typer.prompt(
        "Default output directory",
        default="./output",
    )
    finding_types = typer.prompt(
        "Default finding types (cve, sast, binary_sca, source_sca, all, ...)",
        default="cve",
    )

    config_data = {
        "domain": domain,
        "output_dir": output_dir,
        "finding_types": finding_types,
        "current_version_only": True,
        "request_delay": 0.5,
        "batch_size": 5,
        "update_check": True,
    }

    config_dir.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_data, f, default_flow_style=False, sort_keys=False)

    console.print(f"\n[green]Config written to {config_path}[/green]")
    console.print(
        "[dim]Set FINITE_STATE_AUTH_TOKEN in your shell profile for the API token.[/dim]"
    )


@config_app.command()
def show() -> None:
    """Show the resolved configuration (config file + env vars)."""
    import os

    from rich.table import Table

    config_path = find_config_file()
    cfg = load_config_file()

    if config_path:
        console.print(f"[cyan]Config file: {config_path}[/cyan]")
    else:
        console.print("[yellow]No config file found.[/yellow]")

    table = Table(title="Resolved Configuration")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Source", style="dim")

    # Domain
    env_domain = os.getenv("FINITE_STATE_DOMAIN", "")
    cfg_domain = cfg.get("domain", "")
    if env_domain:
        table.add_row("domain", env_domain, "env var")
    elif cfg_domain:
        table.add_row("domain", cfg_domain, "config file")
    else:
        table.add_row("domain", "(not set)", "—")

    # Token
    env_token = os.getenv("FINITE_STATE_AUTH_TOKEN", "")
    if env_token:
        from fs_report.cli.common import redact_token

        table.add_row("auth_token", redact_token(env_token), "env var")
    else:
        table.add_row("auth_token", "(not set)", "—")

    # Config file values
    for key in [
        "output_dir",
        "finding_types",
        "current_version_only",
        "request_delay",
        "batch_size",
        "recipes_dir",
        "cache_ttl",
        "ai",
        "ai_depth",
        "serve_port",
        "update_check",
    ]:
        val = cfg.get(key)
        if val is not None:
            table.add_row(key, str(val), "config file")

    console.print(table)
