"""The 'help' command group: periods."""

import typer
from rich.console import Console

from fs_report.period_parser import PeriodParser

console = Console()

help_app = typer.Typer(
    name="help",
    help="Show help topics.",
    add_completion=False,
)


@help_app.command()
def periods() -> None:
    """Show help for period specifications."""
    console.print("[bold cyan]Period Specifications[/bold cyan]")
    console.print(PeriodParser.get_help_text())
