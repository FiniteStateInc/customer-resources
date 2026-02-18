"""The 'changelog' command group: display per-report release notes."""

from typing import Union

import typer
import yaml
from rich.console import Console
from rich.text import Text

console = Console()

changelog_app = typer.Typer(
    name="changelog",
    help="Show per-report changelog.",
    add_completion=False,
    invoke_without_command=True,
)

_TYPE_STYLES = {
    "added": ("green", "+"),
    "improved": ("cyan", "^"),
    "fixed": ("yellow", "!"),
    "changed": ("blue", "~"),
    "removed": ("red", "-"),
}


def _load_changelog() -> list[dict]:
    """Load changelog.yaml bundled with the package."""
    import importlib.resources

    ref = importlib.resources.files("fs_report").joinpath("changelog.yaml")
    text = ref.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    releases: list[dict] = data.get("releases", [])
    return releases


@changelog_app.callback(invoke_without_command=True)
def changelog(
    ctx: typer.Context,
    report: Union[str, None] = typer.Option(
        None,
        "--report",
        "-r",
        help="Filter changes to a specific report (substring match).",
    ),
    last: int = typer.Option(
        5,
        "--last",
        "-n",
        help="Number of releases to show.",
    ),
) -> None:
    """Show recent per-report changes across releases."""
    if ctx.invoked_subcommand is not None:
        return

    releases = _load_changelog()

    if not releases:
        console.print("[yellow]No changelog entries found.[/yellow]")
        raise typer.Exit(0)

    shown = 0
    for release in releases:
        if shown >= last:
            break

        changes = release.get("changes", [])

        # Filter by report name (substring, case-insensitive)
        if report:
            changes = [
                c
                for c in changes
                if c.get("report") and report.lower() in c["report"].lower()
            ]
            if not changes:
                continue

        version = release["version"]
        date = release.get("date", "")
        console.print(f"\n[bold cyan]v{version}[/bold cyan]  [dim]{date}[/dim]")

        for change in changes:
            ctype = change.get("type", "changed")
            style, marker = _TYPE_STYLES.get(ctype, ("white", "*"))
            report_name = change.get("report")
            desc = change.get("description", "")

            line = Text()
            line.append(f"  {marker} ", style=style)
            if report_name:
                line.append(f"[{report_name}] ", style="bold")
            line.append(desc)
            console.print(line)

        shown += 1

    if shown == 0:
        if report:
            console.print(f"[yellow]No changelog entries matching '{report}'.[/yellow]")
        else:
            console.print("[yellow]No changelog entries found.[/yellow]")
