"""CLI entry point for the Finite State Reporting Kit.

This package replaces the monolithic ``cli.py`` module.  The top-level
``app`` Typer instance is assembled here by registering command groups.

For backwards compatibility, all names that tests previously imported from
``fs_report.cli`` are re-exported here so that ``@patch("fs_report.cli.X")``
continues to resolve.
"""

import importlib.metadata
import sys
from typing import Union

import typer
from rich.console import Console

# ── Sub-apps ─────────────────────────────────────────────────────────
from fs_report.cli.cache import cache_app
from fs_report.cli.changelog_cmd import changelog_app

# ── Re-exports for backwards compatibility ───────────────────────────
# Tests import these from ``fs_report.cli``.  Keep them importable.
from fs_report.cli.common import (  # noqa: F401
    console,
    deprecation_warning,
    find_config_file,
    get_default_dates,
    load_config_file,
    merge_config,
    redact_token,
    resolve_auth,
    setup_logging,
)
from fs_report.cli.config_cmd import config_app
from fs_report.cli.help_cmd import help_app
from fs_report.cli.list_cmd import list_app
from fs_report.cli.run import create_config, run_app, run_reports  # noqa: F401
from fs_report.cli.serve import serve_app

# Re-export heavy dependencies that tests patch via ``fs_report.cli.X``
from fs_report.models import Config  # noqa: F401
from fs_report.recipe_loader import RecipeLoader  # noqa: F401
from fs_report.report_engine import ReportEngine  # noqa: F401
from fs_report.sqlite_cache import SQLiteCache, parse_ttl  # noqa: F401

# ── Version ──────────────────────────────────────────────────────────

try:
    __version__ = importlib.metadata.version("fs-report")
except importlib.metadata.PackageNotFoundError:
    __version__ = "dev"


# ── Main app ─────────────────────────────────────────────────────────

_console = Console()

app = typer.Typer(
    name="fs-report",
    help="Finite State Stand-Alone Reporting Kit",
    add_completion=False,
    no_args_is_help=False,
)

# Register command groups
app.add_typer(run_app, name="run", help="Generate reports from recipes.")
app.add_typer(list_app, name="list", help="List resources (projects, recipes, ...).")
app.add_typer(cache_app, name="cache", help="Manage cached data.")
app.add_typer(config_app, name="config", help="Manage configuration.")
app.add_typer(help_app, name="help", help="Show help topics.")
app.add_typer(serve_app, name="serve", help="Serve reports via local HTTP server.")
app.add_typer(changelog_app, name="changelog", help="Show per-report changelog.")


# ── Deprecated top-level commands (backwards compat) ─────────────────


def _version_callback(value: bool) -> None:
    if value:
        _console.print(f"fs-report {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Finite State Stand-Alone Reporting Kit.

    Run with no arguments to launch the web UI.
    Use 'fs-report run' to generate reports from the command line.
    """
    if ctx.invoked_subcommand is not None:
        return

    # Bare ``fs-report`` with no subcommand → launch web UI.
    try:
        from fs_report.web import run_web

        _console.print(
            "[bold cyan]Finite State Report Kit[/bold cyan] "
            f"[dim]v{__version__}[/dim]\n"
        )
        _console.print("[cyan]Starting web UI on http://localhost:8321[/cyan]")
        _console.print("[dim]Press Ctrl+C to stop.[/dim]\n")
        run_web(port=8321, open_browser=True)
    except ImportError:
        _console.print(
            "[bold cyan]Finite State Report Kit[/bold cyan] "
            f"[dim]v{__version__}[/dim]\n"
        )
        _console.print(
            "Install [bold]fastapi[/bold] and [bold]uvicorn[/bold] to "
            "enable the web UI.\n"
        )
        _console.print("Use [bold]fs-report run[/bold] to generate reports.")
        _console.print(
            "Use [bold]fs-report --help[/bold] to see all available commands.\n"
        )
    raise typer.Exit(0)


# ── Deprecated commands registered at top level ──────────────────────
# These emit a warning and delegate to the new grouped commands.


@app.command(hidden=True)
def show_periods() -> None:
    """[Deprecated] Show help for period specifications."""
    deprecation_warning("fs-report show-periods", "fs-report help periods")
    from fs_report.cli.help_cmd import periods

    periods()


@app.command(hidden=True, name="list-recipes")
def list_recipes_compat(
    recipes: Union[typer.FileTextWrite, None] = typer.Option(
        None, "--recipes", "-r", help="Path to recipes directory"
    ),
    no_bundled_recipes: bool = typer.Option(
        False, "--no-bundled-recipes", help="Disable bundled recipes."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[Deprecated] List all available recipes."""
    deprecation_warning("fs-report list-recipes", "fs-report list recipes")
    from fs_report.cli.list_cmd import recipes as list_recipes_fn

    list_recipes_fn(
        recipes_dir=None,
        no_bundled_recipes=no_bundled_recipes,
        verbose=verbose,
    )


@app.command(hidden=True, name="list-projects")
def list_projects_compat(
    token: Union[str, None] = typer.Option(None, "--token", "-t", hide_input=True),
    domain: Union[str, None] = typer.Option(None, "--domain", "-d"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[Deprecated] List all available projects."""
    deprecation_warning("fs-report list-projects", "fs-report list projects")
    from fs_report.cli.list_cmd import projects

    projects(
        recipes_dir=None,
        token=token,
        domain=domain,
        verbose=verbose,
    )


@app.command(hidden=True, name="list-folders")
def list_folders_compat(
    token: Union[str, None] = typer.Option(None, "--token", "-t", hide_input=True),
    domain: Union[str, None] = typer.Option(None, "--domain", "-d"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[Deprecated] List all available folders."""
    deprecation_warning("fs-report list-folders", "fs-report list folders")
    from fs_report.cli.list_cmd import folders

    folders(
        recipes_dir=None,
        token=token,
        domain=domain,
        verbose=verbose,
    )


@app.command(hidden=True, name="list-versions")
def list_versions_compat(
    project: Union[str, None] = typer.Argument(None),
    token: Union[str, None] = typer.Option(None, "--token", "-t", hide_input=True),
    domain: Union[str, None] = typer.Option(None, "--domain", "-d"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[Deprecated] List versions."""
    deprecation_warning("fs-report list-versions", "fs-report list versions")
    from fs_report.cli.list_cmd import versions

    versions(
        project=project,
        recipes_dir=None,
        token=token,
        domain=domain,
        verbose=verbose,
    )


# ── Bare-invocation deprecation bridge ────────────────────────────────
# When users run ``fs-report --recipe ...`` (old syntax), Typer rejects
# the unknown flags before the callback fires.  Detect this and
# transparently inject the ``run`` subcommand.

_RUN_FLAGS = {
    "--recipe",
    "--project",
    "--start",
    "--end",
    "--period",
    "--token",
    "--domain",
    "--output",
    "--data-file",
    "--project-filter",
    "--version-filter",
    "--folder-filter",
    "--folder",
    "--finding-types",
    "--cache-ttl",
    "--cache-dir",
    "--no-cache",
    "--detected-after",
    "--ai",
    "--ai-provider",
    "--ai-depth",
    "--ai-prompts",
    "--nvd-api-key",
    "--baseline-date",
    "--baseline-version",
    "--current-version",
    "--open-only",
    "--request-delay",
    "--batch-size",
    "--cve-filter",
    "--cve",
    "--scoring-file",
    "--vex-override",
    "--overwrite",
    "--no-bundled-recipes",
    "--current-version-only",
    "--all-versions",
    "--serve",
    "--serve-port",
    "--headless",
    "--verbose",
    "-r",
    "-o",
    "-t",
    "-d",
    "-v",
    "-p",
    "-s",
    "-e",
    "-pr",
    "-fl",
    "-V",
    "-ft",
    "-cvo",
    "-av",
    "-df",
}


_GLOBAL_FLAGS = {"--version", "--help", "-h"}


def _main() -> None:
    """Entry point that bridges old bare-flag invocations to ``run``."""
    args = sys.argv[1:]

    # Check: no subcommand present but run-style flags are
    subcommands = {"run", "list", "cache", "config", "help", "serve", "changelog"}
    has_subcommand = any(a in subcommands for a in args)

    if not has_subcommand and args:
        # If ONLY global flags are present, let Typer handle them normally
        non_global = [a for a in args if a not in _GLOBAL_FLAGS]
        if non_global:
            has_run_flag = any(
                a in _RUN_FLAGS or any(a.startswith(f + "=") for f in _RUN_FLAGS)
                for a in non_global
                if a.startswith("-")
            )
            if has_run_flag:
                deprecation_warning(
                    "fs-report <run-flags>",
                    "fs-report run <run-flags>",
                )
                sys.argv = [sys.argv[0], "run"] + args

    try:
        app(prog_name="fs-report")
    except SystemExit as e:
        if e.code in (None, 0):
            _maybe_show_update_notification()
        raise


def _maybe_show_update_notification() -> None:
    """Print a one-line upgrade notice when a newer PyPI version exists."""
    try:
        from fs_report.cli.update_check import get_update_notification

        notification = get_update_notification(__version__)
        if notification:
            _console.print()
            _console.print(notification)
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    _main()
