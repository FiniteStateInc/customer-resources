"""CLI interface for FS-Smartsheet integration."""

import warnings

# Suppress DeprecationWarnings from the Smartsheet SDK only (not all libraries)
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"smartsheet\b")

import asyncio
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .cache import SQLiteCache, parse_ttl
from .config import AppConfig, load_config
from .sync import SyncEngine
from .sync.filters import SyncFilters

app = typer.Typer(
    name="fs-smartsheet",
    help="Sync data between Finite State and Smartsheet",
    no_args_is_help=True,
)
console = Console()


def get_config(config_path: Path | None = None) -> AppConfig:
    """Load configuration from file and environment."""
    try:
        return load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        raise typer.Exit(1) from None


def run_async(coro: Any) -> Any:
    """Run an async function synchronously."""
    return asyncio.run(coro)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for CLI."""
    import logging

    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


class SyncProgressReporter:
    """Live progress display for sync operations using Rich."""

    def __init__(self, live: Live):
        self.live = live
        self._phase = ""
        self._fetched = 0
        self._written = 0
        self._wb_done = 0
        self._wb_total = 0
        self._sheet_name = ""
        self._finished = False
        self._completed_sheets: list[tuple[str, int, int, int]] = []  # (name, fetched, written, wb)

    def set_sheet_name(self, name: str) -> None:
        # Save previous sheet (if any had activity)
        if self._sheet_name and (self._finished or self._fetched > 0):
            self._completed_sheets.append(
                (self._sheet_name, self._fetched, self._written, self._wb_done)
            )
        self._sheet_name = name
        self._phase = "fetch"
        self._fetched = 0
        self._written = 0
        self._wb_done = 0
        self._wb_total = 0
        self._finished = False

    def callback(self, phase: str, current: int, total: int | None, detail: str = "") -> None:
        """Engine calls this to report progress."""
        self._phase = phase
        if phase == "start":
            self.set_sheet_name(detail)
        elif phase == "fetch":
            self._fetched = current
        elif phase == "write":
            self._written = current
        elif phase == "writeback":
            self._wb_done = current
            if total is not None:
                self._wb_total = total
        elif phase == "done":
            self._finished = True
        self._render()

    def _format_sheet_summary(self, name: str, fetched: int, written: int, wb: int) -> Text:
        """Format a completed sheet summary line."""
        line = Text("  ✓ ", style="green")
        line.append(Text(name, style="cyan"))
        parts = []
        if fetched:
            parts.append(f"{fetched:,} fetched")
        if written:
            parts.append(f"{written:,} written")
        if wb:
            parts.append(f"{wb} written back")
        if parts:
            line.append(f"  {', '.join(parts)}")
        else:
            line.append("  up to date")
        return line

    def _render(self) -> None:
        """Render the current progress state."""
        lines: list[Text] = []

        # Show completed sheets
        for name, fetched, written, wb in self._completed_sheets:
            lines.append(self._format_sheet_summary(name, fetched, written, wb))

        # Show current sheet
        if self._sheet_name:
            if self._finished:
                lines.append(
                    self._format_sheet_summary(
                        self._sheet_name, self._fetched, self._written, self._wb_done
                    )
                )
            elif self._phase in ("fetch", "write"):
                line = Text("  ⠋ ", style="bold blue")
                line.append(Text(self._sheet_name, style="cyan"))
                line.append(f"  ↓ {self._fetched:,} fetched")
                if self._written > 0:
                    line.append(f"  ↑ {self._written:,} written")
                lines.append(line)
            elif self._phase == "writeback":
                line = Text("  ⠋ ", style="bold blue")
                line.append(Text(self._sheet_name, style="cyan"))
                line.append(f"  ↔ writing back {self._wb_done}/{self._wb_total}")
                lines.append(line)
            else:
                line = Text("  ⠋ ", style="bold blue")
                line.append(Text(self._sheet_name, style="cyan"))
                line.append("  preparing…", style="dim")
                lines.append(line)

        # Combine into a single renderable
        if lines:
            combined = lines[0]
            for extra_line in lines[1:]:
                combined = Text.assemble(combined, "\n", extra_line)
            self.live.update(combined)
        else:
            self.live.update(Text("  Starting sync…", style="dim"))


@app.command()
def verify(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
) -> None:
    """Verify connections to Finite State and Smartsheet APIs."""
    config = get_config(config_path)
    engine = SyncEngine(config)

    console.print("[bold]Verifying API connections...[/bold]\n")

    async def _verify():
        try:
            results = await engine.verify_connections()
            return results
        finally:
            await engine.close()

    results = run_async(_verify())

    table = Table(title="Connection Status")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="green")

    for service, connected in results.items():
        status = "[green]✓ Connected[/green]" if connected else "[red]✗ Failed[/red]"
        table.add_row(service.replace("_", " ").title(), status)

    console.print(table)

    if not all(results.values()):
        raise typer.Exit(1)


@app.command()
def sync(  # noqa: C901
    sheet_type: Annotated[
        str,
        typer.Argument(help="Sheet type to sync (projects, findings, components, or 'all')"),
    ] = "all",
    # Sync mode options
    full: Annotated[
        bool,
        typer.Option("--full", "-f", help="Force full sync (refresh all data)"),
    ] = False,
    # Smartsheet organization options
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            "-w",
            help="Smartsheet workspace name (created if not exists)",
        ),
    ] = None,
    sheet_name: Annotated[
        str | None,
        typer.Option(
            "--sheet-name",
            help="Custom sheet name (default: '{project} Findings' or 'FS Findings')",
        ),
    ] = None,
    # Filter options
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            "-p",
            help="Filter by project ID(s) or name(s), comma-separated",
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            "-s",
            help="Filter by severity (critical,high,medium,low), comma-separated",
        ),
    ] = None,
    status: Annotated[
        str | None,
        typer.Option(
            "--status",
            help="Filter by VEX status (null,affected,not_affected,fixed), comma-separated",
        ),
    ] = None,
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            help="Filter by detection date (e.g., '30d' for 30 days, or '2024-01-01')",
        ),
    ] = None,
    finding_type: Annotated[
        str | None,
        typer.Option(
            "--type",
            "-t",
            help="Filter by finding type (cve,binary-sast,etc.), comma-separated",
        ),
    ] = None,
    # Version override
    version: Annotated[
        str | None,
        typer.Option(
            "--version",
            help="Sync a specific project version ID (default: current/latest version)",
        ),
    ] = None,
    # Component options
    include_files: Annotated[
        bool,
        typer.Option(
            "--include-files",
            help="Include 'file' component types (excluded by default)",
        ),
    ] = False,
    # Target folder override
    target_folder: Annotated[
        int | None,
        typer.Option(
            "--target-folder",
            help="Smartsheet folder ID to place sheets in (bypasses hierarchy)",
        ),
    ] = None,
    # Safety options
    max_rows: Annotated[
        int | None,
        typer.Option(
            "--max-rows",
            help="Maximum rows to sync (no limit by default)",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Force sync (skip confirmation prompts)",
        ),
    ] = False,
    # Caching options
    cache_ttl: Annotated[
        str | None,
        typer.Option(
            "--cache-ttl",
            help=(
                "Enable persistent SQLite cache with TTL "
                "(e.g. '4' for 4 hours, '30m', '1d'). "
                "Bare numbers are hours. Default: disabled."
            ),
        ),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache",
            help="Force fresh data (ignore any existing cache)",
        ),
    ] = False,
    # Config and debug
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose/debug output"),
    ] = False,
) -> None:
    """
    Sync data from Finite State to Smartsheet.

    Sheet placement follows the Finite State folder hierarchy.  Only FS
    folders are mirrored — project sheets go directly inside their folder:

        Workspace (e.g. "Finite State")
        ├── FS Projects (sheet, at workspace root)
        ├── {FS Folder A}/
        │   ├── Project 1 Findings
        │   ├── Project 1 Components
        │   ├── Project 2 Findings
        │   └── Project 2 Components
        └── Project X Findings         (no FS folder → workspace root)

    Use --target-folder to bypass this and place sheets in a specific folder.

    Use --cache-ttl to cache FS API responses locally so repeat syncs are
    instant within the TTL window.

    Examples:

        # Sync all findings
        fs-smartsheet sync findings

        # Sync findings for specific project (mirrors FS hierarchy)
        fs-smartsheet sync findings --project "My Project"

        # Sync with 4-hour cache (second run is instant)
        fs-smartsheet sync findings --project "My Project" --cache-ttl 4

        # Custom workspace name
        fs-smartsheet sync findings --project "My Project" --workspace "SBOM Data"

        # Place sheets in a specific folder (bypass hierarchy)
        fs-smartsheet sync findings --target-folder 1234567890

        # Custom sheet name
        fs-smartsheet sync findings --project "My Project" --sheet-name "Critical Vulns"

        # Sync critical findings only
        fs-smartsheet sync findings --severity critical

        # Sync findings from last 30 days
        fs-smartsheet sync findings --since 30d
    """
    setup_logging(verbose)
    config = get_config(config_path)

    # Parse cache TTL
    cache_ttl_seconds = 0
    if no_cache:
        cache_ttl_seconds = 0
    elif cache_ttl:
        try:
            cache_ttl_seconds = parse_ttl(cache_ttl)
            if cache_ttl_seconds > 0:
                console.print(
                    f"[cyan]SQLite cache enabled (TTL: {cache_ttl} → {cache_ttl_seconds}s)[/cyan]"
                )
        except ValueError as e:
            console.print(f"[red]Invalid --cache-ttl: {e}[/red]")
            raise typer.Exit(1) from None

    # Override workspace name if provided via CLI
    if workspace:
        config.smartsheet.workspace_name = workspace
    engine = SyncEngine(config, cache_ttl=cache_ttl_seconds)

    # Build filters from CLI args
    filters = SyncFilters.from_cli_args(
        project=project,
        severity=severity,
        status=status,
        since=since,
        finding_type=finding_type,
        max_rows=max_rows,
        include_files=include_files,
        target_folder=target_folder,
        version=version,
    )

    # Display sync configuration
    sync_type = "full" if full else "incremental"
    console.print(f"[bold]Starting {sync_type} sync...[/bold]")

    if not filters.is_empty():
        console.print(f"[dim]Filters: {filters.get_description()}[/dim]")

    console.print()

    async def _sync():
        with Live(console=console, refresh_per_second=4) as live:
            reporter = SyncProgressReporter(live)

            # For single-sheet sync, set the name early
            if sheet_type != "all":
                display_name = sheet_name or sheet_type.title()
                reporter.set_sheet_name(display_name)

            try:
                if sheet_type == "all":
                    return await engine.sync_all(
                        full=full,
                        filters=filters,
                        force=force,
                        progress=reporter.callback,
                    )
                else:
                    return [
                        await engine.sync_sheet(
                            sheet_type,
                            full=full,
                            filters=filters,
                            force=force,
                            sheet_name=sheet_name,
                            progress=reporter.callback,
                        )
                    ]
            finally:
                engine.save_state()
                await engine.close()

    results = run_async(_sync())

    def _truncate(val: Any, max_len: int = 60) -> str | None:
        """Truncate and flatten a value for single-line display."""
        if val is None:
            return None
        text = str(val).replace("\n", " ").strip()
        # Collapse multiple spaces
        while "  " in text:
            text = text.replace("  ", " ")
        if len(text) > max_len:
            text = text[:max_len] + "…"
        return text or None

    # Results table
    table = Table(title="Sync Results")
    table.add_column("Sheet", style="cyan")
    table.add_column("Added", style="green")
    table.add_column("Updated", style="yellow")
    table.add_column("Deleted", style="red")
    table.add_column("Unchanged", style="dim")
    table.add_column("Skipped", style="dim")
    table.add_column("Write-back", style="magenta")
    table.add_column("Duration", style="blue")
    table.add_column("Status")

    has_errors = False
    has_warnings = False

    for result in results:
        if not result.success:
            has_errors = True
            status_icon = "[red]✗[/red]"
        elif result.row_limit_hit:
            has_warnings = True
            status_icon = "[yellow]⚠[/yellow]"
        else:
            status_icon = "[green]✓[/green]"

        # Writeback summary
        wb_total = (
            result.writeback_ok + result.writeback_failed + result.writeback_validation_errors
        )
        if wb_total > 0:
            wb_parts = []
            if result.writeback_ok:
                wb_parts.append(f"[green]{result.writeback_ok}✓[/green]")
            if result.writeback_failed:
                wb_parts.append(f"[red]{result.writeback_failed}✗[/red]")
            if result.writeback_validation_errors:
                wb_parts.append(f"[yellow]{result.writeback_validation_errors}![/yellow]")
            wb_str = " ".join(wb_parts)
        else:
            wb_str = "-"

        table.add_row(
            result.sheet_name,
            str(result.added),
            str(result.updated),
            str(result.deleted),
            str(result.unchanged),
            str(result.skipped),
            wb_str,
            f"{result.duration_seconds:.1f}s",
            status_icon,
        )

    console.print(table)

    # Show updated rows (FS → Smartsheet changes)
    for result in results:
        if result.updated_rows:
            console.print(
                f"\n[bold yellow]Updated in {result.sheet_name}"
                " (data changed in Finite State):[/bold yellow]"
            )
            for row_info in result.updated_rows:
                pk = row_info["key"]
                changes = row_info.get("changes", {})
                if changes:
                    change_parts = []
                    for field_name, (old_val, new_val) in changes.items():
                        old_display = _truncate(old_val) or "(empty)"
                        new_display = _truncate(new_val) or "(empty)"
                        change_parts.append(f"{field_name}: {old_display} → {new_display}")
                    console.print(f"  • [cyan]{pk}[/cyan]: {', '.join(change_parts)}")
                else:
                    console.print(f"  • [cyan]{pk}[/cyan]")

    # Show writeback details
    for result in results:
        if result.writeback_details:
            console.print(
                f"\n[bold magenta]Write-back details for {result.sheet_name}:[/bold magenta]"
            )
            for detail in result.writeback_details:
                title = detail.get("title", detail["finding_id"])
                changes = detail.get("changes", {})
                change_parts = []
                for field_name, (old_val, new_val) in changes.items():
                    old_display = _truncate(old_val) or "(empty)"
                    new_display = _truncate(new_val) or "(empty)"
                    change_parts.append(f"{field_name}: {old_display} → {new_display}")
                changes_str = ", ".join(change_parts) if change_parts else "changed"
                console.print(f"  • [cyan]{title}[/cyan]: {changes_str}")

    # Show warnings
    for result in results:
        if result.warnings:
            console.print(f"\n[yellow]Warnings for {result.sheet_name}:[/yellow]")
            for warning in result.warnings:
                console.print(f"  ⚠ {warning}")

    # Show errors
    for result in results:
        if result.errors:
            console.print(f"\n[red]Errors for {result.sheet_name}:[/red]")
            for error in result.errors:
                console.print(f"  ✗ {error}")

    # Show filter tips if limit was hit
    if has_warnings and not force:
        console.print(
            Panel(
                "[bold]Tip:[/bold] --max-rows limit reached. To sync more data:\n\n"
                "• Increase limit with --max-rows 50000\n"
                "• Remove --max-rows to sync everything",
                title="Row Limit",
                border_style="yellow",
            )
        )

    if has_errors:
        raise typer.Exit(1)


@app.command()
def writeback(
    # Target status (required)
    target_status: Annotated[
        str,
        typer.Option(
            "--status",
            "-s",
            help="Target VEX status to apply",
        ),
    ],
    # Required fields for certain statuses
    response: Annotated[
        str | None,
        typer.Option(
            "--response",
            "-r",
            help="Response value (required for EXPLOITABLE)",
        ),
    ] = None,
    justification: Annotated[
        str | None,
        typer.Option(
            "--justification",
            "-j",
            help="Justification value (required for NOT_AFFECTED)",
        ),
    ] = None,
    reason: Annotated[
        str | None,
        typer.Option(
            "--reason",
            help="Optional reason/comment for the status change",
        ),
    ] = None,
    # Filters
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            "-p",
            help="Filter by project name(s), comma-separated",
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            help="Filter by severity (critical,high,medium,low), comma-separated",
        ),
    ] = None,
    finding_type: Annotated[
        str | None,
        typer.Option(
            "--type",
            "-t",
            help="Filter by finding type (cve,binary-sast,etc.), comma-separated",
        ),
    ] = None,
    # Safety options
    max_rows: Annotated[
        int,
        typer.Option(
            "--max-rows",
            help="Maximum rows to update",
        ),
    ] = 1000,
    batch_size: Annotated[
        int,
        typer.Option(
            "--batch-size",
            help="Number of concurrent API calls",
        ),
    ] = 50,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show what would be updated without making changes",
        ),
    ] = False,
    # Config and debug
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose/debug output"),
    ] = False,
) -> None:
    """
    Bulk-update VEX status on findings in Finite State.

    Applies the given --status to all findings matching the filter criteria
    (--project, --severity, --type).  Updates are sent directly to the
    Finite State API without going through Smartsheet.

    To detect and sync user edits made in Smartsheet, use the ``sync``
    command instead — it handles writeback automatically.

    Examples:

        fs-smartsheet writeback --status IN_TRIAGE --severity critical
        fs-smartsheet writeback --status NOT_AFFECTED \\
            --justification "Code Not Reachable" --project "MyApp"
        fs-smartsheet writeback --status IN_TRIAGE --severity critical --dry-run

    VEX Status Values:
        EXPLOITABLE (requires --response)
        RESOLVED
        RESOLVED_WITH_PEDIGREE
        IN_TRIAGE
        FALSE_POSITIVE
        NOT_AFFECTED (requires --justification)

    Response Values (for EXPLOITABLE):
        "Can Not Fix", "Will Not Fix", "Update", "Rollback", "Workaround Available"

    Justification Values (for NOT_AFFECTED):
        "Code Not Present", "Code Not Reachable", "Requires Configuration",
        "Requires Dependency", "Requires Environment", "Protected By Compiler",
        "Protected At Runtime", "Protected At Perimeter", "Protected By Mitigating Control"
    """
    setup_logging(verbose)
    config = get_config(config_path)
    engine = SyncEngine(config)

    mode_desc = f"to {target_status}"
    if project:
        mode_desc += f" for projects: {project}"
    if severity:
        mode_desc += f" with severity: {severity}"

    if dry_run:
        console.print(f"[yellow]DRY RUN[/yellow] - {mode_desc}\n")
    else:
        console.print(f"[bold]Processing write-back[/bold] {mode_desc}\n")

    async def _writeback():
        try:
            filters = SyncFilters.from_cli_args(
                project=project,
                severity=severity,
                finding_type=finding_type,
            )

            return await engine.writeback_with_filters(
                target_status=target_status,
                response=response,
                justification=justification,
                reason=reason,
                filters=filters,
                max_rows=max_rows,
                dry_run=dry_run,
                batch_size=batch_size,
            )
        finally:
            await engine.close()

    result = run_async(_writeback())

    # Display results
    _display_writeback_result(result)

    if not result.success:
        raise typer.Exit(1)


def _display_writeback_result(result: "WritebackResult") -> None:  # type: ignore[name-defined]  # noqa: F821
    """Display writeback result with formatting."""
    from .sync import WritebackResult  # noqa: F811, F401

    # Summary table
    table = Table(title="Writeback Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count")

    table.add_row("Total changes detected", str(result.total))
    table.add_row("Successful", f"[green]{result.successful}[/green]")
    table.add_row("Failed", f"[red]{result.failed}[/red]" if result.failed else "0")
    table.add_row(
        "Skipped (validation)", f"[yellow]{result.skipped}[/yellow]" if result.skipped else "0"
    )

    console.print(table)

    if result.dry_run:
        console.print("\n[yellow]DRY RUN - no changes made[/yellow]")

    # Validation errors
    if result.validation_errors:
        console.print("\n[yellow]Validation Errors (rows skipped):[/yellow]")
        for finding_id, errors in result.validation_errors:
            console.print(f"  [cyan]{finding_id}[/cyan]:")
            for error in errors:
                console.print(f"    - {error}")

    # API errors
    if result.api_errors:
        console.print("\n[red]API Errors:[/red]")
        for finding_id, error in result.api_errors:
            if finding_id:
                console.print(f"  [cyan]{finding_id}[/cyan]: {error}")
            else:
                console.print(f"  {error}")

    # Final status
    if result.success and result.total > 0:
        console.print("\n[green]✓ Writeback completed successfully[/green]")
    elif result.total == 0:
        console.print("\n[dim]No changes detected[/dim]")
    else:
        console.print("\n[red]✗ Writeback completed with errors[/red]")


@app.command()
def status(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
) -> None:
    """Show current sync status."""
    config = get_config(config_path)
    engine = SyncEngine(config)

    status_info = engine.get_sync_status()

    console.print(f"[bold]State File:[/bold] {status_info['state_file']}")
    console.print(f"[bold]Last Modified:[/bold] {status_info['last_modified'] or 'Never'}\n")

    if not status_info["sheets"]:
        console.print("[dim]No sheets synced yet.[/dim]")
        return

    table = Table(title="Sheet Status")
    table.add_column("Sheet", style="cyan")
    table.add_column("Sheet ID", style="dim")
    table.add_column("Rows", style="green")
    table.add_column("Last Full Sync", style="blue")
    table.add_column("Last Incremental", style="blue")

    for name, info in status_info["sheets"].items():
        table.add_row(
            name,
            str(info["sheet_id"]) if info["sheet_id"] else "-",
            str(info["row_count"]),
            info["last_full_sync"] or "Never",
            info["last_incremental_sync"] or "Never",
        )

    console.print(table)


@app.command()
def init(
    workspace_name: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Smartsheet workspace name"),
    ] = None,
    refresh: Annotated[
        bool,
        typer.Option(
            "--refresh", help="Compare FS hierarchy with Smartsheet and report differences"
        ),
    ] = False,
    clean: Annotated[
        bool,
        typer.Option("--clean", help="Delete orphaned folders/sheets (requires --refresh)"),
    ] = False,
    cache_ttl: Annotated[
        str | None,
        typer.Option(
            "--cache-ttl",
            help=(
                "Cache FS API responses with TTL "
                "(e.g. '4' for 4 hours, '30m', '1d'). Default: disabled."
            ),
        ),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option("--no-cache", help="Force fresh data (ignore any existing cache)"),
    ] = False,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
) -> None:
    """Initialize workspace, folder hierarchy, and root sheets in Smartsheet.

    Creates the workspace (if needed), the FS Projects sheet at the workspace
    root, and mirrors the Finite State folder structure as Smartsheet folders.
    Only FS folders are mirrored — project sheets are placed directly inside
    their FS folder (no per-project subfolder).

    Use --refresh to compare the current FS folder hierarchy with what's in
    Smartsheet and report any orphaned folders or new paths.

    Use --refresh --clean to also delete orphaned Smartsheet folders/sheets
    that no longer correspond to the FS hierarchy.

    Use --cache-ttl to cache FS API responses so repeat init/refresh runs
    don't re-fetch from the API.
    """
    if clean and not refresh:
        console.print("[red]--clean requires --refresh[/red]")
        raise typer.Exit(1)

    # Parse cache TTL
    cache_ttl_seconds = 0
    if no_cache:
        cache_ttl_seconds = 0
    elif cache_ttl:
        try:
            cache_ttl_seconds = parse_ttl(cache_ttl)
            if cache_ttl_seconds > 0:
                console.print(
                    f"[cyan]SQLite cache enabled (TTL: {cache_ttl} → {cache_ttl_seconds}s)[/cyan]"
                )
        except ValueError as e:
            console.print(f"[red]Invalid --cache-ttl: {e}[/red]")
            raise typer.Exit(1) from None

    config = get_config(config_path)
    if workspace_name:
        config.smartsheet.workspace_name = workspace_name
    engine = SyncEngine(config, cache_ttl=cache_ttl_seconds)

    ws = config.smartsheet.workspace_name
    console.print(f"[bold]Initializing workspace '{ws}'...[/bold]\n")

    from .smartsheet_client.schemas import STANDARD_SCHEMAS

    # --- 1. Ensure workspace exists (auto-created by workspace_id property) ---
    ws_id = engine.ss_client.workspace_id
    console.print(f"[green]Workspace:[/green] {ws} (ID: {ws_id})")

    # --- 2. Create FS Projects sheet at workspace root ---
    projects_schema = STANDARD_SCHEMAS["projects"]
    sheet = engine.ss_client.get_sheet_by_name(projects_schema.name)
    if sheet:
        console.print(f"[yellow]  Already exists:[/yellow] {projects_schema.name}")
        engine.state.set_sheet_id(projects_schema.name, sheet.id)
    else:
        sheet = engine.ss_client.create_sheet(projects_schema)
        console.print(f"[green]  Created:[/green] {projects_schema.name}")
        engine.state.set_sheet_id(projects_schema.name, sheet.id)

    # --- 3. Fetch folders from Finite State and mirror as Smartsheet folders ---
    console.print("\n[bold]Building folder hierarchy from Finite State...[/bold]\n")

    async def _build_hierarchy(do_refresh: bool = False) -> tuple[int, list[str], Any]:
        # Load the full folder tree (with parentFolderId) to reconstruct paths
        await engine._ensure_folder_tree()

        folder_paths_created: set[str] = set()
        projects_found = 0
        async for project in engine.fs_client.iter_projects():
            projects_found += 1
            if project.folder:
                # Build the FS folder path: ["Top", "Middle", "Leaf"]
                folder_path = engine._get_folder_path(project.folder.id)
                if folder_path:
                    path_str = "/".join(folder_path)
                    if path_str not in folder_paths_created:
                        engine._create_smartsheet_folder_chain(ws_id, folder_path)  # type: ignore[arg-type]
                        folder_paths_created.add(path_str)
            # Projects without an FS folder get sheets at workspace root — no folder needed

        # Run refresh in the same event loop to avoid stale aiohttp sessions
        diff = None
        if do_refresh:
            diff = await engine.refresh_hierarchy()

        return projects_found, sorted(folder_paths_created), diff

    projects_found, folders, diff = run_async(_build_hierarchy(do_refresh=refresh))

    if folders:
        console.print(
            f"[green]Folder structure ({len(folders)} FS folders,"
            f" {projects_found} projects):[/green]"
        )
        for path in folders:
            console.print(f"  📁 {path}")
    else:
        console.print(
            "[yellow]No FS folders found (project sheets will go at workspace root).[/yellow]"
        )

    # --- 4. Refresh: compare FS hierarchy with Smartsheet ---
    if refresh and diff is not None:
        console.print("\n[bold]Comparing FS hierarchy with Smartsheet workspace...[/bold]\n")

        # Report new paths (not yet in Smartsheet — should have been created above)
        if diff.has_new:
            console.print(f"[cyan]New in FS ({len(diff.new_in_fs)} paths):[/cyan]")
            for path in diff.new_in_fs:
                console.print(f"  [cyan]+ {path}[/cyan]")

        # Report orphaned items
        if diff.has_orphans:
            console.print(
                f"\n[yellow]Orphaned in Smartsheet "
                f"({len(diff.orphaned_folders)} folders, "
                f"{len(diff.orphaned_sheets)} sheets):[/yellow]"
            )
            for item in diff.orphaned_folders:
                console.print(f"  [yellow]📁 {item['path']}[/yellow]")
            for item in diff.orphaned_sheets:
                console.print(f"  [yellow]📄 {item['path']}[/yellow]")

            if clean:
                console.print()
                deleted = engine.clean_orphans(diff)
                console.print(f"[red]Deleted {deleted} orphaned items.[/red]")
            else:
                console.print("\n[dim]Run with --refresh --clean to delete orphaned items.[/dim]")
        else:
            console.print("[green]✓ Smartsheet hierarchy is in sync with FS.[/green]")

    engine.save_state()
    console.print("\n[green]✓ Initialization complete[/green]")
    console.print(
        "[dim]Run 'fs-smartsheet sync findings --project \"<name>\"' "
        "to populate sheets for a project.[/dim]"
    )


@app.command()
def reset(
    sheet_type: Annotated[
        str,
        typer.Argument(help="Sheet to reset (projects, findings, components, or 'all')"),
    ] = "all",
    project: Annotated[
        str | None,
        typer.Option("--project", "-p", help="Project name (sheet is named '<project> Findings')"),
    ] = None,
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Smartsheet workspace name"),
    ] = None,
    target_folder: Annotated[
        int | None,
        typer.Option(
            "--target-folder",
            help="Smartsheet folder ID to place sheets in (bypasses hierarchy)",
        ),
    ] = None,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt"),
    ] = False,
) -> None:
    """Delete and recreate sheets (fixes column mismatch errors)."""
    from .smartsheet_client.schemas import STANDARD_SCHEMAS

    config = get_config(config_path)
    if workspace:
        config.smartsheet.workspace_name = workspace
    engine = SyncEngine(config)

    # Determine which sheet types to reset
    if sheet_type == "all":
        sheets_to_reset = list(STANDARD_SCHEMAS.keys())
        # Skip "projects" for project-specific resets — it's redundant
        if project:
            sheets_to_reset = [t for t in sheets_to_reset if t != "projects"]
    elif sheet_type in STANDARD_SCHEMAS:
        sheets_to_reset = [sheet_type]
    else:
        console.print(f"[red]Unknown sheet type: {sheet_type}[/red]")
        raise typer.Exit(1)

    # Build filters so _resolve_sheet_location can figure out hierarchy
    filters = SyncFilters.from_cli_args(project=project, target_folder=target_folder)

    # Resolve sheet names and folder for each sheet type using hierarchy logic
    async def _resolve_all():
        results: list[tuple[str, str, int | None]] = []
        for key in sheets_to_reset:
            base = STANDARD_SCHEMAS[key]
            name, fid = await engine._resolve_sheet_location(key, base, filters)
            results.append((key, name, fid))
        return results

    sheets_info = run_async(_resolve_all())

    if not yes:
        ws_name = workspace or config.smartsheet.workspace_name
        console.print(f"[yellow]Workspace: {ws_name}[/yellow]")
        if project:
            console.print(f"[yellow]Project: {project}[/yellow]")
        console.print("[yellow]This will DELETE the following sheets:[/yellow]")
        for _, sname, _ in sheets_info:
            console.print(f"  - {sname}")
        console.print()
        confirm = typer.confirm("Are you sure?")
        if not confirm:
            console.print("Cancelled.")
            raise typer.Exit(0)

    # Delete existing sheets
    for _sheet_type_key, sname, fid in sheets_info:
        sheet = engine.ss_client.get_sheet_by_name(sname, folder_id=fid)
        if sheet:
            console.print(f"Deleting [cyan]{sname}[/cyan]...")
            engine.ss_client.delete_sheet(sheet.id)
        else:
            console.print(f"[dim]{sname} not found, skipping delete[/dim]")
        # Clear state for this sheet
        if sname in engine.state.sheets:
            del engine.state.sheets[sname]

    # Clear all caches — Smartsheet auto-deletes empty folders/workspaces,
    # so cached IDs may be stale after deleting sheets.
    engine.ss_client._folder_cache.clear()
    engine.ss_client._workspace_id = None

    # Re-resolve locations (folders may need to be recreated)
    sheets_info = run_async(_resolve_all())

    # Recreate sheets
    console.print()
    for sheet_type_key, sname, fid in sheets_info:
        schema = STANDARD_SCHEMAS[sheet_type_key].with_name(sname)
        console.print(f"Creating [cyan]{sname}[/cyan]...")
        sheet = engine.ss_client.get_or_create_sheet(schema, folder_id=fid)
        engine.state.set_sheet_id(sname, sheet.id)

    engine.save_state()
    console.print("\n[green]✓ Sheets reset successfully[/green]")


@app.command(name="cache")
def cache_cmd(
    action: Annotated[
        str,
        typer.Argument(help="Action: 'stats' (show cache info), 'clear' (delete all cached data)"),
    ] = "stats",
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
) -> None:
    """Manage the local SQLite API cache.

    The cache stores Finite State API responses to speed up repeated
    sync / init operations.  It is only populated when --cache-ttl is used.

    Examples:

        # Show cache stats
        fs-smartsheet cache stats

        # Clear all cached data
        fs-smartsheet cache clear
    """
    config = get_config(config_path)
    domain = config.finite_state.domain
    cache = SQLiteCache(domain=domain, cache_dir=config.sync.cache_dir)

    if action == "clear":
        cache.clear()
        console.print("[green]✓ Cache cleared[/green]")
        console.print(f"[dim]Database: {cache.db_path}[/dim]")
    elif action == "stats":
        stats = cache.get_stats()
        table = Table(title="API Cache")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        table.add_row("Database", stats.db_path)
        table.add_row("Cached queries", str(stats.total_queries))
        table.add_row("Cached records", str(stats.total_records))
        size_mb = round(stats.db_size_bytes / (1024 * 1024), 2)
        table.add_row("Size", f"{size_mb} MB ({stats.db_size_bytes:,} bytes)")
        console.print(table)
    else:
        console.print(f"[red]Unknown action: {action}. Use 'stats' or 'clear'.[/red]")
        raise typer.Exit(1)


@app.command()
def config_show(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
) -> None:
    """Show current configuration (with secrets masked)."""
    config = get_config(config_path)

    table = Table(title="Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row("Finite State Domain", config.finite_state.domain)
    fs_token = config.finite_state.auth_token
    table.add_row("Finite State Token", f"{fs_token[:8]}..." if fs_token else "[red]Not set[/red]")
    ss_token = config.smartsheet.access_token
    table.add_row("Smartsheet Token", f"{ss_token[:8]}..." if ss_token else "[red]Not set[/red]")
    table.add_row("Smartsheet Workspace", config.smartsheet.workspace_id or "[dim]Not set[/dim]")  # type: ignore[arg-type]
    table.add_row("Sync Interval", f"{config.sync.interval_minutes} minutes")
    table.add_row("Batch Size", str(config.sync.batch_size))
    table.add_row("State File", str(config.sync.state_file))

    console.print(table)


if __name__ == "__main__":
    app()
