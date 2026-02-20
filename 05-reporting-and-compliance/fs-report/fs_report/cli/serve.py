"""The 'serve' command: start a report server with landing page."""

from pathlib import Path
from typing import Union

import typer
from rich.console import Console

console = Console()

serve_app = typer.Typer(
    name="serve",
    help="Serve generated reports via a local HTTP server.",
    add_completion=False,
    context_settings={"allow_interspersed_args": True},
)


@serve_app.callback(invoke_without_command=True)
def serve_command(
    ctx: typer.Context,
    directory: Union[Path, None] = typer.Argument(
        None,
        help="Output directory to serve (defaults to ./output).",
    ),
    port: int = typer.Option(
        8321,
        "--port",
        "-p",
        help="Port for the local HTTP server.",
    ),
) -> None:
    """Start a local server with a landing page showing report history.

    Reuses an existing server if one is already running on the port.
    """
    if ctx.invoked_subcommand is not None:
        return

    output_dir = Path(directory or "./output").expanduser().resolve()
    if not output_dir.exists():
        console.print(f"[red]Output directory not found: {output_dir}[/red]")
        raise typer.Exit(1)

    # Check if a server is already running
    import httpx

    try:
        resp = httpx.get(f"http://127.0.0.1:{port}/fsapi/session", timeout=2)
        if resp.status_code == 200:
            console.print(
                f"[cyan]Server already running on http://localhost:{port}[/cyan]"
            )
            import webbrowser

            webbrowser.open(f"http://localhost:{port}")
            return
    except Exception:
        pass

    # Start the FastAPI web server
    console.print(f"[cyan]Starting web UI on http://localhost:{port}[/cyan]")
    console.print(f"[dim]Serving reports from: {output_dir}[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    import os

    # Ensure the output directory is used
    os.environ.setdefault("FS_REPORT_OUTPUT_DIR", str(output_dir))

    from fs_report.web import run_web

    run_web(port=port, open_browser=True)
