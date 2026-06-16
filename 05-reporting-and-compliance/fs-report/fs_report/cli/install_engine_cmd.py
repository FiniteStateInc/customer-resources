"""`fs-report install-engine` — explicit Chromium install.

For CI runners, Dockerfile builds, and any deployment where lazy install
during a render is undesirable. Same code path as the lazy install in
PDFRenderer._get_browser(), but invoked explicitly.

The --with-deps flag passes through to `playwright install --with-deps
chromium`, which pulls Chromium's system dependencies on Linux (libnss3,
libatk-bridge2.0-0, etc.). Required on bare-metal Linux hosts that
don't already have Chrome/Chromium installed; harmless on macOS.
"""

from __future__ import annotations

import subprocess
import sys

import typer

install_engine_app = typer.Typer(
    name="install-engine",
    help="Install the Chromium binary used by the Playwright PDF renderer.",
    invoke_without_command=True,
)


@install_engine_app.callback()
def install_engine(
    with_deps: bool = typer.Option(
        False,
        "--with-deps",
        help=(
            "Also install Chromium's system dependencies (libnss3, "
            "libatk-bridge2.0-0, etc.). Required on bare-metal Linux "
            "hosts; no-op on macOS."
        ),
    ),
) -> None:
    typer.echo("Installing Chromium for the Playwright PDF renderer...")
    cmd = [sys.executable, "-m", "playwright", "install"]
    if with_deps:
        cmd.append("--with-deps")
    cmd.append("chromium")
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        typer.echo(
            f"Chromium install failed (exit {result.returncode}). "
            f"Ensure network access to playwright.azureedge.net. On "
            f"bare-metal Linux, re-run with --with-deps to also install "
            f"libnss3 / libatk-bridge2.0-0 / etc. Otherwise stay on the "
            f"1.9.x maintenance line on release/1.9.",
            err=True,
        )
        raise typer.Exit(result.returncode)
    typer.echo("Chromium installed. fs-report PDF rendering is ready.")
