"""Finite State Report Kit — Web UI.

FastAPI-based web interface that replaces the Textual TUI.
Launched when ``fs-report`` is invoked with no subcommand.
"""

from __future__ import annotations

import webbrowser

from fs_report.web.app import create_app


def run_web(*, port: int = 8321, open_browser: bool = True) -> None:
    """Start the web UI server and optionally open the browser."""
    import threading
    import time

    import uvicorn

    app = create_app()
    url = f"http://localhost:{port}"

    if open_browser:

        def _open() -> None:
            time.sleep(0.8)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


__all__ = ["create_app", "run_web"]
