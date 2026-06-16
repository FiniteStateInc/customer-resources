"""Finite State Report Kit — Web UI.

FastAPI-based web interface that replaces the Textual TUI.
Launched when ``fs-report`` is invoked with no subcommand.
"""

from __future__ import annotations

import webbrowser

from fs_report.web.app import create_app


def run_web(
    *, port: int = 8321, open_browser: bool = True, reload: bool = False
) -> None:
    """Start the web UI server and optionally open the browser.

    Args:
        port: TCP port to listen on.
        open_browser: Open the browser automatically after startup.
        reload: Enable uvicorn auto-reload on code changes (dev only).
            When True, uvicorn is started via an import string + factory so the
            reloader can re-import the module.  When False (default), the
            pre-built app object is passed directly — no change to production
            behaviour.
    """
    import threading
    import time

    import uvicorn

    url = f"http://localhost:{port}"

    if open_browser:

        def _open() -> None:
            time.sleep(0.8)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    if reload:
        # factory=True tells uvicorn to call create_app() with no args on each
        # reload.  create_app()'s port kwarg defaults to 8321; CORS origin uses
        # that — acceptable for dev use.
        uvicorn.run(
            "fs_report.web:create_app",
            host="127.0.0.1",
            port=port,
            reload=True,
            factory=True,
            log_level="warning",
        )
    else:
        app = create_app()
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


__all__ = ["create_app", "run_web"]
