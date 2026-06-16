# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""PDF renderer using Playwright + headless Chromium.

Replaces WeasyPrint as the sole PDF engine (rip-and-replace; no toggle,
no fallback — see docs/superpowers/specs/2026-06-01-playwright-pdf-design.md).

Thread-safe browser lifecycle
──────────────────────────────
Playwright's sync API binds its greenlet to the thread that called
``sync_playwright().start()``.  The web serve runs each report in a fresh
daemon thread (``run.py`` ``_execute_run`` → ``threading.Thread``); if
those threads all shared a singleton browser that was created on a
previous (now-exited) thread the call would raise::

    cannot switch to a different thread (which happens to have exited)

To avoid that, ``render()`` branches on whether the caller is the main
thread:

* **Main thread** (CLI ``fs-report run``) — the existing process-wide
  singleton is used (``_get_browser()`` under ``_LOCK``).  Fast: the
  browser is kept alive between reports in the same process.
* **Off-main-thread** (web serve run threads) — each ``render()`` call
  creates its own Playwright driver + browser, renders, and closes both
  in a ``finally`` block.  No singleton, no cross-thread sharing, no
  greenlet confusion.  This is slower per call (Chromium launch ~1–2 s)
  but correct.

Singleton cleanup layers (main-thread / CLI path only):
  1. atexit.register(cleanup_pdf_engines) fires at Python process exit
     so the browser tears down regardless of which entrypoint owns the
     render (CLI, web router, library callers, cli_legacy, etc.).
  2. cli/run.py:run_reports() calls cleanup_pdf_engines() explicitly in
     its finally block — per-invocation cleanup for CLI runs that may
     keep the process alive (fs-report shell, test harness, etc.).
  3. tests/conftest.py registers an autouse fixture that calls
     cleanup_pdf_engines() between tests — keeps the singleton from
     bleeding state across test cases regardless of marker.

Chromium is installed lazily on first browser launch via:

    [sys.executable, "-m", "playwright", "install", "chromium"]

— NOT a bare `playwright` shell command. pipx-installed fs-report does
not necessarily expose a `playwright` script on PATH, but `python -m
playwright` always works through the same interpreter.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from playwright._impl._errors import Error as PlaywrightError
from playwright.sync_api import Browser, Playwright, sync_playwright

from fs_report.models import Recipe, ReportData
from fs_report.renderers.html_renderer import HTMLRenderer
from fs_report.renderers.render_mode import RenderMode

_LOG = logging.getLogger(__name__)

_LAUNCH_KEY: str | None = None
_PLAYWRIGHT_CTX: Any = None
_PLAYWRIGHT_DRIVER: Playwright | None = None
_PLAYWRIGHT_BROWSER: Browser | None = None

# Reentrant lock so cleanup_pdf_engines() called from within _get_browser()
# (during a relaunch) doesn't deadlock.
_LOCK = threading.RLock()

_DEFAULT_LAUNCH_ARGS: dict[str, Any] = {
    "headless": True,
}

_CHART_READY_TIMEOUT_MS = 30_000
_GOTO_RETRIES = 1

# Cap the number of concurrent off-main-thread Chromium instances so that a
# burst of parallel web runs (if the _stderr_lock serialisation is ever
# relaxed) cannot spawn unbounded browsers.  Web runs are currently serialised
# by _stderr_lock in run.py, but this semaphore provides a defence-in-depth
# cap at the renderer layer.  The main-thread (CLI) singleton path is
# unaffected — it does not acquire this semaphore.
_RENDER_SEMAPHORE = threading.Semaphore(2)

_MISSING_EXEC_HINT = "Executable doesn't exist"

_MISSING_DEPS_HINTS = (
    "libnss3",
    "libatk-bridge",
    "libdrm",
    "libgbm",
    "Missing libraries",
    "Host system is missing dependencies",
)


def _missing_deps_error_message(original_exc: Exception) -> str:
    return (
        "Chromium installed but launch failed — system libraries are "
        "missing. On bare-metal Linux, run `fs-report install-engine "
        "--with-deps` to install them (requires sudo). Original error: "
        f"{original_exc}"
    )


def _is_missing_deps_error(exc: Exception) -> bool:
    msg = str(exc)
    return any(hint in msg for hint in _MISSING_DEPS_HINTS)


def _hash_launch_args(args: dict[str, Any]) -> str:
    """Stable key from launch args so a relaunch fires only when args change."""
    return hashlib.sha256(
        json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _is_missing_chromium_error(exc: PlaywrightError) -> bool:
    return _MISSING_EXEC_HINT in (str(exc) or "")


def _install_chromium() -> None:
    """Run `python -m playwright install chromium` via sys.executable."""
    _LOG.info(
        "PDF rendering: Chromium not installed. Installing now "
        "(one-time, ~150 MB download)..."
    )
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "chromium"],
        capture_output=False,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Chromium install failed (exit {result.returncode}). "
            "Resolve network access and re-run, "
            "or use `fs-report install-engine` explicitly "
            "(`fs-report install-engine --with-deps` on bare-metal Linux). "
            "If neither option is available, stay on the 1.9.x "
            "maintenance line on release/1.9 (which uses WeasyPrint)."
        )
    _LOG.info("Chromium install complete. Continuing.")


def _launch_browser(driver: Playwright, args: dict[str, Any]) -> Browser:
    """Launch Chromium via *driver* with *args*, performing a lazy install + retry
    on first run when the executable is absent.

    This is the single source of the install-retry logic shared by:
    - ``_get_browser()``  (singleton, main-thread / CLI path)
    - ``render()`` off-main-thread path (ephemeral per-render browser)

    Callers are responsible for cleanup on failure (closing any already-entered
    driver context) — this function does NOT touch module-level singleton state.
    """
    try:
        return driver.chromium.launch(**args)
    except Exception as exc:
        # Missing-Chromium-executable → lazy install + retry.
        if isinstance(exc, PlaywrightError) and _is_missing_chromium_error(exc):
            _install_chromium()
            try:
                return driver.chromium.launch(**args)
            except Exception as relaunch_exc:
                if _is_missing_deps_error(relaunch_exc):
                    raise RuntimeError(
                        _missing_deps_error_message(relaunch_exc)
                    ) from relaunch_exc
                raise
        # Already-installed Chromium can fail to launch on bare-metal Linux
        # when system deps (libnss3, etc.) are missing.
        if _is_missing_deps_error(exc):
            raise RuntimeError(_missing_deps_error_message(exc)) from exc
        raise


def _get_browser(launch_args: dict[str, Any] | None = None) -> Browser:
    """Return the process-wide browser singleton, launching if needed.

    Only safe to call from the **main thread** (CLI path). Off-main-thread
    callers (web serve run threads) must use their own ephemeral driver
    via ``_launch_browser()`` directly — see ``render()`` for details.
    """
    global _LAUNCH_KEY, _PLAYWRIGHT_CTX, _PLAYWRIGHT_DRIVER, _PLAYWRIGHT_BROWSER

    with _LOCK:
        args = {**_DEFAULT_LAUNCH_ARGS, **(launch_args or {})}
        new_key = _hash_launch_args(args)
        needs_relaunch = (
            _PLAYWRIGHT_BROWSER is None
            or not _PLAYWRIGHT_BROWSER.is_connected()
            or _LAUNCH_KEY != new_key
        )
        if not needs_relaunch:
            return _PLAYWRIGHT_BROWSER  # type: ignore[return-value]

        cleanup_pdf_engines()
        # Wrap driver context entry so a partial sync_playwright()
        # / __enter__() failure also cleans up (round-4 review M3-1).
        try:
            _PLAYWRIGHT_CTX = sync_playwright()
            _PLAYWRIGHT_DRIVER = _PLAYWRIGHT_CTX.__enter__()
        except Exception:
            cleanup_pdf_engines()
            raise
        # Catch broad `Exception` (not just PlaywrightError) so an
        # unexpected initial-launch failure still triggers cleanup of
        # _PLAYWRIGHT_CTX/_PLAYWRIGHT_DRIVER. Round-2 review M1-7
        # flagged that a non-PlaywrightError would otherwise leak the
        # entered driver context.
        try:
            _PLAYWRIGHT_BROWSER = _launch_browser(_PLAYWRIGHT_DRIVER, args)
        except Exception:
            cleanup_pdf_engines()
            raise
        _LAUNCH_KEY = new_key
        return _PLAYWRIGHT_BROWSER


def cleanup_pdf_engines() -> None:
    """Tear down the singleton in reverse-acquisition order.

    Invoked from three layers:
    1. `atexit.register(cleanup_pdf_engines)` at module import — fires at
       Python process exit so every entrypoint (web router, library
       callers, cli_legacy, bridge/engine_wrapper, tests) cleans up.
    2. `fs_report/cli/run.py:run_reports()` finally block — per-CLI-run
       cleanup for long-lived Python processes (fs-report shell, etc.).
    3. `tests/conftest.py` autouse fixture — between-test teardown so
       playwright-marked tests don't bleed singleton state.

    Safe to call when nothing has been launched (no-op)."""
    global _LAUNCH_KEY, _PLAYWRIGHT_CTX, _PLAYWRIGHT_DRIVER, _PLAYWRIGHT_BROWSER

    with _LOCK:
        if _PLAYWRIGHT_BROWSER is not None:
            try:
                _PLAYWRIGHT_BROWSER.close()
            except Exception as exc:
                _LOG.warning("Browser close failed: %s", exc)
        if _PLAYWRIGHT_CTX is not None:
            try:
                _PLAYWRIGHT_CTX.__exit__(None, None, None)
            except Exception as exc:
                _LOG.warning("Playwright context exit failed: %s", exc)
        _LAUNCH_KEY = None
        _PLAYWRIGHT_CTX = None
        _PLAYWRIGHT_DRIVER = None
        _PLAYWRIGHT_BROWSER = None


# Register cleanup at process exit so the Chromium singleton is torn down
# regardless of which entrypoint owns the render (CLI run_reports, web
# router, library callers, etc.). Belt-and-suspenders with the explicit
# cleanup in cli/run.py:run_reports finally — that one fires at end-of-run
# (per-invocation), this one at process exit.
atexit.register(cleanup_pdf_engines)


class PDFRenderer:
    """PDF renderer using Playwright + Chromium.

    Public contract (unchanged from WeasyPrint era):

        PDFRenderer().render(recipe, report_data, output_path) -> Path
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self._html_renderer = HTMLRenderer()

    def _should_wait_for_charts(self, recipe: Recipe) -> bool:
        """Return True if the recipe declares ANY form of chart that
        Chart.js will render at runtime."""
        if recipe.output.charts:
            return True
        if getattr(recipe.output, "chart", None) is not None:
            return True
        return bool(getattr(recipe.output, "has_inline_charts", False))

    def _render_with_browser(
        self,
        browser: Browser,
        recipe: Recipe,
        tmp_path: Path,
        output_path: Path,
    ) -> Path:
        """Execute the per-page render steps against an already-open *browser*.

        Shared by both the main-thread singleton path and the off-main-thread
        ephemeral path.  The caller owns the browser lifecycle; this method
        only opens/closes a Page.

        ``tmp_path`` is the temp HTML file written by HTMLRenderer.render()
        prior to this call.  It is **not** cleaned up here — the enclosing
        ``render()`` finally block handles that so both paths get consistent
        cleanup behaviour.
        """
        page = browser.new_page()
        try:
            last_exc: Exception | None = None
            for attempt in range(_GOTO_RETRIES + 1):
                try:
                    page.goto(tmp_path.as_uri())
                    page.wait_for_load_state("load")
                    last_exc = None
                    break
                except Exception as exc:
                    last_exc = exc
                    self.logger.warning(
                        "page.goto() attempt %d failed for %s: %s",
                        attempt + 1,
                        recipe.name,
                        exc,
                    )
            if last_exc is not None:
                raise RuntimeError(
                    f"PDF render failed: page.goto() did not "
                    f"succeed after {_GOTO_RETRIES + 1} attempts. "
                    f"Temp HTML preserved at {tmp_path}."
                ) from last_exc

            if self._should_wait_for_charts(recipe):
                try:
                    page.wait_for_function(
                        "window.fsReportReady === true",
                        timeout=_CHART_READY_TIMEOUT_MS,
                    )
                except Exception as exc:
                    # page.evaluate can itself fail if the page
                    # context is unstable after timeout; guard it
                    # so we don't escalate a degraded-but-complete
                    # render into a hard failure (round-2 review
                    # M3-3 flagged the unguarded evaluate).
                    try:
                        pending = page.evaluate("window.fsReportPendingCharts")
                    except Exception:
                        pending = "<unavailable>"
                    self.logger.error(
                        "BEACON_TIMEOUT: chart-readiness beacon "
                        "timed out for %s (pending=%s); proceeding "
                        "with page.pdf() anyway — output may contain "
                        "blank chart regions. Temp HTML preserved at "
                        "%s. (%s)",
                        recipe.name,
                        pending,
                        tmp_path,
                        exc,
                    )

            footer_template = (
                getattr(recipe.output, "pdf_footer_template", None) or "<span></span>"
            )
            # Header template: optional Chromium-rendered header on
            # every page. The recipe declares pdf_header_template_id
            # pointing at a <template> element in the rendered HTML
            # (Jinja-rendered context lives in there); we extract its
            # innerHTML and pass to page.pdf(header_template=...).
            # Chromium's header_template parameter has no template
            # engine and a restrictive CSS subset, so all styles in
            # the <template> element must be inline.
            header_template_id = getattr(recipe.output, "pdf_header_template_id", None)
            if header_template_id:
                header_html = page.evaluate(
                    f"document.querySelector('#{header_template_id}')?.innerHTML ?? null"
                )
                header_template = header_html or "<span></span>"
            else:
                header_template = "<span></span>"
            pdf_kwargs: dict[str, Any] = {
                "path": str(output_path),
                "format": "A4",
                "print_background": True,
                "prefer_css_page_size": True,
                "display_header_footer": bool(
                    footer_template.strip() != "<span></span>"
                    or header_template.strip() != "<span></span>"
                ),
                "footer_template": footer_template,
                "header_template": header_template,
            }
            recipe_margin = getattr(recipe.output, "pdf_margin", None)
            if recipe_margin is not None:
                pdf_kwargs["margin"] = recipe_margin
            page.pdf(**pdf_kwargs)
        finally:
            page.close()

        return output_path

    def render(
        self,
        recipe: Recipe,
        report_data: ReportData,
        output_path: Path,
    ) -> Path:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        success = False
        try:
            # PDFs always render in light theme. Playwright executes the
            # toggle JS in _theme_init.html, but PDF output should be
            # deterministic — passing theme="light" together with
            # render_mode=RenderMode.PDF tells _theme_init.html to skip
            # the localStorage / URL / prefers-color-scheme runtime
            # checks and honor the server-rendered theme exactly. The
            # @media print rules in _design_system.html still apply as a
            # safety net.
            self._html_renderer.render(
                recipe,
                report_data,
                tmp_path,
                render_mode=RenderMode.PDF,
                theme="light",
            )

            on_main = threading.current_thread() is threading.main_thread()
            if on_main:
                # Main-thread (CLI) path: use the process-wide singleton.
                # _LOCK is reentrant so _get_browser's inner acquisition
                # inside this block doesn't deadlock.
                with _LOCK:
                    browser = _get_browser()
                    self._render_with_browser(browser, recipe, tmp_path, output_path)
            else:
                # Off-main-thread path (web serve run threads): each render
                # creates its own driver + browser so Playwright's sync-API
                # greenlet never crosses a thread boundary.  This avoids
                # "cannot switch to a different thread (which happens to have
                # exited)" on run #2+ after the thread that created the
                # singleton has exited.
                #
                # Per-render Chromium launch adds ~1–2 s latency per web run
                # (compared to re-using a singleton), which is acceptable for
                # correctness.  _RENDER_SEMAPHORE caps concurrent launches at 2
                # so a burst of parallel runs cannot spawn unbounded browsers.
                _ctx = None
                _driver: Playwright | None = None
                _browser: Browser | None = None
                with _RENDER_SEMAPHORE:
                    try:
                        _ctx = sync_playwright()
                        _driver = _ctx.__enter__()
                        _browser = _launch_browser(_driver, {**_DEFAULT_LAUNCH_ARGS})
                        self._render_with_browser(
                            _browser, recipe, tmp_path, output_path
                        )
                    finally:
                        if _browser is not None:
                            try:
                                _browser.close()
                            except Exception as _e:
                                _LOG.warning(
                                    "off-main-thread browser.close() failed: %s", _e
                                )
                        if _ctx is not None:
                            try:
                                _ctx.__exit__(None, None, None)
                            except Exception as _e:
                                _LOG.warning(
                                    "off-main-thread playwright ctx exit failed: %s",
                                    _e,
                                )

            success = True
            return output_path

        finally:
            if success:
                tmp_path.unlink(missing_ok=True)
            else:
                self.logger.error(
                    "PDF render failed; temp HTML preserved at %s", tmp_path
                )

    def render_html(
        self,
        html_path: Path,
        output_path: Path,
        *,
        header_template: str | None = None,
        footer_template: str | None = None,
        pdf_header_template_id: str | None = None,
        pdf_footer_template_id: str | None = None,
        pdf_margin: dict[str, str] | None = None,
        wait_for_chart_beacon: bool = True,
    ) -> Path:
        """Render an already-written HTML file to PDF.

        Mirrors the ``render(recipe, report_data, output_path)`` flow but
        skips the ``HTMLRenderer.render()`` step — the caller (compound
        assembler) has already produced the HTML. Compound bundles call
        this with ``wait_for_chart_beacon=True`` because the assembled
        HTML carries the live chart-init JS for every child that declares
        charts.

        ``header_template`` / ``footer_template`` are passed verbatim to
        ``page.pdf()`` (Chromium's restrictive header/footer CSS subset
        applies — all styles inline). If both ``header_template`` and
        ``pdf_header_template_id`` are provided, the explicit string wins;
        the ``_id`` variant looks up a ``<template id="...">`` element in
        the rendered DOM and uses its ``innerHTML`` — same mechanism the
        standalone ``render()`` flow uses for ``pdf_header_template_id``.

        Unlike ``render()``, this method does NOT manage a temp HTML file.
        ``html_path`` is owned by the caller; on failure the file is left
        in place so the caller can inspect it.
        """
        # Resolve to an absolute path so as_uri() succeeds — the CLI may
        # have left config.output_dir as a relative path (e.g. the
        # default "./output"), which Path.as_uri() rejects with a
        # ValueError. (PR #100 round-1 multi-review C2.)
        html_path = html_path.resolve()

        def _render_page(browser: Browser) -> None:
            page = browser.new_page()
            try:
                last_exc: Exception | None = None
                for attempt in range(_GOTO_RETRIES + 1):
                    try:
                        page.goto(html_path.as_uri())
                        page.wait_for_load_state("load")
                        last_exc = None
                        break
                    except Exception as exc:
                        last_exc = exc
                        self.logger.warning(
                            "page.goto() attempt %d failed for %s: %s",
                            attempt + 1,
                            html_path,
                            exc,
                        )
                if last_exc is not None:
                    raise RuntimeError(
                        f"PDF render failed: page.goto() did not "
                        f"succeed after {_GOTO_RETRIES + 1} attempts. "
                        f"HTML preserved at {html_path}."
                    ) from last_exc

                if wait_for_chart_beacon:
                    try:
                        page.wait_for_function(
                            "window.fsReportReady === true",
                            timeout=_CHART_READY_TIMEOUT_MS,
                        )
                    except Exception as exc:
                        try:
                            pending = page.evaluate("window.fsReportPendingCharts")
                        except Exception:
                            pending = "<unavailable>"
                        self.logger.error(
                            "BEACON_TIMEOUT: chart-readiness beacon "
                            "timed out for %s (pending=%s); proceeding "
                            "with page.pdf() anyway — output may contain "
                            "blank chart regions. HTML preserved at %s. (%s)",
                            html_path,
                            pending,
                            html_path,
                            exc,
                        )

                resolved_header = header_template
                if resolved_header is None and pdf_header_template_id:
                    resolved_header = page.evaluate(
                        f"document.querySelector('#{pdf_header_template_id}')?.innerHTML ?? null"
                    )
                if not resolved_header:
                    resolved_header = "<span></span>"

                resolved_footer = footer_template
                if resolved_footer is None and pdf_footer_template_id:
                    resolved_footer = page.evaluate(
                        f"document.querySelector('#{pdf_footer_template_id}')?.innerHTML ?? null"
                    )
                if not resolved_footer:
                    resolved_footer = "<span></span>"

                pdf_kwargs: dict[str, Any] = {
                    "path": str(output_path),
                    "format": "A4",
                    "print_background": True,
                    "prefer_css_page_size": True,
                    "display_header_footer": bool(
                        resolved_footer.strip() != "<span></span>"
                        or resolved_header.strip() != "<span></span>"
                    ),
                    "footer_template": resolved_footer,
                    "header_template": resolved_header,
                }
                if pdf_margin is not None:
                    pdf_kwargs["margin"] = pdf_margin
                page.pdf(**pdf_kwargs)
            finally:
                page.close()

        on_main = threading.current_thread() is threading.main_thread()
        if on_main:
            with _LOCK:
                browser = _get_browser()
                _render_page(browser)
        else:
            # _RENDER_SEMAPHORE caps concurrent off-main-thread Chromium launches.
            _ctx = None
            _driver: Playwright | None = None
            _browser: Browser | None = None
            with _RENDER_SEMAPHORE:
                try:
                    _ctx = sync_playwright()
                    _driver = _ctx.__enter__()
                    _browser = _launch_browser(_driver, {**_DEFAULT_LAUNCH_ARGS})
                    _render_page(_browser)
                finally:
                    if _browser is not None:
                        try:
                            _browser.close()
                        except Exception as _e:
                            _LOG.warning(
                                "off-main-thread browser.close() failed: %s", _e
                            )
                    if _ctx is not None:
                        try:
                            _ctx.__exit__(None, None, None)
                        except Exception as _e:
                            _LOG.warning(
                                "off-main-thread playwright ctx exit failed: %s", _e
                            )

        return output_path
