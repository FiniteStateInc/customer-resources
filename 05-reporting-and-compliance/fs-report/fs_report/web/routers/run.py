"""Run execution router — start runs, SSE progress, status polling."""

import asyncio
import io
import json
import logging
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.state import WebAppState

logger = logging.getLogger(__name__)

router = APIRouter(tags=["run"])

# In-memory store of active/completed runs
_runs: dict[str, dict[str, Any]] = {}

# Recipe groups that drive conditional field visibility (mirrors TUI prerun.py)
CVE_RECIPES = {"cve impact"}
TRIAGE_RECIPES = {"triage prioritization"}
FINDINGS_RECIPES = {"findings by project"}
VERSION_RECIPES = {"version comparison"}
COMPONENT_RECIPES = {"component list"}


class SSELogHandler(logging.Handler):
    """Captures Python logging records and pushes them into an asyncio queue."""

    def __init__(
        self, queue: asyncio.Queue[dict[str, str]], loop: asyncio.AbstractEventLoop
    ) -> None:
        super().__init__()
        self._queue = queue
        self._loop = loop

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            level = record.levelname.lower()
            self._loop.call_soon_threadsafe(
                self._queue.put_nowait,
                {
                    "event": "log",
                    "data": f'{{"level":"{level}","message":"{_escape_json(msg)}"}}',
                },
            )
        except Exception:
            pass


def _escape_json(s: str) -> str:
    """Escape a string for safe embedding in JSON."""
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _execute_run(
    run_id: str,
    recipe_names: list[str],
    state_data: dict[str, Any],
    overrides: dict[str, Any],
    queue: asyncio.Queue[dict[str, str]],
    loop: asyncio.AbstractEventLoop,
    cancel_event: threading.Event | None = None,
) -> None:
    """Worker thread: run recipes and push events to the SSE queue."""
    from fs_report.cli.run import create_config
    from fs_report.report_engine import ReportCancelled, ReportEngine

    # Merge state with overrides
    effective = {**state_data, **overrides}

    # Install SSE log handler
    handler = SSELogHandler(queue, loop)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    old_level = root_logger.level
    if root_logger.level > logging.INFO:
        root_logger.setLevel(logging.INFO)

    captured_stderr = io.StringIO()
    old_stderr = sys.stderr

    try:
        token = effective.get("token", "")
        domain = effective.get("domain", "")

        if not token or not domain:
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {
                    "event": "done",
                    "data": '{"status":"error","error":"Missing token or domain"}',
                },
            )
            return

        output_dir = effective.get("output_dir", "./output")

        config = create_config(
            period=effective.get("period", "30d"),
            finding_types=effective.get("finding_types", "cve"),
            token=token,
            domain=domain,
            output=Path(output_dir).expanduser(),
            project_filter=effective.get("project_filter") or None,
            folder_filter=effective.get("folder_filter") or None,
            version_filter=effective.get("version_filter") or None,
            cache_ttl=int(effective.get("cache_ttl", 4)),
            cache_dir=effective.get("cache_dir") or None,
            current_version_only=bool(effective.get("current_version_only", True)),
            overwrite=bool(effective.get("overwrite", False)),
            ai=bool(effective.get("ai", False)),
            ai_depth=str(effective.get("ai_depth", "summary")),
            ai_prompts=bool(effective.get("ai_prompts", False)),
            cve_filter=effective.get("cve_filter") or None,
            baseline_version=effective.get("baseline_version") or None,
            current_version=effective.get("current_version") or None,
            verbose=bool(effective.get("verbose", False)),
        )

        engine = ReportEngine(config, cancel_event=cancel_event)
        engine.recipe_loader.recipe_filter = [name.lower() for name in recipe_names]

        total = len(recipe_names)
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"event": "progress", "data": f'{{"completed":0,"total":{total}}}'},
        )

        sys.stderr = captured_stderr
        success = engine.run()
        sys.stderr = old_stderr

        stderr_output = captured_stderr.getvalue().strip()
        if stderr_output:
            for line in stderr_output.splitlines():
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {
                        "event": "log",
                        "data": f'{{"level":"info","message":"{_escape_json(line)}"}}',
                    },
                )

        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"event": "progress", "data": f'{{"completed":{total},"total":{total}}}'},
        )

        status = "success" if success else "error"
        error_msg = "" if success else "Report generation failed"

        # Collect HTML report paths relative to the output dir for direct linking
        output_dir_abs = Path(output_dir).expanduser().resolve()
        html_files = []
        for f in engine.generated_files:
            fp = Path(f)
            if fp.suffix == ".html":
                try:
                    html_files.append(str(fp.relative_to(output_dir_abs)))
                except ValueError:
                    pass

        done_payload = {"status": status, "error": error_msg, "files": html_files}
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"event": "done", "data": json.dumps(done_payload)},
        )

    except ReportCancelled:
        sys.stderr = old_stderr
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {
                "event": "done",
                "data": '{"status":"cancelled"}',
            },
        )
    except SystemExit:
        sys.stderr = old_stderr
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {
                "event": "done",
                "data": '{"status":"error","error":"Configuration error"}',
            },
        )
    except Exception as e:
        sys.stderr = old_stderr
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {
                "event": "done",
                "data": f'{{"status":"error","error":"{_escape_json(str(e))}"}}',
            },
        )
    finally:
        sys.stderr = old_stderr
        root_logger.removeHandler(handler)
        root_logger.setLevel(old_level)
        _runs[run_id]["status"] = "completed"


@router.post("/api/run/prerun")
async def prerun_form(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Return the adaptive pre-run form as an HTML partial."""
    form = await request.form()
    recipe_names = [
        r.strip() for r in str(form.get("recipes", "")).split(",") if r.strip()
    ]
    workflow_title = str(form.get("workflow_title", ""))

    selected = {r.lower() for r in recipe_names}
    show_cve = bool(selected & CVE_RECIPES)
    show_ai = bool(selected & (CVE_RECIPES | TRIAGE_RECIPES))
    show_finding_types = bool(selected & FINDINGS_RECIPES)
    show_version_fields = bool(selected & VERSION_RECIPES)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/prerun.html",
        {
            "request": request,
            "nonce": nonce,
            "state": state,
            "recipe_names": recipe_names,
            "workflow_title": workflow_title,
            "show_cve": show_cve,
            "show_ai": show_ai,
            "show_finding_types": show_finding_types,
            "show_version_fields": show_version_fields,
        },
    )


@router.post("/api/run")
async def start_run(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Start a report run. Returns the run_id."""
    form = await request.form()
    recipe_names = [
        r.strip() for r in str(form.get("recipes", "")).split(",") if r.strip()
    ]

    if not recipe_names:
        return JSONResponse({"error": "No recipes specified"}, status_code=400)

    # Collect overrides from form
    overrides: dict[str, Any] = {}
    for key in (
        "period",
        "output_dir",
        "cache_ttl",
        "project_filter",
        "folder_filter",
        "finding_types",
        "cve_filter",
        "baseline_version",
        "current_version",
        "ai_depth",
    ):
        val = form.get(key)
        if val:
            overrides[key] = str(val)

    for key in ("overwrite", "current_version_only", "ai", "ai_prompts"):
        val = form.get(key)
        if val is not None:
            overrides[key] = str(val).lower() in ("true", "on", "1", "yes")

    run_id = uuid.uuid4().hex[:8]
    queue: asyncio.Queue[dict[str, str]] = asyncio.Queue()
    loop = asyncio.get_event_loop()
    cancel_event = threading.Event()

    _runs[run_id] = {
        "status": "running",
        "queue": queue,
        "recipes": recipe_names,
        "buffer": [],  # replay buffer for late-joining clients
        "started_at": time.time(),
        "cancel_event": cancel_event,
    }

    thread = threading.Thread(
        target=_execute_run,
        args=(
            run_id,
            recipe_names,
            state.to_dict(),
            overrides,
            queue,
            loop,
            cancel_event,
        ),
        daemon=True,
    )
    thread.start()

    return JSONResponse({"run_id": run_id})


@router.get("/api/run/{run_id}/events")
async def run_events(run_id: str) -> EventSourceResponse:
    """SSE stream for a running report."""
    if run_id not in _runs:
        return EventSourceResponse(
            iter(
                [
                    {
                        "event": "done",
                        "data": '{"status":"error","error":"Run not found"}',
                    }
                ]
            )
        )

    run = _runs[run_id]
    queue: asyncio.Queue[dict[str, str]] = run["queue"]
    buffer: list[dict[str, str]] = run["buffer"]

    async def event_generator():  # type: ignore[no-untyped-def]
        # Replay buffer for late-joining clients
        for event in buffer:
            yield event

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                buffer.append(event)
                yield event
                if event.get("event") == "done":
                    break
            except asyncio.TimeoutError:
                # Send keep-alive ping
                yield {"event": "ping", "data": ""}

    return EventSourceResponse(event_generator())


@router.get("/api/runs/active")
async def active_runs() -> JSONResponse:
    """Return all runs (active and recent completed)."""
    result = []
    now = time.time()
    for run_id, run in _runs.items():
        age = now - run.get("started_at", now)
        # Include running runs and completed runs less than 1 hour old
        if run["status"] == "running" or age < 3600:
            result.append(
                {
                    "run_id": run_id,
                    "status": run["status"],
                    "recipes": run["recipes"],
                    "started_at": run.get("started_at", 0),
                    "elapsed": round(age),
                }
            )
    # Sort: running first, then by start time descending
    result.sort(key=lambda r: (0 if r["status"] == "running" else 1, -r["started_at"]))
    return JSONResponse(result)


@router.get("/api/run/{run_id}/status")
async def run_status(run_id: str) -> JSONResponse:
    """JSON poll fallback for run status."""
    if run_id not in _runs:
        return JSONResponse({"error": "Run not found"}, status_code=404)

    run = _runs[run_id]
    return JSONResponse(
        {
            "status": run["status"],
            "recipes": run["recipes"],
        }
    )


@router.post("/api/run/{run_id}/cancel")
async def cancel_run(run_id: str) -> JSONResponse:
    """Signal a running report to cancel."""
    run = _runs.get(run_id)
    if not run or run["status"] != "running":
        return JSONResponse(
            {"error": "Run not found or already completed"}, status_code=404
        )

    cancel_event: threading.Event | None = run.get("cancel_event")
    if cancel_event is not None:
        cancel_event.set()
    return JSONResponse({"cancelled": True})


@router.get("/run/{run_id}")
async def run_progress_page(
    run_id: str,
    request: Request,
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the progress page for a specific run."""
    run = _runs.get(run_id)
    if not run:
        from starlette.responses import RedirectResponse

        return RedirectResponse(url="/")

    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/progress.html",
        {
            "request": request,
            "nonce": nonce,
            "run_id": run_id,
            "recipes": run["recipes"],
        },
    )
