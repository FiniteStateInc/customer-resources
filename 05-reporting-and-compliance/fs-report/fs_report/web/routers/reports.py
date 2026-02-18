"""Reports browser router."""

import mimetypes
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse

from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.state import WebAppState

router = APIRouter(tags=["reports"])


def _human_age(mtime: float) -> str:
    """Return a human-readable age string."""
    now = datetime.now(UTC)
    dt = datetime.fromtimestamp(mtime, tz=UTC)
    seconds = int((now - dt).total_seconds())

    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _get_report_files(output_dir: Path) -> list[dict]:
    """Scan output directory for HTML report files."""
    if not output_dir.exists():
        return []

    files = sorted(
        output_dir.rglob("*.html"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    results = []
    for f in files:
        stat = f.stat()
        results.append(
            {
                "name": f.stem.replace("_", " ").title(),
                "path": str(f.relative_to(output_dir)),
                "size_kb": round(stat.st_size / 1024),
                "age": _human_age(stat.st_mtime),
                "mtime": stat.st_mtime,
            }
        )
    return results


def _human_timestamp(iso_ts: str) -> str:
    """Format an ISO timestamp into a readable string with age."""
    try:
        dt = datetime.fromisoformat(iso_ts)
        age = _human_age(dt.timestamp())
        return f"{dt.strftime('%Y-%m-%d %H:%M')} ({age})"
    except (ValueError, TypeError):
        return iso_ts or ""


def _enrich_history(runs: list[dict]) -> list[dict]:
    """Add file-existence checks and size/age metadata to history runs."""
    for run in runs:
        out_dir = Path(run["output_dir"])
        enriched_files = []
        for f in run.get("files", []):
            abs_path = out_dir / f["path"]
            if not abs_path.exists():
                continue
            stat = abs_path.stat()
            enriched_files.append(
                {
                    **f,
                    "name": abs_path.stem.replace("_", " ").title(),
                    "size_kb": round(stat.st_size / 1024),
                    "age": _human_age(stat.st_mtime),
                    "exists": True,
                }
            )
        # Sort: HTML first, then by name
        enriched_files.sort(
            key=lambda f: (0 if f.get("format") == "html" else 1, f.get("name", ""))
        )
        run["files"] = enriched_files
        run["timestamp_display"] = _human_timestamp(run.get("timestamp", ""))
    return runs


@router.get("/reports")
async def reports_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the reports browser page."""
    output_dir = Path(state.get("output_dir", "./output")).expanduser().resolve()
    report_files = _get_report_files(output_dir)

    # Load and enrich run history
    try:
        from fs_report.report_history import list_runs

        history = _enrich_history(list_runs(limit=50))
    except Exception:
        history = []

    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/reports.html",
        {
            "request": request,
            "nonce": nonce,
            "state": state,
            "report_files": report_files,
            "output_dir": str(output_dir),
            "history": history,
        },
    )


@router.get("/reports/file/{run_id}/{path:path}")
async def serve_history_file(run_id: str, path: str) -> FileResponse:
    """Serve a report file from any historically-recorded output directory."""
    from fs_report.report_history import get_run

    # Look up run in history DB
    run = get_run(run_id)
    if not run:
        return JSONResponse({"error": "Run not found"}, status_code=404)  # type: ignore[return-value]

    output_dir = Path(run["output_dir"])
    abs_path = (output_dir / path).resolve()

    # Path traversal guard: must stay inside output_dir
    if not str(abs_path).startswith(str(output_dir.resolve())):
        return JSONResponse({"error": "Invalid path"}, status_code=400)  # type: ignore[return-value]

    if not abs_path.exists() or not abs_path.is_file():
        return JSONResponse({"error": "File not found"}, status_code=404)  # type: ignore[return-value]

    media_type = mimetypes.guess_type(str(abs_path))[0] or "application/octet-stream"
    return FileResponse(abs_path, media_type=media_type)


@router.get("/api/reports/files")
async def report_files_api(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Return report file listing as JSON."""
    output_dir = Path(state.get("output_dir", "./output")).expanduser().resolve()
    return JSONResponse(_get_report_files(output_dir))


@router.get("/api/reports/history")
async def report_history_api() -> JSONResponse:
    """Return run history from SQLite."""
    try:
        from fs_report.report_history import list_runs

        return JSONResponse(list_runs(limit=50))
    except Exception:
        return JSONResponse([])


@router.get("/setup")
async def setup_page(
    request: Request,
    nonce: str = Depends(get_nonce),
    state: WebAppState = Depends(get_state),
) -> object:
    """Render the first-run onboarding wizard."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/setup.html",
        {
            "request": request,
            "nonce": nonce,
            "state": state,
        },
    )


@router.post("/api/setup")
async def save_setup(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Save initial setup configuration."""
    form = await request.form()

    domain = str(form.get("domain", ""))
    token = str(form.get("token", ""))
    output_dir = str(form.get("output_dir", "./output"))

    if domain:
        state["domain"] = domain
    if token:
        state["token"] = token
    if output_dir:
        state["output_dir"] = output_dir

    state.save(include_token=bool(token))
    state.reload()

    return JSONResponse({"status": "saved"})
