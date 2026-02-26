"""Reports browser router."""

import io
import mimetypes
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from starlette.responses import StreamingResponse

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


_REPORT_EXTENSIONS = {".html", ".csv", ".xlsx", ".md"}


def _get_report_files(output_dir: Path) -> list[dict]:
    """Scan output directory for report files (HTML, CSV, XLSX, MD)."""
    if not output_dir.exists():
        return []

    all_files: list[Path] = []
    for ext in _REPORT_EXTENSIONS:
        all_files.extend(output_dir.rglob(f"*{ext}"))

    results = []
    for f in sorted(all_files, key=lambda p: p.stat().st_mtime, reverse=True):
        stat = f.stat()
        fmt = f.suffix.lstrip(".")
        results.append(
            {
                "name": f.stem.replace("_", " ").title(),
                "path": str(f.relative_to(output_dir)),
                "format": fmt,
                "size_kb": round(stat.st_size / 1024),
                "age": _human_age(stat.st_mtime),
                "mtime": stat.st_mtime,
            }
        )
    # Sort: HTML first, then by name
    results.sort(
        key=lambda f: (0 if f.get("format") == "html" else 1, f.get("name", ""))
    )
    return results


def _group_report_files(files: list[dict]) -> list[dict]:
    """Group report files by stem so ancillary formats appear under their HTML.

    Returns a list of group dicts:
        {"name": str, "html": dict | None, "ancillary": [dict, ...], "age": str}
    Groups are ordered by the HTML file's mtime (newest first), with groups
    that have no HTML file at the end.
    """
    from collections import OrderedDict

    groups: OrderedDict[str, dict] = OrderedDict()
    for f in files:
        # Derive a group key from the path stem (without extension)
        stem = Path(f["path"]).stem
        if stem not in groups:
            groups[stem] = {
                "name": f["name"],
                "html": None,
                "ancillary": [],
                "age": f["age"],
                "mtime": f.get("mtime", 0),
            }
        if f["format"] == "html":
            groups[stem]["html"] = f
            groups[stem]["age"] = f["age"]
            groups[stem]["mtime"] = f.get("mtime", 0)
        else:
            groups[stem]["ancillary"].append(f)

    result = list(groups.values())
    # Sort: groups with HTML first (by mtime desc), then groups without HTML
    result.sort(key=lambda g: (0 if g["html"] else 1, -g["mtime"]))
    return result


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
                    "mtime": stat.st_mtime,
                    "exists": True,
                }
            )
        # Sort: HTML first, then by name
        enriched_files.sort(
            key=lambda f: (0 if f.get("format") == "html" else 1, f.get("name", ""))
        )
        run["files"] = enriched_files
        run["file_groups"] = _group_report_files(enriched_files)
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
    report_groups = _group_report_files(report_files)

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
            "report_groups": report_groups,
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


@router.get("/reports/bundle/output")
async def download_output_bundle(
    state: WebAppState = Depends(get_state),
) -> StreamingResponse:
    """Zip all report files in the current output directory."""
    output_dir = Path(state.get("output_dir", "./output")).expanduser().resolve()
    if not output_dir.is_dir():
        return JSONResponse({"error": "Output directory not found"}, status_code=404)  # type: ignore[return-value]

    report_files = _get_report_files(output_dir)
    if not report_files:
        return JSONResponse({"error": "No files available"}, status_code=404)  # type: ignore[return-value]

    buf = io.BytesIO()
    file_count = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in report_files:
            abs_path = (output_dir / f["path"]).resolve()
            if not str(abs_path).startswith(str(output_dir)):
                continue
            if not abs_path.is_file():
                continue
            zf.write(abs_path, arcname=f["path"])
            file_count += 1

    if file_count == 0:
        return JSONResponse({"error": "No files available"}, status_code=404)  # type: ignore[return-value]

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="reports_output.zip"'},
    )


@router.get("/reports/bundle/{run_id}")
async def download_bundle(run_id: str) -> StreamingResponse:
    """Zip all report files for a history run and stream as a download."""
    from fs_report.report_history import get_run

    run = get_run(run_id)
    if not run:
        return JSONResponse({"error": "Run not found"}, status_code=404)  # type: ignore[return-value]

    output_dir = Path(run["output_dir"]).resolve()
    buf = io.BytesIO()
    file_count = 0

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in run.get("files", []):
            abs_path = (output_dir / f["path"]).resolve()
            # Path traversal guard
            if not str(abs_path).startswith(str(output_dir)):
                continue
            if not abs_path.is_file():
                continue
            zf.write(abs_path, arcname=f["path"])
            file_count += 1

    if file_count == 0:
        return JSONResponse({"error": "No files available"}, status_code=404)  # type: ignore[return-value]

    buf.seek(0)
    filename = f"reports_{run_id}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/reports/log/{run_id}")
async def serve_history_log(run_id: str) -> PlainTextResponse:
    """Serve the log file for a history run as plain text."""
    from fs_report.logging_utils import LOG_DIR
    from fs_report.report_history import get_run

    run = get_run(run_id)
    log_filename = run.get("log_file") if run else None

    if log_filename:
        log_path = LOG_DIR / log_filename
    else:
        # Fall back to globbing for the run_id
        matches = list(LOG_DIR.glob(f"*_{run_id}.log"))
        log_path = matches[0] if matches else None

    if not log_path or not log_path.is_file():
        return PlainTextResponse("Log file not found.", status_code=404)

    return PlainTextResponse(log_path.read_text(encoding="utf-8"))


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
