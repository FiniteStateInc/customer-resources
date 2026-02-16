"""Reports browser router."""

from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

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


@router.get("/reports")
async def reports_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the reports browser page."""
    output_dir = Path(state.get("output_dir", "./output")).expanduser().resolve()
    report_files = _get_report_files(output_dir)

    # Load run history
    try:
        from fs_report.report_history import list_runs

        history = list_runs(limit=20)
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

    state.save()
    state.reload()

    return JSONResponse({"status": "saved"})
