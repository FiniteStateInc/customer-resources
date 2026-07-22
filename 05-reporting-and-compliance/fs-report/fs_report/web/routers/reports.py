"""Reports browser router."""

import io
import logging
import mimetypes
import re
import urllib.parse
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.responses import StreamingResponse

from fs_report.report_history import list_runs
from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.recipe_meta import categorize
from fs_report.web.shell_context import build_shell_context
from fs_report.web.state import WebAppState

logger = logging.getLogger(__name__)

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


# Sidecar artifacts that must never become a download target or a format chip.
_SIDECAR_SUFFIXES = ("_schema.json",)


def _encode_path(path: str) -> str:
    """URL-encode a relative report path per segment (paths contain spaces)."""
    return "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))


def _recipe_label(recipe: str) -> str:
    """Display label for a recipe: title-case a lowercased slug, else as-is."""
    if any(c.isupper() for c in recipe):
        return recipe
    return recipe.replace("_", " ").title()


def _scope_str(scope: dict) -> str:
    """Human scope string from a run's recorded scope (superset of the feed).

    Prepends the folder breadcrumb (``folder_path``, root->leaf) with ' > ':
    project scope renders 'Folder > Project'; folder scope renders the
    breadcrumb. Falls back to the raw folder filter / 'entire portfolio' for
    rows recorded before folder_path was stored.
    """
    folder_disp = " > ".join(scope.get("folder_path") or [])
    project = (
        scope.get("project_name") or scope.get("project_filter") or scope.get("project")
    )
    if project:
        return f"{folder_disp} > {project}" if folder_disp else project
    if folder_disp:
        return folder_disp
    return scope.get("folder_filter") or "entire portfolio"


def _run_when(timestamp: str) -> str:
    """Relative age of the run from its ISO timestamp (guarded → '')."""
    try:
        return _human_age(datetime.fromisoformat(timestamp).timestamp())
    except (ValueError, TypeError):
        return ""


def _date_group(timestamp: str) -> str:
    """'Today' / 'Yesterday' / '%b %d' for the run's local-time date."""
    try:
        dt = datetime.fromisoformat(timestamp).astimezone()
    except (ValueError, TypeError):
        return ""
    today = datetime.now().astimezone().date()
    d = dt.date()
    delta = (today - d).days
    if delta == 0:
        return "Today"
    if delta == 1:
        return "Yesterday"
    return dt.strftime("%b %d")


def _build_reports(run: dict) -> list[dict]:
    """Group a run's existing files by recipe into per-recipe report rows."""
    run_id = run["id"]
    # Group recorded (non-sidecar) files by recipe, preserving first-seen order.
    # Includes files that are missing from disk (exists=False) so a report whose
    # artifacts were deleted still shows as an inert row rather than vanishing.
    groups: dict[str, list[dict]] = {}
    for f in run.get("files", []):
        name = Path(f["path"]).name
        if any(name.endswith(suffix) for suffix in _SIDECAR_SUFFIXES):
            continue
        groups.setdefault(f.get("recipe", ""), []).append(f)

    scope_str = _scope_str(run.get("scope", {}) or {})
    when = _run_when(run.get("timestamp", ""))
    date_group = _date_group(run.get("timestamp", ""))
    # Bundle is the whole-run zip; only meaningful if some file still exists.
    run_has_existing = any(f.get("exists") for f in run.get("files", []))
    bundle_href = f"/reports/bundle/{run_id}" if run_has_existing else None
    log_href = f"/api/reports/log/{run_id}" if run.get("log_file") else None

    reports: list[dict] = []
    for recipe, files in groups.items():
        if not files:
            continue
        category, cat_slug, icon = categorize(recipe)

        # Only on-disk files are linkable. One chip per FILE (not per distinct
        # format) so a recipe that emits several files of the same format keeps
        # them all reachable. Files are pre-sorted existing-first, HTML-first.
        existing = [f for f in files if f.get("exists")]
        format_links = [
            {
                "label": str(f.get("format", "")).upper(),
                "slug": str(f.get("format", "")).lower(),
                "href": f"/reports/file/{run_id}/{_encode_path(f['path'])}",
                "is_html": f.get("format") == "html",
                # filename for a hover title so same-format chips are
                # distinguishable (e.g. two CSVs → cards.csv vs summary.csv).
                "name": Path(f["path"]).name,
            }
            for f in existing
        ]

        html = next((f for f in existing if f.get("format") == "html"), None)
        view_href = (
            f"/reports/file/{run_id}/{_encode_path(html['path'])}" if html else None
        )
        size_src = html or (existing[0] if existing else {})
        size_display = size_src.get("size_kb", 0)

        reports.append(
            {
                "recipe": _recipe_label(recipe),
                "category": category,
                "cat_slug": cat_slug,
                "icon": icon,
                "formats": format_links,
                "view_href": view_href,
                # has_files: any artifact for this report still exists on disk;
                # False → inert "files removed" row.
                "has_files": bool(existing),
                "size_display": size_display,
                "scope_str": scope_str,
                "domain": run.get("domain", ""),
                "when": when,
                "date_group": date_group,
                "bundle_href": bundle_href,
                "log_href": log_href,
            }
        )
    return reports


def _enrich_history(runs: list[dict]) -> list[dict]:
    """Mark each file's on-disk existence (+ size/age for existing) and build
    the per-recipe report rows for each run.

    Resilient per run: a malformed/corrupt history record is skipped (logged)
    so one bad row can't blank the whole page. Missing files are kept (with
    ``exists=False``) so deleted reports still render as inert rows.
    """
    enriched: list[dict] = []
    for run in runs:
        try:
            out_dir = Path(run["output_dir"])
            files = []
            for f in run.get("files", []):
                abs_path = out_dir / f["path"]
                if abs_path.is_file():
                    stat = abs_path.stat()
                    files.append(
                        {
                            **f,
                            "name": abs_path.stem.replace("_", " ").title(),
                            "size_kb": round(stat.st_size / 1024),
                            "age": _human_age(stat.st_mtime),
                            "mtime": stat.st_mtime,
                            "exists": True,
                        }
                    )
                else:
                    files.append(
                        {
                            **f,
                            "name": Path(f["path"]).stem.replace("_", " ").title(),
                            "size_kb": 0,
                            "age": "",
                            "mtime": 0.0,
                            "exists": False,
                        }
                    )
            # existing-first, then HTML-first, then by name — so report rows
            # pick the primary HTML and order chips predictably.
            files.sort(
                key=lambda f: (
                    0 if f.get("exists") else 1,
                    0 if f.get("format") == "html" else 1,
                    f.get("name", ""),
                )
            )
            run["files"] = files
            run["reports"] = _build_reports(run)
            enriched.append(run)
        except Exception:
            logger.warning(
                "Skipping malformed history run %s", run.get("id", "?"), exc_info=True
            )
    return enriched


def _flatten_reports(runs: list[dict]) -> list[dict]:
    """Flatten enriched runs into a flat report list, newest-run-first.

    Sorts by run timestamp desc defensively so date-group headers stay
    contiguous even if the run source isn't already ordered.
    """
    rows: list[dict] = []
    for run in sorted(runs, key=lambda r: r.get("timestamp", ""), reverse=True):
        rows.extend(run.get("reports", []))
    return rows


def _load_report_rows() -> list[dict]:
    """Load + enrich + flatten the recent report rows. Never raises.

    On any failure logs a warning and returns ``[]`` so the page degrades to
    the empty state instead of a 500 (and distinguishes a real fault from a
    legitimately empty history).
    """
    try:
        return _flatten_reports(_enrich_history(list_runs(limit=50)))
    except Exception:
        logger.warning("Failed to load report history", exc_info=True)
        return []


@router.get("/reports")
async def reports_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the Report History page on the Command Center shell.

    Offline-capable: report history + file/log serving are local, so this page
    renders regardless of platform configuration (no /setup redirect).
    """
    reports = _load_report_rows()

    ctx = build_shell_context(
        state, nonce, crumb="Report History", active_view="reports"
    )
    ctx["state"] = state
    ctx["reports"] = reports
    ctx["total_reports"] = len(reports)

    templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/reports.html", ctx)


@router.get("/api/reports/list")
async def reports_list_fragment(request: Request) -> object:
    """Return the swappable Report History body fragment (for manual Refresh)."""
    templates = request.app.state.templates
    reports = _load_report_rows()
    return templates.TemplateResponse(
        request,
        "components/_reports_list.html",
        {"reports": reports},
    )


@router.get("/reports/file/{run_id}/{path:path}")
async def serve_history_file(run_id: str, path: str) -> StreamingResponse:
    """Serve a report file from any historically-recorded output directory.

    Uses StreamingResponse (no Content-Length) to avoid race conditions
    when a report is regenerated while being served.
    """
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

    def _iter_file():  # type: ignore[no-untyped-def]
        with open(abs_path, "rb") as f:
            while chunk := f.read(64 * 1024):
                yield chunk

    return StreamingResponse(_iter_file(), media_type=media_type)


@router.get("/reports/bundle/output")
async def download_output_bundle(
    state: WebAppState = Depends(get_state),
) -> StreamingResponse:
    """Zip all report files in the current output directory.

    B12 #5 deliberately does NOT apply the per-run flatten/``<name>-<date>.zip``
    rename here (the spec's "check the sibling path too"): this is a whole
    output-directory dump with no single run/recipe identity or timestamp to
    name from, and it inherently spans multiple recipes, so the nested
    ``reports_output.zip`` is the correct shape for it. The per-run history
    bundle (``/reports/bundle/{run_id}``) is where the rename/flatten applies.
    """
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


def _safe_name_stem(name: str) -> str:
    """Filesystem-safe stem for a download name (B12 #5)."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", str(name)).strip("-._")
    return stem or "report"


def _bundle_download_name(run: dict) -> str:
    """The ``<name>-<YYYY-MM-DD>.zip`` download name for a history run (B12 #5).

    Name source: the run's first recorded recipe — for a single-recipe or a
    compound/comparison run that IS the report/bundle name (compound/comparison
    files are tagged with the bundle recipe, see ``_build_history_files``);
    fallback → the first file's recipe, else the run id. Date comes from the run
    timestamp.
    """
    recipes = run.get("recipes") or []
    files = run.get("files", [])
    name = ""
    if recipes:
        name = str(recipes[0])
    elif files:
        name = str(files[0].get("recipe", ""))
    stem = _safe_name_stem(name or run.get("id", "reports"))
    date = str(run.get("timestamp", "")).split("T", 1)[0]
    return f"{stem}-{date}.zip" if date else f"{stem}.zip"


@router.get("/reports/bundle/{run_id}")
async def download_bundle(run_id: str) -> StreamingResponse:
    """Zip all report files for a history run and stream as a download."""
    from fs_report.report_history import get_run

    run = get_run(run_id)
    if not run:
        return JSONResponse({"error": "Run not found"}, status_code=404)  # type: ignore[return-value]

    output_dir = Path(run["output_dir"]).resolve()
    files = run.get("files", [])
    # B12 #5: flatten when the run is a SINGLE report (one distinct recipe) — drop
    # the redundant "<Recipe Name>/" nesting; keep recipe sub-dirs only when the
    # bundle spans >1 recipe (a workflow), so siblings don't collide.
    distinct_recipes = {f.get("recipe", "") for f in files}
    flatten = len(distinct_recipes) <= 1

    buf = io.BytesIO()
    file_count = 0
    used_arcnames: set[str] = set()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            abs_path = (output_dir / f["path"]).resolve()
            # Path traversal guard
            if not str(abs_path).startswith(str(output_dir)):
                continue
            if not abs_path.is_file():
                continue
            arcname = Path(f["path"]).name if flatten else f["path"]
            # On a flatten collision (two files sharing a basename), suffix the
            # stem so neither is dropped from the archive.
            if arcname in used_arcnames:
                p = Path(arcname)
                i = 1
                while f"{p.stem}-{i}{p.suffix}" in used_arcnames:
                    i += 1
                arcname = f"{p.stem}-{i}{p.suffix}"
            used_arcnames.add(arcname)
            zf.write(abs_path, arcname=arcname)
            file_count += 1

    if file_count == 0:
        return JSONResponse({"error": "No files available"}, status_code=404)  # type: ignore[return-value]

    buf.seek(0)
    filename = _bundle_download_name(run)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/reports/log/{run_id}")
async def serve_history_log(run_id: str) -> PlainTextResponse:
    """Serve the log file for a history run as plain text."""
    from fs_report.logging_utils import resolve_log_path
    from fs_report.report_history import get_run

    run = get_run(run_id)
    log_filename = run.get("log_file") if run else None

    # Shared resolver: the history DB's ``log_file`` is the primary hint; the
    # glob fallback gets the same glob-escape + newest-match behaviour as the
    # run router's log viewers, so every log endpoint resolves identically.
    log_path = resolve_log_path(run_id, log_filename)
    if log_path is None:
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


@router.get("/output/{path:path}")
async def serve_output_file(
    path: str,
    state: WebAppState = Depends(get_state),
) -> StreamingResponse:
    """Serve a report file from the output directory.

    Uses StreamingResponse (no Content-Length) to avoid race conditions
    when a report is regenerated while being served.
    """
    output_dir = Path(state.get("output_dir", "./output")).expanduser().resolve()
    abs_path = (output_dir / path).resolve()

    # Path traversal guard
    if not str(abs_path).startswith(str(output_dir)):
        return JSONResponse({"error": "Invalid path"}, status_code=400)  # type: ignore[return-value]

    # If path is a directory, try index.html
    if abs_path.is_dir():
        abs_path = abs_path / "index.html"

    if not abs_path.exists() or not abs_path.is_file():
        return JSONResponse({"error": "File not found"}, status_code=404)  # type: ignore[return-value]

    media_type = mimetypes.guess_type(str(abs_path))[0] or "application/octet-stream"

    def _iter_file():  # type: ignore[no-untyped-def]
        with open(abs_path, "rb") as f:
            while chunk := f.read(64 * 1024):
                yield chunk

    return StreamingResponse(_iter_file(), media_type=media_type)


@router.get("/setup")
async def setup_page(
    request: Request,
    nonce: str = Depends(get_nonce),
    state: WebAppState = Depends(get_state),
) -> object:
    """Render the first-run onboarding wizard."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "pages/setup.html",
        {
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
