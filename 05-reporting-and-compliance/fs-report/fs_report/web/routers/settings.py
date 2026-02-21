"""Settings page and API router."""

import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from fs_report.cli.common import redact_token
from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.state import WebAppState

router = APIRouter(tags=["settings"])


def _count_rows(db_path: Path, table: str) -> int:
    """Return row count for *table* in *db_path*, or -1 on error."""
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.execute(f"SELECT COUNT(*) FROM [{table}]")  # noqa: S608
        count: int = cur.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return -1


def _file_size_mb(path: Path) -> float:
    return round(path.stat().st_size / (1024 * 1024), 2) if path.is_file() else 0


def _get_cache_info(state: WebAppState) -> dict[str, Any]:
    """Gather cache database stats."""
    cache_dir = Path(state.get("cache_dir", "") or str(Path.home() / ".fs-report"))
    info: dict[str, Any] = {"location": str(cache_dir)}

    # --- API cache (domain-specific *.db files contain cache_meta) ---
    api_entries = 0
    api_size = 0.0
    domain_dbs: list[str] = []
    for db_file in sorted(cache_dir.glob("*.finitestate.io.db")):
        n = _count_rows(db_file, "cache_meta")
        if n >= 0:
            api_entries += n
        api_size += _file_size_mb(db_file)
        domain_dbs.append(db_file.name)
    info["api_entries"] = api_entries
    info["api_size_mb"] = round(api_size, 2)
    info["domain_dbs"] = domain_dbs

    # --- NVD cache ---
    nvd_path = cache_dir / "nvd_cache.db"
    info["nvd_size_mb"] = _file_size_mb(nvd_path)
    info["nvd_entries"] = (
        _count_rows(nvd_path, "nvd_cve_cache") if nvd_path.is_file() else 0
    )

    # --- AI remediation cache (cve_remediations in cache.db) ---
    ai_db = cache_dir / "cache.db"
    info["ai_size_mb"] = _file_size_mb(ai_db)
    info["ai_entries"] = (
        _count_rows(ai_db, "cve_remediations") if ai_db.is_file() else 0
    )

    return info


@router.get("/settings")
async def settings_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the settings page."""
    token_display = redact_token(state.token) if state.token else "(not set)"
    cache_info = _get_cache_info(state)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/settings.html",
        {
            "request": request,
            "nonce": nonce,
            "state": state,
            "token_display": token_display,
            "cache_info": cache_info,
        },
    )


@router.get("/api/settings")
async def get_settings(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Return current settings as JSON."""
    data = state.to_dict()
    # Never expose token
    data.pop("token", None)
    return JSONResponse(data)


@router.post("/api/settings")
async def save_settings(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Save settings from form submission."""
    form = await request.form()

    for key in (
        "output_dir",
        "period",
        "cache_ttl",
        "project_filter",
        "folder_filter",
        "version_filter",
        "finding_types",
        "ai_depth",
        "logo",
    ):
        val = form.get(key)
        if val is not None:
            state[key] = str(val)

    for key in (
        "overwrite",
        "verbose",
        "current_version_only",
        "ai",
        "ai_prompts",
    ):
        val = form.get(key)
        state[key] = str(val).lower() in ("true", "on", "1", "yes") if val else False

    state.save()
    return JSONResponse({"status": "saved"})


@router.get("/api/settings/cache")
async def cache_stats(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Return cache stats."""
    return JSONResponse(_get_cache_info(state))


@router.delete("/api/settings/cache/api")
async def clear_api_cache(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Clear all domain-specific API cache databases."""
    cache_dir = Path(state.get("cache_dir", "") or str(Path.home() / ".fs-report"))
    cleared = 0
    for db_file in cache_dir.glob("*.finitestate.io.db"):
        db_file.unlink(missing_ok=True)
        # Also remove WAL/SHM sidecar files
        for suffix in ("-wal", "-shm"):
            sidecar = db_file.parent / (db_file.name + suffix)
            sidecar.unlink(missing_ok=True)
        cleared += 1
    if cleared:
        return JSONResponse({"status": "cleared", "type": "api", "count": cleared})
    return JSONResponse({"status": "not_found", "type": "api"})


@router.delete("/api/settings/cache/nvd")
async def clear_nvd_cache(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Clear the NVD CVE cache."""
    cache_dir = Path(state.get("cache_dir", "") or str(Path.home() / ".fs-report"))
    target = cache_dir / "nvd_cache.db"
    if target.is_file():
        target.unlink()
        return JSONResponse({"status": "cleared", "type": "nvd"})
    return JSONResponse({"status": "not_found", "type": "nvd"})


@router.delete("/api/settings/cache/ai")
async def clear_ai_cache(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Clear the AI remediation cache (cve_remediations table in cache.db)."""
    cache_dir = Path(state.get("cache_dir", "") or str(Path.home() / ".fs-report"))
    target = cache_dir / "cache.db"
    if target.is_file():
        try:
            conn = sqlite3.connect(str(target))
            conn.execute("DELETE FROM cve_remediations")
            conn.commit()
            conn.execute("VACUUM")
            conn.close()
            return JSONResponse({"status": "cleared", "type": "ai"})
        except Exception:
            # Table may not exist; delete the whole file
            target.unlink(missing_ok=True)
            return JSONResponse({"status": "cleared", "type": "ai"})
    return JSONResponse({"status": "not_found", "type": "ai"})


# ── Available logos ───────────────────────────────────────────────
@router.get("/api/logos")
async def list_logos() -> JSONResponse:
    """List available logo images in ~/.fs-report/logos/."""
    logos_dir = Path.home() / ".fs-report" / "logos"
    if not logos_dir.is_dir():
        return JSONResponse({"logos": []})
    allowed = {".png", ".jpg", ".jpeg", ".svg", ".webp"}
    logos = sorted(
        f.name
        for f in logos_dir.iterdir()
        if f.is_file() and f.suffix.lower() in allowed
    )
    return JSONResponse({"logos": logos})


# ── Filesystem browser ───────────────────────────────────────────
@router.get("/api/filesystem/browse")
async def browse_filesystem(
    path: str = Query(""),
) -> JSONResponse:
    """List directories at *path* for the directory picker."""
    try:
        base = Path(path).expanduser().resolve() if path.strip() else Path.home()
        if not base.is_dir():
            return JSONResponse({"error": f"Not a directory: {base}"}, status_code=400)
        dirs: list[str] = sorted(
            entry.name
            for entry in base.iterdir()
            if entry.is_dir() and not entry.name.startswith(".")
        )
        parent = str(base.parent) if base.parent != base else None
        return JSONResponse({"current": str(base), "parent": parent, "dirs": dirs})
    except PermissionError:
        return JSONResponse({"error": "Permission denied"}, status_code=403)
