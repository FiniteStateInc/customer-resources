"""Settings page and API router."""

import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from fs_report.cli.common import redact_token
from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.shell_context import build_shell_context
from fs_report.web.state import WebAppState

logger = logging.getLogger(__name__)

router = APIRouter(tags=["settings"])


def _detected_ai(state: WebAppState) -> dict[str, Any]:
    """Return read-only AI provider/key status detected from the environment.

    Mirrors ``LLMClient._detect_provider()``'s auto-detect EXACTLY (two-phase):
      1. First present of the PRIMARY vars, in order:
         ``ANTHROPIC_API_KEY``→anthropic, ``OPENAI_API_KEY``→openai,
         ``GEMINI_API_KEY``→gemini, ``GITHUB_TOKEN``→copilot.
      2. Only if phase 1 found nothing, the LEGACY fallbacks:
         ``ANTHROPIC_AUTH_TOKEN``→anthropic, then ``GOOGLE_API_KEY``→gemini.

    Grouping a legacy var into phase 1 would change precedence vs the run path
    when multiple creds are set (e.g. ``ANTHROPIC_AUTH_TOKEN`` +
    ``OPENAI_API_KEY`` must resolve to **openai**).

    The high/low model values reflect what a run would actually use: the
    ``ai_model_high`` / ``ai_model_low`` config overrides (from config.yaml,
    surfaced through ``state``) take precedence over the provider's
    ``MODEL_MAP`` defaults, exactly as ``cli/run.py`` merges them. When an
    override is in effect the corresponding ``*_overridden`` flag is True so
    the UI can label it.

    Returns ``{detected, provider, env_var, high_model, low_model,
    high_overridden, low_overridden, hint}``. Guarded: on any failure returns
    ``detected=False`` and never raises. Uses the public
    ``llm_client.AI_ENV_VARS`` for the "any key present?" hint; never imports
    the private ``_PROVIDER_ENV_VARS``.
    """
    empty: dict[str, Any] = {
        "detected": False,
        "provider": "",
        "provider_label": "",
        "env_var": "",
        "high_model": "",
        "low_model": "",
        "high_overridden": False,
        "low_overridden": False,
        "hint": "",
    }
    labels = {
        "anthropic": "Anthropic",
        "openai": "OpenAI",
        "gemini": "Gemini",
        "copilot": "Copilot",
    }
    try:
        from fs_report.llm_client import AI_ENV_VARS, MODEL_MAP

        # Phase 1 — primary vars, in detect order.
        primary: list[tuple[str, str]] = [
            ("ANTHROPIC_API_KEY", "anthropic"),
            ("OPENAI_API_KEY", "openai"),
            ("GEMINI_API_KEY", "gemini"),
            ("GITHUB_TOKEN", "copilot"),
        ]
        provider = ""
        env_var = ""
        for var, prov in primary:
            if os.getenv(var):
                provider, env_var = prov, var
                break

        # Phase 2 — legacy fallbacks (only if phase 1 found nothing).
        if not provider:
            legacy: list[tuple[str, str]] = [
                ("ANTHROPIC_AUTH_TOKEN", "anthropic"),
                ("GOOGLE_API_KEY", "gemini"),
            ]
            for var, prov in legacy:
                if os.getenv(var):
                    provider, env_var = prov, var
                    break

        if not provider:
            return {
                **empty,
                "hint": "No AI key detected — set " + " / ".join(AI_ENV_VARS),
            }

        high, low = MODEL_MAP.get(provider, ("", ""))
        # Config overrides win, exactly as cli/run.py merges them onto the
        # provider defaults. state.get returns None when unset (not in DEFAULTS).
        cfg_high = str(state.get("ai_model_high") or "").strip()
        cfg_low = str(state.get("ai_model_low") or "").strip()
        return {
            "detected": True,
            "provider": provider,
            "provider_label": labels.get(provider, provider.title()),
            "env_var": env_var,
            "high_model": cfg_high or high,
            "low_model": cfg_low or low,
            "high_overridden": bool(cfg_high),
            "low_overridden": bool(cfg_low),
            "hint": "",
        }
    except Exception:
        logger.warning("AI provider detection failed", exc_info=True)
        # Distinct from the "no key" case so a detection failure isn't misread
        # as a missing credential.
        return {**empty, "hint": "AI status unavailable"}


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
    """Gather cache database stats.

    The directory glob / stat calls are wrapped in try/except so a bad or
    inaccessible ``cache_dir`` degrades to an "unavailable" notice instead of
    raising (the page would otherwise 500). ``_count_rows`` is already guarded.
    """
    cache_dir = Path(
        str(state.get("cache_dir") or "").strip() or str(Path.home() / ".fs-report")
    )
    info: dict[str, Any] = {
        "location": str(cache_dir),
        "available": True,
        "api_entries": 0,
        "api_size_mb": 0.0,
        "domain_dbs": [],
        "nvd_size_mb": 0.0,
        "nvd_entries": 0,
        "ai_size_mb": 0.0,
        "ai_entries": 0,
    }

    try:
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

        # --- AI cache (cve_remediations + ai_summary_cache in cache.db) ---
        # Count BOTH narrative tables: ai_summary_cache holds the portfolio /
        # project / finding / action narrative, which is the bulk of the AI
        # cache and was previously omitted from the reported size.
        ai_db = cache_dir / "cache.db"
        info["ai_size_mb"] = _file_size_mb(ai_db)
        info["ai_entries"] = (
            max(_count_rows(ai_db, "cve_remediations"), 0)
            + max(_count_rows(ai_db, "ai_summary_cache"), 0)
            if ai_db.is_file()
            else 0
        )
    except Exception:
        logger.warning("Cache info collection failed for %s", cache_dir, exc_info=True)
        info["available"] = False

    return info


@router.get("/settings")
async def settings_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the Settings page on the Command Center shell.

    Offline-capable: local fields are editable without platform config and the
    page never redirects to /setup. Cache + AI provider detection are guarded
    so a bad cache_dir / import cannot 500 the page.
    """
    token_display = redact_token(state.token) if state.token else "(not set)"
    try:
        cache_info = _get_cache_info(state)
    except Exception:
        logger.warning("Cache info unavailable", exc_info=True)
        cache_info = {"location": str(state.get("cache_dir", "")), "available": False}

    ctx = build_shell_context(state, nonce, crumb="Settings", active_view="settings")
    ctx["state"] = state
    ctx["token_display"] = token_display
    ctx["cache_info"] = cache_info
    ctx["ai_detected"] = _detected_ai(state)
    ctx["nvd_mirror"] = os.getenv("FS_NVD_SERVICE_URL", "")

    templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/settings.html", ctx)


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
        "product_type",
        "network_exposure",
        "regulatory",
        "deployment_notes",
        # SP3: uploaded scoring/context file paths (global Settings defaults).
        "scoring_file",
        "context_file",
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

    # ── Couple version filter to project scope ───────────────────────────────
    # A version name is only meaningful relative to one project, so drop a bare
    # version_filter that has no project scoped (the engine rejects
    # version+multi-project anyway). The "version no longer belongs to the
    # project" case is handled AUTHORITATIVELY at the source: the scope cascade
    # clears the version when the project changes (see _scope_dropdowns.html),
    # so the form never submits a stale version past a project change. That is
    # deliberately NOT re-derived here from a version-name comparison — names
    # are not unique across projects, so a server-side equality check can't tell
    # a valid same-named re-pick (project A's "v2.0" → project B's "v2.0") from a
    # stale carry-over, and would silently wipe a legitimate selection.
    if state.get("version_filter") and not state.get("project_filter"):
        state["version_filter"] = ""

    state.save()
    return JSONResponse({"status": "saved"})


@router.get("/api/settings/cache")
async def cache_stats(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Return cache stats."""
    return JSONResponse(_get_cache_info(state))


@router.delete("/api/settings/cache/api")
async def clear_api_cache(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Clear all domain-specific API cache databases."""
    cache_dir = Path(
        str(state.get("cache_dir") or "").strip() or str(Path.home() / ".fs-report")
    )
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
    cache_dir = Path(
        str(state.get("cache_dir") or "").strip() or str(Path.home() / ".fs-report")
    )
    target = cache_dir / "nvd_cache.db"
    if target.is_file():
        target.unlink()
        return JSONResponse({"status": "cleared", "type": "nvd"})
    return JSONResponse({"status": "not_found", "type": "nvd"})


@router.delete("/api/settings/cache/ai")
async def clear_ai_cache(state: WebAppState = Depends(get_state)) -> JSONResponse:
    """Clear the AI narrative caches in cache.db.

    Clears ``cve_remediations`` (component/CVE guidance) and the project-specific
    narrative rows of ``ai_summary_cache`` (portfolio / project / finding /
    action). Preserves the project-blind library-fact rows (``identity`` /
    ``applicability``) — the same rows the schema-version purge keeps — so
    clearing customer narrative doesn't force expensive regeneration of shared
    facts. Clearing only ``cve_remediations`` (the original behavior) left the
    bulk of the project-naming narrative on disk.
    """
    from fs_report.llm_client import _FACT_SUMMARY_SCOPES

    cache_dir = Path(
        str(state.get("cache_dir") or "").strip() or str(Path.home() / ".fs-report")
    )
    target = cache_dir / "cache.db"
    if not target.is_file():
        return JSONResponse({"status": "not_found", "type": "ai"})

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(str(target))
        try:
            conn.execute("DELETE FROM cve_remediations")  # all narrative
        except sqlite3.OperationalError:
            pass  # table may not exist yet
        try:
            placeholders = ",".join("?" for _ in _FACT_SUMMARY_SCOPES)
            conn.execute(
                f"DELETE FROM ai_summary_cache "  # noqa: S608 - fixed placeholders
                f"WHERE scope IS NULL OR scope NOT IN ({placeholders})",
                tuple(_FACT_SUMMARY_SCOPES),
            )
        except sqlite3.OperationalError:
            pass
        conn.commit()
        conn.execute("VACUUM")
        return JSONResponse({"status": "cleared", "type": "ai"})
    except Exception:
        # Do NOT unlink cache.db here: it is shared with the API-data cache and
        # the project-blind fact tables (cve_detail/exploit_detail), so deleting
        # the file would destroy unrelated data. Report the failure instead.
        logger.warning("Failed to clear AI cache in %s", target, exc_info=True)
        return JSONResponse({"status": "error", "type": "ai"}, status_code=500)
    finally:
        if conn is not None:
            conn.close()


# ── Logo upload ───────────────────────────────────────────────────
@router.post("/api/logos/upload")
async def upload_logo(request: Request) -> JSONResponse:
    """Upload a logo image to ~/.fs-report/logos/."""
    form = await request.form()
    file = form.get("file")
    if file is None or not hasattr(file, "filename") or not hasattr(file, "read"):
        return JSONResponse({"error": "No file provided"}, status_code=400)

    filename = Path(str(file.filename)).name  # strip directory components
    allowed = {".png", ".jpg", ".jpeg", ".svg", ".webp"}
    suffix = Path(filename).suffix.lower()
    if suffix not in allowed:
        return JSONResponse(
            {
                "error": f"Invalid file type: {suffix}. Allowed: {', '.join(sorted(allowed))}"
            },
            status_code=400,
        )

    contents = await file.read()
    if len(contents) > 512_000:
        return JSONResponse({"error": "File too large (max 500KB)"}, status_code=400)

    logos_dir = Path.home() / ".fs-report" / "logos"
    logos_dir.mkdir(parents=True, exist_ok=True)
    dest = logos_dir / filename
    dest.write_bytes(contents)

    return JSONResponse({"filename": filename})


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


@router.post("/api/filesystem/mkdir")
async def create_directory(request: Request) -> JSONResponse:
    """Create a new subdirectory inside the given parent path."""
    body = await request.json()
    parent = body.get("parent", "").strip()
    name = body.get("name", "").strip()

    if not parent or not name:
        return JSONResponse(
            {"error": "Parent path and folder name are required"}, status_code=400
        )

    # Sanitise: block path separators and hidden dirs
    if "/" in name or "\\" in name or name.startswith("."):
        return JSONResponse({"error": "Invalid folder name"}, status_code=400)

    try:
        parent_path = Path(parent).expanduser().resolve()
        if not parent_path.is_dir():
            return JSONResponse(
                {"error": f"Not a directory: {parent_path}"}, status_code=400
            )

        new_dir = (parent_path / name).resolve()
        # Path traversal guard
        if not str(new_dir).startswith(str(parent_path)):
            return JSONResponse({"error": "Invalid folder name"}, status_code=400)

        new_dir.mkdir(exist_ok=True)
        return JSONResponse({"created": str(new_dir)})
    except PermissionError:
        return JSONResponse({"error": "Permission denied"}, status_code=403)
    except OSError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
