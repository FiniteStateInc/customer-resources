"""SP3 file uploads — POST /api/uploads (scoring / context / recs) + helpers.

Mirrors the logo-upload pattern (`settings.upload_logo`): validate, store under a
unique immutable name, return the stored path. The persisted scoring/context
paths become ordinary string overrides; the recs path feeds the one-shot apply
(`/api/vex/apply-file`). CSRF is enforced by the middleware via the
``X-FS-Session`` header (multipart bodies carry no ``_csrf`` field).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from fs_report.web.dependencies import get_state
from fs_report.web.state import WebAppState

router = APIRouter()

_TRUTHY = {"true", "on", "1", "yes"}


def _is_truthy(v: object) -> bool:
    return str(v).strip().lower() in _TRUTHY


def _status_list(raw: object) -> list[str] | None:
    """Coerce a comma-string or list to an uppercased VEX-status list (or None)."""
    if not raw:
        return None
    items = raw if isinstance(raw, list) else str(raw).split(",")
    out = [str(s).strip().upper() for s in items if str(s).strip()]
    return out or None


UPLOADS_ROOT = Path.home() / ".fs-report" / "uploads"

_KINDS = ("scoring", "context", "recs")
_KIND_SUFFIXES: dict[str, set[str]] = {
    "scoring": {".yaml", ".yml"},
    "context": {".yaml", ".yml"},
    "recs": {".json"},
}
_MAX_BYTES: dict[str, int] = {
    "scoring": 1_000_000,
    "context": 1_000_000,
    "recs": 8_000_000,
}


def uploads_dir(kind: str) -> Path:
    """The storage dir for a given upload kind (created on demand)."""
    d = UPLOADS_ROOT / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def confine_to(path: str, base: Path) -> Path | None:
    """Canonicalize ``path`` and return it only if it resolves under ``base``.

    Returns ``None`` for any path outside ``base`` (path-traversal guard) or that
    can't be resolved. Used by the destructive apply endpoint to confine the
    client-supplied recs path to ``uploads/recs/``.
    """
    try:
        resolved = Path(path).resolve()
        resolved.relative_to(base.resolve())
        return resolved
    except (ValueError, OSError):
        return None


def _store_unique(kind: str, filename: str, contents: bytes) -> Path:
    """Store ``contents`` under a unique, immutable name; return the path.

    ``<stem>-<uuid4-hex><ext>`` — a per-upload random token (never a content
    hash), so two uploads never alias one file and a previewed recs file can't
    change underneath a pending apply.
    """
    safe = Path(filename).name  # strip directory components
    stem = Path(safe).stem or "upload"
    ext = Path(safe).suffix
    dest = uploads_dir(kind) / f"{stem}-{uuid.uuid4().hex}{ext}"
    dest.write_bytes(contents)
    return dest


@router.post("/api/uploads")
async def upload_file(request: Request) -> JSONResponse:
    """Upload a scoring/context YAML or a recs JSON (SP3 §4).

    200 -> {"path", "name", "warnings": [...]} ; hard failure -> 400 {"error"}.
    """
    form = await request.form()
    kind = str(form.get("kind", "")).strip().lower()
    if kind not in _KINDS:
        return JSONResponse(
            {"error": f"kind must be one of: {', '.join(_KINDS)}"}, status_code=400
        )

    file = form.get("file")
    if file is None or not hasattr(file, "filename") or not hasattr(file, "read"):
        return JSONResponse({"error": "No file provided"}, status_code=400)

    filename = Path(str(file.filename)).name
    suffix = Path(filename).suffix.lower()
    if suffix not in _KIND_SUFFIXES[kind]:
        allowed = ", ".join(sorted(_KIND_SUFFIXES[kind]))
        return JSONResponse(
            {
                "error": f"invalid file type {suffix or '(none)'} for {kind}; allowed: {allowed}"
            },
            status_code=400,
        )

    contents = await file.read()
    if len(contents) > _MAX_BYTES[kind]:
        mb = _MAX_BYTES[kind] // 1_000_000
        return JSONResponse({"error": f"file too large (max {mb}MB)"}, status_code=400)
    if not contents.strip():
        return JSONResponse({"error": "file is empty"}, status_code=400)

    # Store first (the YAML validators read by path), then validate; remove the
    # stored file on a hard failure so a bad upload leaves nothing behind.
    dest = _store_unique(kind, filename, contents)
    warnings: list[str] = []
    try:
        if kind == "scoring":
            from fs_report.scoring_support import validate_scoring_yaml

            errors, warnings = validate_scoring_yaml(str(dest))
            if errors:
                dest.unlink(missing_ok=True)
                return JSONResponse({"error": "; ".join(errors)}, status_code=400)
        elif kind == "context":
            from fs_report.deployment_context import load_context_file

            try:
                load_context_file(str(dest))
            except (FileNotFoundError, ValueError) as e:
                dest.unlink(missing_ok=True)
                return JSONResponse(
                    {"error": f"invalid context file: {e}"}, status_code=400
                )
        else:  # recs
            try:
                data = json.loads(contents)
            except ValueError as e:
                dest.unlink(missing_ok=True)
                return JSONResponse({"error": f"invalid JSON: {e}"}, status_code=400)
            if not (
                isinstance(data, list)
                and data
                and all(isinstance(r, dict) for r in data)
            ):
                dest.unlink(missing_ok=True)
                return JSONResponse(
                    {
                        "error": "recommendations must be a non-empty JSON array of objects"
                    },
                    status_code=400,
                )
    except Exception:
        dest.unlink(missing_ok=True)
        raise

    return JSONResponse({"path": str(dest), "name": filename, "warnings": warnings})


@router.post("/api/vex/apply-file")
async def apply_vex_file(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """One-shot destructive apply of an uploaded vex_recommendations.json (SP3 §7).

    Body ``{path, dry_run?, confirm?, autotriage_status?, vex_override?}``.
    Reuses SP2's ``apply_recs_file`` + ``summarize_apply_result``. Safety:
    - the ``path`` is **canonicalized + confined to ~/.fs-report/uploads/recs/**
      (a destructive endpoint never applies an arbitrary server path) → 400;
    - a **real** (non-dry-run) apply requires ``confirm: true`` → else 400
      (parity with SP2's direct-real launch).
    """
    try:
        body = await request.json()
    except Exception:
        try:
            body = dict(await request.form())
        except Exception:
            body = {}

    raw_path = str(body.get("path", "")).strip()
    if not raw_path:
        return JSONResponse({"error": "path is required"}, status_code=400)

    confined = confine_to(raw_path, uploads_dir("recs"))
    if confined is None or not confined.is_file():
        return JSONResponse(
            {"error": "path must be a previously uploaded recs file"}, status_code=400
        )

    dry_run = _is_truthy(body.get("dry_run"))
    if not dry_run and not _is_truthy(body.get("confirm")):
        return JSONResponse(
            {"error": "confirm=true required to write VEX to the platform"},
            status_code=400,
        )

    token = state.token
    domain = state.domain
    if not token or not domain:
        return JSONResponse({"error": "missing token or domain"}, status_code=400)

    from fs_report.vex_apply_support import apply_recs_file, summarize_apply_result

    try:
        result = apply_recs_file(
            str(confined),
            domain=domain,
            auth_token=token,
            dry_run=dry_run,
            vex_override=_is_truthy(body.get("vex_override")),
            filter_statuses=_status_list(body.get("autotriage_status")),
        )
    except Exception:
        import logging

        logging.getLogger(__name__).warning("apply-vex-file failed", exc_info=True)
        return JSONResponse(
            {"error": "VEX apply failed; see server log"}, status_code=500
        )

    return JSONResponse({"dry_run": dry_run, "summary": summarize_apply_result(result)})
