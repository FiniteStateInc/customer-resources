"""Workflow Builder CRUD + export router (Pass 3, Tasks 2 & 4).

Endpoints
---------
GET  /api/workflows                       → list summaries
GET  /api/workflows/{slug}                → load + normalize
POST /api/workflows                       → save (create or overwrite)
DELETE /api/workflows/{slug}              → delete
POST /api/workflows/export?target=<...>   → export to one of four targets

POST and DELETE are CSRF-guarded by ``CSRFMiddleware`` (middleware-level;
no per-endpoint logic required here — matches the other routers).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.shell_context import build_shell_context
from fs_report.web.state import WebAppState
from fs_report.web.workflow_export import TARGETS, dispatch
from fs_report.web.workflow_meta import MCP_TOOLS
from fs_report.workflow_store import (
    _RESERVED_CANVAS_IDS,
    WorkflowCorrupt,
    WorkflowNotFound,
    WorkflowValidationError,
    _normalize_model,
    _validate_for_save,
    delete_workflow,
    list_workflows,
    load_workflow,
    save_workflow,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["workflows"])


def _forge_builder_enabled() -> bool:
    """Whether the Forge/MCP Builder surface is shown (#7, B6).

    Gates the MCP-tool library group + the Forge YAML / Forge MCP export targets.
    Single server-side flag, **DEFAULT OFF** for 2.0 — the backend (``MCP_TOOLS``,
    ``workflow_export``) stays intact; only the UI surface is hidden.  Flip
    ``FORGE_BUILDER_ENABLED`` (1/true/yes/on) to re-enable.
    """
    return os.getenv("FORGE_BUILDER_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# ── scope_override (#11, B5) ──────────────────────────────────────
# A workflow run may carry an optional run-time global scope override so a saved
# or inline workflow can be re-targeted WITHOUT editing the saved doc.  It is
# read once here (one read path for {slug}, {model}, and replay bodies), applied
# as an overlay on the in-memory model's global scope before preflight/run, and
# is NEVER persisted back to the store.
_SCOPE_OVERRIDE_KEYS = ("project", "project_id", "folder", "version")


def _parse_scope_override(raw: object) -> dict[str, str] | None:
    """Validate + normalize a request body's ``scope_override``.

    Returns a ``{project, project_id, folder, version}`` dict of trimmed
    strings, or ``None`` when absent / an empty object (no scope intent).
    ``folder`` is a folder **ID** (matching ``global.folder_filter``), not a
    display name; ``project_id`` is the unambiguous project ID companion to
    ``project`` (the name), used to resolve same-named projects across folders.
    Raises :class:`ValueError` for a malformed shape — a non-object, an
    **unknown key** (so a typo like ``projct`` fails loudly instead of silently
    clearing scope to portfolio), or a non-string field — so the caller can
    return 400.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("scope_override must be a JSON object")
    unknown = set(raw) - set(_SCOPE_OVERRIDE_KEYS)
    if unknown:
        raise ValueError(
            "scope_override has unknown key(s): "
            + ", ".join(sorted(map(str, unknown)))
            + f" (allowed: {', '.join(_SCOPE_OVERRIDE_KEYS)})"
        )
    # An empty object carries no scope intent → treat as "no override" so a
    # caller must send at least one (possibly empty-string) recognized field to
    # deliberately re-target/clear scope.
    if not raw:
        return None
    out: dict[str, str] = {}
    for k in _SCOPE_OVERRIDE_KEYS:
        v = raw.get(k, "")
        if v is None:
            v = ""
        if not isinstance(v, str):
            raise ValueError(f"scope_override.{k} must be a string")
        out[k] = v.strip()
    return out


def _apply_scope_override(model: dict, override: dict[str, str]) -> None:
    """Overlay *override* onto *model*'s global scope, in place.

    A run-time scope override fully defines the global target: project wins
    (a chosen project clears the folder), a folder-only choice clears the
    project, and an empty override clears both (portfolio-wide).  Idempotent —
    re-applying the same override (e.g. on a replay) yields the same scope, so
    storing the override in a replay body can never compound.
    """
    g = model.setdefault("global", {})
    project = override.get("project", "")
    folder = override.get("folder", "")
    g["project_filter"] = project
    # Project ID companion (name stays the visible target): resolves the exact
    # project among same-named ones. Only alongside a project — a folder-only /
    # portfolio override clears it so no stale ID lingers.
    g["project_id"] = override.get("project_id", "") if project else ""
    g["folder_filter"] = "" if project else folder
    g["version_filter"] = override.get("version", "")


def _override_validation_errors(model: dict) -> list[str]:
    """Run validate_run_overrides over the workflow global block + each step's
    overrides; prefix step errors with the step id.  Empty list = OK."""
    from fs_report.web.routers.run import (  # inline (avoid cycle)
        validate_destructive_overrides,
        validate_run_overrides,
    )

    gblock = model.get("global", {}) or {}
    errs: list[str] = list(validate_run_overrides(gblock))
    # B7 (#10B): autotriage in the workflow GLOBAL block is always rejected
    # (recipes=[] → no FP context), so the FP autotriage opt-in can only ever be
    # a per-step override on an FP step — never a global that autotriages every
    # step. The per-step check below passes each step's recipe ref so an FP step
    # may carry it.
    errs.extend(validate_destructive_overrides(gblock, recipes=[], is_workflow=True))
    # Step-id integrity (fix ⑥): step ids key the canvas node, the SSE step_id,
    # AND the Builder's raw step.id — a duplicate or a reserved-canvas-id
    # collision breaks node lighting.  ``_validate_for_save`` already enforces
    # this for save + the inline ``{model}`` run; re-checking here also covers
    # the saved-``{slug}`` run path against a hand-edited YAML that bypassed save.
    seen_ids: set[str] = set()
    for i, step in enumerate(model.get("steps", []) or []):
        sid = step.get("id", f"step {i}")
        sov = step.get("overrides", {}) or {}
        for e in validate_run_overrides(sov):
            errs.append(f"Step {sid!r}: {e}")
        # B7: pass the step's recipe ref so an FP step may carry the autotriage
        # opt-in (validate_destructive_overrides gates it FP-only in a workflow).
        _step_ref = str(step.get("ref", ""))
        for e in validate_destructive_overrides(
            sov, recipes=[_step_ref], is_workflow=True
        ):
            errs.append(f"Step {sid!r}: {e}")
        step_id = step.get("id")
        if step_id in _RESERVED_CANVAS_IDS:
            errs.append(f"Step id {step_id!r} is reserved")
        elif step_id in seen_ids:
            errs.append(f"Duplicate step id {step_id!r}")
        seen_ids.add(step_id)
    return errs


def _raw_submission_errors(model: dict) -> list[str]:
    """Errors for submission-level period/range ambiguities that normalization
    would silently resolve.  Run on the RAW submitted model (before normalize)
    so an ambiguous client payload 400s instead of being rewritten.

    For the global block and each step's overrides:
    - A NON-"custom" period set together with a start/end range → reject
      (ambiguous: named period + custom range).  period == "custom" is the
      LEGACY SP0 sentinel — it is exempted here so a legacy body migrates.
    - A partial range (exactly one of start/end set) → reject (both-or-neither).
    """

    def _check_block(block: object, prefix: str) -> list[str]:
        errs: list[str] = []
        # The RAW (un-normalized) model may hold any JSON value for a malformed
        # payload.  A non-dict block carries no period/range to check; leave its
        # structural rejection to _normalize_model / _validate_for_save (which
        # 400/422 it) rather than raising a 500 here.
        if not isinstance(block, dict):
            return errs
        period = block.get("period")
        start = block.get("start")
        end = block.get("end")

        # Treat a value as "set" only when it is non-None and non-whitespace string.
        def _is_set(v: object) -> bool:
            if v is None:
                return False
            if isinstance(v, str) and not v.strip():
                return False
            return True

        period_set = _is_set(period) and str(period).strip().lower() != "custom"
        has_start = _is_set(start)
        has_end = _is_set(end)

        if period_set and (has_start or has_end):
            errs.append(
                f"{prefix}specify either a named period or a custom start/end range, not both"
            )
        elif has_start != has_end:
            errs.append(
                f"{prefix}both 'start' and 'end' must be provided together for a custom date range"
            )
        return errs

    # Mirror _normalize_model's source selection EXACTLY (`global` OR the
    # `global_` alias, on ANY falsy value — not just None), so an ambiguous
    # payload can't bypass the check via the alias when `global` is present-but-
    # falsy (e.g. `{}`).
    global_block = model.get("global") or model.get("global_") or {}
    errs: list[str] = _check_block(global_block, "")
    raw_steps = model.get("steps", []) or []
    if not isinstance(raw_steps, list):
        raw_steps = []
    for i, step in enumerate(raw_steps):
        # A malformed (non-dict) step can't carry overrides to check; skip it
        # (its structure is rejected later by _normalize_model/_validate_for_save).
        if not isinstance(step, dict):
            continue
        sid = step.get("id", f"step {i}")
        step_errs = _check_block(step.get("overrides", {}) or {}, f"Step {sid!r}: ")
        errs.extend(step_errs)
    return errs


# ---------------------------------------------------------------------------
# GET /workflows/builder — the Workflow Builder authoring page
# ---------------------------------------------------------------------------


def _json_safe_params(spec: dict[str, object]) -> dict[str, object]:
    """Return a JSON-serializable copy of an MCP-tool ``params`` spec.

    Each param spec may carry a ``type`` whose value is a Python type object
    (e.g. ``str``) — not JSON-encodable.  Convert it to its lowercase name
    (``"str"``) so the spec can ride the ``window`` bootstrap; all other keys
    (``required`` / ``default`` / ``domain``) are already JSON-safe and pass
    through unchanged.
    """
    out: dict[str, object] = {}
    for key, raw in spec.items():
        if not isinstance(raw, dict):
            out[key] = raw
            continue
        clean = dict(raw)
        if "type" in clean and isinstance(clean["type"], type):
            clean["type"] = clean["type"].__name__
        out[key] = clean
    return out


@router.get("/workflows/builder")
async def builder_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the Workflow Builder authoring page on the Command Center shell.

    Offline-capable (spec §5.1): authoring, save, and export work without
    platform configuration, so this route never redirects to ``/setup`` — it
    mirrors the Settings / Report History page routes.

    Passes to the template:

    * ``recipes`` — the shared shell recipe list (``build_shell_context``
      already excludes ``category == "comparison"`` recipes), used to render
      the draggable Reports library cards.
    * ``mcp_tools`` — the canonical six MCP tools (id / title / tool / icon /
      params) from ``workflow_meta.MCP_TOOLS``, used to render the MCP-tool
      library cards (each tagged "export-only — runs via Forge agent") and to
      drive the per-tool inspector ``params`` fields (Task 7). The ``params``
      spec is JSON-safe (``type`` objects are emitted as a string tag) so it can
      ride a ``window`` bootstrap script.

    The CSRF nonce is exposed via the shell's ``fs-csrf`` meta and bootstrapped
    into ``window.NONCE`` (mirroring Settings) so the save / load / delete
    fetches can send the ``X-FS-Session`` header.
    """
    ctx = build_shell_context(state, nonce, crumb="Builder", active_view="builder")
    ctx["state"] = state
    # The library MCP tools — id/title/tool/icon for the cards PLUS a JSON-safe
    # ``params`` spec so the Task-7 inspector can render each tool's editable
    # params without a second source of truth.  A param spec's ``type`` value is
    # a Python type object (e.g. ``str``) which is not JSON-serializable, so it
    # is emitted as a lowercase string tag (``"str"``) the client treats as a
    # free-text field.  ``required`` / ``default`` / ``domain`` pass through.
    # PR3.1: comparison_recipes is set by build_shell_context (shell_context.py
    # ~line 449 via load_comparison_recipes) and is already in ctx — no inline
    # reload needed here.
    ctx["mcp_tools"] = [
        {
            "id": t["id"],
            "title": t["title"],
            "tool": t["id"],
            "icon": t["icon"],
            "params": _json_safe_params(t.get("params", {})),
        }
        for t in MCP_TOOLS
    ]
    # #7 (B6): gate the Forge/MCP surface (MCP library group + Forge export
    # targets) — default OFF.  Exposed to the template (library group) and, via
    # the page bootstrap, to JS (exportTargets filtering).
    ctx["forge_builder_enabled"] = _forge_builder_enabled()

    templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/builder.html", ctx)


# ---------------------------------------------------------------------------
# GET /builder — alias that redirects to /workflows/builder (preserves query)
# ---------------------------------------------------------------------------


@router.get("/builder")
async def builder_alias(request: Request) -> RedirectResponse:
    """Alias for /workflows/builder — redirects with a 307 (temporary).

    Preserves the incoming query string so ``/builder?kind=compound&new=1``
    forwards to ``/workflows/builder?kind=compound&new=1``; client-side
    ``?kind``/``new``/``load`` dispatch is handled by builder-page.js (PR1.5).
    """
    qs = request.url.query
    target = f"/workflows/builder?{qs}" if qs else "/workflows/builder"
    return RedirectResponse(url=target, status_code=307)


# ---------------------------------------------------------------------------
# GET /api/workflows
# ---------------------------------------------------------------------------


@router.get("/api/workflows")
async def get_workflows() -> JSONResponse:
    """Return a summary list of all saved workflows.

    Each entry carries ``{name, slug, step_count, updated}``.  Malformed
    files are skipped by the store (it logs a WARNING and continues) so
    one bad file can never blank the whole list.
    """
    return JSONResponse(list_workflows())


# ---------------------------------------------------------------------------
# GET /api/workflows/{slug}
# ---------------------------------------------------------------------------


@router.get("/api/workflows/{slug}")
async def get_workflow(slug: str) -> JSONResponse:
    """Return the normalized workflow model for *slug*.

    * Bad slug (fails regex/path-safety validation) → **404** (can't exist).
    * File absent → **404**.
    * File present but corrupt → **422** with a descriptive message.
    """
    try:
        model = load_workflow(slug)
    except WorkflowCorrupt as exc:
        # File present but unparseable — must come before ValueError since
        # WorkflowCorrupt subclasses ValueError.
        logger.warning("Workflow %r is corrupt: %s", slug, exc)
        return JSONResponse(
            {"error": str(exc)},
            status_code=422,
        )
    except WorkflowNotFound:
        return JSONResponse(
            {"error": f"Workflow not found: {slug!r}"},
            status_code=404,
        )
    except ValueError:
        # _validate_slug raised — slug is structurally invalid, can't exist.
        return JSONResponse(
            {"error": f"Workflow not found: {slug!r}"},
            status_code=404,
        )
    return JSONResponse(model)


# ---------------------------------------------------------------------------
# POST /api/workflows
# ---------------------------------------------------------------------------


@router.post("/api/workflows")
async def create_workflow(request: Request) -> JSONResponse:
    """Save (create or overwrite) a workflow from the JSON body.

    Returns ``{slug, status}`` on success.  On validation failure
    (``WorkflowValidationError``, ``ValueError`` from the store, or an
    empty name that produces an invalid slug) → **400** with the message.

    CSRF-guarded by ``CSRFMiddleware`` (header ``X-FS-Session`` required).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Request body must be valid JSON"}, status_code=400
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "Workflow model must be a JSON object"}, status_code=400
        )

    # Check RAW body for submission-level period/range ambiguities FIRST, before
    # normalization hides them.  A NON-"custom" period + start/end is ambiguous
    # and must 400.  period=="custom" is the legacy SP0 sentinel and is exempted
    # so a legacy body can still migrate to start/end.
    raw_errs = _raw_submission_errors(body)
    if raw_errs:
        return JSONResponse(
            {"error": "; ".join(raw_errs), "errors": raw_errs}, status_code=400
        )

    # Validate the NORMALIZED model for field values (bad ISO dates, bad scan
    # enum, unparseable period, bad top/triage, etc.).  save_workflow re-normalizes
    # internally, so passing the raw body there is fine.
    try:
        norm = _normalize_model(body)
    except (WorkflowValidationError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    errs = _override_validation_errors(norm)
    if errs:
        return JSONResponse({"error": "; ".join(errs), "errors": errs}, status_code=400)

    try:
        wf_slug = save_workflow(body)
    except WorkflowValidationError as exc:
        # Must come before ValueError since WorkflowValidationError subclasses it.
        return JSONResponse({"error": str(exc)}, status_code=400)
    except ValueError as exc:
        # Bad derived slug (e.g. empty name → slug("") → "workflow" might be ok,
        # but an illegal slug from _validate_slug propagates here).
        return JSONResponse({"error": str(exc)}, status_code=400)

    return JSONResponse({"slug": wf_slug, "status": "saved"})


# ---------------------------------------------------------------------------
# DELETE /api/workflows/{slug}
# ---------------------------------------------------------------------------


@router.delete("/api/workflows/{slug}")
async def remove_workflow(slug: str) -> JSONResponse:
    """Delete the workflow for *slug*.

    * Bad slug → **404**.
    * Absent file → **404**.
    * Deleted successfully → **200** ``{status: "deleted", slug}``.

    CSRF-guarded by ``CSRFMiddleware`` (header ``X-FS-Session`` required).
    """
    try:
        found = delete_workflow(slug)
    except ValueError:
        return JSONResponse(
            {"error": f"Workflow not found: {slug!r}"},
            status_code=404,
        )

    if not found:
        return JSONResponse(
            {"error": f"Workflow not found: {slug!r}"},
            status_code=404,
        )

    return JSONResponse({"status": "deleted", "slug": slug})


# ---------------------------------------------------------------------------
# POST /api/workflows/export?target=<cli|forge_yaml|github_action|forge_mcp>
# ---------------------------------------------------------------------------


@router.post("/api/workflows/export")
async def export_workflow(
    request: Request,
    target: str = Query(
        ..., description="Export target: cli, forge_yaml, github_action, or forge_mcp"
    ),
) -> JSONResponse:
    """Export a workflow to one of four runnable artifacts.

    **Request body** — either:
    - ``{slug: "<slug>"}`` to load a saved workflow from the store, or
    - ``{model: {<workflow model>}}`` to export an inline (unsaved) model.

    **Query parameter** ``target`` — one of:
    - ``cli`` — shell script (``.sh``)
    - ``forge_yaml`` — finite-state-forge workflow file (``.yaml``)
    - ``github_action`` — GitHub Actions job YAML (``.yml``)
    - ``forge_mcp`` — Forge MCP JS snippet (``.js``)

    **Response** — ``{target, text, filename}`` on success.

    * Unknown target → **400** with an error message.
    * ``slug`` not found → **404**.
    * ``slug`` resolves a corrupt file → **422**.
    * No ``slug`` or ``model`` in body → **400**.

    CSRF-guarded by ``CSRFMiddleware`` (header ``X-FS-Session`` required).
    """
    # Validate target first — fail fast before touching the body or store.
    if target not in TARGETS:
        return JSONResponse(
            {
                "error": (
                    f"Unknown export target {target!r}. "
                    f"Must be one of: {', '.join(sorted(TARGETS))}"
                )
            },
            status_code=400,
        )

    # Parse the request body.
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Request body must be valid JSON"}, status_code=400
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "Request body must be a JSON object"}, status_code=400
        )

    # Resolve the model — either from {slug} or from {model}.
    if "slug" in body:
        wf_slug = str(body["slug"])
        try:
            model = load_workflow(wf_slug)
        except WorkflowCorrupt as exc:
            logger.warning("Workflow %r is corrupt (export): %s", wf_slug, exc)
            return JSONResponse({"error": str(exc)}, status_code=422)
        except WorkflowNotFound:
            return JSONResponse(
                {"error": f"Workflow not found: {wf_slug!r}"}, status_code=404
            )
        except ValueError:
            # Bad slug format — can't exist.
            return JSONResponse(
                {"error": f"Workflow not found: {wf_slug!r}"}, status_code=404
            )
        # M2-1: revalidate the loaded (normalized) model so a hand-edited or
        # legacy saved workflow with bad field values is rejected here.
        errs = _override_validation_errors(model)
        if errs:
            return JSONResponse(
                {"error": "; ".join(errs), "errors": errs}, status_code=400
            )
    elif "model" in body:
        raw_model = body["model"]
        if not isinstance(raw_model, dict):
            return JSONResponse(
                {"error": "model must be a JSON object"}, status_code=400
            )
        # Check RAW submission for period/range ambiguities before normalization
        # hides them.  period=="custom" is the legacy SP0 sentinel — exempted.
        raw_errs = _raw_submission_errors(raw_model)
        if raw_errs:
            return JSONResponse(
                {"error": "; ".join(raw_errs), "errors": raw_errs}, status_code=400
            )
        # Normalize + validate the inline model exactly like save does, so a
        # draft can't export with author-time violations and a normalize error
        # (e.g. a non-numeric schema_version) returns 400 — never a 500.
        try:
            model = _normalize_model(raw_model)
            _validate_for_save(model)
        except (WorkflowValidationError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        # Validate the NORMALIZED model for field values (bad ISO dates, bad scan
        # enum, etc.) — consistent with the slug branch.
        errs = _override_validation_errors(model)
        if errs:
            return JSONResponse(
                {"error": "; ".join(errs), "errors": errs}, status_code=400
            )
    else:
        return JSONResponse(
            {"error": "Request body must contain 'slug' or 'model'"}, status_code=400
        )

    # Dispatch to the serializer.
    try:
        text, filename = dispatch(model, target)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    return JSONResponse({"target": target, "text": text, "filename": filename})


# ---------------------------------------------------------------------------
# POST /api/workflows/run
# ---------------------------------------------------------------------------


@router.post("/api/workflows/run")
async def run_workflow(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Run a workflow in place (spec §6.1).

    **Request body** — either:
    - ``{slug: "<slug>"}`` to load a saved workflow from the store, or
    - ``{model: {<workflow model>}}`` to run an inline (unsaved) draft.

    Resolves + normalizes the workflow, runs the **authoritative server-side
    preflight** (spec §10) over each runnable step's EFFECTIVE config, then
    registers a monitor-compatible run in the ``_runs`` registry and kicks off
    ``_execute_workflow`` in a background thread (same pattern as ``start_run``).

    * No ``slug`` / ``model`` → **400**.
    * ``slug`` not found → **404**; corrupt → **422**.
    * No runnable (recipe) step → **400**.
    * Any runnable step's effective scope/requirement unmet → **400** naming
      the offending step.
    * On pass → **200** ``{run_id}``.

    CSRF-guarded by ``CSRFMiddleware`` (header ``X-FS-Session`` required).
    """
    # Imported here (not at module level) so the CRUD/export tests that import
    # this router don't pull the run machinery, and to keep the run-router as
    # the single owner of the workflow executor.
    from fs_report.web.routers.run import (
        RunEventHub,
        WorkflowPreflightError,
        _execute_workflow,
        _register_workflow_run,
        _workflow_scope,
        workflow_preflight,
    )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Request body must be valid JSON"}, status_code=400
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "Request body must be a JSON object"}, status_code=400
        )

    # #11 (B5): optional run-time global scope override, read once for every
    # body shape (slug / model / replay).  Validated up front so a malformed
    # override 400s before any model resolution.
    try:
        scope_override = _parse_scope_override(body.get("scope_override"))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    # Resolve the model — either from {slug} or from {model}.
    replay: dict[str, Any]
    if "slug" in body:
        wf_slug = str(body["slug"])
        try:
            model = load_workflow(wf_slug)
        except WorkflowCorrupt as exc:
            logger.warning("Workflow %r is corrupt (run): %s", wf_slug, exc)
            return JSONResponse({"error": str(exc)}, status_code=422)
        except WorkflowNotFound:
            return JSONResponse(
                {"error": f"Workflow not found: {wf_slug!r}"}, status_code=404
            )
        except ValueError:
            return JSONResponse(
                {"error": f"Workflow not found: {wf_slug!r}"}, status_code=404
            )
        # Revalidate the loaded (normalized) model so a hand-edited or legacy
        # saved workflow with bad field values is rejected before running.
        errs = _override_validation_errors(model)
        if errs:
            return JSONResponse(
                {"error": "; ".join(errs), "errors": errs}, status_code=400
            )
        # Pass 4: a saved-workflow replay re-POSTs /api/workflows/run with the
        # slug (spec §8).
        replay = {
            "endpoint": "/api/workflows/run",
            "encoding": "json",
            "body": {"slug": wf_slug},
        }
    elif "model" in body:
        raw_model = body["model"]
        if not isinstance(raw_model, dict):
            return JSONResponse(
                {"error": "model must be a JSON object"}, status_code=400
            )
        # Check RAW submission for period/range ambiguities before normalization
        # hides them.  period=="custom" is the legacy SP0 sentinel — exempted.
        raw_errs = _raw_submission_errors(raw_model)
        if raw_errs:
            return JSONResponse(
                {"error": "; ".join(raw_errs), "errors": raw_errs}, status_code=400
            )
        # Normalize + validate the inline draft exactly like save does, so a
        # draft can't run with author-time violations and a normalize error
        # (e.g. a non-numeric schema_version) returns 400 — never a 500.
        try:
            model = _normalize_model(raw_model)
            _validate_for_save(model)
        except (WorkflowValidationError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        # Validate the NORMALIZED model for field values (bad ISO dates, bad scan
        # enum, etc.) — consistent with the slug branch.
        errs = _override_validation_errors(model)
        if errs:
            return JSONResponse(
                {"error": "; ".join(errs), "errors": errs}, status_code=400
            )
        # Pass 4: an inline-draft replay re-POSTs /api/workflows/run with the
        # NORMALIZED model — re-running re-normalizes idempotently (spec §8).
        replay = {
            "endpoint": "/api/workflows/run",
            "encoding": "json",
            "body": {"model": model},
        }
    else:
        return JSONResponse(
            {"error": "Request body must contain 'slug' or 'model'"}, status_code=400
        )

    # #11 (B5): apply the run-time scope override as an overlay on the in-memory
    # model (never persisted to the store) BEFORE preflight + run, and thread it
    # into the replay body so a replay re-targets identically.  Uniform for both
    # the {slug} and {model} shapes — one application point, one read path.
    if scope_override is not None:
        _apply_scope_override(model, scope_override)
        replay["body"]["scope_override"] = scope_override

    # At least one runnable (recipe) step is required to run locally.
    runnable = [
        s
        for s in model.get("steps", [])
        if s.get("kind") == "recipe" and s.get("runnable_locally")
    ]
    if not runnable:
        return JSONResponse(
            {
                "error": (
                    "Workflow has no runnable recipe step "
                    "(MCP-tool steps run via the Forge agent — export to run)."
                )
            },
            status_code=400,
        )

    # Authoritative server-side preflight (spec §10).  ``state`` supplies
    # domain/token so the preflight can resolve/validate a targeted folder
    # (Finding 4) — best-effort, skipped if creds are absent.
    try:
        workflow_preflight(model, state)
    except WorkflowPreflightError as exc:
        return JSONResponse(
            {"error": str(exc), "step_id": exc.step_id, "step_index": exc.step_index},
            status_code=400,
        )

    # SP3: run-start re-check that uploaded scoring/context files (global or any
    # step) still exist + parse — parity with start_run, so a workflow with a
    # deleted/corrupted upload fails fast with a 400 instead of mid-step.
    from fs_report.web.routers.run import (
        should_validate_context_file,
        stale_upload_path_errors,
    )

    _wf_global = model.get("global", {}) or {}
    # report-config-card-gating: only re-validate context_file when some runnable
    # step recipe actually consumes the deployment context (parity with
    # start_run) — else a stale/deleted hidden value can't 400 a workflow whose
    # recipes all ignore it. scoring_file is validated unchanged.
    _wf_refs = [str(s.get("ref", "")) for s in runnable if s.get("ref")]
    _wf_check_ctx = should_validate_context_file(_wf_refs)
    _blocks = [_wf_global] + [
        s.get("overrides", {}) or {} for s in model.get("steps", []) or []
    ]
    _wf_stale: list[str] = []
    for _blk in _blocks:
        _eff = {
            "scoring_file": _blk.get("scoring_file") or _wf_global.get("scoring_file"),
            "context_file": (
                (_blk.get("context_file") or _wf_global.get("context_file"))
                if _wf_check_ctx
                else None
            ),
        }
        _wf_stale.extend(stale_upload_path_errors(_eff))
    if _wf_stale:
        _uniq: list[str] = []
        for _e in _wf_stale:  # de-dup, preserve order
            if _e not in _uniq:
                _uniq.append(_e)
        return JSONResponse(
            {"error": "; ".join(_uniq), "errors": _uniq}, status_code=400
        )

    run_id = uuid.uuid4().hex[:8]
    queue = RunEventHub()  # multi-subscriber fan-out (#12)
    loop = asyncio.get_event_loop()
    cancel_event = threading.Event()

    state_data = state.to_dict()
    # C2: precompute the monitor scope label OFF the event loop. _workflow_scope →
    # _run_scope_label → _project_folder_parts does a blocking httpx GET (the
    # folder breadcrumb). run_workflow is an async handler, so resolving it inline
    # (as _register_workflow_run does by default) would stall the loop up to the
    # GET's 10s timeout. Resolve it in a worker thread and pass it in.
    scope = await asyncio.to_thread(_workflow_scope, model, state_data)
    _register_workflow_run(
        run_id, model, state_data, queue, cancel_event, replay, scope=scope
    )

    thread = threading.Thread(
        target=_execute_workflow,
        args=(run_id, model, state_data, queue, loop, cancel_event),
        daemon=True,
    )
    thread.start()

    return JSONResponse({"run_id": run_id})
