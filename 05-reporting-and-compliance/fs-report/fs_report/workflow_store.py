"""File-backed workflow store for the Workflow Builder (Pass 3).

Each workflow is persisted as ``~/.fs-report/workflows/<slug>.yaml``.
The on-disk schema is defined in the design spec §4.1.

Public API
----------
list_workflows() -> list[dict]
    Resilient summary list; malformed files are skipped + logged.

load_workflow(slug) -> dict
    Parse + normalize to the canonical model. Raises ``WorkflowNotFound``
    or ``WorkflowCorrupt``.

save_workflow(model) -> str
    Validate/normalize then write <slug>.yaml; returns the slug.

delete_workflow(slug) -> bool
    Unlink the file; returns True on success.

Exception classes
-----------------
WorkflowNotFound   — file absent for the given slug.
WorkflowCorrupt    — file present but unparseable / schema-invalid.
WorkflowValidationError — author-time validation failure (raised on save).
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from fs_report.paths import get_workflows_dir
from fs_report.slug import slug as make_slug
from fs_report.web.workflow_meta import (
    fill_mcp_defaults,
    get_mcp_tool,
    validate_mcp_params,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared truthy-coercion
# ---------------------------------------------------------------------------


def coerce_bool(value: Any) -> bool:
    """Coerce *value* to a real bool using the run path's truthy semantics.

    A value is True only if it is already ``True`` (a real bool) or its string
    form (stripped, lowercased) is one of ``"true"`` / ``"on"`` / ``"1"`` /
    ``"yes"``.  Everything else — including the strings ``"false"`` / ``"0"`` /
    ``"no"`` — is False (never the truthy ``bool("false")``).

    This single shared helper is the home for the coercion the run path
    (``run._coerce_touched_flag``), the export path
    (``workflow_export._coerce_bool``), and the ``target_agnostic`` strip
    (here + in those modules) all use, so a hand-edited / inline YAML string
    boolean such as ``"false"`` is read consistently everywhere.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "on", "1", "yes")


# ---------------------------------------------------------------------------
# Slug / path safety
# ---------------------------------------------------------------------------

_SLUG_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def _validate_slug(s: str) -> None:
    """Raise ``ValueError`` if *s* is not a safe workflow slug.

    Guards against path traversal (``..``, separators, absolute paths) and
    invalid characters before any filesystem operation is attempted.
    """
    if not s or not _SLUG_RE.match(s):
        raise ValueError(
            f"Invalid workflow slug {s!r}: must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
        )
    # Extra paranoia: no path separators, no absolute component.
    if "/" in s or "\\" in s or Path(s).is_absolute():
        raise ValueError(
            f"Invalid workflow slug {s!r}: must not contain path separators"
        )


def _slug_path(s: str) -> Path:
    """Return the absolute path for slug *s*, asserting containment.

    Raises ``ValueError`` when the resolved path is not inside the workflows
    directory (guards against ``..`` traversal even after the regex check).
    """
    _validate_slug(s)
    wf_dir = get_workflows_dir()
    candidate = (wf_dir / f"{s}.yaml").resolve()
    # Assert containment — resolved path must be inside wf_dir.
    try:
        candidate.relative_to(wf_dir.resolve())
    except ValueError as exc:
        raise ValueError(
            f"Resolved path for slug {s!r} escapes the workflows directory"
        ) from exc
    return candidate


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class WorkflowNotFound(KeyError):
    """No workflow file exists for the requested slug."""


class WorkflowCorrupt(ValueError):
    """Workflow file exists but could not be parsed or normalized."""


class WorkflowValidationError(ValueError):
    """Author-time validation failure; raised on ``save_workflow``."""


# ---------------------------------------------------------------------------
# Canonical model constants
# ---------------------------------------------------------------------------

_VALID_AI_DEPTHS = frozenset({"summary", "full"})
_VALID_ERROR_POLICIES = frozenset({"halt", "continue"})
# Reserved Run-canvas node ids (the source + the compound/aggregate deliverable).
# A workflow step id MUST NOT collide with one of these — see _validate_for_save.
_RESERVED_CANVAS_IDS = frozenset({"source", "deliverable"})

# NOTE: _VALID_PERIODS has been removed as of SP1 — period values are now
# freeform strings validated at request-time by PeriodParser in the router
# (Task 5b).  The "custom" sentinel has been eliminated; use top-level
# start/end keys instead.

_GLOBAL_DEFAULTS: dict[str, Any] = {
    "project_filter": None,
    # Folder targeting (design §6): a workflow GLOBAL folder scope (the folder
    # ID).  Must be in _GLOBAL_DEFAULTS so _normalize_global preserves it (else
    # it's dropped on save/normalize and never reaches per-step effective
    # config).  Server-side precedence (project wins, _build_engine_config)
    # drops it at run/export time when a project is also set.
    "folder_filter": None,
    "version_filter": None,
    # NOTE: period and start/end are intentionally NOT in _GLOBAL_DEFAULTS.
    # They are mutually exclusive (range wins when both present) and the
    # default ("30d") is applied in _normalize_global only when neither is set.
    # Keeping them out of defaults prevents naive dict-merge from clobbering
    # an explicit range with a default period value.
    #
    # C1: Global-Properties date-mode "touched" intent flags. These are plain
    # persisted bools (NOT special-cased like period/start/end), so listing them
    # in _GLOBAL_DEFAULTS makes _normalize_global preserve them and
    # _model_to_yaml_dict emit them verbatim. They record whether the USER
    # explicitly set the global period (period_touched) or a complete global
    # range (range_touched); when set, the global date mode OVERRIDES a step's
    # card period (the read-and-strip precedence applied in _effective_step_config
    # / workflow_export._effective_config / builder-page.effectiveConfig). They
    # are deliberately NOT engine keys — they must never reach the engine config,
    # only steer precedence — so they are NOT in _WORKFLOW_GLOBAL_ENGINE_KEYS.
    "period_touched": False,
    "range_touched": False,
    # C2: target-bound vs general workflow. A "general" (portfolio/target-
    # agnostic) workflow carries NO baked target — the project/folder/version is
    # chosen at run time (Global-Properties selection → scope_override) rather
    # than persisted into the doc. Default False (target-bound) so a LEGACY doc
    # with no flag keeps seeding its saved scope. When True, save_workflow /
    # _model_to_yaml_dict STRIP the *_filter keys (so the persisted + exported
    # doc has no baked target), and the export path omits the baked target across
    # all serializers. It is a plain persisted bool, NOT an engine key — listing
    # it in _GLOBAL_DEFAULTS makes _normalize_global preserve it and
    # _model_to_yaml_dict emit it; it is NOT in _WORKFLOW_GLOBAL_ENGINE_KEYS.
    "target_agnostic": False,
    "ai": False,
    "ai_depth": "summary",
    "cache_ttl": "4h",
    # SP3: a workflow GLOBAL uploaded scoring/context path — must be in
    # _GLOBAL_DEFAULTS so _normalize_global preserves it (else it's dropped on
    # save/normalize and never reaches per-step effective config).
    "scoring_file": None,
    "context_file": None,
}

# Engine override keys that are valid in a recipe step's ``overrides`` dict.
# Mirrors _RUN_STR_KEYS / _RUN_BOOL_KEYS in web/routers/run.py plus the
# workflow-special ``error_policy``. ``folder_filter`` is a per-step override
# (design §6 — folder targeting): a step can re-target a different folder than
# the global; server-side precedence (project wins, _build_engine_config + the
# Builder step-override merge) drops it when that step's effective project is
# set. Deliberately EXCLUDED (not per-step overrides): ``output_dir`` (run-only;
# per-step output roots are assigned by the executor), ``baseline_version`` /
# ``current_version`` (comparison-only keys), and ``ai_analysis`` (dead config —
# the engine derives a recipe's ai_analysis from ``ai_depth == "full"`` and
# never reads ``config.ai_analysis``; the Settings page dropped its toggle for
# the same reason).
_VALID_OVERRIDE_STR_KEYS = frozenset(
    {
        "period",
        "start",
        "end",
        "cache_ttl",
        "project_filter",
        "folder_filter",
        "version_filter",
        "finding_types",
        "cve_filter",
        "component_filter",
        "ai_depth",
        "product_type",
        "network_exposure",
        "regulatory",
        "deployment_notes",
        "scoring_file",  # SP3: uploaded scoring-file path (per-step override)
        "context_file",  # SP3: uploaded context-file path (per-step override)
        "tp_gate",
        "component_match",
        "component_version",
        "license_filter",
        "threat_context",
        "baseline_date",
        "detected_after",
        "scan_types",
        "scan_statuses",
        "error_policy",  # workflow-special — NOT passed to the engine
        # B7 (#10B): FP-Analysis autotriage VEX-write status filter. Persistable
        # so a saved/exported FP workflow can carry the opt-in; semantically
        # gated FP-step-only by validate_destructive_overrides (a non-FP or
        # global autotriage 400s on save/run).
        "autotriage_status",
    }
)
_VALID_OVERRIDE_BOOL_KEYS = frozenset(
    {
        "ai",
        "ai_prompts",
        "overwrite",
        "current_version_only",
        "open_only",
        "detailed",
        "standalone",
        "vex_override",
        # B7 (#10B): the FP-Analysis autotriage opt-in. Persistable per-step so a
        # saved/exported FP workflow carries the deliberate opt-in; gated
        # FP-step-only by validate_destructive_overrides + default-off (a step
        # that doesn't set it never writes VEX).
        "autotriage",
    }
)
_VALID_OVERRIDE_INT_KEYS = frozenset({"top", "triage"})
_VALID_OVERRIDE_KEYS = (
    _VALID_OVERRIDE_STR_KEYS | _VALID_OVERRIDE_BOOL_KEYS | _VALID_OVERRIDE_INT_KEYS
)

# ---------------------------------------------------------------------------
# Concurrency guard — single lock serialises concurrent writes to the same
# slug, preventing partial-write interleaving.
# ---------------------------------------------------------------------------

_SAVE_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Recipe resolution helper
# ---------------------------------------------------------------------------


def _resolve_recipe_ref(ref: str) -> str | None:
    """Return the canonical recipe name for *ref*, or ``None`` if unresolvable.

    Uses the same slug-based matching the run path uses:
    ``executive_summary`` / ``Executive Summary`` / ``executive-summary``
    all match the same recipe.

    Guarded: a RecipeLoader failure degrades to ``None`` (unresolvable)
    rather than raising, so a broken recipe corpus doesn't block loading
    a workflow.
    """
    from fs_report.recipe_loader import RecipeLoader

    try:
        recipes = RecipeLoader(use_bundled=True).load_recipes()
    except Exception:
        logger.debug("RecipeLoader failed during ref resolution", exc_info=True)
        return None
    target_slug = make_slug(ref)
    for r in recipes:
        if make_slug(r.name) == target_slug:
            return r.name
    return None


# ---------------------------------------------------------------------------
# Normalize / validate helpers
# ---------------------------------------------------------------------------


def _normalize_global(raw: Any) -> dict[str, Any]:
    """Normalize the ``global`` block, filling defaults for absent keys.

    SP1 date-mode contract
    ----------------------
    Period and date-range are *mutually exclusive* in the canonical model.
    This is required because ``create_config`` gives ``period`` PRECEDENCE over
    ``start``/``end`` — if both were present a custom range would be silently
    overridden by the named period.

    Resolution rules (applied in order):
    1. ``period`` is read first and the legacy ``"custom"`` sentinel noted.
    2. ``start`` / ``end`` are resolved — including legacy migration.  The SP0
       ``custom_range`` dict is lifted into top-level ``start``/``end`` ONLY when
       the range was the *active* SP0 mode — i.e. ``period`` was the ``"custom"``
       sentinel (or unset).  When SP0 stored a NAMED period (e.g. ``"7d"``) the
       ``custom_range`` was dormant/stale and is IGNORED (the user's named period
       is their real choice), so we do not resurrect those dates.
    3. The ``"custom"`` sentinel is dropped (period → None).
    4. Mutual-exclusion default:
       • Both ``start`` AND ``end`` set (non-empty) → keep start/end, omit period.
       • Only ``period`` set (non-empty, not "custom") → keep period, omit start/end.
       • Neither (incl. a partial range — only start OR only end) → default
         ``period = "30d"``.  (A partial range can only reach here via a
         hand-edited file; the request-time validator rejects it at the router.)
    5. The output global NEVER contains a ``custom_range`` key, NEVER has
       ``period == "custom"``, and NEVER carries both a period and start/end.

    Period values are no longer validated against an enum here.  Freeform
    period strings (``"Q1"``, ``"60d"``, …) are accepted at save-time and
    validated by PeriodParser at the router (Task 5b).
    """
    if not isinstance(raw, dict):
        raw = {}

    # --- Non-date defaults (project_filter, version_filter, ai, …) -----------
    g: dict[str, Any] = dict(_GLOBAL_DEFAULTS)
    for key in _GLOBAL_DEFAULTS:
        if key in raw and raw[key] is not None and raw[key] != "":
            g[key] = raw[key]

    # --- Date-mode resolution -------------------------------------------------
    # Step 1: read period + note the legacy "custom" sentinel.
    period: str | None = raw.get("period")
    period_is_custom = isinstance(period, str) and period.lower().strip() == "custom"

    # Step 2: resolve start/end, including SP0 custom_range migration.
    start = raw.get("start")
    end = raw.get("end")

    # Legacy migration: SP0 stored a custom range in ``custom_range`` and only
    # USED it when ``period == "custom"``.  Lift it ONLY in that case (or when no
    # period was set); a named SP0 period means custom_range was dormant/stale and
    # must NOT override the user's named choice.
    if (
        (not start or not end)
        and isinstance(raw.get("custom_range"), dict)
        and (period_is_custom or period is None or period == "")
    ):
        cr = raw["custom_range"]
        if not start:
            start = cr.get("start")
        if not end:
            end = cr.get("end")

    # Treat empty string / None as unset.
    start = start if (start is not None and start != "") else None
    end = end if (end is not None and end != "") else None

    # Step 3: drop the legacy "custom" sentinel.
    if period_is_custom:
        period = None
        if start is None or end is None:
            # SP0 "custom" with an incomplete range — log the discard for
            # visibility; falls through to the default period below.
            logger.debug(
                "Workflow global had period='custom' but an incomplete custom "
                "range; dropping the sentinel and defaulting the period."
            )

    # Step 4: mutual-exclusion + default.
    if start is not None and end is not None:
        # Range wins — period stays absent so create_config cannot shadow it.
        g["start"] = start
        g["end"] = end
    elif period is not None and period != "":
        # Named/freeform period wins.
        g["period"] = period
    else:
        # Neither — fall back to the default named period.
        g["period"] = "30d"

    # Guarantee: no custom_range key in the output model (SP0 artefact).
    g.pop("custom_range", None)

    return g


def _normalize_overrides(raw: Any) -> dict[str, Any]:
    """Return only recognised override keys from *raw*; drop unknown keys."""
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if k in _VALID_OVERRIDE_KEYS}


def _normalize_step(raw: Any, index: int) -> dict[str, Any]:
    """Normalize a single step dict.

    Fills required fields with safe defaults; derives ``runnable_locally``.
    Does NOT raise on an unresolvable ``ref`` — the step is flagged invalid
    but preserved so exports still carry it.
    """
    if not isinstance(raw, dict):
        raw = {}

    step_id = str(raw.get("id") or f"s{index + 1}")
    kind = str(raw.get("kind", "recipe"))
    if kind not in ("recipe", "mcp_tool"):
        kind = "recipe"
    ref = str(raw.get("ref", ""))

    overrides = _normalize_overrides(raw.get("overrides"))
    params: dict[str, Any] = {}
    if isinstance(raw.get("params"), dict):
        params = dict(raw["params"])

    # Resolve ref and derive runnable_locally.
    if kind == "recipe":
        canonical_ref = _resolve_recipe_ref(ref) if ref else None
        runnable_locally = canonical_ref is not None
        resolved_ref = canonical_ref if canonical_ref is not None else ref
    else:
        # mcp_tool — validate tool id + MATERIALIZE declared param defaults
        # (e.g. priority="P0", poll=True) so even an inline/hand-authored model
        # with params:{} carries the concrete defaults into save/run/export and
        # required-with-default params validate.  workflow_meta is the single
        # source of truth for those defaults.
        runnable_locally = False
        resolved_ref = ref
        params = fill_mcp_defaults(ref, params)

    return {
        "id": step_id,
        "kind": kind,
        "ref": resolved_ref,
        "overrides": overrides,
        "params": params,
        "runnable_locally": runnable_locally,
    }


def _normalize_model(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize and fill defaults for a raw workflow dict.

    Returns a canonical model dict.  Does NOT perform author-time validation
    (that runs only on save) so load is lenient — it flags issues but doesn't
    raise for load consumers.
    """
    name = str(raw.get("name", "")).strip()
    wf_slug = make_slug(name) if name else "workflow"
    schema_version = int(raw.get("schema_version", 1))
    global_block = _normalize_global(raw.get("global") or raw.get("global_", {}))
    raw_steps = raw.get("steps") or []
    if not isinstance(raw_steps, list):
        raw_steps = []
    steps = [_normalize_step(s, i) for i, s in enumerate(raw_steps)]

    return {
        "schema_version": schema_version,
        "name": name,
        "slug": wf_slug,
        "global": global_block,
        "steps": steps,
    }


def _validate_for_save(model: dict[str, Any]) -> None:
    """Run author-time validation on a normalized model.

    Raises ``WorkflowValidationError`` with a descriptive message on the
    first problem found.  Checks both the global block and every step.
    """
    name = model.get("name", "").strip()
    if not name:
        raise WorkflowValidationError("Workflow name must not be empty")

    g = model.get("global", {})

    # version_filter without project_filter → reject.
    if g.get("version_filter") and not g.get("project_filter"):
        raise WorkflowValidationError(
            "version_filter requires project_filter to be set"
        )

    # ai_depth validation.
    ai_depth = g.get("ai_depth", "summary")
    if ai_depth not in _VALID_AI_DEPTHS:
        raise WorkflowValidationError(
            f"ai_depth {ai_depth!r} must be one of {sorted(_VALID_AI_DEPTHS)!r}"
        )

    # NOTE: period/start/end are NOT validated here.  This validator is
    # structural-only; period/date-range values are validated at request-time
    # by PeriodParser in the router (Task 5b).

    # Per-step validation.
    for i, step in enumerate(model.get("steps", [])):
        kind = step.get("kind", "recipe")
        step_id = step.get("id", f"step {i}")

        # Per-step overrides — validate error_policy if present.
        overrides = step.get("overrides") or {}
        error_policy = overrides.get("error_policy")
        if error_policy is not None and error_policy not in _VALID_ERROR_POLICIES:
            raise WorkflowValidationError(
                f"Step {step_id!r}: error_policy {error_policy!r} must be one of"
                f" {sorted(_VALID_ERROR_POLICIES)!r}"
            )

        # Per-step override: version_filter without project_filter
        step_version_filter = overrides.get("version_filter")
        step_project_filter = overrides.get("project_filter") or g.get("project_filter")
        if step_version_filter and not step_project_filter:
            raise WorkflowValidationError(
                f"Step {step_id!r}: version_filter requires project_filter to be set"
                " (in overrides or global)"
            )

        # Per-step override: ai_depth validation.
        step_ai_depth = overrides.get("ai_depth")
        if step_ai_depth is not None and step_ai_depth not in _VALID_AI_DEPTHS:
            raise WorkflowValidationError(
                f"Step {step_id!r}: ai_depth {step_ai_depth!r} must be one of"
                f" {sorted(_VALID_AI_DEPTHS)!r}"
            )

        # MCP-tool param validation.
        if kind == "mcp_tool":
            tool_id = step.get("ref", "")
            if get_mcp_tool(tool_id) is None:
                raise WorkflowValidationError(
                    f"Step {step_id!r}: unknown MCP tool id {tool_id!r}"
                )
            params = step.get("params") or {}
            errs = validate_mcp_params(tool_id, params)
            if errs:
                raise WorkflowValidationError(
                    f"Step {step_id!r}: invalid params — {'; '.join(errs)}"
                )

    # Step ids key the Run-canvas node, the SSE ``step_id``, AND the Builder's
    # in-place run node (raw ``step.id``).  A duplicate id, or an id that
    # collides with a RESERVED canvas id (``source`` / ``deliverable``), would
    # break node lighting in BOTH the canvas and the Builder.  Reject the model
    # here (validation-only) rather than sanitizing the executor — sanitizing
    # would desync the Builder, which uses the raw ``step.id`` (fix ⑥).
    seen_ids: set[str] = set()
    for step in model.get("steps", []):
        sid = step.get("id")
        if sid in _RESERVED_CANVAS_IDS:
            raise WorkflowValidationError(f"Step id {sid!r} is reserved")
        if sid in seen_ids:
            raise WorkflowValidationError(f"Duplicate step id {sid!r}")
        seen_ids.add(sid)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _model_to_yaml_dict(model: dict[str, Any]) -> dict[str, Any]:
    """Convert a normalized model to a plain dict suitable for YAML serialization.

    Strips the derived ``runnable_locally`` and ``slug`` fields (not persisted).

    C2 — target-agnostic strip: when the global block is flagged
    ``target_agnostic`` (a "general"/portfolio workflow), the baked scope
    (``project_filter`` / ``folder_filter`` / ``version_filter``) is stripped
    from the PERSISTED doc — a general workflow carries no saved target; the
    target is chosen at run time (Global-Properties → ``scope_override``). The
    strip is done here (the single save serialization point, also the source
    fed to ``save_workflow``) so a saved general workflow's YAML has no baked
    target. The in-memory run/normalize model is NOT mutated by this — only the
    on-disk shape — so a RUN still honors the user's current target.
    """
    steps_out = []
    for step in model.get("steps", []):
        s: dict[str, Any] = {
            "id": step["id"],
            "kind": step["kind"],
            "ref": step["ref"],
        }
        if step.get("overrides"):
            s["overrides"] = step["overrides"]
        if step.get("params"):
            s["params"] = step["params"]
        steps_out.append(s)

    global_block = model["global"]
    if isinstance(global_block, dict) and coerce_bool(
        global_block.get("target_agnostic")
    ):
        # Shallow copy so we never mutate the caller's normalized model.
        global_block = dict(global_block)
        # POP the baked scope keys (key-absent), not set-to-None: a saved general
        # workflow's YAML carries no ``*_filter: null`` noise — matching the
        # key-absent shape of _strip_target_agnostic_scope in workflow_export.
        for _scope_key in ("project_filter", "folder_filter", "version_filter"):
            global_block.pop(_scope_key, None)

    return {
        "schema_version": model.get("schema_version", 1),
        "name": model["name"],
        "global": global_block,
        "steps": steps_out,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_workflows() -> list[dict[str, Any]]:
    """Return a summary list of all saved workflows.

    Each entry is ``{name, slug, step_count, updated}``.  A malformed file is
    skipped with a WARNING log (mirrors the ``_enrich_history`` resilience
    pattern in ``reports.py``) so one bad file can't blank the whole list.
    """
    wf_dir = get_workflows_dir()
    summaries: list[dict[str, Any]] = []
    for path in sorted(wf_dir.glob("*.yaml")):
        # Skip files whose stem is not an addressable slug — GET/DELETE on such a
        # slug would 404 (they go through _validate_slug), so advertising them in
        # the dropdown would only surface dead entries.
        try:
            _validate_slug(path.stem)
        except ValueError:
            logger.debug(
                "Skipping workflow file with unaddressable slug: %s", path.name
            )
            continue
        try:
            with path.open(encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict):
                raise ValueError("top-level YAML document is not a dict")
            name = str(raw.get("name", "")).strip() or path.stem
            steps = raw.get("steps") or []
            step_count = len(steps) if isinstance(steps, list) else 0
            mtime = path.stat().st_mtime
            updated = datetime.fromtimestamp(mtime, tz=UTC).isoformat()
            summaries.append(
                {
                    "name": name,
                    "slug": path.stem,
                    "step_count": step_count,
                    "updated": updated,
                }
            )
        except Exception:
            logger.warning(
                "Skipping malformed workflow file %s", path.name, exc_info=True
            )
    return summaries


def load_workflow(wf_slug: str) -> dict[str, Any]:
    """Load and normalize the workflow for *wf_slug*.

    Returns the canonical model dict with ``runnable_locally`` derived on
    each step.

    Raises
    ------
    WorkflowNotFound
        When no file exists for *wf_slug*.
    WorkflowCorrupt
        When the file exists but cannot be parsed or normalized.
    ValueError
        When *wf_slug* fails slug/path-safety validation.
    """
    path = _slug_path(wf_slug)
    try:
        with path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict):
            raise ValueError("top-level YAML document is not a dict")
        return _normalize_model(raw)
    except FileNotFoundError:
        raise WorkflowNotFound(wf_slug)
    except Exception as exc:
        raise WorkflowCorrupt(f"Could not load workflow {wf_slug!r}: {exc}") from exc


def save_workflow(model: dict[str, Any]) -> str:
    """Validate, normalize, and persist *model*.

    A module-level lock serialises concurrent writes to the *same* slug,
    preventing partial-write interleaving / last-write-wins corruption.
    Each workflow lives in its own file (``<slug>.yaml``), so no
    cross-slug coordination or merge is required.

    Returns the slug.

    Raises
    ------
    WorkflowValidationError
        When author-time validation fails.
    ValueError
        When the derived slug is unsafe.
    """
    # Normalize first (fills defaults, resolves refs, derives slug).
    normalized = _normalize_model(model)
    # Author-time validation (raises WorkflowValidationError on failure).
    _validate_for_save(normalized)

    wf_slug = str(normalized["slug"])
    path = _slug_path(wf_slug)

    with _SAVE_LOCK:
        yaml_dict = _model_to_yaml_dict(normalized)
        with path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(
                yaml_dict,
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

    return wf_slug


def delete_workflow(wf_slug: str) -> bool:
    """Delete the workflow file for *wf_slug*.

    Returns ``True`` when the file was deleted, ``False`` when it did not
    exist.

    Raises ``ValueError`` when *wf_slug* fails slug/path-safety validation.
    """
    path = _slug_path(wf_slug)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
