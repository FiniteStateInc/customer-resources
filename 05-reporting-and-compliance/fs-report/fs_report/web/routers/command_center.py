"""Command Center aggregation endpoints (spec §8.2–§8.6)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from fs_report.scope_ref import ScopeRefError
from fs_report.scope_ref import parse as parse_scope_ref
from fs_report.slug import slug
from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.routers._scans_client import ScanFetchResult, _parse_iso, fetch_scans
from fs_report.web.state import (
    DEFAULTS,
    WebAppState,
    missing_card_inputs,
    needs_setup,
    recipe_override,
)

router = APIRouter(prefix="/api/cc", tags=["command-center"])

# Serialise the card-config fresh-read-merge-save so a save of recipe A can
# never clobber a concurrent save of a *different* recipe B (spec §6).  A
# module-level Lock (not per-request) because it guards the on-disk file, which
# is shared across all requests.  Single-user local serve makes true concurrency
# rare, but the lock + fresh read make the merge correct regardless.
_SAVE_LOCK = threading.Lock()

# Fixed typed allowlist for POST /api/cc/card-config (spec §6).  Mirrors
# start_run's coercion so a stored value can never bypass /api/run's own
# coercion and crash a run.  Unknown keys are dropped.
#
# WHEN ADDING A KEY: it must also be CLASSIFIED for `_build_override` — either
# give it a `DEFAULTS` entry (state.py) so it stores only when it differs from
# that default, OR add it to `_NO_GLOBAL_KEYS` below (no default; stores when
# non-empty).  A key in neither set is silently skipped by `_build_override`.
_STR_KEYS: tuple[str, ...] = (
    "finding_types",
    "period",
    "cve_filter",
    "component_filter",
    "baseline_version",
    "current_version",
    "ai_depth",
    "cache_ttl",
    "product_type",
    "network_exposure",
    "regulatory",
    "deployment_notes",
    "scoring_file",
    "context_file",
    "start",
    "end",
    "tp_gate",
    "component_match",
    "component_version",
    "license_filter",
    "threat_context",
    "baseline_date",
    "detected_after",
    "scan_types",
    "scan_statuses",
    # SP2: VEX-write status filter (comma-joined multi-select, no DEFAULTS entry
    # -> also listed in _NO_GLOBAL_KEYS below, like scan_types/scan_statuses).
    "autotriage_status",
)
_INT_KEYS: tuple[str, ...] = ("top", "triage")
_BOOL_KEYS: tuple[str, ...] = (
    "ai",
    "ai_prompts",
    "overwrite",
    "current_version_only",
    "open_only",
    "detailed",
    "standalone",
    "vex_override",
    # SP2: auto-apply VEX toggle (has a DEFAULTS entry = False, so it routes
    # through the diff-vs-default branch like vex_override).
    "autotriage",
)
# Keys with NO DEFAULTS entry. They can still carry a live global set via
# config.yaml (they round-trip through ``state._data``), so they ARE diffed
# against ``state.get(key)`` and stored only when non-empty AND different — the
# rest (DEFAULTS-keyed fields) are likewise diffed against the live global.
#
# ``component_match`` is NOT listed here — it has a DEFAULTS entry ("contains"),
# so _build_override routes it through the DEFAULTS branch.  The 10 new STR keys
# below have no DEFAULTS entry, so they live here.
_NO_GLOBAL_KEYS: frozenset[str] = frozenset(
    {
        "cve_filter",
        "component_filter",
        "baseline_version",
        "current_version",
        "top",
        "triage",
        "start",
        "end",
        "tp_gate",
        "license_filter",
        "component_version",
        "threat_context",
        "baseline_date",
        "detected_after",
        "scan_types",
        "scan_statuses",
        "autotriage_status",  # SP2: comma-joined status filter, no DEFAULTS entry
    }
)

_TRUTHY = {"true", "on", "1", "yes"}


def _load_recipe(name: str) -> Any | None:
    """Return the bundled recipe whose lowercase name matches ``name``, or None.

    Guarded: a recipe-load failure degrades to ``None`` (the caller returns a
    404) rather than raising.
    """
    from fs_report.recipe_loader import RecipeLoader

    try:
        recipes = RecipeLoader(use_bundled=True, scan_user_recipes=True).load_recipes()
    except Exception:
        return None
    key = name.strip().lower()
    for r in recipes:
        if r.name.lower() == key:
            return r
    return None


class CardConfigCoercionError(ValueError):
    """A card-config form field failed coercion (e.g. non-numeric ``top``).

    Carries the offending field name so the save handler can surface a 400
    that names it, matching the endpoint's existing validation-error shape.
    """

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"Invalid value for {field}")


def _coerce_card_config(form: Any) -> dict[str, Any]:
    """Apply the fixed typed allowlist + coercion to a card-config form.

    Strings stay strings; ``top``/``triage`` → int; bools parsed from truthy
    tokens.  Unknown keys never enter the result.  ``finding_types`` is taken
    verbatim from the hidden field (the JS rebuilds it from the ``ft_cb``
    checkbox group, mirroring the modal).

    An EMPTY/blank ``top``/``triage`` is valid (means "unset" → dropped). A
    *present, non-empty* int field that fails int parsing raises
    ``CardConfigCoercionError`` so the save can reject with a 400 and persist
    NOTHING, instead of silently dropping it and saving the rest (PR #117
    review Fix 2 / spec §6).
    """
    coerced: dict[str, Any] = {}
    for key in _STR_KEYS:
        val = form.get(key)
        if val is not None:
            coerced[key] = str(val)
    for key in _INT_KEYS:
        val = form.get(key)
        if val is not None and str(val).strip():
            try:
                coerced[key] = int(str(val).strip())
            except (ValueError, TypeError) as exc:
                # Present non-empty but non-numeric → reject (don't drop +
                # partially persist a value /api/run can't coerce).
                raise CardConfigCoercionError(key) from exc
    for key in _BOOL_KEYS:
        val = form.get(key)
        # Only coerce a bool that is actually present in the form.  The card-back
        # JS (mirroring the modal's _wireCfgSubmit) submits every *rendered*
        # checkbox explicitly as 'true'/'false', so a present value with no
        # truthy token is a deliberate "unchecked" → False that the diff rule can
        # weigh against the global.  A key absent from the form means the field
        # was NOT rendered for this recipe (e.g. ``ai`` on a non-``show_ai``
        # recipe) — it must never silently become an override.
        if val is not None:
            coerced[key] = str(val).lower() in _TRUTHY
    return coerced


def _build_override(state: WebAppState, coerced: dict[str, Any]) -> dict[str, Any]:
    """Apply the diff-vs-global rule (spec §6) to produce the sparse override.

    Fields with a DEFAULTS counterpart are stored only when they DIFFER from the
    current global (``state.get(key)``) — equal values keep inheriting so later
    Settings changes still propagate.

    Fields in ``_NO_GLOBAL_KEYS`` (``cve_filter`` etc.) have no DEFAULTS entry,
    but they CAN still carry a live global: config.yaml may set them even though
    they aren't in DEFAULTS (they round-trip through ``state._data``). So they
    are diffed against the live global (``state.get(key)``) too — store only
    when non-empty AND different from the global. Storing a value that EQUALS
    the global would pin it into ``recipe_overrides`` and break the inherit
    model (``is_ov()`` would then mark an inherited value as an override, and a
    later Settings change to that field would stop propagating). The empty-as-
    inherit behavior is preserved (an empty/whitespace string or empty/None
    non-string is never stored). (PR #117 review Fix 3.)
    """
    override: dict[str, Any] = {}
    for key, value in coerced.items():
        if key in _NO_GLOBAL_KEYS:
            # Has no DEFAULTS entry but may still have a live global from
            # config.yaml — store when non-empty AND different from the global.
            if isinstance(value, str):
                if value.strip() and value != state.get(key):
                    override[key] = value
            elif value not in ("", None) and value != state.get(key):
                override[key] = value
        elif key in DEFAULTS:
            # Diff against the live global; store only when different.  An
            # empty/whitespace-only *string* counts as "inherit" and is NOT
            # stored, even though it differs from the global: storing "" would
            # shadow /api/run's ``effective.get(key, default)`` fallback (the
            # key would be present-but-empty, so the run-time default never
            # applies — e.g. unchecking all finding-type boxes submits
            # ``finding_types=""``, which must inherit ``"cve"`` rather than
            # flow an empty finding-types set into the report). Non-string
            # values (bools) keep the plain diff rule.
            if isinstance(value, str):
                if value.strip() and value != state.get(key):
                    override[key] = value
            elif value != state.get(key):
                override[key] = value
        # else: not a global-counterpart field and not in the no-global set —
        # nothing in the allowlist falls here, but be defensive and skip.
    return override


def _save_recipe_override(
    state: WebAppState, recipe_key: str, override: dict[str, Any] | None
) -> None:
    """Locked fresh-read-merge-save of a single recipe's override (spec §6).

    Under ``_SAVE_LOCK``: re-read the on-disk ``recipe_overrides`` fresh, set
    (or remove when ``override`` is None/empty) the single target recipe key,
    then assign the merged map onto ``state`` and persist.  Re-reading guarantees
    saving recipe A never loses a concurrently-saved recipe B, since
    ``WebAppState.save`` shallow-merges only top-level keys.
    """
    from fs_report.cli.common import load_config_file

    with _SAVE_LOCK:
        disk = load_config_file().get("recipe_overrides", {})
        if not isinstance(disk, dict):
            disk = {}
        merged: dict[str, Any] = {k: v for k, v in disk.items() if isinstance(k, str)}
        if override:
            merged[recipe_key] = override
        else:
            merged.pop(recipe_key, None)
        state["recipe_overrides"] = merged
        state.save()


# ── Scope-ref builder (reused by builder_recipes.py for comparison save) ─────


def _build_scope_ref(side: dict[str, Any]) -> tuple[str | None, str | None]:
    """Build a scope-ref string for one side from its components.

    Returns ``(ref, note)``.  Exactly one is non-None on a determinate side:
    a valid ref string (``note`` None), or ``None`` + a note describing why it
    couldn't be built (incomplete / unsupported name / un-parseable).

    Grammar (``fs_report/scope_ref.py``): ``project`` wins over ``folder``;
    ``@<version>`` is appended only for a project side with a version; a folder
    side NEVER carries a version.  A ``@`` in the project/folder NAME is rejected
    up front (``parse`` splits a ``project:`` ref on the FIRST ``@`` and would
    mis-split a name containing ``@``); the version may contain ``@``.  The
    built ref is then validated by round-tripping through ``parse``.
    """
    project = str(side.get("project", "") or "").strip()
    version = str(side.get("version", "") or "").strip()
    folder = str(side.get("folder", "") or "").strip()

    if project:
        if "@" in project:
            return None, "unsupported name: project names cannot contain '@'"
        ref = f"project:{project}@{version}" if version else f"project:{project}"
    elif folder:
        if "@" in folder:
            return None, "unsupported name: folder names cannot contain '@'"
        # Folders have no version concept — never append @version.
        ref = f"folder:{folder}"
    else:
        return None, None  # incomplete — no project, no folder

    # Validate by round-tripping through the canonical grammar.
    try:
        parse_scope_ref(ref)
    except ScopeRefError as exc:
        return None, f"invalid scope: {exc}"
    return ref, None


def _title_collides_with_bundled(title: str) -> str | None:
    """Return the BUNDLED recipe name whose slug equals ``title``'s slug, else None.

    Mirrors the execute-only ``compare`` path (``compare_cmd.py`` §3): a
    ``--title`` whose slug collides with a built-in/bundled recipe is rejected,
    but a collision with only a USER recipe is allowed.  So we scan bundled
    recipes only (``scan_user_recipes=False``).  Guarded: a loader failure
    degrades to "no collision" (``None``) rather than raising.  The returned
    recipe name lets the caller name the offender in the note — as actionable
    as the CLI's "collides with the built-in recipe '<name>'" error.
    """
    from fs_report.recipe_loader import RecipeLoader

    try:
        recipes = RecipeLoader(use_bundled=True, scan_user_recipes=False).load_recipes()
    except Exception:
        return None
    target = slug(title)
    for r in recipes:
        if slug(r.name) == target:
            return r.name
    return None


# Grade thresholds: (minimum_rate, label)
_GRADES: list[tuple[float, str]] = [
    (0.99, "A"),
    (0.97, "A−"),
    (0.95, "B+"),
    (0.90, "B"),
    (0.85, "C+"),
    (0.80, "C"),
]


def _state_configured(state: WebAppState) -> bool:
    """Return True when token and domain are both non-empty."""
    return bool(state.token and state.domain)


def _grade(rate: float) -> str:
    """Map a success rate in [0,1] to a letter grade."""
    for thresh, label in _GRADES:
        if rate >= thresh:
            return label
    return "D"


def _delta_pct(cur: int, prior: int) -> int | None:
    """Return percentage change from prior to cur, or None when prior is 0."""
    if prior > 0:
        return round((cur - prior) / prior * 100)
    return None


def _in_window(dt: datetime | None, start: datetime, end: datetime) -> bool:
    """Return True when dt falls within [start, end)."""
    return dt is not None and start <= dt < end


def _build_overview(
    scans: list[dict[str, Any]],
    reports_30d: int,
    reports_prior: int,
    now: datetime,
) -> dict[str, Any]:
    """Build the overview response body from raw scans and report counts."""
    w30 = now - timedelta(days=30)
    w60 = now - timedelta(days=60)

    cur = [s for s in scans if _in_window(_parse_iso(s.get("created")), w30, now)]
    prior = [s for s in scans if _in_window(_parse_iso(s.get("created")), w60, w30)]

    completed = sum(1 for s in cur if s.get("status") == "COMPLETED")
    errored = sum(1 for s in cur if s.get("status") == "ERROR")
    denom = completed + errored
    rate: float | None = (completed / denom) if denom else None

    # Determine scan type tags from the trailing 30d window.
    types = {s.get("type") for s in cur if s.get("type")}
    tags: list[str] = []
    if types:
        if "SAST" in types:
            tags.append("binary + source")
        else:
            tags.append("binary")

    authors = {s.get("createdBy") for s in cur if s.get("createdBy")}

    # 12 ISO-week UTC throughput buckets (completed scans only).
    # Align to ISO calendar weeks: each bucket runs from Monday 00:00 UTC.
    # iso_day: Monday=1 … Sunday=7; days_since_monday brings us to this week's Monday.
    days_since_monday = now.isoweekday() - 1  # isoweekday(): Mon=1, Sun=7
    this_week_start = (now - timedelta(days=days_since_monday)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    weeks: list[dict[str, Any]] = []
    for wk in range(12):
        # oldest bucket first: wk=0 → 12 weeks ago, wk=11 → current week
        start = this_week_start - timedelta(weeks=11 - wk)
        end = start + timedelta(weeks=1)
        n = sum(
            1
            for s in scans
            if s.get("status") == "COMPLETED"
            and _in_window(_parse_iso(s.get("created")), start, end)
        )
        weeks.append({"label": f"W{wk + 1}", "completed": n})

    return {
        "connected": True,
        "status": "ok",
        "platform": "operational",
        "scans_30d": {
            "count": len(cur),
            "delta_pct": _delta_pct(len(cur), len(prior)),
        },
        "reports_30d": {
            "count": reports_30d,
            "delta_pct": _delta_pct(reports_30d, reports_prior),
        },
        "active_users_30d": {"count": len(authors)},
        "scan_health": {
            "success_rate": rate,
            "grade": _grade(rate) if rate is not None else "—",
            "completed": completed,
            "errored": errored,
            "tags": tags,
        },
        "throughput": {"weeks": weeks},
        # meta is overwritten by the caller with real pages_fetched/capped
        "meta": {"pages_fetched": 0, "capped": False},
    }


@router.get("/overview")
async def overview(
    request: Request, state: WebAppState = Depends(get_state)
) -> JSONResponse:
    """Return Command Center overview data."""
    if not _state_configured(state):
        return JSONResponse(
            {
                "connected": False,
                "status": "unconfigured",
                "platform": "unreachable",
            }
        )

    since = datetime.now(UTC) - timedelta(weeks=12)
    res: ScanFetchResult = await fetch_scans(
        state,
        since=since,
        early_stop_terminal=False,
        max_pages=12,
    )

    if res.status != "ok":
        platform = "degraded" if res.status == "rate_limited" else "unreachable"
        return JSONResponse(
            {
                "connected": False,
                "status": res.status,
                "platform": platform,
            }
        )

    from fs_report.report_history import count_runs_since  # local import avoids cycles

    now = datetime.now(UTC)
    try:
        out = str(Path(state.get("output_dir", "./output")).expanduser().resolve())
        reports_30d = count_runs_since(now - timedelta(days=30), output_dir=out)
        reports_prior = (
            count_runs_since(now - timedelta(days=60), output_dir=out) - reports_30d
        )
    except Exception:
        reports_30d = reports_prior = 0

    body = _build_overview(res.scans, reports_30d, max(reports_prior, 0), now)
    body["meta"] = {"pages_fetched": res.pages_fetched, "capped": res.capped}
    return JSONResponse(body)


@router.post("/pin")
async def pin(
    request: Request, state: WebAppState = Depends(get_state)
) -> JSONResponse:
    """Save pinned report/project/version/folder to state.

    ``pinned_folder`` carries the folder ID (design §4); a folder-only pin (no
    project) round-trips here just like project/version so the run bar / R-key /
    palette can seed ``SCOPE.folder`` from ``CC.pinned.folder`` on any page.
    """
    form = await request.form()
    for key in ("pinned_report", "pinned_project", "pinned_version", "pinned_folder"):
        val = form.get(key)
        if val is not None:
            state[key] = str(val)
    state.save()
    return JSONResponse(
        {
            k: state.get(k, "")
            for k in (
                "pinned_report",
                "pinned_project",
                "pinned_version",
                "pinned_folder",
            )
        }
    )


# ── Per-report card config (spec §5/§6/§8) ────────────────────────────


@router.get("/card-config")
async def card_config_fragment(
    request: Request,
    recipe: str = Query(""),
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the tabbed card-back HTML fragment for a single recipe.

    Fields are pre-filled with EFFECTIVE values (the recipe's saved override
    merged over the global ``state``) and field visibility comes from
    ``compute_prerun_fields([recipe])``.  Each overridable field carries
    ``data-override`` (1 = currently an override, 0 = inheriting) so Task-4 JS
    can render the inherit indicator.
    """
    # Inline (not module-level) to break the run <-> command_center import
    # cycle: run.py imports _load_recipe from this module.
    from fs_report.web.routers.run import compute_prerun_fields

    if not recipe.strip():
        return JSONResponse({"error": "recipe is required"}, status_code=400)

    recipe_obj = _load_recipe(recipe)
    if recipe_obj is None:
        return JSONResponse({"error": f"Unknown recipe: {recipe}"}, status_code=404)

    override = recipe_override(state, recipe_obj.name)

    # For a plain compound, derive field visibility and requires_cve from the
    # union of its children's requirements (PR2.3a).
    from fs_report.recipe_requirements import (
        compound_prerun_inputs as _compound_prerun_inputs,
    )

    compound_children_map: dict[str, list[str]] | None = None
    result = _compound_prerun_inputs(recipe_obj, _load_recipe)
    if result is not None:
        reqs, child_names = result
        requires_cve_flag = reqs.requires_cve
        requires_component_flag = reqs.requires_component
        compound_children_map = {recipe_obj.name.lower(): child_names}
    else:
        requires_cve_flag = bool(getattr(recipe_obj, "requires_cve", False))
        requires_component_flag = bool(getattr(recipe_obj, "requires_component", False))

    fields = compute_prerun_fields(
        [recipe_obj.name], compound_children=compound_children_map
    )

    def _is_ov(key: str) -> bool:
        return key in override

    def _glob_val(key: str) -> Any:
        return state.get(key, "")

    class _Eff:
        """Effective view: override value if present, else global ``state``."""

        @staticmethod
        def get(key: str, default: Any = None) -> Any:
            if key in override:
                return override[key]
            return state.get(key, default)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "components/_card_config.html",
        {
            "recipe": recipe_obj.name,
            "nonce": nonce,
            "eff": _Eff(),
            "is_ov": _is_ov,
            "glob_val": _glob_val,
            "requires_cve": requires_cve_flag,
            "requires_component": requires_component_flag,
            **fields,
        },
    )


@router.post("/card-config")
async def card_config_save(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Persist a recipe's per-card override (CSRF-guarded).

    Order (spec §6/§13): typed allowlist + coercion → diff-vs-global rule →
    ``missing_card_inputs`` validation (400, no persist when a required card
    input is missing) → locked fresh-read-merge-save.  Returns
    ``{status, needs_setup}`` with ``needs_setup`` recomputed against the
    just-saved effective state.
    """
    form = await request.form()
    recipe_name = str(form.get("recipe", "")).strip()
    if not recipe_name:
        return JSONResponse({"error": "recipe is required"}, status_code=400)

    recipe_obj = _load_recipe(recipe_name)
    if recipe_obj is None:
        return JSONResponse(
            {"error": f"Unknown recipe: {recipe_name}"}, status_code=404
        )

    try:
        coerced = _coerce_card_config(form)
    except CardConfigCoercionError as exc:
        # Present non-empty but non-numeric int field → 400, persist nothing.
        return JSONResponse(
            {"error": f"Invalid value for {exc.field}", "field": exc.field},
            status_code=400,
        )

    # Request-time validation of the coerced form values (SP1).  Inline import
    # to break the run <-> command_center import cycle (mirrors the inline import
    # of compute_prerun_fields in card_config_fragment above).
    #
    # This IS the card-config equivalent of "period↔range mutual clearing": a
    # card-config save REPLACES the recipe's stored override (it does not fold a
    # payload over a saved override the way start_run does), so there is no
    # base/incoming merge to perform here.  Rejecting an ambiguous combination
    # (e.g. both a named period AND a custom range) at validation is the correct
    # enforcement for this surface.  Do NOT call merge_with_period_range_clearing
    # here — there is no merge at the card-config save surface.
    from fs_report.web.routers.run import validate_run_overrides

    val_errors = validate_run_overrides(coerced)
    if val_errors:
        return JSONResponse(
            {"error": "; ".join(val_errors), "errors": val_errors}, status_code=400
        )

    # SP2: recipe-aware destructive check — a saved autotriage card override is
    # only valid on a Triage Prioritization card. (Confirm is enforced at run
    # time, not save time — saving an autotriage card writes nothing.)
    from fs_report.web.routers.run import validate_destructive_overrides

    destr_errors = validate_destructive_overrides(
        coerced, recipes=[recipe_name], is_workflow=False
    )
    if destr_errors:
        return JSONResponse(
            {"error": "; ".join(destr_errors), "errors": destr_errors},
            status_code=400,
        )

    override = _build_override(state, coerced)

    # Validate card-suppliable required inputs (requires_cve → cve_filter)
    # against the EFFECTIVE value (this save's sparse override merged OVER the
    # live global), NOT the sparse override alone (PR #117 review Fix 3).
    # Rationale: ``needs_setup`` — the READ-side gate that decides whether a card
    # is runnable — uses the effective value (override ∪ global). Validating the
    # WRITE here against the bare override disagreed with that read gate: a
    # ``requires_cve`` recipe whose CVE is set GLOBALLY (no per-card override)
    # would 400 "missing cve_filter" when the user saved an unrelated field
    # (e.g. just ``period``), even though the card is plainly runnable. Build the
    # effective view by overlaying this save's override onto the live global so
    # the read and write gates agree. A recipe with neither override nor global
    # CVE still 400s (the card legitimately stays needs-setup).
    effective_card = dict(override)
    for key in ("cve_filter", "component_filter"):
        if key not in effective_card:
            glob = state.get(key)
            if glob is not None:
                effective_card[key] = glob
    missing = missing_card_inputs(recipe_obj, effective_card)
    if missing:
        return JSONResponse(
            {"error": "Missing required field(s)", "missing": missing},
            status_code=400,
        )

    _save_recipe_override(state, recipe_obj.name.lower(), override)

    return JSONResponse(
        {"status": "saved", "needs_setup": needs_setup(state, recipe_obj)}
    )


@router.post("/card-config/reset")
async def card_config_reset(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Delete a recipe's per-card override (CSRF-guarded).

    Removes the single target recipe key via the same locked
    fresh-read-merge-save, then returns ``{status, needs_setup}`` recomputed
    (a ``requires_cve`` recipe with no global CVE goes back to needs-setup).
    """
    form = await request.form()
    recipe_name = str(form.get("recipe", "")).strip()
    if not recipe_name:
        return JSONResponse({"error": "recipe is required"}, status_code=400)

    recipe_obj = _load_recipe(recipe_name)
    if recipe_obj is None:
        return JSONResponse(
            {"error": f"Unknown recipe: {recipe_name}"}, status_code=404
        )

    _save_recipe_override(state, recipe_obj.name.lower(), None)

    return JSONResponse(
        {"status": "reset", "needs_setup": needs_setup(state, recipe_obj)}
    )
