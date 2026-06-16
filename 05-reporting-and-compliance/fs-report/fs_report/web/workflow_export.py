"""Four pure ``model → str`` serializers for workflow export (Pass 3, Task 4).

Each serializer is PURE — no I/O, no FastAPI.  They receive the normalized
workflow model (engine-key shape from ``workflow_store``) and return a text
string ready to write to disk or return from an API endpoint.

Public API
----------
serialize_cli(model) -> str
    Shell script (.sh) — one ``fs-report run …`` line per recipe step.

serialize_forge_yaml(model) -> str
    Finite-State Forge workflow file (.yaml).

serialize_github_action(model) -> str
    GitHub Actions job YAML (.yml).

serialize_forge_mcp(model) -> str
    Forge MCP JS snippet (.js) — a ``forge.runWorkflow({…})`` call.

dispatch(model, target) -> tuple[str, str]
    Dispatch to the correct serializer by *target* name.
    Returns ``(text, filename)``.  Raises ``ValueError`` on unknown target.

TARGETS : frozenset[str]
    The four valid target names: ``cli``, ``forge_yaml``, ``github_action``,
    ``forge_mcp``.

Model shape (normalized, from workflow_store._normalize_model)
--------------------------------------------------------------
{
  name: str,
  slug: str,                          # derived; slug(name)
  global: {
    project_filter: str | None,
    version_filter: str | None,
    period: str,                      # 7d|14d|30d|2m|3m|6m|1y  (never "custom")
    start: str | None,                # ISO date — present instead of period
    end: str | None,                  # ISO date — present instead of period
    ai: bool,
    ai_depth: str,                    # summary|full
    cache_ttl: str,
  },
  steps: [{
    id: str,
    kind: str,                        # recipe | mcp_tool
    ref: str,                         # canonical recipe name | mcp tool id
    overrides: {<engine keys>},       # partial; only for recipe steps
    params: {<tool-specific>},        # only for mcp_tool steps
    runnable_locally: bool,           # derived; not persisted
  }],
}

SP1 date-mode contract
----------------------
The model NEVER carries ``period == "custom"`` or a ``custom_range`` key.
Instead a custom date range is expressed as top-level ``start`` + ``end``
keys in the global block (and in step ``overrides`` when a per-step range
is needed).  A global or step config carries EITHER ``period`` OR
``start``+``end``, never both.

Effective config per step (recipe steps only)
---------------------------------------------
The effective config for a step is ``global`` merged with the step's
``overrides`` (override wins on collision).  MCP-tool steps use ``params``
and are excluded from local execution.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from fs_report.slug import slug as make_slug
from fs_report.web.routers.run import merge_with_period_range_clearing as _merge_clear
from fs_report.web.shell_utils import shquote as _shquote
from fs_report.workflow_store import coerce_bool as _coerce_bool

# ---------------------------------------------------------------------------
# Target constants
# ---------------------------------------------------------------------------

TARGETS: frozenset[str] = frozenset({"cli", "forge_yaml", "github_action", "forge_mcp"})

# File extensions per target.
_EXTENSIONS: dict[str, str] = {
    "cli": "sh",
    "forge_yaml": "yaml",
    "github_action": "yml",
    "forge_mcp": "js",
}

# ---------------------------------------------------------------------------
# CONFIG KEY → CLI FLAG mapping table
# (Verified against fs_report/cli/run.py flag definitions)
# ---------------------------------------------------------------------------

#: Maps normalized engine config keys to their real ``fs-report run`` flags.
#: NOTE: this table is REFERENCE/documentation — ``serialize_cli`` emits each flag
#: via an explicit ``if _nonempty(...)`` block, not by iterating this dict.  Adding
#: a key here alone has NO effect; add the matching emit block in ``serialize_cli``.
_CONFIG_KEY_TO_FLAG: dict[str, str] = {
    "project_filter": "--project",
    "folder_filter": "--folder",
    "version_filter": "--version",
    "cve_filter": "--cve",
    "finding_types": "--finding-types",
    "period": "--period",
    "start": "--start",
    "end": "--end",
    "ai": "--ai",  # boolean flag — emitted as bare flag (no value)
    "ai_depth": "--ai-depth",
    "cache_ttl": "--cache-ttl",
    "output_dir": "--output",
    # SP1 new keys
    "top": "--top",
    "triage": "--triage",
    "tp_gate": "--tp-gate",
    "component_match": "--component-match",
    "component_version": "--component-version",
    "license_filter": "--license",
    "threat_context": "--context",
    "baseline_date": "--baseline-date",
    "detected_after": "--detected-after",
    "scan_types": "--scan-type",
    "scan_statuses": "--scan-status",
    "open_only": "--open-only",
    "detailed": "--detailed",
    "standalone": "--standalone",
    "vex_override": "--vex-override",
}

# Keys that are boolean flags (emitted as bare ``--flag``, no value argument).
_BOOL_FLAGS: frozenset[str] = frozenset(
    {"ai", "open_only", "detailed", "standalone", "vex_override"}
)

# SP1 report-config keys that are NOT finite-state-actions GHA inputs.  When a
# step's effective config sets any of these, the GHA serializer emits a single
# ``# note: …`` comment line (they configure in the recipe / platform instead).
_GHA_UNSUPPORTED_NEW_KEYS: frozenset[str] = frozenset(
    {
        "tp_gate",
        "component_match",
        "component_version",
        "license_filter",
        "threat_context",
        "baseline_date",
        "detected_after",
        "scan_types",
        "scan_statuses",
        "open_only",
        "detailed",
        "standalone",
        "vex_override",
        # SP3: uploaded scoring/context file paths are server-local — never
        # emitted to any export; the GHA note tells the user to re-supply them.
        "scoring_file",
        "context_file",
    }
)

# Keys that are NOT emitted in the CLI serializer (workflow-internal or
# non-CLI-applicable).  These are silently skipped.
_SKIP_FOR_CLI: frozenset[str] = frozenset(
    {
        "error_policy",  # workflow executor concept, not a CLI flag
        "ai_prompts",  # reserved override key; emitted separately if needed
        "overwrite",
        # NOTE: current_version_only is NOT skipped — it emits --all-versions
        # when False (default True → no flag); see the emit block in serialize_cli.
        "product_type",
        "network_exposure",
        "regulatory",
        "deployment_notes",
        "component_filter",
    }
)

# Boolean override keys that must be coerced from string → real bool in
# _effective_config so that a hand-edited/inline model with e.g.
# ``vex_override: "false"`` (string) is not treated as True by the exporters
# (``bool("false") is True``).
_BOOL_OVERRIDE_KEYS: frozenset[str] = frozenset(
    {
        "ai",
        "ai_prompts",
        "overwrite",
        "current_version_only",
        "open_only",
        "detailed",
        "standalone",
        "vex_override",
        # B7 (#10B): coerce the destructive FP autotriage opt-in so a string
        # ``"autotriage": "false"`` doesn't emit --autotriage in the CLI export.
        "autotriage",
    }
)

# Integer override keys that must be coerced from string → real int in
# _effective_config so that a Builder-written override like ``top: "50"``
# (string, from a number-input applyOverride call) is emitted by serialize_cli
# as ``--top 50`` (the isinstance(v, int) check in the emit block requires a
# real int, not a string).  Non-numeric values are left as-is so the validator
# catches them.
_INT_OVERRIDE_KEYS: frozenset[str] = frozenset({"top", "triage"})

# ---------------------------------------------------------------------------
# Effective config helper
# ---------------------------------------------------------------------------


def _nonempty(v: Any) -> bool:
    """Return True when *v* is set and, for strings, not whitespace-only."""
    if v is None:
        return False
    if isinstance(v, str):
        return v.strip() != ""
    return True


def _effective_config(
    global_block: dict[str, Any], overrides: dict[str, Any]
) -> dict[str, Any]:
    """Merge *global_block* with step *overrides* (override wins on collision).

    Returns a flat dict of effective config values for a single recipe step.
    The step override's date mode wins over the global: if the override sets a
    custom range (start + end) the global period is dropped, and if the override
    sets a named period the global start/end are dropped.  The result carries
    at most one of {period} or {start, end}.  Period↔range clearing is
    delegated to the shared ``merge_with_period_range_clearing`` helper from
    ``fs_report.web.routers.run`` (no cycle — run.py does not import this
    module).

    Boolean override keys in ``_BOOL_OVERRIDE_KEYS`` are coerced to real bools
    via ``_coerce_bool`` so that string values such as ``"false"`` (from a
    hand-edited or inline model) are not misread as truthy.

    Integer override keys in ``_INT_OVERRIDE_KEYS`` (``top``, ``triage``) are
    coerced from string to real int so that Builder-written string values like
    ``"50"`` satisfy the ``isinstance(v, int)`` emit check in ``serialize_cli``.
    Non-numeric strings are left as-is for the validator to catch.
    """
    # C1: when the USER explicitly set the Global-Properties date mode
    # (period_touched / range_touched), that choice OVERRIDES a step's card
    # period — export parity with the run path's _effective_step_config. Read the
    # touched flags off the GLOBAL block (they are NOT engine keys — read-and-
    # strip), and when one is set, drop the step's date keys so the step
    # contributes no date mode and the global period/range flows through the
    # merge unchanged. Untouched ⇒ today's override-wins behavior.
    period_touched = _coerce_bool(global_block.get("period_touched"))
    # range_touched only overrides a step's date keys when BOTH global bounds are
    # present — a hand-edited range_touched:true with one bound can't force an
    # incomplete range (the frontend only sets it with both). Otherwise fall back
    # to today's step-wins so a partial range never silently drops the step date.
    range_touched = _coerce_bool(global_block.get("range_touched")) and bool(
        str(global_block.get("start") or "").strip()
        and str(global_block.get("end") or "").strip()
    )
    if period_touched or range_touched:
        overrides = {
            k: v for k, v in overrides.items() if k not in ("period", "start", "end")
        }

    # Merge global_block with overrides using the shared period↔range clearing
    # helper (replaces the previous inline duplication of the same logic).
    effective = _merge_clear(global_block, overrides)
    # The touched flags steer precedence only — they must NEVER appear in the
    # effective/engine dict (they would otherwise be copied verbatim from
    # global_block by the merge). Strip them.
    effective.pop("period_touched", None)
    effective.pop("range_touched", None)

    # Coerce boolean keys so string "false" / "0" / "no" does not silently
    # enable a bare CLI flag (bool("false") is True).
    for key in _BOOL_OVERRIDE_KEYS:
        if key in effective:
            effective[key] = _coerce_bool(effective[key])

    # Coerce integer keys (top / triage) so a Builder-written string override
    # like ``"50"`` (from applyOverride('top', "50")) is converted to a real int
    # before the isinstance(v, int) emit check in serialize_cli.  Non-numeric
    # strings are left as-is so the validator (validate_run_overrides) catches them.
    for key in _INT_OVERRIDE_KEYS:
        if key in effective:
            v = effective[key]
            if isinstance(v, str) and v.strip():
                try:
                    effective[key] = int(v.strip())
                except ValueError:
                    pass  # leave as-is; validator will catch it

    # Step folder overrides an INHERITED global project (Finding 5; mirrors
    # _effective_step_config in the run path). When the step's OWN override
    # explicitly sets ``folder_filter`` and does NOT set its own
    # ``project_filter``, the user retargeted that step to a FOLDER — so the only
    # ``project_filter`` in ``effective`` is the INHERITED global one. Left in
    # place, the project-wins precedence below would silently drop the step's
    # folder and emit the global project instead. Clear the inherited global
    # project for this step so folder-wins applies. The normal rule stays intact
    # when the step sets its OWN project (then we don't clear).
    step_sets_folder = bool(str(overrides.get("folder_filter") or "").strip())
    step_sets_project = bool(str(overrides.get("project_filter") or "").strip())
    step_sets_version = bool(str(overrides.get("version_filter") or "").strip())
    if step_sets_folder and not step_sets_project:
        effective.pop("project_filter", None)
        # A version is project-specific; a folder-only step has no project to
        # version. The inherited global ``version_filter`` would otherwise leave
        # the exported step at folder + a stale version, which the engine
        # rejects (a version requires a project). Clear it alongside the
        # inherited project so a folder-only step exports as folder-only. (A
        # step setting its OWN project keeps ``step_sets_project`` True, so we
        # don't reach here and its inherited/own version is preserved.)
        effective.pop("version_filter", None)
    # A version ID is scoped to ONE project (round-5; mirrors
    # _effective_step_config). When a step retargets to its OWN
    # ``project_filter``, the inherited global ``version_filter`` belongs to the
    # GLOBAL project — exporting ``StepProj`` + a ``GlobalProj`` version ID is an
    # invalid pairing. Drop it UNLESS the step supplies its OWN version.
    if step_sets_project and not step_sets_version:
        effective.pop("version_filter", None)

    # Folder-targeting precedence — project wins (design §6, authoritative).
    # When the effective config (global ← override) carries a SPECIFIC project,
    # the folder was only a UI filter and must not travel with it.  Drop it here
    # — the single effective-config chokepoint shared by all four serializers —
    # mirroring _build_engine_config (run path) so an exported artifact never
    # emits both an ambiguous project + folder scope.  Folder-only (no project)
    # keeps its folder_filter.
    if str(effective.get("project_filter") or "").strip():
        effective.pop("folder_filter", None)

    # Invariant: a version requires a project (mirrors _build_engine_config in the
    # run path). ``version_filter`` is a project-scoped version ID, meaningless and
    # engine-rejected without a project. Whenever the (stripped) ``project_filter``
    # is empty — folder-only OR portfolio-wide — drop any inherited/leftover
    # ``version_filter`` so no exported CLI/YAML/MCP/Action artifact emits a
    # project-less folder+version (or portfolio+version) scope. This general rule
    # supersedes the narrow folder-only-step clear above (kept harmless) and also
    # covers a workflow whose GLOBAL scope is folder-only with a version. When a
    # project IS set the version is kept untouched.
    if not str(effective.get("project_filter") or "").strip():
        effective.pop("version_filter", None)

    return effective


# ---------------------------------------------------------------------------
# 1. CLI serializer
# ---------------------------------------------------------------------------


def serialize_cli(model: dict[str, Any]) -> str:
    """Serialize *model* to a shell script (.sh) reproducing the workflow.

    Each recipe step becomes one ``fs-report run …`` line using the real
    CLI flags (``_CONFIG_KEY_TO_FLAG`` table).  A custom date range (top-level
    ``start``+``end`` in the effective config) emits ``--start <date> --end
    <date>``.  A named period emits ``--period <period>``.  The model NEVER
    carries ``period == "custom"`` or ``custom_range`` (SP1 contract).

    MCP-tool steps render as comment lines:
    ``# <tool>(<params>)  — MCP tool step, runs via Forge agent``.
    """
    name = str(model.get("name") or "Workflow")
    global_block: dict[str, Any] = model.get("global") or {}
    steps: list[dict[str, Any]] = model.get("steps") or []

    lines: list[str] = [
        "#!/usr/bin/env bash",
        f"# Workflow: {name}",
        "# Generated by fs-report Workflow Builder",
        "# Reproduce this workflow with the fs-report CLI",
        "",
    ]

    for step in steps:
        kind = step.get("kind", "recipe")
        ref = step.get("ref", "")

        if kind == "mcp_tool":
            # MCP steps: render as a comment with params.
            params: dict[str, Any] = step.get("params") or {}
            if params:
                params_str = ", ".join(
                    f"{k}={json.dumps(v)}" for k, v in sorted(params.items())
                )
                lines.append(
                    f"# {ref}({params_str})  — MCP tool step, runs via Forge agent"
                )
            else:
                lines.append(f"# {ref}()  — MCP tool step, runs via Forge agent")
            continue

        # Recipe step: build effective config and emit the CLI command.
        overrides = step.get("overrides") or {}
        eff = _effective_config(global_block, overrides)

        parts: list[str] = ["fs-report run"]

        # --recipe flag always first.
        parts.append(f"--recipe {_shquote(ref)}")

        # Project and version (scope).  Folder targeting (design §6): emit
        # --folder (the folder ID) ONLY when no project is set — _effective_config
        # already dropped folder_filter under project-wins precedence, so this
        # `if folder` arm only fires for a folder-only step.
        project = eff.get("project_filter")
        version = eff.get("version_filter")
        folder = eff.get("folder_filter")
        if project:
            parts.append(f"--project {_shquote(str(project))}")
        elif folder:
            parts.append(f"--folder {_shquote(str(folder))}")
        if version:
            parts.append(f"--version {_shquote(str(version))}")

        # Date mode: custom range → --start/--end; named period → --period.
        # The model never carries period=="custom" or custom_range (SP1).
        start = eff.get("start")
        end = eff.get("end")
        period = eff.get("period")
        if _nonempty(start) and _nonempty(end):
            parts.append(f"--start {_shquote(str(start))}")
            parts.append(f"--end {_shquote(str(end))}")
        elif _nonempty(period):
            parts.append(f"--period {period}")

        # AI enrichment (boolean flag).
        ai = eff.get("ai", False)
        if ai:
            parts.append("--ai")

        # AI depth (only relevant when AI is on; emit anyway if set).
        ai_depth = eff.get("ai_depth")
        if ai_depth and ai_depth != "summary":
            parts.append(f"--ai-depth {ai_depth}")

        # Cache TTL.
        cache_ttl = eff.get("cache_ttl")
        if cache_ttl:
            parts.append(f"--cache-ttl {cache_ttl}")

        # CVE filter.
        cve_filter = eff.get("cve_filter")
        if cve_filter:
            parts.append(f"--cve {_shquote(str(cve_filter))}")

        # Finding types (only emit if non-default).
        finding_types = eff.get("finding_types")
        if finding_types:
            parts.append(f"--finding-types {finding_types}")

        # Version scope — the CLI flag is --current-version-only/--all-versions
        # (default True). Builder persists current_version_only=False (the
        # "compare all versions, not just latest" toggle); the only non-default
        # to emit is --all-versions on the False value. True is the default →
        # emit nothing (no redundant --current-version-only). The value is
        # already coerced to a real bool by _BOOL_OVERRIDE_KEYS in
        # _effective_config, so a string "false" reads as False here.
        if "current_version_only" in eff and eff["current_version_only"] is False:
            parts.append("--all-versions")

        # SP1 new str keys.
        tp_gate = eff.get("tp_gate")
        if _nonempty(tp_gate):
            parts.append(f"--tp-gate {_shquote(str(tp_gate))}")

        component_match = eff.get("component_match")
        # Omit the default "contains" to keep output minimal.
        if _nonempty(component_match) and component_match != "contains":
            parts.append(f"--component-match {_shquote(str(component_match))}")

        component_version = eff.get("component_version")
        if _nonempty(component_version):
            parts.append(f"--component-version {_shquote(str(component_version))}")

        license_filter = eff.get("license_filter")
        if _nonempty(license_filter):
            parts.append(f"--license {_shquote(str(license_filter))}")

        threat_context = eff.get("threat_context")
        if _nonempty(threat_context):
            parts.append(f"--context {_shquote(str(threat_context))}")

        baseline_date = eff.get("baseline_date")
        if _nonempty(baseline_date):
            parts.append(f"--baseline-date {_shquote(str(baseline_date))}")

        detected_after = eff.get("detected_after")
        if _nonempty(detected_after):
            parts.append(f"--detected-after {_shquote(str(detected_after))}")

        scan_types = eff.get("scan_types")
        if _nonempty(scan_types):
            parts.append(f"--scan-type {_shquote(str(scan_types))}")

        scan_statuses = eff.get("scan_statuses")
        if _nonempty(scan_statuses):
            parts.append(f"--scan-status {_shquote(str(scan_statuses))}")

        # Triage-tab limit settings (--top / --triage): emit only when positive.
        # 0 means "unset/all" (matches the CLI default), so skip 0/empty/None.
        top_val = eff.get("top")
        if isinstance(top_val, int) and top_val > 0:
            parts.append(f"--top {top_val}")
        triage_val = eff.get("triage")
        if isinstance(triage_val, int) and triage_val > 0:
            parts.append(f"--triage {triage_val}")

        # SP1 new bool flags (bare flag when truthy).
        if eff.get("open_only"):
            parts.append("--open-only")
        if eff.get("detailed"):
            parts.append("--detailed")
        if eff.get("standalone"):
            parts.append("--standalone")
        if eff.get("vex_override"):
            parts.append("--vex-override")

        # B7 (#10B): FP-Analysis autotriage (destructive VEX write). Emitted ONLY
        # for an FP step that carries the explicit opt-in — the exported command
        # runs headless, so the persisted --autotriage IS the authorization (no
        # interactive prompt). A non-FP step never emits it (validation blocks the
        # opt-in there anyway). --autotriage is a bare boolean flag.
        if ref.strip().lower() == "false positive analysis" and eff.get("autotriage"):
            parts.append("--autotriage")
            _at_status = eff.get("autotriage_status")
            if _nonempty(_at_status):
                parts.append(f"--autotriage-status {_shquote(str(_at_status))}")

        lines.append(" \\\n  ".join(parts))

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 2. Forge YAML serializer
# ---------------------------------------------------------------------------


def serialize_forge_yaml(model: dict[str, Any]) -> str:
    """Serialize *model* to a finite-state-forge workflow YAML file (.yaml).

    The output shape matches the reference snapshot in
    ``tests/fixtures/forge_workflow_schema.yaml``.  Recipe steps map to
    ``run_recipe`` tool calls; MCP-tool steps map to their tool id, including
    each step's ``params``.

    Date translation (SP1): our model uses top-level ``start``/``end`` for a
    custom range (never ``period=="custom"``).  Forge's wire format uses
    ``period: "custom"`` + ``start_date``/``end_date`` — this serializer
    translates back to Forge's wire form so the emitted YAML is Forge-native.
    """
    name = str(model.get("name") or "Workflow")
    slug = model.get("slug") or make_slug(name) or "workflow"
    global_block: dict[str, Any] = model.get("global") or {}
    steps: list[dict[str, Any]] = model.get("steps") or []

    # Build the config block.
    config: dict[str, Any] = {}
    # Strip project_filter to its meaningful value (M2-1): this global block is
    # read directly, NOT via _effective_config, so a whitespace-only project
    # from a hand-edited/imported workflow must be treated as NO project —
    # matching _build_engine_config / _effective_config — or it would emit a
    # bogus ``project: "   "`` plus its project-scoped version.
    project = (global_block.get("project_filter") or "").strip() or None
    folder = global_block.get("folder_filter")
    version = global_block.get("version_filter")
    # SP1: model uses start/end (no period) for a custom range.
    g_start = global_block.get("start")
    g_end = global_block.get("end")
    period = global_block.get("period", "30d")
    ai_depth = global_block.get("ai_depth", "summary")
    ai = global_block.get("ai", False)
    cache_ttl = global_block.get("cache_ttl")

    # Folder targeting (design §6): emit the global folder scope (folder ID)
    # ONLY when no project is set — project wins (matching _build_engine_config /
    # _effective_config precedence).
    if project:
        config["project"] = project
    elif _nonempty(folder):
        config["folder"] = folder
    # Invariant: a version requires a project (mirrors _build_engine_config /
    # _effective_config). The GLOBAL config block reads version_filter directly
    # (not through _effective_config), so guard it here too — emit the
    # project-scoped version ONLY when a project is the global scope. A
    # folder-only or portfolio-wide global must not carry a project-less version
    # (the engine would reject it).
    if project and version:
        config["project_version_id"] = version

    # Translate date mode to Forge wire format.
    if _nonempty(g_start) and _nonempty(g_end):
        # Custom range → Forge uses period:"custom" + start_date/end_date.
        config["period"] = "custom"
        config["start_date"] = g_start
        config["end_date"] = g_end
    else:
        config["period"] = period

    config["ai_depth"] = ai_depth
    if ai:
        config["ai"] = True
    if cache_ttl:
        config["cache_ttl"] = cache_ttl

    # Build the steps list.
    forge_steps: list[dict[str, Any]] = []
    for i, step in enumerate(steps):
        kind = step.get("kind", "recipe")
        ref = step.get("ref", "")
        overrides = step.get("overrides") or {}
        step_params_raw: dict[str, Any] = step.get("params") or {}
        # Step IDs use the tool name slug (run-recipe for recipe steps, tool id
        # for MCP steps), matching native forge output (e.g. "run-recipe_2").
        tool_name = "run_recipe" if kind == "recipe" else ref
        step_id = f"{make_slug(tool_name) or 'step'}_{i + 1}"

        if kind == "recipe":
            eff = _effective_config(global_block, overrides)
            params: dict[str, Any] = {"recipe": ref}
            # Per-step overrides that differ from global.  Folder targeting
            # (design §6): folder_filter → "folder".  _effective_config has
            # already applied project-wins precedence (folder dropped when the
            # effective project is set), so a step that overrides the project
            # never emits a stale folder.
            for key, forge_key in [
                ("period", "period"),
                ("ai_depth", "ai_depth"),
                ("project_filter", "project"),
                ("folder_filter", "folder"),
                ("version_filter", "project_version_id"),
                ("cve_filter", "cve"),
                ("finding_types", "finding_types"),
                ("cache_ttl", "cache_ttl"),
            ]:
                eff_val = eff.get(key)
                global_val = global_block.get(key)
                # Only emit if override differs from global (keep output minimal).
                if key in overrides and eff_val != global_val:
                    if eff_val is not None and eff_val != "":
                        params[forge_key] = eff_val
            # current_version_only is the ONE field we emit ALWAYS, not via the
            # usual emit-only-non-default rule: Forge's run_recipe tool defaults
            # current_version_only to FALSE (all-versions) — the OPPOSITE of
            # fs-report's CLI default True (latest-only).  So a default step
            # (effectively True) that OMITTED the field on Forge would silently
            # run all-versions.  Emit the RESOLVED effective bool (default True
            # when unset) so the Forge step always carries fs-report's intent.
            params["current_version_only"] = bool(eff.get("current_version_only", True))
            # Per-step custom range: translate to Forge wire format.
            # The effective step may carry start/end either inherited from global
            # or set via a step override.
            eff_start = eff.get("start")
            eff_end = eff.get("end")
            if _nonempty(eff_start) and _nonempty(eff_end):
                params["period"] = "custom"
                params["start_date"] = eff_start
                params["end_date"] = eff_end
            # AI flag (per-step): always emit when there is an explicit per-step
            # override OR when the effective value is true, so that a step
            # overriding global ai=true down to ai=false round-trips correctly.
            step_ai = eff.get("ai", False)
            if "ai" in overrides or step_ai:
                params["ai"] = bool(step_ai)
            # error_policy is an fs-report EXECUTOR concept (consumed by the local
            # run loop), NOT a Forge workflow-schema key — it is deliberately NOT
            # emitted into the Forge YAML / MCP step params (Task 6).
            # SP1 new keys (tp_gate, component_match, etc.) are also NOT Forge
            # schema keys — they are CLI/GHA only and are NOT emitted here.

            forge_step: dict[str, Any] = {
                "id": step_id,
                "tool": "run_recipe",
                "params": params,
                "description": ref,
            }
        else:
            # MCP-tool step.
            tool_params: dict[str, Any] = {}
            if step_params_raw:
                tool_params.update(step_params_raw)
            forge_step = {
                "id": step_id,
                "tool": ref,
                "description": ref,
            }
            if tool_params:
                forge_step["params"] = tool_params

        forge_steps.append(forge_step)

    doc: dict[str, Any] = {
        "id": slug,
        "name": name,
        "version": "1.0.0",
        "bundled": False,
        "config": config,
        "steps": forge_steps,
    }

    return yaml.dump(
        doc,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


# ---------------------------------------------------------------------------
# 3. GitHub Action serializer
# ---------------------------------------------------------------------------


def _gha_scalar(value: Any) -> str:
    """Render *value* as a YAML-safe scalar for a GitHub Action ``with:`` line.

    Delegates to PyYAML's scalar emitter (via a one-key ``yaml.safe_dump``) so a
    value containing ``"`` / ``\\`` / ``:`` / leading-special chars is correctly
    quoted/escaped and the document still ``yaml.safe_load``s.  Hand-rolled
    ``f'recipe: "{ref}"'`` interpolation (the bug) produced invalid YAML for such
    values; this routes every value through the emitter instead.
    """
    # safe_dump a single-key mapping, then strip the "k: " prefix + trailing
    # newline to recover just the emitted scalar (with whatever quoting/escaping
    # PyYAML deems necessary).
    dumped = yaml.safe_dump(
        {"k": value}, default_flow_style=False, allow_unicode=True
    ).rstrip("\n")
    return dumped[len("k: ") :]


def serialize_github_action(model: dict[str, Any]) -> str:
    """Serialize *model* to a GitHub Actions job YAML file (.yml).

    The output shape matches the reference snapshot in
    ``tests/fixtures/github_action_reference.yml``.  Recipe steps become job
    steps (``FiniteStateInc/finite-state-actions@v1``); **MCP-tool steps are
    interleaved as YAML comment lines** so the GHA file documents the full
    pipeline (spec §7).

    Date mode (SP1): when the effective config carries top-level ``start``+``end``
    (a custom range), those are emitted as ``start:``/``end:`` inputs and
    ``period`` is omitted.  A named period emits ``period: <period>``.  The model
    never carries ``period=="custom"`` or ``custom_range``.

    Every emitted value is routed through :func:`_gha_scalar` (the PyYAML scalar
    emitter) so a recipe/project/CVE value containing ``"`` or ``\\`` produces
    valid, round-trippable YAML.
    """

    name = str(model.get("name") or "Workflow")
    global_block: dict[str, Any] = model.get("global") or {}
    steps: list[dict[str, Any]] = model.get("steps") or []

    job_steps: list[str] = []

    has_recipe_step = any(s.get("kind") == "recipe" for s in steps)

    for step in steps:
        kind = step.get("kind", "recipe")
        ref = step.get("ref", "")

        if kind == "mcp_tool":
            # MCP-tool steps document the full pipeline as a comment, mirroring
            # the CLI serializer (they run via the Forge agent, not as a GHA
            # step).  Comment text is plain (not YAML-parsed) so no escaping is
            # needed, but ``params`` are JSON-rendered for fidelity.
            mcp_params: dict[str, Any] = step.get("params") or {}
            if mcp_params:
                params_str = ", ".join(
                    f"{k}={json.dumps(v)}" for k, v in sorted(mcp_params.items())
                )
                job_steps.append(
                    f"      # {ref}({params_str})  "
                    "— MCP tool step, runs via Forge agent"
                )
            else:
                job_steps.append(
                    f"      # {ref}()  — MCP tool step, runs via Forge agent"
                )
            continue

        overrides = step.get("overrides") or {}
        eff = _effective_config(global_block, overrides)

        eff_project = eff.get("project_filter") or ""
        eff_folder = eff.get("folder_filter") or ""
        eff_version = eff.get("version_filter") or ""
        # SP1: date mode — top-level start/end for custom range.
        eff_start = eff.get("start")
        eff_end = eff.get("end")
        eff_period = eff.get("period")
        eff_ai = eff.get("ai", False)
        eff_cve = eff.get("cve_filter")
        eff_finding_types = eff.get("finding_types")
        eff_cache_ttl = eff.get("cache_ttl")

        # The two secrets references are GitHub expression syntax — emit them
        # verbatim (they are valid YAML plain scalars and must not be quoted by
        # the value emitter, which would still parse but reads less cleanly).
        step_lines: list[str] = [
            "      - uses: FiniteStateInc/finite-state-actions@v1",
            "        with:",
            "          domain: ${{ secrets.FS_DOMAIN }}",
            "          token: ${{ secrets.FS_AUTH_TOKEN }}",
            f"          recipe: {_gha_scalar(ref)}",
        ]
        # Folder targeting (design §6): the finite-state-actions action forwards
        # ``folder`` to the CLI's --folder.  Emit it ONLY when no project is set
        # (eff already dropped folder_filter under project-wins precedence), so a
        # GHA step never carries both an ambiguous project + folder scope.
        if eff_project:
            step_lines.append(f"          project: {_gha_scalar(str(eff_project))}")
        elif eff_folder:
            step_lines.append(f"          folder: {_gha_scalar(str(eff_folder))}")
        if eff_version:
            step_lines.append(f"          version: {_gha_scalar(str(eff_version))}")

        # Date mode: custom range → start/end inputs, omit period; named → period.
        if _nonempty(eff_start) and _nonempty(eff_end):
            step_lines.append(f"          start: {_gha_scalar(str(eff_start))}")
            step_lines.append(f"          end: {_gha_scalar(str(eff_end))}")
        elif _nonempty(eff_period):
            step_lines.append(f"          period: {_gha_scalar(eff_period)}")

        if "ai" in overrides or eff_ai:
            step_lines.append(f"          ai: {'true' if eff_ai else 'false'}")
        if eff_cve:
            step_lines.append(f"          cve: {_gha_scalar(str(eff_cve))}")
        if eff_finding_types:
            step_lines.append(
                f"          finding_types: {_gha_scalar(str(eff_finding_types))}"
            )
        if eff_cache_ttl:
            step_lines.append(f"          cache_ttl: {_gha_scalar(str(eff_cache_ttl))}")

        # SP1 new keys are not finite-state-actions inputs — document in a single
        # comment line per step so the user knows where to configure them.
        unsupported_set_keys = [
            k for k in _GHA_UNSUPPORTED_NEW_KEYS if bool(eff.get(k))
        ]
        # current_version_only is also NOT a finite-state-actions input (the
        # action has no current-version-only / all-versions input). It is a
        # DEFAULT-TRUE key whose only non-default is False (the Builder "compare
        # all versions" toggle), so the truthy filter above can't catch it —
        # surface the False case explicitly with the same non-silent note rather
        # than dropping it silently (the export would otherwise revert to the
        # latest-only default with no warning).
        if "current_version_only" in eff and eff["current_version_only"] is False:
            unsupported_set_keys.append("current_version_only")
        if unsupported_set_keys:
            step_lines.append(
                f"          # note: {', '.join(sorted(unsupported_set_keys))} "
                "configure in the recipe/platform (not finite-state-actions inputs)"
            )

        job_steps.extend(step_lines)

    # Build the full YAML document as a string (preserving exact structure).
    lines: list[str] = [
        f"name: {_gha_scalar('fs-report · ' + name)}",
        "on:",
        "  workflow_dispatch: {}",
        "  schedule:",
        '    - cron: "0 6 * * *"',
        "jobs:",
        "  report:",
        "    runs-on: ubuntu-latest",
        "    steps:",
    ]
    if has_recipe_step:
        lines.extend(job_steps)
    else:
        # No recipe steps → no real GHA step.  Keep any MCP comment lines for
        # documentation, then add the placeholder comment.
        lines.extend(job_steps)
        lines.append("      # add report steps on the canvas")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 4. Forge MCP serializer
# ---------------------------------------------------------------------------


def serialize_forge_mcp(model: dict[str, Any]) -> str:
    """Serialize *model* to a Forge MCP JS snippet (.js).

    The output is a ``forge.runWorkflow({…})`` call whose inner object is a
    valid JSON-compatible object literal.  MCP steps include their ``params``;
    the exact custom date range is carried in the top-level ``config`` block.

    Date translation (SP1): mirrors serialize_forge_yaml — our model's top-level
    ``start``/``end`` are translated to Forge's ``period:"custom"`` +
    ``start_date``/``end_date`` wire form.
    """
    name = str(model.get("name") or "Workflow")
    global_block: dict[str, Any] = model.get("global") or {}
    steps: list[dict[str, Any]] = model.get("steps") or []

    # Build the config object.
    config: dict[str, Any] = {}
    # Strip project_filter to its meaningful value (M2-1): this global block is
    # read directly, NOT via _effective_config, so a whitespace-only project
    # from a hand-edited/imported workflow must be treated as NO project —
    # matching _build_engine_config / _effective_config — or it would emit a
    # bogus ``project: "   "`` plus its project-scoped version.
    project = (global_block.get("project_filter") or "").strip() or None
    folder = global_block.get("folder_filter")
    version = global_block.get("version_filter")
    g_start = global_block.get("start")
    g_end = global_block.get("end")
    period = global_block.get("period", "30d")

    # Folder targeting (design §6): emit the global folder scope (folder ID)
    # ONLY when no project is set — project wins.
    if project:
        config["project"] = project
    elif _nonempty(folder):
        config["folder"] = folder
    # Invariant: a version requires a project (mirrors _build_engine_config /
    # _effective_config). The GLOBAL config block reads version_filter directly
    # (not through _effective_config), so guard it here too — emit the
    # project-scoped version ONLY when a project is the global scope, never for a
    # folder-only or portfolio-wide global.
    if project and version:
        config["version"] = version

    # Translate date mode to Forge wire format.
    if _nonempty(g_start) and _nonempty(g_end):
        config["period"] = "custom"
        config["start_date"] = g_start
        config["end_date"] = g_end
    else:
        config["period"] = period

    # Build the steps array.
    step_rows: list[dict[str, Any]] = []
    for step in steps:
        kind = step.get("kind", "recipe")
        ref = step.get("ref", "")
        overrides = step.get("overrides") or {}
        step_params: dict[str, Any] = step.get("params") or {}

        if kind == "recipe":
            eff = _effective_config(global_block, overrides)
            params: dict[str, Any] = {"recipe": ref}
            # Carry the FULL effective config for the step (global ← overrides),
            # using the same engine-key → forge-key mapping as serialize_forge_yaml
            # so a per-step override (project/period/cve/…) is faithful in the MCP
            # snippet and isn't silently dropped (Task 5).
            # Folder targeting (design §6): folder_filter → "folder".
            # _effective_config already applied project-wins precedence (folder
            # dropped when the effective project is set), so a project-scoped step
            # never emits a stale folder.
            for eng_key, forge_key in (
                ("project_filter", "project"),
                ("folder_filter", "folder"),
                ("version_filter", "project_version_id"),
                ("period", "period"),
                ("ai_depth", "ai_depth"),
                ("cve_filter", "cve"),
                ("finding_types", "finding_types"),
                ("cache_ttl", "cache_ttl"),
            ):
                val = eff.get(eng_key)
                if val is not None and val != "":
                    params[forge_key] = val
            # current_version_only is emitted ALWAYS (not emit-only-non-default):
            # Forge's run_recipe tool defaults it to FALSE (all-versions) — the
            # OPPOSITE of fs-report's True (latest-only) — so a default step that
            # omitted it would silently run all-versions on Forge.  Emit the
            # resolved effective bool (default True when unset), mirroring
            # serialize_forge_yaml.
            params["current_version_only"] = bool(eff.get("current_version_only", True))
            # Per-step custom range: translate to Forge wire format.
            eff_start = eff.get("start")
            eff_end = eff.get("end")
            if _nonempty(eff_start) and _nonempty(eff_end):
                params["period"] = "custom"
                params["start_date"] = eff_start
                params["end_date"] = eff_end
            # AI flag: always emit when there is an explicit per-step override
            # OR when the effective value is true, so global ai=true→step
            # ai=false round-trips correctly.
            step_ai = eff.get("ai", False)
            if "ai" in overrides or step_ai:
                params["ai"] = bool(step_ai)
            row: dict[str, Any] = {"tool": "run_recipe", "params": params}
        else:
            # MCP tool — tool id carries the ref, params merged in.
            row = {"tool": ref}
            row.update(step_params)

        step_rows.append(row)

    # Build the full object as a JSON-serializable dict, then render it.
    # The wrapper is a JS await-call, not pure JSON, but the inner argument
    # is JSON-compatible (all values are JSON primitives/objects/arrays).
    outer: dict[str, Any] = {
        "name": name,
        "config": config,
        "steps": step_rows,
    }
    # Render the inner JSON with indentation, then wrap in the JS call.
    inner_json = json.dumps(outer, indent=2)

    return (
        "// Run inside your agent via the Forge MCP server\n"
        f"await forge.runWorkflow({inner_json});\n"
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def dispatch(model: dict[str, Any], target: str) -> tuple[str, str]:
    """Dispatch *model* to the serializer for *target*.

    Parameters
    ----------
    model:
        Normalized workflow model dict.
    target:
        One of ``"cli"``, ``"forge_yaml"``, ``"github_action"``,
        ``"forge_mcp"``.

    Returns
    -------
    tuple[str, str]
        ``(text, filename)`` — the serialized text and the suggested filename.
        The filename is ``<slug>.<ext>`` where ``<slug>`` is derived from the
        workflow name and ``<ext>`` is the target's file extension.

    Raises
    ------
    ValueError
        When *target* is not one of the four known targets.
    """
    if target not in TARGETS:
        raise ValueError(
            f"Unknown export target {target!r}. "
            f"Must be one of: {', '.join(sorted(TARGETS))}"
        )

    serializers = {
        "cli": serialize_cli,
        "forge_yaml": serialize_forge_yaml,
        "github_action": serialize_github_action,
        "forge_mcp": serialize_forge_mcp,
    }

    name = model.get("name", "Workflow")
    slug = model.get("slug") or make_slug(name) or "workflow"
    ext = _EXTENSIONS[target]
    filename = f"{slug}.{ext}"

    # C2 — target-agnostic export parity: a "general"/portfolio workflow exports
    # WITHOUT a baked target.  EVERY serializer reads ``model["global"]`` (some
    # directly, some via _effective_config), so stripping the baked scope here —
    # the single funnel feeding all four serializers — covers CLI, Forge YAML,
    # GHA, and Forge-MCP uniformly.  A shallow copy keeps the caller's model
    # intact (export must never mutate the run/save model).
    export_model = _strip_target_agnostic_scope(model)

    text = serializers[target](export_model)
    return text, filename


def _strip_target_agnostic_scope(model: dict[str, Any]) -> dict[str, Any]:
    """Return *model* with the global baked scope removed IFF the global block is
    flagged ``target_agnostic`` (C2).  Otherwise return *model* unchanged.

    The stripped keys are ``project_filter`` / ``folder_filter`` /
    ``version_filter`` in the GLOBAL block (per-step overrides are kept — a
    general workflow can still pin a specific step).  Shallow-copies only the
    model + its global block so the caller's dict is never mutated.
    """
    global_block = model.get("global")
    if not (
        isinstance(global_block, dict)
        and _coerce_bool(global_block.get("target_agnostic"))
    ):
        return model
    stripped = dict(model)
    new_global = dict(global_block)
    for key in ("project_filter", "folder_filter", "version_filter"):
        new_global.pop(key, None)
    stripped["global"] = new_global
    return stripped
