"""Shared helpers for applying VEX triage recommendations.

The CLI (``fs_report.cli.run``) and the serve web path both need to apply the
VEX recommendations a Triage-Prioritization report produces. The post-report
apply is orchestrated by the *caller* (not the engine), so this module holds the
pieces both callers share:

- :func:`invalidate_findings_cache_for_versions` — drop cached findings for
  versions a real (non-dry-run) apply changed.
- :func:`select_tp_recommendations_path` — pick the Triage-Prioritization
  recipe's recs file out of a run's generated files.
- :func:`apply_vex_from_run` — locate that recs file and apply it via
  ``VexApplier`` (web SP2's post-report orchestration).

No live API is touched here directly — ``VexApplier`` performs the calls.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import only for typing
    from fs_report.vex_applier import VexApplyResult

logger = logging.getLogger(__name__)

# The autotriage-capable recipes whose recommendations the web auto-apply can
# target.  B7 (#10B) generalized this beyond TP: FP Analysis can also autotriage.
# Per-recipe recs are written under the recipe's verbatim name (neither name has
# characters the renderer sanitizes), so the directory name is the recipe name.
TP_RECIPE_NAME = "Triage Prioritization"
FP_RECIPE_NAME = "False Positive Analysis"
# Default apply precedence when a recipe target isn't specified: TP first, then
# FP (a multi-recipe run that produced both applies TP's file, preserving the
# pre-B7 behavior for interactive TP+other runs).
_AUTOTRIAGE_RECIPE_DIRS = (TP_RECIPE_NAME, FP_RECIPE_NAME)

# Per-recipe recs are written at ``<output>/<sanitized recipe name>/
# vex_recommendations.json`` (report_engine). "Triage Prioritization" has no
# characters the renderer sanitizes, so the directory name is the recipe name
# verbatim.
_RECS_FILENAME = "vex_recommendations.json"


def invalidate_findings_cache_for_versions(domain: str, results: list[dict]) -> None:
    """Invalidate cached findings for versions affected by a VEX apply."""
    version_ids = {
        str(r["project_version_id"])
        for r in results
        if r.get("success") and r.get("project_version_id")
    }
    if not version_ids:
        return
    try:
        from fs_report.sqlite_cache import SQLiteCache

        cache = SQLiteCache(domain=domain)
        cache.invalidate_versions(version_ids)
    except Exception:
        logger.warning(
            "Failed to invalidate findings cache after VEX apply",
            exc_info=True,
        )


def select_recommendations_path(
    generated_files: list[str],
    recipe_dirs: tuple[str, ...] = _AUTOTRIAGE_RECIPE_DIRS,
) -> str | None:
    """Return the first autotriage recs file found among *recipe_dirs*, in order.

    *recipe_dirs* is the per-recipe output directory names to look for (in
    precedence order) — e.g. ``(FP_RECIPE_NAME,)`` for an FP-only workflow apply,
    or the default ``(TP, FP)`` for an interactive run.  Returns ``None`` if none
    produced a ``vex_recommendations.json``.
    """
    found: dict[str, str] = {}
    for f in generated_files:
        p = Path(f)
        if p.name == _RECS_FILENAME:
            found[p.parent.name] = f
    for d in recipe_dirs:
        if d in found:
            return found[d]
    return None


def select_tp_recommendations_path(generated_files: list[str]) -> str | None:
    """Return the Triage-Prioritization recipe's ``vex_recommendations.json``.

    Thin back-compat wrapper over :func:`select_recommendations_path` restricted
    to the TP recipe.  Returns ``None`` if the run produced no TP recs file.
    """
    return select_recommendations_path(generated_files, (TP_RECIPE_NAME,))


def apply_recs_file(
    recs_path: str,
    *,
    domain: str,
    auth_token: str,
    dry_run: bool,
    vex_override: bool,
    filter_statuses: list[str] | None,
    concurrency: int = 5,
) -> VexApplyResult:
    """Apply a specific ``vex_recommendations.json`` via ``VexApplier``.

    The low-level apply both the initial run (via :func:`apply_vex_from_run`)
    and the apply-for-real endpoint share. On a real (non-dry-run) write it
    invalidates the findings cache for the affected versions.
    """
    from fs_report.vex_applier import VexApplier

    applier = VexApplier(
        auth_token=auth_token,
        domain=domain,
        concurrency=concurrency,
        dry_run=dry_run,
        vex_override=vex_override,
        filter_statuses=filter_statuses,
    )
    result = applier.apply_file(recs_path)
    if not dry_run:
        invalidate_findings_cache_for_versions(domain, result.results)
    return result


def apply_vex_from_run(
    *,
    domain: str,
    auth_token: str,
    generated_files: list[str],
    dry_run: bool,
    vex_override: bool,
    filter_statuses: list[str] | None,
    concurrency: int = 5,
    recipe_dirs: tuple[str, ...] = _AUTOTRIAGE_RECIPE_DIRS,
) -> tuple[VexApplyResult | None, str | None]:
    """Apply an autotriage-capable recipe's VEX recommendations from a run.

    Locates the recs file among ``recipe_dirs`` (default TP→FP precedence; pass
    ``(FP_RECIPE_NAME,)`` to restrict a workflow apply to FP Analysis) and
    applies it.  Returns ``(result, recs_path)``, or ``(None, None)`` when no
    matching recs file was produced (a logged no-op).
    """
    recs_path = select_recommendations_path(generated_files, recipe_dirs)
    if recs_path is None:
        logger.warning(
            "VEX auto-apply requested but no %s was generated for recipe(s) %s",
            _RECS_FILENAME,
            ", ".join(recipe_dirs),
        )
        return None, None
    result = apply_recs_file(
        recs_path,
        domain=domain,
        auth_token=auth_token,
        dry_run=dry_run,
        vex_override=vex_override,
        filter_statuses=filter_statuses,
        concurrency=concurrency,
    )
    return result, recs_path


def summarize_apply_result(result: VexApplyResult) -> dict:
    """A small JSON-serializable summary of a ``VexApplyResult`` for the run
    record / preview panel (the full per-finding results stay out of the record).
    """
    by_status: dict[str, int] = {}
    for r in result.results or []:
        status = str(r.get("status") or r.get("vex_status") or "UNKNOWN")
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "total": result.total,
        "succeeded": result.succeeded,
        "failed": result.failed,
        "skipped_invalid": result.skipped_invalid,
        "skipped_existing": result.skipped_existing,
        "dry_run": result.dry_run,
        "by_status": by_status,
    }
