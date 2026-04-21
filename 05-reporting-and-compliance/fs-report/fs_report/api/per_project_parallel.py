"""Reusable per-project parallel execution helper.

Used by recipes that iterate per-project/per-version work units where
each unit is a small bundle of sequential API calls, and the
portfolio-wide loop is dominated by I/O (HTTP latency + throttling).

The helper runs work units concurrently across a thread pool. Failures
in one unit do not abort the overall run — the caller receives each
project paired with either its result or its exception, and can decide
how to aggregate.

Typical usage:

    def fetch_summary_for_project(proj):
        pv_id = proj["defaultBranch"]["latestVersion"]["id"]
        return {
            "severities": fetch_severities_counts(api_client, pv_id),
            "exploit": fetch_exploit_counts(api_client, pv_id),
            ...
        }

    results = per_project_parallel(projects, fetch_summary_for_project,
                                    max_workers=10)
    for proj, outcome in results:
        if isinstance(outcome, Exception):
            logger.warning("Project %s failed: %s", proj["name"], outcome)
            continue
        # aggregate outcome into dashboard data
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


def per_project_parallel(
    projects: list[dict[str, Any]],
    work_fn: Callable[[dict[str, Any]], Any],
    max_workers: int = 10,
) -> list[tuple[dict[str, Any], Any]]:
    """Run `work_fn(project)` concurrently across projects.

    Args:
        projects: Iterable of project dicts (or any records).
        work_fn: Callable receiving one project, returning a result.
        max_workers: Concurrency level. 1 = serial (deterministic order).

    Returns:
        List of `(project, result_or_exception)` tuples, one per input
        project. Ordering is input order when `max_workers == 1`;
        otherwise unordered (caller should not rely on it).
    """
    if not projects:
        return []

    if max_workers <= 1:
        # Serial path — deterministic ordering for tests and debugging.
        return [(p, _run_safely(work_fn, p)) for p in projects]

    results: list[tuple[dict[str, Any], Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_proj = {pool.submit(work_fn, p): p for p in projects}
        for future in as_completed(future_to_proj):
            proj = future_to_proj[future]
            try:
                results.append((proj, future.result()))
            except Exception as e:  # noqa: BLE001 — we preserve per-project exceptions
                results.append((proj, e))
    return results


def _run_safely(work_fn: Callable[[dict[str, Any]], Any], proj: dict[str, Any]) -> Any:
    """Serial variant — return result or captured exception."""
    try:
        return work_fn(proj)
    except Exception as e:  # noqa: BLE001
        return e
