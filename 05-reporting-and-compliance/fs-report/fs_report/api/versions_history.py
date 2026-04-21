"""Fetch the full version history for a project, with count rollups.

Uses the cross-project `/public/v0/versions` endpoint (not
`/public/v0/projects/{id}/versions`) because only the former returns
`componentCount`, `findingCount`, `violations`, and `warnings` per
version. The project-scoped URL returns a lightweight list
(id/name/created/updated only) — insufficient for summary-mode panels
that need per-version counts for Severity Trends and Finding Age.

Caching: the response is stored in the raw cache under
`versions_history:<project_id>` (bypassing the structured-table cache
which doesn't know about the /versions endpoint). Honors the API
client's `cache_ttl` + `sqlite_cache` like the summary_counts wrappers.
"""

from __future__ import annotations

from typing import Any

from fs_report.models import QueryConfig, QueryParams


def fetch_versions_history(api_client: Any, project_id: Any) -> list[dict]:
    """Return all versions for `project_id` with per-version count fields.

    Each element contains at least: `id`, `name`, `created`,
    `componentCount`, `findingCount`, `violations`, `warnings`.
    Sorted by `created` ascending.
    """
    project_id_str = str(project_id)
    cache_key = f"versions_history:{project_id_str}"

    # Check cache
    cache = getattr(api_client, "sqlite_cache", None)
    ttl = getattr(api_client, "cache_ttl", 0) or 0
    if cache is not None and ttl > 0:
        cached = cache.get_raw(cache_key, ttl)
        if isinstance(cached, list):
            return cached

    query = QueryConfig(
        endpoint="/public/v0/versions",
        params=QueryParams(
            limit=10000,
            filter=f"project=={project_id_str}",
            sort="created:asc",
        ),
    )
    # skip_cache_store=True: avoids the "Unknown endpoint '/public/v0/versions'"
    # warning from the structured-table cache layer, which doesn't know about
    # /versions. We cache ourselves below via put_raw.
    result = api_client.fetch_all_with_resume(
        query, show_progress=False, skip_cache_store=True
    )
    versions = result if isinstance(result, list) else []

    # Write back
    if cache is not None and ttl > 0:
        cache.put_raw(cache_key, versions)

    return versions
