"""Typed wrappers for /project/version/{pvId}/findings/*/counts endpoints.

Each wrapper:
- Builds a `QueryConfig` with the per-pvId endpoint path.
- Consults the SQLite cache under `summary_counts:<kind>:<pvId>`.
- On cache miss, calls the API and writes the result back.

The server response is wrapped in a list by `fetch_data`; we unwrap
the first element (always a single dict for these endpoints).
"""

from __future__ import annotations

from typing import Any

from fs_report.models import QueryConfig, QueryParams

_ENDPOINTS = {
    "severities": "findings/severities/counts",
    "exploit": "findings/exploit/counts",
    "status": "findings/status/counts",
    "category": "findings/category/counts",
}


def _fetch_counts(api_client: Any, pv_id: str, kind: str) -> dict[str, Any]:
    pv_id_str = str(pv_id)
    cache_key = f"summary_counts:{kind}:{pv_id_str}"

    # Check cache
    cache = getattr(api_client, "sqlite_cache", None)
    ttl = getattr(api_client, "cache_ttl", 0) or 0
    if cache is not None and ttl > 0:
        cached = cache.get_raw(cache_key, ttl)
        if isinstance(cached, dict):
            return cached

    endpoint = f"/public/v0/project/version/{pv_id_str}/{_ENDPOINTS[kind]}"
    query = QueryConfig(endpoint=endpoint, params=QueryParams(limit=1))
    result = api_client.fetch_data(query)
    # fetch_data wraps single-object responses in a list.
    data = result[0] if isinstance(result, list) and result else {}

    # Write back
    if cache is not None and ttl > 0 and data:
        cache.put_raw(cache_key, data)

    return data


def fetch_severities_counts(api_client: Any, pv_id: str) -> dict[str, Any]:
    """Return {bySeverity: {critical,high,medium,low,none}, total}."""
    return _fetch_counts(api_client, pv_id, "severities")


def fetch_exploit_counts(api_client: Any, pv_id: str) -> dict[str, Any]:
    """Return {byExploit: {kev,vckev,poc,weaponized,ransomware,botnets,threatactors,commercial,reported}, withExploit, withoutExploit, total}."""
    return _fetch_counts(api_client, pv_id, "exploit")


def fetch_status_counts(api_client: Any, pv_id: str) -> dict[str, Any]:
    """Return {byStatus: {noStatus,notAffected,falsePositive,inTriage,resolved,resolvedWithPedigree,exploitable}, total}."""
    return _fetch_counts(api_client, pv_id, "status")


def fetch_category_counts(api_client: Any, pv_id: str) -> dict[str, Any]:
    """Return {byCategory: {cve,configIssues,credentials,cryptoMaterial,sastAnalysis}, total}."""
    return _fetch_counts(api_client, pv_id, "category")


def fetch_all_summary_counts(api_client: Any, pv_id: str) -> dict[str, dict[str, Any]]:
    """Convenience: fetch all four summary-count endpoints for one pvId.

    Returns {severities, exploit, status, category} each mapping to the
    corresponding endpoint's response dict.
    """
    return {
        "severities": fetch_severities_counts(api_client, pv_id),
        "exploit": fetch_exploit_counts(api_client, pv_id),
        "status": fetch_status_counts(api_client, pv_id),
        "category": fetch_category_counts(api_client, pv_id),
    }
