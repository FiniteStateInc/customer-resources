"""Typed wrappers for /project/version/{pvId}/findings/*/counts endpoints.

Each wrapper:
- Builds a `QueryConfig` with the per-pvId endpoint path.
- Consults the SQLite cache under `summary_counts:<kind>:<pvId>`.
- On cache miss, calls the API and writes the result back.

The server response is wrapped in a list by `fetch_data`; we unwrap
the first element (always a single dict for these endpoints).
"""

from __future__ import annotations

import logging
from typing import Any

from fs_report.models import QueryConfig, QueryParams

logger = logging.getLogger(__name__)

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


def _add_into(target: dict[str, Any], other: dict[str, Any]) -> None:
    """Recursively accumulate ``other``'s numeric leaves into ``target``."""
    for key, value in other.items():
        if isinstance(value, dict):
            nested = target.get(key)
            if not isinstance(nested, dict):
                # A scalar already sitting where this part carries a sub-object
                # means the two payloads disagree on shape. Take the object —
                # skipping would silently drop every count inside it. Logged
                # because the scalar's contribution IS dropped: a shape
                # disagreement is an API-contract anomaly worth a trace.
                if nested is not None:
                    logger.warning(
                        "summary counts disagree on shape at %r "
                        "(scalar %r vs object); keeping the object, "
                        "dropping the scalar",
                        key,
                        nested,
                    )
                nested = {}
                target[key] = nested
            _add_into(nested, value)
        elif isinstance(value, bool):
            # Not a count — last writer wins rather than summing True as 1.
            target[key] = value
        elif isinstance(value, int | float):
            running = target.get(key)
            if isinstance(running, dict):
                # Mirror of the branch above: the accumulator already holds a
                # sub-object where this part carries a scalar. Keep the object —
                # `dict + number` would raise, and the object holds real counts.
                logger.warning(
                    "summary counts disagree on shape at %r "
                    "(object vs scalar %r); keeping the object, "
                    "dropping the scalar",
                    key,
                    value,
                )
                continue
            if isinstance(running, bool) or not isinstance(running, int | float):
                running = 0
            target[key] = running + value
        else:
            target.setdefault(key, value)


def sum_summary_counts(
    parts: list[dict[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """Element-wise sum of several ``fetch_all_summary_counts`` payloads.

    Used by ``--product-only`` to roll a product's dependency-tree versions
    up into the product's own counts. The per-version endpoints report only
    that version's findings, so a product's true posture is the sum over its
    whole tree.

    Always returns a FRESH structure, including for a one-element list:
    ``_fetch_counts`` hands back the cached dict object itself, so returning it
    by reference would let a downstream mutation corrupt the cache entry.
    """
    if not parts:
        return {}
    total: dict[str, dict[str, Any]] = {}
    for part in parts:
        _add_into(total, part or {})
    return total
