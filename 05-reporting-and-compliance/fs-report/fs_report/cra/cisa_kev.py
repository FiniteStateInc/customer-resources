"""CISA Known Exploited Vulnerabilities (KEV) catalog fetch + 24h cache.

Fetches the public CISA KEV catalog from:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The catalog is cached at ~/.fs-report/cache/cisa-kev.json with a 24-hour TTL.

Cache storage strategy: project-on-save.  Only ``cveID``, ``dateAdded``, and
``dueDate`` are stored per entry (full catalog is ~3 MB; projected cache is
~50 KB for a ~1000-entry catalog).  The cache is a flat dict keyed by cveID:

  {
    "CVE-2024-1234": {
      "cisa_dateAdded": "2024-06-15",
      "cisa_remediation_due": "2024-07-15"
    },
    ...
  }

Offline fallback behaviour
--------------------------
* Live fetch failure + fresh cache  → serve cached data (normal TTL path).
* Live fetch failure + stale cache  → serve stale data + log warning.
* Live fetch failure + no cache     → return {} + log warning.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, cast

import httpx

logger = logging.getLogger(__name__)

_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_PATH: Path = Path.home() / ".fs-report" / "cache" / "cisa-kev.json"
_CACHE_TTL_SECONDS: int = 24 * 60 * 60


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _cache_is_fresh(path: Path) -> bool:
    """Return True if *path* exists and its mtime is within the TTL."""
    if not path.exists():
        return False
    return time.time() - path.stat().st_mtime < _CACHE_TTL_SECONDS


def _load_cache(path: Path) -> dict[str, Any] | None:
    """Return the parsed cache dict, or None if the file is missing or stale.

    The cache format is a flat ``{cveID: {cisa_dateAdded, cisa_remediation_due}}``
    dict.  If the file exists but is stale this function still returns None so
    the caller can decide whether to attempt a live fetch first before falling
    back to stale data.
    """
    if not path.exists():
        return None
    if not _cache_is_fresh(path):
        return None
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("CISA KEV: failed to read cache %s: %s", path, exc)
        return None


def _load_stale_cache(path: Path) -> dict[str, Any] | None:
    """Return the parsed cache dict regardless of TTL (stale-ok read).

    Returns None only if the file is absent or unreadable.
    """
    if not path.exists():
        return None
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("CISA KEV: failed to read stale cache %s: %s", path, exc)
        return None


def _save_cache(path: Path, payload: dict[str, Any]) -> None:
    """Persist *payload* (already projected) to *path*, creating parent dirs."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    except OSError as exc:
        logger.warning("CISA KEV: failed to write cache %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Network fetch
# ---------------------------------------------------------------------------


def _fetch_catalog(url: str) -> dict[str, Any] | None:
    """Fetch and parse the CISA KEV JSON.  Returns None on any failure."""
    try:
        response = httpx.get(url, timeout=30)
        response.raise_for_status()
        return cast(dict[str, Any], response.json())
    except Exception as exc:  # noqa: BLE001
        logger.warning("CISA KEV: failed to fetch catalog from %s: %s", url, exc)
        return None


def _project_catalog(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert raw CISA wire format to the projected cache dict.

    Returns a flat ``{cveID: {cisa_dateAdded, cisa_remediation_due}}`` dict.
    """
    result: dict[str, Any] = {}
    for entry in raw.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        result[cve_id] = {
            "cisa_dateAdded": entry.get("dateAdded", ""),
            "cisa_remediation_due": entry.get("dueDate", ""),
        }
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_kev_due_dates(cve_ids: set[str]) -> dict[str, dict]:
    """Fetch CISA KEV catalog (cached 24h) and return per-CVE entries.

    Args:
        cve_ids: Set of CVE ID strings to look up (e.g. ``{"CVE-2024-1234"}``).

    Returns:
        A dict keyed by CVE ID containing only CVEs present in both the input
        set and the CISA KEV catalog::

            {
                "CVE-2024-1234": {
                    "cisa_dateAdded": "2024-06-15",
                    "cisa_remediation_due": "2024-07-15",
                },
                ...
            }

        Only CVEs in both the input set AND the catalog appear in the result.

    Offline fallback:
        * Live fetch fails + stale cache → serve stale data + log warning.
        * Live fetch fails + no cache    → return {} + log warning.
    """
    if not cve_ids:
        return {}

    cache_path = _CACHE_PATH

    # 1. Try the fresh cache first (avoids any network call).
    catalog = _load_cache(cache_path)

    if catalog is None:
        # Cache is absent or stale — attempt a live fetch.
        raw = _fetch_catalog(_CATALOG_URL)
        if raw is not None:
            catalog = _project_catalog(raw)
            _save_cache(cache_path, catalog)
        else:
            # Live fetch failed.  Try the stale cache as a graceful fallback.
            catalog = _load_stale_cache(cache_path)
            if catalog is None:
                logger.warning(
                    "CISA KEV: catalog unavailable (offline and no cache). "
                    "CRA KEV due-date enrichment will be skipped."
                )
                return {}
            logger.warning(
                "CISA KEV: using stale cache (offline fallback). "
                "CRA KEV due-dates may be out of date."
            )

    # 2. Filter to only the requested CVEs.
    return {cve_id: catalog[cve_id] for cve_id in cve_ids if cve_id in catalog}
