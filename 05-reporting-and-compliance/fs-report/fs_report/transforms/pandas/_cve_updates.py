"""
Shared helpers for CVE-update processing.

This module is the single source of truth for:
  - fetching and classifying /public/v0/cves/updates records
    (consumed by Security Progress and Version Comparison), and
  - CRA-specific helpers (CveUpdate dataclass, normalize_update,
    threshold_crossings_from_updates) used by the CRA Compliance
    morning-queue report.

Wire format for /cves/updates records:
    {
        "cveId": "CVE-2024-1234",
        "type": "update" | "new" | "retract",
        "oldValue": {"severity": "HIGH", "cvss": 7.5, "exploitMaturity": "poc"},
        "newValue": {"severity": "HIGH", "cvss": 7.5, "exploitMaturity": "weaponized"},
        "projects": [{"id": "p1", "name": "Home Cloud", "defaultBranch": {...}}],
    }

    Notes (audit 2026-05-23):
      - oldValue is null for type=="new"; newValue is null for type=="retract"
      - The endpoint carries NO timestamps and NO inKev/exploitInfo deltas
        (API wishlist #15-#17).

    Notes (live, 2026-10-15):
      - A startDate..endDate window over 90 days is rejected with HTTP 400;
        ``fetch_cve_updates_window`` fetches longer windows in slices.
      - Identical records repeat (a Jan-2026 window: 5,858 records, 1,111
        distinct); the fetch drops exact repeats. Paging is stable.
      - Severity and exploitMaturity values are lowercase; older records
        (Jan-Mar 2026) are type "update" with oldValue null and only
        exploitMaturity set, and an empty projects list.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

# The endpoint rejects a startDate..endDate window longer than this with HTTP
# 400 ("CVE update windows may not exceed 90 days"; observed live 2026-10-15,
# not in the OpenAPI spec). Exactly 90 days is accepted.
_MAX_WINDOW_DAYS = 90

# Severity rank mapping for comparison
_SEVERITY_RANK: dict[str, int] = {
    "UNKNOWN": 0,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _to_iso8601z(date_str: str | None) -> str | None:
    """Convert "2024-01-01" or "2024-01-01T00:00:00" to "2024-01-01T00:00:00Z".

    Returns None if date_str is None or unparseable.
    """
    if not date_str:
        return None
    try:
        dt = pd.to_datetime(date_str, utc=False)
        # Format without microseconds, with Z suffix
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001
        return None


def _fetch_cve_updates(
    api_client: Any, config: Config, errors: list[str] | None = None
) -> list[dict]:
    """Fetch all CVE updates for the run's period (``config`` start/end dates).

    Never folder-scoped. ``config.folder_filter`` is the raw ``--folder``
    input — often a folder name — and the endpoint's ``folderId`` rejects
    names and ignores subfolders, so passing it through made a ``--folder
    "Name"`` run silently get no external changes. A caller that needs folder
    scope narrows the result itself with ``scope_updates_to_projects`` and
    the engine-resolved folder tree (Security Progress), or post-filters
    against its own findings (Version Comparison, CRA Compliance).

    Returns empty list if api_client is None or dates are missing, and when
    the lookup failed — then a WARNING says no updates are reported, and
    ``errors`` (when given) receives the reason, as from
    ``fetch_cve_updates_window``.
    """
    start_date = getattr(config, "start_date", None)
    end_date = getattr(config, "end_date", None)
    failures: list[str] = []
    updates = fetch_cve_updates_window(
        api_client, start_date, end_date, errors=failures
    )
    if errors is not None:
        errors.extend(failures)
    # One line per run period here; the per-window fetch logs at DEBUG
    # because Version Comparison repeats it for every version pair.
    if failures:
        logger.warning(
            "CVE updates for period %s to %s could not be looked up; " "reporting none",
            _to_iso8601z(start_date) or start_date,
            _to_iso8601z(end_date) or end_date,
        )
    elif api_client is not None:
        logger.info(
            "Fetched %d CVE updates for period %s to %s",
            len(updates),
            _to_iso8601z(start_date),
            _to_iso8601z(end_date),
        )
    return updates


def scope_updates_to_projects(
    updates: list[dict], project_ids: AbstractSet[Any]
) -> list[dict]:
    """Keep the /cves/updates records that touch any of ``project_ids``.

    Each kept record's ``projects`` list is narrowed to those projects, so a
    report scoped to a folder tree never names a project outside it. IDs
    compare as strings (the engine's folder set holds strings; the wire may
    carry numbers). A record with no in-scope project is dropped.
    """
    wanted = {str(pid) for pid in project_ids}
    scoped: list[dict] = []
    for update in updates:
        projects = [
            p
            for p in update.get("projects") or []
            if isinstance(p, dict) and str(p.get("id")) in wanted
        ]
        if projects:
            scoped.append({**update, "projects": projects})
    return scoped


def fetch_cve_updates_window(
    api_client: Any,
    start_date: str | None,
    end_date: str | None,
    errors: list[str] | None = None,
) -> list[dict]:
    """Fetch all CVE updates from /public/v0/cves/updates between two dates,
    with pagination.

    Dates may be ``YYYY-MM-DD`` or ISO datetimes. There is deliberately no
    folder parameter: the endpoint's ``folderId`` rejects names and ignores
    subfolders, so callers scope the result client-side (see
    ``_fetch_cve_updates``). Returns an empty list if api_client is None or either
    date is missing or unparseable. When ``errors`` is given, a missing date or
    a failed request appends a message to it, so a caller can tell "no updates"
    from "could not look".

    A window longer than the endpoint's 90-day cap is fetched as contiguous
    slices. The result is all or nothing: a failed request fails the whole
    window, returning no records (never the slices or pages fetched before
    it, which would read as the full window's updates) and requesting no
    later slice. Exact-duplicate records, which the endpoint repeats, are
    dropped.
    """
    if api_client is None:
        return []

    start = _to_iso8601z(start_date)
    end = _to_iso8601z(end_date)

    if not start or not end:
        if errors is not None:
            message = f"missing or unparseable date ({start_date!r}, {end_date!r})"
            logger.warning("Could not look up CVE updates: %s", message)
            errors.append(message)
        return []

    # APIClient exposes its httpx client directly (no `.get()` helper); use it
    # the same way the rest of the codebase does for endpoints that don't fit
    # the QueryConfig shape (see scan_quality.py, dependency_resolver.py).
    url = f"{api_client.base_url}/public/v0/cves/updates"

    results: list[dict] = []
    seen: set[str] = set()
    for slice_start, slice_end in _window_slices(start, end):
        if not _fetch_window_slice(
            api_client, url, slice_start, slice_end, results, seen, errors
        ):
            # A failed slice fails the window. Partial records would read as
            # the whole window's updates — a silent undercount — so none are
            # returned, and later slices are not worth the requests.
            return []

    logger.debug("Fetched %d CVE updates for period %s to %s", len(results), start, end)
    return results


def _window_slices(start: str, end: str) -> list[tuple[str, str]]:
    """Split ``start``..``end`` into consecutive windows the endpoint accepts.

    The endpoint rejects windows longer than ``_MAX_WINDOW_DAYS`` with HTTP
    400. ``startDate`` is exclusive and ``endDate`` inclusive, so slices that
    share a boundary neither overlap nor leave a gap. A window that is short
    enough — or empty or reversed, which the endpoint answers with no
    records — is sent as it is.
    """
    lo, hi = pd.Timestamp(start), pd.Timestamp(end)
    step = pd.Timedelta(days=_MAX_WINDOW_DAYS)
    if hi - lo <= step:
        return [(start, end)]
    slices: list[tuple[str, str]] = []
    while hi - lo > step:
        nxt = lo + step
        slices.append((_format_z(lo), _format_z(nxt)))
        lo = nxt
    slices.append((_format_z(lo), end))
    return slices


def _format_z(ts: pd.Timestamp) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _fetch_window_slice(
    api_client: Any,
    url: str,
    start: str,
    end: str,
    results: list[dict],
    seen: set[str],
    errors: list[str] | None,
) -> bool:
    """Page one slice into ``results``, skipping records already in ``seen``.

    The endpoint repeats identical records (one Jan-2026 window held 5,858
    records for 1,110 CVEs), and every consumer counts records, so an exact
    repeat is dropped. Records that differ in any field — another change of
    the same CVE, or the same change for other projects — are kept.

    Returns False when a request failed (logged, and appended to
    ``errors`` when given).
    """
    params: dict[str, Any] = {
        "startDate": start,
        "endDate": end,
        "limit": 100,
        "offset": 0,
    }
    while True:
        try:
            response = api_client.client.get(url, params=params, timeout=60)
            response.raise_for_status()
            payload = response.json()
            # Endpoint returns either a bare list or {"data": [...]}.
            if isinstance(payload, dict) and "data" in payload:
                batch = payload["data"]
            elif isinstance(payload, list):
                batch = payload
            else:
                batch = []
        except Exception as exc:  # noqa: BLE001
            message = _request_error_message(exc)
            logger.warning(
                "Could not fetch CVE updates for %s to %s (offset=%d): %s",
                start,
                end,
                params["offset"],
                message,
            )
            if errors is not None:
                errors.append(message)
            return False

        if not batch:
            return True

        for record in batch:
            key = json.dumps(record, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                results.append(record)

        if len(batch) < 100:
            return True

        params["offset"] += 100


def _request_error_message(exc: Exception) -> str:
    """The exception text plus the response body when there is one: httpx's
    ``raise_for_status`` message omits the body, which is where the endpoint
    says why it refused (e.g. "CVE update windows may not exceed 90 days")."""
    response = getattr(exc, "response", None)
    body = ""
    if response is not None:
        try:
            body = (response.text or "").strip()
        except Exception:  # noqa: BLE001
            body = ""
    if not body:
        return str(exc)
    return f"{exc} — {body[:500]}"


def _exploit_rank(maturity: str | None) -> int:
    """Map exploit maturity string to a comparable rank (0-3)."""
    if not maturity:
        return 0
    m = maturity.upper()
    if m in ("POC", "PROOF_OF_CONCEPT"):
        return 1
    if m == "FUNCTIONAL":
        return 2
    if m in ("HIGH", "WEAPONIZED", "EXPLOITED_IN_WILD"):
        return 3
    # UNPROVEN and unknown values -> 0
    return 0


def _process_cve_updates(updates: list[dict]) -> dict[str, list[dict]]:
    """Classify CVE updates into categories.

    Returns a dict with keys:
        added, retracted, severity_escalated, severity_downgraded,
        exploit_gained, exploit_subsided, other_updates

    A single update may appear in BOTH severity_escalated AND exploit_gained.
    """
    result: dict[str, list[dict]] = {
        "added": [],
        "retracted": [],
        "severity_escalated": [],
        "severity_downgraded": [],
        "exploit_gained": [],
        "exploit_subsided": [],
        "other_updates": [],
    }

    for update in updates:
        cve_id = update.get("cveId", "")
        utype = update.get("type", "")
        old_val = update.get("oldValue") or {}
        new_val = update.get("newValue") or {}
        project_names = [
            p.get("name", "") for p in update.get("projects", []) if isinstance(p, dict)
        ]

        if utype == "new":
            result["added"].append(
                {
                    "cve_id": cve_id,
                    "new_severity": new_val.get("severity"),
                    "new_cvss": new_val.get("cvss"),
                    "projects": project_names,
                }
            )
        elif utype == "retract":
            result["retracted"].append(
                {
                    "cve_id": cve_id,
                    "old_severity": old_val.get("severity"),
                    "projects": project_names,
                }
            )
        elif utype == "update":
            old_sev = old_val.get("severity")
            new_sev = new_val.get("severity")
            old_exploit = old_val.get("exploitMaturity")
            new_exploit = new_val.get("exploitMaturity")

            old_sev_rank = _SEVERITY_RANK.get((old_sev or "").upper(), 0)
            new_sev_rank = _SEVERITY_RANK.get((new_sev or "").upper(), 0)
            old_exp_rank = _exploit_rank(old_exploit)
            new_exp_rank = _exploit_rank(new_exploit)

            sev_changed = False
            exp_changed = False

            if new_sev_rank > old_sev_rank:
                sev_changed = True
                result["severity_escalated"].append(
                    {
                        "cve_id": cve_id,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                        "old_cvss": old_val.get("cvss"),
                        "new_cvss": new_val.get("cvss"),
                        "projects": project_names,
                    }
                )
            elif new_sev_rank < old_sev_rank:
                sev_changed = True
                result["severity_downgraded"].append(
                    {
                        "cve_id": cve_id,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                        "old_cvss": old_val.get("cvss"),
                        "new_cvss": new_val.get("cvss"),
                        "projects": project_names,
                    }
                )

            if new_exp_rank > old_exp_rank:
                exp_changed = True
                result["exploit_gained"].append(
                    {
                        "cve_id": cve_id,
                        "old_exploit": old_exploit,
                        "new_exploit": new_exploit,
                        "severity": new_sev,
                        "projects": project_names,
                    }
                )
            elif new_exp_rank < old_exp_rank:
                exp_changed = True
                result["exploit_subsided"].append(
                    {
                        "cve_id": cve_id,
                        "old_exploit": old_exploit,
                        "new_exploit": new_exploit,
                        "severity": new_sev,
                        "projects": project_names,
                    }
                )

            if not sev_changed and not exp_changed:
                result["other_updates"].append(
                    {
                        "cve_id": cve_id,
                        "old_severity": old_sev,
                        "new_severity": new_sev,
                        "projects": project_names,
                    }
                )

    return result


# ---------------------------------------------------------------------------
# CRA-specific helpers (Task A1.B)
# ---------------------------------------------------------------------------


@dataclass
class CveUpdate:
    """Normalized view of one /cves/updates record for CRA Compliance.

    The API returns camelCase keys (cveId / oldValue / newValue /
    exploitMaturity); this dataclass holds the snake_case normalized
    form so CRA-side code reads cleanly. Wire-format details:

      - type is "update" | "new" | "retract" (NOT "modify")
      - oldValue and newValue carry only {severity, cvss, exploitMaturity}
      - oldValue is null for type=="new"; newValue is null for type=="retract"
      - /cves/updates carries NO timestamps and NO inKev/exploitInfo deltas
        (audit 2026-05-23; API wishlist #15-#17)

    Detection of KEV / ransomware / threat-actor crossings is NOT this
    dataclass's job — see fs_report/cra/snapshot.py.
    """

    cve_id: str
    type: str  # "update" | "new" | "retract"
    old: dict[str, Any]
    new: dict[str, Any]
    projects: list[dict[str, Any]] = field(default_factory=list)


def _normalize_side(side: dict[str, Any] | None) -> dict[str, Any]:
    """Convert one of {oldValue, newValue} from API camelCase to
    normalized snake_case. None → empty dict (matches the dataclass
    contract for retract/new debuts)."""
    if not side:
        return {}
    out: dict[str, Any] = {}
    if "severity" in side:
        out["severity"] = side["severity"]
    if "cvss" in side:
        out["cvss"] = side["cvss"]
    if "exploitMaturity" in side:
        out["exploit_maturity"] = side["exploitMaturity"]
    return out


def normalize_update(record: dict[str, Any]) -> CveUpdate:
    """Convert one raw /cves/updates record to a CveUpdate.

    The function preserves project IDs (the existing _process_cve_updates
    drops them and keeps only names). See spec §0 wire-format details.
    """
    return CveUpdate(
        cve_id=record.get("cveId", ""),
        type=record.get("type", ""),
        old=_normalize_side(record.get("oldValue")),
        new=_normalize_side(record.get("newValue")),
        projects=list(record.get("projects", [])),
    )


# Maturity tiers this helper recognizes. Order is meaningful only for
# diagnostics — the predicate uses set membership on the threshold.
_MATURITY_TIERS = {"poc", "weaponized"}


def _maturity_in_threshold(maturity: str | None, threshold: set[str]) -> bool:
    """True when `maturity` (lowercase, audit-confirmed) is one of the
    threshold's maturity tiers."""
    return maturity in (threshold & _MATURITY_TIERS)


def threshold_crossings_from_updates(
    updates: list[CveUpdate],
    threshold: set[str],
) -> set[str]:
    """Return CVE IDs whose maturity tier crossed INTO the threshold.

    Crossing rules (per spec §0):
      - type=="update": old.maturity not in threshold AND new.maturity in threshold
      - type=="new":    new.maturity in threshold
      - type=="retract": never a crossing

    Args:
        updates: List of CveUpdate records (already normalized via
            normalize_update — wire-format camelCase has been mapped
            to snake_case).
        threshold: Set of CRA tier names. Tier values MUST be lowercase
            ("kev", "weaponized", "poc", "ransomware", "threat_actor")
            to match the audit-confirmed lowercase ``exploitMaturity``
            values on the wire. Uppercase or mixed-case values are
            silently treated as no-tiers (intersection with
            ``_MATURITY_TIERS`` is empty).

    KEV / ransomware / threat-actor crossings are NOT computed here —
    those come from snapshot-diff in fs_report/cra/snapshot.py because
    /cves/updates lacks the relevant fields (audit 2026-05-23; API
    wishlist #15-#17).
    """
    crossed: set[str] = set()
    for u in updates:
        if u.type == "retract":
            continue
        if not _maturity_in_threshold(u.new.get("exploit_maturity"), threshold):
            continue
        if u.type == "new":
            crossed.add(u.cve_id)
            continue
        # type == "update"
        if not _maturity_in_threshold(u.old.get("exploit_maturity"), threshold):
            crossed.add(u.cve_id)
    return crossed
