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
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

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


def _fetch_cve_updates(api_client: Any, config: Config) -> list[dict]:
    """Fetch all CVE updates from /public/v0/cves/updates with pagination.

    Returns empty list if api_client is None or dates are missing.
    """
    if api_client is None:
        return []

    start = _to_iso8601z(getattr(config, "start_date", None))
    end = _to_iso8601z(getattr(config, "end_date", None))

    if not start or not end:
        return []

    params: dict[str, Any] = {
        "startDate": start,
        "endDate": end,
        "limit": 100,
        "offset": 0,
    }

    folder_filter = getattr(config, "folder_filter", None)
    if folder_filter:
        params["folderId"] = folder_filter

    # APIClient exposes its httpx client directly (no `.get()` helper); use it
    # the same way the rest of the codebase does for endpoints that don't fit
    # the QueryConfig shape (see scan_quality.py, dependency_resolver.py).
    url = f"{api_client.base_url}/public/v0/cves/updates"

    results: list[dict] = []
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
            logger.warning(
                "Could not fetch CVE updates (offset=%d): %s", params["offset"], exc
            )
            break

        if not batch:
            break

        results.extend(batch)

        if len(batch) < 100:
            break

        params["offset"] += 100

    logger.info("Fetched %d CVE updates for period %s to %s", len(results), start, end)
    return results


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
