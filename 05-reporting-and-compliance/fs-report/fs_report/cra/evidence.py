"""CRA Compliance — per-finding evidence fan-out helpers.

Implements Phase C2 (/exploits) and Phase C3 (/findings/activity) of the
morning-queue redesign.

Phase C2 — /exploits fan-out
Fetches ``/public/v0/findings/{pvId}/{findingId}/exploits`` in parallel for
findings in the 4 queue sections (🔥 sla_breach, 🆕 newly_above,
🔁 re_emerged, ⏰ still_in_triage) and projects the rich VulnCheck-
derived response down to a 3-field evidence dict:

  {
      "threat_actor_names": ["APT28", ...],   # sorted, deduped
      "ransomware_families": ["LockBit", ...], # sorted, deduped
      "botnet_names": ["Mirai", ...],          # sorted, deduped
  }

The full /exploits payload can be ~13 MB for high-profile CVEs (log4shell);
the projection keeps it to <5 KB per finding.

Phase C3 — /activity fan-out (opt-in via --with-triage-age)
Fetches ``/public/v0/projects/{pid}/findings/activity?cve=<cve_id>`` in
parallel for still_in_triage + re_emerged findings and projects to:

  {
      "triage_started_at": "2026-04-15T10:00:00Z" | None,
      "resolution_date": "2026-05-01T12:00:00Z" | None,
  }

Budget cap: 500 fetches per run (spec §1 / §2). Callers pre-prioritise
the target list so that 🔥 → 🆕 → 🔁 → ⏰ ordering means the most urgent
findings get evidence even when the budget is exhausted.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# Budget caps (spec §1 / §2):
_DEFAULT_MAX_FETCHES = 500  # Hard cap on /exploits or /activity fan-out per run
# Lowered from 10 → 4 in UX-8 because live runs on maven-repro (139 🔥)
# saw ~70 % of /exploits requests rejected with HTTP 429. Combined with
# the new retry-with-backoff in _fetch_one, 4 workers ships consistent
# threat-actor / ransomware / botnet evidence without overwhelming the
# platform rate limiter.
_DEFAULT_MAX_WORKERS = 4  # Parallel fetches
_DEFAULT_TIMEOUT_SECONDS = 60  # Per-request timeout

# Retry policy for transient 429 / 5xx on /exploits fan-out (UX-8).
# Backoff schedule in seconds between attempts; first entry is the wait
# AFTER attempt 1 fails. Two retries (after 1 s and 4 s) is enough to
# absorb the bursts that maven-repro produced and keeps total worst-case
# latency per finding bounded (~5 s of waits + 3 × timeout).
_RETRY_BACKOFF_SECONDS: tuple[float, ...] = (1.0, 4.0)
_RETRY_STATUS_CODES: frozenset[int] = frozenset({429, 502, 503, 504})

# Resolved states for C3 /activity resolution_date detection
_RESOLVED_STATES = {
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fetch_threat_evidence(
    api_client: Any,
    targets: list[tuple[str, str]],  # list of (pv_id, finding_id)
    *,
    max_fetches: int = _DEFAULT_MAX_FETCHES,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[tuple[str, str], dict[str, list[str]]]:
    """Fan out /exploits fetches for the given (pv_id, finding_id) targets.

    Returns a mapping from (pv_id, finding_id) → projected evidence dict.
    Findings whose fetch fails or times out are absent from the result
    (caller treats as empty evidence).

    Respects ``max_fetches`` cap (spec §1 budget). When
    ``len(targets) > max_fetches``, only the first ``max_fetches`` targets
    are fetched and a WARNING is logged. Callers should pre-prioritize the
    target list so that important findings (🔥 SLA-breach, 🆕 newly above)
    come before less-important ones (⏰ still in triage).
    """
    if not targets:
        return {}

    capped = targets[:max_fetches]
    if len(targets) > max_fetches:
        logger.warning(
            "C2: target list of %d exceeds budget cap of %d; "
            "fetching only the first %d (caller-prioritized).",
            len(targets),
            max_fetches,
            max_fetches,
        )

    results: dict[tuple[str, str], dict[str, list[str]]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _fetch_one, api_client, pv_id, finding_id, timeout_seconds
            ): (pv_id, finding_id)
            for pv_id, finding_id in capped
        }
        for future in as_completed(futures):
            key, evidence = future.result()
            if evidence is not None:
                results[key] = evidence

    logger.info(
        "C2 /exploits fan-out: %d/%d targets returned evidence",
        len(results),
        len(capped),
    )
    return results


def merge_evidence_into_sections(
    sections_dict: dict[str, pd.DataFrame],
    evidence_map: dict[tuple[str, str], dict[str, list[str]]],
    section_keys: tuple[str, ...],
) -> dict[str, pd.DataFrame]:
    """Add threat_actor_names / ransomware_families / botnet_names columns.

    Adds three new columns (comma-joined strings) to each section DataFrame
    named in ``section_keys``.  Sections not in ``section_keys`` are
    unchanged.

    Rows with no evidence in the map (missing key or empty arrays) get
    empty strings.

    Args:
        sections_dict: ``{section_key: DataFrame}`` from
            ``cra_sections.assemble_sections``.
        evidence_map: ``{(pv_id, finding_id): evidence_dict}`` from
            ``fetch_threat_evidence``.
        section_keys: Tuple of section keys to enrich
            (e.g. ``("sla_breach", "newly_above", "re_emerged",
            "still_in_triage")``).

    Returns:
        Updated ``sections_dict`` (the non-enriched sections are the
        original DataFrame objects; enriched sections are new DataFrame
        objects with the extra columns appended).
    """
    _EVIDENCE_COLS = ("threat_actor_names", "ransomware_families", "botnet_names")

    out = dict(sections_dict)  # shallow copy of the outer dict

    for key in section_keys:
        df = sections_dict.get(key)
        if df is None:
            continue

        df = df.copy()

        if df.empty:
            # Add empty columns so downstream code can rely on their presence
            for col in _EVIDENCE_COLS:
                if col not in df.columns:
                    df[col] = pd.Series(dtype=str)
            out[key] = df
            continue

        rows = df.to_dict(orient="records")
        ta_vals: list[str] = []
        rf_vals: list[str] = []
        bn_vals: list[str] = []

        for row in rows:
            pv_id = str(row.get("project_version_id") or "")
            # Prefer the numeric finding_row_id (used as the path param in
            # /exploits URL).  Fall back to cve_id for DataFrames that pre-date
            # the finding_row_id column addition.
            finding_id = str(row.get("finding_row_id") or row.get("cve_id") or "")
            ev = evidence_map.get((pv_id, finding_id))
            if ev is None:
                ta_vals.append("")
                rf_vals.append("")
                bn_vals.append("")
            else:
                ta_vals.append(", ".join(ev.get("threat_actor_names", [])))
                rf_vals.append(", ".join(ev.get("ransomware_families", [])))
                bn_vals.append(", ".join(ev.get("botnet_names", [])))

        df["threat_actor_names"] = ta_vals
        df["ransomware_families"] = rf_vals
        df["botnet_names"] = bn_vals
        out[key] = df

    return out


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _project_exploits_response(payload: dict) -> dict[str, list[str]]:
    """Project the /exploits response to the 3-field evidence shape.

    Drops everything except threat-actor names, ransomware family names,
    and botnet names.  Returns a dict with three sorted, deduped lists.

    Response-shape unwrapping (UX-8 finding from live diagnosis): the
    actual /exploits API returns a CVE-keyed envelope around a forge
    "request" wrapper. Sample for Log4Shell::

        {
            "CVE-2021-44228": {
                "_key": "CVE-2021-44228",
                "request": {
                    "threat_actors":      [{threat_actor_name: ..., ...}, ...],
                    "ransomware":         [{ransomware_family: ..., ...}, ...],
                    "botnets":            [{botnet_name: ..., ...}, ...],
                    ...
                }
            }
        }

    Older test fixtures (and what the original spec assumed) had the
    VulnCheck data at the top level — we accept both shapes. The inner
    record-key names are also platform-correct here:
    ``ransomware_family`` / ``botnet_name`` (not ``family`` / ``name``).
    """
    # Unwrap {CVE: {_key, request}} → request-level dict
    inner = payload
    if isinstance(inner, dict) and inner and "_key" not in inner:
        first_val = next(iter(inner.values()), None)
        if isinstance(first_val, dict) and "request" in first_val:
            inner = first_val["request"]
        elif isinstance(first_val, dict) and (
            "threat_actors" in first_val
            or "ransomware" in first_val
            or "botnets" in first_val
        ):
            # CVE-keyed but no "request" envelope
            inner = first_val
    elif isinstance(inner, dict) and "request" in inner:
        inner = inner["request"]
    inner = inner or {}

    # Threat actors: list[dict] with "threat_actor_name" key
    raw_actors = inner.get("threat_actors") or []
    actor_names: list[str] = sorted(
        {
            str(a["threat_actor_name"])
            for a in raw_actors
            if isinstance(a, dict) and a.get("threat_actor_name")
        }
    )

    # Ransomware: list[dict]. Real API uses "ransomware_family"; older
    # test fixtures used "family" — accept either to keep the fixtures
    # working without forcing a rewrite of every test.
    raw_ransomware = inner.get("ransomware") or []
    ransomware_families: list[str] = sorted(
        {
            str(r.get("ransomware_family") or r.get("family"))
            for r in raw_ransomware
            if isinstance(r, dict) and (r.get("ransomware_family") or r.get("family"))
        }
    )

    # Botnets: list[dict]. Real API uses "botnet_name"; older test
    # fixtures used "name" — accept either.
    raw_botnets = inner.get("botnets") or []
    botnet_names: list[str] = sorted(
        {
            str(b.get("botnet_name") or b.get("name"))
            for b in raw_botnets
            if isinstance(b, dict) and (b.get("botnet_name") or b.get("name"))
        }
    )

    return {
        "threat_actor_names": actor_names,
        "ransomware_families": ransomware_families,
        "botnet_names": botnet_names,
    }


def _fetch_one(
    api_client: Any,
    pv_id: str,
    finding_id: str,
    timeout: int,
) -> tuple[tuple[str, str], dict[str, list[str]] | None]:
    """Fetch /exploits for one (pv_id, finding_id), with retry on rate-limit.

    Returns ``((pv_id, finding_id), projected_evidence)`` on success or
    ``((pv_id, finding_id), None)`` on terminal failure (logs a warning).

    Retry policy (Round 4 review M2-2 / M3-3 tightened): retries ONLY on
    a successful HTTP response whose status is in ``_RETRY_STATUS_CODES``
    (429, 502, 503, 504). Other exceptions — network errors, JSON decode
    errors, raise_for_status on 4xx (e.g. 404), unexpected payload shape
    — fail terminally without consuming the backoff schedule.
    """
    key: tuple[str, str] = (pv_id, finding_id)
    url = f"{api_client.base_url}/public/v0/findings/{pv_id}/{finding_id}/exploits"

    # attempt 1 (no wait), then retries at _RETRY_BACKOFF_SECONDS intervals.
    waits: tuple[float, ...] = (0.0,) + _RETRY_BACKOFF_SECONDS
    last_status: int | None = None
    for attempt_idx, wait in enumerate(waits):
        if wait > 0:
            time.sleep(wait)
        try:
            response = api_client.client.get(url, timeout=timeout)
        except Exception as exc:
            # Network/timeout/connection errors are not retriable here —
            # a retry only helps for transient server-side rate limits or
            # outages that surface as HTTP status responses. Anything that
            # prevents getting a status code (DNS, conn-reset, timeout)
            # is treated as terminal.
            logger.warning(
                "C2: /exploits transport failure for (%s, %s): %s",
                pv_id,
                finding_id,
                exc,
            )
            return key, None

        status = getattr(response, "status_code", 0)
        last_status = status
        if status in _RETRY_STATUS_CODES and attempt_idx < len(waits) - 1:
            # Retriable status — log at DEBUG and loop. Only the final
            # terminal-exhaustion path emits a WARNING.
            logger.debug(
                "C2: /exploits %s attempt %d hit HTTP %d; will retry " "after %.1fs",
                finding_id,
                attempt_idx + 1,
                status,
                waits[attempt_idx + 1],
            )
            continue
        try:
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            # Non-retriable HTTP error (4xx other than 429) or JSON
            # decode failure — fail terminally without consuming the
            # remaining backoff.
            logger.warning(
                "C2: /exploits fetch failed for (%s, %s) [HTTP %s]: %s",
                pv_id,
                finding_id,
                status,
                exc,
            )
            return key, None

        if not isinstance(payload, dict):
            logger.warning(
                "C2: /exploits for (%s, %s) returned unexpected type %s; skipping",
                pv_id,
                finding_id,
                type(payload).__name__,
            )
            return key, None
        return key, _project_exploits_response(payload)

    # Exhausted retries on a retriable status (e.g., HTTP 429 every attempt).
    logger.warning(
        "C2: /exploits fetch exhausted retries for (%s, %s); last HTTP %s",
        pv_id,
        finding_id,
        last_status,
    )
    return key, None


# ---------------------------------------------------------------------------
# Phase C3 — /findings/activity fan-out (opt-in via --with-triage-age)
# ---------------------------------------------------------------------------


def fetch_triage_activity(
    api_client: Any,
    targets: list[tuple[str, str]],  # list of (project_id, cve_id)
    *,
    max_fetches: int = _DEFAULT_MAX_FETCHES,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[tuple[str, str], dict[str, str | None]]:
    """Fan out /findings/activity fetches for the given (project_id, cve_id) targets.

    Returns mapping from (project_id, cve_id) → {
        "triage_started_at": ISO datetime str | None,
        "resolution_date": ISO datetime str | None,
    }.

    Failures are absent from result (caller treats as None for both fields).
    Same budget pattern as fetch_threat_evidence.
    """
    if not targets:
        return {}

    capped = targets[:max_fetches]
    if len(targets) > max_fetches:
        logger.warning(
            "C3: target list of %d exceeds budget cap of %d; "
            "fetching only the first %d (caller-prioritized).",
            len(targets),
            max_fetches,
            max_fetches,
        )

    results: dict[tuple[str, str], dict[str, str | None]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _fetch_one_activity, api_client, project_id, cve_id, timeout_seconds
            ): (project_id, cve_id)
            for project_id, cve_id in capped
        }
        for future in as_completed(futures):
            key, activity = future.result()
            if activity is not None:
                results[key] = activity

    logger.info(
        "C3 /activity fan-out: %d/%d targets returned data",
        len(results),
        len(capped),
    )
    return results


def _project_activity_response(payload: dict) -> dict[str, str | None]:
    """Project the /activity events list to {triage_started_at, resolution_date}.

    - triage_started_at: earliest event with newState=='IN_TRIAGE' AND
      oldState!='IN_TRIAGE' (transition INTO triage, not a self-transition)
    - resolution_date: latest event with newState in _RESOLVED_STATES

    Both None if no qualifying event.
    """
    events = payload.get("events") or []

    triage_started_at: str | None = None
    resolution_date: str | None = None

    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventType") != "VulnerabilityStatusChangedEvent":
            continue
        new_state = event.get("newState")
        old_state = event.get("oldState")
        timestamp = event.get("timestamp")
        if not timestamp:
            continue

        # triage_started_at: INTO IN_TRIAGE transition (not self-transition)
        if new_state == "IN_TRIAGE" and old_state != "IN_TRIAGE":
            if triage_started_at is None or timestamp < triage_started_at:
                triage_started_at = timestamp

        # resolution_date: latest transition into a resolved state
        if new_state in _RESOLVED_STATES:
            if resolution_date is None or timestamp > resolution_date:
                resolution_date = timestamp

    return {
        "triage_started_at": triage_started_at,
        "resolution_date": resolution_date,
    }


def _fetch_one_activity(
    api_client: Any,
    project_id: str,
    cve_id: str,
    timeout: int,
) -> tuple[tuple[str, str], dict[str, str | None] | None]:
    """Fetch /findings/activity for one (project_id, cve_id).

    Returns ``((project_id, cve_id), projected_activity)`` on success or
    ``((project_id, cve_id), None)`` on failure (logs a warning).
    """
    key: tuple[str, str] = (project_id, cve_id)
    url = f"{api_client.base_url}/public/v0/projects/{project_id}/findings/activity"
    try:
        response = api_client.client.get(url, params={"cve": cve_id}, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            logger.warning(
                "C3: /activity for (%s, %s) returned unexpected type %s; skipping",
                project_id,
                cve_id,
                type(payload).__name__,
            )
            return key, None
        return key, _project_activity_response(payload)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "C3: /activity fetch failed for (%s, %s): %s",
            project_id,
            cve_id,
            exc,
        )
        return key, None


def _days_since(iso_str: str, now: datetime) -> int:
    """Days from iso_str (e.g. '2026-04-15T10:00:00Z') to now."""
    started = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    delta = now - started
    return max(0, delta.days)


def merge_triage_activity_into_sections(
    sections_dict: dict[str, pd.DataFrame],
    activity_map: dict[tuple[str, str], dict[str, str | None]],
    *,
    now: datetime,
) -> dict[str, pd.DataFrame]:
    """Update still_in_triage's triage_age_days using triage_started_at
    from activity_map (overriding the detected-fallback from C1). Add
    resolution_date to re_emerged.

    Rows whose finding is absent from activity_map: still_in_triage
    keeps its detected-fallback; re_emerged.resolution_date = empty.
    """
    out = dict(sections_dict)  # shallow copy of the outer dict

    # --- still_in_triage: override triage_age_days from triage_started_at ---
    sit_df = sections_dict.get("still_in_triage")
    if sit_df is not None:
        sit_df = sit_df.copy()
        if not sit_df.empty and "triage_age_days" in sit_df.columns:
            new_ages: list[int] = []
            for row in sit_df.to_dict(orient="records"):
                project_id = str(row.get("project_id") or "")
                cve_id = str(row.get("cve_id") or "")
                activity = activity_map.get((project_id, cve_id))
                if activity is not None and activity.get("triage_started_at"):
                    new_ages.append(
                        _days_since(activity["triage_started_at"], now)  # type: ignore[arg-type]
                    )
                else:
                    # Keep the C1 detected-date fallback
                    new_ages.append(int(row.get("triage_age_days", 0)))
            sit_df["triage_age_days"] = new_ages
        out["still_in_triage"] = sit_df

    # --- re_emerged: add resolution_date column ---
    re_df = sections_dict.get("re_emerged")
    if re_df is not None:
        re_df = re_df.copy()
        resolution_dates: list[str] = []
        if not re_df.empty:
            for row in re_df.to_dict(orient="records"):
                project_id = str(row.get("project_id") or "")
                cve_id = str(row.get("cve_id") or "")
                activity = activity_map.get((project_id, cve_id))
                if activity is not None and activity.get("resolution_date"):
                    resolution_dates.append(activity["resolution_date"])  # type: ignore[arg-type]
                else:
                    resolution_dates.append("")
            re_df["resolution_date"] = resolution_dates
        else:
            # Empty DataFrame — add empty column
            re_df["resolution_date"] = pd.Series(dtype=str)
        out["re_emerged"] = re_df

    return out
