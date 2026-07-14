"""CRA Compliance morning-queue section assembler.

Implements Phase C1 of the morning-queue redesign. Takes the merged
Fetch A + Fetch B rows (post-_merge_a_and_b) and produces 5 section
DataFrames with the dedup priority:

  🔥 sla_breach > 🆕 newly_above > 🔁 re_emerged > ⏰ still_in_triage

Queue sections are mutually exclusive (a row in 🔥 doesn't also appear in
🆕). 📋 full_snapshot is *separate from the queue dedup chain* and contains
the full A ∪ B set — queue rows ALSO appear in 📋 (spec §6 line 674: "all
of (A ∪ B), no further status filtering"). This is the morning-briefing
contract: queue highlights + complete audit-appendix inventory.

EU Cyber Resilience Act context: manufacturers must notify ENISA within
24 hours of becoming aware of an actively exploited vulnerability. The
sla_breach section flags KEV findings with their CRA Article 14
notification deadline.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd

from fs_report.cra.tiers import derive_tiers
from fs_report.models import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

SECTION_KEYS = (
    "sla_breach",
    "newly_above",
    "re_emerged",
    "still_in_triage",
    "full_snapshot",
)

SECTION_LABELS = {
    "sla_breach": "🔥 SLA-Breach Risk",
    "newly_above": "🆕 Newly Above Threshold",
    "re_emerged": "🔁 Re-emerged",
    "still_in_triage": "⏰ Still in Triage",
    "full_snapshot": "📋 Full Snapshot",
}

# Statuses that represent suppressed / resolved findings.
RESOLVED_STATUSES = {
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
}

# Severity rank for sorting (higher = more severe).
_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}

# Reachability labels that carry signal. UNKNOWN / empty mean either the
# scan was source-code-only (no reachability run) or the platform hasn't
# computed it yet — in both cases the renderer suppresses the column +
# KPI to avoid empty-table noise.
_MEANINGFUL_REACHABILITY: frozenset[str] = frozenset(
    {"REACHABLE", "UNREACHABLE", "INCONCLUSIVE"}
)


def format_since_period_label(since_start: str, since_end: str) -> str:
    """Format the --since window as a humanized period label for KPI display.

    Rule: <7 days → hours ("24h", "72h", "167h"); ≥7 days → days
    ("7d", "30d", "90d"). Returns "—" when either timestamp is missing
    or the window is non-positive (defensive). Both inputs are expected
    as ISO 8601 strings (the form the transform produces via window.py).
    """
    if not since_start or not since_end:
        return "—"
    start_dt = _parse_iso_date(since_start)
    end_dt = _parse_iso_date(since_end)
    if start_dt is None or end_dt is None:
        return "—"
    delta = end_dt - start_dt
    total_hours = int(delta.total_seconds() // 3600)
    if total_hours <= 0:
        return "—"
    # 7d = 168h is the cutover; <168h shows in hours, ≥168h shows in days.
    if total_hours < 168:
        return f"{total_hours}h"
    return f"{total_hours // 24}d"


def filter_reachability_cols(
    col_specs: list[tuple[str, str]], *, has_reachability: bool
) -> list[tuple[str, str]]:
    """Return *col_specs* with reachability columns stripped when the
    project has no reachability data. Single source of truth for the
    UX-5 suppression applied to multiple section column lists (🔥
    SLA-Breach and 📋 Full Snapshot) across both HTML and MD renderers.
    """
    if has_reachability:
        return list(col_specs)
    reach_keys = {"reachability_label"}
    return [c for c in col_specs if c[0] not in reach_keys]


def has_reachability_data(
    dfs: list[pd.DataFrame] | tuple[pd.DataFrame, ...],
) -> bool:
    """Return True if any row across the provided DataFrames has a
    meaningful reachability_label (REACHABLE / UNREACHABLE / INCONCLUSIVE).

    Used by both HTML and MD renderers to decide whether to show the
    "Reachable" KPI card and the reachability_label column in 📋 Full
    Snapshot. Source-code-scanned projects return UNKNOWN on every row;
    binary scans light it up. Extracted (PR #61 multi-review M1-7) so the
    two renderers can't drift on the suppression heuristic.
    """
    for df in dfs:
        if df.empty or "reachability_label" not in df.columns:
            continue
        if df["reachability_label"].isin(_MEANINGFUL_REACHABILITY).any():
            return True
    return False


# ---------------------------------------------------------------------------
# Testable UTC-now hook (same pattern as window.py)
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """UTC now, aware. Wrapped so tests can monkeypatch."""
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    """Return numeric severity rank (higher = more severe)."""
    return _SEVERITY_RANK.get(str(severity).upper(), 0)


def _parse_iso_date(value: str) -> datetime | None:
    """Parse an ISO date / datetime string to an aware datetime (UTC).

    Handles:
      - "YYYY-MM-DD"
      - "YYYY-MM-DDTHH:MM:SSZ"
      - "YYYY-MM-DDTHH:MM:SS+HH:MM"
      - Trailing Z replaced with +00:00 for Python < 3.11 compat.

    Returns None on empty string or parse failure.
    """
    if not value:
        return None
    # Normalise the Z suffix so fromisoformat works on all Python 3.x.
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


def _fmt_date(dt: datetime) -> str:
    """Format an aware datetime as YYYY-MM-DD (date only)."""
    return dt.astimezone(UTC).strftime("%Y-%m-%d")


def _fmt_iso(dt: datetime) -> str:
    """Format an aware datetime as ISO 8601 with Z suffix."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# CRA Article 14 "became aware" clock (single source of the awareness rule)
# ---------------------------------------------------------------------------


def became_aware_clock(
    *,
    anchor: str | None,
    cisa_date_added: str | None,
    detected: str | None = None,
    anchor_label: str = "detected",
) -> dict[str, Any]:
    """Build the CRA Article 14 "became aware" clock for an early-warning notice.

    ``became_aware = max(cisa_dateAdded, anchor)`` — under CRA Art. 14 the
    manufacturer becomes aware at the *later* of the CISA KEV listing date and the
    platform's awareness anchor. The anchor is normally the platform's detection
    date; the SRP-cascade early recipe falls back to the evidence-seal or
    report-generation time when no detection date is available, recording which it
    used in ``became_aware_basis`` (via ``anchor_label``) so a consumer never
    mistakes a seal/export time for a detection date.

    ``detected`` is the *true* platform detection date (or ``None``) and is reported
    verbatim in the returned clock — it is NEVER inferred from the seal/export
    fallback (a fallback anchor leaves ``detected`` ``None``).

    This is the single source of the awareness rule for the SRP-cascade early
    recipe; it mirrors the same ``max(cisa_dateAdded, anchor)`` rule the
    morning-queue SLA derivation (:func:`_derive_sla_breach_columns`) applies (the
    two are intentionally separate call sites — this one is the SRP producer).

    Either timestamp may be ``None``/empty. The later parseable value wins; if only
    one parses it is used; if neither parses the ``anchor`` is echoed back verbatim
    (which may be empty/non-ISO). Callers that require a usable absolute clock — the
    early recipe — must reject an empty/unparseable result (it does, via
    ``ClockAnchorError``); this function does not fabricate a date.

    Returns the machine-readable ``meta.clock`` object the early recipe emits and the
    forge assembler lifts into ``bundle.clock``::

        {became_aware, became_aware_basis, cisa_date_added, detected}
    """
    dt_cisa = _parse_iso_date(cisa_date_added or "")
    dt_anchor = _parse_iso_date(anchor or "")

    if dt_cisa is not None and dt_anchor is not None:
        became_aware = _fmt_iso(max(dt_cisa, dt_anchor))
    elif dt_cisa is not None:
        became_aware = _fmt_iso(dt_cisa)
    elif dt_anchor is not None:
        became_aware = _fmt_iso(dt_anchor)
    else:
        # Neither parsed — echo the anchor verbatim (may be "").
        became_aware = anchor or ""

    return {
        "became_aware": became_aware,
        "became_aware_basis": f"max(cisa_dateAdded, {anchor_label})",
        "cisa_date_added": cisa_date_added or None,
        "detected": detected or None,
    }


# ---------------------------------------------------------------------------
# Per-section column derivation helpers
# ---------------------------------------------------------------------------


def _derive_sla_breach_columns(
    row: dict[str, Any],
    *,
    kev_catalog: dict[str, dict[str, str]],
    now: datetime,
    awareness_anchor: str = "detected",
) -> dict[str, Any]:
    """Return sla_breach-specific derived columns for *row*.

    Derived columns (spec §6):
      - cra_notification_at: ISO date = max(cisa_dateAdded, anchor)
      - cra_notification_deadline: ISO datetime = cra_notification_at + 24h
      - hours_until_cra_due: float (negative when overdue)
      - breach_status: OVERDUE | DUE_SOON | UPCOMING | UNKNOWN
      - cisa_remediation_due: ISO date from KEV catalog

    ``awareness_anchor`` selects when the customer "became aware" per CRA
    Article 14:
      * ``"detected"`` (default): the platform's `detected_date` for this
        finding. Correct for 🔥 SLA-Breach (continuously-actively-exploited
        from day one) and for ⏰ Still in Triage / 📋 Full Snapshot
        (steady-state inventory).
      * ``"now"``: this run's wall clock. Correct for 🆕 Newly Above
        Threshold and 🔁 Re-emerged — the customer is being made aware of
        the NEW exploit signal by *this* report, not by the original
        detection (which may be weeks old for a CVE that only just crossed
        to weaponized). Round 4 multi-review caught the false-OVERDUE bug
        this introduces when "detected" is used for newly-aware-of rows.
    """
    cve_id = row.get("cve_id", "")
    kev_entry = kev_catalog.get(cve_id, {})

    cisa_date_added = kev_entry.get("cisa_dateAdded", "")
    detected_date = row.get("detected_date", "")
    cisa_remediation_due = kev_entry.get("cisa_remediation_due", "")

    dt_cisa = _parse_iso_date(cisa_date_added)
    dt_detected = _parse_iso_date(detected_date)

    # Per-section anchor: "detected" preserves the historical semantic
    # (customer was aware as soon as FS first observed the finding);
    # "now" is the right anchor for sections where the report itself is
    # the customer's first awareness moment (🆕 just-crossed-to-active,
    # 🔁 re-emergence-from-resolved).
    if awareness_anchor == "now":
        section_anchor: datetime | None = now
    else:
        section_anchor = dt_detected

    # max(cisa_dateAdded, section_anchor) — pick the later of the two.
    if dt_cisa is not None and section_anchor is not None:
        awareness_dt = max(dt_cisa, section_anchor)
    elif dt_cisa is not None:
        awareness_dt = dt_cisa
    elif section_anchor is not None:
        awareness_dt = section_anchor
    else:
        awareness_dt = None

    if awareness_dt is not None:
        cra_notification_at = _fmt_date(awareness_dt)
        deadline_dt = awareness_dt + timedelta(hours=24)
        cra_notification_deadline = _fmt_iso(deadline_dt)
        hours_until = (deadline_dt - now).total_seconds() / 3600.0

        if hours_until < 0:
            breach_status = "OVERDUE"
        elif hours_until <= 24:
            breach_status = "DUE_SOON"
        else:
            breach_status = "UPCOMING"
    else:
        cra_notification_at = ""
        cra_notification_deadline = ""
        hours_until = None
        breach_status = "UNKNOWN"

    return {
        "cra_notification_at": cra_notification_at,
        "cra_notification_deadline": cra_notification_deadline,
        "hours_until_cra_due": hours_until,
        "breach_status": breach_status,
        "cisa_remediation_due": cisa_remediation_due,
    }


def _derive_crossed_to(
    row: dict[str, Any],
    effective_threshold: set[str],
) -> str:
    """Return comma-joined sorted list of tiers the row triggers that are in threshold."""
    tiers = derive_tiers(row) & effective_threshold
    return ",".join(sorted(tiers))


# ---------------------------------------------------------------------------
# Row classification
# ---------------------------------------------------------------------------


_DROP = "_drop"


def _classify_row(
    row: dict[str, Any],
    *,
    stage1_crossed_cves: set[str],
    stage1_crossed_row_ids: set[str],
    effective_threshold: set[str],
    kev_sla_enabled: bool = True,
) -> str:
    """Return the section key this row belongs to (highest-priority match).

    Priority order: sla_breach > newly_above > re_emerged > still_in_triage
    > full_snapshot. Rows whose derived tier set has no intersection with
    `effective_threshold` and which did NOT cross this run are returned as
    ``_DROP`` so the caller can discard them — this is the client-side
    narrowing for the `wide-fetch` strategy (where Fetch A skips the
    server-side threshold filter because the tier set contains unfilterable
    tiers like ransomware/threat_actor).

    Crossing detection is two-layer:
      * `stage1_crossed_cves` — CVE-level, from /cves/updates (the platform's
        authoritative maturity-change feed). When the platform says CVE-X
        crossed, every customer finding for that CVE crossed simultaneously.
      * `stage1_crossed_row_ids` — row-level (per finding), from the
        snapshot-diff fallback for KEV/token additions. Only the specific
        finding that gained the signal counts as crossed.
    """
    status = str(row.get("status", "")).upper()
    cve_id = row.get("cve_id", "")
    finding_row_id = str(row.get("finding_row_id") or "")
    in_resolved = status in RESOLVED_STATUSES

    row_crossed = (
        cve_id in stage1_crossed_cves or finding_row_id in stage1_crossed_row_ids
    )

    # Client-side tier narrowing: rows that match no tier in the effective
    # threshold AND didn't cross are dropped. Crossing rows always pass
    # through because a crossing IS the signal that this row is now above
    # threshold (the threshold-aware sections below pick them up).
    row_tiers = derive_tiers(row)
    if not (row_tiers & effective_threshold) and not row_crossed:
        return _DROP

    # 1. sla_breach — KEV findings not yet resolved, only when kev in
    # threshold AND the operator hasn't disabled the SLA model via
    # `--kev-due-date-source=none` (in which case there's no breach clock
    # to compute and the section ships empty per F3).
    if kev_sla_enabled and "kev" in effective_threshold:
        if (row.get("inKev") or row.get("inVcKev")) and not in_resolved:
            return "sla_breach"

    # 2. newly_above — stage1 crossing, not yet resolved
    if row_crossed and not in_resolved:
        return "newly_above"

    # 3. re_emerged — stage1 crossing, currently resolved. Spec §5 line 91:
    # "findings previously resolved that gained a new exploit signal — re-
    # verify mitigation." The row was dismissed/mitigated (status ∈
    # RESOLVED_STATUSES) BEFORE this run; the crossing this run IS the new
    # signal that should make the operator reconsider the resolution
    # decision. We do not (and the spec does not ask us to) detect a
    # "resolved→active" status transition — that would require row-level
    # status history we don't persist.
    if row_crossed and in_resolved:
        return "re_emerged"

    # 4. still_in_triage — currently in triage (but not a stage1 crossing with a
    #    higher-priority section)
    if status == "IN_TRIAGE":
        return "still_in_triage"

    # 5. full_snapshot — everything else (above-threshold but not breached,
    # not newly-crossed, not in-triage; the steady-state above-threshold view)
    return "full_snapshot"


# ---------------------------------------------------------------------------
# Section builder functions
# ---------------------------------------------------------------------------


def _build_sla_breach(
    rows: list[dict[str, Any]],
    *,
    kev_catalog: dict[str, dict[str, str]],
    now: datetime,
) -> pd.DataFrame:
    """Build the sla_breach DataFrame with derived columns and sorted.

    Timing columns (breach_status / hours_until_cra_due /
    cra_notification_at / cra_notification_deadline /
    cisa_remediation_due) are already enriched on each row by
    assemble_sections so that 🆕/🔁/⏰/📋 inherit them too. kev_catalog
    and now are still accepted as kwargs for backward compat with
    callers that invoke this builder directly (e.g., tests).
    """
    output = []
    for row in rows:
        enriched = dict(row)
        # Defensive: re-enrich if the row didn't go through assemble_sections
        # (e.g., direct test invocations). The first call sets the keys; this
        # second call is a no-op when they're already populated.
        if "breach_status" not in enriched:
            enriched.update(
                _derive_sla_breach_columns(row, kev_catalog=kev_catalog, now=now)
            )
        enriched["primary_section"] = "sla_breach"
        output.append(enriched)

    if not output:
        return pd.DataFrame(
            columns=[
                "primary_section",
                "cra_notification_at",
                "cra_notification_deadline",
                "hours_until_cra_due",
                "breach_status",
                "cisa_remediation_due",
            ]
        )

    df = pd.DataFrame(output)

    # Sort: OVERDUE first, then DUE_SOON, UPCOMING, UNKNOWN last.
    # Within the same breach_status, sort by hours_until_cra_due ascending
    # (most negative = most overdue). UNKNOWN gets hours_until_cra_due=None,
    # so we use a secondary sort key that places them last.
    status_order = {"OVERDUE": 0, "DUE_SOON": 1, "UPCOMING": 2, "UNKNOWN": 3}
    df["_breach_rank"] = df["breach_status"].map(lambda s: status_order.get(s, 3))
    # Replace None with a large positive number so UNKNOWN sorts last by hours too.
    df["_hours_sort"] = df["hours_until_cra_due"].apply(
        lambda h: h if h is not None else float("inf")
    )
    df = df.sort_values(["_breach_rank", "_hours_sort"], ascending=[True, True])
    df = df.drop(columns=["_breach_rank", "_hours_sort"])
    return df.reset_index(drop=True)


def _build_newly_above(
    rows: list[dict[str, Any]],
    *,
    effective_threshold: set[str],
    crossing_sources: dict[str, str],
) -> pd.DataFrame:
    """Build the newly_above DataFrame with derived columns and sorted.

    Spec §6: crossing_source ∈ {"updates", "snapshot-diff"} per the
    provenance map (updates wins on overlap). crossed_from is the prior
    tier set the row was at — currently always implicitly "<below_threshold>"
    since these rows have, by definition, just crossed *into* the threshold;
    a future enhancement could compare against the prior signal set to
    record e.g. {weaponized}→{kev}.
    """
    output = []
    for row in rows:
        enriched = dict(row)
        enriched["crossed_to"] = _derive_crossed_to(row, effective_threshold)
        enriched["crossed_from"] = "<below_threshold>"
        # crossing_sources is keyed by cve_id (for "updates" entries) AND
        # by finding_row_id (for "snapshot-diff" entries). Check cve_id
        # first so "updates" wins on overlap.
        enriched["crossing_source"] = crossing_sources.get(
            row.get("cve_id", "")
        ) or crossing_sources.get(str(row.get("finding_row_id") or ""), "snapshot-diff")
        enriched["primary_section"] = "newly_above"
        output.append(enriched)

    if not output:
        return pd.DataFrame(
            columns=[
                "primary_section",
                "crossed_to",
                "crossed_from",
                "crossing_source",
            ]
        )

    df = pd.DataFrame(output)
    df["_sev_rank"] = df["severity"].apply(_severity_rank)
    df = df.sort_values(
        ["_sev_rank", "cvss_score", "epss_percentile"],
        ascending=[False, False, False],
    )
    df = df.drop(columns=["_sev_rank"])
    return df.reset_index(drop=True)


def _build_re_emerged(
    rows: list[dict[str, Any]],
    *,
    effective_threshold: set[str],
    crossing_sources: dict[str, str],
) -> pd.DataFrame:
    """Build the re_emerged DataFrame with derived columns and sorted."""
    output = []
    for row in rows:
        enriched = dict(row)
        enriched["previous_resolution"] = str(row.get("status", ""))
        enriched["crossed_to"] = _derive_crossed_to(row, effective_threshold)
        enriched["crossed_from"] = "<below_threshold>"
        # crossing_sources is keyed by cve_id (for "updates" entries) AND
        # by finding_row_id (for "snapshot-diff" entries). Check cve_id
        # first so "updates" wins on overlap.
        enriched["crossing_source"] = crossing_sources.get(
            row.get("cve_id", "")
        ) or crossing_sources.get(str(row.get("finding_row_id") or ""), "snapshot-diff")
        enriched["primary_section"] = "re_emerged"
        output.append(enriched)

    if not output:
        return pd.DataFrame(
            columns=[
                "primary_section",
                "previous_resolution",
                "crossed_to",
                "crossed_from",
                "crossing_source",
            ]
        )

    df = pd.DataFrame(output)
    df["_sev_rank"] = df["severity"].apply(_severity_rank)
    df = df.sort_values(
        ["_sev_rank", "cvss_score"],
        ascending=[False, False],
    )
    df = df.drop(columns=["_sev_rank"])
    return df.reset_index(drop=True)


def _build_still_in_triage(
    rows: list[dict[str, Any]],
    *,
    now: datetime,
) -> pd.DataFrame:
    """Build the still_in_triage DataFrame with triage_age_days and sorted."""
    output = []
    for row in rows:
        enriched = dict(row)
        detected_date = row.get("detected_date", "")
        dt_detected = _parse_iso_date(detected_date)
        if dt_detected is not None:
            triage_age_days = int((now - dt_detected).total_seconds() / 86400)
        else:
            triage_age_days = 0
        enriched["triage_age_days"] = triage_age_days
        enriched["primary_section"] = "still_in_triage"
        output.append(enriched)

    if not output:
        return pd.DataFrame(columns=["primary_section", "triage_age_days"])

    df = pd.DataFrame(output)
    df = df.sort_values("triage_age_days", ascending=False)
    return df.reset_index(drop=True)


def _build_full_snapshot(rows: list[dict[str, Any]]) -> pd.DataFrame:
    """Build the full_snapshot DataFrame with primary_section and sorted."""
    if not rows:
        return pd.DataFrame(columns=["primary_section"])

    output = []
    for row in rows:
        enriched = dict(row)
        enriched["primary_section"] = "full_snapshot"
        output.append(enriched)

    df = pd.DataFrame(output)
    df["_sev_rank"] = df["severity"].apply(_severity_rank)
    df = df.sort_values(
        ["_sev_rank", "cvss_score"],
        ascending=[False, False],
    )
    df = df.drop(columns=["_sev_rank"])
    return df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Public assembler
# ---------------------------------------------------------------------------


def assemble_sections(
    merged_rows: list[dict[str, Any]],
    *,
    stage1_crossed_cves: set[str],
    stage1_crossed_row_ids: set[str] | None = None,
    crossing_sources: dict[str, str] | None = None,
    effective_threshold: set[str],
    kev_catalog: dict[str, dict[str, str]],
    kev_sla_enabled: bool = True,
    config: Config,
) -> dict[str, pd.DataFrame]:
    """Assemble the 5 CRA Compliance morning-queue sections.

    Args:
        merged_rows: rows from Fetch A + Fetch B (post-_merge_a_and_b),
            each as a dict in the shape produced by _row_from_record
            plus the original API record keys (inKev, inVcKev, status, etc.)
        stage1_crossed_cves: CVE IDs that crossed the threshold this run
            (maturity from /cves/updates ∪ KEV/token from snapshot-diff)
        effective_threshold: tiers active for this run (after wide-fetch
            / drop-tier resolution in build_threshold_filter)
        kev_catalog: {cve_id: {"cisa_dateAdded": str, "cisa_remediation_due": str}}
            from get_kev_due_dates
        config: Config; consulted for include/exclude_status,
            with_triage_age, snapshot_diff

    Returns:
        {section_key: DataFrame, ...} for all 5 sections. Empty sections
        are present as empty DataFrames (not omitted). Each section's
        DataFrame includes a primary_section column = the section key
        the row was assigned to (for CSV export). Per-section derived
        columns per spec §6.

    Dedup model (spec §6 line 674):
      * Queue sections (sla_breach > newly_above > re_emerged > still_in_triage)
        are *mutually exclusive* — a row that qualifies for multiple queue
        sections appears only in the highest-priority one.
      * 📋 Full Snapshot is *NOT part of the queue dedup chain*. It contains
        every above-threshold row (A ∪ B) as an audit appendix — so a row
        that lands in a queue section ALSO appears in 📋. This is the
        "queue highlight + complete inventory" model the morning briefing
        delivers.
    """
    now = _utcnow()
    crossing_sources = crossing_sources or {}
    stage1_crossed_row_ids = stage1_crossed_row_ids or set()

    # Classify each row.  Queue sections (sla_breach/newly_above/re_emerged/
    # still_in_triage) are deduped — a row gets its highest-priority match
    # only (spec lines 73-76). 📋 Full Snapshot is *separate* from the dedup
    # chain: spec line 674 says it's "all of (A ∪ B)" with no further
    # status filtering — queue rows appear in BOTH their queue section AND
    # in 📋. Rows below threshold and not crossed are dropped entirely.
    buckets: dict[str, list[dict[str, Any]]] = {key: [] for key in SECTION_KEYS}
    full_snapshot_rows: list[dict[str, Any]] = []
    dropped = 0

    # Per-section awareness-anchor rule (R4-1 / multi-review M1-1, M3-1):
    # 🆕 / 🔁 anchor on `now` because the customer becomes aware via this
    # report; their `detected_date` is the original-detection moment and
    # using it would false-OVERDUE a CVE that JUST crossed weaponized.
    # 🔥 / ⏰ / 📋 keep the historical "detected" anchor — those represent
    # continuously-known active findings where awareness started at first
    # detection.
    _ANCHOR_BY_SECTION: dict[str, str] = {
        "sla_breach": "detected",
        "newly_above": "now",
        "re_emerged": "now",
        "still_in_triage": "detected",
        "full_snapshot": "detected",
    }

    def _enrich(row: dict[str, Any], anchor: str) -> dict[str, Any]:
        """Return a shallow copy of `row` with timing columns derived
        using `anchor`. Shallow copy prevents the per-section enrichment
        from cross-contaminating 📋's "detected"-anchored copy."""
        copy = dict(row)
        copy.update(
            _derive_sla_breach_columns(
                copy,
                kev_catalog=kev_catalog,
                now=now,
                awareness_anchor=anchor,
            )
        )
        return copy

    for row in merged_rows:
        section = _classify_row(
            row,
            stage1_crossed_cves=stage1_crossed_cves,
            stage1_crossed_row_ids=stage1_crossed_row_ids,
            effective_threshold=effective_threshold,
            kev_sla_enabled=kev_sla_enabled,
        )
        if section == _DROP:
            dropped += 1
            continue
        # 📋 always gets the steady-state "detected" anchor, regardless of
        # whether the row also lives in a queue section (the queue copy
        # uses its own section-specific anchor — see _ANCHOR_BY_SECTION).
        full_snapshot_rows.append(_enrich(row, "detected"))
        # The queue sections are mutually exclusive; the leftover catch-all
        # ("full_snapshot" from _classify_row) only contributes to 📋, not
        # to any queue section.
        if section != "full_snapshot":
            anchor = _ANCHOR_BY_SECTION.get(section, "detected")
            buckets[section].append(_enrich(row, anchor))

    logger.info(
        "assemble_sections: sla_breach=%d newly_above=%d re_emerged=%d "
        "still_in_triage=%d full_snapshot=%d dropped=%d",
        len(buckets["sla_breach"]),
        len(buckets["newly_above"]),
        len(buckets["re_emerged"]),
        len(buckets["still_in_triage"]),
        len(full_snapshot_rows),
        dropped,
    )

    return {
        "sla_breach": _build_sla_breach(
            buckets["sla_breach"],
            kev_catalog=kev_catalog,
            now=now,
        ),
        "newly_above": _build_newly_above(
            buckets["newly_above"],
            effective_threshold=effective_threshold,
            crossing_sources=crossing_sources,
        ),
        "re_emerged": _build_re_emerged(
            buckets["re_emerged"],
            effective_threshold=effective_threshold,
            crossing_sources=crossing_sources,
        ),
        "still_in_triage": _build_still_in_triage(
            buckets["still_in_triage"],
            now=now,
        ),
        "full_snapshot": _build_full_snapshot(full_snapshot_rows),
    }
