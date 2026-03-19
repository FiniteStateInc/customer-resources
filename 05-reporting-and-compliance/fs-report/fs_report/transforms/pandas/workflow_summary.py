"""
Pandas transform for the Workflow Summary report.

Renders a journal of steps from a forge workflow run. Each journal entry
has ``step``, ``timestamp``, and ``data`` fields. The transform classifies
steps, extracts KPIs, and builds a timeline.

Returns a dict with:
- ``main``: flat DataFrame for CSV/table fallback
- ``kpis``: aggregate counts (triaged, vex, tickets, notifications, etc.)
- ``timeline``: ordered list of steps with inter-step durations
- ``steps``: per-step detail dicts with classification
- ``workflow_meta``: start/end/duration metadata
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# ── Known step type registry (prefix-matched) ───────────────────────────

_STEP_PREFIXES: list[tuple[str, str]] = [
    ("triage", "triage"),
    ("tickets", "tickets"),
    ("notification", "notification"),
    ("recipe_run", "recipe_run"),
]


def _classify_step(step_name: str) -> tuple[str, bool]:
    """Return (step_type, known) based on prefix matching."""
    lower = step_name.lower()
    for prefix, step_type in _STEP_PREFIXES:
        if lower.startswith(prefix):
            return step_type, True
    return "unknown", False


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely convert a value to int."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _parse_timestamp(ts: Any) -> datetime | None:
    """Parse an ISO-format timestamp string to datetime."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        # Handle both Z-suffix and +00:00
        cleaned = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


def _extract_kpis_from_step(step_type: str, data: Any) -> dict[str, int]:
    """Extract KPI contributions from a single step's data."""
    kpis: dict[str, int] = {}
    if not isinstance(data, dict):
        return kpis

    if step_type == "triage":
        # Look in nested structures for triage counts
        triage_summary = data.get("triage_summary", data)
        if isinstance(triage_summary, dict):
            kpis["total_findings_triaged"] = _safe_int(
                triage_summary.get("total_recommendations", 0)
            )
        change_report = data.get("change_report", {})
        if isinstance(change_report, dict):
            kpis["new_recommendations"] = _safe_int(
                change_report.get("new_recommendations", 0)
            )
        vex_applied = data.get("vex_applied", {})
        if isinstance(vex_applied, dict):
            kpis["vex_applied"] = _safe_int(vex_applied.get("applied_count", 0))

    elif step_type == "tickets":
        # Count tickets created
        tickets = data.get("tickets_created", data.get("tickets", []))
        if isinstance(tickets, list):
            kpis["tickets_created"] = len(tickets)
        elif isinstance(tickets, int):
            kpis["tickets_created"] = tickets

    elif step_type == "notification":
        success = data.get("success", False)
        if success:
            kpis["notifications_sent"] = 1

    return kpis


def _build_step_detail(step_type: str, data: Any) -> Any:
    """Parse step data into a structured detail dict."""
    if not isinstance(data, dict):
        return data
    if step_type == "triage":
        return {
            "triage_summary": data.get("triage_summary", {}),
            "change_report": data.get("change_report", {}),
            "vex_applied": data.get("vex_applied", {}),
        }
    if step_type == "tickets":
        raw = data.get("tickets_created", data.get("tickets", []))
        # Normalize: may be int (count), list (ticket objects), or missing
        if isinstance(raw, list):
            tickets_list = raw
        else:
            tickets_list = []
        return {
            "tickets_created": tickets_list,
            "tickets_count": (
                len(tickets_list)
                if tickets_list
                else (raw if isinstance(raw, int) else 0)
            ),
        }
    if step_type == "notification":
        return {
            "success": data.get("success", False),
            "channel": data.get("channel", ""),
            "message": data.get("message", ""),
            "subject": data.get("subject", ""),
            "recipients": data.get("recipients", []),
            "body_preview": data.get("body_preview", ""),
        }
    if step_type == "recipe_run":
        output_files = data.get("output_files", [])
        return {
            "recipe": data.get("recipe", ""),
            "output_files": output_files if isinstance(output_files, list) else [],
        }
    return data


def workflow_summary_transform(
    data: pd.DataFrame | list,
    config: Any = None,
    additional_data: dict | None = None,
) -> dict[str, Any]:
    """Transform a workflow journal into a structured summary."""
    # Convert to list of dicts
    if isinstance(data, pd.DataFrame):
        if data.empty:
            records: list[dict[str, Any]] = []
        else:
            records = data.to_dict("records")  # type: ignore[assignment]
    elif isinstance(data, list):
        records = data
    else:
        records = []  # type: ignore[unreachable]

    # Initialize KPI accumulators
    kpis: dict[str, int | float] = {
        "total_findings_triaged": 0,
        "new_recommendations": 0,
        "vex_applied": 0,
        "tickets_created": 0,
        "notifications_sent": 0,
        "total_steps": len(records),
        "total_duration_sec": 0,
    }

    steps: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    timestamps: list[datetime] = []

    prev_ts: datetime | None = None

    for i, record in enumerate(records):
        step_name = str(record.get("step", f"step_{i}"))
        label = record.get("label", "") or ""
        ts_raw = record.get("timestamp", "")
        step_data = record.get("data", {})

        step_type, known = _classify_step(step_name)

        # Parse timestamp
        ts = _parse_timestamp(ts_raw)
        if ts is not None:
            timestamps.append(ts)

        # Duration from previous step
        duration_from_prev = 0.0
        if ts is not None and prev_ts is not None:
            duration_from_prev = (ts - prev_ts).total_seconds()
        prev_ts = ts if ts is not None else prev_ts

        # Extract KPIs
        step_kpis = _extract_kpis_from_step(step_type, step_data)
        for k, v in step_kpis.items():
            kpis[k] = kpis.get(k, 0) + v

        # Build detail
        detail = _build_step_detail(step_type, step_data)

        steps.append(
            {
                "step": step_name,
                "label": label,
                "timestamp": ts_raw,
                "step_type": step_type,
                "known": known,
                "detail": detail,
                "raw_data": step_data,
            }
        )

        timeline.append(
            {
                "step": step_name,
                "label": label,
                "timestamp": ts_raw,
                "duration_from_prev_sec": duration_from_prev,
                "index": i,
            }
        )

    # Workflow meta
    start_time = ""
    end_time = ""
    total_duration_sec = 0.0
    if timestamps:
        start_time = min(timestamps).isoformat()
        end_time = max(timestamps).isoformat()
        total_duration_sec = (max(timestamps) - min(timestamps)).total_seconds()
    kpis["total_duration_sec"] = total_duration_sec

    workflow_meta = {
        "start_time": start_time,
        "end_time": end_time,
        "total_duration_sec": total_duration_sec,
        "step_count": len(records),
    }

    # Build flat main DataFrame for CSV fallback
    main_rows = []
    for i, record in enumerate(records):
        step_name = str(record.get("step", f"step_{i}"))
        ts_raw = record.get("timestamp", "")
        step_type, _ = _classify_step(step_name)
        tl = timeline[i] if i < len(timeline) else {}
        main_rows.append(
            {
                "step": step_name,
                "timestamp": ts_raw,
                "duration_sec": tl.get("duration_from_prev_sec", 0),
                "status": "completed",
                "headline": step_name,
            }
        )
    main_df = pd.DataFrame(
        main_rows,
        columns=["step", "timestamp", "duration_sec", "status", "headline"],
    )

    return {
        "main": main_df,
        "kpis": kpis,
        "timeline": timeline,
        "steps": steps,
        "workflow_meta": workflow_meta,
    }
