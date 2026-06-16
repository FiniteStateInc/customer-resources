"""Scan queue router — live view of recent scans.

Fetches the most recent scans (by created:desc) from the Finite State API,
groups them by project version, and renders a live queue panel.
"""

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse

from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.routers._scans_client import (
    TERMINAL_STATUSES,
    _parse_iso,
    fetch_scans,
)
from fs_report.web.shell_context import build_shell_context
from fs_report.web.state import WebAppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["queue"])
# Unprefixed router for the standalone /queue PAGE. Kept in this module so a
# single `fetch_scans` mock covers both the page and the refresh fragment.
page_router = APIRouter(tags=["pages"])

# Degraded-state copy, shared across the three queue routes so the wording
# stays in sync.
_ERR_RATE_LIMITED = "Rate-limited — retrying shortly"
_ERR_UNREACHABLE = "Could not reach API"

# Active-window fetch depth. When the fetch exhausts this many FULL pages it
# sets ScanFetchResult.capped, meaning the queue is the "recent active window"
# (not the full history) — surfaced so the page shows a subtle affordance
# instead of implying completeness. (Use result.capped, not a page-count
# heuristic: a partial or early-stopped final page is complete, not capped.)
_MAX_QUEUE_PAGES = 6


def _total_scans(queue: dict[str, Any] | None) -> int:
    """Total scan count across all groups (for the panel meta line)."""
    if not queue:
        return 0
    return sum(len(g["scans"]) for g in queue.get("groups", []))


def _force_requested(request: Request) -> bool:
    """True if the request asks to bypass the fetch memo (manual Refresh).

    Accepts the common truthy query encodings so a hand-typed or bookmarked
    ``?force=true`` behaves the same as the HTMX button's ``?force=1``.
    """
    return request.query_params.get("force", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


_TYPE_DISPLAY = {"VULNERABILITY_ANALYSIS": "REACHABILITY"}
# Left-to-right completion priority (B8 #2): binary SCA → config → reachability
# → binary SAST → bandit (SOURCE_SCA) → SBOM import. SBOM_IMPORT gets an explicit
# slot rather than the unknown-type 99 fallback so it orders predictably.
_TYPE_ORDER = {
    "SCA": 0,
    "CONFIG": 1,
    "VULNERABILITY_ANALYSIS": 2,
    "SAST": 3,
    "SOURCE_SCA": 4,
    "SBOM_IMPORT": 5,
}
# Scan-type → CSS slug (B8 #2 color-by-type). Drives the `qt-<slug>` class on
# queue dots/chips; the `--scan-<slug>` token supplies the hue (see tokens.css).
# Unknown types fall back to the neutral `other` hue.
_TYPE_SLUG = {
    "SCA": "sca",
    "CONFIG": "config",
    "VULNERABILITY_ANALYSIS": "vuln",
    "SAST": "sast",
    "SOURCE_SCA": "source-sca",
    "SBOM_IMPORT": "sbom",
}


def _format_wait(minutes: float) -> str:
    if minutes < 1:
        return "< 1m"
    if minutes < 60:
        return f"{int(minutes)}m"
    hours = int(minutes // 60)
    remaining = int(minutes % 60)
    if remaining == 0:
        return f"{hours}h"
    return f"{hours}h {remaining}m"


def _extract_nested(obj: Any, field: str, fallback: str = "Unknown") -> str:
    if isinstance(obj, dict):
        return str(obj.get(field, fallback))
    return str(obj) if obj else fallback


def _build_scan_entry(scan: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Build a scan entry dict with group metadata."""
    status = scan.get("status", "")
    created = _parse_iso(scan.get("created"))
    wait_minutes = (now - created).total_seconds() / 60 if created else 0

    pv = scan.get("projectVersion")
    pv_id = _extract_nested(pv, "id", "")
    version_name = _extract_nested(pv, "version", "")

    project = scan.get("project")
    project_name = _extract_nested(project, "name", "Unknown")
    project_id = _extract_nested(project, "id", "")

    group_key = pv_id if pv_id else f"_orphan_{scan.get('id', '')}"

    scan_type = scan.get("type", "Unknown")
    likely_stuck = (
        status == "STARTED" and scan_type in ("SCA", "SOURCE_SCA") and wait_minutes > 60
    )
    is_done = status in TERMINAL_STATUSES
    is_error = status == "ERROR"
    display_type = _TYPE_DISPLAY.get(scan_type, scan_type)
    type_order = _TYPE_ORDER.get(scan_type, 99)
    type_slug = _TYPE_SLUG.get(scan_type, "other")

    return {
        "id": scan.get("id", ""),
        "type": display_type,
        "type_order": type_order,
        "type_slug": type_slug,
        "status": status,
        "wait_minutes": wait_minutes,
        "wait_display": _format_wait(wait_minutes),
        "created": scan.get("created", ""),
        "likely_stuck": likely_stuck,
        "is_done": is_done,
        "is_error": is_error,
        "group_key": group_key,
        "project_name": project_name,
        "project_id": project_id,
        "version_name": version_name,
        "created_by": scan.get("createdBy", ""),
    }


def _group_scans(
    all_scans: list[dict[str, Any]],
    now: datetime,
) -> dict[str, Any]:
    """Group scans by project version and compute metrics."""
    version_groups: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()

    for scan in all_scans:
        entry = _build_scan_entry(scan, now)
        scan_id = str(entry["id"])
        if scan_id in seen_ids:
            continue
        seen_ids.add(scan_id)

        group_key = entry["group_key"]
        if group_key not in version_groups:
            version_groups[group_key] = {
                "project_name": entry["project_name"],
                "project_id": entry["project_id"],
                "version_name": entry["version_name"],
                "version_id": group_key if not group_key.startswith("_orphan_") else "",
                "oldest_wait_minutes": 0.0,
                "oldest_wait_display": "",
                "scans": [],
                "initial_count": 0,
                "started_count": 0,
                "completed_count": 0,
                "error_count": 0,
                "has_stuck": False,
                "created_by": set(),
            }

        group = version_groups[group_key]
        group["scans"].append(entry)
        if entry["created_by"]:
            group["created_by"].add(entry["created_by"])

        status = entry["status"]
        if status == "INITIAL":
            group["initial_count"] += 1
        elif status == "STARTED":
            group["started_count"] += 1
        elif entry["is_error"]:
            group["error_count"] += 1
        elif entry["is_done"]:
            group["completed_count"] += 1

        if entry["likely_stuck"]:
            group["has_stuck"] = True
        if entry["wait_minutes"] > group["oldest_wait_minutes"]:
            group["oldest_wait_minutes"] = entry["wait_minutes"]
            group["oldest_wait_display"] = _format_wait(entry["wait_minutes"])

    groups_queued = 0
    groups_processing = 0
    oldest_active_wait: float = 0

    two_weeks = 14 * 24 * 60
    for group in version_groups.values():
        group["scans"] = [
            s
            for s in group["scans"]
            if not (s["likely_stuck"] and s["wait_minutes"] > two_weeks)
        ]
        group["has_stuck"] = any(s["likely_stuck"] for s in group["scans"])
        group["has_error"] = any(s["is_error"] for s in group["scans"])
        group["all_done"] = (
            all(s["is_done"] for s in group["scans"]) if group["scans"] else True
        )
        # A group is "running" only when it has a non-stuck, non-terminal
        # STARTED scan — the same population total_processing counts below, so
        # the Processing KPI and the Processing filter chip never disagree.
        group["has_running"] = any(
            s["status"] == "STARTED" and not s["likely_stuck"] and not s["is_done"]
            for s in group["scans"]
        )
        # Order by completion priority alone (B8 #2) — NOT (is_done, type_order):
        # keying on is_done made a scan jump to the end the moment it finished,
        # so the row reshuffled on every poll. type_order-only keeps each scan in
        # its lane; Python's stable sort preserves arrival order within a type.
        group["scans"].sort(key=lambda s: s["type_order"])
        group["created_by"] = sorted(group["created_by"])

        # Recompute the displayed wait from the scans that REMAIN after the
        # two-week filter, so the wait shown always belongs to a rendered scan.
        if group["scans"]:
            group_oldest = max(s["wait_minutes"] for s in group["scans"])
            group["oldest_wait_minutes"] = group_oldest
            group["oldest_wait_display"] = _format_wait(group_oldest)
        else:
            group["oldest_wait_minutes"] = 0.0
            group["oldest_wait_display"] = ""

        if not group["all_done"]:
            non_stuck = [
                s for s in group["scans"] if not s["likely_stuck"] and not s["is_done"]
            ]
            if non_stuck:
                groups_queued += 1
            if group["has_running"]:
                groups_processing += 1
            # "Oldest" reflects the worst wait across ALL active groups,
            # including stuck ones — otherwise an all-stuck backlog would show
            # "—" while the rows below still display long waits.
            if group["oldest_wait_minutes"] > oldest_active_wait:
                oldest_active_wait = group["oldest_wait_minutes"]

    groups = sorted(
        (g for g in version_groups.values() if g["scans"]),
        key=lambda g: (g["all_done"], g["oldest_wait_minutes"]),
    )

    oldest_wait_display = (
        _format_wait(oldest_active_wait) if oldest_active_wait > 0 else ""
    )

    total_stuck = sum(
        1 for g in version_groups.values() if g["scans"] and g["has_stuck"]
    )

    return {
        "groups": groups,
        "total_queued": groups_queued,
        "total_processing": groups_processing,
        "oldest_wait": oldest_wait_display,
        "total_stuck": total_stuck,
    }


@router.get("/queue")
async def scan_queue(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> object:
    """Return an HTML fragment with the current scan queue status."""
    templates = request.app.state.templates
    now = datetime.now(UTC)

    # A manual Refresh (?force=1) bypasses the fetch memo for live data;
    # the auto-poll omits it to stay within the idle request budget.
    force = _force_requested(request)
    result = await fetch_scans(
        state,
        since=None,
        early_stop_terminal=True,
        max_pages=_MAX_QUEUE_PAGES,
        force=force,
    )

    if result.status == "unconfigured":
        return templates.TemplateResponse(
            request,
            "components/_scan_queue.html",
            {"connected": False, "error": None, "queue": None},
        )
    if result.status == "rate_limited":
        return templates.TemplateResponse(
            request,
            "components/_scan_queue.html",
            {"connected": True, "error": _ERR_RATE_LIMITED, "queue": None},
        )
    if result.status == "unreachable":
        return templates.TemplateResponse(
            request,
            "components/_scan_queue.html",
            {"connected": True, "error": _ERR_UNREACHABLE, "queue": None},
        )

    queue = _group_scans(result.scans, now)
    return templates.TemplateResponse(
        request,
        "components/_scan_queue.html",
        {
            "connected": True,
            "error": None,
            "queue": queue,
            "platform_domain": state.domain,
        },
    )


@router.get("/queue/full")
async def scan_queue_full(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> object:
    """Return the full Scan-Queue body fragment (all groups), for HTMX swaps."""
    templates = request.app.state.templates
    now = datetime.now(UTC)

    # A manual Refresh (?force=1) bypasses the fetch memo for live data;
    # the 180 s auto-poll omits it to stay within the idle request budget.
    force = _force_requested(request)
    result = await fetch_scans(
        state,
        since=None,
        early_stop_terminal=True,
        max_pages=_MAX_QUEUE_PAGES,
        force=force,
    )

    def _render(
        connected: bool, error: str | None, queue: dict[str, Any] | None
    ) -> object:
        return templates.TemplateResponse(
            request,
            "components/_scan_queue_full.html",
            {
                "connected": connected,
                "error": error,
                "queue": queue,
                "total_scans": _total_scans(queue),
                "capped": result.capped and queue is not None,
            },
        )

    if result.status == "unconfigured":
        return _render(connected=False, error=None, queue=None)
    if result.status == "rate_limited":
        return _render(connected=True, error=_ERR_RATE_LIMITED, queue=None)
    if result.status == "unreachable":
        return _render(connected=True, error=_ERR_UNREACHABLE, queue=None)

    queue = _group_scans(result.scans, now)
    return _render(connected=True, error=None, queue=queue)


@page_router.get("/queue")
async def queue_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the standalone Scan Queue page (rides on the shared shell)."""
    if not state.has_config:
        return RedirectResponse(url="/setup")

    templates = request.app.state.templates
    now = datetime.now(UTC)

    result = await fetch_scans(
        state, since=None, early_stop_terminal=True, max_pages=_MAX_QUEUE_PAGES
    )

    if result.status == "unconfigured":
        # Defensive: should be caught by the has_config guard above. Redirect
        # before building the shell context so the failure path skips the
        # bundled-recipe load.
        return RedirectResponse(url="/setup")

    # Shared shell contract + page-specific extras (state mirrors the dashboard
    # route so any future shell template can read it on /queue too).
    ctx = build_shell_context(state, nonce, crumb="Scan Queue", active_view="queue")
    ctx["state"] = state
    ctx["capped"] = False

    if result.status == "rate_limited":
        ctx.update(
            {
                "connected": True,
                "error": _ERR_RATE_LIMITED,
                "queue": None,
                "total_scans": 0,
            }
        )
    elif result.status == "unreachable":
        ctx.update(
            {
                "connected": True,
                "error": _ERR_UNREACHABLE,
                "queue": None,
                "total_scans": 0,
            }
        )
    else:
        queue = _group_scans(result.scans, now)
        ctx.update(
            {
                "connected": True,
                "error": None,
                "queue": queue,
                "total_scans": _total_scans(queue),
                "capped": result.capped,
            }
        )

    return templates.TemplateResponse(request, "pages/queue.html", ctx)
