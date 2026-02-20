"""Scan queue router — live view of recent scans.

Fetches the most recent scans (by created:desc) from the Finite State API,
groups them by project version, and renders a live queue panel.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request

from fs_report.web.dependencies import get_state
from fs_report.web.state import WebAppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["queue"])

_TERMINAL_STATUSES = frozenset({"COMPLETED", "ERROR", "NOT_APPLICABLE"})
_PAGES = 5
_PAGE_SIZE = 100

_TYPE_DISPLAY = {"VULNERABILITY_ANALYSIS": "REACHABILITY"}
_TYPE_ORDER = {
    "SCA": 0,
    "SOURCE_SCA": 0,
    "SAST": 1,
    "CONFIG": 2,
    "VULNERABILITY_ANALYSIS": 3,
}


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


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
    is_done = status in _TERMINAL_STATUSES
    is_error = status == "ERROR"
    display_type = _TYPE_DISPLAY.get(scan_type, scan_type)
    type_order = _TYPE_ORDER.get(scan_type, 99)

    return {
        "id": scan.get("id", ""),
        "type": display_type,
        "type_order": type_order,
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
        group["all_done"] = (
            all(s["is_done"] for s in group["scans"]) if group["scans"] else True
        )
        group["scans"].sort(key=lambda s: (s["is_done"], s["type_order"]))
        group["created_by"] = sorted(group["created_by"])

        if not group["all_done"]:
            non_stuck = [
                s for s in group["scans"] if not s["likely_stuck"] and not s["is_done"]
            ]
            if non_stuck:
                groups_queued += 1
                if any(s["status"] == "STARTED" for s in non_stuck):
                    groups_processing += 1
                group_oldest = max(s["wait_minutes"] for s in non_stuck)
                if group_oldest > oldest_active_wait:
                    oldest_active_wait = group_oldest

    groups = sorted(
        (g for g in version_groups.values() if g["scans"]),
        key=lambda g: (g["all_done"], g["oldest_wait_minutes"]),
    )

    oldest_wait_display = (
        _format_wait(oldest_active_wait) if oldest_active_wait > 0 else ""
    )

    return {
        "groups": groups,
        "total_queued": groups_queued,
        "total_processing": groups_processing,
        "oldest_wait": oldest_wait_display,
    }


def _parse_scan_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("items") or data.get("scans") or []
    return []


@router.get("/queue")
async def scan_queue(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> object:
    """Return an HTML fragment with the current scan queue status."""
    state.reload()
    templates = request.app.state.templates
    now = datetime.now(UTC)

    if not state.token or not state.domain:
        return templates.TemplateResponse(
            "components/_scan_queue.html",
            {
                "request": request,
                "connected": False,
                "error": None,
                "queue": None,
            },
        )

    base_url = f"https://{state.domain}/api/public/v0/scans"
    headers = {"X-Authorization": state.token}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            page_reqs = [
                client.get(
                    base_url,
                    headers=headers,
                    params={
                        "sort": "created:desc",
                        "limit": str(_PAGE_SIZE),
                        "offset": str(i * _PAGE_SIZE),
                    },
                )
                for i in range(_PAGES)
            ]
            results = await asyncio.gather(*page_reqs, return_exceptions=True)

        all_scans: list[dict[str, Any]] = []
        any_success = False
        last_error = ""
        for resp in results:
            if isinstance(resp, BaseException):
                last_error = str(resp)
                continue
            if resp.status_code != 200:
                last_error = f"API returned {resp.status_code}"
                continue
            any_success = True
            all_scans.extend(_parse_scan_list(resp.json()))

        if not any_success:
            logger.warning("Queue fetch: all pages failed, last: %s", last_error)
            return templates.TemplateResponse(
                "components/_scan_queue.html",
                {
                    "request": request,
                    "connected": True,
                    "error": last_error or "API error",
                    "queue": None,
                },
            )

        queue = _group_scans(all_scans, now)

        return templates.TemplateResponse(
            "components/_scan_queue.html",
            {
                "request": request,
                "connected": True,
                "error": None,
                "queue": queue,
                "platform_domain": state.domain,
            },
        )
    except Exception as e:
        logger.warning("Queue fetch error: %s", e)
        return templates.TemplateResponse(
            "components/_scan_queue.html",
            {
                "request": request,
                "connected": True,
                "error": "Could not reach API",
                "queue": None,
            },
        )
