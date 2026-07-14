"""Tracker (Jira) ticket-creation router — serve-side ``/api/tracker/tickets``.

The report-page "🎫 Jira" buttons POST here (instead of the dumb proxy) so the
create goes through retry-bearing Python that speaks Customer API v0.3.0's routed,
per-project-version contract (CVE-string findings + vc_id components). Mirrors the
VEX apply-file endpoint (``uploads.py``): creds come from ``state`` (never the
body), validation returns ``{"error": ...}`` with a 400, and the helper is imported
lazily so tests can patch it at its source module.

CSRF is automatic — the route is ``/api/...`` (not exempt), so the method-gated
``CSRFMiddleware`` requires the ``X-FS-Session`` nonce on the POST.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from fs_report.web.dependencies import get_state
from fs_report.web.state import WebAppState

logger = logging.getLogger(__name__)

router = APIRouter()

_VALID_ENDPOINTS = {"findings", "components"}
_VALID_MODES = {
    "SINGLE_FINDING",
    "ONE_PER_FINDING",
    "ONE_FOR_ALL_FINDINGS",
    "SINGLE_COMPONENT",
    "ONE_PER_COMPONENT",
    "ONE_FOR_ALL_COMPONENTS",
}


@router.post("/api/tracker/tickets")
async def create_tracker_tickets(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Create tracker tickets for the selected findings/components.

    Body: ``{endpoint, mode, items[], ticket_name?, ticket_summary?, priority?,
    project_key, type?}`` where each ``item`` carries its own
    ``project_version_id``, CVE ``finding_ids``, and ``component {id?, name?,
    version?}``. Returns the per-version summary
    (``{status, created, failed, warnings}``) with HTTP 200 when ≥1 ticket was
    created, 502 when none were, and 400 for invalid requests.
    """
    try:
        body = await request.json()
    except Exception:
        try:
            body = dict(await request.form())
        except Exception:
            body = {}

    endpoint = body.get("endpoint")
    if endpoint not in _VALID_ENDPOINTS:
        return JSONResponse(
            {"error": "endpoint must be 'findings' or 'components'"},
            status_code=400,
        )

    mode = body.get("mode")
    if mode not in _VALID_MODES:
        return JSONResponse({"error": f"unknown mode: {mode!r}"}, status_code=400)

    items = body.get("items")
    if not isinstance(items, list) or not items:
        return JSONResponse(
            {"error": "items must be a non-empty list"}, status_code=400
        )
    for it in items:
        if (
            not isinstance(it, dict)
            or not str(it.get("project_version_id") or "").strip()
        ):
            return JSONResponse(
                {"error": "each item requires a project_version_id"},
                status_code=400,
            )
        # Light type validation so malformed payloads fail as a deterministic
        # 400 here rather than as an opaque upstream 500/502 later.
        if "finding_ids" in it and not isinstance(it["finding_ids"], list):
            return JSONResponse(
                {"error": "item finding_ids must be a list"}, status_code=400
            )
        if "component" in it and not isinstance(it["component"], dict):
            return JSONResponse(
                {"error": "item component must be an object"}, status_code=400
            )

    # Mode invariant: a SINGLE_* selection must carry exactly one item (the
    # client only ever sends one; reject scripted multi-item SINGLE payloads
    # that would otherwise fan out per version).
    if mode in ("SINGLE_FINDING", "SINGLE_COMPONENT") and len(items) != 1:
        return JSONResponse(
            {"error": f"{mode} requires exactly one item"}, status_code=400
        )

    # A findings ticket with no CVE findings anywhere is meaningless — reject it
    # rather than POST an empty findings list (parity with the components
    # endpoint's all-unresolvable guard in the helper).
    if endpoint == "findings" and not any(
        (it.get("finding_ids") or []) for it in items
    ):
        return JSONResponse(
            {"error": "findings endpoint requires at least one CVE finding id"},
            status_code=400,
        )

    token = state.token
    domain = state.domain
    if not token or not domain:
        return JSONResponse({"error": "missing token or domain"}, status_code=400)

    from fs_report.tracker_support import create_tracker_tickets as _create

    try:
        summary = _create(
            domain=domain,
            auth_token=token,
            endpoint=endpoint,
            mode=mode,
            items=items,
            ticket_name=str(body.get("ticket_name") or ""),
            ticket_summary=str(body.get("ticket_summary") or ""),
            priority=str(body.get("priority") or "High"),
            project_key=str(body.get("project_key") or ""),
            issue_type=str(body.get("type") or "Task"),
        )
    except Exception:
        logger.warning("tracker ticket creation failed", exc_info=True)
        return JSONResponse(
            {"error": "ticket creation failed; see server log"}, status_code=500
        )

    # 200 when ≥1 ticket was created (success/partial); 502 when none were.
    status_code = 200 if summary.get("created") else 502
    return JSONResponse(summary, status_code=status_code)
