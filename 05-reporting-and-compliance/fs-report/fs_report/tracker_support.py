"""Serve-side helper for creating tracker (Jira) tickets via Customer API v0.3.0.

Mirrors :mod:`fs_report.vex_apply_support`: a package-root module the web
``/api/tracker/tickets`` endpoint imports lazily.  fs-report's ``APIClient`` is
GET-only, so — exactly like ``VexApplier`` — this builds its **own** dedicated
``httpx.Client`` for the write path.

Contract (verified live via spike SA-44 and the forge reference
``finite_state_forge/tools/tickets.py``):

- Create is routed **per project version**:
  ``POST /public/v0/tracker/{projectVersionId}/tickets/{findings|components}``.
  The pvId is a **URL path param** — there is no cross-version create, so a
  selection spanning K versions produces K tickets (one POST per version).
- ``findings`` are **CVE strings** (e.g. ``CVE-2021-44228``), NOT internal finding
  PKs.  Sending internal PKs is what 500s today.
- ``components`` are **version-component IDs** (``vc_id``).
- The request body is a plain **snake_case** dict (there is no pydantic model on
  the platform side); the response is **camelCase**
  (``createdTicketKeys`` / ``failedTickets``).

Two retry mechanisms compose:

1. A VexApplier-style **transient** retry loop (429/502/503/504, capped
   exponential backoff + jitter, never raises) around each POST.
2. The forge **HTTP-500 graceful-degradation** ladder: on 500, retry with
   ``priority="High"``, then with ``findings=[]``, then fail — recording each
   degradation as a warning.
"""

from __future__ import annotations

import json
import logging
import random
import time

import httpx

logger = logging.getLogger(__name__)

# Transient-retry configuration (matches fs_report.vex_applier).
# 500s are deliberately EXCLUDED here — they are handled by the separate
# graceful-degradation ladder below, not retried verbatim.
RETRY_STATUS_CODES = {429, 502, 503, 504}
MAX_RETRIES = 6
MAX_RETRY_DELAY = 64  # seconds


class TrackerError(Exception):
    """A per-version ticket-create failure (caught and recorded per version)."""


def _normalize_base_url(domain: str) -> str:
    """Strip any scheme/trailing slash and re-prefix https:// (cf. VexApplier)."""
    d = domain.replace("https://", "").replace("http://", "").rstrip("/")
    return f"https://{d}"


def _sleep_backoff(attempt: int) -> None:
    """Capped exponential backoff with jitter (identical to vex_applier)."""
    time.sleep(min(2**attempt, MAX_RETRY_DELAY) + random.uniform(0, 1))


def _group_by_version(items: list[dict]) -> dict[str, list[dict]]:
    """Group request items by their own ``project_version_id`` (insertion order)."""
    groups: dict[str, list[dict]] = {}
    for it in items:
        pv = str(it.get("project_version_id") or "").strip()
        if not pv:
            continue
        groups.setdefault(pv, []).append(it)
    return groups


def _components_lookup(
    pv_id: str,
    *,
    domain: str,
    auth_token: str,
    cache: dict[str, dict[tuple[str, str], str] | None],
) -> dict[tuple[str, str], str] | None:
    """Build a ``(name, version) -> vc_id`` map for a version, cached per pv.

    Pages the version-scoped components endpoint via the read-only ``APIClient``
    (exactly ``report_engine._fetch_scope_components_fresh``).  A version-scoped
    component row's ``id`` *is* its version-component id (matches forge's
    ``_resolve_version_component_ids``).

    Returns the map on a successful fetch (possibly empty if the version has no
    components), or ``None`` when the fetch itself **failed** — the distinction
    lets the caller tell "this component genuinely isn't in the version" (drop +
    warn) apart from "we couldn't read the catalog" (also drop, but with a
    distinct 'catalog unavailable' warning, since the row-provided id can't be
    verified as a vc_id).  Never raises.
    """
    if pv_id in cache:
        return cache[pv_id]

    lookup: dict[tuple[str, str], str] = {}
    result: dict[tuple[str, str], str] | None = lookup
    try:
        from fs_report.api_client import APIClient
        from fs_report.models import Config, QueryConfig, QueryParams

        config = Config(
            auth_token=auth_token,
            domain=domain,
            start_date="1970-01-01",
            end_date="1970-01-01",
        )
        api = APIClient(config)
        try:
            rows = api.fetch_all_with_resume(
                QueryConfig(
                    endpoint=f"/public/v0/versions/{pv_id}/components",
                    params=QueryParams(limit=10000, archived=False, excluded=False),
                ),
                show_progress=False,
            )
        finally:
            try:
                api.client.close()
            except Exception:  # pragma: no cover - best-effort close
                pass
        for comp in rows or []:
            cid = comp.get("id")
            if cid is not None:
                lookup[(comp.get("name", ""), comp.get("version", ""))] = str(cid)
    except Exception:
        # Fetch failed — signal it (None) so the caller drops the (now
        # unverifiable) component with a distinct warning rather than POSTing an
        # id it can't confirm is a vc_id.
        result = None
        logger.warning(
            "Failed to fetch components for version %s; "
            "named components there cannot be verified and will be dropped",
            pv_id,
            exc_info=True,
        )

    cache[pv_id] = result
    return result


def _resolve_components(
    pv_items: list[dict],
    pv_id: str,
    *,
    domain: str,
    auth_token: str,
    cache: dict[str, dict[tuple[str, str], str] | None],
) -> tuple[list[str], list[str]]:
    """Resolve a version's items to ``vc_id`` strings (deduped, order-preserving).

    Uses the item's ``component.id`` (already vcId-first from the row) when
    present; otherwise resolves ``(name, version) -> vc_id`` via
    :func:`_components_lookup`.  Returns ``(vc_ids, warnings)``; each
    unresolvable component contributes one warning and is dropped.
    """
    vc_ids: list[str] = []
    seen: set[str] = set()
    warnings: list[str] = []

    for it in pv_items:
        comp = it.get("component") or {}
        raw_id = str(comp.get("id") or "").strip()
        name = (comp.get("name") or "").strip()
        ver = comp.get("version") or ""

        if name:
            # Authoritative resolution. A row's ``component.id`` is vcId-first but
            # falls back to a *global* component PK when ``component.vcId`` is
            # absent (triage ``_normalize_columns``) — and a global PK 500s the
            # tracker, the exact failure class this fix targets. So when we have a
            # ``(name, version)`` we resolve it against the version's components
            # (matching forge's ``_resolve_version_component_ids``) and *prefer*
            # that vc_id; we only fall back to the provided id when the lookup
            # can't resolve it (unknown component, or the fetch failed).
            lookup = _components_lookup(
                pv_id, domain=domain, auth_token=auth_token, cache=cache
            )
            if lookup is None:
                # The components catalog fetch failed (after the API client's own
                # retries — i.e. a hard failure, not a transient blip). We cannot
                # *verify* the row-provided id, and a row id can be a global
                # component PK rather than a vc_id, so we refuse to POST it
                # unverified (that is the exact 500 class this fix targets). Drop
                # it: a findings ticket still creates from its CVEs (the component
                # is supplementary); a components-endpoint version then fails
                # cleanly via the all-unresolvable guard.
                warnings.append(
                    f"{pv_id}: component catalog unavailable; could not verify "
                    f"component {name!r}; dropped"
                )
                continue
            cid = lookup.get((name, ver), "")
            if not cid and raw_id and raw_id in lookup.values():
                # The (name, version) didn't match (e.g. cosmetic name/version
                # normalization differences), but the provided id IS a real
                # version-component id for this version — trust it. We do NOT
                # trust an *unknown* raw id (could be a global PK).
                cid = raw_id
            if not cid:
                warnings.append(
                    f"{pv_id}: could not resolve component "
                    f"{name!r} ({ver or 'n/a'}) to a "
                    "version-component id; dropped"
                )
                continue
        elif raw_id:
            # No ``(name, version)`` to resolve against — trust the provided id.
            cid = raw_id
        else:
            # No component metadata at all (the common case for findings
            # tickets) — nothing to resolve, nothing to warn about.
            continue

        if cid not in seen:
            seen.add(cid)
            vc_ids.append(cid)

    return vc_ids, warnings


def _resolve_project_name(
    client: httpx.Client, base_url: str, project_key: str
) -> str | None:
    """Resolve ``project_key -> project_name`` via a single tracker ping.

    Never blocks a create: any failure (network/4xx/5xx, key absent) returns
    ``None`` and the caller proceeds without ``project_name`` (forge omits it too).
    """
    if not project_key:
        return None
    url = f"{base_url}/api/public/v0/tracker/tickets/ping"
    try:
        resp = client.post(url, json={})
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            for proj in data.get("projects") or []:
                if isinstance(proj, dict) and proj.get("key") == project_key:
                    name = proj.get("name")
                    return str(name) if name else None
    except Exception:
        logger.warning(
            "Tracker ping failed; proceeding without project_name", exc_info=True
        )
    return None


def _post_once(client: httpx.Client, url: str, body: dict) -> tuple[bool, dict]:
    """POST once with the transient-retry loop. Returns ``(ok, payload)``.

    ``ok`` True → ``payload`` is the parsed JSON dict. ``ok`` False → ``payload``
    is a failure dict with ``status_code`` (int|None), ``error``, and (for HTTP
    errors) ``response_body``. Never raises.
    """
    for attempt in range(MAX_RETRIES):
        try:
            resp = client.post(url, json=body)
            resp.raise_for_status()
            try:
                parsed = resp.json()
            except (json.JSONDecodeError, ValueError):
                parsed = {}
            return True, (parsed if isinstance(parsed, dict) else {})
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            if code in RETRY_STATUS_CODES and attempt < MAX_RETRIES - 1:
                _sleep_backoff(attempt)
                continue
            return False, {
                "status_code": code,
                "error": str(e),
                "response_body": e.response.text[:500],
            }
        except httpx.RequestError as e:
            if attempt < MAX_RETRIES - 1:
                _sleep_backoff(attempt)
                continue
            return False, {"status_code": None, "error": str(e)}
    return False, {"status_code": None, "error": "Max retries exceeded"}


def _describe_failure(payload: dict) -> str:
    err = payload.get("error")
    if err:
        return str(err)
    code = payload.get("status_code")
    return f"HTTP {code}" if code else "unknown error"


def _post_ticket_with_retry(
    client: httpx.Client,
    base_url: str,
    pv_id: str,
    endpoint: str,
    body: dict,
) -> tuple[dict, list[str]]:
    """POST the routed per-version create with forge's 500-degradation ladder.

    Returns ``(platform_response, warnings)``. Raises :class:`TrackerError` on any
    non-recoverable failure (non-500 error, or 500 with no degradation left).
    """
    url = f"{base_url}/api/public/v0/tracker/{pv_id}/tickets/{endpoint}"
    warnings: list[str] = []

    # Attempt 1: original body.
    ok, payload = _post_once(client, url, body)
    if ok:
        return payload, warnings
    if payload.get("status_code") != 500:
        raise TrackerError(_describe_failure(payload))
    logger.warning("Platform ticket 500 on first attempt for %s", pv_id)

    # Attempt 2: degrade priority to High (only if it wasn't already).
    if body.get("priority", "High") != "High":
        original = body["priority"]
        ok, payload = _post_once(client, url, {**body, "priority": "High"})
        if ok:
            warnings.append(
                f"Priority degraded from '{original}' to 'High' "
                "(original caused HTTP 500)"
            )
            return payload, warnings
        if payload.get("status_code") != 500:
            raise TrackerError(_describe_failure(payload))
        logger.warning("Platform ticket 500 after priority fallback for %s", pv_id)

    # Attempt 3: drop findings (always with priority=High).
    if body.get("findings"):
        ok, payload = _post_once(
            client, url, {**body, "priority": "High", "findings": []}
        )
        if ok:
            warnings.append("Findings dropped from ticket (caused HTTP 500)")
            if body.get("priority", "High") != "High":
                warnings.append(
                    f"Priority degraded from '{body['priority']}' to 'High'"
                )
            return payload, warnings
        # All degradations exhausted — surface the real last error (forge
        # re-raises the actual last error here, not a hardcoded 500).
        raise TrackerError(_describe_failure(payload))

    raise TrackerError("Platform ticket creation failed after retries (HTTP 500)")


def create_tracker_tickets(
    *,
    domain: str,
    auth_token: str,
    endpoint: str,
    mode: str,
    items: list[dict],
    ticket_name: str = "",
    ticket_summary: str = "",
    priority: str = "High",
    project_key: str = "",
    issue_type: str = "Task",
) -> dict:
    """Create tracker tickets for ``items``, grouped + POSTed once per version.

    ``items`` are dicts of ``{project_version_id, finding_ids:[CVE...],
    component:{id?, name?, version?}}``. Returns the serve→browser summary::

        {"status": "success"|"partial"|"failure",
         "created": [{"project_version_id", "ticket_keys": [...]}],
         "failed":  [{"project_version_id", "error"}],
         "warnings": [...]}

    Honest accounting: ``success`` only when every requested version produced at
    least one ticket; ``partial`` when some versions failed; ``failure`` when none
    were created.
    """
    base_url = _normalize_base_url(domain)
    created: list[dict] = []
    failed: list[dict] = []
    warnings: list[str] = []
    comp_cache: dict[str, dict[tuple[str, str], str] | None] = {}

    with httpx.Client(
        headers={"X-Authorization": auth_token, "Content-Type": "application/json"},
        timeout=30.0,
    ) as client:
        project_name = _resolve_project_name(client, base_url, project_key)
        groups = _group_by_version(items)

        for pv_id, pv_items in groups.items():
            try:
                vc_ids, comp_warnings = _resolve_components(
                    pv_items,
                    pv_id,
                    domain=domain,
                    auth_token=auth_token,
                    cache=comp_cache,
                )
                warnings.extend(comp_warnings)

                # Partial-resolution policy: a components ticket with no resolvable
                # components is a failure (don't POST an empty components list);
                # for findings tickets, components are supplementary.
                if endpoint == "components" and not vc_ids:
                    failed.append(
                        {
                            "project_version_id": pv_id,
                            "error": (
                                "no components could be resolved to "
                                "version-component IDs"
                            ),
                        }
                    )
                    continue

                cve_ids = sorted(
                    {c for it in pv_items for c in (it.get("finding_ids") or []) if c}
                )

                body: dict = {
                    "components": vc_ids,
                    "findings": cve_ids,
                    "ticket_name": ticket_name,
                    "ticket_summary": ticket_summary,
                    "priority": priority,
                    "project_key": project_key,
                    "type": issue_type,
                    "mode": mode,
                }
                if project_name:
                    body["project_name"] = project_name

                result, deg = _post_ticket_with_retry(
                    client, base_url, pv_id, endpoint, body
                )
                warnings.extend(f"{pv_id}: {w}" for w in deg)

                created_keys = result.get("createdTicketKeys") or []
                failed_tickets = result.get("failedTickets") or []
                if created_keys:
                    created.append(
                        {
                            "project_version_id": pv_id,
                            "ticket_keys": list(created_keys),
                        }
                    )
                    if failed_tickets:
                        warnings.append(
                            f"{pv_id}: {len(failed_tickets)} ticket(s) reported "
                            "as failed by the platform"
                        )
                else:
                    detail = (
                        f"platform reported {len(failed_tickets)} failed ticket(s) "
                        "and created none"
                        if failed_tickets
                        else "platform created no tickets"
                    )
                    failed.append({"project_version_id": pv_id, "error": detail})
            except TrackerError as e:
                failed.append({"project_version_id": pv_id, "error": str(e)})
            except Exception as e:  # pragma: no cover - defensive
                logger.warning(
                    "Tracker ticket creation failed for version %s",
                    pv_id,
                    exc_info=True,
                )
                failed.append({"project_version_id": pv_id, "error": str(e)})

    if created and not failed:
        status = "success"
    elif created:
        status = "partial"
    else:
        status = "failure"

    return {
        "status": status,
        "created": created,
        "failed": failed,
        "warnings": warnings,
    }
