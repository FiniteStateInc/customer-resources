"""Shared effective-scope resolution (B1 / Theme 3a).

The single arbiter of "what is this run actually scoped to, honestly." A
confirmed scope leak (#27) plus three transparency gaps (#26 Running Reports,
#15 report-shell topbar, #14 command palette) all stemmed from surfaces showing
the *captured/pinned* scope rather than the **effective** scope the engine uses.

This module is deliberately dependency-light (no web/router imports) so it can
be imported by BOTH the FastAPI web routers (``fs_report.web.routers.run``) AND
the HTML renderers (``fs_report.renderers.html_renderer``) without a circular
dependency on the web layer — the renderers sit *below* the web router in the
import graph, so the helper cannot live in ``run.py``.

**Portfolio-recipe scope (deferred).** The spec originally proposed forcing the
recipes that *can* run portfolio-wide (CVA / CVE Impact / Component Impact) to
ALWAYS ignore a pinned project — both in display and engine config. That is a
real behavior change (it removes the ability to scope those recipes to one
project) and was deferred: an explicitly pinned project still narrows every
recipe, so this helper honestly reflects the pinned scope and reports
``portfolio`` only when nothing is pinned. The "always portfolio-wide" behavior
+ the audited recipe membership belong to the follow-on Builder/recipe-scope
audit, not here.
"""

from __future__ import annotations

from typing import Any


def _build_active_filters(effective: dict[str, Any]) -> list[dict[str, str]]:
    """Non-scope filters active on the run, as ``{label, value}`` chips.

    Surfaced as active-filter chips (#15) alongside the scope. Scope itself
    (project/folder/version) is reported via ``scope_kind``/``label``/``version``
    — these chips are the *additional* narrowing the engine applies.
    """
    chips: list[dict[str, str]] = []
    component = str(effective.get("component_filter") or "").strip()
    if component:
        version_range = str(effective.get("component_version") or "").strip()
        value = f"{component} {version_range}".strip() if version_range else component
        chips.append({"label": "Component", "value": value})
    cve = str(effective.get("cve_filter") or "").strip()
    if cve:
        chips.append({"label": "CVE", "value": cve})
    return chips


def compute_effective_scope(effective: dict[str, Any]) -> dict[str, Any]:
    """Resolve the EFFECTIVE scope a run/render uses, honestly.

    Reads the pinned selection in ``effective`` (``project_filter`` /
    ``folder_filter`` / ``version_filter``, plus an optional pre-resolved
    ``folder_label``) and reports what the engine actually scopes to. Pure:
    never mutates ``effective``, never touches the network.

    Returns a dict::

        {
          "scope_kind": "project" | "folder" | "portfolio",
          "label":      str,           # e.g. "My Firmware" / "Routers" / "Portfolio"
          "version":    str | None,    # effective version (project scope only)
          "active_filters": [{"label": str, "value": str}, ...],
        }

    Precedence mirrors the engine chokepoint (``_build_engine_config``): a
    project wins over a folder (project-scoped run), a version is meaningful only
    with a project, and an empty/whitespace selection is "unset" (→ portfolio).
    """
    project = str(effective.get("project_filter") or "").strip()
    folder = str(effective.get("folder_filter") or "").strip()
    version = str(effective.get("version_filter") or "").strip()

    if project:
        scope_kind = "project"
        label = project
        eff_version: str | None = version or None
    elif folder:
        scope_kind = "folder"
        label = str(effective.get("folder_label") or "").strip() or folder
        eff_version = None
    else:
        scope_kind = "portfolio"
        label = "Portfolio"
        eff_version = None

    return {
        "scope_kind": scope_kind,
        "label": label,
        "version": eff_version,
        "active_filters": _build_active_filters(effective),
    }
