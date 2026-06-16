"""Shared shell context contract for all Command Center shell pages.

Every page that extends ``_cc_shell.html`` calls ``build_shell_context``
to obtain the dict it needs for the shared chrome: palette, status-bar,
breadcrumb, sidebar active-item, pinned scope, and version stamp.

Routes spread page-specific extras on top::

    ctx = build_shell_context(state, nonce, crumb="Command Center",
                              active_view="command-center")
    ctx["history"] = report_history.list_runs(limit=12)   # dashboard only
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fs_report import __version__
from fs_report.models import CompoundRecipe as _CompoundRecipe
from fs_report.recipe_loader import RecipeLoader
from fs_report.slug import slug
from fs_report.web.state import WebAppState, needs_setup

logger = logging.getLogger(__name__)

# ── Folders cache for pinned-folder name resolution (design §4 round-2) ──
#
# The shell render is synchronous and otherwise never touches the platform
# (``projects`` is intentionally ``[]``, fetched client-side).  A pinned folder
# stores its ID, so to render the display name + invalidate a stale pin we need
# the folders list.  We do a single best-effort synchronous fetch, memoized per
# domain for a short TTL so rapid multi-page navigation doesn't re-hit the API,
# and only when a ``pinned_folder`` is actually set (an unpinned shell pays
# nothing).  Every failure degrades gracefully — see ``_resolve_pinned_folder``.
_FOLDERS_CACHE_TTL = 60.0  # seconds
_folders_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _clear_folders_cache_for_tests() -> None:
    """Reset the per-domain folders memo (test isolation helper)."""
    _folders_cache.clear()


def _fetch_folders(domain: str, token: str) -> tuple[bool, list[dict[str, Any]]]:
    """Best-effort synchronous fetch of ``/public/v0/folders`` (memoized).

    Returns ``(ok, folders)`` where ``ok`` is ``True`` only when the fetch
    SUCCEEDED (HTTP 200 with a parseable, recognized response shape) — so the
    caller can distinguish a confirmed-empty list from a transient
    failure/auth/unconfigured miss it could not confirm.

    Accepts the platform's paginated shapes — a bare top-level ``list``,
    ``{"items": [...]}``, or ``{"data": [...]}`` (matching ``fetchFolders()`` /
    ``api_client``) — not just a bare list.

    Memoization is per domain for ``_FOLDERS_CACHE_TTL`` seconds, and ONLY a
    successful, NON-EMPTY result is cached: a failed/empty fetch is never
    memoized, so the next render retries instead of a stale TTL hiding a valid
    pin.  Never raises (a network failure degrades to ``(False, [])``).
    """
    now = time.monotonic()
    hit = _folders_cache.get(domain)
    if hit is not None and (now - hit[0]) < _FOLDERS_CACHE_TTL:
        return True, hit[1]

    import httpx

    ok = False
    folders: list[dict[str, Any]] = []
    try:
        url = f"https://{domain}/api/public/v0/folders?limit=10000"
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, headers={"X-Authorization": token})
        if resp.status_code == 200:
            data = resp.json()
            # Accept the platform's paginated shapes, not just a bare list:
            # ``{items: [...]}`` / ``{data: [...]}`` (fetchFolders/api_client)
            # plus a top-level list.
            raw: Any = None
            if isinstance(data, list):
                raw = data
            elif isinstance(data, dict):
                raw = data.get("items")
                if raw is None:
                    raw = data.get("data")
            if isinstance(raw, list):
                ok = True
                folders = [f for f in raw if isinstance(f, dict)]
    except Exception as exc:  # pragma: no cover - network failure path
        logger.debug("pinned-folder resolution: folder fetch failed: %s", exc)
        ok = False
        folders = []

    # Only memoize a SUCCESSFUL, NON-EMPTY result — a failed/empty fetch is not
    # cached so the next render retries (no 60s TTL hiding a valid pin).
    if ok and folders:
        _folders_cache[domain] = (now, folders)
    return ok, folders


def _resolve_pinned_folder(state: WebAppState) -> tuple[str, str]:
    """Resolve the pinned folder to ``(id, display_name)``; ``("", "")`` if none.

    The persisted ``pinned_folder`` stores the folder **ID** (design §4).  This
    helper resolves it against the live folders list so the sidebar/breadcrumb
    can render the folder's display **name** and so a *genuinely* stale pin is
    invalidated:

    * Empty/whitespace pin → ``("", "")`` (no fetch).
    * **Name→ID migration:** a legacy value holding a folder NAME (pre-ID
      seeding) resolves to that folder's ID (case-insensitive), consistent with
      the ID-keyed cascade.
    * **Render-time invalidation (stale):** clear the pin (``("", "")``) ONLY
      when the folders fetch SUCCEEDED and the stored ID/name is genuinely
      absent from the list — same shape as the ``pinned_report`` migration — so
      a confirmed-stale pin can never seed a bad run.
    * **Transient miss (keep):** when the fetch FAILED / was empty / could not
      be confirmed (network/auth/unconfigured), the pin is NOT unpinned — we
      KEEP ``pinned_folder`` and render a best-effort label (the raw value, i.e.
      the ID) so a valid pin survives a transient lookup miss.

    All resolution is render-time only; the persisted value is left untouched
    (the next ``/pin`` write rewrites it to the ID).
    """
    raw = str(state.get("pinned_folder", "") or "").strip()
    if not raw:
        return "", ""

    domain = state.domain
    token = state.token
    if not domain or not token:
        # Unconfigured — couldn't confirm staleness, so keep the pin and render
        # a best-effort label (the raw value / ID) rather than unpinning.
        return raw, raw

    ok, folders = _fetch_folders(domain, token)
    if not ok:
        # Transient fetch failure — couldn't confirm the pin is stale, so keep
        # it and render the raw value (ID) as a best-effort label.
        return raw, raw

    # Exact ID match first (the canonical stored form).
    for f in folders:
        if str(f.get("id", "")) == raw:
            return raw, str(f.get("name", "") or raw)

    # Name→ID migration: legacy value held a folder NAME (case-insensitive).
    low = raw.lower()
    for f in folders:
        name = str(f.get("name", "") or "")
        if name.lower() == low:
            return str(f.get("id", "")), name

    # Confirmed-stale pin (fetch succeeded; ID/name not found) → unpinned.
    return "", ""


def load_comparison_recipes() -> list[dict[str, str]]:
    """Return ``[{name, slug}]`` for each comparison recipe (canonical order).

    The SINGLE source of truth for comparison-recipe discovery, shared by the
    launcher (``build_shell_context``) and the Builder comparison editor
    (``builder_recipes.py`` / the facet rail) so a future filter/order change
    can't desync the two.

    Sourced the way the CLI ``compare`` resolver does — bundled PLUS user recipes
    (``scan_user_recipes=True`` — see
    ``compare_cmd._resolve_comparison_argv_to_names``) — so a user-defined
    ``category: comparison`` recipe the CLI would accept is not dropped by the UI
    whitelist.  Each entry's ``slug`` is ``slug(name)`` (hyphens), the exact token
    ``compare`` resolves argv against, so the diff checkbox values + generated
    command resolve by construction.  Filtered to ``audience is None`` and
    ``category == "comparison"``, then sorted alphabetically by name for a
    deterministic diff order (matching ``fs-report list recipes``' comparison
    group, not ``iterdir()`` order).  Falls back to ``[]`` on any load failure
    (never raises).
    """
    try:
        recipes = RecipeLoader(use_bundled=True, scan_user_recipes=True).load_recipes()
    except Exception:
        return []
    out = [
        {"name": r.name, "slug": slug(r.name)}
        for r in recipes
        if getattr(r, "audience", None) is None
        and getattr(r, "category", None) == "comparison"
    ]
    out.sort(key=lambda c: c["name"])
    return out


def build_shell_context(
    state: WebAppState,
    nonce: str,
    *,
    crumb: str,
    active_view: str,
) -> dict[str, Any]:
    """Return the shared shell contract dict for a Command Center shell page.

    Parameters
    ----------
    state:
        Live ``WebAppState`` instance (provides domain, cache_ttl, pinned_*).
    nonce:
        CSRF nonce for the current request.
    crumb:
        Breadcrumb label rendered in the top-bar (e.g. ``"Command Center"``).
    active_view:
        Sidebar active-item key (e.g. ``"command-center"``, ``"queue"``).

    Returns
    -------
    dict
        Contains: ``nonce``, ``domain``, ``version``, ``cache_ttl``,
        ``pinned_report``, ``pinned_project``, ``pinned_version``,
        ``pinned_folder``, ``pinned_folder_name``, ``crumb``, ``active_view``,
        ``recipes``, ``comparison_recipes``, ``needs_setup_recipes``,
        ``scope_req``, ``projects``.

    Notes
    -----
    * ``recipes`` are loaded via ``RecipeLoader(use_bundled=True)``; on any
      load failure the list falls back to ``[]`` (never raises).  Each recipe
      dict carries its ``requires_cve`` / ``requires_project`` /
      ``requires_project_or_folder`` flags and a server-computed ``needs_setup``
      boolean (the effective setup gate from the card-config design §4).
      ``recipes`` **excludes** ``category == "comparison"`` recipes — those are
      not runnable via ``/api/run`` (the engine refuses a comparison recipe on
      the normal run path) so they must not appear in the launcher grid or the
      run-bar dropdown.  ``recipes`` is sorted by ``(nav_category, name)`` (both
      case-insensitive) so the run-bar dropdown is simply category-grouped +
      alphabetical — a sensible dropdown order matching the launcher's category
      chips.  This is NOT strict parity with ``fs-report list recipes`` (the CLI
      partitions by execution order); it is just a semblance of order for the UI.
    * ``comparison_recipes`` is the list of ``{name, slug}`` for each
      ``category == "comparison"`` recipe (``audience is None``), where
      ``slug == fs_report.slug.slug(name)`` (hyphenated, the exact token the CLI
      ``compare`` subcommand resolves argv against).  Sourced the way ``compare``
      does (bundled **plus** user recipes, ``scan_user_recipes=True``) and sorted
      alphabetically by name for a deterministic diff order.  Falls back to
      ``[]`` on any load failure (never raises).
    * ``pinned_report`` is migrated at render time: if the effective pinned
      report's name is an EXACT member of the comparison-recipe names (the pin is
      stored as the recipe ``name``), it is returned as ``""`` (treated as
      unpinned) so the run bar / palette ``r`` never point at a recipe absent
      from ``recipes``.  Matching by exact name (not slug) avoids unpinning a
      non-comparison recipe whose name merely slug-collides with a comparison
      recipe.  This does not mutate persisted state.
    * ``pinned_folder`` is resolved + invalidated at render time
      (``_resolve_pinned_folder``): the persisted value stores the folder ID, so
      its display name is resolved from a best-effort cached ``/folders`` fetch
      and emitted as ``pinned_folder_name``.  A stale pin (ID no longer found) is
      treated as unpinned (``pinned_folder == ""``), same shape as the
      ``pinned_report`` migration; a legacy NAME value is migrated to its ID.
      Render-time only — the persisted value is not mutated.
    * The coarse ``configure_recipes`` heuristic is no longer emitted: every
      launch path (card body, run-bar ``__openFR``, palette plain-Enter) now
      gates on ``needs_setup`` (open the configure modal) / ``scope_req`` (toast)
      via the two client maps below.  The palette's explicit Alt+Enter still
      always opens the modal.
    * ``needs_setup_recipes`` is the list of lowercase recipe names whose
      ``needs_setup`` is true; ``scope_req`` maps lowercase recipe name ->
      ``"project"`` | ``"project_or_folder"`` | ``""`` — both for the client
      bootstrap of the off-card launch paths.
    * ``projects`` is ``[]`` — the shell's cross-page JS fetches the live list
      from the platform proxy and pushes it into ``window.__CC.projects``.
    * ``history`` is not provided — the Command Center's Recent Activity feed
      (its only consumer) was removed; browse past runs via Report History
      (``/reports``).
    """
    # ── Load recipes (same guards as the original dashboard route) ──
    loader = RecipeLoader(use_bundled=True, scan_user_recipes=True)
    try:
        recipe_list = loader.load_recipes()
    except Exception:
        recipe_list = []

    # Launcher recipes (internal/forge recipes hidden).  Each carries its
    # engine requirement flags + a server-computed needs_setup boolean (the
    # effective setup gate from §4), so the dashboard can render
    # data-needs-setup / data-scope-req without an extra fetch.
    #
    # category == "comparison" recipes are EXCLUDED here (spec §4): they are not
    # runnable via /api/run (the engine refuses a comparison recipe on the normal
    # run path), so they must vanish from both the launcher grid and the run-bar
    # dropdown.  They are surfaced separately as ``comparison_recipes`` below.
    launcher_recipes = [
        r
        for r in recipe_list
        if getattr(r, "audience", None) is None
        and getattr(r, "category", None) != "comparison"
    ]

    # Inline import to avoid the shell_context ↔ run.py import cycle.
    # (run.py imports build_shell_context from shell_context's neighbours;
    # mirroring the pattern used by command_center.card_config_fragment.)
    # PR2.3a: build compound-children helpers ONCE from the already-loaded corpus.
    #
    # compound_children_map: lowercase compound name → list of child recipe names,
    # used by compute_prerun_fields to expand a compound into its children before
    # computing show_* flags.
    #
    # recipe_index: lowercase name → recipe object, used below to resolve child
    # objects for compound_effective_requirements WITHOUT re-loading the corpus.
    #
    # Both are O(1) passes over the in-memory corpus — no per-recipe disk I/O.
    from fs_report.recipe_requirements import (
        compound_prerun_inputs as _compound_prerun_inputs,
    )
    from fs_report.web.routers.run import compute_prerun_fields

    recipe_index: dict[str, Any] = {r.name.lower(): r for r in launcher_recipes}
    compound_children_map: dict[str, list[str]] = {}
    for r in launcher_recipes:
        if isinstance(r, _CompoundRecipe) and r.axis is None:
            _pre = _compound_prerun_inputs(r, lambda n: recipe_index.get(n.lower()))
            if _pre is not None:
                compound_children_map[r.name.lower()] = _pre[1]

    # Precompute the requires_cve name set ONCE from the already-loaded corpus and
    # pass it into compute_prerun_fields per recipe — otherwise each call would
    # re-scan the bundled recipe corpus from disk (O(N) reloads per page render).
    # For plain compounds, the requires_cve name set is expanded from children in
    # compute_prerun_fields itself (via compound_children_map), so only non-compound
    # recipes need to contribute directly here.
    requires_cve_names = frozenset(
        r.name.lower() for r in launcher_recipes if getattr(r, "requires_cve", False)
    )

    recipes: list[dict[str, Any]] = []
    needs_setup_recipes: list[str] = []
    scope_req: dict[str, str] = {}
    for r in launcher_recipes:
        key = r.name.lower()
        recipe_needs_setup = needs_setup(state, r)
        if recipe_needs_setup:
            needs_setup_recipes.append(key)

        # kind badge: compound bundles without axis → "compound";
        # compound bundles with a non-null axis → "comparison"; plain → None.
        if isinstance(r, _CompoundRecipe):
            recipe_kind: str | None = "comparison" if r.axis is not None else "compound"
        else:
            recipe_kind = None

        # For plain compounds, derive requires_* flags from the union of children
        # (PR2.3a) rather than from the compound's own declared flags (which are
        # all False by default).  Axis compounds and plain recipes use own flags.
        _prerun_result = _compound_prerun_inputs(
            r, lambda n: recipe_index.get(n.lower())
        )
        if _prerun_result is not None:
            effective = _prerun_result[0]
            requires_cve = effective.requires_cve
            requires_project = effective.requires_project
            requires_project_or_folder = effective.requires_project_or_folder
        else:
            requires_cve = bool(getattr(r, "requires_cve", False))
            requires_project = bool(getattr(r, "requires_project", False))
            requires_project_or_folder = bool(
                getattr(r, "requires_project_or_folder", False)
            )

        # Compute scope_req from the (possibly compound-derived) flags.
        if requires_project:
            scope_req[key] = "project"
        elif requires_project_or_folder:
            scope_req[key] = "project_or_folder"
        else:
            scope_req[key] = ""

        recipes.append(
            {
                "name": r.name,
                "label": r.name,
                "nav_category": r.nav_category or "Uncategorized",
                "description": r.description or "",
                # B10 #23: short launcher-card summary (falls back to the full
                # description client/template-side); "" when unset.
                "card_description": getattr(r, "card_description", None) or "",
                "auto_run": r.auto_run,
                "requires_cve": requires_cve,
                "requires_project": requires_project,
                "requires_project_or_folder": requires_project_or_folder,
                "needs_setup": recipe_needs_setup,
                "kind": recipe_kind,
                "applicability": compute_prerun_fields(
                    [r.name],
                    requires_cve_names=requires_cve_names,
                    compound_children=compound_children_map,
                ),
            }
        )

    # Sort the launcher/run-bar recipes by (nav_category, name), both
    # case-insensitive, so the run-bar #rb-report dropdown is simply
    # category-grouped + alphabetical — a sensible dropdown order matching the
    # launcher's category chips.  This is NOT strict parity with
    # `fs-report list recipes` (the CLI partitions by execution order); it's a
    # semblance of order for the UI.  RecipeLoader yields iterdir() order
    # otherwise.
    recipes.sort(key=lambda r: (r["nav_category"].lower(), r["name"].lower()))

    # ── Comparison recipes (the synthetic Comparison card / CLI bridge) ──
    # Single shared discovery helper (also used by the Builder comparison editor
    # facet rail — builder_recipes.py reuses _build_scope_ref, and workflows.py
    # / the builder page consume load_comparison_recipes for the facet rail) so
    # the launcher and the editor can't desync on a future filter/order change.
    # See load_comparison_recipes.
    comparison_recipes = load_comparison_recipes()

    # ── Pinned-report migration (spec §4) ───────────────────────────
    # Removing comparison recipes from ``recipes`` would orphan a pinned_report
    # that points at one of them.  The pin is stored as the recipe's exact
    # ``name``, so migrate (treat as unpinned) ONLY when the pinned report's name
    # is an EXACT member of the comparison-recipe names — not when its slug merely
    # collides.  Matching by slug would wrongly unpin a NON-comparison recipe
    # whose name happens to slug-collide with a comparison recipe; recipe names
    # are unique, so a non-comparison recipe can never share an exact name with a
    # comparison recipe.  Render-time only — the persisted value is left
    # untouched.
    pinned_report = state.get("pinned_report", "")
    comparison_names = {c["name"] for c in comparison_recipes}
    if pinned_report and pinned_report in comparison_names:
        pinned_report = ""

    # ── Pinned-folder resolution + render-time invalidation (spec §4) ──
    # pinned_folder stores the folder ID; resolve its display name and clear a
    # stale pin (ID no longer found) at render time, mirroring the pinned_report
    # migration above.  Render-time only — persisted state is untouched.
    pinned_folder, pinned_folder_name = _resolve_pinned_folder(state)

    return {
        "nonce": nonce,
        "domain": state.domain,
        "version": __version__,
        "cache_ttl": state.get("cache_ttl"),
        "pinned_report": pinned_report,
        "pinned_project": state.get("pinned_project", ""),
        "pinned_version": state.get("pinned_version", ""),
        # Folder-targeting (spec §4): resolved ID + display name. ``pinned_folder``
        # is "" when unpinned OR stale (invalidated above); ``pinned_folder_name``
        # is the folder's display name for the sidebar/breadcrumb readout.
        "pinned_folder": pinned_folder,
        "pinned_folder_name": pinned_folder_name,
        "crumb": crumb,
        "active_view": active_view,
        "recipes": recipes,
        "comparison_recipes": comparison_recipes,
        # Client bootstrap for the off-card launch paths (wired into the shell
        # template's window.__CC): the set of recipes currently needing setup,
        # and the scope-requirement map.  Both use lowercase keys.
        "needs_setup_recipes": needs_setup_recipes,
        "scope_req": scope_req,
        "projects": [],  # populated client-side by the cross-page JS fetch
    }
