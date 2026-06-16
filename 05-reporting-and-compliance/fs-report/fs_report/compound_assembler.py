# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

"""Compound-report HTML assembler.

Implements the contract from the compound-reports design spec § 5
(``docs/superpowers/specs/2026-05-11-compound-reports-design.md``).

Given a ``CompoundRecipe`` plus the per-child render results produced by
``ReportEngine._process_compound``, ``assemble()`` returns a single HTML
string suitable for direct PDF rendering via
``PDFRenderer.render_html()``.

The assembler owns:

- Cover-page composition (substitution-variable resolution, logo, classification).
- Table-of-contents construction (one entry per child, anchors match the
  ``fs-section-{slug}`` ids ``fragment_extractor.extract_fragment``
  emits on the wrapper ``<div>``).
- Per-section body blocks — section divider + fragment HTML for
  ``RenderedFragment`` entries, or a failure-callout partial render for
  ``FailedSection`` entries.
- Driving Jinja over ``_compound_brief.html`` with the assembled context.

The assembler is intentionally narrow:

- It does NOT fetch data, run child transforms, or touch the API client.
  ``ReportEngine._process_compound`` does that work and hands in
  ``section_results`` already built.
- It does NOT resolve logo paths to bytes — the engine pre-resolves any
  ``compound.cover.logo`` to a data URI and passes ``logo_data_uri`` in.
  This keeps the assembler dependency-free for unit tests and makes the
  bare-filename resolution helper a single-owner concern on the engine.
- It does NOT decide which children render as fragments vs. failures —
  that decision happens in ``_process_compound`` and arrives encoded in
  the ``SectionResult`` discriminated union.
"""

from __future__ import annotations

import html as html_escape_mod
import importlib.resources
import re
from collections.abc import Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from fs_report.models import (
    CompoundRecipe,
    FailedSection,
    RenderedFragment,
    SectionResult,
)
from fs_report.transforms.pandas.comparison._shared import SEVERITY_ORDER

_WHITELISTED_SCOPE_VARS = (
    "project_name",
    "period",
    "title",
    "generated_at",
    "left_scope",
    "right_scope",
)

# Trailing " (N projects)" / " (N of M projects with a version)" parenthetical
# that folder scope labels carry. Stripped by ``short_scope`` for repeated table
# headers / chips so long labels don't clip the PDF worklist tables.
_SCOPE_SUFFIX_RE = re.compile(r"\s*\([^)]*\bprojects?\b[^)]*\)\s*$", re.IGNORECASE)
# Leading "folder " / "project " scope-kind prefix.
_SCOPE_PREFIX_RE = re.compile(r"^\s*(?:folder|project)\s+", re.IGNORECASE)


def short_scope(label: object) -> str:
    """Collapse a long scope label to its bare name (Open Q #4 — owner decision).

    Strips a leading ``folder ``/``project `` kind-prefix and a trailing
    ``(N projects)`` / ``(N of M projects with a version)`` count parenthetical,
    so ``"folder TeamEdward (3 projects)"`` → ``"TeamEdward"``. The cover + exec
    headline keep the FULL label (they don't run this filter); only the repeated
    table headers / chips / per-row scope mentions use the alias, where the long
    form clips the PDF tables.

    Deterministic and total: a label with no prefix/suffix is returned unchanged
    (trimmed). Single source of truth — registered as the ``short_scope`` Jinja
    filter in BOTH the assembler env (``_make_default_env``) and the fragment
    renderer env (``HTMLRenderer.__init__``).
    """
    text = "" if label is None else str(label)
    text = _SCOPE_SUFFIX_RE.sub("", text)
    text = _SCOPE_PREFIX_RE.sub("", text)
    return text.strip()


def _substitute(text: str | None, runtime_scope: dict[str, str]) -> str:
    """Resolve the whitelisted ``{{var}}`` placeholders in ``text``.

    Uses plain string substitution (NOT Jinja) so cover-config strings
    coming from user YAML can't smuggle in template syntax (loops,
    conditionals, attribute access). Only the six whitelisted variables
    in ``_WHITELISTED_SCOPE_VARS`` are substituted; anything else is
    left as-is.
    """
    if not text:
        return ""
    out = text
    for var in _WHITELISTED_SCOPE_VARS:
        placeholder = "{{" + var + "}}"
        out = out.replace(placeholder, runtime_scope.get(var, ""))
        # Tolerate one whitespace inside the braces, matching Jinja's
        # default trim_blocks-style permissiveness ("{{ project_name }}").
        spaced = "{{ " + var + " }}"
        out = out.replace(spaced, runtime_scope.get(var, ""))
    return out


def _render_cover_html(
    compound: CompoundRecipe,
    runtime_scope: dict[str, str],
    *,
    verdict: dict | None = None,
    logo_data_uri: str | None,
    facet_titles: list[str] | None = None,
) -> str:
    """Build the cover-page HTML block.

    Returns an empty string when ``compound.cover`` is ``None`` — the
    cover-page omission contract from the spec § 3 (``CoverConfig``).

    When ``verdict`` is a meta-compare verdict (``is_meta_compare`` truthy),
    the Left/Right metadata rows carry a ``Leader``/``Behind`` role tag and a
    ``left_scope → right_scope`` spine line is added (README "Cover"). For
    non-comparison compounds the role tag / spine are omitted (today's
    behavior).
    """
    cover = compound.cover
    if cover is None:
        return ""

    title = _substitute(compound.title, runtime_scope) or compound.title
    subtitle = _substitute(cover.subtitle, runtime_scope)
    classification = _substitute(cover.classification, runtime_scope)

    esc = html_escape_mod.escape

    # Metadata grid — emit only the keys runtime_scope actually carries
    # so a bundle run without --project (e.g., portfolio-scoped) doesn't
    # ship an empty "Project:" cell. Each entry carries a full <dd> element
    # so the Left/Right rows can attach side-identity classes + a role tag.
    meta_rows: list[tuple[str, str]] = []
    if runtime_scope.get("project_name"):
        meta_rows.append(("Project", f"<dd>{esc(runtime_scope['project_name'])}</dd>"))
    if runtime_scope.get("period"):
        meta_rows.append(("Period", f"<dd>{esc(runtime_scope['period'])}</dd>"))
    if runtime_scope.get("generated_at"):
        meta_rows.append(
            ("Generated", f"<dd>{esc(runtime_scope['generated_at'])}</dd>")
        )
    left_scope = runtime_scope.get("left_scope", "")
    right_scope = runtime_scope.get("right_scope", "")
    is_compare = bool(verdict and verdict.get("is_meta_compare"))
    if left_scope:
        # Side roles for the cover (README "Cover"): the leader side shows
        # "Leader", the other "Behind". ``left_leads`` decides which is which.
        left_leads = bool(verdict.get("left_leads")) if verdict else True
        left_role = "Leader" if left_leads else "Behind"
        right_role = "Behind" if left_leads else "Leader"
        if is_compare:
            left_dd = (
                f'<dd class="mc-side left">{esc(left_scope)}'
                f'<span class="fs-compound-cover-role">{left_role}</span></dd>'
            )
            right_dd = (
                f'<dd class="mc-side right">{esc(right_scope)}'
                f'<span class="fs-compound-cover-role">{right_role}</span></dd>'
            )
        else:
            left_dd = f"<dd>{esc(left_scope)}</dd>"
            right_dd = f"<dd>{esc(right_scope)}</dd>"
        meta_rows.append(("Left", left_dd))
        meta_rows.append(("Right", right_dd))

    # Comparison cover metadata (README "Cover" / spec §6 Cover): Facets =
    # the child section display titles joined " · "; Recipe = the compound
    # name; Classification = the actual classification text (NOT hardcoded
    # "Confidential"), omitted when unset. ``facet_titles`` is the ordered
    # list of child section display titles (``child.output.slide_title or
    # child.name`` — the SAME rule the section divider/TOC uses), resolved by
    # the engine at cover time from the loaded child Recipe objects (spec §6
    # R5 M1-4) and passed in here. Keeps the assembler loader-free. When it's
    # ``None`` (other callers / legacy tests) fall back to the bare
    # ``SectionRef.recipe`` canonical names from ``compound.sections``.
    if is_compare:
        resolved_facet_titles = (
            facet_titles
            if facet_titles is not None
            else [s.recipe for s in compound.sections if getattr(s, "recipe", None)]
        )
        if resolved_facet_titles:
            facets_text = " · ".join(resolved_facet_titles)
            meta_rows.append(("Facets", f"<dd>{esc(facets_text)}</dd>"))
        recipe_text = compound.title or "fs-report compare"
        meta_rows.append(
            ("Recipe", f"<dd>{esc(_substitute(recipe_text, runtime_scope))}</dd>")
        )
        if classification:
            meta_rows.append(
                (
                    "Classification",
                    f'<dd><span class="mc-cover-badge">{esc(classification)}</span></dd>',
                )
            )

    meta_html = "".join(
        f"<div><dt>{esc(label)}</dt>{dd_html}</div>" for label, dd_html in meta_rows
    )

    # Spine line — scope labels only (the cover has no child summaries).
    spine_html = (
        '<div class="mc-cover-spine">'
        f'<span class="mc-cv-arrow">{esc(left_scope)} &rarr; {esc(right_scope)}</span>'
        "</div>"
        if is_compare and left_scope
        else ""
    )

    logo_html = (
        f'<img class="fs-compound-cover-logo" src="{esc(logo_data_uri)}" alt="">'
        if logo_data_uri
        else ""
    )

    classification_html = (
        f'<div class="fs-compound-cover-classification">{esc(classification)}</div>'
        if classification
        else ""
    )

    subtitle_html = (
        f'<p class="fs-compound-cover-subtitle">{esc(subtitle)}</p>' if subtitle else ""
    )

    eyebrow_text = "FS REPORT · COMPARISON" if left_scope else "FS REPORT"

    return (
        '<section class="fs-compound-cover">'
        '<div class="fs-compound-cover-inner">'
        f"{logo_html}"
        f'<div class="fs-compound-cover-eyebrow">{eyebrow_text}</div>'
        '<div class="fs-compound-cover-divider"></div>'
        f'<h1 class="fs-compound-cover-title">{esc(title)}</h1>'
        f"{subtitle_html}"
        f"{spine_html}"
        f'<dl class="fs-compound-cover-meta">{meta_html}</dl>'
        "</div>"
        f"{classification_html}"
        "</section>"
    )


def _render_toc_entries(section_results: list[SectionResult]) -> list[dict[str, str]]:
    """Build TOC entry dicts in section order.

    Each entry: ``{anchor: "fs-section-<slug>", title: "..."}``. Failed
    sections keep their anchor so the TOC link still resolves (lands on
    the failure callout instead of 404-ing inside the document).
    """
    return [
        {"anchor": f"fs-section-{r.slug}", "title": r.title} for r in section_results
    ]


def _render_section_divider(rendered: RenderedFragment, section_number: int) -> str:
    """Section eyebrow + title divider that precedes a fragment body.

    The fragment HTML already contains the wrapper ``<div id="fs-section-{slug}">``
    (emitted by ``fragment_extractor.extract_fragment``); the divider sits
    immediately before that wrapper in document order. Page break is
    on the divider (``break-before: page``) so the section title and its
    body land on the same page where layout permits.
    """
    esc = html_escape_mod.escape
    return (
        '<div class="fs-compound-section-divider">'
        f'<div class="fs-compound-section-eyebrow">SECTION {section_number:02d}</div>'
        f'<h2 class="fs-compound-section-title">{esc(rendered.title)}</h2>'
        "</div>"
    )


def _render_failed_section(
    env: Environment, failed: FailedSection, section_number: int
) -> str:
    """Render the failure-callout placeholder for one failed child."""
    tmpl = env.get_template("_compound_failure_section.html")
    return tmpl.render(failure=failed, section_number=section_number)


def _build_section_blocks(
    env: Environment, section_results: list[SectionResult]
) -> list[str]:
    """Assemble per-section body blocks in order.

    For each ``RenderedFragment``: emit a section divider followed by
    the fragment HTML verbatim. For each ``FailedSection``: emit the
    failure-callout partial.
    """
    blocks: list[str] = []
    for idx, result in enumerate(section_results, start=1):
        if isinstance(result, RenderedFragment):
            blocks.append(_render_section_divider(result, idx))
            blocks.append(result.html)
        elif isinstance(result, FailedSection):
            blocks.append(_render_failed_section(env, result, idx))
        else:
            raise TypeError(
                f"Unexpected SectionResult variant: {type(result).__name__}"
            )
    return blocks


def _make_default_env() -> Environment:
    """Build the default Jinja env that resolves bundled templates.

    Mirrors ``HTMLRenderer.__init__`` so partials referenced by the
    shell template (``_tokens_inline.html``, ``_chart_ready.html``,
    ``_echarts_ready.html``, ``_compound_libs.html``, etc.) resolve
    through ``importlib.resources`` and the package works when installed
    as a wheel.
    """
    template_dir = str(importlib.resources.files("fs_report.templates"))
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    # ``short_scope`` aliases long folder labels in repeated table headers /
    # chips (single source of truth — same filter is registered on the fragment
    # renderer env). The cover + exec headline keep the full label.
    env.filters["short_scope"] = short_scope
    return env


def compute_left_leads(comparison_summaries: dict[str, dict]) -> bool:
    """Decide whether the LEFT scope leads the comparison (single source of truth).

    Extracted from ``_compute_verdict`` so the two-pass engine
    (``_process_axis_compound``) and the assembler verdict share one decision
    function. They agree whenever they see the same facet summaries; the only
    way they can differ is if a leader-driving facet *transforms* successfully
    (so the engine counts it from pass-1 survivors) but then fails to *render*
    (so it never becomes a ``RenderedFragment`` the assembler can see) — a
    low-probability degraded-render edge, not the normal path. The leader is the
    side with the greater sum of portable fixes + portable triage:

        L = fixed_left_open_right + triaged_left_untriaged_right
        R = fixed_right_open_left + triaged_right_untriaged_left

    ``left_leads`` is ``L >= R`` (left wins ties).

    Fallback (M1-8): missing facet summaries contribute zero. If the finding
    facet failed/absent, the comparison falls back to the triage counts alone;
    if both facets are absent, both sides are 0 and ``left_leads`` stays
    ``True`` (left). A degraded run therefore stays self-consistent because
    ``_compute_verdict`` reuses this exact computation.
    """
    fd = comparison_summaries.get("finding-diff", {}) or {}
    td = comparison_summaries.get("triage-status-diff", {}) or {}

    fixed_l = int(fd.get("fixed_left_open_right_count", 0) or 0)
    fixed_r = int(fd.get("fixed_right_open_left_count", 0) or 0)
    triage_l = int(td.get("triaged_left_untriaged_right_count", 0) or 0)
    triage_r = int(td.get("triaged_right_untriaged_left_count", 0) or 0)

    return (fixed_l + triage_l) >= (fixed_r + triage_r)


def _compute_verdict(
    comparison_summaries: dict[str, dict],
    runtime_scope: dict[str, str],
    left_leads: bool | None = None,
) -> dict:
    """Compute the deterministic meta-compare verdict (single source of truth).

    The exec band in ``_compound_brief.html`` binds to this dict directly;
    none of this math is repeated in Jinja. Aliases follow the README
    "Comparison Summary" section: ``cd`` = component-diff summary, ``fd`` =
    finding-diff, ``ld`` = license-diff, ``td`` = triage-status-diff.

    ``leader``/``laggard`` (and the ``port_*`` / ``laggard_only`` picks) are
    chosen by the L >= R branch where:

        L = fixed_left_open_right + triaged_left_untriaged_right
        R = fixed_right_open_left + triaged_right_untriaged_left

    ``left_leads`` override (M1-1 / M1-5 / M3-3): when not ``None`` it is USED
    verbatim as the leader direction — the two-pass engine threads its pass-1
    value here so the verdict band can never disagree with the direction baked
    into the surviving fragments, even when a leader-driving facet transforms
    but then fails to render (so it's a ``FailedSection`` the assembler's
    summary collection never sees). When ``None`` (standalone / test callers)
    it falls back to ``compute_left_leads(comparison_summaries)``, preserving
    today's behavior.

    Returns an empty-ish dict (``is_meta_compare=False``) for non-comparison
    compounds so the template's ``{% if verdict and verdict.is_meta_compare %}``
    gate keeps today's behavior.
    """
    cd = comparison_summaries.get("component-diff", {})
    fd = comparison_summaries.get("finding-diff", {})
    ld = comparison_summaries.get("license-diff", {})
    td = comparison_summaries.get("triage-status-diff", {})

    # Robust labels (M2-5): a finding/component facet that FAILED contributes no
    # left_label/right_label, so fall back to the runtime scope labels — always
    # present for a comparison — BEFORE the literal "Left"/"Right". This kills
    # the generic-label regression on a finding-failed, triage-only plan, and
    # _compute_action_plan reuses these resolved labels via the verdict.
    left_label = (
        fd.get("left_label")
        or cd.get("left_label")
        or runtime_scope.get("left_scope")
        or "Left"
    )
    right_label = (
        fd.get("right_label")
        or cd.get("right_label")
        or runtime_scope.get("right_scope")
        or "Right"
    )

    fixed_l = fd.get("fixed_left_open_right_count", 0)
    fixed_r = fd.get("fixed_right_open_left_count", 0)
    triage_l = td.get("triaged_left_untriaged_right_count", 0)
    triage_r = td.get("triaged_right_untriaged_left_count", 0)

    # Single source of truth: prefer the engine's threaded pass-1 left_leads so
    # fragments, cover, verdict band, and action plan all agree regardless of
    # render failures. Fall back to the helper over the RenderedFragment
    # summaries when no override is given.
    if left_leads is None:
        left_leads = compute_left_leads(comparison_summaries)

    leader = left_label if left_leads else right_label
    laggard = right_label if left_leads else left_label
    port_fixes = fixed_l if left_leads else fixed_r
    port_triage = triage_l if left_leads else triage_r
    laggard_only = (
        cd.get("right_only_count", 0) if left_leads else cd.get("left_only_count", 0)
    )

    is_meta_compare = bool(comparison_summaries and runtime_scope.get("left_scope"))

    return {
        "cd": cd,
        "fd": fd,
        "ld": ld,
        "td": td,
        "left_label": left_label,
        "right_label": right_label,
        "leader": leader,
        "laggard": laggard,
        "left_leads": left_leads,
        "port_fixes": port_fixes,
        "port_triage": port_triage,
        "laggard_only": laggard_only,
        "is_meta_compare": is_meta_compare,
    }


def _sev_counts(rows: list[dict]) -> dict[str, int]:
    """Tally rows by severity over the canonical severity set (deterministic).

    Every label in :data:`SEVERITY_ORDER` gets a key (0 when absent) so the
    template can read a stable shape regardless of which severities appear.
    Severity strings are upper-cased/stripped to match the transforms.
    """
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for row in rows:
        sev = str(row.get("severity", "")).strip().upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _owners_union(rows: list[dict]) -> list[str]:
    """Sorted-unique-blank-filtered union of a step's rows' ``project_names``."""
    owners: set[str] = set()
    for row in rows:
        for name in row.get("project_names") or []:
            text = str(name).strip()
            if text:
                owners.add(text)
    return sorted(owners)


def _compute_action_plan(
    comparison_summaries: dict[str, dict],
    comparison_rows: dict[str, dict],
    runtime_scope: dict[str, str],
    left_leads: bool | None = None,
    verdict: dict | None = None,
) -> dict | None:
    """Compute the deterministic, leader-aware Sync Plan (spec §5b).

    Returns a structured dict — numbers, lists, and fixed enum strings only,
    **no prose**. ``_compound_brief.html`` composes sentences from it; this
    function never authors text. Shares the leader direction and the resolved
    leader/laggard labels with :func:`_compute_verdict` so the plan can never
    diverge from the verdict band, and uses the severity constants the
    transforms use so ranking is consistent.

    Direction (M1-1/2/3): ``left_leads`` picks the leader/laggard labels and the
    leader-direction port + triage row lists and the leader-direction port
    count. A right-leader dataset therefore flips every figure to right→left
    with zero human authoring.

    ``left_leads`` override (M1-1 / M1-5 / M3-3): when not ``None`` it is USED
    verbatim (the engine threads its pass-1 value); when ``None`` it falls back
    to ``compute_left_leads(comparison_summaries)``. ``verdict`` (M2-5): when a
    verdict dict is supplied the plan's ``leader`` / ``laggard`` labels are taken
    from it (``verdict["leader"]`` / ``verdict["laggard"]``) so a finding-failed
    plan still shows the real scope labels the verdict resolved — never a bare
    "Left"/"Right". When ``verdict`` is ``None`` the labels are resolved here
    against the same fallback chain (finding facet → runtime scope → literal).

    Steps: port-fix rows are grouped by ``component_name`` (one step per
    component, ``fix_target`` = the single leader version off the rows), plus a
    spliced triage step. Steps are ranked by ``(crit desc, high desc, total
    desc)`` — one Critical outranks any number of Highs — and the resulting
    order *is* ``rank`` (1-based).

    Degrade (M2-5): if the finding facet's rows are absent (that child failed)
    or there are no port rows, the plan is built from whatever lists survive
    (e.g. triage-only). Returns ``None`` for non-meta compounds (mirrors
    :func:`_compute_verdict`'s ``is_meta_compare`` guard).
    """
    # Non-meta guard — mirror _compute_verdict: no comparison summaries OR no
    # left_scope means this isn't a meta-compare; the brief gates on a truthy
    # action_plan exactly as it gates on verdict.is_meta_compare.
    if not (comparison_summaries and runtime_scope.get("left_scope")):
        return None

    # The finding facet drives the leader-direction port figures below; it may
    # be absent (that child failed) — degrade to an empty dict.
    fd = comparison_summaries.get("finding-diff", {}) or {}

    # Single source of truth for the direction (see _compute_verdict): prefer
    # the engine's threaded pass-1 value; fall back to the helper otherwise.
    if left_leads is None:
        left_leads = compute_left_leads(comparison_summaries)

    # Labels come from the verdict when available (M2-5) — the verdict already
    # resolves finding/component facet labels → runtime scope → literal, so a
    # finding-failed plan shows the real scope labels, not "Left"/"Right". When
    # no verdict is threaded in, resolve against the same fallback chain here.
    if verdict is not None:
        leader = verdict["leader"]
        laggard = verdict["laggard"]
    else:
        cd = comparison_summaries.get("component-diff", {}) or {}
        left_label = (
            fd.get("left_label")
            or cd.get("left_label")
            or runtime_scope.get("left_scope")
            or "Left"
        )
        right_label = (
            fd.get("right_label")
            or cd.get("right_label")
            or runtime_scope.get("right_scope")
            or "Right"
        )
        leader = left_label if left_leads else right_label
        laggard = right_label if left_leads else left_label

    # Leader-direction row lists. The finding facet may be absent (it failed):
    # degrade to empty port rows rather than assuming the key exists.
    finding_rows = comparison_rows.get("finding-diff", {}) or {}
    triage_rows = comparison_rows.get("triage-status-diff", {}) or {}
    port: list[dict] = list(
        finding_rows.get(
            "port_fixes_left_to_right" if left_leads else "port_fixes_right_to_left"
        )
        or []
    )
    triage_port: list[dict] = list(
        triage_rows.get(
            "triaged_left_untriaged_right"
            if left_leads
            else "triaged_right_untriaged_left"
        )
        or []
    )

    # Leader-direction port count from the finding summary (NOT a hardcoded
    # left count) so the parity caption compares against the right figure.
    port_count = int(
        (
            fd.get("fixed_left_open_right_count")
            if left_leads
            else fd.get("fixed_right_open_left_count")
        )
        or 0
    )
    needs_action_in_both_count = int(fd.get("needs_action_in_both_count") or 0)

    # Severity-weighted headline figures (the template composes the sentence).
    # Single normalization site — reuse the same counter the steps use.
    _port_sev = _sev_counts(port)
    crit = _port_sev["CRITICAL"]
    high = _port_sev["HIGH"]

    # ---- Build the port steps: one per component_name (deterministic group
    # order via sorted keys, though the final order is the rank sort below).
    # The group key is the component name as the transform emitted it
    # (case-sensitive by intent): a component's rows share one normalized
    # identity upstream, so case-variant duplicate steps don't arise in
    # practice; if they ever did, each group is still deterministic and
    # carries the same fix_target (resolved case-insensitively).
    grouped: dict[str, list[dict]] = {}
    for row in port:
        component = str(row.get("component_name", "")).strip()
        grouped.setdefault(component, []).append(row)

    steps: list[dict] = []
    for component in sorted(grouped):
        rows = grouped[component]
        # fix_target is the leader version — one per component. Pick the first
        # non-null target deterministically (rows share a component; targets
        # are resolved by the same leader_component_version helper upstream).
        fix_target = None
        for r in rows:
            t = r.get("fix_target")
            if t:
                fix_target = t
                break
        sev_counts = _sev_counts(rows)
        steps.append(
            {
                "component": component,
                "fix_target": fix_target,
                "clears": len(rows),
                "total": len(rows),
                "sev_counts": sev_counts,
                "owners": _owners_union(rows),
                # component_bump when the leader has the component at a
                # resolvable version; component_rebuild when it doesn't.
                "effort_kind": "component_bump" if fix_target else "component_rebuild",
            }
        )

    # ---- Splice the triage step (no engineering — pure VEX propagation).
    triage_step: dict | None = None
    if triage_port:
        triage_step = {
            "component": None,
            "fix_target": None,
            "clears": len(triage_port),
            "total": len(triage_port),
            "sev_counts": _sev_counts(triage_port),
            "owners": _owners_union(triage_port),
            "effort_kind": "no_engineering",
        }
        steps.append(triage_step)

    # ---- Rank: (crit desc, high desc, total desc) — one Critical outranks any
    # number of Highs. Stable sort over the deterministic pre-order keeps ties
    # reproducible. The resulting position IS the rank (1-based).
    def _rank_key(step: dict) -> tuple[int, int, int]:
        sc = step["sev_counts"]
        return (-sc.get("CRITICAL", 0), -sc.get("HIGH", 0), -step["total"])

    steps.sort(key=_rank_key)
    for idx, step in enumerate(steps, start=1):
        step["rank"] = idx

    return {
        "leader": leader,
        "laggard": laggard,
        "left_leads": left_leads,
        # Headline figures — template composes "Port {crit} Critical + {high}
        # High fixes to {laggard}"; port_total is the raw subtitle figure.
        "crit": crit,
        "high": high,
        "port_total": len(port),
        # Parity: template renders the caption when needs_action_in_both_count
        # exceeds the leader-direction port_count.
        "needs_action_in_both_count": needs_action_in_both_count,
        "port_count": port_count,
        "steps": steps,
    }


def assemble(
    compound: CompoundRecipe,
    *,
    runtime_scope: dict[str, str],
    section_results: list[SectionResult],
    chart_libraries: Iterable[str],
    tokens_inline_css: str = "",
    logo_data_uri: str | None = None,
    env: Environment | None = None,
    facet_titles: list[str] | None = None,
    left_leads: bool | None = None,
) -> str:
    """Assemble a compound-report HTML document.

    Parameters:

    - ``compound`` — the ``CompoundRecipe`` being rendered.
    - ``runtime_scope`` — substitution values for cover/title
      placeholders. Whitelisted keys: ``project_name``, ``period``,
      ``title``, ``generated_at``, ``left_scope``, ``right_scope``.
      Missing keys substitute to empty. When ``left_scope`` is non-empty
      the cover eyebrow reads ``FS REPORT · COMPARISON`` and Left/Right
      metadata rows are appended after Generated. Providing only ``right_scope`` has no effect — ``left_scope`` gates comparison mode.
    - ``section_results`` — per-child render outputs in ``compound.sections``
      order. ``ReportEngine._process_compound`` builds this list.
    - ``chart_libraries`` — the deduped union of chart-library tokens
      across surviving children. Computed by the engine over
      ``RenderedFragment`` entries only (failed sections don't contribute
      library needs, per spec § 5).
    - ``tokens_inline_css`` — verbatim ``static/css/tokens.css`` contents
      so the standalone and compound paths inline the same design tokens.
    - ``logo_data_uri`` — pre-resolved data URI for the cover logo, or
      ``None`` if no logo is configured or the file couldn't be loaded.
    - ``env`` — optional Jinja env override for tests; defaults to a
      fresh env over ``fs_report/templates/``.
    - ``facet_titles`` — ordered child section display titles
      (``child.output.slide_title or child.name``) for the comparison cover's
      Facets row, resolved by the engine at cover time (spec §6 R5 M1-4). When
      ``None`` the cover falls back to the bare ``SectionRef.recipe`` names.
    - ``left_leads`` — the engine's already-computed pass-1 leader direction
      (M1-1 / M1-5 / M3-3). When not ``None`` it is threaded verbatim into the
      verdict band and the action plan so the cover, verdict, action plan, and
      the surviving fragments share ONE direction even when a leader-driving
      facet transformed but failed to render. When ``None`` (the non-axis path,
      standalone, and tests) the verdict/plan fall back to
      ``compute_left_leads`` over the ``RenderedFragment`` summaries.

    Returns the rendered HTML string.
    """
    if env is None:
        env = _make_default_env()

    # Expose each comparison child's facet summary dict to the cover/exec
    # overview, keyed by bare recipe slug. Only RenderedFragments carrying a
    # dict summary contribute (non-comparison children have summary=None).
    comparison_summaries: dict[str, dict] = {
        r.slug: r.summary
        for r in section_results
        if isinstance(r, RenderedFragment) and isinstance(r.summary, dict)
    }

    # Expose each comparison child's per-facet row lists (§5a), keyed by bare
    # recipe slug, so the exec Action Plan can group/rank them. Only
    # RenderedFragments carrying a dict ``rows`` contribute (non-comparison
    # children have rows=None).
    comparison_rows: dict[str, dict] = {
        r.slug: r.rows
        for r in section_results
        if isinstance(r, RenderedFragment) and isinstance(r.rows, dict)
    }

    # Compute the deterministic verdict in Python — single source of truth.
    # The exec band binds to this dict; the math is NOT repeated in Jinja.
    # ``left_leads`` (the engine's pass-1 direction) is threaded through as an
    # override so the verdict can't diverge from the surviving fragments across
    # a render failure; None falls back to compute_left_leads over the summaries.
    verdict = _compute_verdict(comparison_summaries, runtime_scope, left_leads)

    # Deterministic, leader-aware Sync Plan (§5b) — numbers/lists/enums only,
    # consumed by the brief's Action Plan. None for non-meta compounds. Shares
    # the same ``left_leads`` override AND the verdict's resolved leader/laggard
    # labels so the plan, verdict band, and cover can never disagree.
    action_plan = _compute_action_plan(
        comparison_summaries,
        comparison_rows,
        runtime_scope,
        left_leads=left_leads,
        verdict=verdict,
    )

    # Degraded signal (Fix 2 / M1-1): a leader-driving facet can transform
    # successfully in pass 1 (so its counts feed left_leads / the verdict) yet
    # FAIL to render in pass 2, arriving here as a FailedSection that the
    # rendered-only ``comparison_summaries`` / ``comparison_rows`` never see. The
    # action plan can then be empty even though real sync work exists. We thread
    # this count into the exec so the "Scopes are aligned." all-clear can switch
    # to an honest degraded notice instead of a false all-clear.
    failed_facets = sum(1 for r in section_results if isinstance(r, FailedSection))
    degraded = failed_facets > 0

    cover_html = _render_cover_html(
        compound,
        runtime_scope,
        verdict=verdict,
        logo_data_uri=logo_data_uri,
        facet_titles=facet_titles,
    )
    toc_entries = _render_toc_entries(section_results)
    section_blocks = _build_section_blocks(env, section_results)

    # Preserve first-seen order across the union while deduping.
    seen: set[str] = set()
    compound_libs: list[str] = []
    for lib in chart_libraries:
        if lib in seen:
            continue
        seen.add(lib)
        compound_libs.append(lib)

    # Pre-resolve compound.title placeholders so the <title> element
    # (visible in browser tabs / bookmarks / PDF metadata) matches the
    # cover-page H1, which also runs substitution. (PR #100 round-1
    # multi-review N2.)
    resolved_title = _substitute(compound.title, runtime_scope) or compound.title

    # Force light ONLY for the meta-compare deliverable (Fix I / M1-7, scoped by
    # R3 M3-2). The redesigned meta-compare surfaces are light-only; passing an
    # EXPLICIT theme makes _theme_init.html re-assert data-theme="light" and skip
    # localStorage / ?theme= / prefers-color-scheme, so a persisted dark theme
    # from another report can't degrade these surfaces. For NON-meta compounds we
    # leave ``theme`` unset so _theme_init.html keeps its normal (auto/persisted)
    # behavior — forcing light on every compound bundle was a cross-feature
    # regression. (PDF is light regardless via pdf_mode.)
    render_ctx: dict = {
        "compound": compound,
        "resolved_title": resolved_title,
        "cover_html": cover_html,
        "toc_entries": toc_entries,
        "show_toc": compound.output.toc,
        "show_page_numbers": compound.output.page_numbers,
        "compound_libs": compound_libs,
        "section_blocks": section_blocks,
        "classification": _substitute(
            compound.cover.classification if compound.cover else None,
            runtime_scope,
        ),
        "tokens_inline_css": tokens_inline_css,
        "comparison_summaries": comparison_summaries,
        "verdict": verdict,
        "action_plan": action_plan,
        # Degraded signal for the exec false-all-clear guard (Fix 2 / M1-1).
        "degraded": degraded,
        "failed_facets": failed_facets,
    }
    if verdict.get("is_meta_compare"):
        render_ctx["theme"] = "light"

    shell = env.get_template("_compound_brief.html")
    return shell.render(**render_ctx)
