"""Convert a fully rendered standalone HTML page into an embeddable fragment.

Used by ``HTMLRenderer.render_fragment()`` so each recipe can be safely
concatenated with siblings in a compound report:

- The document shell (``<!DOCTYPE>``, ``<html>``, ``<head>``, ``<body>``)
  is stripped.
- ``<style>`` block contents are collected and run through
  :func:`css_scoper.scope_css`, then re-emitted as a single scoped
  ``<style>`` element prepended to the fragment.
- ``<script>`` blocks are dropped by default. When ``fragment_scripts_enabled``
  is True (the compound assembler under Option X), body ``<script>`` blocks
  are preserved so per-section chart-init JS survives concatenation; the
  compound shell owns the ``<head>``-loaded chart libraries those scripts
  reference.
- The body's inner HTML is wrapped in
  ``<div id="{scope_class}" class="{scope_class}" …>…</div>`` so the
  scoped selectors match AND compound TOC anchors (``#fs-section-<slug>``)
  navigate to the section.
"""

from __future__ import annotations

import re
from html import escape as html_escape

from fs_report.renderers.css_scoper import scope_css

_STYLE_RE = re.compile(r"<style\b[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_BODY_RE = re.compile(r"<body\b([^>]*)>(.*?)</body>", re.DOTALL | re.IGNORECASE)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"</?html\b[^>]*>", re.IGNORECASE)
_HEAD_RE = re.compile(r"<head\b[^>]*>.*?</head>", re.DOTALL | re.IGNORECASE)
_HEADING_RE = re.compile(r"<(/?)h([1-6])(\b[^>]*)>", re.IGNORECASE)

# HTML void elements per the HTML living standard — these don't have closing
# tags even without the explicit XML self-closing slash. _remove_section_title
# must recognize them so a marker placed on e.g. <img data-fs-section-title>
# (no /> suffix) is removed cleanly. (Round-1 multi-review M2-4, M3-3.)
_HTML_VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)
_BODY_DATA_NAV_RE = re.compile(r'data-nav-category\s*=\s*"([^"]*)"', re.IGNORECASE)


def _shift_headings(html: str, shift: int) -> str:
    """Promote every ``<hN>`` by ``shift`` levels (clamped at h6).

    A heading_depth of 2 (the default for compound fragments) means
    the section title was originally an h1 and should land at h2,
    with sub-headings cascading h2→h3, h3→h4, etc. Preserves the
    relative outline while making the section nest cleanly under a
    parent compound document's h1.
    """
    if shift <= 0:
        return html

    def repl(m: re.Match[str]) -> str:
        slash = m.group(1)
        level = int(m.group(2))
        rest = m.group(3) or ""
        new_level = min(6, level + shift)
        return f"<{slash}h{new_level}{rest}>"

    return _HEADING_RE.sub(repl, html)


_SECTION_TITLE_OPEN_RE = re.compile(
    r"<(?P<tag>[A-Za-z][A-Za-z0-9]*)\b[^>]*?\bdata-fs-section-title\b[^>]*>",
    re.IGNORECASE,
)


def _remove_section_title(html: str) -> str:
    """Remove the single element marked with ``data-fs-section-title``.

    Recipe templates opt into title-suppression by adding the
    ``data-fs-section-title`` attribute to their section-title element
    (typically ``<h1 data-fs-section-title>Recipe Name</h1>``, which
    becomes ``<h2 …>`` after fragment heading-shift). The compound
    assembler removes that one element so the section divider's title
    doesn't duplicate the in-fragment title.

    Templates that don't add the marker → this is a no-op; no risk of
    accidentally removing content. Marker-based identification means
    document position, heading level, and surrounding markup don't
    matter — only the explicit opt-in matters. See the compound-reports
    design spec § 6.

    Scans a copy where ``<script>`` blocks are masked to whitespace so
    a string literal inside preserved chart-init JS can't match.

    If no marker is present, returns ``html`` unchanged.
    """

    def _mask(m: re.Match[str]) -> str:
        # Preserve length so all match offsets stay valid for the unmasked
        # html slicing at the end.
        return " " * len(m.group(0))

    # Mask <script>...</script> AND <!-- ... --> blocks so neither preserved
    # JS string literals nor HTML comments containing fake </tag> closers
    # can fool the nesting counter. (Round-1 multi-review M1-10, M2-4,
    # M3-3 — 3/3.)
    masked = _SCRIPT_RE.sub(_mask, html)
    masked = _COMMENT_RE.sub(_mask, masked)
    open_match = _SECTION_TITLE_OPEN_RE.search(masked)
    if open_match is None:
        return html

    tag = open_match.group("tag")
    # Treat as self-closing if EITHER the opening tag explicitly ends in />
    # OR the tag name is an HTML void element (img, br, input, etc.). Both
    # have no separate closer to consume.
    is_void = tag.lower() in _HTML_VOID_ELEMENTS
    if open_match.group(0).rstrip().endswith("/>") or is_void:
        return html[: open_match.start()] + html[open_match.end() :]

    # Track nesting depth through the masked HTML so a marker placed on a
    # wrapping element (``<div class="hero" data-fs-section-title>...</div>``)
    # consumes the OUTER closer rather than the first inner ``</div>``
    # — the naive non-nesting version dropped the open tag plus the first
    # nested closer, leaving an orphaned ``</div>`` that broke the
    # surrounding ``<div class="briefing">`` wrapper. (B1.4 follow-up:
    # fragment-mode visual parity.)
    open_re = re.compile(rf"<{re.escape(tag)}\b[^>]*?(?<!/)>", re.IGNORECASE)
    close_re = re.compile(rf"</{re.escape(tag)}\s*>", re.IGNORECASE)
    pos = open_match.end()
    depth = 1
    while depth > 0:
        next_close = close_re.search(masked, pos)
        if next_close is None:
            # Malformed input: opening tag without a matching closer.
            # Leave the body alone rather than truncate.
            return html
        next_open = open_re.search(masked, pos)
        if next_open is not None and next_open.start() < next_close.start():
            depth += 1
            pos = next_open.end()
        else:
            depth -= 1
            if depth == 0:
                return html[: open_match.start()] + html[next_close.end() :]
            pos = next_close.end()
    # Unreachable — the loop returns when depth hits 0.
    return html


def extract_fragment(
    html: str,
    scope_class: str,
    *,
    heading_depth: int = 2,
    nav_category_slug: str | None = None,
    fragment_scripts_enabled: bool = False,
    suppress_section_title: bool = False,
) -> str:
    """Return a scoped fragment derived from ``html``.

    Parameters mirror ``HTMLRenderer.render_fragment()``:

    - ``heading_depth``: top-level heading level for the section. Headings
      in the body are shifted so the original ``<h1>`` lands at this depth
      (default ``<h2>``). Pass ``1`` to keep headings unchanged.
    - ``nav_category_slug``: if set, emits ``data-nav-category="<slug>"``
      on the section wrapper so scoped ``[data-nav-category="..."]``
      accent rules still match in fragment mode.
    - ``fragment_scripts_enabled``: when True, body ``<script>`` blocks are
      NOT stripped — the fragment carries its chart-init JS into the
      compound bundle, where the compound shell owns the ``<head>``-loaded
      libraries (Option X path; see the compound-reports design spec § 2).
      Default False matches single-recipe fragment behavior (script-free).
      ``<style>`` handling is unchanged in either mode (always rescoped).
    - ``suppress_section_title``: when True, the post-shift body is
      searched for the single element marked with the attribute
      ``data-fs-section-title`` and that one element is removed. Recipe
      templates opt into title suppression by adding the attribute to
      their section-title element (typically the top-level heading).
      Templates without the marker → no-op; no risk of accidentally
      removing content. Used by the compound assembler so the section
      divider's title doesn't duplicate the in-fragment title. See the
      compound-reports design spec § 6.

    The wrapper ``<div>`` carries ``id="{scope_class}"`` in addition to
    ``class="{scope_class}"`` so compound TOC anchors (``#fs-section-<slug>``)
    navigate to it. Single-recipe consumers ignore the extra id.

    Per-recipe chrome preservation depends on the template's own
    render_mode gating. Templates that wrap their <header>/<footer>/
    metadata in {% if render_mode != 'fragment' %} (e.g., briefing
    recipes that extend _briefing_shell.html, which gates chrome
    internally) emit only content into the body that lands here, so
    this function sees no chrome to preserve.

    See module docstring for full behavior. If ``html`` has no ``<body>``
    wrapper, the whole input is treated as body content (with document
    shell tags stripped defensively).
    """
    style_blocks = _STYLE_RE.findall(html)

    body_match = _BODY_RE.search(html)
    body_attrs = ""
    if body_match:
        body_attrs = body_match.group(1) or ""
        body = body_match.group(2)
    else:
        body = _DOCTYPE_RE.sub("", html)
        body = _HEAD_RE.sub("", body)
        body = _HTML_TAG_RE.sub("", body)

    # Strip <style> tags from the body too. Their contents were already
    # collected into style_blocks above and will be re-emitted (scoped)
    # at the top of the fragment; leaving the original unscoped <style>
    # in the body would let those selectors bleed across siblings.
    body = _STYLE_RE.sub("", body)
    if not fragment_scripts_enabled:
        body = _SCRIPT_RE.sub("", body)
    body = _shift_headings(body, heading_depth - 1)

    if suppress_section_title:
        body = _remove_section_title(body)

    if nav_category_slug is None:
        match = _BODY_DATA_NAV_RE.search(body_attrs)
        if match:
            nav_category_slug = match.group(1)

    # HTML-escape attribute values so a recipe name containing `"` or `&`
    # cannot break out of the wrapper attributes. scope_class is produced
    # by ``fs_report.slug.slug`` (alphanumeric + hyphens only) so the
    # escape is normally a no-op, but the defensive call removes any
    # surprise from a future caller passing a raw name.
    esc_scope = html_escape(scope_class, quote=True)
    nav_attr = (
        f' data-nav-category="{html_escape(nav_category_slug, quote=True)}"'
        if nav_category_slug
        else ""
    )

    css = "\n".join(b.strip() for b in style_blocks if b.strip())
    parts: list[str] = []
    if css:
        parts.append(f"<style>\n{scope_css(css, scope_class)}\n</style>")
    parts.append(f'<div id="{esc_scope}" class="{esc_scope}"{nav_attr}>{body}</div>')
    return "\n".join(parts)
