"""Convert a fully rendered standalone HTML page into an embeddable fragment.

Used by ``HTMLRenderer.render_fragment()`` so each recipe can be safely
concatenated with siblings in a compound report:

- The document shell (``<!DOCTYPE>``, ``<html>``, ``<head>``, ``<body>``)
  is stripped.
- ``<script>`` blocks are dropped — Chart.js bootstrap isn't needed in
  fragments because chart SVGs are already inlined when
  ``fragment_mode`` / ``pdf_target`` is set.
- ``<style>`` block contents are collected and run through
  :func:`css_scoper.scope_css`, then re-emitted as a single scoped
  ``<style>`` element prepended to the fragment.
- The body's inner HTML is wrapped in ``<div class="{scope_class}">…</div>``
  so the scoped selectors actually match something.
"""

from __future__ import annotations

import re

from fs_report.renderers.css_scoper import scope_css

_STYLE_RE = re.compile(r"<style\b[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
_BODY_RE = re.compile(r"<body\b([^>]*)>(.*?)</body>", re.DOTALL | re.IGNORECASE)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"</?html\b[^>]*>", re.IGNORECASE)
_HEAD_RE = re.compile(r"<head\b[^>]*>.*?</head>", re.DOTALL | re.IGNORECASE)
_HEADING_RE = re.compile(r"<(/?)h([1-6])(\b[^>]*)>", re.IGNORECASE)
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


def extract_fragment(
    html: str,
    scope_class: str,
    *,
    heading_depth: int = 2,
    nav_category_slug: str | None = None,
) -> str:
    """Return a scoped fragment derived from ``html``.

    Parameters mirror ``HTMLRenderer.render_fragment()``:

    - ``heading_depth``: top-level heading level for the section. Headings
      in the body are shifted so the original ``<h1>`` lands at this depth
      (default ``<h2>``). Pass ``1`` to keep headings unchanged.
    - ``nav_category_slug``: if set, emits ``data-nav-category="<slug>"``
      on the section wrapper so scoped ``[data-nav-category="..."]``
      accent rules still match in fragment mode.

    Per-recipe chrome (header / metadata / footer) is NOT stripped here
    — the Phase 2 compound assembler will decide how to handle that,
    likely via per-recipe data attributes or template conventions that
    can disambiguate top-level chrome from inline content callouts.

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
    body = _SCRIPT_RE.sub("", body)
    body = _shift_headings(body, heading_depth - 1)

    if nav_category_slug is None:
        match = _BODY_DATA_NAV_RE.search(body_attrs)
        if match:
            nav_category_slug = match.group(1)

    nav_attr = f' data-nav-category="{nav_category_slug}"' if nav_category_slug else ""

    css = "\n".join(b.strip() for b in style_blocks if b.strip())
    parts: list[str] = []
    if css:
        parts.append(f"<style>\n{scope_css(css, scope_class)}\n</style>")
    parts.append(f'<div class="{scope_class}"{nav_attr}>{body}</div>')
    return "\n".join(parts)
