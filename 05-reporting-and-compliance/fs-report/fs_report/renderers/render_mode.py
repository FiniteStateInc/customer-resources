"""Render-mode enum consumed by HTMLRenderer and recipe templates.

Replaces the legacy ``pdf_target: bool`` + ``fragment_mode: bool``
parameter pair (which collapsed to three meaningful states but read as
four truthy-vs-falsy combinations). StrEnum so Jinja literal comparisons
(`{% if render_mode == 'fragment' %}`) work without injecting the enum
class into the template environment globals.
"""

from __future__ import annotations

from enum import StrEnum


class RenderMode(StrEnum):
    """Where the HTML the renderer produces is going.

    HTML: standalone HTML for browser viewing or fs-report --serve.
        Chart.js loads via CDN, charts render in the browser, full
        document chrome.
    PDF: HTML intermediate for Playwright → page.pdf(). JS executes
        (Chromium runs Chart.js), the chart-readiness beacon must fire
        before page.pdf() is called. Full document chrome.
    FRAGMENT: HTML for compound-bundle inclusion. fragment_extractor
        strips <html>/<head>/<body> and removes <script> blocks
        post-render, so charts must be pre-rendered to server-side SVGs.
        B1 (Compound Phase 2) revisits this contract.
    """

    HTML = "html"
    PDF = "pdf"
    FRAGMENT = "fragment"
