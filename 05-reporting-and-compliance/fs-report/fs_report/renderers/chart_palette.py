"""Design tokens — Python single source of truth.

This module is the canonical source for color and typography values used by
both server-side renderers (matplotlib via ChartRenderer) and browser-side
Chart.js (palette emitted into _standalone_shell.html as a script literal).

The CSS tokens at ``fs_report/static/css/tokens.css`` must mirror the values
here. ``tests/test_chart_palette.py`` asserts the two stay in sync in one
direction: CSS must match Python.

Background: ``getComputedStyle()`` works in the browser but never runs under
WeasyPrint (no JS engine). Routing the palette through Python avoids parsing
CSS at render time and keeps the matplotlib + Chart.js outputs visually
identical.
"""

from __future__ import annotations

# ── Surface (light theme; dark theme is browser-only in Phase 2) ──────────
FS_SURFACE_PAGE = "#f5f7fa"
FS_SURFACE_CARD = "#ffffff"
FS_HAIRLINE = "#e2e8f0"

# ── Ink ramp ──────────────────────────────────────────────────────────────
FS_INK = "#0f172a"
FS_INK_DIM = "#475569"
FS_INK_FAINT = "#94a3b8"

# ── Accent palette ────────────────────────────────────────────────────────
FS_ACCENT_TEAL = "#0d9488"
FS_ACCENT_CYAN = "#0891b2"
FS_ACCENT_PURPLE = "#7c3aed"
FS_ACCENT_AMBER = "#b45309"
FS_ACCENT_ROSE = "#be123c"
FS_ACCENT_GREEN = "#15803d"
FS_ACCENT_BLUE = "#1d4ed8"

# ── Nav stripes (report header accent + --serve sidebar grouping) ─────────
FS_NAV_PALETTE: dict[str, str] = {
    "executive": FS_ACCENT_TEAL,
    "investigation": FS_ACCENT_CYAN,
    "remediation": FS_ACCENT_PURPLE,
    "compliance": FS_ACCENT_AMBER,
}

# ── Severity (colorblind-friendly; Tol-derived hues) ──────────────────────
FS_SEV_PALETTE: dict[str, str] = {
    "critical": "#9f1239",
    "high": "#c2410c",
    "medium": "#b45309",
    "low": "#15803d",
    "info": "#0369a1",
}

# ── Chart palette (8-hue Tol-derived, colorblind-friendly) ────────────────
FS_CHART_PALETTE: list[str] = [
    "#0d9488",  # 1 teal
    "#0891b2",  # 2 cyan
    "#7c3aed",  # 3 purple
    "#b45309",  # 4 amber
    "#be123c",  # 5 rose
    "#15803d",  # 6 green
    "#1d4ed8",  # 7 blue
    "#475569",  # 8 slate
]

# ── Typography ────────────────────────────────────────────────────────────
FS_FONT_BODY = (
    "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, "
    "Oxygen, Ubuntu, Cantarell, sans-serif"
)
FS_FONT_DISPLAY = (
    "Manrope, Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', "
    "Roboto, sans-serif"
)
FS_FONT_MONO = (
    "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
    "'Liberation Mono', monospace"
)

# ── Resolved colors for inline style="..." attributes ─────────────────────
# CSS variables don't reliably resolve in inline style attributes across all
# DOM contexts (e.g. Slack mrkdwn output embedded in arbitrary container).
SLACK_LINK_COLOR = "#1d4ed8"


# ── Non-color tokens (mirrored to tokens.css; asserted by
#     tests/test_chart_palette.py to prevent drift) ─────────────────────────
#
# These don't drive matplotlib (which has its own units), but they're the
# canonical values the CSS uses; keeping them here lets the drift test
# catch a typo in tokens.css that the SHA-only check would miss.

# Type scale (rem-based, mirrors --fs-* tokens)
FS_TYPE_SCALE: dict[str, str] = {
    "xs": "0.75rem",
    "sm": "0.875rem",
    "base": "1rem",
    "lg": "1.125rem",
    "xl": "1.25rem",
    "2xl": "1.5rem",
    "3xl": "1.875rem",
    "4xl": "2.25rem",
}

# Spacing scale (4px base, mirrors --sp-* tokens)
FS_SPACING: dict[str, str] = {
    "1": "4px",
    "2": "8px",
    "3": "12px",
    "4": "16px",
    "5": "24px",
    "6": "32px",
    "7": "48px",
    "8": "64px",
}

# Border radii (mirrors --r-* tokens)
FS_RADII: dict[str, str] = {
    "sm": "4px",
    "md": "8px",
    "lg": "12px",
    "xl": "20px",
}

# Motion durations (mirrors --dur-* tokens)
FS_MOTION_DURATIONS: dict[str, str] = {
    "fast": "120ms",
    "med": "240ms",
    "slow": "480ms",
    "drift": "32s",
}

# Motion easings (mirrors --ease-* tokens)
FS_MOTION_EASINGS: dict[str, str] = {
    "out": "cubic-bezier(0.16, 1, 0.3, 1)",
    "in-out": "cubic-bezier(0.65, 0, 0.35, 1)",
}

# Shadows (mirrors --shadow-* tokens, light theme)
FS_SHADOWS: dict[str, str] = {
    "soft": "0 1px 2px rgba(15, 23, 42, 0.04), 0 1px 3px rgba(15, 23, 42, 0.06)",
    "card": "0 2px 6px rgba(15, 23, 42, 0.06), 0 4px 12px rgba(15, 23, 42, 0.05)",
    "elev": "0 8px 24px rgba(15, 23, 42, 0.10), 0 4px 8px rgba(15, 23, 42, 0.04)",
}
