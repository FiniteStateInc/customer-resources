"""Canonical recipe-slug normalization.

One function, used everywhere a recipe slug or compound name appears
(argv resolution, fragment scope class, section id, output directory
name, saved YAML filename). Defined in the compound-reports design
spec at docs/superpowers/specs/2026-05-11-compound-reports-design.md
§ 7 "Canonical slug() function".

Rules, in order:

1. Lowercase the input.
2. Strip leading and trailing whitespace.
3. Map every non-alphanumeric character to ``-`` (covers space,
   underscore, ``&``, ``/``, ``.``, etc.).
4. Collapse runs of ``-`` to a single ``-``.
5. Strip leading and trailing ``-``.
6. If the result is empty (input was all punctuation/whitespace),
   return ``"section"`` as a defensive fallback so downstream
   consumers — CSS classes, HTML ids, output directory names — never
   see a trailing-hyphen or empty value like ``fs-section-``.

This makes the output safe to use in every consumer surface — CSS
class selectors, HTML ``id`` attributes, URL fragments, filesystem
paths, and YAML filenames — without further escaping. Argv tokens
like ``executive_summary``, ``Cra-Compliance``, and
``triage prioritization`` all normalize to the same hyphenated value.
"""

from __future__ import annotations

import re

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def slug(s: str) -> str:
    """Normalize ``s`` to the canonical fs-report slug form."""
    out = _NON_ALNUM_RE.sub("-", s.lower().strip()).strip("-")
    return out or "section"
