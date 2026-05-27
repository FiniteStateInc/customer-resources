"""Scope CSS so it can be embedded as a fragment without bleeding into siblings.

Used by ``HTMLRenderer.render_fragment()`` to prefix every selector with
``.fs-section-<slug>``. ``:root`` declarations stay global (global custom
properties). ``@keyframes`` animation-step selectors (``from`` / ``to`` /
``0%``) inside the rule body are left alone, but the keyframe **name** is
renamed to ``{scope_class}_<original>`` and matching ``animation`` /
``animation-name`` declaration values are rewritten so two fragments
can't share an animation namespace. ``html`` and ``body`` selectors map
onto the scope class itself, since the scope ``<div>`` replaces those
wrapper elements in fragment mode.

The single public entrypoint is :func:`scope_css`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import tinycss2  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# At-rules whose body is a stylesheet (rules-in-rules) — recurse for scoping.
_NESTED_STYLESHEET_AT_RULES = {"media", "supports", "document", "container"}

# At-rules whose body is keyframe selectors (0% / from / to) — leave alone.
_KEYFRAME_AT_RULES = {"keyframes", "-webkit-keyframes", "-moz-keyframes"}


def _split_selector_list(selector_text: str) -> list[str]:
    """Split a CSS selector list on top-level commas."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in selector_text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _prefix_selector(selector: str, scope_class: str) -> str:
    s = selector.strip()
    if not s:
        return s
    if s.startswith(":root"):
        return s
    for el in ("html", "body"):
        if s == el:
            return f".{scope_class}"
        if s.startswith(el):
            nxt = s[len(el) : len(el) + 1]
            if nxt in {".", "#", ":", "[", " ", ">", "+", "~", ""}:
                return f".{scope_class}{s[len(el) :]}"
    return f".{scope_class} {s}"


# Match a keyframe name in an animation declaration value, with word
# boundaries. Used to rewrite references when we rename the keyframe.
_IDENT_BOUNDARY_LEFT = r"(?<![A-Za-z0-9_-])"
_IDENT_BOUNDARY_RIGHT = r"(?![A-Za-z0-9_-])"


def _collect_keyframe_names(rules: list[Any]) -> set[str]:
    """Return the set of @keyframes names declared in ``rules``."""
    names: set[str] = set()
    for rule in rules:
        if getattr(rule, "type", None) != "at-rule":
            continue
        if rule.lower_at_keyword not in _KEYFRAME_AT_RULES:
            continue
        prelude = tinycss2.serialize(rule.prelude).strip()
        if prelude:
            # Animation name is the first token in the prelude.
            ident = prelude.split()[0]
            names.add(ident)
    return names


def _rewrite_animation_refs(body_text: str, rename_map: dict[str, str]) -> str:
    """Rewrite ``animation`` / ``animation-name`` value references.

    Only rewrites identifiers appearing in declarations whose property is
    ``animation`` or ``animation-name`` — avoids clobbering accidental
    occurrences elsewhere in the CSS body.
    """
    if not rename_map:
        return body_text

    def _rewrite_value(value: str) -> str:
        for old, new in rename_map.items():
            value = re.sub(
                _IDENT_BOUNDARY_LEFT + re.escape(old) + _IDENT_BOUNDARY_RIGHT,
                new,
                value,
            )
        return value

    decl_re = re.compile(r"(animation(?:-name)?\s*:)([^;}]*)([;}])", re.IGNORECASE)

    def repl(m: re.Match[str]) -> str:
        return f"{m.group(1)}{_rewrite_value(m.group(2))}{m.group(3)}"

    return decl_re.sub(repl, body_text)


def _scope_qualified_rule(
    rule: Any, scope_class: str, rename_map: dict[str, str]
) -> str:
    selector_text = tinycss2.serialize(rule.prelude)
    selectors = _split_selector_list(selector_text)
    scoped = ", ".join(_prefix_selector(s, scope_class) for s in selectors)
    body = tinycss2.serialize(rule.content) if rule.content is not None else ""
    body = _rewrite_animation_refs(body, rename_map)
    return f"{scoped} {{{body}}}"


def _scope_at_rule(rule: Any, scope_class: str, rename_map: dict[str, str]) -> str:
    name = rule.lower_at_keyword
    prelude_text = tinycss2.serialize(rule.prelude)
    if rule.content is None:
        return f"@{name}{prelude_text};"
    if name in _KEYFRAME_AT_RULES:
        # Rename the keyframe so concatenated fragments can't shadow each
        # other's animations.
        ident = prelude_text.strip().split()[0] if prelude_text.strip() else ""
        if ident and ident in rename_map:
            new_prelude = prelude_text.replace(ident, rename_map[ident], 1)
        else:
            new_prelude = prelude_text
        body = tinycss2.serialize(rule.content)
        return f"@{name}{new_prelude}{{{body}}}"
    if name in _NESTED_STYLESHEET_AT_RULES:
        inner = tinycss2.parse_stylesheet(
            tinycss2.serialize(rule.content),
            skip_whitespace=True,
            skip_comments=True,
        )
        return (
            f"@{name}{prelude_text}{{{_scope_rules(inner, scope_class, rename_map)}}}"
        )
    body = tinycss2.serialize(rule.content)
    body = _rewrite_animation_refs(body, rename_map)
    return f"@{name}{prelude_text}{{{body}}}"


def _scope_rules(rules: list[Any], scope_class: str, rename_map: dict[str, str]) -> str:
    out: list[str] = []
    for rule in rules:
        rtype = getattr(rule, "type", None)
        if rtype == "qualified-rule":
            out.append(_scope_qualified_rule(rule, scope_class, rename_map))
        elif rtype == "at-rule":
            out.append(_scope_at_rule(rule, scope_class, rename_map))
        elif rtype == "error":
            msg = getattr(rule, "message", "") or "tinycss2 parse error"
            logger.warning(
                "css_scoper: dropping unparseable rule (%s) under scope %r",
                msg,
                scope_class,
            )
    return "\n".join(out)


def scope_css(css: str, scope_class: str) -> str:
    """Return ``css`` with every selector scoped under ``.{scope_class}``.

    - ``:root`` declarations stay global (token custom properties).
    - ``html`` / ``body`` are replaced by the scope class.
    - ``@media`` / ``@supports`` / ``@container`` / ``@document`` inner
      rules are recursively scoped.
    - ``@keyframes`` names are renamed to ``{scope_class}_<original>``
      and any matching ``animation`` / ``animation-name`` declaration
      values are rewritten so two fragments can't share the same
      animation namespace.
    - tinycss2 parse errors are logged at WARNING and the affected rule
      is dropped.
    """
    rules = tinycss2.parse_stylesheet(css, skip_whitespace=True, skip_comments=True)
    keyframe_names = _collect_keyframe_names(rules)
    rename_map = {name: f"{scope_class}_{name}" for name in keyframe_names}
    return _scope_rules(rules, scope_class, rename_map)
