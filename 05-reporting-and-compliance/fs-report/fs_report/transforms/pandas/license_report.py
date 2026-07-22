"""
Pandas transform for the License Report.

Groups components by license, classifies into risk categories
(Permissive, Weak Copyleft, Strong Copyleft, Proprietary/Restricted, Unknown),
and produces chart-ready data plus a tabular breakdown.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Any

import pandas as pd

from fs_report.transforms.pandas.component_list import COPYLEFT_LOOKUP

logger = logging.getLogger(__name__)

# Categories in display order (highest risk first)
RISK_CATEGORIES = [
    "Strong Copyleft",
    "Weak Copyleft",
    "Proprietary/Restricted",
    "Unknown",
    "Permissive",
]

CATEGORY_COLORS = {
    "Strong Copyleft": "#d32f2f",
    "Weak Copyleft": "#f57c00",
    "Proprietary/Restricted": "#7b1fa2",
    "Unknown": "#757575",
    "Permissive": "#388e3c",
}

# Map internal COPYLEFT_LOOKUP values to display categories
_CLASSIFICATION_MAP = {
    "STRONG_COPYLEFT": "Strong Copyleft",
    "WEAK_COPYLEFT": "Weak Copyleft",
    "PERMISSIVE": "Permissive",
}

# Map the API's copyleftFamily enum (returned in `*LicenseDetails[].copyleftFamily`)
# to display categories. This is the same source of truth the platform UI uses.
# Verified enum on adamd: 'PERMISSIVE', 'COPYLEFT_WEAK', 'COPYLEFT_STRONG' (note the
# permissive value has no COPYLEFT_ prefix).
_API_COPYLEFT_FAMILY_MAP = {
    "COPYLEFT_STRONG": "Strong Copyleft",
    "COPYLEFT_WEAK": "Weak Copyleft",
    "PERMISSIVE": "Permissive",
    # Forward-compat aliases in case the API ever flips the prefix order.
    "STRONG_COPYLEFT": "Strong Copyleft",
    "WEAK_COPYLEFT": "Weak Copyleft",
}


def _extract_url_from_details(comp: dict[str, Any]) -> str:
    """Return the platform-provided license reference URL for a component
    (``licenseDetails[].url``), or '' when the platform carries none.

    This is REAL platform data — the same field Component List surfaces.
    Precedence mirrors ``_extract_policy_from_details``: concluded > declared >
    generic; the first detail carrying a non-empty ``url`` wins. The caller
    (``_flatten_component``) ORs this with ``_synthesize_license_url`` so a
    licensed component still gets a canonical SPDX reference when the platform
    carries no URL — see that function.
    """
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        details = comp.get(field)
        if not isinstance(details, list):
            continue
        for ld in details:
            if isinstance(ld, dict):
                url = ld.get("url")
                if isinstance(url, str) and url.strip():
                    return url.strip()
    return ""


# A single SPDX-style identifier (letters/digits/.-+, no spaces/separators).
_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9.\-+]+$")


def _synthesize_license_url(license_name: Any) -> str:
    """Canonical SPDX reference page for a *recognized* single SPDX id, else ''.

    Only emits a link for an id we're confident is a real SPDX identifier with a
    ``spdx.org/licenses/<id>.html`` page: a known license from ``COPYLEFT_LOOKUP``
    OR a versioned id (contains a digit, e.g. ``Apache-2.0`` /
    ``GPL-2.0-with-classpath-exception``). Free-text single words (``Proprietary``,
    ``Commercial``), custom ``LicenseRef-*`` ids, the deprecated trailing-``+``
    form, and compound expressions (``MIT OR Apache-2.0``) get no URL — so we
    never emit a dead link. Uncommon digit-less ids not in the table stay blank
    (a blank beats a 404); the platform ``licenseDetails[].url`` still covers them
    when the platform carries one.

    For a ``<license> WITH <exception>`` token (the spaced SPDX form, e.g.
    ``GPL-2.0-only WITH Linux-syscall-note``) the exception has no standalone
    SPDX page, so we synthesize the **base license's** page — a sub-license of a
    compound expression still gets a link instead of a dangling empty line.
    """
    name = str(license_name or "").strip()
    # Spaced "<license> WITH <exception>" → link the base license only.
    if re.search(r"\s+WITH\s+", name, re.IGNORECASE):
        name = re.split(r"\s+WITH\s+", name, maxsplit=1, flags=re.IGNORECASE)[0].strip()
    if not name or not _SPDX_ID_RE.match(name):
        return ""
    if name.startswith("LicenseRef-") or name.endswith("+"):
        return ""
    if name in COPYLEFT_LOOKUP or any(ch.isdigit() for ch in name):
        return f"https://spdx.org/licenses/{name}.html"
    return ""


# Tenant license-policy enum → display label. NONE = a known license with no
# policy assigned; unmapped/absent → blank (unknown or no license).
_POLICY_DISPLAY = {
    "PERMITTED": "Permitted",
    "WARNING": "Warning",
    "VIOLATION": "Violation",
    "NONE": "None",
}

# Severity of the RAW policy enum, for picking the most-severe policy among a
# component's license-detail entries (a dual-licensed component must report its
# worst policy, matching Component List's most-restrictive selection).
_POLICY_RAW_SEVERITY = {"VIOLATION": 4, "WARNING": 3, "PERMITTED": 2, "NONE": 1}

# Policy-distribution chart buckets (severity-first) + colors. Anything that
# isn't a Permitted/Warning/Violation policy (a NONE policy, an unmapped license,
# or no license) collapses into "Unknown". Colors mirror the risk chart palette.
POLICY_CHART_ORDER = ["Violation", "Warning", "Permitted", "Unknown"]
POLICY_CHART_COLORS = {
    "Violation": "#d32f2f",
    "Warning": "#f57c00",
    "Permitted": "#388e3c",
    "Unknown": "#757575",
}

# Severity ordering for aggregating a per-LICENSE policy from its components
# (summary table + chart): the most severe status a license's components carry
# represents the license. "None" (a known no-policy license) ranks ABOVE blank
# (no license / unresolved) so an all-None license summarizes as "None", not "".
_POLICY_SEVERITY = {"Violation": 4, "Warning": 3, "Permitted": 2, "None": 1, "": 0}


def _most_severe_policy(statuses: Any) -> str:
    """Return the most severe policy-status label from an iterable (or '')."""
    best = ""
    for s in statuses:
        if _POLICY_SEVERITY.get(str(s), 0) > _POLICY_SEVERITY.get(best, 0):
            best = str(s)
    return best


# Risk-category severity for picking the most-severe (worst-case) risk among a
# compound expression's sub-licenses — an "A AND B" component must report the
# worst of the two, mirroring the most-severe policy selection. Unknown ranks
# above Permissive (an unclassified license is riskier than a known-permissive
# one).
_RISK_SEVERITY = {
    "Strong Copyleft": 5,
    "Weak Copyleft": 4,
    "Proprietary/Restricted": 3,
    "Unknown": 2,
    "Permissive": 1,
    "": 0,
}


def _most_severe_risk(risks: Any) -> str:
    """Return the most severe risk-category label from an iterable (or '')."""
    best = ""
    best_sev = -1
    for r in risks:
        sev = _RISK_SEVERITY.get(str(r), 0)
        if sev > best_sev:
            best_sev = sev
            best = str(r)
    return best


# Licenses that impose NO attribution obligation; everything else defaults to
# "attribution required". Compared case-insensitively against each SPDX token —
# "CC0" covers both the bare alias and the canonical "CC0-1.0" id.
_NO_ATTRIBUTION_LICENSES = {"0BSD", "MIT-0", "CC0", "CC0-1.0", "UNLICENSE"}


def _is_no_attribution(token: Any) -> bool:
    return str(token).strip().upper() in _NO_ATTRIBUTION_LICENSES


def _attribution_required(tokens: list[str]) -> str:
    """Attribution-required label ("TRUE" / "FALSE" / "") for the license(s)
    that govern a row. Attribution is required UNLESS every governing license
    is a no-attribution license (0BSD / MIT-0 / CC0 / Unlicense). A row with no
    license at all yields "" (nothing to assert)."""
    real = [t for t in tokens if str(t).strip()]
    if not real:
        return ""
    return "FALSE" if all(_is_no_attribution(t) for t in real) else "TRUE"


# SPDX license expressions join sub-licenses with the AND / OR / WITH operators.
# _EXPR_OP_RE detects/splits on AND / OR only (WITH binds an exception to its
# license and stays attached). Operators require surrounding whitespace so
# hyphenated ids like "GPL-2.0-or-later" (embedding a lowercase "or") never
# split. Used for compound detection + the malformed-input flat fallback; the
# authoritative path is _tokenize_expression + _parse_expression.
_EXPR_OP_RE = re.compile(r"\s+(?:AND|OR)\s+", re.IGNORECASE)
_WITH_RE = re.compile(r"\s+WITH\s+", re.IGNORECASE)


def _looks_like_spdx_token(token: str) -> bool:
    """True if *token* is shaped like a single SPDX license id (optionally with
    a trailing ``WITH <exception>``).

    Distinguishes a real SPDX operand from free-text prose that merely contains
    the English words "or"/"and" (e.g. the PyPI/Trove classifier
    ``GNU Library General Public License v2 or later (LGPLv2+)``). SPDX ids carry
    no internal whitespace, so a multi-word operand is prose, not a sub-license.

    Known limitation: a short single free-text word (``Commercial``) is
    indistinguishable in shape from a real short id (``MIT``/``ISC``), so
    single-word-on-both-sides prose (``Commercial or Proprietary``) still reads
    as compound. Tightening further would risk rejecting real unversioned ids.
    """
    base = _WITH_RE.split(token, maxsplit=1)[0].strip()
    return bool(base) and bool(_SPDX_ID_RE.match(base))


def _tokenize_expression(text: str) -> list[str]:
    """Split an SPDX expression into ``(`` / ``)`` / ``AND`` / ``OR`` / leaf
    tokens. AND/OR are operators only when whitespace-delimited (so ids like
    ``GPL-2.0-or-later`` are one leaf); ``WITH`` and its exception glue into
    the current leaf (an exception binds to its base license)."""
    padded = str(text or "").replace("(", " ( ").replace(")", " ) ")
    out: list[str] = []
    leaf: list[str] = []

    def _flush() -> None:
        if leaf:
            out.append(" ".join(leaf))
            leaf.clear()

    for raw in padded.split():
        if raw in ("(", ")"):
            _flush()
            out.append(raw)
        elif raw.upper() in ("AND", "OR"):
            _flush()
            out.append(raw.upper())
        else:
            # license id, WITH keyword, or exception name — all glue.
            leaf.append(raw)
    _flush()
    return out


def _parse_expression(tokens: list[str]) -> tuple:
    """Recursive-descent parse of a tokenized SPDX expression into an AST.

    Grammar (lowest to highest precedence)::

        or_expr   := and_expr ( "OR"  and_expr )*
        and_expr  := term     ( "AND" term )*
        term      := "(" or_expr ")" | leaf

    Nodes are ``("leaf", token)`` / ``("and", [child, ...])`` /
    ``("or", [child, ...])``. Raises ``ValueError`` on malformed input
    (empty, unbalanced parens, dangling/leading operators, trailing tokens).
    """
    if not tokens:
        raise ValueError("empty expression")
    pos = 0

    def _peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def _advance() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def _parse_or() -> tuple:
        children = [_parse_and()]
        while _peek() == "OR":
            _advance()
            children.append(_parse_and())
        return children[0] if len(children) == 1 else ("or", children)

    def _parse_and() -> tuple:
        children = [_parse_term()]
        while _peek() == "AND":
            _advance()
            children.append(_parse_term())
        return children[0] if len(children) == 1 else ("and", children)

    def _parse_term() -> tuple:
        tok = _peek()
        if tok is None:
            raise ValueError("unexpected end of expression")
        if tok == "(":
            _advance()
            node = _parse_or()
            if _peek() != ")":
                raise ValueError("unbalanced parentheses")
            _advance()
            return node
        if tok in ("AND", "OR", ")"):
            raise ValueError(f"unexpected token: {tok}")
        return ("leaf", _advance())

    node = _parse_or()
    if pos != len(tokens):
        raise ValueError("trailing tokens after expression")
    return node


def _is_compound_expression(text: str) -> bool:
    """True iff the string carries a whitespace-delimited AND/OR operator."""
    return bool(_EXPR_OP_RE.search(str(text or "")))


def _flat_fallback_tokens(text: str) -> list[str]:
    """Parens-stripped flat split on AND/OR — the pre-parser behavior, used
    only when :func:`_parse_expression` rejects a malformed string so a report
    still renders (worst-of all tokens) instead of crashing."""
    cleaned = str(text or "").replace("(", " ").replace(")", " ")
    return [t.strip() for t in _EXPR_OP_RE.split(cleaned) if t.strip()]


def _has_spdx_operands(text: str) -> bool:
    """True iff every leaf of the tokenized expression is SPDX-id-shaped.

    Guards compound handling against free-text prose that merely contains a
    lowercase English "or"/"and" (which ``_EXPR_OP_RE`` would otherwise treat
    as an operator): such a string keeps its ``license_name`` verbatim instead
    of being split/mangled into fake sub-licenses."""
    leaves = [t for t in _tokenize_expression(text) if t not in ("(", ")", "AND", "OR")]
    return bool(leaves) and all(_looks_like_spdx_token(leaf) for leaf in leaves)


def _build_license_detail_map(comp: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Map ``spdx_lower -> {policy, copyleftFamily, url}`` from a component's
    license-detail arrays so a compound expression's sub-licenses can each be
    resolved to their own policy / risk / URL. Precedence mirrors the other
    extractors (concluded > declared > generic): the first array to carry a
    given SPDX id wins."""
    out: dict[str, dict[str, str]] = {}
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        details = comp.get(field)
        if not isinstance(details, list):
            continue
        for ld in details:
            if not isinstance(ld, dict):
                continue
            spdx = ld.get("spdx") or ld.get("license") or ld.get("name")
            if not (isinstance(spdx, str) and spdx.strip()):
                continue
            key = spdx.strip().lower()
            if key in out:
                continue
            out[key] = {
                "policy": (
                    ld["policy"].strip() if isinstance(ld.get("policy"), str) else ""
                ),
                "copyleftFamily": (
                    ld["copyleftFamily"].strip()
                    if isinstance(ld.get("copyleftFamily"), str)
                    else ""
                ),
                "url": ld["url"].strip() if isinstance(ld.get("url"), str) else "",
            }
    return out


def _resolve_sub_license(
    token: str, detail_map: dict[str, dict[str, str]], policies: dict[str, str]
) -> dict[str, str]:
    """Resolve one sub-license token to ``{token, policy, risk, url}``.

    Prefers the platform's per-license detail (policy / copyleftFamily / url),
    then falls back to the tenant config map for policy, the SPDX copyleft
    lookup for risk, and a synthesized SPDX reference for the URL.

    Policy / risk / detail lookups key on the BASE license — any
    ``WITH <exception>`` is stripped first (as ``_synthesize_license_url``
    already does for the URL). Otherwise a spaced leaf like
    ``GPL-2.0-only WITH Classpath-exception-2.0`` misses ``COPYLEFT_LOOKUP`` /
    the config map / ``detail_map`` and silently classifies as Unknown/blank,
    hiding the base license's copyleft risk. The displayed ``token`` keeps the
    full ``WITH`` form.
    """
    base = _WITH_RE.split(token, maxsplit=1)[0].strip() or token.strip()
    # Base-keyed detail first: the platform keys licenseDetails by the base id,
    # and preferring it avoids an incomplete WITH-form entry masking the base's
    # policy/copyleftFamily.
    d = detail_map.get(base.lower()) or detail_map.get(token.strip().lower(), {})
    pol_raw = d.get("policy", "")
    policy = (
        _POLICY_DISPLAY.get(pol_raw.upper(), "")
        if pol_raw
        else _policy_status(base, policies)
    )
    risk = _classify_from_copyleft_family(
        d.get("copyleftFamily", "")
    ) or _classify_license(base)
    # Synthesize from the base id (WITH-stripped) so the link is correct even
    # if _synthesize_license_url's own WITH handling ever changes.
    url = d.get("url", "") or _synthesize_license_url(base)
    return {"token": token, "policy": policy, "risk": risk, "url": url}


def _evaluate_worst_case(
    node: tuple, detail_map: dict[str, dict[str, str]], policies: dict[str, str]
) -> list[dict[str, str]]:
    """Return the worst-case *governing set* of resolved sub-licenses for an
    AST node. A leaf resolves to itself; ``AND`` unions its children (every
    branch applies); ``OR`` returns the single child whose set has the worst
    aggregate ``(policy severity, then risk severity)`` — you would pick the
    worst option, and its whole AND-group's obligations come with it."""
    kind = node[0]
    if kind == "leaf":
        return [_resolve_sub_license(node[1], detail_map, policies)]
    child_sets = [
        _evaluate_worst_case(child, detail_map, policies) for child in node[1]
    ]
    if kind == "and":
        return [resolved for child_set in child_sets for resolved in child_set]

    # "or": the child set with the worst aggregate severity.
    def _aggregate(child_set: list[dict[str, str]]) -> tuple[int, int]:
        return (
            max(_POLICY_SEVERITY.get(r["policy"], 0) for r in child_set),
            max(_RISK_SEVERITY.get(r["risk"], 0) for r in child_set),
        )

    return max(child_sets, key=_aggregate)


def _policy_status(license_name: Any, policies: dict[str, str]) -> str:
    """Map a license to its policy status via the tenant's license policies.

    ``policies`` is ``{spdx_lower: POLICY}`` (from
    ``/public/v0/config/licensePolicies``, threaded by the engine). Lookup is
    case-insensitive on the SPDX id. Returns '' when there's no license, no
    policy map, or the license isn't a single id present in the map (e.g. a
    free-text name or a compound expression).
    """
    name = str(license_name or "").strip()
    if not name or not policies:
        return ""
    pol = policies.get(name.lower())
    return _POLICY_DISPLAY.get(str(pol or "").upper(), "") if pol else ""


def _extract_policy_from_details(comp: dict[str, Any]) -> str:
    """Pull the platform's RESOLVED per-component policy from a component's
    license-detail arrays (raw enum, or '' when none carry a policy).

    This is the authoritative value the platform UI shows — it handles deprecated
    SPDX ids and per-component overrides the tenant config map can't (e.g. the
    deprecated ``LGPL-2.0`` id is ``NONE`` in the config map but resolves to
    ``VIOLATION`` here via ``copyleftFamily``). Precedence mirrors
    ``_extract_copyleft_family``: concluded > declared > generic.
    """
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        details = comp.get(field)
        if not isinstance(details, list):
            continue
        # Most-severe policy WITHIN this detail array (a dual-licensed component
        # reports its worst policy). Precedence across arrays is concluded >
        # declared > generic: the first array that carries any policy wins.
        best = ""
        best_sev = 0
        for ld in details:
            if isinstance(ld, dict):
                pol = ld.get("policy")
                if isinstance(pol, str) and pol.strip():
                    sev = _POLICY_RAW_SEVERITY.get(pol.strip().upper(), 0)
                    if sev > best_sev:
                        best_sev = sev
                        best = pol.strip()
        if best:
            return best
    return ""


def _component_policy_status(
    policy_raw: str, license_name: Any, policies: dict[str, str]
) -> str:
    """Per-component policy status (display label).

    Prefer the platform's RESOLVED per-component policy (``licenseDetails.policy``
    → ``policy_raw``); fall back to the tenant config map keyed by SPDX id when
    the component carries no per-component policy (e.g. a version-scoped fetch
    whose ``licenseDetails`` is empty). '' when neither yields a policy.
    """
    if policy_raw:
        return _POLICY_DISPLAY.get(policy_raw.upper(), "")
    return _policy_status(license_name, policies)


def _classify_license(name: str) -> str:
    """Classify a license SPDX identifier into a risk category.

    Used as a fallback when the API doesn't surface a copyleftFamily for the
    component (e.g. components without licenseDetails arrays). When
    licenseDetails IS present, prefer `_classify_from_copyleft_family` which
    matches the platform UI exactly.
    """
    if not name or name.strip() == "":
        return "Unknown"
    classification = COPYLEFT_LOOKUP.get(name.strip())
    if classification:
        return _CLASSIFICATION_MAP.get(classification, "Unknown")
    # Heuristic fallback for non-SPDX names
    upper = name.upper()
    if any(kw in upper for kw in ("PROPRIETARY", "COMMERCIAL", "RESTRICTED", "EULA")):
        return "Proprietary/Restricted"
    return "Unknown"


def _classify_from_copyleft_family(copyleft_family: str) -> str:
    """Map the API's copyleftFamily enum to a display risk category, or '' if
    the value is unrecognised / empty."""
    if not copyleft_family:
        return ""
    return _API_COPYLEFT_FAMILY_MAP.get(copyleft_family.strip(), "")


def _extract_copyleft_family(comp: dict[str, Any]) -> str:
    """Pull the API's copyleftFamily classification from a component record.

    Precedence mirrors `_extract_license_string` and component_list.py's
    `_best_license_details`: concluded > declared > generic. Returns the raw
    enum value (e.g. 'COPYLEFT_STRONG') or '' if no license-detail array on
    the record carries a copyleftFamily.
    """
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        details = comp.get(field)
        if not isinstance(details, list):
            continue
        for ld in details:
            if isinstance(ld, dict):
                cf = ld.get("copyleftFamily")
                if isinstance(cf, str) and cf.strip():
                    return cf.strip()
    return ""


def _coerce_license_value(val: Any) -> str:
    """Normalise a license field value into a comma-joined SPDX string.

    Handles four real-world shapes returned by /public/v0/components:
      - plain string ("Sleepycat", "MIT OR Apache-2.0")
      - list of strings (["MIT", "Apache-2.0"])
      - list of dicts with `spdx` / `license` / `name` keys
        (e.g. [{"spdx": "Sleepycat", "name": "Sleepycat License"}])
      - None / NaN / non-iterable scalars → ""
    """
    import math

    if val is None:
        return ""
    if isinstance(val, float):
        if math.isnan(val):
            return ""
        return str(val).strip()
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, list):
        parts: list[str] = []
        for item in val:
            if isinstance(item, str):
                if item.strip():
                    parts.append(item.strip())
            elif isinstance(item, dict):
                # Match the precedence used by component_list.extract_licenses_summary
                # plus a `name` fallback for the {"name": "Sleepycat"} shape.
                spdx = item.get("spdx") or item.get("license") or item.get("name") or ""
                if isinstance(spdx, str) and spdx.strip():
                    parts.append(spdx.strip())
        return ", ".join(parts)
    return str(val).strip()


def _extract_license_string(comp: dict[str, Any]) -> str:
    """Pull the best available license string from a component record.

    Precedence mirrors fs_report.transforms.pandas.component_list (and
    customer_brief): user-curated `concludedLicenses` wins over auto-detected
    `declaredLicenses`, with `licenses` (legacy) and the structured
    `*LicenseDetails` arrays as fallbacks. The field-precedence rationale
    is documented in `sqlite_cache.py` ("User-specified licenses (takes
    precedence)") and `component_list.py::_best_license_details`.
    """
    for field in ("concludedLicenses", "declaredLicenses", "licenses"):
        s = _coerce_license_value(comp.get(field))
        if s:
            return s
    # Singular variants kept for backward compat with older fixtures.
    for field in ("declaredLicense", "license"):
        s = _coerce_license_value(comp.get(field))
        if s:
            return s
    # Structured-array fallback — concluded > declared > generic.
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        s = _coerce_license_value(comp.get(field))
        if s:
            return s
    return ""


def _flatten_component(
    comp: dict[str, Any], policies: dict[str, str] | None = None
) -> dict[str, str]:
    """Extract license fields and project info from a raw component record.

    Handles SPDX compound expressions (``A AND B`` / ``A OR B``):
    - ``license_expression`` carries the full compound string, or mirrors the
      single license when there's no AND/OR (blank only when unlicensed);
    - ``license_display`` is what the License column shows — both sub-licenses
      (one per line) for ``AND``, or the most-restrictive branch for ``OR``
      (you satisfy only one, so the risk is the worst option you might pick —
      a single sub-license for a simple ``A OR B``, but the whole winning
      AND-group, multiple lines, for a grouped branch like ``(A AND B) OR C``,
      so co-obligations are never dropped);
    - ``license_url`` mirrors that (one or more URLs, one per line, matching
      whatever ``license_display`` shows);
    - ``risk_category`` / ``policy_status`` are the worst case across the
      governing sub-licenses.
    """
    policies = policies or {}
    license_name = _extract_license_string(comp)
    # Compound only when a real SPDX operator joins SPDX-id-shaped operands —
    # free-text prose with a lowercase English "or"/"and" stays a single
    # verbatim license instead of being split into fake sub-licenses.
    is_compound = _is_compound_expression(license_name) and _has_spdx_operands(
        license_name
    )

    # Component-level (single-license) resolution — the authoritative platform
    # values used verbatim when the license is a single SPDX id.
    copyleft_family = _extract_copyleft_family(comp)
    # Classify/policy off the BASE license id — strip any "WITH <exception>"
    # (as _synthesize_license_url already does for the URL). Otherwise a
    # STANDALONE spaced token like "GPL-2.0-only WITH Linux-syscall-note"
    # (common, e.g. OpenJDK) misses COPYLEFT_LOOKUP / the config map and
    # under-reports as Unknown/blank, hiding its copyleft risk.
    license_base = _WITH_RE.split(license_name, maxsplit=1)[0].strip() or license_name
    base_risk = _classify_from_copyleft_family(copyleft_family) or _classify_license(
        license_base
    )
    base_policy = _component_policy_status(
        _extract_policy_from_details(comp), license_base, policies
    )
    base_url = _extract_url_from_details(comp) or _synthesize_license_url(license_name)

    if not is_compound:
        # A single license carries no AND/OR expression; mirror the License
        # value into License Expression so the column is never blank for a
        # licensed component (blank only when there's no license at all).
        expression = license_name
        license_display = license_name
        url_display = base_url
        risk_category = base_risk
        policy_status = base_policy
        attribution = _attribution_required([license_name])
    else:
        # Unconcluded compound expression -> worst case. Parse to an AST that
        # honors parentheses + SPDX precedence (OR < AND < WITH/leaf), then
        # take the worst-case governing set. Malformed strings degrade to the
        # flat worst-of-all-tokens behavior rather than crash the report.
        detail_map = _build_license_detail_map(comp)
        try:
            governing = _evaluate_worst_case(
                _parse_expression(_tokenize_expression(license_name)),
                detail_map,
                policies,
            )
        except ValueError:
            governing = [
                _resolve_sub_license(t, detail_map, policies)
                for t in _flat_fallback_tokens(license_name)
            ]
        expression = license_name
        license_display = "\n".join(r["token"] for r in governing)
        url_display = "\n".join(r["url"] for r in governing)
        risk_category = _most_severe_risk(r["risk"] for r in governing)
        policy_status = _most_severe_policy(r["policy"] for r in governing)
        attribution = _attribution_required([r["token"] for r in governing])

    # Extract project name from nested dict or flat field
    project = comp.get("project", {})
    if isinstance(project, dict):
        project_name = project.get("name", "")
    else:
        project_name = comp.get("project.name", "")

    return {
        "component_name": comp.get("name", ""),
        "component_version": comp.get("version", ""),
        # Raw license string — the grouping/filtering key (a compound expression
        # groups as its own row).
        "license_name": license_name,
        # Full compound expression (with AND/OR), or the single license mirrored
        # in; blank only for an unlicensed component.
        "license_expression": expression,
        # What the License column shows (see docstring).
        "license_display": license_display,
        "risk_category": risk_category,
        "policy_status": policy_status,
        # "True" / "False" / "" — attribution obligation for the row.
        "attribution_required": attribution,
        # License reference URL(s): platform ``licenseDetails[].url`` when
        # present, else a synthesized canonical SPDX reference; newline-joined
        # for an AND expression so a licensed component always carries a link.
        "license_url": url_display,
        "project_name": str(project_name),
        # Per-component folder breadcrumb (root->leaf) injected by the engine's
        # _inject_folder_names_df(column="folder_breadcrumb") for folder/portfolio
        # (multi-project) runs — lets the Folder column show each row's OWN folder
        # so same-named projects across folders are distinguishable.
        "folder_breadcrumb": str(comp.get("folder_breadcrumb", "") or ""),
    }


def license_report_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform component data into a license risk report.

    Args:
        data: Raw component data from the API (list of dicts or DataFrame).
        config: Optional config object.
        additional_data: Dict with 'config', etc.

    Returns:
        Dict with keys for the Jinja2 template context:
          - main: DataFrame for CSV/XLSX export
          - license_table: list of dicts for the HTML table
          - risk_pie: dict for Chart.js pie chart
          - category_summary: dict of category → count
          - total_components: int
          - total_licenses: int
    """
    additional_data = additional_data or {}

    # Convert to list of dicts
    records: list[dict[str, Any]] = []
    if isinstance(data, pd.DataFrame):
        if not data.empty:
            records = data.to_dict("records")  # type: ignore[assignment]
    elif isinstance(data, list):
        records = data

    if not records:
        return _empty_result()

    # Tenant license-policy map ({spdx_lower: POLICY}, from
    # /public/v0/config/licensePolicies), threaded by the engine — needed to
    # resolve each sub-license of a compound expression.
    _policies = additional_data.get("license_policies") or {}

    # Flatten + classify (expression-aware). risk_category, per-component
    # policy_status, the License-Expression/License split, URL(s), and the
    # Attribution Required flag are all computed per component in
    # _flatten_component and reused by the detail table, the summary
    # (aggregated most-severe per license), and the policy chart.
    rows: list[dict[str, Any]] = [
        _flatten_component(comp, _policies) for comp in records
    ]

    df = pd.DataFrame(rows)

    # Apply component filter if configured
    cfg = config or (additional_data.get("config") if additional_data else None)
    component_filter = getattr(cfg, "component_filter", None) if cfg else None
    if component_filter:
        from fs_report.transforms.pandas._component_filter import (
            apply_component_filter,
        )

        match_mode = getattr(cfg, "component_match", "contains")
        df = apply_component_filter(
            df,
            component_filter,
            match_mode=match_mode,
            name_col="component_name",
            version_col="component_version",
        )

    # Apply license filter (case-insensitive substring, comma-separated terms)
    license_filter = getattr(cfg, "license_filter", None) if cfg else None
    if license_filter:
        terms = [t.strip().lower() for t in str(license_filter).split(",") if t.strip()]
        if terms:
            df = df[
                df["license_name"]
                .str.lower()
                .apply(lambda name: any(t in name for t in terms))
            ].reset_index(drop=True)
            logger.info(
                f"License report: filtered to {len(df)} components "
                f"matching license terms {terms}"
            )

    logger.info(f"License report: {len(df)} components")

    # Sanity check: warn if a large fraction of components have no license
    # after extraction. This is the canary for the next regression where the
    # API adds a new license field we don't read (cf. concludedLicenses miss
    # before this code path).
    if len(df) > 0:
        empty_frac = float((df["license_name"] == "").sum()) / len(df)
        if empty_frac > 0.10:
            logger.debug(
                f"License report: {empty_frac:.0%} of components have no "
                f"license after extraction. If this looks wrong, verify the "
                f"API still surfaces licenses under concludedLicenses / "
                f"declaredLicenses / licenseDetails."
            )

    # Per-license policy (most severe across the license's components), for the
    # summary table + chart so they agree with the per-component detail rows.
    # Computed from the POST-filter df so a --component/--license filtered export
    # never shows a policy derived from components no longer in the result set.
    _license_policy_by_name = {
        str(k): str(v)
        for k, v in df.groupby("license_name")["policy_status"]
        .agg(_most_severe_policy)
        .to_dict()
        .items()
    }

    # --- License table: group by license ---
    # NOTE: risk_category / license_display / attribution_required use "first"
    # (a summary approximation), while the group's Policy Status below is
    # RECOMPUTED as most-severe across all of the group's components. So for
    # the rare case where two components share the same compound expression
    # string but carry divergent per-component licenseDetails, this row's
    # displayed License/Risk may reflect a different component than its
    # Policy Status. The detail table is authoritative per-component.
    license_groups = (
        df.groupby("license_name")
        .agg(
            component_count=("component_name", "count"),
            risk_category=("risk_category", "first"),
            # Expression-aware display fields (identical within a license group,
            # since the group key IS the raw license string) — "first" is safe.
            license_expression=("license_expression", "first"),
            license_display=("license_display", "first"),
            attribution_required=("attribution_required", "first"),
            projects=(
                "project_name",
                lambda x: ", ".join(sorted({str(v) for v in x if v})),
            ),
            # License URL for the group: prefer a real platform licenseDetails[].url
            # over a synthesized spdx.org reference (deterministic, not first-in-
            # group order), so the summary link matches the detail's best link.
            license_url=(
                "license_url",
                lambda s: next(
                    (
                        str(v)
                        for v in s
                        if v and not str(v).startswith("https://spdx.org/licenses/")
                    ),
                    next((str(v) for v in s if v), ""),
                ),
            ),
        )
        .reset_index()
        .sort_values("component_count", ascending=False)
    )

    # Policy status per license for the HTML summary table (license_url is
    # aggregated above — platform licenseDetails[].url preferred, else a
    # synthesized SPDX reference).
    license_groups["license_policy"] = (
        license_groups["license_name"].map(_license_policy_by_name).fillna("")
    )

    license_table = license_groups.to_dict("records")

    # --- Category summary for KPIs ---
    category_counts: Counter[str] = Counter()
    for _, row in df.iterrows():
        category_counts[row["risk_category"]] += 1

    # --- Risk pie chart ---
    pie_labels = []
    pie_data = []
    pie_colors = []
    for cat in RISK_CATEGORIES:
        count = category_counts.get(cat, 0)
        if count > 0:
            pie_labels.append(cat)
            pie_data.append(count)
            pie_colors.append(CATEGORY_COLORS.get(cat, "#757575"))

    risk_pie = {
        "labels": pie_labels,
        "data": pie_data,
        "backgroundColor": pie_colors,
    }

    # --- Policy status pie chart ---
    # Count the per-component policy status (computed above), collapsed into the
    # four display buckets (Violation / Warning / Permitted / Unknown — where
    # Unknown = a NONE policy, unmapped license, or no license).
    policy_counts: Counter[str] = Counter()
    for status in df["policy_status"]:
        bucket = (
            status if status in ("Permitted", "Warning", "Violation") else "Unknown"
        )
        policy_counts[bucket] += 1
    policy_labels: list[str] = []
    policy_data: list[int] = []
    policy_colors: list[str] = []
    for status in POLICY_CHART_ORDER:
        count = policy_counts.get(status, 0)
        if count > 0:
            policy_labels.append(status)
            policy_data.append(count)
            policy_colors.append(POLICY_CHART_COLORS[status])
    policy_pie = {
        "labels": policy_labels,
        "data": policy_data,
        "backgroundColor": policy_colors,
    }

    # --- Build main DataFrame for CSV/XLSX ---
    # Column order: License Expression (the compound AND/OR string, before
    # License) → License (resolved display) → Policy Status → Attribution
    # Required (after Policy Status) → URL → Risk Category → counts.
    main_df = pd.DataFrame(
        {
            "License Expression": license_groups["license_expression"],
            "License": license_groups["license_display"],
            "Policy Status": license_groups["license_name"]
            .map(_license_policy_by_name)
            .fillna(""),
            "Attribution Required": license_groups["attribution_required"],
            "URL": license_groups["license_url"],
            "Risk Category": license_groups["risk_category"],
            "Component Count": license_groups["component_count"],
            "Projects": license_groups["projects"],
        }
    )

    # --- Detail DataFrame: one row per component
    #     (License × Folder × Project × Component) ---
    # A version-scoped fetch returns components WITHOUT a per-record project, so
    # fall back to the resolved scope project name (threaded by the engine as
    # ``additional_data["project_name"]``) — otherwise the Project column is
    # blank for a single-project run. The Folder column is PER-COMPONENT: a
    # folder/portfolio (multi-project) run shows each row's own project folder
    # breadcrumb (root->leaf, injected by the engine as ``folder_breadcrumb``);
    # a single-project / version-scoped run has none per-component, so its rows
    # fall back to the scoped project's breadcrumb. Both are root->leaf, so the
    # column reads consistently across scopes.
    scope_project = str(additional_data.get("project_name") or "")
    # Scope-level breadcrumb LIST, threaded by the engine under
    # ``folder_path_parts`` (NOT ``folder_path`` — that key is a STRING top-level
    # template var; reusing it let the list clobber the string in shared chrome).
    _folder_path = additional_data.get("folder_path_parts")
    folder_disp = (
        " > ".join(str(p) for p in _folder_path)
        if isinstance(_folder_path, list)
        else (str(_folder_path) if _folder_path else "")
    )
    project_col = df["project_name"].apply(lambda v: str(v) if v else scope_project)
    # Folder column: prefer each row's OWN per-component folder breadcrumb (engine
    # injects it for folder/portfolio runs); fall back to the scope-level
    # breadcrumb for single-project / version-scoped runs. The column-presence
    # guard covers callers that never route through the engine injection.
    # When the engine injected per-project folders (a multi-project run — at
    # least one row resolved to a folder), the Folder column is PER-COMPONENT and
    # an unmapped row is BLANK (do NOT borrow the scope path — it would
    # mis-attribute the component to the query folder). When NO per-component
    # folder was injected (single-project / version-scoped run), the scope-level
    # breadcrumb applies to every row. The flattener always adds the column (as
    # ""), so gate on whether ANY value is populated, not on column presence.
    folder_col: Any  # per-row Series, or the scope-level str (pandas broadcasts)
    _has_per_component_folder = "folder_breadcrumb" in df.columns and bool(
        df["folder_breadcrumb"].map(lambda v: bool(str(v).strip())).any()
    )
    if _has_per_component_folder:
        folder_col = df["folder_breadcrumb"].apply(lambda v: str(v) if v else "")
    else:
        folder_col = folder_disp
    # Per-component policy status (computed once above: licenseDetails.policy →
    # config-map fallback).
    policy_col = df["policy_status"]
    detail_df = (
        pd.DataFrame(
            {
                "Folder": folder_col,
                "Project": project_col,
                "Component": df["component_name"],
                "Version": df["component_version"],
                "Risk Category": df["risk_category"],
                # License Expression (compound AND/OR string) before License;
                # License shows the resolved display (both sub-licenses for AND,
                # the worst-case sub-license for OR).
                "License Expression": df["license_expression"],
                "License": df["license_display"],
                "Policy Status": policy_col,
                # Attribution Required immediately after Policy Status.
                "Attribution Required": df["attribution_required"],
                "URL": df["license_url"],
            }
        )
        .sort_values(
            by=["Folder", "Project", "Component", "Version", "License"],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )

    # No-license components
    no_license_count = int((df["license_name"] == "").sum())

    return {
        "main": main_df,
        "detail": detail_df,
        "detail_table": detail_df.to_dict("records"),
        "license_table": license_table,
        "risk_pie": risk_pie,
        "policy_pie": policy_pie,
        "category_summary": dict(category_counts),
        "total_components": len(df),
        "total_licenses": int(
            license_groups[license_groups["license_name"] != ""].shape[0]
        ),
        "no_license_count": no_license_count,
    }


def _empty_result() -> dict[str, Any]:
    return {
        "main": pd.DataFrame(),
        "detail": pd.DataFrame(),
        "detail_table": [],
        "license_table": [],
        "risk_pie": {"labels": [], "data": [], "backgroundColor": []},
        "policy_pie": {"labels": [], "data": [], "backgroundColor": []},
        "category_summary": {},
        "total_components": 0,
        "total_licenses": 0,
        "no_license_count": 0,
    }
