"""Pure mapping helpers for SBOM export (VEX states, sources, licences, ids)."""

from __future__ import annotations

import hashlib
import logging
import re
from decimal import Decimal
from functools import lru_cache
from typing import Any

from license_expression import get_spdx_licensing  # type: ignore[import-untyped]

log = logging.getLogger(__name__)

_STATES = {
    "not_affected",
    "false_positive",
    "exploitable",
    "resolved",
    "resolved_with_pedigree",
    "in_triage",
}
_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}
_RESPONSES = {
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available",
}
_OPENVEX = {
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "exploitable": "affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "in_triage": "under_investigation",
}
_warned: set[tuple[str, str]] = set()


def _lower_known(kind: str, value: str | None, known: set[str]) -> str | None:
    if not value:
        return None
    v = str(value).lower()
    if v in known:
        return v
    if (kind, v) not in _warned:
        _warned.add((kind, v))
        log.warning("Unknown VEX %s %r omitted from SBOM", kind, value)
    return None


def cdx_state(status: str | None) -> str | None:
    return _lower_known("state", status, _STATES)


def cdx_justification(j: str | None) -> str | None:
    return _lower_known("justification", j, _JUSTIFICATIONS)


def cdx_response(r: str | list[str] | None) -> list[str]:
    items = [r] if isinstance(r, str) else (r or [])
    out = (_lower_known("response", x, _RESPONSES) for x in items)
    return [x for x in out if x]


def openvex_status(state: str | None) -> str | None:
    return _OPENVEX.get(state.lower()) if state else None


# "Defined database prefixes" table of the OSV schema
# (https://ossf.github.io/osv-schema/#id-modified-fields, docs/schema.md at
# ossf/osv-schema main e1cced93, fetched 2026-10-22). Only these get osv.dev links.
OSV_PREFIXES = frozenset(
    {
        "ASB-A", "PUB-A", "ALSA", "ALBA", "ALEA", "ALPINE", "AZL", "BELL",
        "BIT", "BREW", "CGA", "CleanStart", "CURL", "CVE", "DEBIAN", "DHI",
        "DRUPAL", "DSA", "DLA", "DTSA", "ECHO", "EEF", "ELA", "GHSA", "GO",
        "GSD", "HSEC", "JLSEC", "KUBE", "LBSEC", "LSN", "MGASA", "MAL",
        "MINI", "OESA", "OSEC", "OSV", "PHSA", "PSF", "PYSEC", "RHSA",
        "RHBA", "RHEA", "RHLW", "RLSA", "RXSA", "RPI", "RSEC", "ROOT",
        "RUSTSEC", "SUSE-SU", "SUSE-RU", "SUSE-FU", "SUSE-OU", "openSUSE-SU",
        "UBUNTU", "USN", "V8", "VCPKG", "CLSA",
    }
)  # fmt: skip


def advisory_source(vuln_id: str) -> tuple[str, str | None]:
    """(source name, advisory URL); URL is None when no known database hosts it."""
    if vuln_id.startswith("CVE-"):
        return "NVD", f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vuln_id.startswith("GHSA-"):
        return "GitHub Advisories", f"https://github.com/advisories/{vuln_id}"
    if vuln_id.startswith("PYSEC-"):
        return "PyPA", f"https://osv.dev/vulnerability/{vuln_id}"
    if any(vuln_id.startswith(p + "-") for p in OSV_PREFIXES):
        return "OSV", f"https://osv.dev/vulnerability/{vuln_id}"
    prefix = vuln_id.split("-", 1)[0] if "-" in vuln_id else ""
    return prefix or "Finite State", None


def clean_supplier(supplier: str | None, purl: str | None) -> str | None:
    """Drop package-namespace artefacts (generic/unknown/purl type) as non-producers."""
    s = (supplier or "").strip()
    if not s or s.lower() in {"generic", "unknown"}:
        return None
    m = re.match(r"pkg:([^/]+)/", purl or "")
    if m and s.lower() == m.group(1).lower():
        return None
    return s


def split_cpes(component_json: dict[str, Any]) -> list[str]:
    cpes = [component_json.get("cpe")]
    cpes += (component_json.get("softwareIdentifiers") or {}).get("cpes") or []
    return list(dict.fromkeys(c for c in cpes if c))


def _license_text(s: str | None) -> str:
    """Strip; the SPDX keywords (any case) become NONE, or "" for NOASSERTION."""
    t = (s or "").strip()
    return {"NONE": "NONE", "NOASSERTION": ""}.get(t.upper(), t)


def license_terms(
    declared: str | None, concluded: str | None
) -> tuple[list[str], bool]:
    """Concluded wins over declared; bool is True when concluded was used.

    A platform NOASSERTION counts as no licence; NONE is kept as the keyword
    ``"NONE"`` (writers emit the format's none-licence, never a named licence).
    """
    if c := _license_text(concluded):
        return [c], True
    if d := _license_text(declared):
        return [d], False
    return [], False


_LOWER_OP = re.compile(r"(?:^|\s)(and|or|with)(?:\s|$)")
LICENSEREF = re.compile(r"(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+")
_OPERATORS = {"AND", "OR", "WITH"}


@lru_cache(maxsize=1)
def _known_tokens() -> frozenset[str]:
    known = get_spdx_licensing().known_symbols
    return frozenset(known) | {a for s in known.values() for a in s.aliases}


def is_spdx_expression(s: str | None) -> bool:
    if not s or not s.strip() or _LOWER_OP.search(s):
        return False
    try:
        get_spdx_licensing().parse(s, strict=True)  # WITH takes an exception
    except Exception:
        return False
    # Every token must be an operator, a well-formed LicenseRef, or a known
    # SPDX id/exception/alias in canonical case.
    known = _known_tokens()
    for tok in re.sub(r"[()]", " ", s).split():
        if tok in _OPERATORS or LICENSEREF.fullmatch(tok):
            continue
        if tok not in known:
            return False
    return True


def spdx_id(prefix: str, key: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]", "-", key)
    return f"SPDXRef-{prefix}-{safe}-{hashlib.sha1(key.encode()).hexdigest()[:8]}"


def cvss_method(vector: str | None) -> str:
    v = vector or ""
    for prefix, name in (
        ("CVSS:3.0/", "CVSSv3"),
        ("CVSS:3.1/", "CVSSv31"),
        ("CVSS:4.0/", "CVSSv4"),
        ("AV:", "CVSSv2"),
    ):
        if v.startswith(prefix):
            return name
    return "other"


CISA_KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
# Catalogue-level page: VulnCheck has no public per-CVE URL without an account.
VULNCHECK_KEV = "https://docs.vulncheck.com/community/vulncheck-kev"


def kev_url(vuln_id: str) -> str | None:
    """CISA KEV catalogue search URL; the catalogue is keyed by CVE id only.
    (``?search=`` is refused by cisa.gov; ``search_api_fulltext`` works.)"""
    return (
        f"{CISA_KEV}?search_api_fulltext={vuln_id}"
        if vuln_id.startswith("CVE-")
        else None
    )


def decimal_str(x: float) -> str:
    """Fixed-point text at the source precision (0.00009, never 9e-05)."""
    return format(Decimal(str(x)), "f")


def exploit_facts(v: Any) -> list[tuple[str, str]]:
    """Exploit data present on a Vuln as (key, value); absent data is omitted."""
    facts = [("kev", "true")] if v.in_kev else []
    if v.in_vulncheck_kev:
        facts.append(("vulncheck_kev", "true"))
    if v.epss_score is not None:
        facts.append(("epss", decimal_str(v.epss_score)))
    if v.epss_percentile is not None:
        facts.append(("epss_percentile", decimal_str(v.epss_percentile)))
    if v.exploit_maturity:
        facts.append(("exploit_maturity", v.exploit_maturity))
    return facts
