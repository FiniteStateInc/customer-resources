"""CRA Article 14 SRP-cascade notification producer (live mode, Phase 2).

The three live-mode recipes — ``early_warning_notification`` (24h),
``vulnerability_notification`` (72h) and ``final_report`` (14d) — all run off the
*one* shared ``exploitability-dataset/v2`` export (``--data-file``) and emit a
``json_package`` of the shape the fs-comply SRP cascade consumes::

    { "stage": "early|full|final",
      "fields": { "<FieldKey>": "<htmlString>", ... },   # EXACTLY this stage's AUTHORED set
      "meta":   { "clock": { ... } } }                    # early recipe ONLY

``fields`` carries EXACTLY the Member-7-**authored** subset for the stage — the
data-derived reporting fields, never the customer-input fields (actively_exploited,
member_states, …) nor the session/runtime fields (notification_type, …). The
canonical authored sets live in fs-comply ``src/model/srp.ts`` and are mirrored by
the vendored ``fs_report/schemas/cra-stages.schema.json`` (``x-cra-authored-by-stage``);
``STAGE_FIELDS`` below is the producer-side mirror, kept honest by the conformance
test (``tests/test_cra/test_srp_notification.py``), which validates every emitted
package against that schema's ``jsonPackage`` definition.

Continuity is by construction: all three stages derive from the same dataset, so
there is no prior-stage threading. The dataset feeding a live notification is the
forge assembler's *narrowed* export (one CVE on one component), so this module
selects the single decisive subject finding from it.

Field values are best-effort derived from the dataset and HTML-escaped; where the
v2 dataset does not carry a field (e.g. EUVD id, CVSS vector when null, CRA product
class) a neutral, non-fabricated placeholder string is emitted so the contract's
"every authored field is a non-empty string" invariant holds. The forge assembler
(Phase 3) and CVE-Impact enrichment (Phase 4) tighten these without any recipe change.
"""

from __future__ import annotations

import html
import logging
from typing import Any

import pandas as pd

from fs_report.cra.sections import _parse_iso_date, became_aware_clock

logger = logging.getLogger(__name__)

SUPPORTED_SCHEMA_VERSION = "exploitability-dataset/v2"

# The seven manufacturer-knowledge authored fields the assembler may supply via a
# top-level ``operator_input`` wrapper (§3 of the CRA customer-input spec). Single
# source of truth for the forge↔fs-report pass-through contract — the tests import
# this rather than re-listing it. ``user_actions`` and ``actively_exploited`` are
# deliberately NOT here (customer-provenance / the P3 boundary).
OPERATOR_INPUT_FIELDS = (
    "cra_product_class",
    "annex_category",
    "measures_taken",
    "security_update",
    "update_available_since",
    "automatic_update",
    "root_cause",
)

# Producer-side mirror of the canonical authored sets (fs-comply src/model/srp.ts /
# the vendored cra-stages.schema.json `x-cra-authored-by-stage`). early ⊂ full ⊂ final.
# The conformance test asserts these set-equal the vendored schema, so drift fails CI.
STAGE_FIELDS: dict[str, tuple[str, ...]] = {
    "early": (
        "product",
        "affected_versions",
        "cve",
        "euvd",
        "weakness",
        "vuln_nature",
    ),
    "full": (
        "product",
        "affected_versions",
        "cra_product_class",
        "annex_category",
        "cve",
        "euvd",
        "weakness",
        "cvss_base",
        "epss",
        "known_exploited",
        "affected_component",
        "reachability",
        "cvss_vector",
        "package_url",
        "vuln_nature",
        "exploit_nature",
        "severity",
        "cia",
        "potential_impact",
        "measures_taken",
    ),
    "final": (
        "product",
        "affected_versions",
        "cra_product_class",
        "annex_category",
        "cve",
        "euvd",
        "weakness",
        "cvss_base",
        "epss",
        "known_exploited",
        "affected_component",
        "reachability",
        "cvss_vector",
        "package_url",
        "vuln_nature",
        "exploit_nature",
        "malicious_actor",
        "first_observed",
        "severity",
        "cia",
        "potential_impact",
        "measures_taken",
        "security_update",
        "update_available_since",
        "automatic_update",
        "vex_status",
        "root_cause",
        "cve_record",
        "euvd_record",
    ),
}

# Decisive-first ordering when a narrowed dataset still carries >1 finding.
# AFFECTED_BY_VERSION is an actionable "affected" bucket (the installed component
# version is vulnerable), so it ranks above the not-yet-decided states.
_KIND_PRIORITY = {
    "AFFECTED": 0,
    "AFFECTED_BY_VERSION": 1,
    "UNDER_INVESTIGATION": 2,
    "INCONCLUSIVE": 3,
    "VERIFIER_FAILED": 4,
    "NOT_AFFECTED": 5,
}

# Small CWE label map for the most common weaknesses (best-effort; falls back to the
# raw CWE id). Not exhaustive — the demo data and live findings mostly hit these.
_CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-119": "Improper Restriction of Operations within Memory Bounds",
    "CWE-120": "Buffer Copy without Checking Size of Input",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-287": "Improper Authentication",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
}

_MATURITY_LABELS = {
    "weaponized": "Weaponized exploit available",
    "functional": "Functional exploit available",
    "poc": "Proof-of-concept exploit available",
    "proof-of-concept": "Proof-of-concept exploit available",
    "unproven": "No reliable public exploit",
    "none": "No public exploit observed",
}

_VEX_FROM_KIND = {
    "AFFECTED": "EXPLOITABLE (affected)",
    "AFFECTED_BY_VERSION": "AFFECTED (version range)",
    "NOT_AFFECTED": "NOT_AFFECTED",
    "INCONCLUSIVE": "UNDER_INVESTIGATION",
    "UNDER_INVESTIGATION": "UNDER_INVESTIGATION",
    "VERIFIER_FAILED": "UNKNOWN",
}


class NoSubjectError(ValueError):
    """Raised when a dataset carries no finding to build a notification from."""


class ClockAnchorError(ValueError):
    """Raised when the early recipe cannot establish a usable ``became_aware`` date.

    A live early-warning bundle requires an absolute, parseable ``became_aware``
    (the consumer's live-mode gate enforces ``minLength: 1`` + ``Date.parse``). The
    producer refuses to emit an empty/unparseable clock rather than push a
    non-conformant bundle downstream to the assembler.
    """


# ---------------------------------------------------------------------------
# Small value helpers
# ---------------------------------------------------------------------------


def _first_nonempty(*values: Any, default: str = "") -> str:
    """Return the first value that stringifies to a non-empty (stripped) string."""
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return default


def _esc(value: Any, default: str = "") -> str:
    """HTML-escape a stringified value (defense-in-depth; fs-comply re-sanitizes)."""
    text = _first_nonempty(value, default=default)
    return html.escape(text) if text else default


def _title(value: Any) -> str:
    return _first_nonempty(value).title()


# ---------------------------------------------------------------------------
# Subject selection (narrowed dataset -> the one decisive finding)
# ---------------------------------------------------------------------------


def select_subject_finding(dataset: dict[str, Any]) -> dict[str, Any] | None:
    """Pick the single decisive finding from a (narrowed) v2 dataset.

    The live dataset is the forge assembler's narrowed export (one CVE on one
    component) so this is usually a single row; the selection is robust for the
    general case: supersession-dedupe (latest ``sealed_at`` per finding), then
    decisive verdict first (AFFECTED before version-range before the not-yet-decided
    states), severity desc as the tie-break. When the dataset is NOT narrowed to a
    single subject (it carries more than one distinct ``(CVE, component)`` pair), a
    warning is logged — pass ``--cve``/``--component`` or have the assembler emit a
    single-subject export.
    """
    findings = dataset.get("findings") or []
    deduped = _dedupe_supersession(findings)
    if not deduped:
        return None

    distinct_subjects = {
        (
            (f.get("target") or {}).get("cve_id"),
            (f.get("target") or {}).get("component_id")
            or (f.get("target") or {}).get("component_name"),
        )
        for f in deduped
    }
    if len(distinct_subjects) > 1:
        logger.warning(
            "CRA notification dataset carries %d distinct (CVE, component) subjects; "
            "selecting the most decisive one heuristically. Pass --cve/--component, "
            "or have the forge assembler emit a narrowed (single-subject) export.",
            len(distinct_subjects),
        )

    def sort_key(finding: dict[str, Any]) -> tuple[int, float]:
        kind = str((finding.get("verdict") or {}).get("kind", ""))
        priority = _KIND_PRIORITY.get(kind, 9)
        cvss = (finding.get("enrichment") or {}).get("cvss")
        score = float(cvss) if isinstance(cvss, (int, float)) else 0.0
        return (priority, -score)

    return sorted(deduped, key=sort_key)[0]


def _supersession_key(finding: dict[str, Any]) -> tuple[str, ...]:
    """Supersession identity for a finding.

    Primary key is the stable ``target.finding_id``. When it is absent (v2 permits
    a null ``finding_id``), fall back to the composite
    ``(project_id, version_id, component_id, cve_id)`` — the same fallback the v2
    exploitability transform uses — so duplicate id-less seals of the same finding
    still collapse instead of all entering the selection pool.
    """
    target = finding.get("target") or {}
    fid = target.get("finding_id")
    if fid:
        return ("fid", str(fid))
    return (
        "composite",
        str(target.get("project_id") or ""),
        str(target.get("version_id") or ""),
        str(target.get("component_id") or ""),
        str(target.get("cve_id") or ""),
    )


def _dedupe_supersession(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the latest-sealed entry per supersession key (see :func:`_supersession_key`).

    "Latest" is by INSTANT, not lexicographic string order: ``sealed_at`` values
    are compared as parsed aware-UTC datetimes (via :func:`_seal_ge`) so a later
    moment wins regardless of the timestamp's UTC-offset format.
    """
    latest: dict[tuple[str, ...], dict[str, Any]] = {}
    for finding in findings:
        key = _supersession_key(finding)
        prev = latest.get(key)
        if prev is None:
            latest[key] = finding
            continue
        prev_seal = str((prev.get("provenance") or {}).get("sealed_at") or "")
        cur_seal = str((finding.get("provenance") or {}).get("sealed_at") or "")
        if _seal_ge(cur_seal, prev_seal):
            latest[key] = finding
    return list(latest.values())


def _seal_ge(a: str, b: str) -> bool:
    """Return True if seal ``a`` is at or after seal ``b`` by instant.

    Compares parsed aware-UTC datetimes so a later instant wins regardless of the
    UTC-offset format (``+05:00`` vs ``Z``); falls back to a raw-string compare
    only when a value is unparseable, preserving a deterministic total order.
    """
    da = _parse_iso_date(a)
    db = _parse_iso_date(b)
    if da is not None and db is not None:
        return da >= db
    return a >= b


# ---------------------------------------------------------------------------
# Clock inputs
# ---------------------------------------------------------------------------


def _first_parseable(*values: Any) -> str | None:
    """Return the first value that is a non-empty, ISO-parseable date string."""
    for value in values:
        text = _first_nonempty(value)
        if text and _parse_iso_date(text) is not None:
            return text
    return None


def resolve_clock_inputs(
    dataset: dict[str, Any], finding: dict[str, Any]
) -> tuple[str | None, str, str | None, str | None]:
    """Return ``(anchor, anchor_label, cisa_date_added, detected)`` for the clock.

    - ``detected`` is the *true* platform detection date — the first PARSEABLE of
      the explicit detection fields (``detected_date`` / ``detected`` /
      ``target.detected_date``), or ``None``. Only a real detection date is reported
      as ``detected`` (a seal/export fallback never is).
    - ``anchor`` drives ``became_aware = max(cisa, anchor)``: the detection date when
      present, else ``provenance.sealed_at``, else the run's ``meta.generated_at``
      (``anchor_label`` records which, for ``became_aware_basis``). The post-#166 v2
      dataset carries no detection/KEV dates natively, so a producer may bake them in
      (v2 permits unknown fields) and the recipe tightens with zero change.
    - ``cisa_date_added`` is the first PARSEABLE explicit CISA date, else ``None`` —
      the recipe never fetches the KEV catalog (it stays self-contained off
      ``--data-file``).

    Every value is parseability-checked, so an unparseable explicit field can never
    block a valid fallback (which would otherwise raise a spurious ClockAnchorError).
    """
    target = finding.get("target") or {}
    enrichment = finding.get("enrichment") or {}
    provenance = finding.get("provenance") or {}
    meta = dataset.get("meta") or {}

    detected = _first_parseable(
        finding.get("detected_date"),
        finding.get("detected"),
        target.get("detected_date"),
    )
    if detected is not None:
        anchor, anchor_label = detected, "detected"
    elif (seal := _first_parseable(provenance.get("sealed_at"))) is not None:
        anchor, anchor_label = seal, "platform seal date"
    elif (gen := _first_parseable(meta.get("generated_at"))) is not None:
        anchor, anchor_label = gen, "report generation date"
    else:
        anchor, anchor_label = None, "detected"

    cisa = _first_parseable(
        finding.get("cisa_date_added"),
        finding.get("cisa_dateAdded"),
        enrichment.get("cisa_date_added"),
        enrichment.get("cisa_dateAdded"),
    )
    return (anchor, anchor_label, cisa, detected)


# ---------------------------------------------------------------------------
# Field derivation (all 29 authored fields -> non-empty HTML strings)
# ---------------------------------------------------------------------------


def derive_authored_fields(
    dataset: dict[str, Any], finding: dict[str, Any]
) -> dict[str, str]:
    """Derive every authored field's HTML value from the subject finding + envelope.

    Returns the full authored map (all 29 keys); callers slice it per stage. Every
    value is a non-empty string (the contract requires ``minLength: 1``); fields the
    dataset does not carry get a neutral, non-fabricated placeholder.
    """
    subject = dataset.get("subject") or {}
    target = finding.get("target") or {}
    verdict = finding.get("verdict") or {}
    enrichment = finding.get("enrichment") or {}
    remediation = finding.get("remediation") or {}

    # Optional assembler-injected pass-through for the manufacturer-knowledge
    # authored fields (§3 of the CRA customer-input spec). It is NOT sealed
    # evidence: a non-empty operator value wins over today's derivation/placeholder
    # (mirroring the clock's prefer-explicit ladder), an empty/whitespace answer
    # degrades to the placeholder (never an empty authored string, which
    # validateBundle rejects), and an absent key leaves today's behaviour intact.
    # A truthy non-dict operator_input (validate_dataset_v2 ignores unknown top-level
    # keys) must degrade to placeholders, never crash the recipe on `.get`.
    operator_input = dataset.get("operator_input")
    if not isinstance(operator_input, dict):
        operator_input = {}

    def _operator_or(field: str, fallback: str) -> str:
        val = operator_input.get(field)
        # Only a non-empty STRING is honored: a mistyped non-string answer
        # (bool/number/list) is treated as absent → today's placeholder, never
        # str()-coerced into a legally-filed CRA notification (e.g. True → "True").
        op = val.strip() if isinstance(val, str) else ""
        # _esc runs the SAME html.escape as every derived value — escape once at the
        # recipe boundary; fs-comply re-sanitizes but never double-escapes.
        return _esc(op) if op else fallback

    has_cve = bool(_first_nonempty(target.get("cve_id")))
    cve = _first_nonempty(target.get("cve_id"), default="CVE pending")
    component_name = target.get("component_name")
    component_version = target.get("component_version")
    cwe = target.get("cwe")
    severity = enrichment.get("severity")
    cvss = enrichment.get("cvss")
    cvss_vector = enrichment.get("cvss_vector")
    cve_description = target.get("cve_description")

    return {
        "product": _esc(
            _first_nonempty(
                subject.get("product_name"),
                target.get("project_name"),
                default="Unspecified product",
            )
        ),
        "affected_versions": _esc(
            _first_nonempty(
                subject.get("version_label"),
                component_version,
                default="Not specified",
            )
        ),
        "cra_product_class": _operator_or(
            "cra_product_class", "Pending CRA product-class determination"
        ),
        "annex_category": _operator_or(
            "annex_category", "Not yet classified under CRA Annex III/IV"
        ),
        "cve": f"<code>{_esc(cve)}</code>",
        "euvd": _euvd_id(cve) if has_cve else "Awaiting EUVD assignment",
        "weakness": _weakness(cwe),
        "cvss_base": _cvss_base(cvss, severity),
        "epss": _epss(enrichment.get("epss")),
        "known_exploited": _known_exploited(
            enrichment.get("kev"), enrichment.get("vckev")
        ),
        "affected_component": _component(component_name, component_version),
        "reachability": _reachability(finding),
        "cvss_vector": (
            f"<code>{_esc(cvss_vector)}</code>" if cvss_vector else "Not available"
        ),
        "package_url": _package_url(component_name, component_version),
        # Neutral, deterministic phrasing: the raw CVE description (escaped once)
        # else the weakness text ONLY. The sealed verdict.reason_summary is NOT a
        # fallback (it can assert a disposition — e.g. "not exploitable" — that
        # contradicts a CRA filing). _weakness() self-escapes, so it is used as-is
        # (no outer _esc, which would double-escape).
        "vuln_nature": (
            _esc(cve_description)
            if _first_nonempty(cve_description)
            else _weakness(cwe)
        ),
        "exploit_nature": _exploit_nature(finding),
        "malicious_actor": _malicious_actor(enrichment),
        "first_observed": _first_observed(finding, dataset),
        "severity": _severity(severity, cvss),
        "cia": _cia(cvss_vector),
        "potential_impact": _potential_impact(severity, cve_description, cwe),
        "measures_taken": _operator_or("measures_taken", _measures(remediation)),
        "security_update": _operator_or(
            "security_update", _security_update(remediation)
        ),
        "update_available_since": _operator_or(
            "update_available_since", _update_available_since(remediation)
        ),
        "automatic_update": _operator_or(
            "automatic_update", "Not determined (no automatic-update channel reported)"
        ),
        "vex_status": _vex_status(verdict, enrichment),
        "root_cause": _operator_or("root_cause", _root_cause(cwe, cve_description)),
        "cve_record": (
            f"<code>https://nvd.nist.gov/vuln/detail/{_esc(cve)}</code>"
            if has_cve
            else "CVE record pending (no CVE assigned)"
        ),
        "euvd_record": _euvd_record(),
    }


def _euvd_id(cve: str) -> str:
    return f"Awaiting EUVD assignment (mirrors {_esc(cve)})"


def _euvd_record() -> str:
    return "<code>https://euvd.enisa.europa.eu/</code> (record pending)"


def _weakness(cwe: Any) -> str:
    text = _first_nonempty(cwe)
    if not text:
        return "Not classified (CWE pending)"
    name = _CWE_NAMES.get(text.upper())
    return f"{_esc(text)}: {_esc(name)}" if name else _esc(text)


def _cvss_base(cvss: Any, severity: Any) -> str:
    if cvss is None or _first_nonempty(cvss) == "":
        return "Not scored"
    sev = _title(severity)
    return f"{_esc(cvss)} ({sev})" if sev else _esc(cvss)


def _epss(epss: Any) -> str:
    try:
        value = float(epss)
    except (TypeError, ValueError):
        return "Not available"
    return f"{value * 100:.2f}% (EPSS probability)"


def _known_exploited(kev: Any, vckev: Any) -> str:
    flags = []
    if kev:
        flags.append("CISA KEV")
    if vckev:
        flags.append("VulnCheck KEV")
    if not flags:
        return "Not listed in CISA KEV or VulnCheck KEV"
    return "Listed in " + " and ".join(flags)


def _component(name: Any, version: Any) -> str:
    name_text = _first_nonempty(name)
    version_text = _first_nonempty(version)
    if name_text and version_text:
        return f"<code>{_esc(name_text)}</code> {_esc(version_text)}"
    if name_text:
        return f"<code>{_esc(name_text)}</code>"
    return "Unspecified component"


def _reachability(finding: dict[str, Any]) -> str:
    # The affirmative signals (an explicit reachability.fact, a dynamic-PoV method,
    # or a call-graph "reachability" method) only speak to an AFFIRMATIVE verdict.
    # For NOT_AFFECTED / INCONCLUSIVE / UNDER_INVESTIGATION / VERIFIER_FAILED a
    # sealed method/fact must NOT be surfaced as "confirmed reachable" — that would
    # contradict a clear/undecided disposition — so we fall through to the neutral
    # marker. Compute the kind first and gate all three kind-blind paths on it.
    kind = _first_nonempty((finding.get("verdict") or {}).get("kind"))
    if kind not in ("AFFECTED", "AFFECTED_BY_VERSION"):
        return "Reachability not assessed"
    evidence = finding.get("evidence") or {}
    reach = evidence.get("reachability") or {}
    fact = _first_nonempty(reach.get("fact"))
    if fact:
        return _esc(fact)
    method = _first_nonempty(finding.get("method"))
    if method == "dynamic_pov":
        return "Reachable — confirmed via dynamic proof-of-value"
    if method == "reachability":
        return "Reachable — confirmed via call-graph analysis"
    if kind == "AFFECTED":
        return "Reachable (affected)"
    return "Version-range match (reachability not individually assessed)"


def _package_url(name: Any, version: Any) -> str:
    name_text = _first_nonempty(name)
    version_text = _first_nonempty(version)
    if name_text and version_text:
        return f"Not exported (component {_esc(name_text)}@{_esc(version_text)})"
    if name_text:
        return f"Not exported (component {_esc(name_text)})"
    return "Not available"


def _exploit_nature(finding: dict[str, Any]) -> str:
    # The SEALED proof-of-value text — evidence.exploit_proof's "— dynamic crash …"
    # suffix and the evidence_summary fallback — asserts a WORKING exploit against
    # this subject, so it only speaks to an AFFIRMATIVE verdict. For NOT_AFFECTED /
    # INCONCLUSIVE / UNDER_INVESTIGATION / VERIFIER_FAILED it must NOT be surfaced —
    # that would contradict a clear/undecided disposition on the filing (the same
    # contradiction class as _reachability). Fall back to the neutral
    # enrichment-maturity-only phrasing (the public-exploit maturity label, which
    # describes the CVE ecosystem, not this finding), else the neutral marker.
    # Compute the kind first and gate the sealed-proof paths on it.
    enrichment = finding.get("enrichment") or {}
    maturity = _first_nonempty(enrichment.get("exploit_maturity")).lower()
    label = _MATURITY_LABELS.get(maturity)
    kind = _first_nonempty((finding.get("verdict") or {}).get("kind"))
    if kind not in ("AFFECTED", "AFFECTED_BY_VERSION"):
        return label or "Exploit nature under assessment"
    evidence = finding.get("evidence") or {}
    proof = evidence.get("exploit_proof") or {}
    signal = _first_nonempty(proof.get("signal"))
    faulting = _first_nonempty(proof.get("faulting_object"))
    if label and signal and faulting:
        return f"{label} — dynamic crash ({_esc(signal)} in {_esc(faulting)})"
    if label:
        return label
    summary = _first_nonempty(evidence.get("evidence_summary"))
    if summary:
        return _esc(summary)
    return "Exploit nature under assessment"


def _malicious_actor(enrichment: dict[str, Any]) -> str:
    if enrichment.get("kev"):
        return "Associated with known exploited-vulnerability activity (CISA KEV)"
    if enrichment.get("vckev"):
        return "Associated with VulnCheck KEV activity"
    return "No specific threat actor attributed"


def _first_observed(finding: dict[str, Any], dataset: dict[str, Any]) -> str:
    explicit = _first_nonempty(
        finding.get("first_observed"),
        (finding.get("target") or {}).get("first_observed"),
    )
    if explicit:
        return _esc(explicit)
    sealed = _first_nonempty((finding.get("provenance") or {}).get("sealed_at"))
    if sealed:
        return f"First observed (platform seal): {_esc(sealed[:10])}"
    return "Not established"


def _severity(severity: Any, cvss: Any) -> str:
    sev = _title(severity)
    if sev:
        return sev
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return "Unrated"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def _cia(cvss_vector: Any) -> str:
    vector = _first_nonempty(cvss_vector)
    if not vector:
        return "Per CVSS (vector pending)"
    levels = {"H": "High", "L": "Low", "N": "None"}
    parts = []
    for metric, label in (
        ("C", "Confidentiality"),
        ("I", "Integrity"),
        ("A", "Availability"),
    ):
        token = f"/{metric}:"
        idx = vector.find(token)
        pos = idx + len(token)
        if idx == -1 or pos >= len(vector):
            # absent, or a truncated/malformed vector ending at the token — skip;
            # if no metric resolves, the neutral fallback below applies.
            continue
        code = vector[pos]
        parts.append(f"{label}: {levels.get(code, code)}")
    if not parts:
        return "Per CVSS (vector pending)"
    return " · ".join(parts)


def _potential_impact(severity: Any, cve_description: Any, cwe: Any) -> str:
    # Detail is the raw CVE description (escaped once) else the weakness text ONLY
    # (_weakness self-escapes — no outer _esc, which would double-escape). The
    # sealed verdict.reason_summary is deliberately NOT a fallback. The
    # "{severity}-severity impact." prefix is omitted when severity is missing.
    desc = _first_nonempty(cve_description)
    detail = _esc(desc) if desc else _weakness(cwe)
    sev = _title(severity)
    if sev:
        return f"{sev}-severity impact. {detail}"
    return detail


def _measures(remediation: dict[str, Any]) -> str:
    action = _first_nonempty(remediation.get("action"))
    fix_version = _first_nonempty(remediation.get("fix_version"))
    workaround = _first_nonempty(remediation.get("workaround"))
    if action and fix_version:
        return f"{_esc(action)} (fixed in {_esc(fix_version)})"
    if action:
        return _esc(action)
    if fix_version:
        return f"Update to {_esc(fix_version)}"
    if workaround:
        return _esc(workaround)
    return "Mitigation planning in progress"


def _security_update(remediation: dict[str, Any]) -> str:
    fix_version = _first_nonempty(remediation.get("fix_version"))
    action = _first_nonempty(remediation.get("action"))
    if fix_version:
        return f"Available — fixed in {_esc(fix_version)}"
    if action:
        return _esc(action)
    return "No security update available yet"


def _update_available_since(remediation: dict[str, Any]) -> str:
    release = _first_nonempty(remediation.get("release_date"))
    if release:
        return _esc(release)
    if _first_nonempty(remediation.get("fix_version")):
        return "Date not specified"
    return "Not specified"


def _vex_status(verdict: dict[str, Any], enrichment: dict[str, Any]) -> str:
    explicit = _first_nonempty(
        verdict.get("platform_status"), enrichment.get("current_vex")
    )
    if explicit:
        return _esc(explicit)
    kind = _first_nonempty(verdict.get("kind"))
    return _VEX_FROM_KIND.get(kind, "UNKNOWN")


def _root_cause(cwe: Any, cve_description: Any) -> str:
    text = _first_nonempty(cwe)
    if text:
        name = _CWE_NAMES.get(text.upper())
        if name:
            return f"{_esc(name)} ({_esc(text)})"
        return f"Weakness {_esc(text)}"
    detail = _first_nonempty(cve_description)
    if detail:
        return _esc(detail)
    return "Root-cause analysis pending"


# ---------------------------------------------------------------------------
# Package assembly + recipe entry point
# ---------------------------------------------------------------------------


def build_json_package(dataset: dict[str, Any], stage: str) -> dict[str, Any]:
    """Build the ``json_package`` for ``stage`` from a v2 dataset.

    Selects the subject finding, derives the authored fields, slices to the stage's
    authored set, and (early only) attaches the machine-readable ``meta.clock``.
    Raises ``NoSubjectError`` when the dataset has no finding, and
    ``ClockAnchorError`` when the early stage cannot establish a parseable
    ``became_aware`` (so the producer never emits a clock the live bundle rejects).
    """
    if stage not in STAGE_FIELDS:
        raise ValueError(
            f"unknown stage {stage!r}; expected one of {tuple(STAGE_FIELDS)}"
        )

    finding = select_subject_finding(dataset)
    if finding is None:
        raise NoSubjectError("exploitability dataset carries no findings")

    all_fields = derive_authored_fields(dataset, finding)
    fields = {key: all_fields[key] for key in STAGE_FIELDS[stage]}

    package: dict[str, Any] = {"stage": stage, "fields": fields}
    if stage == "early":
        anchor, anchor_label, cisa, detected = resolve_clock_inputs(dataset, finding)
        clock = became_aware_clock(
            anchor=anchor,
            cisa_date_added=cisa,
            detected=detected,
            anchor_label=anchor_label,
        )
        # The live-mode bundle gate requires an absolute, parseable became_aware
        # (minLength:1 + Date.parse). The producer-side jsonPackage schema only
        # types it as a string, so guard here rather than ship an unusable clock.
        if _parse_iso_date(clock.get("became_aware") or "") is None:
            raise ClockAnchorError(
                "cannot establish a CRA 'became aware' date for the early-warning "
                "notification: the dataset carries no parseable awareness anchor "
                "(a detection date, evidence seal time, or report-generation time) "
                "and no parseable CISA date."
            )
        # Pinned cross-repo contract: emit meta.subject_verdict alongside meta.clock
        # for the record select_subject_finding chose, so the forge assembler's
        # disposition-consistency gate reads it directly (no subject re-selection).
        verdict = finding.get("verdict") or {}
        # Normalize empty/whitespace strings to null so the emitted subject_verdict
        # matches the documented "<field | null>" contract (a raw ""/"   " must not
        # pass through as an empty string the assembler's gate would misread).
        package["meta"] = {
            "clock": clock,
            "subject_verdict": {
                "kind": _first_nonempty(verdict.get("kind")) or None,
                "platform_status": _first_nonempty(verdict.get("platform_status"))
                or None,
            },
        }
    return package


def _split_csv(value: Any) -> list[str]:
    """Split a CSV scope-filter string (e.g. ``--cve A,B``) into trimmed parts."""
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _cf_set(value: Any) -> set[str]:
    """Case-folded set of CSV scope-filter parts (for case-insensitive matching)."""
    return {part.casefold() for part in _split_csv(value)}


def _candidates(*values: Any) -> set[str]:
    """Case-folded set of the non-empty identifiers a filter may match against."""
    out = set()
    for value in values:
        text = _first_nonempty(value)
        if text:
            out.add(text.casefold())
    return out


def _matches_scope(
    finding: dict[str, Any], subject: dict[str, Any], filters: dict[str, set[str]]
) -> bool:
    """True if *finding* satisfies every set scope dimension.

    Matching is case-insensitive and accepts the identifier forms the rest of the
    repo's scope resolution accepts: a component by name, ``component_id``, or
    ``name@version``; a version by ``version_id`` or label; a project by id or name;
    a folder by id. An unset dimension is not a constraint.
    """
    target = finding.get("target") or {}

    if (
        filters["cve"]
        and _first_nonempty(target.get("cve_id")).casefold() not in filters["cve"]
    ):
        return False

    if filters["component"]:
        name = _first_nonempty(target.get("component_name"))
        version = _first_nonempty(target.get("component_version"))
        cands = _candidates(target.get("component_name"), target.get("component_id"))
        if name and version:
            cands.add(f"{name}@{version}".casefold())
        if not (filters["component"] & cands):
            return False

    if filters["version"]:
        cands = _candidates(
            target.get("version_id"),
            subject.get("version_id"),
            subject.get("version_label"),
        )
        if not (filters["version"] & cands):
            return False

    if filters["project"]:
        cands = _candidates(
            target.get("project_id"),
            target.get("project_name"),
            subject.get("project_id"),
            subject.get("project_name"),
        )
        if not (filters["project"] & cands):
            return False

    if filters["folder"]:
        # Match the finding's OWN folder membership (subject.folders is only used to
        # resolve names -> ids when building the filter set, never to widen a row's
        # membership — see _resolve_folder_filter).
        fids = {str(x).casefold() for x in (target.get("folder_ids") or [])}
        if not (filters["folder"] & fids):
            return False

    return True


def _resolve_folder_filter(value: Any, subject: dict[str, Any]) -> set[str]:
    """Expand a ``--folder`` filter (names or ids) to the set of folder IDS to match.

    ``target.folder_ids`` carries ids; ``subject.folders`` maps id -> name. So a
    name filter is translated to its id via ``subject.folders`` and matched against
    each finding's own ``folder_ids`` — narrowing per finding, not by the
    dataset-wide subject scope.
    """
    raw = _cf_set(value)
    if not raw:
        return set()
    resolved = set(raw)  # a raw value may already be a folder id
    for folder in subject.get("folders") or []:
        folder = folder or {}
        fid = _first_nonempty(folder.get("id")).casefold()
        fname = _first_nonempty(folder.get("name")).casefold()
        if fid and (fid in raw or (fname and fname in raw)):
            resolved.add(fid)
    return resolved


def _apply_scope_filters(dataset: dict[str, Any], cfg: Any) -> dict[str, Any]:
    """Narrow ``dataset.findings`` to the operator's CLI scope flags.

    A hard guardrail for direct ``--data-file`` runs: when the caller passes
    ``--cve`` / ``--component`` / ``--version`` / ``--project`` / ``--folder``, only
    matching findings are eligible as the notification subject. Raises
    ``NoSubjectError`` when a non-empty dataset has no finding in the requested scope
    (so a typo selects nothing rather than the wrong subject). A no-op when no scope
    flag is set (the normal forge-narrowed path).
    """
    subject = dataset.get("subject") or {}
    filters = {
        "cve": _cf_set(getattr(cfg, "cve_filter", None)),
        "component": _cf_set(getattr(cfg, "component_filter", None)),
        "version": _cf_set(getattr(cfg, "version_filter", None)),
        "project": _cf_set(getattr(cfg, "project_filter", None)),
        "folder": _resolve_folder_filter(getattr(cfg, "folder_filter", None), subject),
    }
    if not any(filters.values()):
        return dataset
    findings = dataset.get("findings") or []
    filtered = [f for f in findings if _matches_scope(f, subject, filters)]
    if findings and not filtered:
        active = {k: sorted(v) for k, v in filters.items() if v}
        raise NoSubjectError(f"no finding matches the requested scope {active}")
    return {**dataset, "findings": filtered}


def run_cra_recipe(
    data: Any,
    stage: str,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Shared recipe body: validate the ``--data-file`` object and emit the package.

    Honors the operator's ``--cve`` / ``--component`` scope flags (via ``config``) as
    a hard subject guardrail for direct runs. Returns the engine's expected dict — an
    (empty) ``main`` DataFrame for the table/CSV fallback plus the ``json_package``
    the JSON renderer serializes verbatim as ``<recipe_name>.json``.
    """
    if not isinstance(data, dict):
        raise ValueError(
            "CRA notification recipes require a --data-file "
            f"{SUPPORTED_SCHEMA_VERSION} object (got {type(data).__name__})"
        )
    schema_version = data.get("schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version {schema_version!r}; "
            f"expected {SUPPORTED_SCHEMA_VERSION!r}"
        )
    # Fail fast with actionable, path-prefixed contract errors on a structurally
    # invalid payload — the same gate the sibling exploitability_report uses —
    # rather than letting build_json_package hit a raw AttributeError downstream.
    from fs_report.transforms.pandas.exploitability_dataset_v2 import (
        validate_dataset_v2,
    )

    validate_dataset_v2(data, source="CRA SRP-cascade notification recipe")

    cfg = config if config is not None else (additional_data or {}).get("config")
    scoped = _apply_scope_filters(data, cfg)
    package = build_json_package(scoped, stage)
    return {"main": pd.DataFrame(), "json_package": package}
