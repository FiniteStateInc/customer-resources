"""SPDX 3.0.1 JSON-LD writer for SbomDoc (hand-built; spdx-tools' spdx3 is a pre-3.0 draft)."""

from __future__ import annotations

import logging
import re
from datetime import UTC, date, datetime
from typing import Any

from packageurl import PackageURL

from fs_report import __version__
from fs_report.sbom_export.mapping import (
    CISA_KEV,
    LICENSEREF,
    VULNCHECK_KEV,
    cvss_method,
    decimal_str,
    kev_url,
    openvex_status,
    spdx_id,
)
from fs_report.sbom_export.model import (
    Component,
    ProjectNode,
    SbomDoc,
    Supplier,
    Vuln,
)
from fs_report.sbom_export.spdx2_writer import SpdxLicenses, homepage_url

log = logging.getLogger(__name__)
_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
_CI = "_:creationinfo"
# expandedLicensing: NoAssertionLicense comes from that profile.
_PROFILES = ["core", "software", "security", "simpleLicensing", "expandedLicensing"]
_NOASSERTION = "expandedlicensing_NoAssertionLicense"
_PURPOSES = {
    "application", "archive", "bom", "configuration", "container", "data",
    "device", "deviceDriver", "diskImage", "documentation", "evidence",
    "executable", "file", "filesystemImage", "firmware", "framework", "install",
    "library", "manifest", "model", "module", "operatingSystem", "other",
    "patch", "platform", "requirement", "source", "specification", "test",
}  # fmt: skip
_HASHES = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384",
    "SHA3-512": "sha3_512",
    "BLAKE2B-256": "blake2b256",
    "BLAKE2B-384": "blake2b384",
    "BLAKE2B-512": "blake2b512",
    "BLAKE3": "blake3",
}
# CycloneDX externalReference type -> SPDX 3 ExternalRefType (else "other").
_EXT_REFS = {
    "vcs": "vcs",
    "issue-tracker": "issueTracker",
    "website": "altWebPage",
    "advisories": "securityAdvisory",
    "mailing-list": "mailingList",
    "social": "socialMedia",
    "chat": "chat",
    "documentation": "documentation",
    "support": "support",
    "distribution": "altDownloadLocation",
    "license": "license",
    "build-meta": "buildMeta",
    "build-system": "buildSystem",
    "release-notes": "releaseNotes",
}
# CycloneDX justification -> SPDX 3 VexJustificationType (CISA/OpenVEX mapping).
_JUSTIFICATIONS = {
    "code_not_present": "vulnerableCodeNotPresent",
    "code_not_reachable": "vulnerableCodeNotInExecutePath",
    "requires_configuration": "vulnerableCodeCannotBeControlledByAdversary",
    "requires_dependency": "vulnerableCodeCannotBeControlledByAdversary",
    "requires_environment": "vulnerableCodeCannotBeControlledByAdversary",
    "protected_by_compiler": "inlineMitigationsAlreadyExist",
    "protected_at_runtime": "inlineMitigationsAlreadyExist",
    "protected_at_perimeter": "inlineMitigationsAlreadyExist",
    "protected_by_mitigating_control": "inlineMitigationsAlreadyExist",
}
# OpenVEX status -> (assessment class, required relationshipType).
_VEX = {
    "not_affected": ("NotAffected", "doesNotAffect"),
    "affected": ("Affected", "affects"),
    "fixed": ("Fixed", "fixedIn"),
    "under_investigation": ("UnderInvestigation", "underInvestigationFor"),
}
_SBOM_TYPE = {"pre-build": "source", "build": "build", "post-build": "analyzed"}
_COMPLETENESS = {"complete": "complete", "incomplete": "incomplete"}
_CVSS = {"CVSSv2": "V2", "CVSSv3": "V3", "CVSSv31": "V3", "CVSSv4": "V4"}
_SEVERITIES = {"critical", "high", "medium", "low", "none"}


def _time(value: str) -> str:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _eol(value: str | None) -> str | None:
    try:
        return (
            date.fromisoformat(value).strftime("%Y-%m-%dT00:00:00Z") if value else None
        )
    except ValueError:
        log.debug("Skipping malformed eol date %r", value)
        return None


def _purpose(t: str | None, default: str) -> str:
    if not t:
        return default
    if t == "machine-learning-model":
        return "model"
    camel = re.sub(r"-(\w)", lambda m: m.group(1).upper(), t)
    return camel if camel in _PURPOSES else "other"


def _severity(score: float, given: str | None) -> str:
    if given and given.lower() in _SEVERITIES:
        return given.lower()
    # CVSS v3/v4 qualitative rating scale.
    if score == 0:
        return "none"
    return (
        "low"
        if score < 4
        else "medium" if score < 7 else "high" if score < 9 else "critical"
    )


def _identifiers(
    purl: str | None, cpes: list[str]
) -> tuple[str | None, list[dict[str, str]]]:
    canonical = None
    if purl:
        try:
            canonical = PackageURL.from_string(purl).to_string()
        except ValueError:
            log.debug("Skipping malformed purl %r", purl)
    ids = [("packageUrl", canonical)] if canonical else []
    for c in cpes:
        if c.startswith(("cpe:2.3:", "cpe:/")):
            ids.append(("cpe23" if c.startswith("cpe:2.3:") else "cpe22", c))
        else:
            log.debug("Skipping malformed CPE %r", c)
    return canonical, [
        {"type": "ExternalIdentifier", "externalIdentifierType": k, "identifier": v}
        for k, v in ids
    ]


class _Graph:
    def __init__(self, doc: SbomDoc) -> None:
        self.base = f"https://finitestate.io/spdx/{doc.serial}#"
        self.elements: dict[str, dict[str, Any]] = {}
        self.rels: dict[tuple[str, str], list[str]] = {}
        self.lic = SpdxLicenses()

    def iri(self, prefix: str, key: str) -> str:
        return self.base + spdx_id(prefix, key)

    def add(self, type_: str, prefix: str, key: str, **props: Any) -> str:
        """Add an element once per IRI (first writer wins); return its IRI."""
        iri = self.iri(prefix, key)
        element = {"type": type_, "spdxId": iri, "creationInfo": _CI}
        kept = {k: v for k, v in props.items() if v not in (None, "", [])}
        self.elements.setdefault(iri, element | kept)
        return iri

    def rel(self, src: str, kind: str, dst: str) -> None:
        targets = self.rels.setdefault((src, kind), [])
        if dst not in targets:
            targets.append(dst)

    def license(self, terms: list[str]) -> str:
        if not terms:
            return _NOASSERTION
        if terms == ["NONE"]:
            return "expandedlicensing_NoneLicense"
        expr = str(self.lic.expression(terms))
        mapping = []
        for ref in dict.fromkeys(LICENSEREF.findall(expr)):
            info = self.lic.extracted.get(ref)
            if info:
                text = self.add(
                    "simplelicensing_SimpleLicensingText",
                    "LicenseText",
                    ref,
                    name=ref,
                    simplelicensing_licenseText=info.extracted_text,
                )
                mapping.append({"type": "DictionaryEntry", "key": ref, "value": text})
        return self.add(
            "simplelicensing_LicenseExpression",
            "License",
            expr,
            simplelicensing_licenseExpression=expr,
            simplelicensing_customIdToUri=mapping,
        )

    def org(self, name: str | None) -> str | None:
        return self.add("Organization", "Org", name, name=name) if name else None

    def package(self, prefix: str, key: str, purpose: str, **props: Any) -> str:
        purl, ids = _identifiers(props.pop("purl"), props.pop("cpes"))
        return self.add(
            "software_Package",
            prefix,
            key,
            software_packageUrl=purl,
            externalIdentifier=ids,
            software_primaryPurpose=purpose,
            **props,
        )


def _supplier(g: _Graph, s: Supplier | None) -> str | None:
    if s is None:
        return None
    email = {
        "type": "ExternalIdentifier",
        "externalIdentifierType": "email",
        "identifier": s.email,
    }
    url = {"type": "ExternalRef", "externalRefType": "altWebPage", "locator": [s.url]}
    return g.add(
        "Organization",
        "Supplier",
        s.name,
        name=s.name,
        externalIdentifier=[email] if s.email else None,
        externalRef=[url] if s.url else None,
    )


def _verified(hashes: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [
        {"type": "Hash", "algorithm": alg, "hashValue": v.lower()}
        for a, v in hashes
        if (alg := _HASHES.get(a.upper()))
    ]


def _annotate(g: _Graph, key: str, iri: str, props: list[tuple[str, str]]) -> None:
    for name, value in props:
        g.add(
            "Annotation",
            "Annotation",
            f"{key}|{name}={value}",
            annotationType="other",
            subject=iri,
            statement=f"{name}={value}",
        )


def _project(g: _Graph, p: ProjectNode, doc: SbomDoc | None = None) -> str:
    """A project package; ``doc`` (root only) adds the user's assertions."""
    iri = g.package(
        "Project",
        p.key,
        _purpose(p.project_type, "application"),
        name=p.project_name or p.project_id,
        software_packageVersion=p.version_name,
        suppliedBy=_supplier(g, doc.supplier) if doc else None,
        software_copyrightText=doc.primary_copyright if doc else None,
        verifiedUsing=_verified(p.hashes),
        purl=p.purl,
        cpes=p.cpes,
    )
    g.rel(iri, "hasDeclaredLicense", _NOASSERTION)
    primary = doc.primary_license if doc else None
    g.rel(iri, "hasConcludedLicense", g.license([primary]) if primary else _NOASSERTION)
    _annotate(g, p.key, iri, p.properties)
    return iri


def _component(g: _Graph, c: Component) -> str:
    author = g.add("Person", "Person", c.author, name=c.author) if c.author else None
    refs = [
        {
            "type": "ExternalRef",
            "externalRefType": _EXT_REFS.get(t, "other"),
            "locator": [u],
        }
        for t, u in c.external_refs
    ]
    iri = g.package(
        "Package",
        c.key,
        _purpose(c.type, "library"),
        name=c.name,
        software_packageVersion=c.version,
        suppliedBy=g.org(c.supplier),
        originatedBy=[author] if author else None,
        description=c.description,
        summary=c.summary,
        comment=c.comment,
        software_homePage=homepage_url(c),
        validUntilTime=_eol(c.eol_date),
        verifiedUsing=_verified(c.hashes),
        externalRef=refs,
        purl=c.purl,
        cpes=c.cpes,
    )
    g.rel(iri, "hasDeclaredLicense", g.license(c.declared_licenses))
    g.rel(iri, "hasConcludedLicense", g.license(c.concluded_licenses))
    _annotate(g, c.key, iri, c.properties)
    return iri


def _exploits(g: _Graph, i: int, v: Vuln, vid: str, pkgs: list[str]) -> None:
    """Exploit data as native Security assessments; maturity has no native field."""
    common = {"from": vid, "relationshipType": "hasAssessmentFor", "to": pkgs}
    catalogs = [("kev", kev_url(v.id) or CISA_KEV)] if v.in_kev else []
    if v.in_vulncheck_kev:
        catalogs.append(("other", VULNCHECK_KEV))
    for kind, locator in catalogs:
        g.add(
            "security_ExploitCatalogVulnAssessmentRelationship",
            "Exploit",
            f"{i}:{kind}:{v.id}",
            **common,
            security_catalogType=kind,
            security_locator=locator,
            security_exploited=True,
        )
    # probability and percentile are both required (3.0.1): never half an EPSS.
    if v.epss_score is not None and v.epss_percentile is not None:
        g.add(
            "security_EpssVulnAssessmentRelationship",
            "Epss",
            f"{i}:{v.id}",
            **common,
            # xsd:decimal in the 3.0.1 context: fixed-point string literals.
            security_probability=decimal_str(v.epss_score),
            security_percentile=decimal_str(v.epss_percentile),
        )
    if v.exploit_maturity:
        statement = f"finitestate:exploit_maturity={v.exploit_maturity}"
        g.add(
            "Annotation",
            "Annotation",
            f"{v.id}|{statement}",
            annotationType="other",
            subject=vid,
            statement=statement,
        )


def _vuln(g: _Graph, i: int, v: Vuln, pkgs: list[str]) -> None:
    url = v.source_url
    vid = g.add(
        "security_Vulnerability",
        "Vuln",
        v.id,
        name=v.id,
        description=v.description,
        externalIdentifier=[
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": (
                    "cve" if v.id.startswith("CVE-") else "securityOther"
                ),
                "identifier": v.id,
            }
        ],
        externalRef=(
            [
                {
                    "type": "ExternalRef",
                    "externalRefType": "securityAdvisory",
                    "locator": [url],
                }
            ]
            if url
            else None
        ),
    )
    for j, r in enumerate(v.ratings):
        version = _CVSS.get(cvss_method(r.vector))
        if not version or r.score is None:
            continue  # "other" ratings have no SPDX 3 assessment class
        g.add(
            f"security_Cvss{version}VulnAssessmentRelationship",
            "Cvss",
            f"{i}:{j}:{v.id}",
            **{"from": vid},
            relationshipType="hasAssessmentFor",
            to=pkgs,
            security_score=r.score,
            security_severity=(
                None if version == "V2" else _severity(r.score, r.severity)
            ),
            security_vectorString=r.vector,
        )
    _exploits(g, i, v, vid, pkgs)
    status = openvex_status(v.state)
    if status not in _VEX:
        # Untriaged: association only, never a fabricated VEX status.
        for p in pkgs:
            g.rel(p, "hasAssociatedVulnerability", vid)
        return
    cls, kind = _VEX[status]
    props: dict[str, Any] = {"from": vid, "relationshipType": kind, "to": pkgs}
    if status == "not_affected":
        just = _JUSTIFICATIONS.get(v.justification or "")
        props["security_justificationType"] = just
        # One of justification/impact statement is required for not_affected.
        props["security_impactStatement"] = v.detail or (
            None if just else f"Triage status: {v.state}"
        )
    else:
        props["security_statusNotes"] = v.detail
    if status == "affected":
        props["security_actionStatement"] = (
            f"Response: {', '.join(v.response)}"
            if v.response
            else "No remediation response recorded."
        )
    g.add(f"security_Vex{cls}VulnAssessmentRelationship", "Vex", f"{i}:{v.id}", **props)


# Neither SPDX 2.3 nor 3.0.1 has a "same element as" type; OTHER / other is
# each spec's type for a relationship it does not define, explained in a comment.
LINK_COMMENT = (
    "Same project version: this placeholder's full SBOM is the external "
    "document whose root element this relationship targets."
)


def build_spdx3(doc: SbomDoc, links: dict[str, str] | None = None) -> dict[str, Any]:
    """Build an SPDX 3.0.1 JSON-LD document (caller does json.dumps).

    ``links`` maps a child project key to the root element IRI of the child's
    own (split) document; its placeholder package gets an ``other`` link to it.
    """
    g = _Graph(doc)
    a = doc.author
    if a.is_org:
        creator = g.add("Organization", "Org", a.name, name=a.name)
    else:
        email = [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": "email",
                "identifier": a.email,
            }
        ]
        creator = g.add(
            "Person",
            "Creator",
            a.name,
            name=a.name,
            externalIdentifier=email if a.email else None,
        )
    tool = g.add("Tool", "Tool", "fs-report", name=f"fs-report {__version__}")
    info = {
        "type": "CreationInfo",
        "@id": _CI,
        "specVersion": "3.0.1",
        "created": _time(doc.timestamp),
        "createdBy": [creator],
        "createdUsing": [tool],
    }
    if doc.lifecycle:
        # sbomType already carries this; sbomqs only reads generation context here.
        info["comment"] = f"lifecycle: {doc.lifecycle}"

    root = _project(g, doc.projects[doc.root], doc)
    for k, p in doc.projects.items():
        if k != doc.root:
            _project(g, p)
    for p in doc.projects.values():
        for ch in p.children:
            g.rel(g.iri("Project", p.key), "contains", g.iri("Project", ch))
            g.rel(g.iri("Project", p.key), "dependsOn", g.iri("Project", ch))
    for key, external in (links or {}).items():
        g.rel(g.iri("Project", key), "other", external)
    # describes mirrors SPDX 2.3 DESCRIBES; sbomqs reads it for the primary component.
    g.rel(g.iri("Document", doc.serial), "describes", root)
    for c in doc.components:
        g.rel(g.iri("Project", c.project_key), "contains", _component(g, c))
    for i, v in enumerate(doc.vulns):
        if v.affects:
            # affects may name a project (folded image record).
            pkgs = [
                g.iri("Project" if k in doc.projects else "Package", k)
                for k in v.affects
            ]
            _vuln(g, i, v, pkgs)

    # User-asserted completeness of the inventory/dependency relationships.
    completeness = _COMPLETENESS.get(doc.completeness, "noAssertion")
    for (src, kind), targets in g.rels.items():
        g.add(
            "Relationship",
            "Relationship",
            f"{src}|{kind}",
            **{"from": src},
            relationshipType=kind,
            to=targets,
            completeness=completeness if kind in ("contains", "dependsOn") else None,
            comment=LINK_COMMENT if kind == "other" else None,
        )

    root_name = doc.projects[doc.root]
    data_license = g.license(["CC0-1.0"])
    members = list(g.elements)
    sbom = g.add(
        "software_Sbom",
        "Sbom",
        doc.serial,
        name=f"{root_name.project_name} {root_name.version_name}".strip(),
        software_sbomType=([_SBOM_TYPE[doc.lifecycle]] if doc.lifecycle else None),
        rootElement=[root],
        element=members,
        profileConformance=_PROFILES,
    )
    spdx_doc = g.add(
        "SpdxDocument",
        "Document",
        doc.serial,
        name=g.elements[sbom]["name"],
        dataLicense=data_license,
        rootElement=[sbom],
        element=[sbom, *members],
        profileConformance=_PROFILES,
    )
    graph = (
        [info]
        + [e for k, e in g.elements.items() if k != spdx_doc]
        + [g.elements[spdx_doc]]
    )
    return {"@context": _CONTEXT, "@graph": graph}
