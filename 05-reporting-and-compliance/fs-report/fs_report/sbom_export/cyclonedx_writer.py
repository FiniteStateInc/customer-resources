"""CycloneDX 1.6/1.7 writer (JSON + XML) for SbomDoc."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID
from xml.sax.saxutils import escape as xml_escape

from cyclonedx.model import (
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    HashType,
    Property,
    XsUri,
)
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component as CdxComponent
from cyclonedx.model.component import ComponentType, Pedigree
from cyclonedx.model.component_evidence import (
    ComponentEvidence,
    Identity,
    IdentityField,
)
from cyclonedx.model.contact import OrganizationalContact, OrganizationalEntity
from cyclonedx.model.license import (
    DisjunctiveLicense,
    LicenseAcknowledgement,
    LicenseExpression,
)
from cyclonedx.model.lifecycle import LifecyclePhase, PredefinedLifecycle
from cyclonedx.model.tool import ToolRepository
from cyclonedx.model.vulnerability import (
    BomTarget,
    ImpactAnalysisJustification,
    ImpactAnalysisResponse,
    ImpactAnalysisState,
    Vulnerability,
    VulnerabilityAdvisory,
    VulnerabilityAnalysis,
    VulnerabilityRating,
    VulnerabilityScoreSource,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.spdx import is_supported_id as is_supported_spdx_id
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.validation.xml import XmlValidator
from packageurl import PackageURL

from fs_report import __version__
from fs_report.sbom_export.mapping import exploit_facts, is_spdx_expression, kev_url
from fs_report.sbom_export.model import (
    Component,
    ProjectNode,
    SbomDoc,
    Supplier,
    Vuln,
)

logger = logging.getLogger(__name__)
Spec = Literal["1.6", "1.7"]
_SCHEMA = {"1.6": SchemaVersion.V1_6, "1.7": SchemaVersion.V1_7}
# exploit_facts key -> vulnerability property name (no native KEV/EPSS field).
_EXPLOIT_PROPS = {"epss": "epss:score", "epss_percentile": "epss:percentile"}
_KEV_TITLE = "CISA Known Exploited Vulnerabilities Catalog"
_PROJECT_TYPES = {
    "firmware",
    "application",
    "device",
    "device-driver",
    "framework",
    "file",
}


def _enum(cls: Any, value: str | None, default: Any = None) -> Any:
    try:
        return cls(value)
    except ValueError:
        return default


def _purl(s: str | None) -> PackageURL | None:
    try:
        return PackageURL.from_string(s) if s else None
    except ValueError:
        return None


def _cpe_evidence(cpes: list[str]) -> ComponentEvidence | None:
    """CPEs beyond the first go in evidence.identity (CycloneDX 1.6+)."""
    if len(cpes) < 2:
        return None
    return ComponentEvidence(
        identity=[
            Identity(field=IdentityField.CPE, concluded_value=x) for x in cpes[1:]
        ]
    )


def _hashes(pairs: list[tuple[str, str]]) -> list[HashType]:
    return [
        HashType(alg=alg, content=content)
        for a, content in pairs
        if (alg := _enum(HashAlgorithm, a))
    ]


def _project_component(p: ProjectNode) -> CdxComponent:
    t = p.project_type.lower()
    return CdxComponent(
        bom_ref=p.key,
        type=ComponentType(t if t in _PROJECT_TYPES else "application"),
        name=p.project_name or p.project_id,
        version=p.version_name,
        purl=_purl(p.purl),
        cpe=p.cpes[0] if p.cpes else None,
        hashes=_hashes(p.hashes),
        properties=[Property(name=n, value=v) for n, v in p.properties],
        evidence=_cpe_evidence(p.cpes),
    )


def _license(
    t: str, ack: LicenseAcknowledgement
) -> LicenseExpression | DisjunctiveLicense | None:
    if t == "NONE":  # SPDX keyword: CycloneDX has no none-licence, omit
        return None
    # Single SPDX id -> license.id; compound (or LicenseRef) -> expression;
    # anything else -> license.name. Case-sensitive: no LicenseFactory.
    if is_supported_spdx_id(t):
        return DisjunctiveLicense(id=t, acknowledgement=ack)
    if is_spdx_expression(t):
        return LicenseExpression(t, acknowledgement=ack)
    return DisjunctiveLicense(name=t, acknowledgement=ack)


def _licence_set(
    ts: list[str], ack: LicenseAcknowledgement
) -> list[LicenseExpression | DisjunctiveLicense]:
    """One set's entries. Several terms with an expression among them are
    AND-ed into one SPDX expression so none is lost to the single-expression
    rule below; if that isn't valid SPDX, each expression is written as a
    named licence instead, so every term is kept."""
    out = [x for t in ts if (x := _license(t, ack))]
    if len(out) > 1 and any(isinstance(x, LicenseExpression) for x in out):
        kept = [t for t in ts if t != "NONE"]
        combined = " AND ".join(f"({t})" if " " in t else t for t in kept)
        if is_spdx_expression(combined):
            return [LicenseExpression(combined, acknowledgement=ack)]
        logger.warning(
            "CycloneDX: licence terms %r don't form an SPDX expression; "
            "writing each as a named licence",
            ts,
        )
        return [
            (
                DisjunctiveLicense(name=x.value, acknowledgement=ack)
                if isinstance(x, LicenseExpression)
                else x
            )
            for x in out
        ]
    return out


def _licenses(c: Component) -> list[LicenseExpression | DisjunctiveLicense]:
    """Both sets, acknowledged (R21). An expression can't share the array
    (CycloneDX 1.6 licenseChoice; the library writes only one expression for
    1.7 too), so a multi-term set with an expression is first AND-ed into one
    expression; then, if any expression remains, the concluded set alone is
    kept whole (declared if none)."""
    concluded = _licence_set(c.concluded_licenses, LicenseAcknowledgement.CONCLUDED)
    declared = _licence_set(c.declared_licenses, LicenseAcknowledgement.DECLARED)
    out = concluded + declared
    if not any(isinstance(x, LicenseExpression) for x in out):
        return out
    return concluded or declared


def _component(c: Component) -> CdxComponent:
    refs = [
        ExternalReference(
            type=_enum(ExternalReferenceType, t, ExternalReferenceType.OTHER),
            url=XsUri(u),
        )
        for t, u in c.external_refs
    ]
    if c.homepage and c.homepage not in {u for _, u in c.external_refs}:
        refs.append(
            ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri(c.homepage))
        )
    props = list(c.properties)
    if c.eol_date:
        props.append(("finitestate:eolDate", c.eol_date))
    if c.comment:
        props.append(("finitestate:comment", c.comment))
    return CdxComponent(
        bom_ref=c.key,
        type=_enum(ComponentType, c.type, ComponentType.LIBRARY),
        group=c.group,
        name=c.name,
        version=c.version,
        purl=_purl(c.purl),
        cpe=c.cpes[0] if c.cpes else None,
        supplier=OrganizationalEntity(name=c.supplier) if c.supplier else None,
        authors=[OrganizationalContact(name=c.author)] if c.author else None,
        licenses=_licenses(c),
        hashes=_hashes(c.hashes),
        description=c.description or c.summary,
        external_references=refs,
        properties=[Property(name=n, value=v) for n, v in props],
        evidence=_cpe_evidence(c.cpes),
        pedigree=(
            Pedigree(
                ancestors=[
                    CdxComponent(
                        # Fixed bom-ref: the library would otherwise mint a random one.
                        bom_ref=f"{c.key}:ancestor",
                        type=_enum(ComponentType, c.type, ComponentType.LIBRARY),
                        name=c.replaced[0],
                        version=c.replaced[1],
                    )
                ]
            )
            if c.replaced
            else None
        ),
    )


def _vuln_ref(v: Vuln) -> str:
    sig = json.dumps(
        [sorted(v.affects), v.state, v.justification, v.response, v.detail]
    )
    return f"{v.id}-{hashlib.sha1(sig.encode()).hexdigest()[:12]}"


def _vulnerability(v: Vuln) -> Vulnerability:
    analysis = None
    if v.state is not None:
        just = _enum(ImpactAnalysisJustification, v.justification)
        analysis = VulnerabilityAnalysis(
            state=ImpactAnalysisState(v.state),
            justification=just,
            responses=[ImpactAnalysisResponse(r) for r in v.response],
            detail=v.detail,
        )
    src = VulnerabilitySource(
        name=v.source_name, url=XsUri(v.source_url) if v.source_url else None
    )
    kev = kev_url(v.id) if v.in_kev else None
    return Vulnerability(
        bom_ref=_vuln_ref(v),
        id=v.id,
        source=src,
        ratings=[
            VulnerabilityRating(
                source=src,
                score=Decimal(str(r.score)) if r.score is not None else None,
                severity=_enum(VulnerabilitySeverity, (r.severity or "").lower(), None),
                method=_enum(VulnerabilityScoreSource, r.method),
                vector=r.vector,
            )
            for r in v.ratings
        ],
        cwes=v.cwes,
        description=v.description,
        affects=[BomTarget(ref=k) for k in v.affects],
        analysis=analysis,
        advisories=(
            [VulnerabilityAdvisory(title=_KEV_TITLE, url=XsUri(kev))] if kev else None
        ),
        properties=[
            Property(name=f"finitestate:{_EXPLOIT_PROPS.get(k, k)}", value=val)
            for k, val in exploit_facts(v)
        ],
    )


def _supplier(s: Supplier | None) -> OrganizationalEntity | None:
    if s is None:
        return None
    return OrganizationalEntity(
        name=s.name,
        urls=[XsUri(s.url)] if s.url else None,
        contacts=[OrganizationalContact(email=s.email)] if s.email else None,
    )


def build_bom(doc: SbomDoc, *, nested: bool = True) -> Bom:
    """Build a cyclonedx-python-lib Bom; nested puts components under their project."""
    nodes = {k: _project_component(p) for k, p in doc.projects.items()}
    # The user-asserted supplier supplies the described product too.
    root = nodes[doc.root]
    root.supplier = _supplier(doc.supplier)
    # User-asserted: the user concludes it. (_license is None for `NONE`.)
    if doc.primary_license and (
        root_lic := _license(doc.primary_license, LicenseAcknowledgement.CONCLUDED)
    ):
        root.licenses = [root_lic]
    root.copyright = doc.primary_copyright
    tool = CdxComponent(
        type=ComponentType.APPLICATION,
        name="fs-report",
        version=__version__,
        supplier=OrganizationalEntity(name="Finite State"),
    )
    a = doc.author
    metadata = BomMetaData(
        timestamp=datetime.fromisoformat(doc.timestamp),
        tools=ToolRepository(components=[tool]),
        # R19: the author (token user or --sbom-author) is never the producer.
        authors=[OrganizationalContact(name=a.name, email=a.email)],
        lifecycles=(
            [PredefinedLifecycle(LifecyclePhase(doc.lifecycle))]
            if doc.lifecycle
            else None
        ),
        component=nodes[doc.root],
        supplier=_supplier(doc.supplier),
        licenses=(
            [DisjunctiveLicense(id=doc.data_license)] if doc.data_license else None
        ),
    )
    bom = Bom(serial_number=UUID(doc.serial), version=1, metadata=metadata)
    # cyclonedx-python-lib has no compositions model: _serialize injects these.
    # Global = the whole BOM (sbomqs sbom_completeness_declared); the
    # dependencies-scoped one covers every node with a dependencies[] entry.
    bom.fs_compositions = [  # type: ignore[attr-defined]
        {"aggregate": doc.completeness},
        {"aggregate": doc.completeness, "dependencies": sorted(doc.projects)},
    ]

    by_project: dict[str, list[CdxComponent]] = {k: [] for k in doc.projects}
    for c in doc.components:
        by_project[c.project_key].append(_component(c))
    for key, node in nodes.items():
        if key == doc.root:
            bom.components.update(by_project[key])
            continue
        bom.components.add(node)
        (node if nested else bom).components.update(by_project[key])
    for key, p in doc.projects.items():
        bom.register_dependency(
            nodes[key], by_project[key] + [nodes[ch] for ch in p.children]
        )
    for v in doc.vulns:
        bom.vulnerabilities.add(_vulnerability(v))
    return bom


def _compositions_xml(comps: list[dict[str, Any]]) -> str:
    out = []
    for c in comps:
        deps = "".join(
            f'<dependency ref="{xml_escape(r, {chr(34): "&quot;"})}"/>'
            for r in c.get("dependencies", [])
        )
        out.append(
            f"<composition><aggregate>{c['aggregate']}</aggregate>"
            + (f"<dependencies>{deps}</dependencies>" if deps else "")
            + "</composition>"
        )
    return f"<compositions>{''.join(out)}</compositions>"


def _serialize(bom: Bom, spec: Spec, encoding: Literal["json", "xml"]) -> str:
    fmt = OutputFormat.JSON if encoding == "json" else OutputFormat.XML
    text = make_outputter(bom, fmt, _SCHEMA[spec]).output_as_string()
    comps = getattr(bom, "fs_compositions", None)
    if not comps:
        return text
    if encoding == "json":
        d = json.loads(text)
        d["compositions"] = comps
        return json.dumps(d)
    # XSD sequence: ... dependencies, compositions, properties, vulnerabilities.
    at = text.find("<vulnerabilities>")
    at = at if at >= 0 else text.rindex("</bom>")
    return text[:at] + _compositions_xml(comps) + text[at:]


def encode_cdx(bom: Bom, spec: Spec, encoding: Literal["json", "xml"]) -> bytes:
    """Serialise and schema-validate; raises ValueError with the first error."""
    text = _serialize(bom, spec, encoding)
    validate_cdx(text, spec, encoding)
    return text.encode("utf-8")


def validate_cdx(text: str, spec: Spec, encoding: Literal["json", "xml"]) -> None:
    """Raise ValueError with the first CycloneDX schema error."""
    validator = (JsonStrictValidator if encoding == "json" else XmlValidator)(
        _SCHEMA[spec]
    )
    error = validator.validate_str(text)
    if error:
        raise ValueError(f"CycloneDX {spec} {encoding} validation failed: {error}")


def cdx_dict(bom: Bom, spec: Spec) -> dict[str, Any]:
    """The CycloneDX JSON form as a dict (for protobuf conversion and JSF signing).

    NOT schema-validated: callers must validate the result or use encode_cdx.
    """
    d: dict[str, Any] = json.loads(_serialize(bom, spec, "json"))
    return d
