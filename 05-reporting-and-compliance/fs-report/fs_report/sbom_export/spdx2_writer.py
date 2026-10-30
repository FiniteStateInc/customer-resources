"""SPDX 2.3 writer (JSON, YAML, XML, RDF/XML, Tag/Value) for SbomDoc."""

from __future__ import annotations

import hashlib
import logging
import re
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from license_expression import get_spdx_licensing  # type: ignore[import-untyped]
from packageurl import PackageURL
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Annotation,
    AnnotationType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    ExtractedLicensingInfo,
    Package,
    PackagePurpose,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
    SpdxNone,
)
from spdx_tools.spdx.validation.external_package_ref_validator import TYPE_TO_REGEX
from spdx_tools.spdx.validation.uri_validators import validate_url
from spdx_tools.spdx.writer.write_anything import write_file

from fs_report import __version__
from fs_report.sbom_export.mapping import (
    LICENSEREF,
    exploit_facts,
    is_spdx_expression,
    kev_url,
    openvex_status,
    spdx_id,
)
from fs_report.sbom_export.model import Component, ProjectNode, SbomDoc, Supplier

log = logging.getLogger(__name__)
Encoding = Literal["json", "yaml", "xml", "rdf-xml", "tag-value"]
_EXT: dict[str, str] = {
    "json": ".spdx.json",
    "yaml": ".spdx.yaml",
    "xml": ".spdx.xml",
    "rdf-xml": ".spdx.rdf.xml",
    "tag-value": ".spdx",
}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "project"


def _project_id(key: str) -> str:
    return spdx_id("Project", key)


def _package_id(key: str) -> str:
    return spdx_id("Package", key)


def _org(name: str | None) -> Actor | SpdxNoAssertion:
    return Actor(ActorType.ORGANIZATION, name) if name else SpdxNoAssertion()


def _purpose(t: str) -> PackagePurpose | None:
    return PackagePurpose.__members__.get(t.upper().replace("-", "_"))


def _checksum(alg: str, value: str) -> Checksum | None:
    # CycloneDX names (SHA-256, SHA3-256, BLAKE2b-256) -> SPDX enum names.
    name = re.sub(r"^SHA-", "SHA", alg.upper()).replace("-", "_")
    a = ChecksumAlgorithm.__members__.get(name)
    return Checksum(a, value.lower()) if a else None


def _ref(category: ExternalPackageRefCategory, kind: str, loc: str) -> Any:
    regex = TYPE_TO_REGEX.get(kind)
    if regex and not re.match(regex, loc):
        return None  # skip rather than emit an invalid locator
    return ExternalPackageRef(category, kind, loc)


def _identity_refs(purl: str | None, cpes: list[str]) -> list[Any]:
    refs: list[Any] = []
    if purl:
        try:
            canonical = PackageURL.from_string(purl).to_string()
        except ValueError:
            canonical = None
        if canonical:
            refs.append(
                _ref(ExternalPackageRefCategory.PACKAGE_MANAGER, "purl", canonical)
            )
    for cpe in cpes:
        kind = "cpe23Type" if cpe.startswith("cpe:2.3:") else "cpe22Type"
        refs.append(_ref(ExternalPackageRefCategory.SECURITY, kind, cpe))
    return [r for r in refs if r]


def _name(lid: str) -> str:
    """LicenseName for a LicenseRef: its suffix, unless that is a keyword
    (``NONE`` / ``NOASSERTION``), which the tag-value and RDF parsers read
    as the keyword rather than a name -- then the full ref id."""
    name = lid.removeprefix("LicenseRef-")
    return lid if name.upper() in {"NONE", "NOASSERTION"} else name


class SpdxLicenses:
    """Licence strings -> SPDX expressions, collecting LicenseRef- texts.

    Shared by the SPDX 2.3 and 3.0 writers so LicenseRef naming matches.
    """

    def __init__(self) -> None:
        self.extracted: dict[str, ExtractedLicensingInfo] = {}

    def _declare(self, text: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9.-]", "-", text)
        lid = f"LicenseRef-{safe}"
        known = self.extracted.get(lid)
        if known and known.extracted_text != text:
            lid += "-" + hashlib.sha1(text.encode()).hexdigest()[:8]
        self.extracted.setdefault(lid, ExtractedLicensingInfo(lid, text, _name(lid)))
        return lid

    def expression(self, terms: list[str]) -> Any:
        if not terms:
            return SpdxNoAssertion()
        if terms == ["NONE"]:
            return SpdxNone()
        parts = []
        for t in terms:
            if is_spdx_expression(t):
                for ref in LICENSEREF.findall(t):
                    # A LicenseRef already inside an SPDX expression has no
                    # licence text on the platform; SPDX requires one, so the
                    # ref name stands in as a placeholder (not real text).
                    if ":" not in ref:
                        self.extracted.setdefault(
                            ref, ExtractedLicensingInfo(ref, ref, _name(ref))
                        )
                parts.append(t if len(terms) == 1 else f"({t})")
            else:
                parts.append(self._declare(t))
        return get_spdx_licensing().parse(" AND ".join(parts))


def _project_package(
    p: ProjectNode,
    advisories: list[tuple[str, str]],
    supplier: Supplier | None = None,
    concluded: Any = None,
    copyright_text: str | None = None,
) -> Package:
    return Package(
        spdx_id=_project_id(p.key),
        name=p.project_name or p.project_id,
        version=p.version_name or None,
        download_location=SpdxNoAssertion(),
        supplier=(
            Actor(ActorType.ORGANIZATION, supplier.name, supplier.email)
            if supplier
            else SpdxNoAssertion()
        ),
        files_analyzed=False,
        checksums=[x for a, v in p.hashes if (x := _checksum(a, v))],
        license_concluded=SpdxNoAssertion() if concluded is None else concluded,
        license_declared=SpdxNoAssertion(),
        copyright_text=copyright_text or SpdxNoAssertion(),
        external_references=_security_refs(_identity_refs(p.purl, p.cpes), advisories),
        primary_package_purpose=_purpose(p.project_type) or PackagePurpose.APPLICATION,
    )


def _other_refs(external_refs: list[tuple[str, str]]) -> list[Any]:
    """Platform external references (vcs, website, ...) as OTHER refs: SPDX 2.3
    has no category for them, and an OTHER type must be an idstring."""
    refs = []
    for t, u in dict.fromkeys(external_refs):
        kind = re.sub(r"[^A-Za-z0-9.]+", "-", t).strip("-")
        if not kind or not u or re.search(r"\s", u):
            log.debug("Skipping malformed external reference %r %r", t, u)
            continue
        refs.append(_ref(ExternalPackageRefCategory.OTHER, kind, u))
    return refs


def homepage_url(c: Component) -> str | None:
    """The component's homepage, else a platform `website` ref (CycloneDX writes
    both as website refs): the first candidate that is a valid URL."""
    sites = [u for t, u in c.external_refs if t == "website"]
    return next((u for u in [c.homepage, *sites] if u and not validate_url(u)), None)


def _security_refs(refs: list[Any], advisories: list[tuple[str, str]]) -> list[Any]:
    refs = refs + [
        _ref(ExternalPackageRefCategory.SECURITY, kind, url)
        for kind, url in dict.fromkeys(advisories)
    ]
    return [r for r in refs if r]


def _date(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value + "T00:00:00") if value else None
    except ValueError:
        log.debug("Skipping malformed eol date %r", value)
        return None


def _package(
    c: Component, lic: SpdxLicenses, advisories: list[tuple[str, str]]
) -> Package:
    concluded = lic.expression(c.concluded_licenses)
    declared = lic.expression(c.declared_licenses)
    return Package(
        spdx_id=_package_id(c.key),
        name=c.name,
        version=c.version,
        download_location=SpdxNoAssertion(),
        supplier=_org(c.supplier),
        originator=Actor(ActorType.PERSON, c.author) if c.author else None,
        files_analyzed=False,
        checksums=[x for a, v in c.hashes if (x := _checksum(a, v))],
        homepage=homepage_url(c),
        license_concluded=concluded,
        license_declared=declared,
        copyright_text=SpdxNoAssertion(),
        summary=c.summary,
        description=c.description,
        comment=c.comment,
        external_references=_security_refs(
            _identity_refs(c.purl, c.cpes) + _other_refs(c.external_refs), advisories
        ),
        primary_package_purpose=_purpose(c.type or "library") or PackagePurpose.OTHER,
        valid_until_date=_date(c.eol_date),
    )


def build_spdx2(doc: SbomDoc) -> Document:
    """Build an spdx-tools 2.3 Document (one package per project and component)."""
    created = datetime.fromisoformat(doc.timestamp).replace(tzinfo=None)
    tool = Actor(ActorType.TOOL, f"fs-report-{__version__}")
    a = doc.author
    creator = (
        Actor(ActorType.ORGANIZATION, a.name)
        if a.is_org
        else Actor(ActorType.PERSON, a.name, a.email)
    )
    root = doc.projects[doc.root]
    info = CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=f"{root.project_name} {root.version_name}".strip(),
        document_namespace=(
            f"https://finitestate.io/spdxdocs/{_slug(root.project_name)}-{doc.serial}"
        ),
        creators=[tool, creator],
        created=created,
        data_license="CC0-1.0",
        creator_comment=f"lifecycle: {doc.lifecycle}" if doc.lifecycle else None,
    )

    def note(target: str, kind: AnnotationType, text: str) -> Annotation:
        return Annotation(target, kind, tool, created, text)

    def target(key: str) -> str:  # affects may name a project (folded image)
        return _project_id(key) if key in doc.projects else _package_id(key)

    # (type, url) SECURITY refs per component key; advisory + CISA KEV url.
    advisories: dict[str, list[tuple[str, str]]] = {}
    annotations: list[Annotation] = []
    exploit_notes: set[tuple[str, str]] = set()
    for v in doc.vulns:
        facts = " ".join(f"{k}={val}" for k, val in exploit_facts(v))
        kev = kev_url(v.id) if v.in_kev else None
        for key in v.affects:
            if v.source_url:
                advisories.setdefault(key, []).append(("advisory", v.source_url))
            if kev:
                advisories.setdefault(key, []).append(("url", kev))
            # No native exploit fields in 2.3: an OTHER note, like properties.
            note_key = (key, f"{v.id} {facts}")
            if facts and note_key not in exploit_notes:
                exploit_notes.add(note_key)
                annotations.append(note(target(key), AnnotationType.OTHER, note_key[1]))
            if v.state is None:
                if not v.source_url and not facts:  # else nothing would name it
                    annotations.append(note(target(key), AnnotationType.OTHER, v.id))
                continue  # untriaged: advisory ref only, never a fabricated status
            text = f"VEX {v.id} status={openvex_status(v.state)}"
            if v.justification:
                text += f" justification={v.justification}"
            if v.response:
                text += f" response={','.join(v.response)}"
            if v.detail:
                text += f" detail={v.detail}"
            annotations.append(note(target(key), AnnotationType.REVIEW, text))

    lic = SpdxLicenses()
    # SPDX 2.3 has no completeness field and no supplier URL: neither is written.
    # The user's supplier / licence / copyright describe the product (root).
    primary = lic.expression([doc.primary_license]) if doc.primary_license else None
    packages = [
        (
            _project_package(
                p, advisories.get(k, []), doc.supplier, primary, doc.primary_copyright
            )
            if k == doc.root
            else _project_package(p, advisories.get(k, []))
        )
        for k, p in doc.projects.items()
    ]
    annotations += [
        note(_project_id(k), AnnotationType.OTHER, f"{n}={val}")
        for k, p in doc.projects.items()
        for n, val in p.properties
    ]
    relationships = [
        Relationship(
            "SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, _project_id(doc.root)
        )
    ]
    for p in doc.projects.values():
        for ch in p.children:
            for kind in (RelationshipType.CONTAINS, RelationshipType.DEPENDS_ON):
                relationships.append(
                    Relationship(_project_id(p.key), kind, _project_id(ch))
                )
    for c in doc.components:
        pid = _package_id(c.key)
        packages.append(_package(c, lic, advisories.get(c.key, [])))
        relationships.append(
            Relationship(_project_id(c.project_key), RelationshipType.CONTAINS, pid)
        )
        annotations += [
            note(pid, AnnotationType.OTHER, f"{n}={val}") for n, val in c.properties
        ]

    return Document(
        creation_info=info,
        packages=packages,
        relationships=relationships,
        annotations=annotations,
        extracted_licensing_info=list(lic.extracted.values()),
    )


def encode_spdx2(document: Document, encoding: Encoding) -> bytes:
    """Serialise via spdx-tools (validates; raises ValueError when invalid)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"sbom{_EXT[encoding]}"
        write_file(document, str(path), validate=True)
        # spdx-tools writes in text mode, so Windows gets CRLF; normalise so
        # every platform emits identical bytes and the anchored fixups match.
        data = path.read_bytes().replace(b"\r\n", b"\n")
        return _spec_spelling(data, encoding)


# spdx-tools 0.8.5 writes enum *names* (OPERATING_SYSTEM, PACKAGE_MANAGER) where
# the 2.3 spec spells values with hyphens (the JSON schema rejects
# OPERATING_SYSTEM), and RDF NOASSERTION download locations and listed licence
# exceptions in shapes that tools-java 2.x rejects. Both spellings parse back in spdx-tools. Patterns are
# anchored to the writer's own field syntax so free text is never touched:
# JSON strings cannot hold raw newlines, XML text escapes "<", YAML values
# continue at a deeper indent, and tag-value multi-line text sits in <text>.
_ENUM = rb"(OPERATING|PACKAGE|PERSISTENT)_(SYSTEM|MANAGER|ID)"
_FIXUPS: dict[str, list[tuple[re.Pattern[bytes], bytes]]] = {
    "json": [
        (
            re.compile(
                rb'^(\s*"(?:primaryPackagePurpose|referenceCategory)": ")' + _ENUM,
                re.M,
            ),
            rb"\1\2-\3",
        )
    ],
    "yaml": [
        (
            re.compile(
                rb"^(  (?:- )?(?:primaryPackagePurpose|referenceCategory): )"
                + _ENUM
                + rb"$",
                re.M,
            ),
            rb"\1\2-\3",
        )
    ],
    "xml": [
        (
            re.compile(rb"(<(primaryPackagePurpose|referenceCategory)>)" + _ENUM),
            rb"\1\3-\4",
        )
    ],
    "tag-value": [
        (
            re.compile(rb"^((?:PrimaryPackagePurpose|ExternalRef): )" + _ENUM, re.M),
            rb"\1\2-\3",
        )
    ],
    "rdf-xml": [
        (
            re.compile(
                rb'<spdx:downloadLocation rdf:resource="'
                rb'http://spdx.org/rdf/terms#noassertion"/>'
            ),
            rb"<spdx:downloadLocation>NOASSERTION</spdx:downloadLocation>",
        ),
        # A listed exception (spdx.org/licenses/ IRI) is a ListedLicenseException;
        # tools-java rejects the same IRI typed as a plain LicenseException.
        (
            re.compile(
                rb'<spdx:LicenseException (rdf:about="http://spdx.org/licenses/)'
            ),
            rb"<spdx:ListedLicenseException \1",
        ),
    ],
}
_TV_TEXT = re.compile(rb"(<text>.*?</text>)", re.S)
_ENUM_KEYS = {"primaryPackagePurpose", "referenceCategory"}
_UNDERSCORED = re.compile(r"[A-Z]+(?:_[A-Z]+)+")
# libyaml-backed when PyYAML has it, as in recipe_loader.
try:
    _YamlLoader: type[yaml.SafeLoader] | type[yaml.CSafeLoader] = yaml.CSafeLoader
except AttributeError:  # pragma: no cover - depends on the PyYAML wheel
    _YamlLoader = yaml.SafeLoader


def _regex_leftover(pattern: re.Pattern[bytes]) -> Callable[[bytes], str | None]:
    def find(data: bytes) -> str | None:
        m = pattern.search(data)
        value = re.search(_ENUM, m.group(0)) if m else None
        return value.group(0).decode() if value else None

    return find


def _yaml_leftover(data: bytes) -> str | None:
    # Parsed, not matched: PyYAML folds long text onto continuation lines,
    # which can start with a field name.
    # Parsed, so any underscore value is caught, not only the known three.
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in _ENUM_KEYS and isinstance(v, str) and _UNDERSCORED.fullmatch(v):
                    found.append(v)
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    try:
        parsed = yaml.load(data, Loader=_YamlLoader)
    except yaml.YAMLError as e:
        raise ValueError(
            "SPDX 2.3 yaml: spdx-tools output could not be parsed back "
            f"({e}); check the installed spdx-tools version"
        ) from e
    walk(parsed)
    return found[0] if found else None


# Looser than the fix-ups (any spacing / attributes): an underscore spelling
# still left in an enum field means spdx-tools' output changed under them.
# JSON strings escape quotes and XML text escapes "<", so free text can't match.
_LEFTOVER: dict[str, Callable[[bytes], str | None]] = {
    "json": _regex_leftover(
        re.compile(
            rb'(?<!\\)"(?:primaryPackagePurpose|referenceCategory)"\s*:\s*"' + _ENUM
        )
    ),
    "yaml": _yaml_leftover,
    "xml": _regex_leftover(
        re.compile(rb"<(?:primaryPackagePurpose|referenceCategory)[^>]*>\s*" + _ENUM)
    ),
    "tag-value": _regex_leftover(
        re.compile(rb"^(?:PrimaryPackagePurpose|ExternalRef):\s*" + _ENUM, re.M)
    ),
}


def _spec_spelling(data: bytes, encoding: Encoding) -> bytes:
    # Odd split parts are tag-value <text> blocks; only patch outside them.
    parts = _TV_TEXT.split(data) if encoding == "tag-value" else [data]
    for i in range(0, len(parts), 2):
        for pattern, repl in _FIXUPS[encoding]:
            parts[i] = pattern.sub(repl, parts[i])
        left = _LEFTOVER.get(encoding)
        if left and (found := left(parts[i])):
            raise ValueError(
                f"SPDX 2.3 {encoding}: spdx-tools output no longer matches the "
                f"enum spelling fix-ups (found {found!r}, invalid SPDX); check "
                "the installed spdx-tools version"
            )
    return b"".join(parts)
