"""SBOM Export orchestration: options -> resolve -> collect -> emit -> write -> sign."""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import itertools
import json
import logging
import os
import re
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from jsonschema import Draft202012Validator, validators
from spdx_tools.spdx.model import (
    Checksum,
    ChecksumAlgorithm,
    ExternalDocumentRef,
    Relationship,
    RelationshipType,
)

from fs_report.models import QueryConfig, QueryParams
from fs_report.sbom_export.cdx_protobuf import cdx_json_to_proto
from fs_report.sbom_export.collect import collect
from fs_report.sbom_export.cyclonedx_writer import (
    build_bom,
    encode_cdx,
    validate_cdx,
)
from fs_report.sbom_export.mapping import spdx_id
from fs_report.sbom_export.model import Author, SbomDoc
from fs_report.sbom_export.options import SbomOptions, SbomOptionsError
from fs_report.sbom_export.resolve import resolve_unique_project, resolve_version_id
from fs_report.sbom_export.signing import (
    cosign_sign,
    sign_jsf,
    sign_xmldsig,
)
from fs_report.sbom_export.spdx2_writer import build_spdx2, encode_spdx2
from fs_report.sbom_export.spdx3_writer import LINK_COMMENT, build_spdx3

SUBDIR = "SBOM Export"
_EXT = {
    ("cyclonedx", "json"): "cdx.json",
    ("cyclonedx", "xml"): "cdx.xml",
    ("cyclonedx", "protobuf"): "cdx.pb",
    ("spdx-2.3", "json"): "spdx.json",
    ("spdx-2.3", "yaml"): "spdx.yaml",
    ("spdx-2.3", "xml"): "spdx.xml",
    ("spdx-2.3", "rdf-xml"): "spdx.rdf.xml",
    ("spdx-2.3", "tag-value"): "spdx",
    ("spdx-3.0", "json-ld"): "spdx3.jsonld",
}


_ANY_OF = Draft202012Validator.VALIDATORS["anyOf"]


def _any_of(validator: Any, any_of: Any, instance: Any, schema: Any) -> Any:
    # A "type": "object" branch can never match a non-object, but jsonschema
    # still evaluates the rest of it: for every IRI string that is the whole
    # ~100-class anyOf, ~3 ms each (minutes for a 20k-component SBOM). Dropping
    # those branches for non-objects gives the same verdict.
    if not isinstance(instance, dict):
        any_of = [s for s in any_of if s.get("type") != "object"]
    yield from _ANY_OF(validator, any_of, instance, schema)


_Spdx3Validator = validators.extend(Draft202012Validator, {"anyOf": _any_of})


@functools.cache
def _spdx3_validator(type_: str | None = None) -> Any:
    """The official SPDX 3.0.1 JSON schema; with ``type_``, one @graph item's.

    The schema checks every @graph item against ``anyOf`` all ~100 classes
    under ``unevaluatedProperties``, which jsonschema re-walks branch by branch.
    Every class $def is ``if type == T``, so an item of type T can only match
    $def T: checking it against that $def alone is the same verdict.
    """
    path = Path(__file__).parents[1] / "schemas/spdx-json-schema-3.0.1.json"
    schema = json.loads(path.read_text())
    if type_ is not None:
        schema = {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "type": "object",
            "$ref": f"#/$defs/{type_ if type_ in schema['$defs'] else 'AnyClass'}",
            "unevaluatedProperties": False,
        }
    return _Spdx3Validator(schema)


def _spdx3_error(graph: dict[str, Any]) -> str | None:
    """First SPDX 3.0.1 schema error in a JSON-LD document, or None."""
    errors = itertools.chain(
        _spdx3_validator().iter_errors(graph | {"@graph": []}),
        *(
            _spdx3_validator(str(item.get("type"))).iter_errors(item)
            for item in graph["@graph"]
        ),
    )
    error = next(errors, None)
    return None if error is None else error.message


@dataclass
class _Written:
    """A file already on disk that a parent document links to."""

    key: str
    uri: str  # CycloneDX BOM-link / SPDX 2.3 namespace / SPDX 3 document IRI
    path: Path
    data: bytes


def options_from_config(config: Any) -> SbomOptions:
    """SbomOptions from the ``config.sbom_<field>`` attributes."""
    return SbomOptions(
        **{
            f.name: getattr(config, f"sbom_{f.name}")
            for f in dataclasses.fields(SbomOptions)
        }
    )


def _safe(name: str) -> str:
    """Filesystem-safe name (same rules as ReportRenderer._sanitize_filename)."""
    return re.sub(r'[/\\:*?"<>|]', "_", name).strip(" .") or "sbom"


def _author(api_client: Any, opts: SbomOptions) -> Author:
    if opts.author:
        return Author(name=opts.author, email=None, is_org=True)
    rows = api_client.fetch_data(
        QueryConfig(endpoint="/public/v0/authUser", params=QueryParams()),
        use_cache=False,
    )
    email = str((rows[0] if rows else {}).get("user") or "")
    if not email:
        raise LookupError(
            "Could not determine the current user for the SBOM author; "
            "pass --sbom-author to set it explicitly."
        )
    return Author(name=email, email=email, is_org=False)


def _subdoc(doc: SbomDoc, key: str) -> SbomDoc:
    """One project version as its own document; child projects stay as components."""
    node = doc.projects[key]
    projects = {key: node} | {
        ch: dataclasses.replace(doc.projects[ch], children=[]) for ch in node.children
    }
    components = [c for c in doc.components if c.project_key == key]
    keys = {key} | {c.key for c in components}  # key: findings on a folded image
    vulns = [
        dataclasses.replace(v, affects=[a for a in v.affects if a in keys])
        for v in doc.vulns
    ]
    return dataclasses.replace(
        doc,
        root=key,
        projects=projects,
        components=components,
        vulns=[v for v in vulns if v.affects],
        serial=str(uuid.uuid4()),
        lifecycle=node.lifecycle,
        # The user's supplier is the product's (root) supplier, not the
        # dependency projects'; the completeness attestation covers the run.
        supplier=doc.supplier if key == doc.root else None,
        primary_license=doc.primary_license if key == doc.root else None,
        primary_copyright=doc.primary_copyright if key == doc.root else None,
    )


def _encode(
    doc: SbomDoc, opts: SbomOptions, links: list[_Written]
) -> tuple[bytes, str]:
    """Build, link to already-written children, encode (validated), embed-sign."""
    std, enc = opts.standard, opts.resolved_encoding()
    if std.startswith("cyclonedx-"):
        spec = cast(Literal["1.6", "1.7"], std.removeprefix("cyclonedx-"))
        bom = build_bom(doc)
        by_ref = {c.bom_ref.value: c for c in bom.components}
        for link in links:
            by_ref[link.key].external_references.add(
                ExternalReference(type=ExternalReferenceType.BOM, url=XsUri(link.uri))
            )
        uri = f"urn:cdx:{doc.serial}/1"
        if enc == "protobuf":
            return (
                cdx_json_to_proto(json.loads(encode_cdx(bom, spec, "json")), spec),
                uri,
            )
        if enc == "json":
            data = encode_cdx(bom, spec, "json")
            if opts.sign_embedded:
                signed = sign_jsf(json.loads(data), Path(str(opts.sign_key)))
                data = json.dumps(signed, indent=2, ensure_ascii=False).encode()
                validate_cdx(data.decode(), spec, "json")
            return data, uri
        data = encode_cdx(bom, spec, "xml")
        if opts.sign_embedded:
            data = sign_xmldsig(data, Path(str(opts.sign_key)))
            validate_cdx(data.decode(), spec, "xml")
        return data, uri
    if std == "spdx-2.3":
        document = build_spdx2(doc)
        refs = [
            ExternalDocumentRef(
                "DocumentRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", link.key),
                link.uri,
                Checksum(ChecksumAlgorithm.SHA1, hashlib.sha1(link.data).hexdigest()),
            )
            for link in links
        ]
        document.creation_info.external_document_refs = refs
        # The child placeholder and the child document's root package share
        # one SPDXID. 2.3 has no "same element as" type; OTHER is its type for
        # an undefined relationship, explained in the comment (SPDX 2.3 §11.1).
        document.relationships += [
            Relationship(
                spdx_id("Project", link.key),
                RelationshipType.OTHER,
                f"{ref.document_ref_id}:{spdx_id('Project', link.key)}",
                comment=LINK_COMMENT,
            )
            for link, ref in zip(links, refs, strict=True)
        ]
        data = encode_spdx2(document, cast(Any, enc))
        return data, document.creation_info.document_namespace
    # A child document's root is its project package, at the IRI build_spdx3
    # gives it under the child document's base.
    roots = {
        link.key: link.uri.split("#")[0] + "#" + spdx_id("Project", link.key)
        for link in links
    }
    graph = build_spdx3(doc, roots)
    spdx_doc = next(e for e in graph["@graph"] if e.get("type") == "SpdxDocument")
    if links:
        spdx_doc["import"] = [
            {
                "type": "ExternalMap",
                "externalSpdxId": external,
                "locationHint": link.path.name,
                "verifiedUsing": [
                    {
                        "type": "Hash",
                        "algorithm": "sha256",
                        "hashValue": hashlib.sha256(link.data).hexdigest(),
                    }
                ],
            }
            for link in links
            for external in (link.uri, roots[link.key])
        ]
    data = json.dumps(graph, indent=2).encode()
    error = _spdx3_error(json.loads(data))
    if error is not None:
        raise ValueError(f"SPDX 3.0.1 schema validation failed: {error}")
    return data, str(spdx_doc["spdxId"])


def _stage(path: Path, data: bytes) -> Path:
    """Write ``data`` to a temp file beside ``path``; the caller os.replace()s
    it into place (never a half file) or unlinks it.

    Mode: an existing destination's, else 0o666 minus the umask (as open()).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    # 0o666 through os.open: the kernel applies the umask (os.umask() to read
    # it would race other threads).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o7777)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _emit_order(doc: SbomDoc) -> list[str]:
    """Post-order (children first); each version once. A cycle is rejected:
    a child is linked only once written, so one edge of it would be lost."""
    order: list[str] = []
    seen: set[str] = set()
    path: list[str] = []

    def visit(key: str) -> None:
        if key in path:
            names = [
                f"{doc.projects[k].project_name} {doc.projects[k].version_name}"
                for k in path[path.index(key) :] + [key]
            ]
            raise SbomOptionsError(
                f"project dependency cycle {' → '.join(names)}; --sbom-split is "
                "not supported for cyclic dependencies — run without --sbom-split"
            )
        if key in seen:
            return
        seen.add(key)
        path.append(key)
        for ch in doc.projects[key].children:
            visit(ch)
        path.pop()
        order.append(key)

    visit(doc.root)
    return order


def run_sbom_export(
    api_client: Any,
    config: Any,
    logger: logging.Logger,
    output_dir: Path,
    check_cancel: Callable[[], None] = lambda: None,
    *,
    project: dict[str, Any] | None = None,
) -> list[str]:
    """Export one SBOM (or one per project version with split) and return paths.

    ``project`` is the record the engine's precheck already resolved (same
    rules as ``resolve_unique_project``); without it the project is resolved
    here.

    ``check_cancel`` raises (the engine's ReportCancelled) once the run is
    stopped; it is called before each page of every component, finding and
    dependency fetch (and every half second of a retry wait), before writing,
    before signing and after signing, so a stopped run never reports success.

    Raises SbomOptionsError / AmbiguousProjectError / LookupError / SigningError.
    Files are staged and put in place only once all are encoded, so a failure
    or Stop before that leaves previous files untouched; a replace failing
    partway restores the previous files from backups. After that, files stay
    in place and only a partial cosign bundle is removed.
    """
    opts = options_from_config(config)
    opts.validate()
    if not getattr(config, "project_filter", None):
        raise SbomOptionsError(
            "SBOM Export requires a project: use --project <name-or-id>."
        )

    project = project or resolve_unique_project(
        api_client, str(config.project_filter), getattr(config, "folder_filter", None)
    )
    version_id, version_name = resolve_version_id(
        api_client, project, getattr(config, "version_filter", None)
    )
    author = _author(api_client, opts)
    logger.info(
        "SBOM Export: %s %s as %s %s",
        project.get("name"),
        version_name,
        opts.standard,
        opts.resolved_encoding(),
    )
    doc = collect(
        api_client,
        project,
        version_id,
        version_name,
        opts,
        author,
        logger,
        check_cancel,
    )

    family = "cyclonedx" if opts.standard.startswith("cyclonedx-") else opts.standard
    ext = _EXT[(family, opts.resolved_encoding())]
    keys = _emit_order(doc) if opts.split else [doc.root]
    base = Path(output_dir) / SUBDIR
    cosign = (bool(opts.sign_key) and not opts.sign_embedded) or opts.sign_keyless

    written: dict[str, _Written] = {}
    staged: list[tuple[Path, Path]] = []  # (temp file, destination)
    backups: dict[Path, Path] = {}  # destination -> copy of its previous file
    paths: list[Path] = []  # destinations already replaced by this run
    taken: set[str] = set()  # casefolded file names allocated so far
    try:
        for key in keys:
            check_cancel()
            sub = _subdoc(doc, key) if opts.split else doc
            node = doc.projects[key]
            # Same names in one tree; casefolded, since a case-insensitive
            # filesystem (macOS/Windows default) aliases Router-1 and router-1.
            # Every candidate, fallbacks included, is checked against them.
            stem = f"{_safe(node.project_name)}-{_safe(node.version_name)}"
            name = f"{stem}.{ext}"
            if name.casefold() in taken:
                stem = f"{_safe(key)}-{stem}"
                name, n = f"{stem}.{ext}", 2
                while name.casefold() in taken:
                    name, n = f"{stem}-{n}.{ext}", n + 1
            taken.add(name.casefold())
            path = base / name
            links = [written[ch] for ch in sub.projects[key].children if ch in written]
            data, uri = _encode(sub, opts, links)
            staged.append((_stage(path, data), path))
            written[key] = _Written(key, uri, path, data)
        # All-or-nothing: replace destinations only once every file is encoded
        # and validated, so a failure above leaves previous files untouched.
        check_cancel()  # last Stop point before files are moved into place
        for _, path in staged:
            if path.exists():
                backups[path] = path.with_name(f".{path.name}.{uuid.uuid4().hex}.bak")
                try:
                    os.link(path, backups[path])
                except OSError:
                    shutil.copy2(path, backups[path])
        for tmp, path in staged:
            os.replace(tmp, path)
            paths.append(path)
    except BaseException:
        # A replace failed partway: put the previous set back.
        for path in paths:
            if path in backups:
                os.replace(backups.pop(path), path)
            else:
                path.unlink(missing_ok=True)
        for tmp, _ in staged:
            tmp.unlink(missing_ok=True)
        for bak in backups.values():
            bak.unlink(missing_ok=True)
        raise
    for bak in backups.values():
        bak.unlink(missing_ok=True)
    # Files are in place: a later failure or Stop still fails the run but keeps
    # them (deleting would leave nothing where --overwrite replaced old files).
    check_cancel()
    for path in list(paths) if cosign else []:
        try:
            paths += cosign_sign(
                path,
                key=None if opts.sign_keyless else opts.sign_key,
                keyless=opts.sign_keyless,
                identity_token=opts.sign_identity_token,
                logger=logger,
            )
        except BaseException:
            path.with_name(path.name + ".bundle").unlink(missing_ok=True)
            logger.error(
                "SBOM written but not signed; kept: %s",
                ", ".join(str(p) for p in paths),
            )
            raise
    check_cancel()
    for p in paths:
        logger.info("SBOM Export wrote %s (%d bytes)", p, p.stat().st_size)
    return [str(p) for p in paths]
