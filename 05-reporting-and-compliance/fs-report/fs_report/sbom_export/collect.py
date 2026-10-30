"""Collect platform data for a project version (and its dependency tree) into SbomDoc."""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fs_report.coerce import coerce_license_value
from fs_report.dependency_resolver import DependencyNode, DependencyResolver
from fs_report.models import QueryConfig, QueryParams
from fs_report.sbom_export.mapping import (
    advisory_source,
    cdx_justification,
    cdx_response,
    cdx_state,
    clean_supplier,
    cvss_method,
    license_terms,
    split_cpes,
)
from fs_report.sbom_export.model import (
    Author,
    Component,
    Lifecycle,
    ProjectNode,
    Rating,
    SbomDoc,
    Supplier,
    Vuln,
)
from fs_report.sbom_export.options import SbomOptions

_DROPPED_PROPERTIES = {"finitestate:sbom:vulnerability_match_hints"}
# uniqueTestTypes -> lifecycle (live, 2026-10-26). Binary scans describe the
# built artefact; source scans what precedes the build; an imported SBOM was
# (by design) made at build time. A mixed set takes the latest phase any scan
# reflects; any other set claims no lifecycle.
_POST_BUILD_TESTS = {"SCA", "SAST", "CONFIG", "VULNERABILITY_ANALYSIS"}
_PRE_BUILD_TESTS = {"SOURCE_SCA", "SONARQUBE", "SONARQUBE_DETAILED"}
_BUILD_TESTS = {"SBOM_IMPORT", "SPDX"}
_CWE = re.compile(r"^CWE-(\d+)$")
_MATURITY = {"poc": 1, "weaponized": 2}


def _lifecycle(tests: set[Any]) -> Lifecycle:
    if tests & _POST_BUILD_TESTS:
        return "post-build"
    if tests & _BUILD_TESTS:
        return "build"
    return "pre-build" if tests & _PRE_BUILD_TESTS else None


def _max(a: float | None, b: Any) -> float | None:
    return a if b is None else b if a is None else max(a, b)


def _get_one(api_client: Any, endpoint: str) -> dict[str, Any]:
    rows = api_client.fetch_data(
        QueryConfig(endpoint=endpoint, params=QueryParams()), use_cache=False
    )
    return rows[0] if rows else {}


def _fetch_all(
    api_client: Any,
    endpoint: str,
    flt: str,
    check_cancel: Callable[[], None],
    **extra: Any,
) -> list[dict[str, Any]]:
    query = QueryConfig(
        endpoint=endpoint, params=QueryParams(limit=10000, filter=flt, **extra)
    )
    # strict: no cache (the persistent SQLite cache (web UI default) stores a
    # trimmed column set — no purl, description, hashes, type, CVSS vector or
    # triage detail) and raise on retry exhaustion or a short count: no
    # silent partial SBOM. A Stop lands between pages, not after the fetch.
    rows: list[dict[str, Any]] = api_client.fetch_all_with_resume(
        query, show_progress=False, strict=True, check_cancel=check_cancel
    )
    return rows


def _project_node(project: dict[str, Any], vid: str, vname: str) -> ProjectNode:
    ids = project.get("softwareIdentifiers") or {}
    purls = ids.get("purls") or []
    return ProjectNode(
        key=vid,
        project_id=str(project.get("id", "")),
        project_name=str(project.get("name", "")),
        version_id=vid,
        version_name=vname,
        project_type=str(project.get("type") or ""),
        folder=(project.get("folder") or {}).get("name"),
        purl=purls[0] if purls else None,
        cpes=list(ids.get("cpes") or []),
    )


def _licenses(val: Any) -> list[str]:
    """One term per list item (a multi-licence component); a string is one term."""
    items = val if isinstance(val, list) else [val]
    return [t for i in items for t in license_terms(coerce_license_value([i]), None)[0]]


def _component(c: dict[str, Any], vid: str) -> Component:
    purl = c.get("purl")
    raw_origin = c.get("origin") or c.get("source")
    origin = (
        raw_origin
        if isinstance(raw_origin, str)
        else ",".join(map(str, raw_origin)) if isinstance(raw_origin, list) else ""
    )
    return Component(
        key=f"{vid}:{c['id']}",
        project_key=vid,
        name=str(c.get("name") or ""),
        version=c.get("version") or None,
        type=c.get("type") or "library",
        group=c.get("groupName") or None,
        purl=purl or None,
        cpes=split_cpes(c),
        hashes=[
            (h["alg"], h["content"])
            for h in c.get("hashes") or []
            if h.get("alg") and h.get("content")
        ],
        declared_licenses=_licenses(c.get("declaredLicenses")),
        concluded_licenses=_licenses(c.get("concludedLicenses")),
        supplier=clean_supplier(c.get("supplier"), purl),
        description=c.get("description") or None,
        summary=c.get("summaryDescription") or None,
        homepage=c.get("homepageUrl") or None,
        external_refs=[
            # Lower-case once: every writer maps the type by exact match.
            (str(r.get("type") or "other").strip().lower(), r["url"])
            for r in c.get("externalReferences") or []
            if r.get("url")
        ],
        author=c.get("author") or None,
        eol_date=(c.get("eolDate") or "")[:10] or None,
        comment=c.get("comment") or None,
        properties=[
            (p["name"], str(p.get("value", "")))
            for p in c.get("properties") or []
            if p.get("name") and p["name"] not in _DROPPED_PROPERTIES
        ]
        + ([("finitestate:origin", origin)] if origin else []),
        replaced=_replaced(c.get("replaced")),
    )


def _replaced(r: Any) -> tuple[str, str | None] | None:
    if not isinstance(r, dict) or not r.get("name"):
        return None
    return str(r["name"]), (str(r["version"]) if r.get("version") else None)


def _image_record(
    rows: list[dict[str, Any]], node: ProjectNode, logger: logging.Logger
) -> dict[str, Any] | None:
    """The platform's record of the scanned image itself (it names the project
    version): same name as the project, type firmware or the project's own
    type, no purl. Only a single unambiguous match is returned."""
    types = {node.project_type.lower(), "firmware"}
    hits = [
        c
        for c in rows
        if node.project_name
        and str(c.get("name") or "").lower() == node.project_name.lower()
        and str(c.get("type") or "").lower() in types
        and not c.get("purl")
    ]
    if len(hits) > 1:
        logger.debug("%d image-like components in %s: not folding", len(hits), node.key)
    return hits[0] if len(hits) == 1 else None


def _add_finding(
    vulns: dict[tuple, Vuln], f: dict[str, Any], comp_key: str | None
) -> None:
    fid = str(f["findingId"])
    state = cdx_state(f.get("status"))
    justification = cdx_justification(f.get("justification"))
    response = cdx_response(f.get("response"))
    detail = f.get("reason") or None
    # Merge per findingId, but only across identical triage: findings are
    # triaged per component, and merging different analyses would misreport VEX.
    key = (fid, state, justification, tuple(response), detail)
    v = vulns.get(key)
    if v is None:
        source, url = advisory_source(fid)
        v = vulns[key] = Vuln(
            id=fid,
            source_name=source,
            source_url=url,
            description=f.get("description") or None,
            state=state,
            justification=justification,
            response=response,
            detail=detail,
        )
    # Per-advisory values that should agree; if not, keep the most severe.
    v.in_kev |= f.get("inKev") is True
    v.in_vulncheck_kev |= f.get("inVcKev") is True
    v.epss_score = _max(v.epss_score, f.get("epssScore"))
    v.epss_percentile = _max(v.epss_percentile, f.get("epssPercentile"))
    # weaponized > poc > unknown strings; among equals the first seen stays.
    mat = f.get("exploitMaturity") or None
    cur = v.exploit_maturity
    if mat and (cur is None or _MATURITY.get(mat, 0) > _MATURITY.get(cur, 0)):
        v.exploit_maturity = mat
    if comp_key and comp_key not in v.affects:
        v.affects.append(comp_key)
    vector = f.get("cvssVector") or None
    if f.get("cvssScore") is not None or f.get("severity") or vector:
        rating = Rating(
            source=v.source_name,
            score=f.get("cvssScore"),
            severity=f.get("severity") or None,
            method=cvss_method(vector),
            vector=vector,
        )
        if rating not in v.ratings:
            v.ratings.append(rating)
    for cwe in f.get("cwes") or []:
        m = _CWE.match(str(cwe))
        if m and int(m.group(1)) not in v.cwes:
            v.cwes.append(int(m.group(1)))


def collect(
    api_client: Any,
    project: dict[str, Any],
    version_id: str,
    version_name: str,
    opts: SbomOptions,
    author: Author,
    logger: logging.Logger,
    check_cancel: Callable[[], None] = lambda: None,
) -> SbomDoc:
    """Fetch components (and CVE-type findings) for the version tree into SbomDoc."""
    if opts.include_dependencies:
        tree = DependencyResolver(
            api_client, strict=True, check_cancel=check_cancel
        ).resolve(project["id"], str(project.get("name", "")), version_id)
    else:
        tree = DependencyNode(
            project["id"], str(project.get("name", "")), version_id, []
        )

    projects: dict[str, ProjectNode] = {
        version_id: _project_node(project, version_id, version_name)
    }
    for node in tree.all_nodes():
        vid = str(node.version_id)
        if vid not in projects:
            child = _get_one(api_client, f"/public/v0/projects/{node.project_id}")
            projects[vid] = _project_node(
                child or {"id": node.project_id, "name": node.project_name},
                vid,
                node.version_name,
            )
        # A re-visited node (diamond/cycle) is a childless leaf, so each
        # edge is recorded exactly once, from the first visit.
        for ch in node.children:
            ck = str(ch.version_id)
            if ck != vid and ck not in projects[vid].children:  # no self-loops
                projects[vid].children.append(ck)

    components: list[Component] = []
    vulns: dict[tuple, Vuln] = {}
    dropped: set[str] = set()
    for vid in projects:
        check_cancel()
        emitted: dict[str, str] = {}
        rows = [
            c
            for c in _fetch_all(
                api_client,
                "/public/v0/components",
                f"projectVersion=={vid}",
                check_cancel,
            )
            if c.get("type") != "file" and not c.get("excluded")
        ]
        pnode = projects[vid]
        image = _image_record(rows, pnode, logger)
        if image:
            # Fold into the project node: not a second top-level entry, and
            # its findings affect the project itself.
            rows.remove(image)
            folded = _component(image, vid)
            pnode.hashes = folded.hashes
            if folded.version:  # upload date or version name; the root keeps vname
                pnode.properties.append(("finitestate:image_version", folded.version))
            emitted[str(image["id"])] = vid
        for c in rows:
            comp = _component(c, vid)
            components.append(comp)
            emitted[str(c["id"])] = comp.key
        if not opts.include_vex:
            continue
        for f in _fetch_all(
            api_client,
            "/public/v0/findings",
            f"projectVersion=={vid};type==cve",
            check_cancel,
            archived=False,
            excluded=False,
        ):
            fid = str(f.get("findingId") or "")
            if f.get("type") != "cve" or not fid or fid.startswith("FS-"):
                continue
            comp_key = emitted.get(str((f.get("component") or {}).get("id")))
            if comp_key is None:  # not emitted: contributes nothing
                dropped.add(fid)
                continue
            _add_finding(vulns, f, comp_key)

    gone = dropped - {v.id for v in vulns.values()}
    if gone:
        logger.info(
            "Dropped %d vulnerabilities whose components are not in the SBOM "
            "(file, excluded or unlisted components)",
            len(gone),
        )

    for vid, pnode in projects.items():
        version = _get_one(api_client, f"/public/v0/versions/{vid}")
        if not version:
            logger.warning(
                "Version %s not returned by /versions: lifecycle unknown, "
                "none written",
                vid,
            )
        tests = {t.get("id") for t in version.get("uniqueTestTypes") or []}
        pnode.lifecycle = _lifecycle(tests)
        if not pnode.version_name:  # the dependency record had no label
            pnode.version_name = str(
                version.get("version") or version.get("name") or ""
            )
    return SbomDoc(
        root=version_id,
        projects=projects,
        components=components,
        vulns=list(vulns.values()),
        author=author,
        serial=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        lifecycle=projects[version_id].lifecycle,
        supplier=(
            Supplier(opts.supplier, opts.supplier_url, opts.supplier_email)
            if opts.supplier
            else None
        ),
        data_license=opts.data_license,
        completeness=opts.completeness,
        primary_license=opts.primary_license,
        primary_copyright=opts.primary_copyright,
    )
