#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = ["requests>=2.25.0"]
# ///

"""
Branch a Finite State project version into a NEW project, carrying its triage.

What it copies, in order:
  1. The version's components, by exporting it as CycloneDX and importing that
     SBOM into a new project (no rescan; same component identities).
  2. Component exclusions (with their comment and "exclude in future versions").
  3. Component statuses and status comments.
  4. Finding VEX: status, justification, response and reason.
  5. Finding comments (author and date kept as a prefix in the comment text).
  6. Optionally (--include-dependencies), the version's project-version links.

Component edits arrive as the edited values, because the export carries the
current values. See README.md for the full list of what is and is not copied.

Environment:
  FINITE_STATE_AUTH_TOKEN   API token
  FINITE_STATE_DOMAIN       e.g. acme.finitestate.io

Examples:
  python clone_version.py --source-version <versionId> --new-project-name "Product X (branch)" --dry-run
  python clone_version.py --source-version <versionId> --new-project-name "Product X (branch)" --report report.json
  python clone_version.py --self-test

API endpoints used (all under /api/public/v0):
  GET  /versions/{id}, GET /projects/{id}, GET /components, GET /findings
  GET  /sboms/cyclonedx/{id}, GET /project-versions/{id}/dependencies
  POST /projects, POST /projects/{id}/versions, DELETE /versions/{id}
  POST /scans/sbom, POST /scans/{id}/process, GET /scans/{id}/status
  PUT  /components/{versionId}/exclude, PUT /components/{versionId}/{componentId}/status
  PUT  /findings/{versionId}/status/bulk, POST /findings/{versionId}/{findingId}/comments
  POST /project-versions/{id}/dependencies
"""

import argparse
import json
import os
import sys
import time

import requests

PAGE_SIZE = 1000
BULK_SIZE = 500  # API max for exclude and bulk finding status
DEFAULT_COMPONENT_STATUS = "NEEDS_REVIEW"
SCAN_DONE = {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
SCAN_FAILED = {"ERROR", "FAILED", "CANCELLED"}
RETRY_STATUSES = {429, 502, 503, 504}

# ponytail: fixed spacing keeps us under the ~100 requests/minute public API limit;
# switch to a token bucket if large clones need to go faster.
MIN_INTERVAL_SECONDS = 0.65


class Api:
    """Thin requests wrapper: auth header, pacing, and retry on 429/5xx."""

    def __init__(self, token, domain, dry_run=False):
        self.base = f"https://{domain}/api/public/v0"
        self.session = requests.Session()
        self.session.headers.update({"X-Authorization": token, "Accept": "application/json"})
        self.dry_run = dry_run
        self._last = 0.0
        self.failures = []

    def request(self, method, path, *, params=None, body=None, raw_url=None, data=None, headers=None, ok=(200, 201, 202, 204)):
        if self.dry_run and method != "GET" and raw_url is None:
            raise RuntimeError(f"dry run attempted a write: {method} {path}")
        url = raw_url or f"{self.base}{path}"
        for attempt in range(6):
            wait = MIN_INTERVAL_SECONDS - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()
            if raw_url:
                resp = requests.request(method, url, data=data, headers=headers, timeout=600)
            else:
                resp = self.session.request(method, url, params=params, json=body, timeout=300)
            if resp.status_code in RETRY_STATUSES and attempt < 5:
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** (attempt + 1)
                print(f"  {resp.status_code} on {method} {path or 'upload'}; retrying in {delay:.0f}s")
                time.sleep(delay)
                continue
            if resp.status_code not in ok:
                raise ApiError(method, path or url.split("?")[0], resp)
            return resp
        raise ApiError(method, path, resp)

    def get(self, path, **params):
        return self.request("GET", path, params=params or None)

    def get_json(self, path, **params):
        return self.get(path, **params).json()

    def get_all(self, path, **params):
        """Page through a list endpoint that returns a bare array or {items: [...]}."""
        rows, offset = [], 0
        while True:
            body = self.get_json(path, **params, limit=PAGE_SIZE, offset=offset)
            page = body.get("items", []) if isinstance(body, dict) else body
            rows.extend(page)
            if len(page) < PAGE_SIZE:
                return rows
            offset += PAGE_SIZE


class ApiError(Exception):
    def __init__(self, method, path, resp):
        try:
            detail = resp.json()
        except ValueError:
            detail = resp.text[:500]
        super().__init__(f"{method} {path} -> HTTP {resp.status_code}: {detail}")
        self.status = resp.status_code


# ---------------------------------------------------------------------------
# Matching (pure functions, covered by --self-test)
# ---------------------------------------------------------------------------


def _norm(value):
    return (value or "").strip().lower()


def component_key(c):
    """Identity used to find the same component after re-import.

    purl when present, otherwise (group, name, version, type) -- the same
    fallback the platform's own version-to-version carry-forward uses.
    """
    purl = _norm(c.get("purl"))
    if purl:
        return ("purl", purl)
    return ("coords", _norm(c.get("groupName") or c.get("group")), _norm(c.get("name")), _norm(c.get("version")), _norm(c.get("type")))


def map_components(source, target):
    """Return ({source_id: target_id}, [unmatched source components]).

    Duplicate keys in the target are matched in order, so two identical
    source rows land on two different target rows when both exist.
    """
    pool = {}
    for t in target:
        pool.setdefault(component_key(t), []).append(t["id"])
    mapping, unmatched = {}, []
    for s in source:
        ids = pool.get(component_key(s))
        if ids:
            mapping[s["id"]] = ids.pop(0)
        else:
            unmatched.append(s)
    return mapping, unmatched


def finding_component_id(f):
    # On a finding, component.id is the version-scoped component row id (the
    # same value as a component's `id` in /components). component.vcId there is
    # the global component id, so it must not be used for matching.
    return (f.get("component") or {}).get("id")


def map_findings(source_findings, target_findings, component_map):
    """Return ([(source_finding, target_finding_id)], [unmatched source findings]).

    A finding is the same when its CVE/finding id matches and its component is
    the mapped component -- never by CVE alone, which would also hit other
    components carrying the same CVE.
    """
    index = {}
    for t in target_findings:
        index.setdefault((finding_component_id(t), _norm(t.get("findingId"))), []).append(t["id"])
    pairs, unmatched = [], []
    for s in source_findings:
        target_component = component_map.get(finding_component_id(s))
        ids = index.get((target_component, _norm(s.get("findingId")))) if target_component else None
        if ids:
            pairs.append((s, ids.pop(0)))
        else:
            unmatched.append(s)
    return pairs, unmatched


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def read_version(api, version_id):
    version = api.get_json(f"/versions/{version_id}")
    project_id = (version.get("project") or {}).get("id")
    project = api.get_json(f"/projects/{project_id}") if project_id else {}
    # The list returns either side of the exclusion flag, so read both.
    comps = {}
    for excluded in ("false", "true"):
        for c in api.get_all("/components", filter=f"projectVersion=={version_id}", excluded=excluded):
            comps[c["id"]] = c
    findings = api.get_all("/findings", versionId=version_id, includeComments="true")
    return version, project, list(comps.values()), findings


def export_sbom(api, version_id, components):
    """CycloneDX export without VEX, plus the excluded components the export omits."""
    bom = api.get_json(f"/sboms/cyclonedx/{version_id}", includeVex="false", includeDependencies="true")
    bom_components = bom.setdefault("components", [])
    present = {component_key({"purl": c.get("purl"), "group": c.get("group"), "name": c.get("name"), "version": c.get("version"), "type": c.get("type")}) for c in bom_components}
    added = 0
    for c in components:
        if not c.get("excluded") or component_key(c) in present:
            continue
        entry = {"type": c.get("type") or "library", "name": c["name"], "bom-ref": f"excluded-{c['id']}"}
        for src, dst in (("version", "version"), ("groupName", "group"), ("purl", "purl"), ("cpe", "cpe")):
            if c.get(src):
                entry[dst] = c[src]
        if c.get("supplier"):
            entry["supplier"] = {"name": c["supplier"]}
        if c.get("declaredLicenses"):
            entry["licenses"] = [{"expression": c["declaredLicenses"]}]
        bom_components.append(entry)
        added += 1
    return bom, added


def create_target(api, project, version, new_project_name, folder_id, version_name, release_type):
    body = {
        "name": new_project_name,
        "description": f"Branched from {project.get('name', '?')} / {version.get('name', '?')}. {project.get('description') or ''}".strip(),
        "type": project.get("type") or "application",
    }
    if folder_id:
        body["folderId"] = folder_id
    new_project = api.request("POST", "/projects", body=body).json()
    placeholders = api.get_all(f"/projects/{new_project['id']}/versions")
    new_version = api.request(
        "POST", f"/projects/{new_project['id']}/versions", body={"version": version_name, "releaseType": release_type}
    ).json()
    # Project creation makes a dated, empty placeholder version; remove it.
    leftover = []
    for p in placeholders:
        try:
            api.request("DELETE", f"/versions/{p['id']}")
        except ApiError as e:
            leftover.append({"id": p["id"], "name": p.get("name"), "error": str(e)})
    return new_project, new_version, leftover


def import_sbom(api, version_id, bom, file_name):
    scan = api.request(
        "POST", "/scans/sbom", body={"projectVersionId": version_id, "sbomFormat": "cyclonedx", "fileName": file_name}
    ).json()
    api.request(
        "PUT", "", raw_url=scan["uploadUrl"], data=json.dumps(bom).encode(), headers={"Content-Type": "application/json"}
    )
    api.request("POST", f"/scans/{scan['scanId']}/process")
    return wait_for_scan(api, scan["scanId"])


def wait_for_scan(api, scan_id):
    print(f"  scan {scan_id} processing", end="", flush=True)
    while True:
        status = api.get_json(f"/scans/{scan_id}/status")
        state = (status.get("status") or "").upper()
        print(".", end="", flush=True)
        if state in SCAN_DONE:
            print(f" {state}: {status.get('componentCount')} components, {status.get('findingCount')} findings")
            return status
        if state in SCAN_FAILED:
            print()
            raise RuntimeError(f"SBOM import failed: {status.get('errorMessage') or state}")
        time.sleep(10)


def apply_exclusions(api, target_version_id, source_components, component_map, report):
    groups = {}
    for c in source_components:
        if c.get("excluded") and c["id"] in component_map:
            key = (c.get("exclusionComment") or "", bool(c.get("includeInFutureVersions", True)))
            groups.setdefault(key, []).append(component_map[c["id"]])
    for (comment, future), ids in groups.items():
        for batch in chunks(ids, BULK_SIZE):
            body = {"componentIds": batch, "excludeInFutureVersions": future}
            if comment:
                body["comment"] = comment[:1000]
            _try(api, report, "PUT", f"/components/{target_version_id}/exclude", body, f"exclude {len(batch)} components")
            report["applied"]["exclusions"] += len(batch)


def apply_component_statuses(api, target_version_id, source_components, component_map, report):
    for c in source_components:
        status = c.get("status")
        if c["id"] not in component_map or not status or (status == DEFAULT_COMPONENT_STATUS and not c.get("statusComment")):
            continue
        body = {"status": status}
        if c.get("statusComment"):
            body["statusComment"] = c["statusComment"]
        target_id = component_map[c["id"]]
        if _try(api, report, "PUT", f"/components/{target_version_id}/{target_id}/status", body, f"status {c['name']}"):
            report["applied"]["component_statuses"] += 1


def apply_finding_vex(api, target_version_id, pairs, report):
    items = []
    for s, target_id in pairs:
        if not s.get("status"):
            continue
        item = {"findingId": target_id, "status": s["status"]}
        for field in ("justification", "response", "reason"):
            if s.get(field):
                item[field] = s[field]
        items.append(item)
    for batch in chunks(items, BULK_SIZE):
        if _try(api, report, "PUT", f"/findings/{target_version_id}/status/bulk", {"findings": batch}, f"VEX x{len(batch)}"):
            report["applied"]["finding_vex"] += len(batch)


def apply_finding_comments(api, target_version_id, pairs, origin, report):
    for s, target_id in pairs:
        # Oldest first, so the copied thread reads in the original order.
        for comment in sorted(s.get("comments") or [], key=lambda c: c.get("date") or ""):
            text = comment.get("text")
            if not text:
                continue
            prefix = f"[Copied from {origin} - {comment.get('author', 'unknown')}, {comment.get('date', '')}]\n"
            body = {"comment": (prefix + text)[:10000]}
            if _try(api, report, "POST", f"/findings/{target_version_id}/{target_id}/comments", body, f"comment on {s.get('findingId')}"):
                report["applied"]["finding_comments"] += 1


def apply_dependencies(api, source_version_id, target_version_id, report):
    for dep in api.get_all(f"/project-versions/{source_version_id}/dependencies"):
        dep_version = (dep.get("dependencyProjectVersion") or {}).get("id")
        if dep.get("redacted") or not dep_version:
            report["skipped_dependencies"].append(dep)
            continue
        body = {"dependencyProjectVersionId": dep_version, "relationshipType": dep.get("relationshipType") or "depends_on"}
        if "carryForward" in dep:
            body["carryForward"] = dep["carryForward"]
        if _try(api, report, "POST", f"/project-versions/{target_version_id}/dependencies", body, f"dependency {dep_version}"):
            report["applied"]["dependencies"] += 1


def _try(api, report, method, path, body, label):
    try:
        api.request(method, path, body=body)
        return True
    except ApiError as e:
        print(f"  FAILED {label}: {e}")
        report["failures"].append({"action": label, "error": str(e)})
        return False


def verify(api, target_version_id, source_components, source_findings, component_map, finding_pairs):
    """Re-read the target and list every triage value that did not land."""
    target_components = {}
    for excluded in ("false", "true"):
        for c in api.get_all("/components", filter=f"projectVersion=={target_version_id}", excluded=excluded):
            target_components[c["id"]] = c
    target_findings = {f["id"]: f for f in api.get_all("/findings", versionId=target_version_id)}
    diffs = []
    for s in source_components:
        t = target_components.get(component_map.get(s["id"]))
        if not t:
            continue
        if bool(s.get("excluded")) != bool(t.get("excluded")):
            diffs.append({"component": s["name"], "field": "excluded", "source": s.get("excluded"), "target": t.get("excluded")})
        if s.get("status") and s.get("status") != t.get("status"):
            diffs.append({"component": s["name"], "field": "status", "source": s.get("status"), "target": t.get("status")})
    for s, target_id in finding_pairs:
        t = target_findings.get(target_id, {})
        for field in ("status", "justification", "response"):
            if s.get(field) and s.get(field) != t.get(field):
                diffs.append({"finding": s.get("findingId"), "field": field, "source": s.get(field), "target": t.get(field)})
    return diffs


# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-version", help="ID of the version to branch")
    parser.add_argument("--new-project-name", help="Name of the project to create")
    parser.add_argument("--version-name", help="Name for the new version (default: the source version's name)")
    parser.add_argument("--release-type", default="RELEASE", choices=["RELEASE", "PRE-RELEASE"])
    parser.add_argument("--folder-id", help="Folder to create the project in")
    parser.add_argument("--include-dependencies", action="store_true", help="Also copy project-version dependency links")
    parser.add_argument("--skip-comments", action="store_true", help="Do not copy finding comments")
    parser.add_argument("--target-version", help="Resume into a version an earlier run already created and imported")
    parser.add_argument("--dry-run", action="store_true", help="Read the source and show what would be copied; no writes")
    parser.add_argument("--report", default="clone_report.json", help="Where to write the JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run the built-in matching checks and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if not args.source_version or (not args.new_project_name and not args.dry_run and not args.target_version):
        parser.error("--source-version and --new-project-name (or --target-version) are required")

    token, domain = os.environ.get("FINITE_STATE_AUTH_TOKEN"), os.environ.get("FINITE_STATE_DOMAIN")
    if not token or not domain:
        parser.error("set FINITE_STATE_AUTH_TOKEN and FINITE_STATE_DOMAIN")
    api = Api(token, domain, dry_run=args.dry_run)

    print(f"Reading source version {args.source_version} ...")
    version, project, components, findings = read_version(api, args.source_version)
    origin = f"{project.get('name', '?')} / {version.get('name', '?')}"
    triaged = [f for f in findings if f.get("status")]
    commented = sum(len(f.get("comments") or []) for f in findings)
    print(f"  {origin}: {len(components)} components ({sum(1 for c in components if c.get('excluded'))} excluded), "
          f"{len(findings)} findings ({len(triaged)} with VEX, {commented} comments)")

    # Limitation: file components (config files, certificates, carved binaries) and
    # the binary-analysis findings on them come from scanning the original binary.
    # An SBOM import cannot recreate them, so they are reported, not cloned.
    file_ids = {c["id"] for c in components if c.get("type") == "file"}
    file_findings = [f for f in findings if finding_component_id(f) in file_ids]
    if file_ids:
        lost = sum(1 for f in file_findings if f.get("status") or f.get("comments"))
        print(f"  not carried: {len(file_ids)} file components with {len(file_findings)} binary-analysis findings "
              f"({lost} of them triaged or commented)")
    components = [c for c in components if c["id"] not in file_ids]
    findings = [f for f in findings if finding_component_id(f) not in file_ids]
    # The version's own root component (the project itself) is not copied: the new
    # project gets its own root when the SBOM is imported.
    components = [c for c in components if not c.get("projectModule")]

    bom, added = export_sbom(api, args.source_version, components)
    print(f"  exported CycloneDX: {len(bom.get('components', []))} components ({added} excluded components added back)")

    report = {
        "source": {"project": project.get("name"), "version": version.get("name"), "versionId": args.source_version},
        "applied": {"exclusions": 0, "component_statuses": 0, "finding_vex": 0, "finding_comments": 0, "dependencies": 0},
        "failures": [], "skipped_dependencies": [], "unmatched_components": [], "unmatched_findings": [], "diffs": [],
        "not_carried": {
            "file_components": len(file_ids),
            "binary_analysis_findings": len(file_findings),
            "triaged_binary_analysis_findings": [
                {"findingId": f.get("findingId"), "component": (f.get("component") or {}).get("name"), "status": f.get("status")}
                for f in file_findings if f.get("status") or f.get("comments")
            ],
        },
    }

    if args.dry_run:
        bom_as_components = [
            {"id": str(i), "purl": c.get("purl"), "groupName": c.get("group"), "name": c.get("name"), "version": c.get("version"), "type": c.get("type")}
            for i, c in enumerate(bom.get("components", []))
        ]
        _, unmatched = map_components(components, bom_as_components)
        status_count = sum(1 for c in components if c.get("status") and c.get("status") != DEFAULT_COMPONENT_STATUS)
        print("\nDry run - would create:")
        print(f"  project '{args.new_project_name or '<name>'}' with version '{args.version_name or version.get('name')}'")
        print(f"  exclusions: {sum(1 for c in components if c.get('excluded'))}, component statuses: {status_count}, "
              f"finding VEX: {len(triaged)}, comments: {0 if args.skip_comments else commented}")
        print(f"  components the export would not carry (unmatched): {len(unmatched)}")
        for c in unmatched[:20]:
            print(f"    - {c.get('groupName') or ''}{'/' if c.get('groupName') else ''}{c['name']} {c.get('version') or ''}")
        report["unmatched_components"] = [{"name": c["name"], "version": c.get("version"), "purl": c.get("purl")} for c in unmatched]
        _write_report(args.report, report)
        return 0

    if args.target_version:
        # Resume: the project and the SBOM import already exist from an earlier run.
        target = api.get_json(f"/versions/{args.target_version}")
        new_version = {"id": args.target_version}
        new_project = {"id": (target.get("project") or {}).get("id")}
        report["target"] = {"projectId": new_project["id"], "versionId": new_version["id"], "resumed": True}
        print(f"Resuming into existing version {args.target_version} ...")
        scans = api.get_json(f"/versions/{args.target_version}/scans", sort="created:desc", limit=1)
        scans = scans.get("items", []) if isinstance(scans, dict) else scans
        if not scans:
            raise SystemExit("The target version has no scan; run without --target-version to create one.")
        wait_for_scan(api, scans[0]["id"])
    else:
        print(f"Creating project '{args.new_project_name}' ...")
        new_project, new_version, leftover = create_target(
            api, project, version, args.new_project_name, args.folder_id, args.version_name or version["name"], args.release_type
        )
        report["target"] = {"projectId": new_project["id"], "versionId": new_version["id"], "leftover_placeholder_versions": leftover}
        print(f"  new version: {new_version['id']} (pass as --target-version to resume if this run stops)")

        print("Importing SBOM ...")
        import_sbom(api, new_version["id"], bom, f"{version.get('name', 'version')}-branch.cdx.json")

    print("Matching components and findings ...")
    target_components = {}
    for excluded in ("false", "true"):
        for c in api.get_all("/components", filter=f"projectVersion=={new_version['id']}", excluded=excluded):
            target_components[c["id"]] = c
    component_map, unmatched_components = map_components(components, list(target_components.values()))
    target_findings = api.get_all("/findings", versionId=new_version["id"])
    pairs, unmatched_findings = map_findings(findings, target_findings, component_map)
    report["unmatched_components"] = [{"name": c["name"], "version": c.get("version"), "purl": c.get("purl")} for c in unmatched_components]
    # A finding whose component made it across but which the new version does not
    # report is not a copy failure: the new version is matched against today's
    # vulnerability data, and the CVE no longer applies to that component version
    # (typically its affected range was corrected after the original scan).
    report["unmatched_findings"] = [
        {"findingId": f.get("findingId"), "component": (f.get("component") or {}).get("name"),
         "status": f.get("status"), "comments": len(f.get("comments") or []),
         "reason": "no_longer_reported" if finding_component_id(f) in component_map else "component_missing"}
        for f in unmatched_findings
    ]
    print(f"  components matched {len(component_map)}/{len(components)}, findings matched {len(pairs)}/{len(findings)}")

    print("Applying triage ...")
    apply_exclusions(api, new_version["id"], components, component_map, report)
    apply_component_statuses(api, new_version["id"], components, component_map, report)
    apply_finding_vex(api, new_version["id"], pairs, report)
    if not args.skip_comments:
        apply_finding_comments(api, new_version["id"], pairs, origin, report)
    if args.include_dependencies:
        apply_dependencies(api, args.source_version, new_version["id"], report)

    print("Verifying ...")
    report["diffs"] = verify(api, new_version["id"], components, findings, component_map, pairs)
    _write_report(args.report, report)

    print(f"\nNew project: https://{domain}/projects/{new_project['id']}/versions/{new_version['id']}")
    print(f"Applied: {report['applied']}")
    triaged = [f for f in report["unmatched_findings"] if f.get("status") or f.get("comments")]
    no_longer = [f for f in triaged if f["reason"] == "no_longer_reported"]
    lost_triage = [f for f in triaged if f["reason"] == "component_missing"]
    if no_longer:
        print(f"Note: {len(no_longer)} triaged findings are no longer reported in the new version. Their components were "
              f"copied, but current vulnerability data no longer lists these CVEs for those component versions, so "
              f"there is nothing to apply the triage to. They are listed under unmatched_findings in {args.report}.")
    if report["unmatched_components"]:
        print(f"{len(report['unmatched_components'])} components could not be matched in the new version.")
    # Only real copy problems fail the run: failed calls, values that did not land,
    # and triaged findings whose component did not come across.
    problems = len(report["failures"]) + len(report["diffs"]) + len(lost_triage)
    if problems:
        print(f"{len(report['failures'])} failed calls, {len(report['diffs'])} values that did not land, "
              f"{len(lost_triage)} triaged findings whose component was not copied -- see {args.report}")
        return 1
    print("Done: all triage that applies to the new version was copied.")
    return 0


def _write_report(path, report):
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"Report written to {path}")


def self_test():
    # purl wins and is case-insensitive; coordinates are the fallback.
    assert component_key({"purl": "pkg:npm/Lodash@4.17.21", "name": "x"}) == ("purl", "pkg:npm/lodash@4.17.21")
    assert component_key({"name": "OpenSSL", "version": "1.1.1", "groupName": None, "type": "library"}) == (
        "coords", "", "openssl", "1.1.1", "library")
    assert component_key({"name": "a", "group": "g"}) == component_key({"name": "A", "groupName": "G"})

    source = [
        {"id": "s1", "purl": "pkg:npm/a@1", "name": "a"},
        {"id": "s2", "name": "busybox", "version": "1.36", "type": "library"},
        {"id": "s3", "name": "busybox", "version": "1.36", "type": "library"},  # duplicate row
        {"id": "s4", "name": "gone", "version": "1"},
    ]
    target = [
        {"id": "t1", "purl": "PKG:NPM/A@1", "name": "a"},
        {"id": "t2", "name": "BusyBox", "version": "1.36", "type": "library"},
        {"id": "t3", "name": "busybox", "version": "1.36", "type": "library"},
    ]
    mapping, unmatched = map_components(source, target)
    assert mapping == {"s1": "t1", "s2": "t2", "s3": "t3"}, mapping
    assert [c["id"] for c in unmatched] == ["s4"]

    # Same CVE on two components maps per component, never across them.
    # Real shape: component.id is the row id; component.vcId is the global id.
    source_findings = [
        {"id": "f1", "findingId": "CVE-2024-1", "component": {"id": "s2", "vcId": "global-busybox"}, "status": "NOT_AFFECTED"},
        {"id": "f2", "findingId": "CVE-2024-1", "component": {"id": "s1", "vcId": "global-a"}, "status": "EXPLOITABLE"},
        {"id": "f3", "findingId": "CVE-2024-9", "component": {"id": "s4", "vcId": "global-gone"}},
    ]
    target_findings = [
        {"id": "g1", "findingId": "cve-2024-1", "component": {"id": "t1", "vcId": "global-a"}},
        {"id": "g2", "findingId": "CVE-2024-1", "component": {"id": "t2", "vcId": "global-busybox"}},
    ]
    pairs, missing = map_findings(source_findings, target_findings, mapping)
    assert [(s["id"], t) for s, t in pairs] == [("f1", "g2"), ("f2", "g1")], pairs
    assert [f["id"] for f in missing] == ["f3"]

    assert list(chunks(list(range(1001)), 500))[-1] == [1000]
    print("self-test passed")


if __name__ == "__main__":
    sys.exit(main())
