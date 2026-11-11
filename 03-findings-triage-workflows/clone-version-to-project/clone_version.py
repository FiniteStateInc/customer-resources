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
  GET  /versions/{id}, GET /projects/{id}, GET /projects/{id}/versions
  GET  /components, GET /findings, GET /sboms/cyclonedx/{id}
  GET  /versions/{id}/scans, GET /project-versions/{id}/dependencies
  POST /projects, POST /projects/{id}/versions, DELETE /versions/{id}
  POST /scans/sbom, POST /scans/{id}/process, GET /scans/{id}/status
  PUT  /components/{versionId}/exclude, PUT /components/{versionId}/{componentId}/status
  PUT  /findings/{versionId}/status/bulk, PUT /findings/{versionId}/{findingId}/status
  POST /findings/{versionId}/{findingId}/comments, POST /project-versions/{id}/dependencies
"""

import argparse
import email.utils
import json
import os
import sys
import time

import requests

PAGE_SIZE = 1000
BULK_SIZE = 500  # API max for exclude and bulk finding status
MAX_EXCLUSION_COMMENT = 1000
MAX_FINDING_COMMENT = 10000
DEFAULT_COMPONENT_STATUS = "NEEDS_REVIEW"
DEFAULT_COMPONENT_TYPE = "library"  # CycloneDX's default component type
SCAN_DONE = {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
SCAN_FAILED = {"ERROR", "FAILED", "CANCELLED", "UPLOAD_FAILED", "NOT_APPLICABLE"}
RETRY_STATUSES = {429, 502, 503, 504}
COPY_PREFIX = "[Copied from "

# Limitation: fixed spacing keeps the script under the public API's ~100
# requests/minute limit; very large clones are slow rather than throttled.
MIN_INTERVAL_SECONDS = 0.65


class Api:
    """Thin requests wrapper: auth header, pacing, and retry on 429/5xx."""

    def __init__(self, token, domain, dry_run=False):
        self.base = f"https://{domain}/api/public/v0"
        self.session = requests.Session()
        self.session.headers.update({"X-Authorization": token, "Accept": "application/json"})
        self.dry_run = dry_run
        self._last = 0.0

    def request(self, method, path, *, params=None, body=None, raw_url=None, data=None, headers=None, ok=(200, 201, 202, 204)):
        if self.dry_run and method != "GET":
            raise RuntimeError(f"dry run attempted a write: {method} {path or 'upload'}")
        url = raw_url or f"{self.base}{path}"
        for attempt in range(6):
            wait = MIN_INTERVAL_SECONDS - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            if raw_url:
                resp = requests.request(method, url, data=data, headers=headers, timeout=600)
            else:
                resp = self.session.request(method, url, params=params, json=body, timeout=300)
            if resp.status_code in RETRY_STATUSES and attempt < 5:
                delay = retry_delay(resp.headers.get("Retry-After"), attempt)
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
        """Page through a list endpoint that returns a bare array or {items: [...]}.

        Stops on an empty page or once the reported total is reached. A short
        page is not treated as the last one, because an endpoint may cap the
        page size below what was asked for.
        """
        rows, offset, previous = [], 0, None
        while True:
            resp = self.get(path, **params, limit=PAGE_SIZE, offset=offset)
            body = resp.json()
            page = body.get("items", []) if isinstance(body, dict) else body
            total = resp.headers.get("X-Total-Count") or (body.get("total") if isinstance(body, dict) else None)
            # An endpoint that ignored `offset` would return the same page forever.
            if page and page == previous:
                return rows
            rows.extend(page)
            if not page or (total is not None and len(rows) >= int(total)):
                return rows
            previous = page
            offset += len(page)


class ApiError(Exception):
    def __init__(self, method, path, resp):
        try:
            detail = resp.json()
        except ValueError:
            detail = resp.text[:500]
        super().__init__(f"{method} {path} -> HTTP {resp.status_code}: {detail}")
        self.status = resp.status_code


def retry_delay(retry_after, attempt):
    """Seconds to wait: the server's Retry-After (seconds or HTTP date), else exponential backoff."""
    if retry_after:
        if retry_after.strip().isdigit():
            return float(retry_after)
        try:
            when = email.utils.parsedate_to_datetime(retry_after)
            return max(0.0, when.timestamp() - time.time())
        except (TypeError, ValueError):
            pass
    return float(2 ** (attempt + 1))


# ---------------------------------------------------------------------------
# Pure logic (covered by --self-test)
# ---------------------------------------------------------------------------


def _norm(value):
    return (value or "").strip().lower()


def component_key(c):
    """Identity used to find the same component after re-import.

    purl when present, otherwise (group, name, version, type) -- the same
    fallback the platform's own version-to-version carry-forward uses. A missing
    type is CycloneDX's default, "library", which is what an import assigns.
    """
    purl = _norm(c.get("purl"))
    if purl:
        return ("purl", purl)
    return (
        "coords",
        _norm(c.get("groupName") or c.get("group")),
        _norm(c.get("name")),
        _norm(c.get("version")),
        _norm(c.get("type")) or DEFAULT_COMPONENT_TYPE,
    )


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


def exclude_in_future(c):
    """The write-side flag for a component's exclusion.

    The read side reports `includeInFutureVersions`, which is the inverse of
    `excludeInFutureVersions`. When it is absent, the exclusion endpoint's own
    default (exclude in future versions) applies.
    """
    if c.get("includeInFutureVersions") is None:
        return True
    return not c["includeInFutureVersions"]


def exclusion_groups(source_components, component_map):
    """{(comment, excludeInFutureVersions): [target component ids]} for excluded components."""
    groups = {}
    for c in source_components:
        if c.get("excluded") and c["id"] in component_map:
            key = ((c.get("exclusionComment") or "")[:MAX_EXCLUSION_COMMENT], exclude_in_future(c))
            groups.setdefault(key, []).append(component_map[c["id"]])
    return groups


def has_component_triage(c):
    status = c.get("status")
    return bool(c.get("excluded") or c.get("statusComment") or (status and status != DEFAULT_COMPONENT_STATUS))


def copied_comment_body(comment, origin):
    """The text posted for one source comment, and whether it had to be cut."""
    prefix = f"{COPY_PREFIX}{origin} - {comment.get('author', 'unknown')}, {comment.get('date', '')}]\n"
    body = prefix + (comment.get("text") or "")
    return body[:MAX_FINDING_COMMENT], len(body) > MAX_FINDING_COMMENT


def _comment_key(text):
    # Compare comments the way a server may store them: line endings and
    # surrounding whitespace are not significant.
    return (text or "").replace("\r\n", "\n").strip()


def comments_to_copy(source_finding, existing_texts, origin):
    """[(body, truncated)] for the source comments not already on the target finding.

    Comparing against the target's existing comments is what makes a resumed
    run safe: comments copied by an earlier run are not posted again.
    """
    existing = {_comment_key(t) for t in existing_texts}
    out = []
    # ISO-8601 timestamps sort chronologically as strings; oldest first keeps the thread order.
    for comment in sorted(source_finding.get("comments") or [], key=lambda c: c.get("date") or ""):
        if not comment.get("text"):
            continue
        body, truncated = copied_comment_body(comment, origin)
        if _comment_key(body) not in existing:
            out.append((body, truncated))
    return out


def split_not_carried(components, findings, report):
    """Set aside what an SBOM import cannot recreate, and record it in the report.

    Limitation: file components (configuration files, certificates, carved
    binaries) and the binary-analysis findings on them come from scanning the
    original binary, so an import cannot recreate them. The version's own root
    component (projectModule) is the project itself; the new project gets its
    own. Neither is copied, and findings on them are reported here rather than
    as unmatched.
    """
    file_ids = {c["id"] for c in components if c.get("type") == "file"}
    module_ids = {c["id"] for c in components if c.get("projectModule")} - file_ids
    skipped = file_ids | module_ids
    skipped_findings = [f for f in findings if finding_component_id(f) in skipped]
    report["not_carried"] = {
        "file_components": len(file_ids),
        "binary_analysis_findings": sum(1 for f in skipped_findings if finding_component_id(f) in file_ids),
        "project_module_components": len(module_ids),
        "triaged_findings": [
            {"findingId": f.get("findingId"), "component": (f.get("component") or {}).get("name"), "status": f.get("status")}
            for f in skipped_findings if f.get("status") or f.get("comments")
        ],
        "triaged_components": [
            {"name": c["name"], "version": c.get("version")} for c in components if c["id"] in skipped and has_component_triage(c)
        ],
    }
    return [c for c in components if c["id"] not in skipped], [f for f in findings if finding_component_id(f) not in skipped]


def status_to_copy(c):
    """Whether a component's status is replayed: a non-default status, or the default with a comment."""
    status = c.get("status")
    return bool(status) and (status != DEFAULT_COMPONENT_STATUS or bool(c.get("statusComment")))


def vex_item(s, target_id):
    item = {"findingId": target_id, "status": s["status"]}
    for field in ("justification", "response", "reason"):
        if s.get(field):
            item[field] = s[field]
    return item


def triage_diffs(source_components, target_components, component_map, finding_pairs, target_findings, origin):
    """Every copied triage value that is not on the target."""
    diffs = []
    for s in source_components:
        t = target_components.get(component_map.get(s["id"]))
        if not t:
            continue
        checks = [("excluded", bool(s.get("excluded")), bool(t.get("excluded")))]
        if s.get("excluded"):
            checks.append(("exclusionComment", (s.get("exclusionComment") or "")[:MAX_EXCLUSION_COMMENT], t.get("exclusionComment") or ""))
            checks.append(("excludeInFutureVersions", exclude_in_future(s), exclude_in_future(t)))
        if s.get("status") and s["status"] != DEFAULT_COMPONENT_STATUS:
            checks.append(("status", s["status"], t.get("status")))
        if s.get("statusComment"):
            checks.append(("statusComment", s["statusComment"], t.get("statusComment")))
        for field, want, got in checks:
            if want != got:
                diffs.append({"component": s["name"], "field": field, "source": want, "target": got})
    for s, target_id in finding_pairs:
        t = target_findings.get(target_id, {})
        for field in ("status", "justification", "response", "reason"):
            if s.get(field) and s.get(field) != t.get(field):
                diffs.append({"finding": s.get("findingId"), "field": field, "source": s.get(field), "target": t.get(field)})
        existing = {c.get("text") for c in t.get("comments") or []}
        missing = comments_to_copy(s, existing, origin)
        if missing:
            diffs.append({"finding": s.get("findingId"), "field": "comments", "source": len(missing), "target": "missing"})
    return diffs


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


# ---------------------------------------------------------------------------
# API steps
# ---------------------------------------------------------------------------


def list_components(api, version_id):
    # The list returns one side of the exclusion flag at a time, so read both.
    comps = {}
    for excluded in ("false", "true"):
        for c in api.get_all("/components", filter=f"projectVersion=={version_id}", excluded=excluded):
            comps[c["id"]] = c
    return comps


def list_findings(api, version_id):
    # /findings returns findings on non-excluded components unless asked, so read both.
    found = {}
    for excluded in ("false", "true"):
        for f in api.get_all("/findings", versionId=version_id, excluded=excluded, includeComments="true"):
            found[f["id"]] = f
    return found


def read_version(api, version_id):
    version = api.get_json(f"/versions/{version_id}")
    project_id = (version.get("project") or {}).get("id")
    project = api.get_json(f"/projects/{project_id}") if project_id else {}
    return version, project, list(list_components(api, version_id).values()), list(list_findings(api, version_id).values())


def repoint_dependencies(bom, dropped_refs):
    """Move dependency edges of removed components onto the BOM's root.

    The source project's root component heads the dependency graph. Its edges
    are re-pointed at metadata.component, which becomes the new project's root
    on import, so the graph is kept; with no metadata root they are removed so
    no edge points at a component that is no longer in the BOM.
    """
    if not dropped_refs or not bom.get("dependencies"):
        return
    root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    out, by_ref = [], {}
    for dep in bom["dependencies"]:
        targets = dep.get("dependsOn") or []
        touched = dep.get("ref") in dropped_refs or any(t in dropped_refs for t in targets)
        if not touched and dep.get("ref") != root:
            out.append(dep)  # unrelated entries pass through unchanged, every key kept
            continue
        ref = root if dep.get("ref") in dropped_refs else dep.get("ref")
        if ref is None:
            continue
        new_targets = [root if t in dropped_refs else t for t in targets]
        if ref not in by_ref:
            by_ref[ref] = dict(dep, ref=ref, dependsOn=[])
            out.append(by_ref[ref])
        entry = by_ref[ref]["dependsOn"]
        entry.extend(t for t in new_targets if t and t != ref and t not in entry)
    bom["dependencies"] = out


def export_sbom(api, version_id, components, drop=()):
    """CycloneDX export without VEX, plus the excluded components the export omits.

    `drop` is the components set aside as not carried (the source project's own
    root component); entries for them are removed, so the new version does not
    get an untriaged copy of the old project's root next to its own.
    """
    bom = api.get_json(f"/sboms/cyclonedx/{version_id}", includeVex="false", includeDependencies="true")
    drop_keys = {component_key(c) for c in drop}
    kept, dropped_refs = [], set()
    for c in bom.get("components") or []:
        if component_key(c) in drop_keys:
            dropped_refs.add(c.get("bom-ref"))
        else:
            kept.append(c)
    bom["components"] = kept
    repoint_dependencies(bom, dropped_refs - {None})
    bom_components = bom["components"]
    present = {component_key(c) for c in bom_components}
    added = 0
    for c in components:
        if not c.get("excluded") or component_key(c) in present:
            continue
        entry = {"type": c.get("type") or DEFAULT_COMPONENT_TYPE, "name": c["name"], "bom-ref": f"excluded-{c['id']}"}
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


def source_marker(source_version_id):
    return f"(source version {source_version_id})"


def create_target(api, project, version, source_version_id, new_project_name, folder_id, version_name, release_type):
    body = {
        "name": new_project_name,
        "description": (
            f"Branched from {project.get('name', '?')} / {version.get('name', '?')} {source_marker(source_version_id)}. "
            f"{project.get('description') or ''}"
        ).strip(),
        "type": project.get("type") or "application",
    }
    if folder_id:
        body["folderId"] = folder_id
    new_project = api.request("POST", "/projects", body=body).json()
    placeholders = api.get_all(f"/projects/{new_project['id']}/versions")
    new_version = api.request(
        "POST", f"/projects/{new_project['id']}/versions", body={"version": version_name, "releaseType": release_type}
    ).json()
    return new_project, new_version, remove_placeholders(api, placeholders, new_version["id"])


def remove_placeholders(api, placeholders, new_version_id):
    """Delete the dated, empty placeholder version that project creation adds.

    The version list carries no counts, so each candidate's details are read
    first; only a version confirmed to have no components and no findings is
    deleted. Anything else is left in place and listed in the report.
    """
    leftover = []
    for p in placeholders:
        if p["id"] == new_version_id:
            continue
        name = p.get("name") or p.get("version")
        try:
            details = api.get_json(f"/versions/{p['id']}")
            if details.get("components") != 0 or details.get("findings") != 0:
                leftover.append({"id": p["id"], "name": name, "error": "not confirmed empty; left in place"})
                continue
            api.request("DELETE", f"/versions/{p['id']}")
        except ApiError as e:
            leftover.append({"id": p["id"], "name": name, "error": str(e)})
    return leftover


def import_sbom(api, version_id, bom, file_name, timeout_s):
    scan = api.request(
        "POST", "/scans/sbom", body={"projectVersionId": version_id, "sbomFormat": "cyclonedx", "fileName": file_name}
    ).json()
    api.request(
        "PUT", "", raw_url=scan["uploadUrl"], data=json.dumps(bom).encode(), headers={"Content-Type": "application/json"}
    )
    api.request("POST", f"/scans/{scan['scanId']}/process")
    return wait_for_scan(api, scan["scanId"], timeout_s)


def wait_for_scan(api, scan_id, timeout_s):
    print(f"  scan {scan_id} processing", end="", flush=True)
    deadline = time.monotonic() + timeout_s
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
        if time.monotonic() > deadline:
            print()
            raise RuntimeError(
                f"SBOM import still {state or 'pending'} after {timeout_s // 60} minutes. Re-run later with "
                f"--target-version to continue once it finishes, or raise --scan-timeout."
            )
        time.sleep(10)


def apply_exclusions(api, target_version_id, source_components, component_map, report):
    for (comment, future), ids in exclusion_groups(source_components, component_map).items():
        for batch in chunks(ids, BULK_SIZE):
            body = {"componentIds": batch, "excludeInFutureVersions": future}
            if comment:
                body["comment"] = comment
            if _try(api, report, "PUT", f"/components/{target_version_id}/exclude", body, f"exclude {len(batch)} components"):
                report["applied"]["exclusions"] += len(batch)
    for c in source_components:
        if c.get("excluded") and c["id"] in component_map and len(c.get("exclusionComment") or "") > MAX_EXCLUSION_COMMENT:
            report["truncated"].append({"component": c["name"], "field": "exclusionComment", "limit": MAX_EXCLUSION_COMMENT})


def apply_component_statuses(api, target_version_id, source_components, component_map, report):
    for c in source_components:
        if c["id"] not in component_map or not status_to_copy(c):
            continue
        body = {"status": c["status"]}
        if c.get("statusComment"):
            body["statusComment"] = c["statusComment"]
        target_id = component_map[c["id"]]
        if _try(api, report, "PUT", f"/components/{target_version_id}/{target_id}/status", body, f"status {c['name']}"):
            report["applied"]["component_statuses"] += 1


def apply_finding_vex(api, target_version_id, pairs, report):
    items = [vex_item(s, target_id) for s, target_id in pairs if s.get("status")]
    for batch in chunks(items, BULK_SIZE):
        try:
            api.request("PUT", f"/findings/{target_version_id}/status/bulk", body={"findings": batch})
            report["applied"]["finding_vex"] += len(batch)
            continue
        except ApiError as e:
            # One bad item rejects the whole batch; apply the batch one finding at
            # a time so only the item that is actually rejected is lost.
            print(f"  bulk VEX x{len(batch)} rejected ({e.status}); applying one at a time")
        for item in batch:
            body = {k: v for k, v in item.items() if k != "findingId"}
            if _try(api, report, "PUT", f"/findings/{target_version_id}/{item['findingId']}/status", body, f"VEX {item['findingId']}"):
                report["applied"]["finding_vex"] += 1


def apply_finding_comments(api, target_version_id, pairs, target_findings, origin, report):
    for s, target_id in pairs:
        existing = {c.get("text") for c in (target_findings.get(target_id) or {}).get("comments") or []}
        for body, truncated in comments_to_copy(s, existing, origin):
            if truncated:
                report["truncated"].append({"finding": s.get("findingId"), "field": "comment", "limit": MAX_FINDING_COMMENT})
            if _try(api, report, "POST", f"/findings/{target_version_id}/{target_id}/comments", {"comment": body}, f"comment on {s.get('findingId')}"):
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


def resume_target(api, args):
    """Check that --target-version is a clone of this source made by this script."""
    if args.target_version == args.source_version:
        raise SystemExit("--target-version is the source version itself.")
    target = api.get_json(f"/versions/{args.target_version}")
    project_id = (target.get("project") or {}).get("id")
    project = api.get_json(f"/projects/{project_id}") if project_id else {}
    if source_marker(args.source_version) not in (project.get("description") or "") and not args.force_target:
        raise SystemExit(
            f"Project '{project.get('name', '?')}' was not created by this script from source version "
            f"{args.source_version}. Refusing to write triage into it; pass --force-target to override."
        )
    return {"id": project_id}, {"id": args.target_version}


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
    parser.add_argument("--force-target", action="store_true", help="With --target-version: skip the check that this script created it")
    parser.add_argument("--scan-timeout", type=int, default=180, help="Minutes to wait for the SBOM import (default 180)")
    parser.add_argument("--dry-run", action="store_true", help="Read the source and show what would be copied; no writes")
    parser.add_argument("--report", default="clone_report.json", help="Where to write the JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run the built-in checks and exit")
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

    report = {
        "source": {"versionId": args.source_version},
        "applied": {"exclusions": 0, "component_statuses": 0, "finding_vex": 0, "finding_comments": 0, "dependencies": 0},
        "failures": [], "skipped_dependencies": [], "unmatched_components": [], "unmatched_findings": [],
        "diffs": [], "truncated": [],
    }
    try:
        return run(api, args, domain, report)
    finally:
        # Written on every exit, including a failure part-way, so a partial run is never a mystery.
        _write_report(args.report, report)


def run(api, args, domain, report):
    print(f"Reading source version {args.source_version} ...")
    version, project, components, findings = read_version(api, args.source_version)
    origin = f"{project.get('name', '?')} / {version.get('name', '?')}"
    report["source"].update({"project": project.get("name"), "version": version.get("name")})
    with_vex = [f for f in findings if f.get("status")]
    commented = sum(len(f.get("comments") or []) for f in findings)
    print(f"  {origin}: {len(components)} components ({sum(1 for c in components if c.get('excluded'))} excluded), "
          f"{len(findings)} findings ({len(with_vex)} with VEX, {commented} comments)")

    roots = [c for c in components if c.get("projectModule") and c.get("type") != "file"]
    components, findings = split_not_carried(components, findings, report)
    nc = report["not_carried"]
    if nc["file_components"] or nc["project_module_components"]:
        print(f"  not carried: {nc['file_components']} file components ({nc['binary_analysis_findings']} binary-analysis "
              f"findings) and {nc['project_module_components']} project root component(s); "
              f"{len(nc['triaged_findings'])} triaged or commented findings on them")

    # A resume already has its SBOM imported, so it skips the export.
    if args.dry_run or not args.target_version:
        bom, added = export_sbom(api, args.source_version, components, drop=roots)
        print(f"  exported CycloneDX: {len(bom.get('components', []))} components ({added} excluded components added back)")

    if args.dry_run:
        bom_as_components = [dict(c, id=str(i)) for i, c in enumerate(bom.get("components", []))]
        _, unmatched = map_components(components, bom_as_components)
        carried_vex = sum(1 for f in findings if f.get("status"))
        carried_comments = sum(len(f.get("comments") or []) for f in findings)
        print("\nDry run - would create:")
        print(f"  project '{args.new_project_name or '<name>'}' with version '{args.version_name or version.get('name')}'")
        print(f"  exclusions: {sum(1 for c in components if c.get('excluded'))}, "
              f"component statuses: {sum(1 for c in components if status_to_copy(c))}, "
              f"finding VEX: {carried_vex}, comments: {0 if args.skip_comments else carried_comments}")
        print(f"  components the export would not carry (unmatched): {len(unmatched)}")
        for c in unmatched[:20]:
            print(f"    - {c.get('groupName') or ''}{'/' if c.get('groupName') else ''}{c['name']} {c.get('version') or ''}")
        report["unmatched_components"] = [{"name": c["name"], "version": c.get("version"), "purl": c.get("purl")} for c in unmatched]
        return 0

    timeout_s = args.scan_timeout * 60
    if args.target_version:
        # Resume: the project and the SBOM import already exist from an earlier run.
        new_project, new_version = resume_target(api, args)
        report["target"] = {"projectId": new_project["id"], "versionId": new_version["id"], "resumed": True}
        print(f"Resuming into existing version {new_version['id']} ...")
        scans = api.get_json(f"/versions/{new_version['id']}/scans", sort="created:desc", limit=1)
        scans = scans.get("items", []) if isinstance(scans, dict) else scans
        if not scans:
            raise SystemExit("The target version has no scan; run without --target-version to create one.")
        wait_for_scan(api, scans[0]["id"], timeout_s)
    else:
        print(f"Creating project '{args.new_project_name}' ...")
        new_project, new_version, leftover = create_target(
            api, project, version, args.source_version, args.new_project_name, args.folder_id,
            args.version_name or version["name"], args.release_type,
        )
        report["target"] = {"projectId": new_project["id"], "versionId": new_version["id"], "leftover_placeholder_versions": leftover}
        print(f"  new version: {new_version['id']} (pass as --target-version to resume if this run stops)")

        print("Importing SBOM ...")
        import_sbom(api, new_version["id"], bom, f"{version.get('name', 'version')}-branch.cdx.json", timeout_s)

    print("Matching components and findings ...")
    component_map, unmatched_components = map_components(components, list(list_components(api, new_version["id"]).values()))
    target_findings = list_findings(api, new_version["id"])
    pairs, unmatched_findings = map_findings(findings, list(target_findings.values()), component_map)
    report["unmatched_components"] = [
        {"name": c["name"], "version": c.get("version"), "purl": c.get("purl"), "triaged": has_component_triage(c)}
        for c in unmatched_components
    ]
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
        apply_finding_comments(api, new_version["id"], pairs, target_findings, origin, report)
    if args.include_dependencies:
        apply_dependencies(api, args.source_version, new_version["id"], report)

    print("Verifying ...")
    verify_pairs = pairs if not args.skip_comments else [(dict(s, comments=[]), t) for s, t in pairs]
    report["diffs"] = triage_diffs(
        components, list_components(api, new_version["id"]), component_map, verify_pairs,
        list_findings(api, new_version["id"]), origin,
    )

    print(f"\nNew project: https://{domain}/projects/{new_project['id']}/versions/{new_version['id']}")
    print(f"Applied: {report['applied']}")
    triaged_unmatched = [f for f in report["unmatched_findings"] if f.get("status") or f.get("comments")]
    no_longer = [f for f in triaged_unmatched if f["reason"] == "no_longer_reported"]
    lost_findings = [f for f in triaged_unmatched if f["reason"] == "component_missing"]
    lost_components = [c for c in report["unmatched_components"] if c["triaged"]]
    if no_longer:
        print(f"Note: {len(no_longer)} triaged findings are no longer reported in the new version. Their components were "
              f"copied, but current vulnerability data no longer lists these CVEs for those component versions, so "
              f"there is nothing to apply the triage to. They are listed under unmatched_findings in {args.report}.")
    if report["truncated"]:
        print(f"Note: {len(report['truncated'])} comments were longer than the API allows (exclusion comments 1,000 "
              f"characters, finding comments 10,000) and were shortened; they are listed under truncated in {args.report}.")
    if report["unmatched_components"]:
        print(f"{len(report['unmatched_components'])} components could not be matched in the new version "
              f"({len(lost_components)} of them had triage).")
    # Only real copy problems fail the run: failed calls, values that did not land,
    # and triage on components or findings that did not come across.
    problems = len(report["failures"]) + len(report["diffs"]) + len(lost_findings) + len(lost_components)
    if problems:
        print(f"{len(report['failures'])} failed calls, {len(report['diffs'])} values that did not land, "
              f"{len(lost_components)} triaged components and {len(lost_findings)} triaged findings not copied -- see {args.report}")
        return 1
    print("Done: all triage that applies to the new version was copied.")
    return 0


def _write_report(path, report):
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"Report written to {path}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code, self._payload, self.headers, self.text = status_code, payload, headers or {}, ""

    def json(self):
        return self._payload


class _FakeApi(Api):
    """Api with the network replaced by a handler, for exercising the request logic offline."""

    def __init__(self, handler, dry_run=False):
        super().__init__("token", "example.test", dry_run=dry_run)
        self.handler, self.calls = handler, []

    def request(self, method, path, **kw):
        if self.dry_run and method != "GET":
            raise RuntimeError("dry run attempted a write")
        self.calls.append((method, path, kw.get("params"), kw.get("body")))
        resp = self.handler(method, path, kw.get("params"), kw.get("body"))
        if resp.status_code >= 400:
            raise ApiError(method, path, resp)
        return resp


def self_test():
    # Matching: purl wins and is case-insensitive; coordinates are the fallback,
    # and a missing type means CycloneDX's default "library".
    assert component_key({"purl": "pkg:npm/Lodash@4.17.21", "name": "x"}) == ("purl", "pkg:npm/lodash@4.17.21")
    assert component_key({"name": "OpenSSL", "version": "1.1.1", "type": None}) == ("coords", "", "openssl", "1.1.1", "library")
    assert component_key({"name": "a", "group": "g"}) == component_key({"name": "A", "groupName": "G", "type": "library"})

    source = [
        {"id": "s1", "purl": "pkg:npm/a@1", "name": "a"},
        {"id": "s2", "name": "busybox", "version": "1.36", "type": "library"},
        {"id": "s3", "name": "busybox", "version": "1.36", "type": "library"},  # duplicate row
        {"id": "s4", "name": "gone", "version": "1", "status": "FALSE_POSITIVE"},
    ]
    target = [
        {"id": "t1", "purl": "PKG:NPM/A@1", "name": "a"},
        {"id": "t2", "name": "BusyBox", "version": "1.36", "type": "library"},
        {"id": "t3", "name": "busybox", "version": "1.36", "type": "library"},
    ]
    mapping, unmatched = map_components(source, target)
    assert mapping == {"s1": "t1", "s2": "t2", "s3": "t3"}, mapping
    assert [c["id"] for c in unmatched] == ["s4"]
    # An unmatched component with triage is a real loss; an untriaged one is not.
    assert has_component_triage(unmatched[0]) and not has_component_triage({"status": "NEEDS_REVIEW"})
    assert has_component_triage({"excluded": True}) and has_component_triage({"statusComment": "x"})

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

    # Exclusions: includeInFutureVersions is the inverse of excludeInFutureVersions.
    assert exclude_in_future({"includeInFutureVersions": False}) is True
    assert exclude_in_future({"includeInFutureVersions": True}) is False
    assert exclude_in_future({}) is True
    groups = exclusion_groups(
        [{"id": "s1", "excluded": True, "includeInFutureVersions": True, "exclusionComment": "x" * 1200},
         {"id": "s2", "excluded": True, "includeInFutureVersions": False},
         {"id": "s3", "excluded": False}],
        mapping,
    )
    assert groups == {("x" * 1000, False): ["t1"], ("", True): ["t2"]}, groups

    # Comments: copied with provenance, never posted twice on a resumed run.
    finding = {"comments": [{"text": "second", "author": "b", "date": "2026-02-01T00:00:00Z"},
                            {"text": "first", "author": "a", "date": "2026-01-01T00:00:00Z"}]}
    todo = comments_to_copy(finding, set(), "P / 1")
    assert [b.split("\n", 1)[1] for b, _ in todo] == ["first", "second"]
    assert comments_to_copy(finding, {todo[0][0]}, "P / 1") == [todo[1]]
    body, cut = copied_comment_body({"text": "y" * 10000, "author": "a", "date": "d"}, "P / 1")
    assert cut and len(body) == MAX_FINDING_COMMENT

    # Verification catches every copied field, and ignores the default status.
    src_c = [{"id": "s1", "name": "a", "excluded": True, "includeInFutureVersions": False, "exclusionComment": "c",
              "status": "FALSE_POSITIVE", "statusComment": "why"},
             {"id": "s2", "name": "b", "status": "NEEDS_REVIEW"}]
    tgt_c = {"t1": {"excluded": True, "includeInFutureVersions": True, "exclusionComment": "c", "status": "FALSE_POSITIVE"},
             "t2": {"status": "UNKNOWN"}}
    src_f = {"findingId": "CVE-1", "status": "NOT_AFFECTED", "reason": "r", "comments": [{"text": "t", "author": "a", "date": "d"}]}
    diffs = triage_diffs(src_c, tgt_c, {"s1": "t1", "s2": "t2"}, [(src_f, "g1")], {"g1": {"status": "NOT_AFFECTED"}}, "P / 1")
    assert sorted(d["field"] for d in diffs) == ["comments", "excludeInFutureVersions", "reason", "statusComment"], diffs

    # Pagination: a server that caps pages at 2 rows is still read to the end.
    rows = [{"id": str(i)} for i in range(5)]
    paged = _FakeApi(lambda m, p, params, b: _FakeResponse(
        200, rows[params["offset"]:params["offset"] + 2], {"X-Total-Count": "5"}))
    assert [r["id"] for r in paged.get_all("/x")] == ["0", "1", "2", "3", "4"]
    unpaged = _FakeApi(lambda m, p, params, b: _FakeResponse(200, rows[params["offset"]:params["offset"] + 2]))
    assert len(unpaged.get_all("/x")) == 5  # no total header: read until an empty page
    ignores_offset = _FakeApi(lambda m, p, params, b: _FakeResponse(200, rows[:2]))
    assert len(ignores_offset.get_all("/x")) == 2  # same page twice: stop instead of looping forever

    # A rejected bulk VEX batch falls back to one finding at a time.
    def bulk_rejects(method, path, params, body):
        if path.endswith("/status/bulk"):
            return _FakeResponse(400, {"error": "bad item"})
        return _FakeResponse(400 if "bad" in path else 200, {})
    vex_api = _FakeApi(bulk_rejects)
    rep = {"applied": {"finding_vex": 0}, "failures": []}
    apply_finding_vex(vex_api, "v", [({"status": "NOT_AFFECTED"}, "good"), ({"status": "RESOLVED"}, "bad")], rep)
    assert rep["applied"]["finding_vex"] == 1 and len(rep["failures"]) == 1, rep

    # A failed exclusion call is not counted as applied.
    excl_api = _FakeApi(lambda m, p, params, b: _FakeResponse(500, {}))
    rep = {"applied": {"exclusions": 0}, "failures": [], "truncated": []}
    apply_exclusions(excl_api, "v", [{"id": "s1", "name": "a", "excluded": True}], {"s1": "t1"}, rep)
    assert rep["applied"]["exclusions"] == 0 and len(rep["failures"]) == 1

    # Dry run blocks every write, including the presigned upload.
    try:
        Api("t", "example.test", dry_run=True).request("PUT", "", raw_url="https://upload.example.test/x")
        raise AssertionError("dry run allowed a write")
    except RuntimeError:
        pass

    # Retry-After: seconds or an HTTP date; otherwise exponential backoff.
    assert retry_delay("7", 0) == 7.0 and retry_delay(None, 2) == 8.0 and retry_delay("garbage", 0) == 2.0
    assert retry_delay(email.utils.formatdate(time.time() - 60, usegmt=True), 0) == 0.0

    # A copied comment the server stored with different line endings or trailing
    # whitespace is still recognised, so a resume does not post it again.
    first_body = todo[0][0]
    assert comments_to_copy(finding, {first_body.replace("\n", "\r\n") + "  "}, "P / 1") == [todo[1]]

    # Component status is replayed for a non-default status, or the default with a comment.
    assert status_to_copy({"status": "CONFIRMED"}) and status_to_copy({"status": "NEEDS_REVIEW", "statusComment": "c"})
    assert not status_to_copy({"status": "NEEDS_REVIEW"}) and not status_to_copy({})

    # File components and the project's own root component are set aside with
    # their findings, so those findings never count as copy failures.
    rep = {}
    comps, finds = split_not_carried(
        [{"id": "lib", "name": "lib"}, {"id": "cfg", "name": "cfg", "type": "file", "excluded": True},
         {"id": "root", "name": "Product", "projectModule": True}],
        [{"findingId": "CVE-1", "component": {"id": "lib"}}, {"findingId": "SAST-1", "component": {"id": "cfg"}, "status": "RESOLVED"},
         {"findingId": "CVE-2", "component": {"id": "root"}, "status": "NOT_AFFECTED"}],
        rep,
    )
    assert [c["id"] for c in comps] == ["lib"] and [f["findingId"] for f in finds] == ["CVE-1"]
    nc = rep["not_carried"]
    assert (nc["file_components"], nc["binary_analysis_findings"], nc["project_module_components"]) == (1, 1, 1), nc
    assert len(nc["triaged_findings"]) == 2 and nc["triaged_components"] == [{"name": "cfg", "version": None}]

    # Placeholder removal reads each version's details and deletes only a confirmed-empty one.
    details = {"empty": {"components": 0, "findings": 0}, "full": {"components": 3, "findings": 0}, "unknown": {}}
    def versions(method, path, params, body):
        return _FakeResponse(200, details.get(path.rsplit("/", 1)[-1], {}))
    ph_api = _FakeApi(versions)
    left = remove_placeholders(ph_api, [{"id": "empty", "name": "2026-01-01"}, {"id": "full", "version": "x"},
                                        {"id": "unknown"}, {"id": "ours"}], "ours")
    deleted = [p for m, p, _, _ in ph_api.calls if m == "DELETE"]
    assert deleted == ["/versions/empty"], deleted
    assert [(x["id"], x["name"]) for x in left] == [("full", "x"), ("unknown", None)], left

    # The export drops the source project's root component and adds back excluded ones.
    bom_in = {"components": [{"name": "Product", "version": "New", "type": "application"},
                             {"name": "Product", "version": "v1.0", "type": "operating-system", "purl": "pkg:generic/Product@v1.0"},
                             {"name": "lib", "version": "1", "type": "library"}]}
    ex_api = _FakeApi(lambda m, p, params, b: _FakeResponse(200, json.loads(json.dumps(bom_in))))
    bom_out, added_back = export_sbom(
        ex_api, "v", [{"id": "x", "name": "gone", "version": "2", "excluded": True}],
        drop=[{"id": "r", "name": "Product", "version": "New", "type": "application", "projectModule": True}],
    )
    assert [(c["name"], c.get("version")) for c in bom_out["components"]] == [
        ("Product", "v1.0"), ("lib", "1"), ("gone", "2")], bom_out["components"]
    assert added_back == 1

    # The removed root's dependency edges move onto the metadata root, and none dangle.
    # Unrelated entries keep every key (e.g. CycloneDX 1.6 `provides`).
    graph = {"metadata": {"component": {"bom-ref": "meta"}},
             "dependencies": [{"ref": "old-root", "dependsOn": ["a", "b"]}, {"ref": "a", "dependsOn": ["old-root", "c"]},
                              {"ref": "meta", "dependsOn": ["b"]}, {"ref": "c", "dependsOn": [], "provides": ["x"]}]}
    repoint_dependencies(graph, {"old-root"})
    assert graph["dependencies"] == [
        {"ref": "meta", "dependsOn": ["a", "b"]}, {"ref": "a", "dependsOn": ["meta", "c"]},
        {"ref": "c", "dependsOn": [], "provides": ["x"]}], graph
    orphan = {"dependencies": [{"ref": "old-root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["old-root"]}]}
    repoint_dependencies(orphan, {"old-root"})
    assert orphan["dependencies"] == [{"ref": "a", "dependsOn": []}], orphan

    assert list(chunks(list(range(1001)), 500))[-1] == [1000]
    print("self-test passed")


if __name__ == "__main__":
    sys.exit(main())
