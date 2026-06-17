#!/usr/bin/env python3
"""
Mark Finite State CVE findings as NOT_AFFECTED when Ubuntu has already fixed
(backported) the vulnerability in the installed package version.

Ubuntu backports security fixes without bumping the upstream version, so our
matching engine flags CVEs against the upstream version (e.g. openssl 3.0.2)
that are actually already patched in the distro revision (e.g.
3.0.2-0ubuntu1.23). This tool walks every CVE finding on an Ubuntu component,
consults Canonical's Security API to see whether the CVE is "released" (fixed)
for the matching release at or below the installed version, and -- when it is --
sets the finding's VEX status to NOT_AFFECTED with the Ubuntu CVE page recorded
as the reason.

Usage:
    mark_ubuntu_fixed.py --project-version-id <id>
    mark_ubuntu_fixed.py --project "<name>" --version "<name>"

Auth/host come from --domain/--token or the FINITE_STATE_DOMAIN /
FINITE_STATE_AUTH_TOKEN environment variables.

Dry-run by default: pass --apply to actually send the status updates.
"""

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Configuration / constants
# ---------------------------------------------------------------------------

UBUNTU_CVE_URL = "https://ubuntu.com/security/cves/{cve}.json"
UBUNTU_CVE_PAGE = "https://ubuntu.com/security/{cve}"
REQUEST_TIMEOUT = 60
FINDINGS_PAGE_SIZE = 200

# VEX values for the status update (see UpdateFindingStatusV0Request in the schema).
VEX_STATUS = "NOT_AFFECTED"
VEX_JUSTIFICATION = "CODE_NOT_PRESENT"  # backported patch removed the vulnerable code

# A finding is considered "already triaged" (and skipped unless --overwrite)
# when its status is anything other than these.
UNTRIAGED_STATUSES = {"", "NO_STATUS", "NONE", None}


# ---------------------------------------------------------------------------
# dpkg version comparison (pure Python, no dpkg binary required)
# Implements the algorithm from deb-version(7): epoch:upstream-revision, with
# '~' sorting before everything (even end-of-string), and alternating
# non-digit / digit segments compared lexically / numerically.
# ---------------------------------------------------------------------------

def _order(ch):
    """Sort weight for a single character in the dpkg lexical ordering."""
    if ch == "~":
        return -1
    if ch.isdigit():
        # digits are handled in the numeric phase, never passed here
        return 0
    if ch.isalpha():
        return ord(ch)
    # all other (punctuation) chars sort after letters
    return ord(ch) + 256


def _compare_fragment(a, b):
    """Compare the non-digit/digit alternating parts of one version section."""
    ia = ib = 0
    la, lb = len(a), len(b)
    while ia < la or ib < lb:
        # --- non-digit run ---
        while (ia < la and not a[ia].isdigit()) or (ib < lb and not b[ib].isdigit()):
            ca = _order(a[ia]) if ia < la and not a[ia].isdigit() else 0
            cb = _order(b[ib]) if ib < lb and not b[ib].isdigit() else 0
            if ca != cb:
                return -1 if ca < cb else 1
            if ia < la and not a[ia].isdigit():
                ia += 1
            if ib < lb and not b[ib].isdigit():
                ib += 1
        # --- digit run ---
        da_start = ia
        while ia < la and a[ia].isdigit():
            ia += 1
        db_start = ib
        while ib < lb and b[ib].isdigit():
            ib += 1
        na = int(a[da_start:ia] or "0")
        nb = int(b[db_start:ib] or "0")
        if na != nb:
            return -1 if na < nb else 1
    return 0


def _split_version(v):
    """Return (epoch:int, upstream:str, revision:str)."""
    v = v.strip()
    epoch = 0
    if ":" in v:
        head, v = v.split(":", 1)
        if head.isdigit():
            epoch = int(head)
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, "0"
    return epoch, upstream, revision


def dpkg_compare(a, b):
    """Return -1, 0, or 1 for a < b, a == b, a > b under Debian version rules."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _compare_fragment(ua, ub)
    if c != 0:
        return c
    return _compare_fragment(ra, rb)


def upstream_of(version):
    """Upstream portion of a Debian version (epoch + revision stripped)."""
    _, upstream, _ = _split_version(version)
    return upstream


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

class ApiError(Exception):
    pass


def _fs_request(method, base_url, token, path, query=None, body=None):
    url = base_url.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "X-Authorization": token,
        "Accept": "application/json",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            raw = resp.read()
            payload = json.loads(raw.decode("utf-8")) if raw else None
            return resp.status, dict(resp.headers), payload
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise ApiError(f"{method} {path} -> HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise ApiError(f"{method} {path} -> {e.reason}") from e


_UBUNTU_CACHE = {}


def fetch_ubuntu_cve(cve, retries=4):
    """Fetch Canonical's security record for a CVE, cached. Returns dict or None.

    ubuntu.com rate-limits bursts (RST / 429 / 5xx), so transient failures are
    retried with exponential backoff + jitter. A 404 is a definitive 'no record'
    and is cached as None."""
    if cve in _UBUNTU_CACHE:
        return _UBUNTU_CACHE[cve]
    url = UBUNTU_CVE_URL.format(cve=urllib.parse.quote(cve))
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    last_err = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            _UBUNTU_CACHE[cve] = result
            return result
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _UBUNTU_CACHE[cve] = None
                return None
            if e.code not in (429, 500, 502, 503, 504):
                raise ApiError(f"ubuntu {cve} -> HTTP {e.code}") from e
            last_err = f"HTTP {e.code}"
        except urllib.error.URLError as e:
            last_err = str(e.reason)
        except (TimeoutError, ConnectionError, OSError) as e:
            last_err = str(e)
        if attempt < retries:
            time.sleep(min(8.0, 0.5 * (2 ** attempt)) + random.uniform(0, 0.4))
    raise ApiError(f"ubuntu {cve} -> {last_err} (after {retries} retries)")


def prefetch_ubuntu(cves, workers=5, progress_every=25):
    """Populate the Ubuntu cache for many CVEs concurrently. Returns errors."""
    todo = [c for c in cves if c not in _UBUNTU_CACHE]
    errors = {}
    if not todo:
        return errors
    done = 0
    t0 = time.time()

    def _one(cve):
        try:
            fetch_ubuntu_cve(cve)
            return cve, None
        except ApiError as e:
            return cve, str(e)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for cve, err in ex.map(_one, todo):
            done += 1
            if err:
                errors[cve] = err
            if done % progress_every == 0 or done == len(todo):
                print(f"    ...fetched {done}/{len(todo)} Ubuntu CVE records "
                      f"({time.time() - t0:.0f}s)", flush=True)

    # Sequential second pass for stragglers: connection resets come from
    # bursting the API, so retrying one-at-a-time clears most of them.
    if errors:
        print(f"    retrying {len(errors)} failed lookups sequentially...",
              flush=True)
        for cve in list(errors):
            _, err = _one(cve)
            if err is None:
                del errors[cve]
    return errors


# ---------------------------------------------------------------------------
# Finite State API operations
# ---------------------------------------------------------------------------

def resolve_project_version_id(base_url, token, project_name, version_name):
    """Resolve a project name + version name to a projectVersionId."""
    # RSQL filter: name=="<project_name>"
    flt = 'name=="{}"'.format(project_name.replace('"', '\\"'))
    _, _, payload = _fs_request(
        "GET", base_url, token, "/public/v0/projects",
        query={"filter": flt, "limit": 50},
    )
    projects = _items(payload)
    if not projects:
        raise ApiError(f'No project found with name "{project_name}".')
    # Prefer an exact name match if the filter was fuzzy.
    exact = [p for p in projects if p.get("name") == project_name]
    candidates = exact or projects
    if len(candidates) > 1:
        names = ", ".join(f'{p.get("name")} ({p.get("id")})' for p in candidates)
        raise ApiError(f'Multiple projects matched "{project_name}": {names}')
    project_id = candidates[0]["id"]

    _, _, versions = _fs_request(
        "GET", base_url, token, f"/public/v0/projects/{project_id}/versions",
    )
    versions = versions or []
    matches = [v for v in versions if v.get("version") == version_name]
    if not matches:
        available = ", ".join(v.get("version", "?") for v in versions) or "(none)"
        raise ApiError(
            f'No version "{version_name}" for project "{project_name}". '
            f"Available: {available}"
        )
    return matches[0]["id"]


def _items(payload):
    """Normalize a list-or-{items:[...]} payload to a list."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    return payload.get("items", []) or []


def iter_cve_findings(base_url, token, pvid, severities=None):
    """Yield every CVE finding for a project version, paginating.

    `severities` optionally restricts results server-side to the given
    severity levels (e.g. ["critical", "high"])."""
    offset = 0
    while True:
        query = {"type": "cve", "offset": offset, "limit": FINDINGS_PAGE_SIZE}
        if severities:
            query["filter"] = "severity=in=({})".format(",".join(severities))
        status, headers, payload = _fs_request(
            "GET", base_url, token,
            f"/public/v0/versions/{pvid}/findings",
            query=query,
        )
        batch = _items(payload)
        if not batch:
            break
        for f in batch:
            yield f
        offset += len(batch)
        total = headers.get("X-Total-Count")
        if total is not None and offset >= int(total):
            break
        if len(batch) < FINDINGS_PAGE_SIZE:
            break


def set_not_affected(base_url, token, pvid, finding_id, reason):
    # Send only the fields that apply. justification/response are enum-
    # validated, so omit response entirely rather than sending "" (which the
    # API rejects with HTTP 400). status + justification + reason is accepted.
    body = {
        "status": VEX_STATUS,
        "justification": VEX_JUSTIFICATION,
        "reason": reason,
    }
    _fs_request(
        "PUT", base_url, token,
        f"/public/v0/findings/{pvid}/{finding_id}/status",
        body=body,
    )


def detect_ubuntu_release(base_url, token, pvid):
    """Inspect the project version's operating-system component(s) and return
    (codename, version_str) for Ubuntu, or (None, None) if not found/unknown.
    Some images carry the Ubuntu release only at the OS level (not per
    package), so this is what unlocks release-level not-affected matching."""
    _, _, payload = _fs_request(
        "GET", base_url, token, "/public/v0/components",
        query={"filter": f"projectVersion=={pvid} and type==operating-system",
               "excluded": "false", "limit": 50},
    )
    codenames = {}
    for c in _items(payload):
        name = (c.get("name") or "")
        supplier = (c.get("supplier") or "")
        if "ubuntu" not in name.lower() and "canonical" not in supplier.lower():
            continue
        cn = ubuntu_release_codename(c.get("version") or "")
        if cn:
            codenames.setdefault(cn, c.get("version"))
    if not codenames:
        return None, None
    if len(codenames) > 1:
        print(f"  WARNING: multiple Ubuntu releases on this version "
              f"({', '.join(sorted(codenames))}); using {sorted(codenames)[0]}.")
    cn = sorted(codenames)[0]
    return cn, codenames[cn]


def fetch_dependencies(base_url, token, pvid):
    """Return all direct dependency edges for a project version (paginated)."""
    out = []
    offset = 0
    page_size = 100
    while True:
        _, headers, payload = _fs_request(
            "GET", base_url, token,
            f"/public/v0/project-versions/{pvid}/dependencies",
            query={"offset": offset, "limit": page_size},
        )
        batch = _items(payload)
        out.extend(batch)
        if not batch or len(batch) < page_size:
            break
        offset += len(batch)
        total = {k.lower(): v for k, v in headers.items()}.get("x-total-count")
        if total is not None and len(out) >= int(total):
            break
    return out


def latest_referenced_versions(base_url, token, deps):
    """Collapse dependency edges to one version per dependency project: the
    most recently created among the versions actually referenced. Returns a
    list of (project_id, project_name, version_id, version_name)."""
    by_proj = {}
    for d in deps:
        proj = d.get("dependencyProject") or {}
        dv = d.get("dependencyProjectVersion") or {}
        pid = proj.get("id")
        if pid is None:
            continue
        entry = by_proj.setdefault(
            pid, {"name": proj.get("name"), "vids": set()})
        if dv.get("id"):
            entry["vids"].add(dv.get("id"))

    selected = []
    for pid, info in by_proj.items():
        _, _, payload = _fs_request(
            "GET", base_url, token, f"/public/v0/projects/{pid}/versions")
        versions = payload if isinstance(payload, list) else []
        referenced = [v for v in versions if v.get("id") in info["vids"]]
        if referenced:
            latest = max(referenced, key=lambda v: v.get("created") or "")
            selected.append((pid, info["name"], latest.get("id"),
                             latest.get("version")))
        elif info["vids"]:
            # No created data available; fall back to an arbitrary referenced id.
            vid = sorted(info["vids"])[0]
            selected.append((pid, info["name"], vid, "?"))
    return selected


# ---------------------------------------------------------------------------
# Core decision: is this CVE fixed by Ubuntu for the installed version?
# ---------------------------------------------------------------------------

def package_name_from_component(name):
    """Strip a purl-style namespace prefix: 'ubuntu/openssl' -> 'openssl'."""
    if not name:
        return ""
    return name.split("/")[-1]


def is_ubuntu_component(name, version):
    """A component is Ubuntu-sourced if its name is namespaced 'ubuntu/...'
    or its Debian version carries an 'ubuntu' revision marker."""
    name = (name or "").lower()
    version = (version or "").lower()
    return name.startswith("ubuntu/") or "ubuntu" in version


# Ubuntu MAJOR.MINOR -> Security-tracker release codename.
UBUNTU_RELEASES = {
    "14.04": "trusty", "16.04": "xenial", "18.04": "bionic",
    "20.04": "focal", "22.04": "jammy", "24.04": "noble",
    "24.10": "oracular", "25.04": "plucky", "25.10": "questing",
    "26.04": "resolute",
}


def ubuntu_release_codename(version_str):
    """Map an OS-component version like '22.04.5 LTS' (or '22.04.5%20LTS') to
    a release codename ('jammy'). Returns None if not recognized."""
    m = re.search(r"(\d+)\.(\d+)", version_str or "")
    if not m:
        return None
    return UBUNTU_RELEASES.get(f"{m.group(1)}.{m.group(2)}")


def pkg_stem(name):
    """Normalized stem of a package name, for fuzzy binary<->source matching
    when there is no exact name match (e.g. perl-base ~ perl,
    libpng16-16 ~ libpng1.6). Strips a leading 'lib', common binary suffixes,
    and trailing version-ish characters."""
    s = (name or "").lower()
    if s.startswith("lib"):
        s = s[3:]
    for suf in ("-dev", "-bin", "-base", "-common", "-data", "-doc",
                "-utils", "-tools", "-dbg"):
        if s.endswith(suf):
            s = s[:-len(suf)]
    return re.sub(r"[0-9.+_-]+$", "", s)


def evaluate_fix(cve_data, comp_name, installed_version, release=None,
                 allow_not_affected=False):
    """
    Decide whether the CVE is moot for `installed_version` of the component,
    per Ubuntu's security data.

    Two ways a finding qualifies as NOT_AFFECTED:
      - "fixed": a 'released' status whose fixed version the installed version
        is >= (dpkg comparison). Guarded by upstream-series equality so we
        never compare across releases or unrelated packages.
      - "not-affected": Ubuntu marks the package not-affected for the relevant
        release (no fixed version needed). Only considered when `release` is
        known (from the operating-system component or --release) and
        allow_not_affected is set, since it is release-specific.

    Ubuntu's tracker is keyed by *source* package while findings carry *binary*
    names (libc6 -> glibc, perl-base -> perl). We prefer an exact source-name
    match and otherwise fall back to every package in the CVE; the upstream
    guard keeps 'fixed' matches honest, and 'not-affected' fallbacks require a
    stem match (or a single-package CVE) to stay conservative.

    When `release` is given, only that release's statuses are considered.
    When it is None, we fall back to lineage matching across releases for
    'released' only (no not-affected).

    Returns (qualifies: bool, detail: dict|None) where detail has
    kind ('fixed'|'not-affected'), release, fixed_version (None if
    not-affected), and source package.
    """
    if not cve_data:
        return False, None
    pkgs = cve_data.get("packages") or []
    if not pkgs:
        return False, None

    target = package_name_from_component(comp_name)
    named = [p for p in pkgs if p.get("name") == target]
    candidates = named if named else pkgs

    installed_upstream = upstream_of(installed_version)
    fixed_best = None
    na_best = None
    for pkg in candidates:
        pname = pkg.get("name")
        # Conservative gate for the version-less not-affected case.
        stem_ok = (pname == target or pkg_stem(pname) == pkg_stem(target)
                   or len(pkgs) == 1)
        for st in pkg.get("statuses") or []:
            codename = st.get("release_codename")
            if release and codename != release:
                continue
            status = st.get("status")
            desc = (st.get("description") or "").strip()
            if status == "released":
                if not desc or upstream_of(desc) != installed_upstream:
                    continue
                if dpkg_compare(installed_version, desc) >= 0:
                    cand = {"kind": "fixed", "release": codename,
                            "fixed_version": desc, "source": pname}
                    if fixed_best is None or dpkg_compare(
                            desc, fixed_best["fixed_version"]) > 0:
                        fixed_best = cand
            elif status == "not-affected" and allow_not_affected and stem_ok:
                if na_best is None:
                    na_best = {"kind": "not-affected", "release": codename,
                               "fixed_version": None, "source": pname}
    if fixed_best is not None:
        return True, fixed_best
    if na_best is not None:
        return True, na_best
    return False, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Mark Ubuntu-fixed CVE findings as NOT_AFFECTED on "
                    "Finite State.",
    )
    p.add_argument("--project-version-id",
                   help="Project version ID (skips name lookup).")
    p.add_argument("--project", help="Project name (use with --version).")
    p.add_argument("--version", dest="version_name",
                   help="Version name (use with --project).")
    p.add_argument("--domain", default=os.environ.get("FINITE_STATE_DOMAIN"),
                   help="Finite State subdomain, e.g. acme.finitestate.io "
                        "(default: $FINITE_STATE_DOMAIN).")
    p.add_argument("--token", default=os.environ.get("FINITE_STATE_AUTH_TOKEN"),
                   help="API token (default: $FINITE_STATE_AUTH_TOKEN).")
    p.add_argument("--release",
                   help="Force an Ubuntu release codename (e.g. jammy), "
                        "overriding OS-component detection. Default: detect "
                        "from the operating-system component; if none is "
                        "found, fall back to version-lineage matching "
                        "(released-only, no not-affected).")
    p.add_argument("--severity", default=None,
                   help="Comma-separated severities to scope to, e.g. "
                        "'critical,high'. Default: all severities.")
    p.add_argument("--include-dependencies", action="store_true",
                   help="Also process the latest referenced version of each "
                        "direct dependency project. Default: only the given "
                        "version (warns if dependencies exist).")
    p.add_argument("--apply", action="store_true",
                   help="Actually send the status updates (default: dry-run).")
    p.add_argument("--overwrite", action="store_true",
                   help="Also re-set findings that already have a VEX status.")
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after acting on N findings total across all "
                        "processed versions (0 = no limit). Useful for "
                        "testing.")
    return p.parse_args(argv)


def _new_stats():
    return {
        "cve_findings": 0, "ubuntu_components": 0, "matched_fixed": 0,
        "matched_not_affected": 0, "updated": 0, "skipped_triaged": 0,
        "no_fix": 0, "no_ubuntu_data": 0, "errors": 0,
    }


def process_version(base_url, token, pvid, args, severities, label, state):
    """Process a single project version. Returns its stats dict. `state` holds
    the shared cross-version attempt counter for the global --limit."""
    stats = _new_stats()
    print(f"\n{'-' * 60}\n{label}  (projectVersionId {pvid})")

    # Determine the Ubuntu release: explicit override, else OS-component.
    release = args.release
    if release:
        print(f"  release: {release} (from --release)")
    else:
        release, osver = detect_ubuntu_release(base_url, token, pvid)
        if release:
            print(f"  release: {release} (detected OS component '{osver}')")
        else:
            print("  release: unknown (no Ubuntu OS component); "
                  "falling back to version-lineage matching, released-only.")
    allow_not_affected = bool(release)

    print("  Fetching CVE findings...", flush=True)
    try:
        findings = list(iter_cve_findings(base_url, token, pvid, severities))
    except ApiError as e:
        print(f"  error fetching findings: {e}")
        stats["errors"] += 1
        return stats
    stats["cve_findings"] = len(findings)

    ubuntu_findings = [
        f for f in findings
        if is_ubuntu_component((f.get("component") or {}).get("name"),
                               (f.get("component") or {}).get("version"))
        and (f.get("findingId") or "").upper().startswith("CVE-")
    ]
    stats["ubuntu_components"] = len(ubuntu_findings)
    print(f"  {stats['cve_findings']} CVE findings, "
          f"{stats['ubuntu_components']} on Ubuntu components.", flush=True)
    if not ubuntu_findings:
        return stats

    unique_cves = sorted({f.get("findingId") for f in ubuntu_findings})
    print(f"  Looking up {len(unique_cves)} unique CVEs on ubuntu.com...",
          flush=True)
    fetch_errors = prefetch_ubuntu(unique_cves)

    for f in ubuntu_findings:
        comp = f.get("component") or {}
        comp_name = comp.get("name") or ""
        comp_version = comp.get("version") or ""
        cve = f.get("findingId") or ""
        finding_id = f.get("id")
        current_status = f.get("status")

        if cve in fetch_errors:
            print(f"  [err ] {cve} {comp_name} {comp_version}: "
                  f"{fetch_errors[cve]}")
            stats["errors"] += 1
            continue

        cve_data = _UBUNTU_CACHE.get(cve)
        if cve_data is None:
            stats["no_ubuntu_data"] += 1
            continue

        ok, detail = evaluate_fix(cve_data, comp_name, comp_version,
                                  release, allow_not_affected)
        if not ok:
            stats["no_fix"] += 1
            continue

        page = UBUNTU_CVE_PAGE.format(cve=cve)
        src = detail["source"]
        src_note = (f" [{src}]" if src
                    and src != package_name_from_component(comp_name) else "")
        if detail["kind"] == "fixed":
            stats["matched_fixed"] += 1
            verdict = f"fix {detail['fixed_version']} / {detail['release']}"
            reason = (
                f"Fixed by Ubuntu{src_note} in {detail['fixed_version']} "
                f"({detail['release']}); installed {comp_version} >= fix. "
                f"Backported patch present. See {page}")
        else:
            stats["matched_not_affected"] += 1
            verdict = f"not-affected / {detail['release']}"
            reason = (
                f"Ubuntu marks {src or comp_name} not-affected for "
                f"{detail['release']}; installed {comp_version}. See {page}")

        if current_status not in UNTRIAGED_STATUSES and not args.overwrite:
            print(f"  [skip] {cve} {comp_name} {comp_version} "
                  f"(already {current_status}) -> {verdict}")
            stats["skipped_triaged"] += 1
            continue

        if args.apply:
            try:
                set_not_affected(base_url, token, pvid, finding_id, reason)
                stats["updated"] += 1
                print(f"  [set ] {cve} {comp_name} {comp_version} "
                      f"-> NOT_AFFECTED ({verdict})")
            except ApiError as e:
                print(f"  [err ] {cve} {comp_name} {comp_version}: {e}")
                stats["errors"] += 1
        else:
            print(f"  [would] {cve} {comp_name} {comp_version} "
                  f"-> NOT_AFFECTED ({verdict})")

        # Global cap on findings *acted on* (would/set), across all versions.
        state["attempted"] += 1
        if args.limit and state["attempted"] >= args.limit:
            print(f"  -- reached --limit {args.limit}, stopping --")
            state["stop"] = True
            break

    return stats


def main(argv):
    args = parse_args(argv)

    if not args.domain:
        sys.exit("error: no domain (set FINITE_STATE_DOMAIN or pass --domain).")
    if not args.token:
        sys.exit("error: no token (set FINITE_STATE_AUTH_TOKEN or pass "
                 "--token).")

    domain = args.domain.replace("https://", "").replace("http://", "")
    domain = domain.strip("/")
    base_url = f"https://{domain}/api"

    if not args.project_version_id and not (args.project and args.version_name):
        sys.exit("error: pass --project-version-id, or both --project and "
                 "--version.")

    severities = None
    if args.severity:
        valid = {"critical", "high", "medium", "low", "none"}
        severities = [s.strip().lower()
                      for s in args.severity.split(",") if s.strip()]
        bad = [s for s in severities if s not in valid]
        if bad:
            sys.exit(f"error: invalid severity {bad}; "
                     f"choose from {sorted(valid)}.")

    try:
        if args.project_version_id:
            root_pvid = args.project_version_id
            root_label = f"version {root_pvid}"
        else:
            root_pvid = resolve_project_version_id(
                base_url, args.token, args.project, args.version_name)
            root_label = f"{args.project} / {args.version_name}"
            print(f"Resolved {root_label} -> projectVersionId {root_pvid}")
    except ApiError as e:
        sys.exit(f"error resolving project version: {e}")

    # Discover dependencies up front.
    try:
        deps = fetch_dependencies(base_url, args.token, root_pvid)
    except ApiError as e:
        print(f"warning: could not fetch dependencies: {e}")
        deps = []

    targets = [(root_pvid, root_label)]
    if deps:
        selected = latest_referenced_versions(base_url, args.token, deps)
        if args.include_dependencies:
            for pid, pname, vid, vname in selected:
                targets.append((vid, f"dependency {pname} / {vname}"))
            print(f"Including {len(selected)} dependency project(s) "
                  f"(from {len(deps)} dependency edges).")
        else:
            print(f"NOTE: this version has {len(deps)} dependency edges across "
                  f"{len(selected)} project(s). Re-run with "
                  f"--include-dependencies to process them too.")

    mode = "APPLY" if args.apply else "DRY-RUN"
    scope = f" severities={','.join(severities)}" if severities else ""
    print(f"\n[{mode}] host={domain}{scope} "
          f"versions-to-process={len(targets)}")

    run_start = time.time()
    state = {"attempted": 0, "stop": False}
    total = _new_stats()
    for pvid, label in targets:
        st = process_version(base_url, args.token, pvid, args, severities,
                             label, state)
        for k in total:
            total[k] += st.get(k, 0)
        if state["stop"]:
            print("\n(global --limit reached; skipping remaining versions)")
            break

    elapsed = time.time() - run_start
    matched = total["matched_fixed"] + total["matched_not_affected"]
    print("\n" + "=" * 60)
    print(f"Versions processed:           {len(targets) if not state['stop'] else '<=' + str(len(targets))}")
    print(f"CVE findings scanned:         {total['cve_findings']}")
    print(f"On Ubuntu components:         {total['ubuntu_components']}")
    print(f"Ubuntu reports moot:          {matched} "
          f"(fixed {total['matched_fixed']}, "
          f"not-affected {total['matched_not_affected']})")
    if args.apply:
        print(f"Marked NOT_AFFECTED:          {total['updated']}")
    else:
        print(f"Would mark NOT_AFFECTED:      {matched - total['skipped_triaged']}")
    print(f"Skipped (already triaged):    {total['skipped_triaged']}")
    print(f"Not moot per Ubuntu:          {total['no_fix']}")
    print(f"No Ubuntu data (404):         {total['no_ubuntu_data']}")
    print(f"Errors:                       {total['errors']}")
    print(f"Elapsed:                      {elapsed:.1f}s")
    print("=" * 60)
    if not args.apply and matched > total["skipped_triaged"]:
        print("\nDry-run only. Re-run with --apply to write these "
              "status updates.")


if __name__ == "__main__":
    main(sys.argv[1:])
