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


def evaluate_fix(cve_data, comp_name, installed_version, release=None):
    """
    Decide whether `installed_version` of the component already contains
    Ubuntu's fix for the CVE described by `cve_data`.

    Matching strategy: Ubuntu's tracker is keyed by *source* package, while
    findings carry *binary* package names (e.g. libc6 -> source glibc). We
    therefore prefer a package whose source name equals the component name,
    but fall back to every package in the CVE when there is no exact match.
    The real signal is the Ubuntu *version lineage*: a fix only counts when a
    'released' status shares the installed version's upstream series and the
    installed version is >= the fixed version (dpkg comparison). The full
    Ubuntu version string (e.g. 2.35-0ubuntu3.8) is source-and-release
    specific, so lineage matching is reliable even without the source name.

    Returns (fixed: bool, detail: dict|None). detail carries the matched
    release_codename, fixed_version, and source package when fixed is True.
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
    best = None  # prefer the highest fixed version we are >= to
    for pkg in candidates:
        for st in pkg.get("statuses") or []:
            if st.get("status") != "released":
                continue
            codename = st.get("release_codename")
            if release and codename != release:
                continue
            fixed_version = (st.get("description") or "").strip()
            if not fixed_version:
                continue
            # Lineage guard: only compare versions from the same upstream
            # series, so we don't compare a jammy install against a focal fix.
            if upstream_of(fixed_version) != installed_upstream:
                continue
            if dpkg_compare(installed_version, fixed_version) >= 0:
                cand = {
                    "release": codename,
                    "fixed_version": fixed_version,
                    "source": pkg.get("name"),
                }
                if best is None or dpkg_compare(
                        fixed_version, best["fixed_version"]) > 0:
                    best = cand
    if best is not None:
        return True, best
    return False, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Mark Ubuntu-fixed CVE findings as NOT_AFFECTED on Finite State.",
    )
    p.add_argument("--project-version-id", help="Project version ID (skips name lookup).")
    p.add_argument("--project", help="Project name (use with --version).")
    p.add_argument("--version", dest="version_name", help="Version name (use with --project).")
    p.add_argument("--domain", default=os.environ.get("FINITE_STATE_DOMAIN"),
                   help="Finite State subdomain, e.g. acme.finitestate.io "
                        "(default: $FINITE_STATE_DOMAIN).")
    p.add_argument("--token", default=os.environ.get("FINITE_STATE_AUTH_TOKEN"),
                   help="API token (default: $FINITE_STATE_AUTH_TOKEN).")
    p.add_argument("--release", help="Restrict matching to one Ubuntu release codename "
                                     "(e.g. jammy). Default: auto-match by version lineage.")
    p.add_argument("--severity", default=None,
                   help="Comma-separated severities to scope to, e.g. "
                        "'critical,high'. Default: all severities.")
    p.add_argument("--apply", action="store_true",
                   help="Actually send the status updates (default: dry-run).")
    p.add_argument("--overwrite", action="store_true",
                   help="Also re-set findings that already have a VEX status.")
    p.add_argument("--limit", type=int, default=0,
                   help="Stop after marking N findings (0 = no limit). Useful for testing.")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    if not args.domain:
        sys.exit("error: no domain (set FINITE_STATE_DOMAIN or pass --domain).")
    if not args.token:
        sys.exit("error: no token (set FINITE_STATE_AUTH_TOKEN or pass --token).")

    domain = args.domain.replace("https://", "").replace("http://", "").strip("/")
    base_url = f"https://{domain}/api"

    if not args.project_version_id and not (args.project and args.version_name):
        sys.exit("error: pass --project-version-id, or both --project and --version.")

    severities = None
    if args.severity:
        valid = {"critical", "high", "medium", "low", "none"}
        severities = [s.strip().lower() for s in args.severity.split(",") if s.strip()]
        bad = [s for s in severities if s not in valid]
        if bad:
            sys.exit(f"error: invalid severity {bad}; choose from {sorted(valid)}.")

    try:
        if args.project_version_id:
            pvid = args.project_version_id
        else:
            pvid = resolve_project_version_id(
                base_url, args.token, args.project, args.version_name)
            print(f"Resolved {args.project} / {args.version_name} -> projectVersionId {pvid}")
    except ApiError as e:
        sys.exit(f"error resolving project version: {e}")

    mode = "APPLY" if args.apply else "DRY-RUN"
    scope = f" severities={','.join(severities)}" if severities else ""
    print(f"\n[{mode}] host={domain} projectVersionId={pvid}{scope}\n")

    run_start = time.time()
    stats = {
        "cve_findings": 0,
        "ubuntu_components": 0,
        "matched_fixed": 0,
        "updated": 0,
        "skipped_triaged": 0,
        "no_fix": 0,
        "no_ubuntu_data": 0,
        "errors": 0,
    }

    print("Fetching CVE findings...", flush=True)
    try:
        findings = list(
            iter_cve_findings(base_url, args.token, pvid, severities))
    except ApiError as e:
        sys.exit(f"error fetching findings: {e}")
    stats["cve_findings"] = len(findings)

    # Keep only CVE findings on Ubuntu components.
    ubuntu_findings = [
        f for f in findings
        if is_ubuntu_component((f.get("component") or {}).get("name"),
                               (f.get("component") or {}).get("version"))
        and (f.get("findingId") or "").upper().startswith("CVE-")
    ]
    stats["ubuntu_components"] = len(ubuntu_findings)
    print(f"  {stats['cve_findings']} CVE findings, "
          f"{stats['ubuntu_components']} on Ubuntu components.", flush=True)

    # Prefetch all referenced Ubuntu CVE records concurrently.
    unique_cves = sorted({f.get("findingId") for f in ubuntu_findings})
    print(f"Looking up {len(unique_cves)} unique CVEs on ubuntu.com...", flush=True)
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

        fixed, detail = evaluate_fix(
            cve_data, comp_name, comp_version, args.release)
        if not fixed:
            stats["no_fix"] += 1
            continue

        stats["matched_fixed"] += 1
        page = UBUNTU_CVE_PAGE.format(cve=cve)
        src = detail["source"]
        src_note = f" [{src}]" if src and src != package_name_from_component(comp_name) else ""
        reason = (
            f"Fixed by Ubuntu{src_note} in {detail['fixed_version']} "
            f"({detail['release']}); installed {comp_version} >= fix. "
            f"Backported patch present. See {page}"
        )

        already_triaged = current_status not in UNTRIAGED_STATUSES
        if already_triaged and not args.overwrite:
            print(f"  [skip] {cve} {comp_name} {comp_version} "
                  f"(already {current_status}) -> {detail['fixed_version']}")
            stats["skipped_triaged"] += 1
            continue

        if args.apply:
            try:
                set_not_affected(base_url, args.token, pvid, finding_id, reason)
                stats["updated"] += 1
                print(f"  [set ] {cve} {comp_name} {comp_version} "
                      f"-> NOT_AFFECTED (fix {detail['fixed_version']} / {detail['release']})")
            except ApiError as e:
                print(f"  [err ] {cve} {comp_name} {comp_version}: {e}")
                stats["errors"] += 1
        else:
            print(f"  [would] {cve} {comp_name} {comp_version} "
                  f"-> NOT_AFFECTED (fix {detail['fixed_version']} / {detail['release']})")

        if args.limit and (stats["updated"] + (0 if args.apply else stats["matched_fixed"])) >= args.limit:
            print(f"  -- reached --limit {args.limit}, stopping --")
            break

    elapsed = time.time() - run_start
    print("\n" + "=" * 60)
    print(f"CVE findings scanned:         {stats['cve_findings']}")
    print(f"On Ubuntu components:         {stats['ubuntu_components']}")
    print(f"Ubuntu reports fixed:         {stats['matched_fixed']}")
    if args.apply:
        print(f"Marked NOT_AFFECTED:          {stats['updated']}")
    else:
        print(f"Would mark NOT_AFFECTED:      {stats['matched_fixed'] - stats['skipped_triaged']}")
    print(f"Skipped (already triaged):    {stats['skipped_triaged']}")
    print(f"Not fixed by Ubuntu:          {stats['no_fix']}")
    print(f"No Ubuntu data (404):         {stats['no_ubuntu_data']}")
    print(f"Errors:                       {stats['errors']}")
    print(f"Elapsed:                      {elapsed:.1f}s")
    print("=" * 60)
    if not args.apply and stats["matched_fixed"]:
        print("\nDry-run only. Re-run with --apply to write these status updates.")


if __name__ == "__main__":
    main(sys.argv[1:])
