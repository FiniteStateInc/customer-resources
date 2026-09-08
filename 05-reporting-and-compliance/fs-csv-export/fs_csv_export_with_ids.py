#!/usr/bin/env python3
"""
Export Finite State findings or components for a project version to CSV.

Reproduces the platform's per-version CSV exports, but adds the row's unique
`id` as the first column:
  * findings   -> the unique finding id (distinct from `findingId`, the CVE id)
  * components -> the unique (version-)component id

Works against both the new (UUID ids) and legacy (numeric ids) backends.

Auth:
  Reads the API token from FINITE_STATE_AUTH_TOKEN and the domain from
  FINITE_STATE_DOMAIN, or takes --token / --domain on the command line (the
  flags win over the env vars). The token is sent as the `X-Authorization`
  request header.

Selecting the version (either mode, mutually exclusive):
  --project-version-id <id>            bypass lookup, OR
  --project <name> --version <name>    resolve the projectVersionId

Usage:
  fs_export.py findings   [options]
  fs_export.py components [options]

Requires only the Python 3 standard library.
"""

import argparse
import csv
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------- #
# Column layouts (platform export order, with the unique `id` prepended).
# --------------------------------------------------------------------------- #

FINDINGS_COLUMNS = [
    "id",
    "CVE ID",
    "Severity (Weighted)",
    "policy - violations",
    "policy - warnings",
    "EPSS-Weighted Score",
    "CVSS Score",
    "CVSS Vector",
    "Component",
    "reachabilityScore",
    "Detection Date",
    "Issue Tracking",
    "Status",
    "columns.epssWeightedRisk",
    "columns.epssWeightedSeverity",
    "columns.exploitMaturity",
    "columns.reason",
    "columns.cveReferences",
    "columns.comments",
]

COMPONENTS_COLUMNS = [
    "id",
    "Name",
    "Version",
    "policy - violations",
    "policy - warnings",
    "Findings - critical",
    "Findings - high",
    "Findings - medium",
    "Findings - low",
    "CDX Type",
    "Supplier",
    "Licenses - names",
    "Licenses - types",
    "releaseDate",
    "Source",
    "Issue Tracking",
    "Status",
    "Edited",
    "Last Modified At",
    "Last Modified By",
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def normalize_domain(domain):
    """Strip scheme/trailing slash so we can build https://<domain>/api/..."""
    domain = domain.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/")


def blank(value):
    return "" if value is None else str(value)


def fmt_num(value):
    """Render a number without a spurious trailing '.0' (e.g. 0.0 -> '0')."""
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def join_list(value, sep="; "):
    """Join a list into a string; pass through non-lists as-is."""
    if value is None:
        return ""
    if isinstance(value, list):
        return sep.join(str(v) for v in value if v is not None)
    return str(value)


def render_tracker(tracker):
    """Issue-tracking cell. Blank unless there is an actual linked ticket.

    New backend sends `tracker: null`; legacy sends an object like
    {enabled, relative_url, all_tickets, first_ticket} which is blank in the
    export until a ticket is actually linked.
    """
    if not tracker:
        return ""
    if isinstance(tracker, str):
        return tracker
    if isinstance(tracker, dict):
        first = tracker.get("first_ticket")
        if isinstance(first, dict):
            return first.get("url") or first.get("key") or first.get("id") or ""
        if isinstance(first, str):
            return first
        allt = tracker.get("all_tickets")
        if isinstance(allt, list) and allt:
            refs = []
            for t in allt:
                if isinstance(t, dict):
                    refs.append(t.get("url") or t.get("key") or t.get("id") or "")
                elif t:
                    refs.append(str(t))
            return "; ".join(r for r in refs if r)
        return ""
    return str(tracker)


# --------------------------------------------------------------------------- #
# API client
# --------------------------------------------------------------------------- #

# Statuses worth retrying: rate limiting and the documented export queue-full.
RETRY_STATUSES = (429, 503)


class FiniteStateClient:
    def __init__(self, domain, token, max_retries=6, on_retry=None):
        self.base = f"https://{normalize_domain(domain)}/api/public/v0"
        self.token = token
        self.max_retries = max_retries
        self.on_retry = on_retry          # called as on_retry(status, wait, attempt)
        self.retries = 0                  # total waits performed
        self._lock = threading.Lock()

    def _backoff(self, err, attempt):
        """Seconds to wait: server's Retry-After if given, else exponential."""
        retry_after = err.headers.get("Retry-After") if err.headers else None
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except ValueError:
                pass
        return min(2.0 ** attempt, 30.0)

    def get(self, path, params=None, fatal=True):
        """GET and decode JSON. fatal=False raises RuntimeError instead of exiting,
        so a caller looping over many resources can survive one failure."""
        url = f"{self.base}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, method="GET")
        req.add_header("X-Authorization", self.token)
        req.add_header("Accept", "application/json")

        def fail(msg):
            if fatal:
                die(msg)
            raise RuntimeError(msg)

        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req) as resp:
                    body = resp.read().decode("utf-8")
                break
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")
                if e.code in RETRY_STATUSES and attempt < self.max_retries:
                    wait = self._backoff(e, attempt)
                    with self._lock:
                        self.retries += 1
                    if self.on_retry:
                        self.on_retry(e.code, wait, attempt)
                    time.sleep(wait)
                    continue
                extra = ""
                if e.code in RETRY_STATUSES:
                    extra = f" (gave up after {self.max_retries} retries)"
                fail(f"HTTP {e.code}{extra} for {url}\n{detail}")
                return None
            except urllib.error.URLError as e:
                fail(f"request failed for {url}: {e.reason}")
                return None
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            fail(f"non-JSON response from {url}:\n{body[:500]}")

    def resolve_project_version_id(self, project_name, version_name):
        """Look up projectVersionId from a project name + version name."""
        projects = self.get(
            "/projects",
            {"filter": f'name=="{project_name}"', "archived": "false", "limit": 100},
        )
        matches = [p for p in projects if p.get("name") == project_name]
        if not matches:
            names = ", ".join(sorted({p.get("name", "?") for p in projects})) or "(none)"
            die(f"no project named {project_name!r}. Candidates returned: {names}")
        if len(matches) > 1:
            ids = ", ".join(p.get("id", "?") for p in matches)
            die(f"multiple projects named {project_name!r}: {ids}. Use --project-version-id.")
        project_id = matches[0]["id"]

        versions = self.get(
            "/versions",
            {"filter": f'project=={project_id};name=="{version_name}"', "limit": 100},
        )
        vmatches = [v for v in versions if v.get("name") == version_name]
        if not vmatches:
            names = ", ".join(sorted({v.get("name", "?") for v in versions})) or "(none)"
            die(f"no version named {version_name!r} in project {project_name!r}. "
                f"Candidates: {names}")
        if len(vmatches) > 1:
            ids = ", ".join(v.get("id", "?") for v in vmatches)
            die(f"multiple versions named {version_name!r}: {ids}. Use --project-version-id.")
        return vmatches[0]["id"]

    def iter_paged(self, path, base_params, page_size, fatal=True):
        """Yield items from a paginated list endpoint until exhausted."""
        offset = 0
        while True:
            params = dict(base_params)
            params["offset"] = offset
            params["limit"] = page_size
            batch = self.get(path, params, fatal=fatal)
            if not isinstance(batch, list):
                die(f"expected a list from {path}, got: {type(batch).__name__}")
            for item in batch:
                yield item
            if len(batch) < page_size:
                break
            offset += page_size


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

def fmt_cvss(f):
    """CVSS base score: the API's own `cvssScore` when present.

    Older backends omit it; there the 0-100 `risk` scaled to 0-10 reproduces the
    platform's value (risk 98 -> 9.8).
    """
    score = f.get("cvssScore")
    if score is None:
        risk = f.get("risk")
        if risk is None:
            return ""
        score = risk / 10.0
    return f"{round(score, 1):.1f}"


def parse_severities(raw):
    """Parse the --severity value into a set of uppercase tokens, or None for all."""
    tokens = {t.strip().upper() for t in raw.split(",") if t.strip()}
    if not tokens or "ALL" in tokens:
        return None
    return tokens


def finding_severity(f, field):
    """Uppercased severity for the chosen field ('severity' raw, or 'weighted')."""
    key = "epssWeightedSeverity" if field == "weighted" else "severity"
    value = f.get(key)
    return value.upper() if isinstance(value, str) else ""


def finding_to_row(f):
    comp = f.get("component") or {}
    component = ""
    if comp.get("name"):
        component = comp["name"]
        if comp.get("version"):
            component = f"{component}:{comp['version']}"

    comments = f.get("comments")
    # The platform renders an empty/absent comments field as the literal "[]".
    comments = json.dumps(comments) if comments else "[]"

    return {
        "id": blank(f.get("id")),
        "CVE ID": blank(f.get("findingId")),
        "Severity (Weighted)": blank(f.get("epssWeightedSeverity")),
        "policy - violations": fmt_num(f.get("violations")),
        "policy - warnings": fmt_num(f.get("warnings")),
        "EPSS-Weighted Score": fmt_num(f.get("epssWeightedRisk")),
        "CVSS Score": fmt_cvss(f),
        "CVSS Vector": blank(f.get("cvssVector")),
        "Component": component,
        "reachabilityScore": fmt_num(f.get("reachabilityScore")),
        "Detection Date": blank(f.get("detected")),
        "Issue Tracking": render_tracker(f.get("tracker")),
        "Status": blank(f.get("status")),
        "columns.epssWeightedRisk": fmt_num(f.get("epssWeightedRisk")),
        "columns.epssWeightedSeverity": blank(f.get("epssWeightedSeverity")),
        "columns.exploitMaturity": blank(f.get("exploitMaturity")),
        "columns.reason": blank(f.get("reason")),
        "columns.cveReferences": join_list(f.get("cveReferences")),
        "columns.comments": comments,
    }


def run_findings(client, pvid, args):
    severities = parse_severities(args.severity)
    base_params = {
        "filter": f"projectVersion=={pvid}",
        "archived": "false",
        "excluded": "false",
        "includeComments": "false" if args.no_comments else "true",
        "includeAdditionalDetails": "false",
        "latestOnly": "false",
    }
    if args.type:
        base_params["type"] = args.type

    def rows():
        for f in client.iter_paged("/findings", base_params, args.page_size):
            if severities is not None and \
                    finding_severity(f, args.severity_field) not in severities:
                yield None  # signals "skipped" to the caller
                continue
            yield finding_to_row(f)

    return FINDINGS_COLUMNS, rows(), severities, args.severity_field


# --------------------------------------------------------------------------- #
# Components
# --------------------------------------------------------------------------- #

def severity_count(severity_counts, level):
    """Case-insensitive lookup into severityCounts; missing -> '0'."""
    if not isinstance(severity_counts, dict):
        return "0"
    for key, value in severity_counts.items():
        if str(key).lower() == level:
            return fmt_num(value)
    return "0"


def license_types(details):
    """Map declaredLicenseDetails[].copyleftFamily to the export's type labels.

    COPYLEFT_STRONG -> Copyleft-Strong, PERMISSIVE -> Permissive, etc.
    Distinct values are joined with '; ' in order of first appearance.
    """
    if not isinstance(details, list):
        return ""
    labels = []
    for d in details:
        family = (d or {}).get("copyleftFamily")
        if not family:
            continue
        label = "-".join(part.capitalize() for part in str(family).split("_"))
        if label not in labels:
            labels.append(label)
    return "; ".join(labels)


def component_to_row(c):
    counts = c.get("severityCounts")
    return {
        "id": blank(c.get("id")),
        "Name": blank(c.get("name")),
        "Version": blank(c.get("version")),
        "policy - violations": fmt_num(c.get("violations")),
        "policy - warnings": fmt_num(c.get("warnings")),
        "Findings - critical": severity_count(counts, "critical"),
        "Findings - high": severity_count(counts, "high"),
        "Findings - medium": severity_count(counts, "medium"),
        "Findings - low": severity_count(counts, "low"),
        "CDX Type": blank(c.get("type")),
        "Supplier": blank(c.get("supplier")),
        "Licenses - names": blank(c.get("declaredLicenses")),
        "Licenses - types": license_types(c.get("declaredLicenseDetails")),
        "releaseDate": blank(c.get("releaseDate")),
        "Source": join_list(c.get("source")),
        "Issue Tracking": render_tracker(c.get("tracker")),
        "Status": blank(c.get("status")),
        "Edited": "Yes" if c.get("edited") else "No",
        "Last Modified At": blank(c.get("lastModifiedAt")),
        "Last Modified By": blank(c.get("lastModifiedBy")),
    }


def run_components(client, pvid, args):
    base_params = {
        "filter": f"projectVersion=={pvid}",
        "excluded": "true" if args.excluded else "false",
        "sort": args.sort,
    }
    if args.edit_status != "any":
        base_params["editStatus"] = args.edit_status

    def rows():
        for c in client.iter_paged("/components", base_params, args.page_size):
            yield component_to_row(c)

    return COMPONENTS_COLUMNS, rows(), None, None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def add_common_args(sub):
    sub.add_argument("-t", "--token", default=os.environ.get("FINITE_STATE_AUTH_TOKEN"),
                     help="API token (default: $FINITE_STATE_AUTH_TOKEN). "
                          "Sent as the X-Authorization header.")
    sub.add_argument("-d", "--domain", default=os.environ.get("FINITE_STATE_DOMAIN"),
                     help="Platform domain, e.g. jermaine.finitestate.io "
                          "(default: $FINITE_STATE_DOMAIN).")
    sub.add_argument("-i", "--project-version-id",
                     help="Resolve directly; mutually exclusive with --project/--version.")
    sub.add_argument("-p", "--project", help="Project name (use together with --version).")
    sub.add_argument("-V", "--version", dest="version_name",
                     help="Version name (use together with --project).")
    sub.add_argument("-n", "--page-size", type=int, default=5000,
                     help="Items per API page (default: 5000, API max 10000).")
    sub.add_argument("-o", "--output",
                     help="Output CSV path (default: <kind>_<projectVersionId>.csv). "
                          "Use '-' for stdout.")


def self_check():
    # cvssScore wins; risk*0.1 is the fallback for backends that omit it.
    assert fmt_cvss({"cvssScore": 9.8, "risk": 10}) == "9.8"
    assert fmt_cvss({"cvssScore": 10}) == "10.0"
    assert fmt_cvss({"cvssScore": 0}) == "0.0"
    assert fmt_cvss({"risk": 98}) == "9.8"
    assert fmt_cvss({"risk": 0}) == "0.0"
    assert fmt_cvss({}) == ""

    # New backend: real vector + score.
    row = finding_to_row({
        "id": "06c5e567", "findingId": "CVE-2026-11856", "severity": "critical",
        "cvssScore": 9.8, "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "risk": 98, "violations": 2, "warnings": 0, "epssWeightedRisk": 7.8,
        "epssWeightedSeverity": "HIGH", "component": {"name": "curl", "version": "8.17.0-2"},
    })
    assert row["CVSS Vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert row["CVSS Score"] == "9.8"
    assert row["Component"] == "curl:8.17.0-2"

    # Legacy backend: no cvss fields at all -> derived score, blank vector.
    legacy = finding_to_row({"id": "-751", "findingId": "CVE-2023-45853", "risk": 98,
                             "epssWeightedSeverity": "HIGH", "violations": 2,
                             "warnings": 0, "epssWeightedRisk": 7.8,
                             "component": {"name": "zlib", "version": "1.2.11"}})
    assert legacy["CVSS Score"] == "9.8", legacy["CVSS Score"]
    assert legacy["CVSS Vector"] == ""
    assert legacy["columns.comments"] == "[]"

    # Components: lowercase/empty severityCounts, copyleft labels, Yes/No.
    c = component_to_row({"id": "1", "name": "Linux", "version": "4.14.95",
                          "violations": 116, "warnings": 1880,
                          "severityCounts": {"critical": 71, "high": 1543},
                          "declaredLicenseDetails": [{"copyleftFamily": "COPYLEFT_STRONG"},
                                                     {"copyleftFamily": "PERMISSIVE"}],
                          "source": ["binary_sca"], "edited": True,
                          "tracker": {"enabled": True, "first_ticket": None}})
    assert c["Findings - critical"] == "71" and c["Findings - medium"] == "0"
    assert c["Licenses - types"] == "Copyleft-Strong; Permissive"
    assert c["Edited"] == "Yes"
    assert c["Issue Tracking"] == ""      # tracker object with no linked ticket
    print("self-check OK")


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Export a Finite State project version's findings or components "
                    "to CSV, with the unique id as the first column.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subs = p.add_subparsers(dest="kind", required=True)

    f = subs.add_parser("findings", help="Export CVE/SAST findings.")
    add_common_args(f)
    f.add_argument("-T", "--type", default="cve",
                   choices=["cve", "sast", "thirdparty", "all"],
                   help="Finding type to export (default: cve, matching the platform "
                        "CVE findings export).")
    f.add_argument("-s", "--severity", default="high,critical",
                   help="Comma-separated severities to include, e.g. 'high,critical' "
                        "(default). Use 'all' to disable filtering. Values: critical, "
                        "high, medium, low, none, info (unknown for the weighted field).")
    f.add_argument("-F", "--severity-field", default="severity",
                   choices=["severity", "weighted"],
                   help="Which field to filter on: 'severity' = raw CVSS severity "
                        "(default), 'weighted' = EPSS-weighted band shown in the "
                        "'Severity (Weighted)' column.")
    f.add_argument("-N", "--no-comments", action="store_true",
                   help="Do not request comments (faster; comments column stays '[]').")

    c = subs.add_parser("components", help="Export SBOM components.")
    add_common_args(c)
    c.add_argument("-x", "--excluded", action="store_true",
                   help="Export excluded components instead of included ones.")
    c.add_argument("-e", "--edit-status", default="any",
                   choices=["any", "edited", "unedited"],
                   help="Restrict to edited/unedited components (default: any).")
    c.add_argument("-S", "--sort", default="name:asc",
                   help="Sort order (default: name:asc).")

    subs.add_parser("self-check", help="Run built-in assertions and exit.")

    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.kind == "self-check":
        return self_check()

    if not args.token:
        die("no token: set FINITE_STATE_AUTH_TOKEN or pass --token")
    if not args.domain:
        die("no domain: set FINITE_STATE_DOMAIN or pass --domain")

    used_lookup = bool(args.project or args.version_name)
    if args.project_version_id and used_lookup:
        die("--project-version-id is mutually exclusive with --project/--version")
    if not args.project_version_id and not (args.project and args.version_name):
        die("provide --project-version-id, OR both --project and --version")
    if args.page_size < 1:
        die("--page-size must be >= 1")

    client = FiniteStateClient(args.domain, args.token)

    if args.project_version_id:
        pvid = args.project_version_id
    else:
        pvid = client.resolve_project_version_id(args.project, args.version_name)
        print(f"resolved project={args.project!r} version={args.version_name!r} "
              f"-> projectVersionId={pvid}", file=sys.stderr)

    if args.kind == "findings":
        columns, rows, severities, sev_field = run_findings(client, pvid, args)
    else:
        columns, rows, severities, sev_field = run_components(client, pvid, args)

    out_path = args.output or f"{args.kind}_{pvid}.csv"
    to_stdout = out_path == "-"
    # utf-8-sig writes a BOM so Excel opens it cleanly, matching the platform export.
    fh = sys.stdout if to_stdout else open(out_path, "w", encoding="utf-8-sig", newline="")

    count = 0
    skipped = 0
    try:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            if row is None:  # severity-filtered finding
                skipped += 1
                continue
            writer.writerow(row)
            count += 1
    finally:
        if not to_stdout:
            fh.close()

    dest = "stdout" if to_stdout else out_path
    if severities is None:
        print(f"wrote {count} {args.kind} to {dest}", file=sys.stderr)
    else:
        levels = ",".join(sorted(severities))
        print(f"wrote {count} {args.kind} to {dest} "
              f"(filtered to {sev_field} in [{levels}]; {skipped} excluded)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
