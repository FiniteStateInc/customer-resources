#!/usr/bin/env python3
"""Standalone CycloneDX VEX/VDR export (legacy NGP CYCLONEDX_VDR_ONLY parity).

Target can be a platform URL, a bare version ID (UUID or signed integer, tenant-
dependent), or --project/--version names:

  fs_vex_export.py https://app.finitestate.io/projects/<pid>/versions/<vid>/overview
  fs_vex_export.py 4c76b60b-1646-4fa5-b279-3902763b891a
  fs_vex_export.py --project "ACME Router" --version "1.2.3"

Auth: export FS_TOKEN=<api token>  (or FINITE_STATE_AUTH_TOKEN, legacy name),
or pass --token. Prefer the env var: an argument is visible to other users via
`ps` and lands in shell history. Sent as X-Authorization. Base URL comes from
the URL when you pass one, else --base / FS_BASE / FINITE_STATE_DOMAIN.
"""

import argparse
import datetime
import email.utils
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "/api/public/v0"

# Socket timeout per request. Generous: the SBOM export is generated server-side
# before the first byte arrives, and firmware documents run to tens of MB. Bounded
# so a stalled connection fails instead of wedging a pipeline forever.
TIMEOUT = 300

# Bounds on a server-supplied Retry-After, so a hostile or bogus value can't park
# the script for an hour.
RETRY_WAIT_DEFAULT = 30
RETRY_WAIT_MAX = 300

# HTTP statuses worth retrying (matches fs-report/api_client.py's
# _RETRYABLE_STATUS_CODES): 503 is the export concurrency cap, the rest are
# ordinary transient gateway/server errors seen on long-running calls.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Some FS tenants issue UUID-like project/version IDs, others signed int64
# (fs-report/api_client.py:resolve_project treats both as already-an-ID).
ID_RE = re.compile(r"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|-?\d+)$", re.I)

# Any VEX state means the finding was triaged (by a human or by auto-triage).
# Untriaged findings carry no analysis block at all, so presence is the filter.
TRIAGED = "analysis"

# CycloneDX JSON convention, with `vex` kept in the name so a VEX document is never
# mistaken for a full SBOM sitting in the same directory.
EXT = ".vex.cdx.json"

# Per-field cap for the project and version name tokens. Firmware build strings are
# routinely 100+ chars (real example: a 206-char project+version pair), which pushes
# the filename past the 255-byte limit on ext4/APFS/NTFS and past Windows' 260-char
# MAX_PATH once nested in any directory. 40 each keeps the worst case near 120.
NAME_MAX = 40

# Marks where characters were removed from the middle of a name.
ELIDE = "~"


def slug(value, fallback="unknown"):
    """Filesystem-safe token: collapse anything not [A-Za-z0-9.-] into single underscores."""
    s = re.sub(r"[^A-Za-z0-9.-]+", "_", str(value or "")).strip("_.")
    return s or fallback


def shorten(value, budget=NAME_MAX, tail=20):
    """Cap `value` at `budget` chars by removing the MIDDLE, keeping head and tail.

    Head-only truncation is wrong for firmware build strings: sibling versions share
    long common prefixes ("BP_ACME1234_R03_BA04_r001_branch_ACMEPLAT_rl_AP_...") and
    differ only near the end, so cutting the tail throws away the part that
    identifies the build. Keeping both ends preserves the human-recognizable prefix
    AND the distinguishing suffix.
    """
    if len(value) <= budget:
        return value
    if budget <= 0:
        return ""
    head = budget - len(ELIDE) - tail
    if head < 0:
        # tail alone (plus ELIDE) doesn't fit budget: keep only what fits, from the
        # tail — that's still more identifying than a mid-string index out of range.
        return value[-budget:] if budget <= len(ELIDE) else f"{ELIDE}{value[-(budget - len(ELIDE)):]}"
    return f"{value[:head]}{ELIDE}{value[-tail:]}"


def default_filename(doc, version_id):
    """<project>_<version>_<versionId8>_<timestamp>.vex.cdx.json

    Project and version names come from the document's own metadata.component, so
    this costs no extra API call. Each is capped at NAME_MAX with middle elision.

    Because two different versions can shorten to the same text, the first 8 chars
    of the version id are always included: that makes every filename unique AND
    traceable back to the platform record it came from. Timestamp is UTC in the
    legacy platform's export format (YYYYMMDDTHHmmss) plus microseconds: the version
    id is stable across reruns of the same version, so without sub-second precision
    two runs within the same second would silently overwrite each other's output.
    """
    comp = (doc.get("metadata") or {}).get("component") or {}
    project = shorten(slug(comp.get("name"), fallback="project"))
    version = shorten(slug(comp.get("version"), fallback="version"))
    vid = slug(version_id, fallback="novid")[:8]
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%S") + f"{now.microsecond:06d}"
    return f"{project}_{version}_{vid}_{stamp}{EXT}"


def parse_target(target):
    """Return (base, project_id, version_id) from a platform URL, or a bare ID.

    Hostname is irrelevant (app.finitestate.io, acme.finitestate.io, ...); only
    the /projects/<id>/versions/<id> path segments matter. A bare ID can be a UUID
    or a signed int64 — tenants issue either.
    """
    if ID_RE.match(target):
        return None, None, target
    if "/" not in target:
        raise SystemExit(f"not a URL or ID: {target!r}")

    url = target if "://" in target else f"https://{target}"
    parts = urllib.parse.urlsplit(url)
    seg = [s for s in parts.path.split("/") if s]

    def after(key):
        return seg[seg.index(key) + 1] if key in seg and seg.index(key) + 1 < len(seg) else None

    version_id = after("versions")
    if not version_id:
        raise SystemExit(f"no /versions/<id> segment in URL: {target}")
    base = f"{parts.scheme}://{parts.netloc}" if parts.netloc else None
    return base, after("projects"), version_id


def normalize_base(value):
    """Add a default https:// scheme to a bare hostname.

    FINITE_STATE_DOMAIN is documented repo-wide as a bare FQDN (e.g.
    `acme.finitestate.io`, shared/api-clients/README.md), not a URL. Without this,
    urllib.request.urlopen() raises a raw ValueError on it in get() instead of the
    script's own SystemExit error contract.
    """
    if not value:
        return value
    return value if "://" in value else f"https://{value}"


def retry_after_seconds(header):
    """Seconds to wait from a Retry-After header, clamped.

    The header is legally either a delay in seconds OR an HTTP-date (RFC 9110), and
    a bare int() on the date form raises ValueError — which would crash on exactly
    the recoverable 503 the retry exists to handle.
    """
    if not header:
        return RETRY_WAIT_DEFAULT
    raw = header.strip()
    try:
        wait = int(raw)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return RETRY_WAIT_DEFAULT
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        wait = int((when - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    return max(1, min(wait, RETRY_WAIT_MAX))


def get(base, path, token, params=None, retries=3):
    """GET JSON. Retries transient errors (429/500/502/503/504) per Retry-After.

    Every branch below either returns or raises, on the first attempt or the
    last — there's no path where the loop just runs out.
    """
    url = f"{base}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"X-Authorization": token, "Accept": "application/json"})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            # 503 is the SBOM export's concurrency cap; the rest are ordinary
            # transient gateway/server errors. Any is worth one more try.
            if e.code in RETRYABLE_STATUS and attempt < retries:
                wait = retry_after_seconds(e.headers.get("Retry-After"))
                print(f"  HTTP {e.code} on {path}, retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            body = e.read().decode("utf-8", "replace")[:400]
            raise SystemExit(f"HTTP {e.code} on {path}: {body}")
        except urllib.error.URLError as e:
            raise SystemExit(f"cannot reach {base}: {e.reason}")
        except json.JSONDecodeError as e:
            raise SystemExit(f"{path} returned a non-JSON response ({e}); check the base URL")


def pick_one(rows, kind, wanted, name_keys):
    """Exactly-one match or fail loud — never silently export the wrong version."""
    if not rows:
        raise SystemExit(f"no {kind} named {wanted!r}")
    if len(rows) > 1:
        names = ", ".join(str(r.get("id")) for r in rows[:5])
        raise SystemExit(f"{len(rows)} {kind}s match {wanted!r} (ids: {names}). Use the id or a URL.")
    row = rows[0]
    label = next((row[k] for k in name_keys if row.get(k)), "?")
    print(f"  {kind}: {label} ({row['id']})", file=sys.stderr)
    return row["id"]


def get_all_pages(base, path, token, page_size=1000, extra_params=None):
    """GET every page of a list endpoint via limit/offset.

    Neither /projects nor /projects/{id}/versions can be trusted for server-side
    name matching here: /versions has no documented `filter` param at all, and
    relying on RSQL's `==` for /projects would silently miss a name that differs
    only in case (fs-report's own resolve_project avoids the filter for the same
    reason). So both are fetched in full and matched client-side.

    A page is expected to be a JSON array (that's this API's documented list
    shape); a differently-shaped response fails loud here instead of `extend()`
    silently iterating something unexpected.
    """
    rows, offset = [], 0
    while True:
        params = {"limit": page_size, "offset": offset, **(extra_params or {})}
        page = get(base, path, token, params)
        if not isinstance(page, list):
            raise SystemExit(f"{path} returned {type(page).__name__}, expected a list")
        if not page:
            break
        rows.extend(page)
        if len(page) < page_size:
            break
        offset += page_size
    return rows


def match_by_name(rows, wanted, *fields):
    """Case-insensitive exact match on the first present field in `fields`."""
    target = wanted.lower()
    return [r for r in rows if str(next((r.get(f) for f in fields if r.get(f)), "")).lower() == target]


def resolve_by_name(base, token, project, version):
    """project name + version name -> version id, matched case-insensitively client-side.

    `archived=false` and `excluded=false` are sent explicitly on the /projects
    fetch, mirroring fs-report/api_client.py:resolve_project against this same
    endpoint, so a deleted or excluded project of the same name can't produce a
    false "2 projects match" ambiguity or get silently selected.

    /projects/{id}/versions has no documented params at all beyond the path's
    projectId (OpenAPI spec) — no archived/excluded equivalent to carry over —
    so only pagination params go to that call.
    """
    projects = get_all_pages(base, f"{API}/projects", token,
                              extra_params={"archived": "false", "excluded": "false"})
    project_id = pick_one(match_by_name(projects, project, "name"), "project", project, ("name",))

    versions = get_all_pages(base, f"{API}/projects/{project_id}/versions", token)
    return pick_one(match_by_name(versions, version, "version", "name"), "version", version, ("version", "name"))


def build_vdr(base, token, version_id, triaged_only):
    """One export call, then drop components[]/dependencies[] (legacy VDR-only shape).

    Returns (doc, total_before_filter).
    """
    # includeVex is the documented-by-usage param fs-report relies on for
    # vulnerability data (api_client.py:fetch_sbom); an additional
    # includeVulnerabilities flag isn't used anywhere else in this repo and
    # isn't in the OpenAPI spec, so it's dropped rather than sent unverified.
    doc = get(base, f"{API}/sboms/cyclonedx/{version_id}", token, {"includeVex": "true"})
    doc.pop("components", None)
    doc.pop("dependencies", None)
    vulns = doc.get("vulnerabilities") or []
    total = len(vulns)
    # Triaged = carries an analysis block. Includes auto-triage by design; strictly
    # human-triaged would need a per-finding /activity call (N+1).
    doc["vulnerabilities"] = [v for v in vulns if v.get(TRIAGED)] if triaged_only else vulns
    return doc, total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="platform URL or version ID (UUID or int)")
    ap.add_argument("--project", help="project name (with --version)")
    ap.add_argument("--version", help="version name (with --project)")
    ap.add_argument("--triaged-only", action="store_true",
                    help="keep only triaged vulnerabilities (any VEX state, incl. auto-triage)")
    ap.add_argument("--base",
                    help="API base, e.g. https://app.finitestate.io "
                         "(overrides a URL's host, FS_BASE, and FINITE_STATE_DOMAIN)")
    ap.add_argument("--token", help="API token (prefer FS_TOKEN; an argument is visible in ps and shell history)")
    out = ap.add_mutually_exclusive_group()
    out.add_argument("-o", "--output", help="write to this path instead of the auto-generated filename")
    out.add_argument("--stdout", action="store_true", help="write the document to stdout instead of a file")
    ap.add_argument("--self-test", action="store_true", help="run built-in checks and exit")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.target and (args.project or args.version):
        raise SystemExit("--project/--version cannot be combined with a URL/ID target")

    # Explicit --token wins; FINITE_STATE_AUTH_TOKEN is the legacy (NGP-era) env name.
    token = args.token or os.environ.get("FS_TOKEN") or os.environ.get("FINITE_STATE_AUTH_TOKEN")
    if not token:
        raise SystemExit("set FS_TOKEN (or FINITE_STATE_AUTH_TOKEN), or pass --token")

    # Base URL precedence: an explicitly typed --base wins, then the host embedded in
    # a platform URL, then FS_BASE / FINITE_STATE_DOMAIN (the repo-wide bare-FQDN
    # env var; shared/api-clients/README.md). The URL's own host MUST outrank the
    # env vars: these are multi-tenant hostnames (app./acme.finitestate.io), and
    # an ambient value left over from another tenant would otherwise silently
    # redirect a pasted link at the wrong host.
    env_base_raw = os.environ.get("FS_BASE") or os.environ.get("FINITE_STATE_DOMAIN")
    env_base = normalize_base(env_base_raw)
    url_base, version_id = None, None
    if args.target:
        url_base, _project_id, version_id = parse_target(args.target)
    elif not (args.project and args.version):
        raise SystemExit("pass a URL/ID, or --project NAME --version NAME")

    base = normalize_base(args.base) or url_base or env_base
    if not base:
        raise SystemExit("no API base: pass --base, set FS_BASE / FINITE_STATE_DOMAIN, or use a full URL")
    if url_base and env_base and not args.base and url_base != env_base:
        print(f"  using {url_base} from the URL (ignoring FS_BASE/FINITE_STATE_DOMAIN={env_base_raw})",
              file=sys.stderr)
    base = base.rstrip("/")

    if not version_id:
        version_id = resolve_by_name(base, token, args.project, args.version)

    doc, total = build_vdr(base, token, version_id, args.triaged_only)

    # Fail loud on an empty VDR — an empty vulnerabilities[] is a valid CycloneDX
    # document, which makes it exactly the kind of thing that ships to a customer
    # unnoticed. Write nothing, exit nonzero.
    n = len(doc.get("vulnerabilities") or [])
    if n == 0:
        if args.triaged_only and total:
            raise SystemExit(f"no triaged vulnerabilities ({total} untriaged) for version {version_id}")
        raise SystemExit(f"no vulnerabilities for version {version_id}")
    print(f"  {n} vulnerabilities" + (f" (of {total})" if args.triaged_only else ""), file=sys.stderr)

    out = json.dumps(doc, indent=2)
    if args.stdout:
        print(out)
        return
    # Default: a file. Explicit -o wins; otherwise derive the name from the document.
    path = args.output or default_filename(doc, version_id)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    except OSError as e:
        raise SystemExit(f"cannot write {path}: {e}")
    print(f"  wrote {path}", file=sys.stderr)


def self_test():
    # URL parsing: hostname must not matter, path segments must.
    for host in ("app.finitestate.io", "acme.finitestate.io"):
        b, p, v = parse_target(
            f"https://{host}/projects/5657a3c5-5727-42e5-842a-13c21f383e11"
            f"/versions/4c76b60b-1646-4fa5-b279-3902763b891a/overview"
        )
        assert b == f"https://{host}", b
        assert p == "5657a3c5-5727-42e5-842a-13c21f383e11", p
        assert v == "4c76b60b-1646-4fa5-b279-3902763b891a", v

    # Bare UUID, and URL with no trailing path segment.
    assert parse_target("4c76b60b-1646-4fa5-b279-3902763b891a") == (None, None, "4c76b60b-1646-4fa5-b279-3902763b891a")
    assert parse_target("https://x.io/projects/a/versions/b")[2] == "b"

    # Bare signed int64 IDs are also valid on this platform (some tenants issue
    # these instead of UUIDs), not just UUID-shaped strings.
    assert parse_target("3456789012345678913") == (None, None, "3456789012345678913")
    assert parse_target("-42") == (None, None, "-42")

    # Missing /versions must fail, not guess.
    try:
        parse_target("https://app.finitestate.io/projects/abc/overview")
        raise AssertionError("expected SystemExit for missing /versions")
    except SystemExit:
        pass

    # normalize_base: bare FQDN (FINITE_STATE_DOMAIN's documented form) gets a
    # scheme; anything already a URL passes through unchanged.
    assert normalize_base("acme.finitestate.io") == "https://acme.finitestate.io"
    assert normalize_base("https://acme.finitestate.io") == "https://acme.finitestate.io"
    assert normalize_base(None) is None

    # match_by_name (resolve_by_name's client-side filter): case-insensitive,
    # falls back to the second field name when the first is absent.
    versions = [{"id": "v1", "version": "1.2.3"}, {"id": "v2", "name": "Legacy Build"}]
    assert [v["id"] for v in match_by_name(versions, "1.2.3", "version", "name")] == ["v1"]
    assert [v["id"] for v in match_by_name(versions, "legacy build", "version", "name")] == ["v2"]
    assert match_by_name(versions, "no such version", "version", "name") == []

    # Triaged filter keeps only findings carrying an analysis block.
    doc = {
        "components": [{"name": "x"}],
        "dependencies": [{"ref": "x"}],
        "vulnerabilities": [
            {"id": "CVE-1", "analysis": {"state": "not_affected"}},
            {"id": "CVE-2"},
        ],
    }
    doc.pop("components"), doc.pop("dependencies")
    kept = [v for v in doc["vulnerabilities"] if v.get(TRIAGED)]
    assert [v["id"] for v in kept] == ["CVE-1"], kept

    # Default filename: names come from metadata.component, unsafe chars collapsed.
    named = {"metadata": {"component": {"name": "ACME Router / Pro", "version": "1.2.3"}}}
    fn = default_filename(named, "4c76b60b-1646-4fa5-b279-3902763b891a")
    assert fn.startswith("ACME_Router_Pro_1.2.3_4c76b60b_"), fn
    assert fn.endswith(EXT), fn
    assert "/" not in fn, fn

    # No metadata.component -> still a usable, traceable name.
    fb = default_filename({}, "4c76b60b-1646-4fa5-b279-3902763b891a")
    assert fb.startswith("project_version_4c76b60b_"), fb
    assert fb.endswith(EXT), fb

    # Long build strings: capped, and the distinguishing tail survives.
    proj = ("BP_ACME1234_R03_BA04_r001_branch_ACMEPLAT_rl_AP_ACME1234_4290_Android14.0"
            "_BA04_r001_branch_ACMEPLAT_rl_MODEM_ACME5678_ACME9012_ACME1234_R02")
    ver = "BA02_r010_branch_ACMEPLAT_rl_ACMEPLATNADAR13A02_BA04BP01ABM03_AP14.0.0.01.012_V01"
    long_fn = default_filename(
        {"metadata": {"component": {"name": proj, "version": ver}}},
        "4c76b60b-1646-4fa5-b279-3902763b891a",
    )
    assert len(long_fn) <= 130, (len(long_fn), long_fn)
    assert long_fn.startswith("BP_ACME1234"), long_fn          # head kept: recognizable
    assert "AP14.0.0.01.012_V01" in long_fn, long_fn          # tail kept: identifies build
    assert ELIDE in long_fn, long_fn

    # Head-sharing siblings must not collide (tail + version id disambiguate).
    a = default_filename({"metadata": {"component": {"name": proj, "version": ver}}}, "aaaaaaaa-1")
    b = default_filename({"metadata": {"component": {"name": proj, "version": ver.replace("V01", "V02")}}},
                         "bbbbbbbb-2")
    assert a != b, (a, b)


    # Retry-After: seconds, HTTP-date, junk, and absent all yield a sane bounded wait.
    assert retry_after_seconds("12") == 12
    assert retry_after_seconds("  7 ") == 7
    assert retry_after_seconds(None) == RETRY_WAIT_DEFAULT
    assert retry_after_seconds("not-a-number") == RETRY_WAIT_DEFAULT
    assert retry_after_seconds("99999") == RETRY_WAIT_MAX          # clamped
    assert retry_after_seconds("-5") == 1                          # floor
    future = email.utils.format_datetime(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=45)
    )
    assert 40 <= retry_after_seconds(future) <= 46, retry_after_seconds(future)
    # A date in the past must not produce a negative sleep.
    past = email.utils.format_datetime(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=45)
    )
    assert retry_after_seconds(past) == 1

    # shorten() respects its budget exactly and is a no-op under it.
    assert shorten("short", 40) == "short"
    assert len(shorten("x" * 200, 40)) == 40
    # A budget too tight for head+ELIDE+tail must not go negative-index-weird.
    assert shorten("x" * 200, budget=5, tail=20) == "~xxxx"
    assert shorten("x" * 200, budget=0) == ""

    # get()/get_all_pages(): mock urlopen so the retry, error, and pagination
    # paths are exercised without a real network call.
    import io
    from unittest import mock

    def http_error(code, headers=None, body=b""):
        return urllib.error.HTTPError("https://x.io/path", code, "err", headers or {}, io.BytesIO(body))

    # A retryable status is retried and the eventual success is returned.
    calls = {"n": 0}

    def flaky_then_ok(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http_error(503, {"Retry-After": "0"})
        return io.BytesIO(b'{"ok": true}')

    with mock.patch("urllib.request.urlopen", side_effect=flaky_then_ok), mock.patch("time.sleep"):
        assert get("https://x.io", "/path", "tok") == {"ok": True}
    assert calls["n"] == 2, calls

    # A non-retryable status raises SystemExit instead of retrying.
    def raise_404(req, timeout=None):
        raise http_error(404, body=b"missing")

    with mock.patch("urllib.request.urlopen", side_effect=raise_404):
        try:
            get("https://x.io", "/path", "tok")
            raise AssertionError("expected SystemExit for a 404")
        except SystemExit as e:
            assert "404" in str(e), e

    # Exhausting all retries on a persistent transient error still fails loud.
    def raise_503(req, timeout=None):
        raise http_error(503)

    with mock.patch("urllib.request.urlopen", side_effect=raise_503), mock.patch("time.sleep"):
        try:
            get("https://x.io", "/path", "tok", retries=1)
            raise AssertionError("expected SystemExit after exhausting retries")
        except SystemExit:
            pass

    # get_all_pages(): walks limit/offset pages until a short page ends it.
    pages = [[{"id": 1}, {"id": 2}], [{"id": 3}]]

    def page_by_page(req, timeout=None):
        return io.BytesIO(json.dumps(pages.pop(0)).encode())

    with mock.patch("urllib.request.urlopen", side_effect=page_by_page):
        rows = get_all_pages("https://x.io", "/path", "tok", page_size=2)
    assert [r["id"] for r in rows] == [1, 2, 3], rows

    # get_all_pages(): a non-list page shape fails loud rather than corrupting the result.
    def wrapped_page(req, timeout=None):
        return io.BytesIO(b'{"items": []}')

    with mock.patch("urllib.request.urlopen", side_effect=wrapped_page):
        try:
            get_all_pages("https://x.io", "/path", "tok")
            raise AssertionError("expected SystemExit for a non-list page")
        except SystemExit:
            pass

    # pick_one(): exactly one match succeeds; zero or multiple fail loud.
    assert pick_one([{"id": "v1", "name": "A"}], "thing", "A", ("name",)) == "v1"
    try:
        pick_one([], "thing", "X", ("name",))
        raise AssertionError("expected SystemExit for no match")
    except SystemExit:
        pass
    try:
        pick_one([{"id": "1"}, {"id": "2"}], "thing", "X", ("name",))
        raise AssertionError("expected SystemExit for an ambiguous match")
    except SystemExit:
        pass

    # resolve_by_name(): project lookup, then version lookup within it.
    def fake_lookup(req, timeout=None):
        if "/versions" in req.full_url:
            return io.BytesIO(json.dumps([{"id": "v42", "version": "2.0"}]).encode())
        return io.BytesIO(json.dumps([{"id": "p7", "name": "Acme"}]).encode())

    with mock.patch("urllib.request.urlopen", side_effect=fake_lookup):
        assert resolve_by_name("https://x.io", "tok", "acme", "2.0") == "v42"

    # build_vdr(): strips components/dependencies, reports the pre-filter total,
    # and --triaged-only keeps only findings carrying an analysis block.
    def fake_sbom(req, timeout=None):
        return io.BytesIO(json.dumps({
            "metadata": {"component": {"name": "p", "version": "v"}},
            "components": [{"name": "c"}],
            "dependencies": [{"ref": "c"}],
            "vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "x"}}, {"id": "CVE-2"}],
        }).encode())

    with mock.patch("urllib.request.urlopen", side_effect=fake_sbom):
        doc, total = build_vdr("https://x.io", "tok", "vid", triaged_only=False)
    assert "components" not in doc and "dependencies" not in doc, doc
    assert total == 2, total
    assert [v["id"] for v in doc["vulnerabilities"]] == ["CVE-1", "CVE-2"], doc

    with mock.patch("urllib.request.urlopen", side_effect=fake_sbom):
        doc, total = build_vdr("https://x.io", "tok", "vid", triaged_only=True)
    assert total == 2, total
    assert [v["id"] for v in doc["vulnerabilities"]] == ["CVE-1"], doc

    # main(): a positional target combined with --project/--version is rejected
    # before any network call, regardless of which name flag(s) are present.
    for extra in (["--project", "X"], ["--version", "Y"], ["--project", "X", "--version", "Y"]):
        with mock.patch("sys.argv", ["fs_vex_export.py", "4c76b60b-1646-4fa5-b279-3902763b891a", *extra]):
            try:
                main()
                raise AssertionError(f"expected SystemExit for target + {extra}")
            except SystemExit as e:
                assert "cannot be combined" in str(e), e

    print("self-test OK")


if __name__ == "__main__":
    main()
