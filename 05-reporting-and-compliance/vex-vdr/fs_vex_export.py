#!/usr/bin/env python3
"""Standalone CycloneDX VEX/VDR export (legacy NGP CYCLONEDX_VDR_ONLY parity).

Target can be a platform URL, a bare version UUID, or --project/--version names:

  fs_vex_export.py https://app.finitestate.io/projects/<pid>/versions/<vid>/overview
  fs_vex_export.py 4c76b60b-1646-4fa5-b279-3902763b891a
  fs_vex_export.py --project "ACME Router" --version "1.2.3"

Auth: export FS_TOKEN=<api token>  (or FINITE_STATE_AUTH_TOKEN, legacy name),
or pass --token. Prefer the env var: an argument is visible to other users via
`ps` and lands in shell history. Sent as X-Authorization. Base URL comes from
the URL when you pass one, else FS_BASE / --base.
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
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

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
    head = budget - len(ELIDE) - tail
    return f"{value[:head]}{ELIDE}{value[-tail:]}"


def default_filename(doc, version_id):
    """<project>_<version>_<versionId8>_<timestamp>.vex.cdx.json

    Project and version names come from the document's own metadata.component, so
    this costs no extra API call. Each is capped at NAME_MAX with middle elision.

    Because two different versions can shorten to the same text, the first 8 chars
    of the version id are always included: that makes every filename unique AND
    traceable back to the platform record it came from. Timestamp is UTC in the
    legacy platform's export format (YYYYMMDDTHHmmss).
    """
    comp = (doc.get("metadata") or {}).get("component") or {}
    project = shorten(slug(comp.get("name"), fallback="project"))
    version = shorten(slug(comp.get("version"), fallback="version"))
    vid = slug(version_id, fallback="novid")[:8]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{project}_{version}_{vid}_{stamp}{EXT}"


def parse_target(target):
    """Return (base, project_id, version_id) from a platform URL, or a bare UUID.

    Hostname is irrelevant (app.finitestate.io, acme.finitestate.io, ...); only
    the /projects/<id>/versions/<id> path segments matter.
    """
    if UUID_RE.match(target):
        return None, None, target
    if "/" not in target:
        raise SystemExit(f"not a URL or UUID: {target!r}")

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


def rsql_quote(value):
    """Escape a value for use inside an RSQL double-quoted string.

    Project and version names are user data and can legitimately contain quotes.
    Unescaped, a `"` terminates the literal early and the rest of the name is
    parsed as filter syntax — at best a confusing "not found", at worst a filter
    that matches something else. The API's RSQL parser is backslash-aware for
    `\"` and `\\` inside a double-quoted value, so this is the escaping it expects.
    """
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


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
    """GET JSON. Retries on 503 (the export endpoint's concurrency cap) per Retry-After."""
    url = f"{base}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"X-Authorization": token, "Accept": "application/json"})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            # 503 = SBOM export concurrency cap, not a rate limit. Honor Retry-After.
            if e.code == 503 and attempt < retries:
                wait = retry_after_seconds(e.headers.get("Retry-After"))
                print(f"  export busy (503), retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            body = e.read().decode("utf-8", "replace")[:400]
            raise SystemExit(f"HTTP {e.code} on {path}: {body}")
        except urllib.error.URLError as e:
            raise SystemExit(f"cannot reach {base}: {e.reason}")
        except json.JSONDecodeError as e:
            raise SystemExit(f"{path} returned a non-JSON response ({e}); check the base URL")
    raise SystemExit(f"gave up on {path} after {retries} retries")


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


def resolve_by_name(base, token, project, version):
    """project name + version name -> version id. Two calls, RSQL-filtered server-side."""
    projects = get(base, f"{API}/projects", token,
                   {"filter": f'name=="{rsql_quote(project)}"', "limit": 50})
    project_id = pick_one(projects, "project", project, ("name",))
    versions = get(base, f"{API}/projects/{project_id}/versions", token,
                   {"filter": f'name=="{rsql_quote(version)}"', "limit": 50})
    return pick_one(versions, "version", version, ("version", "name"))


def build_vdr(base, token, version_id, triaged_only):
    """One export call, then drop components[]/dependencies[] (legacy VDR-only shape).

    Returns (doc, total_before_filter).
    """
    doc = get(base, f"{API}/sboms/cyclonedx/{version_id}", token,
              {"includeVex": "true", "includeVulnerabilities": "true"})
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
    ap.add_argument("target", nargs="?", help="platform URL or version UUID")
    ap.add_argument("--project", help="project name (with --version)")
    ap.add_argument("--version", help="version name (with --project)")
    ap.add_argument("--triaged-only", action="store_true",
                    help="keep only triaged vulnerabilities (any VEX state, incl. auto-triage)")
    ap.add_argument("--base", help="API base, e.g. https://app.finitestate.io (overrides a URL's host and FS_BASE)")
    ap.add_argument("--token", help="API token (prefer FS_TOKEN; an argument is visible in ps and shell history)")
    ap.add_argument("-o", "--output", help="write to this path instead of the auto-generated filename")
    ap.add_argument("--stdout", action="store_true", help="write the document to stdout instead of a file")
    ap.add_argument("--self-test", action="store_true", help="run built-in checks and exit")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    # Explicit --token wins; FINITE_STATE_AUTH_TOKEN is the legacy (NGP-era) env name.
    token = args.token or os.environ.get("FS_TOKEN") or os.environ.get("FINITE_STATE_AUTH_TOKEN")
    if not token:
        raise SystemExit("set FS_TOKEN (or FINITE_STATE_AUTH_TOKEN), or pass --token")

    # Base URL precedence: an explicitly typed --base wins, then the host embedded in
    # a platform URL, then the FS_BASE env var. The URL's own host MUST outrank
    # FS_BASE: these are multi-tenant hostnames (app./acme.finitestate.io), and an
    # ambient FS_BASE left over from another tenant would otherwise silently redirect
    # a pasted link at the wrong host.
    env_base = os.environ.get("FS_BASE")
    url_base, version_id = None, None
    if args.target:
        url_base, _project_id, version_id = parse_target(args.target)
    elif not (args.project and args.version):
        raise SystemExit("pass a URL/UUID, or --project NAME --version NAME")

    base = args.base or url_base or env_base
    if not base:
        raise SystemExit("no API base: pass --base or FS_BASE, or use a full URL")
    if url_base and env_base and not args.base and url_base != env_base:
        print(f"  using {url_base} from the URL (ignoring FS_BASE={env_base})", file=sys.stderr)
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
    with open(path, "w", encoding="utf-8") as f:
        f.write(out + "\n")
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

    # Missing /versions must fail, not guess.
    try:
        parse_target("https://app.finitestate.io/projects/abc/overview")
        raise AssertionError("expected SystemExit for missing /versions")
    except SystemExit:
        pass

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

    # RSQL escaping: a quote in a name must not terminate the literal early.
    assert rsql_quote('plain') == 'plain'
    assert rsql_quote('say "hi"') == 'say \\"hi\\"'
    assert rsql_quote('back\\slash') == 'back\\\\slash'
    # The built filter keeps exactly one unescaped quote at each end.
    built = f'name=="{rsql_quote(chr(34) + "x")}"'
    assert built == 'name=="\\"x"', built

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

    print("self-test OK")


if __name__ == "__main__":
    main()
