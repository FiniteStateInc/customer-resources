"""
Pandas transform for the CVE Component Evidence report.

For a single project version, lists components that have at least one
associated CVE with two key columns:

* CVEs — distinct CVE IDs associated with each component, comma-joined.
* Evidence File Paths — union of firmware file paths where the component
  was detected, newline-joined.

Components with no associated CVEs are excluded — this report is for
triage, and CVE-free components don't need it. Components of type ``file``
(raw scanner artifacts) and components with ``findings == 0`` are also
excluded before the per-component fan-out.

CVE data comes from ``/public/v0/findings`` queried *per component* with
``filter=projectVersion==<pvid>;affected==<componentId>&type=cve`` — the
same canonical join the platform UI uses, so no name+version guessing.

Evidence comes from the platform's match-evidence endpoint, which differs
by back-end (both return ``related_file_paths`` — the union of firmware
file paths where the component was detected):

* Helix → ``/public/v0/components/{pvid}/{cid}/evidence``
* Alloy/legacy → ``/fs/v1/projects/versions/{pvid}/components/{cid}/evidence``

Each route 404s on the *other* back-end, so ``_fetch_evidence_for_component``
tries one and falls back to the other (``_evidence_endpoints`` orders the
attempts by id shape purely to avoid a wasted first call). The fallback —
not the id shape — is what keeps the column populated on both back-ends,
since an Alloy tenant may also use UUID ids.

Findings are fetched via ``APIClient.fetch_all_with_resume``, so the
SQLite cache (--cache-ttl) covers them across runs. Evidence is fetched
via ``APIClient.fetch_data``, which only uses the in-memory per-run cache —
--cache-ttl does NOT persist evidence across runs, so every run re-issues
the full per-component evidence fan-out.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, cast

import pandas as pd

from fs_report.models import Config, QueryConfig, QueryParams
from fs_report.transforms.pandas.component_list import (
    SOURCE_LABELS,
    flatten_component_data,
)

logger = logging.getLogger(__name__)


_OUTPUT_COLUMNS = [
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
    "Source",
    "Status",
    "CVEs",
    "Evidence File Paths",
]

# Delimiter for the CVEs column. ", " keeps a many-CVE component on one
# row in spreadsheets (newlines would force one row per CVE in Excel/Sheets
# with text-wrap, which made the report unmanageably tall).
_CVE_DELIM = ", "

# Map platform copyleft classifications to the strings used in the
# customer-facing CSV export (e.g. "Copyleft-Strong", "Permissive").
_COPYLEFT_DISPLAY: dict[str, str] = {
    "STRONG_COPYLEFT": "Copyleft-Strong",
    "WEAK_COPYLEFT": "Copyleft-Weak",
    "PERMISSIVE": "Permissive",
}

# Max parallel evidence requests. The Helix match-evidence endpoint isn't
# hardened for bursts — testing shows 10 workers reliably trips 500s on large
# projects.  Default to 5; override with FS_REPORT_EVIDENCE_WORKERS=N for
# fast tokens, or =1 for sequential when the server is unhappy.
_DEFAULT_EVIDENCE_WORKERS = 5


def _is_uuid(value: str) -> bool:
    """True when ``value`` parses as a UUID."""
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _evidence_endpoints(pvid: str, component_id: str) -> list[str]:
    """Return the match-evidence endpoints to try, in preference order.

    Both back-ends expose match evidence at different routes, and both return
    ``{related_file_paths: [...]}``:

    * Helix    → ``/public/v0/components/{pvid}/{cid}/evidence``
    * Alloy    → ``/fs/v1/projects/versions/{pvid}/components/{cid}/evidence``

    Each route 404s on the *other* back-end, so we try one then fall back to
    the other — the column stays populated on both. Id shape (UUID→Helix,
    numeric→Alloy) only orders the attempts to avoid a wasted first call in
    the common case; it is NOT a hard switch, because Alloy instances can also
    use UUID ids (a UUID-id Alloy tenant would 404 on the Helix route and must
    fall back to /fs/v1). The fallback is what makes both back-ends work.
    """
    helix = f"/public/v0/components/{pvid}/{component_id}/evidence"
    alloy = f"/fs/v1/projects/versions/{pvid}/components/{component_id}/evidence"
    return [helix, alloy] if _is_uuid(pvid) else [alloy, helix]


def _evidence_workers() -> int:
    raw = os.environ.get("FS_REPORT_EVIDENCE_WORKERS")
    if not raw:
        return _DEFAULT_EVIDENCE_WORKERS
    try:
        n = int(raw)
        return max(1, n)
    except ValueError:
        logger.warning(
            "Invalid FS_REPORT_EVIDENCE_WORKERS=%r — using default %d",
            raw,
            _DEFAULT_EVIDENCE_WORKERS,
        )
        return _DEFAULT_EVIDENCE_WORKERS


# Per-call HTTP timeouts live on the api_client/httpx layer (see
# APIClient.fetch_data — 60s GET timeout, plus the client-level 30s
# Timeout). We don't pass timeout= to fut.result() because as_completed
# only yields *finished* futures, so a fut.result() timeout would never
# fire and would just be misleading dead code.


def cve_component_evidence_pandas_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config | None = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the per-component evidence report for one project version."""
    config = config or (additional_data.get("config") if additional_data else None)
    api_client = additional_data.get("api_client") if additional_data else None

    if config is None:
        raise ValueError(
            "component_evidence requires a Config (none passed to transform)"
        )
    if api_client is None:
        raise ValueError(
            "component_evidence requires api_client in additional_data. "
            "The report engine injects this for opted-in recipes."
        )
    pvid = getattr(config, "version_filter", None)

    if isinstance(data, pd.DataFrame):
        df = data.copy()
    elif not data:
        df = pd.DataFrame()
    else:
        df = pd.DataFrame(data)

    if df.empty:
        # An empty fetch is just an empty report — nothing to scope, whether or
        # not a --version was supplied. (A project-only launch must never crash
        # here; pre-release crash report 2026-06-14.)
        logger.warning("No component data — returning empty report")
        return {
            "main": pd.DataFrame(columns=_OUTPUT_COLUMNS),
            "evidence_summary": _empty_summary(),
        }

    df = flatten_component_data(df)

    # Resolve the project version. Prefer an explicit --version; otherwise fall
    # back to the engine-resolved current version carried in the fetched
    # components. This is the natural project-only + --current-version-only path
    # (web launcher / CLI without --version): the engine has already scoped the
    # fetch to one version, so requiring --version a second time just crashed a
    # valid launch (pre-release crash report 2026-06-14).
    if not pvid:
        resolved_versions = []
        if "projectVersion.id" in df.columns:
            # flatten_component_data fills a missing version id with the literal
            # "Unknown" sentinel — exclude it; a real scope can't be inferred
            # from it (would fetch findings with projectVersion==Unknown).
            resolved_versions = sorted(
                v
                for v in df["projectVersion.id"].dropna().astype(str).unique()
                if v and v != "Unknown"
            )
        if len(resolved_versions) == 1:
            pvid = resolved_versions[0]
            logger.info(
                "No --version provided; using current version %s resolved from "
                "the fetched components.",
                pvid,
            )
        else:
            raise ValueError(
                "component_evidence requires --version <project_version_id> "
                "(or --version <version_name> with --project <project_name_or_id>). "
                "This report is scoped to a single project version"
                + (
                    f"; the fetched components span {len(resolved_versions)} "
                    "versions, so a version must be specified."
                    if len(resolved_versions) > 1
                    else " and one could not be inferred from the fetched "
                    "components."
                )
            )
    pvid = str(pvid)
    if "projectVersion.id" in df.columns:
        df = df[df["projectVersion.id"].astype(str) == pvid]
    if df.empty:
        logger.warning(
            "No components found for project_version_id=%s. "
            "Check that --version refers to a version of --project.",
            pvid,
        )
        return {
            "main": pd.DataFrame(columns=_OUTPUT_COLUMNS),
            "evidence_summary": _empty_summary(),
        }

    # Components of type "file" are raw scanner artifacts, not real
    # components — the evidence endpoint returns nothing for them, so they
    # add noise and 500-prone calls to the fan-out.  Drop them.
    if "type" in df.columns:
        before = len(df)
        df = df[df["type"].astype(str).str.lower() != "file"]
        dropped = before - len(df)
        if dropped:
            logger.info(
                "Dropped %d component(s) of type=file (no match evidence available)",
                dropped,
            )
    # Pre-filter: components with zero findings of ANY kind can't have CVEs.
    # Saves an entire round of findings-API calls for the inevitable long
    # tail of CVE-free components.
    if "findings" in df.columns:
        before = len(df)
        findings_count = pd.to_numeric(df["findings"], errors="coerce").fillna(0)
        df = df[findings_count > 0]
        skipped = before - len(df)
        if skipped:
            logger.info(
                "Skipping %d component(s) with findings=0 — cannot have CVEs",
                skipped,
            )
    logger.info("Building Component Evidence for %d components", len(df))

    # Fetch CVE findings per component using the same `affected==<cid>`
    # filter the platform UI uses. This is the canonical join — no
    # name+version guessing.
    component_ids = [str(cid) for cid in df["id"].tolist() if cid]
    cves_by_cid, sev_by_cid, findings_fetch_errors = (
        _fetch_findings_per_component_parallel(api_client, pvid, component_ids)
    )

    # Drop components with no CVE findings — this report is for triage,
    # and CVE-free components don't need it.
    before = len(df)
    df = df[df["id"].astype(str).isin(set(cves_by_cid.keys()))]
    logger.info(
        "Kept %d/%d components with at least one CVE (dropped %d)",
        len(df),
        before,
        before - len(df),
    )

    if df.empty:
        logger.warning(
            "No components in this project version have any associated CVEs — "
            "report will be empty."
        )
        # Even on the empty path the findings_fetch_errors count must
        # propagate — otherwise the user can't tell whether the report is
        # empty because nothing has CVEs or because every findings call
        # failed.
        empty_summary = _empty_summary()
        empty_summary["findings_fetch_errors"] = findings_fetch_errors
        empty_summary["summary_df"] = pd.DataFrame(
            [
                {"Metric": "Total components", "Value": 0},
                {
                    "Metric": "Findings fetch errors",
                    "Value": findings_fetch_errors,
                },
            ]
        )
        return {
            "main": pd.DataFrame(columns=_OUTPUT_COLUMNS),
            "evidence_summary": empty_summary,
        }

    surviving_cids = [str(cid) for cid in df["id"].tolist() if cid]
    # Both back-ends serve match evidence (Helix and Alloy use different
    # routes; _evidence_endpoints orders attempts by version-id shape but
    # always falls back), so always fan out.
    evidence_by_component, evidence_fetch_errors = _fetch_evidence_parallel(
        api_client, pvid, surviving_cids
    )

    output_df = _build_output_dataframe(
        df,
        cves_by_cid,
        sev_by_cid,
        evidence_by_component,
    )

    summary = _build_summary(
        output_df,
        evidence_by_component,
        evidence_fetch_errors,
        findings_fetch_errors,
    )
    return {"main": output_df, "evidence_summary": summary}


# ----------------------------------------------------------------------
# Findings (CVE + severity) per component
# ----------------------------------------------------------------------


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _fetch_findings_for_component(
    api_client: Any, pvid: str, component_id: str
) -> list[dict[str, Any]]:
    """Fetch CVE findings for ONE component using the same filter the
    platform UI uses: ``projectVersion==<pvid>;affected==<component_id>``
    plus ``type=cve``. This is the canonical join — no name+version
    guessing required.
    """
    query = QueryConfig(
        endpoint="/public/v0/findings",
        params=QueryParams(
            filter=f"projectVersion=={pvid};affected=={component_id}",
            finding_type="cve",
            limit=1000,
        ),
    )
    result = api_client.fetch_all_with_resume(query, show_progress=False)
    return cast(list[dict[str, Any]], result)


def _fetch_findings_per_component_parallel(
    api_client: Any, pvid: str, component_ids: list[str]
) -> tuple[dict[str, list[str]], dict[str, dict[str, int]], int]:
    """Fan out per-component findings calls.

    Returns ``(cves_by_cid, sev_by_cid, fetch_errors)``. Only components
    that actually return CVE findings are added to the output dicts —
    callers can use ``cid in cves_by_cid`` as the "this component has
    CVEs" check. The error count is surfaced so the caller can show it
    in the report summary; otherwise a 500 on the findings call would
    silently drop a component from the report as if it had no CVEs.
    """
    cves_by_cid: dict[str, list[str]] = {}
    sev_by_cid: dict[str, dict[str, int]] = {}
    if not component_ids:
        return cves_by_cid, sev_by_cid, 0
    workers = _evidence_workers()
    logger.info(
        "Fetching CVE findings for %d components with %d worker(s)",
        len(component_ids),
        workers,
    )
    total_findings = 0
    fetch_errors = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_fetch_findings_for_component, api_client, pvid, cid): cid
            for cid in component_ids
        }
        for fut in as_completed(futures, timeout=None):
            cid = futures[fut]
            try:
                findings = fut.result()
            except Exception as exc:
                fetch_errors += 1
                logger.warning("Findings fetch failed for component %s: %s", cid, exc)
                continue
            cves: set[str] = set()
            sevs = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                for cve in _cve_ids_from_finding(f):
                    cves.add(cve)
                sev = str(f.get("severity") or "").strip().lower()
                if sev in sevs:
                    sevs[sev] += 1
            total_findings += len(findings)
            if cves:
                cves_by_cid[cid] = sorted(cves)
                sev_by_cid[cid] = sevs
    logger.info(
        "Fetched %d CVE findings across %d components "
        "(%d components have CVEs, %d findings-fetch errors)",
        total_findings,
        len(component_ids),
        len(cves_by_cid),
        fetch_errors,
    )
    return cves_by_cid, sev_by_cid, fetch_errors


def _cve_ids_from_finding(finding: dict[str, Any]) -> list[str]:
    """Extract every CVE identifier reachable on a finding record.

    The findings endpoint returns CVE IDs in inconsistent places depending
    on scan source:
    * top-level ``cveId`` / ``cve`` (single string)
    * ``cves`` array of strings or dicts (e.g. ``{cveId, id, name}``)
    * embedded in ``title`` (e.g. "CVE-2024-12345: heap overflow in ...")
    * embedded in ``findingId`` for some legacy records
    """
    candidates: list[str] = []

    cves = finding.get("cves")
    if isinstance(cves, list):
        for c in cves:
            if isinstance(c, dict):
                cve_id = c.get("cveId") or c.get("id") or c.get("name")
            else:
                cve_id = c
            if cve_id:
                candidates.append(str(cve_id))

    for key in ("cveId", "cve", "findingId"):
        val = finding.get(key)
        if isinstance(val, str) and val:
            candidates.append(val)

    # Last resort: scrape CVE-XXXX-NNNN out of title/description.
    for key in ("title", "description"):
        val = finding.get(key)
        if isinstance(val, str) and val:
            candidates.extend(_CVE_RE.findall(val))

    # Only return well-formed CVE IDs, normalised to uppercase.
    return [
        m.group(0).upper() for s in candidates if (m := _CVE_RE.fullmatch(s.strip()))
    ]


# ----------------------------------------------------------------------
# Evidence (file paths) per component
# ----------------------------------------------------------------------


# Archive/package extensions the unpacker descends into. A path that continues
# *past* one of these (``…/foo.jar/…``) is an entry unpacked from that package,
# not a real filesystem path — so we collapse it to the package itself.
# ``.tar.gz`` etc. resolve via the trailing ``.gz`` boundary.
#
# Deliberately EXCLUDES firmware filesystem images (squashfs, cramfs, ubifs,
# jffs2, ext*, iso, img, cpio): those unpack to the device's *root filesystem*,
# where inner paths are the real, meaningful file locations (e.g.
# ``/rootfs.img/usr/lib/libc.so`` is where libc actually lives) — collapsing
# them would hide exactly the evidence a firmware analyst wants. Only true
# archive/package containers, whose internal members are all "the package"
# for match-evidence purposes, belong here.
_ARCHIVE_EXTS: tuple[str, ...] = (
    ".jar",
    ".war",
    ".ear",
    ".aar",
    ".zip",
    ".apk",
    ".jmod",
    ".nupkg",
    ".whl",
    ".egg",
    ".gem",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".rpm",
    ".deb",
    ".ipk",
    ".cab",
)


def _collapse_to_top_archive(path: str) -> str:
    """Collapse a path that descends into an archive to the top-level archive.

    Firmware unpacking recurses into nested archives, exploding a single
    component into thousands of per-entry paths like
    ``/BOOT-INF/lib/app.jar/META-INF/.../inner.jar/META-INF/BC2048KE.DSA``.
    Rendering every entry makes the report unusable, so we truncate at the
    FIRST (outermost) archive boundary — here ``/BOOT-INF/lib/app.jar``.

    Boundaries are matched per path *segment*: a segment is a boundary only
    when it ends with a known archive extension AND has segments after it (it
    was unpacked into). This is exact — a directory that merely contains dots
    (``com.thoughtworks.xstream``) or ends in a look-alike (``myjaring``) is
    never a boundary, and mid-segment matches can't misfire. A path with no
    boundary (loose file, or a bare archive with nothing listed after it) is
    returned unchanged. ``.tar.gz`` resolves via its trailing ``.gz`` segment.
    """
    segments = path.split("/")
    for i, seg in enumerate(segments[:-1]):  # last segment can't be a boundary
        low = seg.lower()
        if any(low.endswith(ext) for ext in _ARCHIVE_EXTS):
            return "/".join(segments[: i + 1])
    return path


def _fetch_evidence_for_component(
    api_client: Any, pvid: str, component_id: str
) -> list[str]:
    """Return the deduplicated list of file paths for one component.

    Tries each candidate endpoint in order (see ``_evidence_endpoints``),
    falling back to the next when one fails — the wrong-back-end route 404s,
    so the fallback is what keeps evidence working on both Helix and Alloy
    regardless of project-version-id shape. A successful call (even one with
    an empty ``related_file_paths``) wins immediately; if every endpoint
    fails, the last error propagates so the caller counts it as a fetch error
    rather than silently reporting no evidence.
    """
    endpoints = _evidence_endpoints(pvid, component_id)
    last_exc: Exception | None = None
    for endpoint in endpoints:
        query = QueryConfig(endpoint=endpoint, params=QueryParams())
        try:
            response = api_client.fetch_data(query)
        except Exception as exc:  # 404 on the wrong back-end, or a real error
            last_exc = exc
            continue
        return _paths_from_evidence_response(response)
    if last_exc is not None:
        raise last_exc
    return []


def _paths_from_evidence_response(response: Any) -> list[str]:
    """Extract, collapse, and dedupe file paths from an evidence response."""
    # fetch_data wraps a single dict in a one-element list.
    if not response:
        return []
    record = response[0] if isinstance(response, list) else response
    if not isinstance(record, dict):
        return []
    paths = record.get("related_file_paths")
    if not isinstance(paths, list):
        return []
    # Collapse archive-internal entries to their top-level archive, preserve
    # API order, and dedupe (the collapse makes many entries identical).
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if not isinstance(p, str):
            continue
        collapsed = _collapse_to_top_archive(p)
        if collapsed not in seen:
            seen.add(collapsed)
            out.append(collapsed)
    return out


def _fetch_evidence_parallel(
    api_client: Any, pvid: str, component_ids: list[str]
) -> tuple[dict[str, list[str]], int]:
    """Fan out evidence calls; return (paths_by_cid, error_count)."""
    results: dict[str, list[str]] = {}
    errors = 0
    if not component_ids:
        return results, 0
    workers = _evidence_workers()
    logger.info(
        "Fetching evidence for %d components with %d worker(s)",
        len(component_ids),
        workers,
    )
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_fetch_evidence_for_component, api_client, pvid, cid): cid
            for cid in component_ids
        }
        for fut in as_completed(futures, timeout=None):
            cid = futures[fut]
            try:
                results[cid] = fut.result()
            except Exception as exc:
                errors += 1
                logger.warning("Evidence fetch failed for component %s: %s", cid, exc)
                results[cid] = []
    return results, errors


# ----------------------------------------------------------------------
# Column shaping
# ----------------------------------------------------------------------


def _source_label(sources: Any) -> str:
    if not isinstance(sources, list):
        return ""
    labels: list[str] = []
    for s in sources:
        label = SOURCE_LABELS.get(s, s)
        if label and label not in labels:
            labels.append(label)
    return ", ".join(labels)


def _licenses_names(row: pd.Series) -> str:
    for field in ("concludedLicenses", "declaredLicenses"):
        val = row.get(field)
        if isinstance(val, str) and val:
            return val
        if isinstance(val, list) and val:
            # license arrays sometimes hold dicts with 'spdx' or 'license'
            parts: list[str] = []
            for entry in val:
                if isinstance(entry, dict):
                    parts.append(str(entry.get("spdx") or entry.get("license") or ""))
                elif entry:
                    parts.append(str(entry))
            joined = ", ".join(p for p in parts if p)
            if joined:
                return joined
    return ""


def _licenses_types(row: pd.Series) -> str:
    """Map the best-available copyleftFamily to the platform's display string."""
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        details = row.get(field)
        if not isinstance(details, list):
            continue
        for ld in details:
            if not isinstance(ld, dict):
                continue
            cf = ld.get("copyleftFamily")
            if cf:
                return _COPYLEFT_DISPLAY.get(str(cf), str(cf))
    return ""


def _build_output_dataframe(
    df: pd.DataFrame,
    cves_by_cid: dict[str, list[str]],
    sev_by_cid: dict[str, dict[str, int]],
    evidence_by_component: dict[str, list[str]],
) -> pd.DataFrame:
    def _str_col(name: str) -> Any:
        if name in df.columns:
            return df[name].fillna("")
        return ""

    out = pd.DataFrame(index=df.index)
    out["Name"] = _str_col("name")
    out["Version"] = _str_col("version")
    violations = pd.to_numeric(
        df["violations"] if "violations" in df.columns else 0, errors="coerce"
    )
    warnings_ = pd.to_numeric(
        df["warnings"] if "warnings" in df.columns else 0, errors="coerce"
    )
    out["policy - violations"] = (
        violations.fillna(0).astype(int)
        if isinstance(violations, pd.Series)
        else int(violations or 0)
    )
    out["policy - warnings"] = (
        warnings_.fillna(0).astype(int)
        if isinstance(warnings_, pd.Series)
        else int(warnings_ or 0)
    )

    cid_series: list[str] = [str(x) for x in df["id"]]

    def _sev(cid: str, sev: str) -> int:
        return int(sev_by_cid.get(cid, {}).get(sev, 0))

    out["Findings - critical"] = [_sev(c, "critical") for c in cid_series]
    out["Findings - high"] = [_sev(c, "high") for c in cid_series]
    out["Findings - medium"] = [_sev(c, "medium") for c in cid_series]
    out["Findings - low"] = [_sev(c, "low") for c in cid_series]

    out["CDX Type"] = _str_col("type")
    out["Supplier"] = _str_col("supplier")
    out["Licenses - names"] = df.apply(_licenses_names, axis=1)
    out["Licenses - types"] = df.apply(_licenses_types, axis=1)
    out["Source"] = df["source"].apply(_source_label) if "source" in df.columns else ""
    out["Status"] = _str_col("status")

    out["CVEs"] = [_CVE_DELIM.join(cves_by_cid.get(c, [])) for c in cid_series]
    out["Evidence File Paths"] = [
        "\n".join(evidence_by_component.get(c, [])) for c in cid_series
    ]

    out = out[_OUTPUT_COLUMNS]
    out = out.sort_values(["Name", "Version"], kind="stable").reset_index(drop=True)
    return out


# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------


def _build_summary(
    output_df: pd.DataFrame,
    evidence_by_component: dict[str, list[str]],
    evidence_fetch_errors: int,
    findings_fetch_errors: int = 0,
) -> dict[str, Any]:
    total = len(output_df)
    with_paths = sum(1 for paths in evidence_by_component.values() if paths)
    without_paths = total - with_paths
    summary_df = pd.DataFrame(
        [
            {"Metric": "Total components", "Value": total},
            {"Metric": "Components with evidence paths", "Value": with_paths},
            {"Metric": "Components without evidence paths", "Value": without_paths},
            {"Metric": "Findings fetch errors", "Value": findings_fetch_errors},
            {"Metric": "Evidence fetch errors", "Value": evidence_fetch_errors},
        ]
    )
    return {
        "summary_df": summary_df,
        "total_components": total,
        "components_with_evidence": with_paths,
        "components_without_evidence": without_paths,
        # Kept for backwards compatibility with the HTML template:
        "fetch_errors": evidence_fetch_errors,
        "evidence_fetch_errors": evidence_fetch_errors,
        "findings_fetch_errors": findings_fetch_errors,
    }


def _empty_summary() -> dict[str, Any]:
    return {
        "summary_df": pd.DataFrame(columns=["Metric", "Value"]),
        "total_components": 0,
        "components_with_evidence": 0,
        "components_without_evidence": 0,
        "fetch_errors": 0,
        "evidence_fetch_errors": 0,
        "findings_fetch_errors": 0,
    }
