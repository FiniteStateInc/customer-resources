"""
Pandas transform for the CRA Compliance morning-queue report.

Pipeline overview (C1, 2026-05-25):
  Stage 0 — Resolve effective config (CLI overrides recipe YAML defaults)
  Stage 1 — Parse --since window (CRA-specific window, not the global period)
  Stage 2 — Fetch C: status-agnostic baseline for snapshot-diff (skipped when
             snapshot_diff=="off")
  Stage 3 — Stage 1 maturity crossings via /cves/updates in the --since window
  Stage 4 — Stage 1 snapshot-diff KEV / token crossings vs prior state
  Stage 5 — Fetch A: above-threshold inventory (RSQL filtered)
  Stage 6 — Fetch B: resolved add-back (chunked at 50 CVE IDs)
  Stage 7 — Merge + section assembly (C1) + persist snapshot state

Section assembly (Phase C1 done): cra_sections.assemble_sections() produces 5
DataFrames keyed by section name. The transform returns {"main": flat_df,
**sections_dict} — "main" preserves backward-compatible CSV/XLSX export,
and the 5 section keys feed the upcoming D2 HTML morning-queue template.

EU Cyber Resilience Act context: manufacturers must notify ENISA within 24 hours
of becoming aware of an actively exploited vulnerability in a product with
digital elements.  KEV inclusion, weaponised / PoC exploit maturity, ransomware
and threat-actor signals are the primary trigger tiers.
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from fs_report.cra import evidence as cra_evidence
from fs_report.cra import sections as cra_sections
from fs_report.cra import snapshot, tiers, window
from fs_report.cra.cisa_kev import get_kev_due_dates
from fs_report.models import Config
from fs_report.transforms.pandas import _cve_updates
from fs_report.transforms.pandas.cve_impact import _reachability_label

logger = logging.getLogger(__name__)

# Severity ordering for sort (lower index = higher priority)
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

# Statuses that represent suppressed / resolved findings — excluded from CRA scope
_EXCLUDED_STATUSES = {
    "FALSE_POSITIVE",
    "NOT_AFFECTED",
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
}

# Canonical output columns for the main DataFrame
_OUTPUT_COLUMNS = [
    "cve_id",
    "title",
    "severity",
    "cvss_score",
    "component",
    "component_version",
    "project",
    "project_version",
    "status",
    "cra_trigger",
    "in_kev",
    "kev_source",
    "exploit_maturity",
    "has_known_exploit",
    "epss_score",
    "epss_percentile",
    "detected_date",
    "reachability_label",
]


# ---------------------------------------------------------------------------
# Field extraction helpers  (kept for Phase C1 section assembly)
# ---------------------------------------------------------------------------


def _extract_str(record: dict[str, Any], *keys: str, default: str = "") -> str:
    """Return the first non-empty string found among ``keys`` in ``record``."""
    for key in keys:
        val = record.get(key)
        if val is None:
            continue
        if isinstance(val, dict):
            # e.g. component.name nested dict
            inner = val.get("name") or val.get("id") or val.get("version")
            if inner is not None:
                return str(inner)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if not isinstance(val, str):
            return str(val)
    return default


def _extract_component_name(record: dict[str, Any]) -> str:
    """Extract component name handling nested dicts and flat keys."""
    import ast

    for key in ("componentName",):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    comp = record.get("component")
    if isinstance(comp, dict):
        name = comp.get("name") or comp.get("id")
        if name:
            return str(name)
    if isinstance(comp, str):
        try:
            parsed = ast.literal_eval(comp)
            if isinstance(parsed, dict):
                name = parsed.get("name") or parsed.get("id")
                if name:
                    return str(name)
        except Exception:
            pass
        if comp.strip():
            return comp.strip()

    return "Unknown"


def _extract_component_version(record: dict[str, Any]) -> str:
    """Extract component version handling nested dicts and flat keys."""
    import ast

    for key in ("componentVersion", "componentVersionName"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    comp = record.get("component")
    if isinstance(comp, dict):
        ver = comp.get("version")
        if ver:
            return str(ver)
    if isinstance(comp, str):
        try:
            parsed = ast.literal_eval(comp)
            if isinstance(parsed, dict):
                ver = parsed.get("version")
                if ver:
                    return str(ver)
        except Exception:
            pass

    return "Unknown"


def _extract_project_name(record: dict[str, Any]) -> str:
    """Extract project name handling nested dicts and flat keys."""
    import ast

    for key in ("projectName",):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    proj = record.get("project")
    if isinstance(proj, dict):
        name = proj.get("name") or proj.get("id")
        if name:
            return str(name)
    if isinstance(proj, str):
        try:
            parsed = ast.literal_eval(proj)
            if isinstance(parsed, dict):
                name = parsed.get("name") or parsed.get("id")
                if name:
                    return str(name)
        except Exception:
            pass
        if proj.strip():
            return proj.strip()

    return "Unknown"


def _extract_project_version(record: dict[str, Any]) -> str:
    """Extract project version name from nested projectVersion or flat keys."""
    for key in ("versionName", "projectVersion"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            ver = v.get("version") or v.get("name")
            if ver:
                return str(ver)

    return "Unknown"


def _extract_project_version_id(record: dict[str, Any]) -> str:
    """Extract the project version ID from the raw API record.

    The API returns ``projectVersion`` as a nested dict with an ``id`` field.
    Flat key ``projectVersionId`` is also accepted as a fallback.

    Returns empty string when the ID cannot be found.
    """
    # Preferred: nested dict shape (standard API response)
    pv = record.get("projectVersion")
    if isinstance(pv, dict):
        pv_id = pv.get("id")
        if pv_id is not None:
            return str(pv_id)

    # Flat key fallback (e.g. cached / normalised records)
    for key in ("projectVersionId", "project_version_id"):
        v = record.get(key)
        if v is not None:
            return str(v)

    return ""


def _extract_project_id(record: dict[str, Any]) -> str:
    """Extract the project ID (NOT project-version ID) from the raw API record.

    The activity endpoint ``/public/v0/projects/{pid}/findings/activity``
    requires the project ID, not the project-version ID.

    The API returns ``project`` as a nested dict with an ``id`` field.
    Flat key ``projectId`` is also accepted as a fallback.

    Returns empty string when the ID cannot be found.
    """
    # Preferred: nested dict shape (standard API response)
    proj = record.get("project")
    if isinstance(proj, dict):
        proj_id = proj.get("id")
        if proj_id is not None:
            return str(proj_id)

    # Flat key fallback (e.g. cached / normalised records)
    for key in ("projectId", "project_id"):
        v = record.get(key)
        if v is not None:
            return str(v)

    return ""


def _extract_cve_id(record: dict[str, Any]) -> str:
    """Extract CVE/advisory ID from various field shapes."""
    for key in ("cveId", "findingId"):
        v = record.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    cve = record.get("cve")
    if isinstance(cve, dict):
        cve_id = cve.get("id")
        if cve_id:
            return str(cve_id)
    if isinstance(cve, str) and cve.strip():
        return cve.strip()

    return "N/A"


def _safe_str(value: Any) -> str:
    """Convert to string, treating None and NaN as empty."""
    if value is None:
        return ""
    s = str(value)
    if s in ("nan", "None", "NaN"):
        return ""
    return s


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float, returning ``default`` on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _severity_rank(severity: str) -> int:
    """Return sort rank for severity (lower = higher priority)."""
    try:
        return _SEVERITY_ORDER.index(severity.upper())
    except (ValueError, AttributeError):
        return len(_SEVERITY_ORDER)


def _row_from_record(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a raw /findings record to a CRA output row dict.

    Returns None for statuses that are excluded from CRA scope (used
    for the legacy flat "main" DataFrame). Phase C1 section assembly
    uses _row_from_record_all which does not filter by status.
    """
    status = str(rec.get("status") or "").upper()
    if status in _EXCLUDED_STATUSES:
        return None

    return _row_from_record_all(rec)


def _row_from_record_all(rec: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw /findings record to a CRA output row dict.

    Unlike _row_from_record, does NOT filter by status — returns a row
    for ALL records including resolved/not-affected/false-positive.
    Used by Phase C1 section assembly so re_emerged can see resolved rows.
    """
    # CRA treats CISA KEV (inKev) and Verified-Compromise KEV (inVcKev) as
    # the same tier for both classification (kev) and KPI labeling. Round 2
    # multi-review caught the asymmetry: section assembly already groups
    # them via `inKev OR inVcKev`, but the row's `in_kev` and `cra_trigger`
    # were read from `inKev` alone, mis-labeling VcKev-only rows.
    in_kev_raw = bool(rec.get("inKev", False))
    in_vckev_raw = bool(rec.get("inVcKev", False))
    in_kev = in_kev_raw or in_vckev_raw

    # kev_source explains WHICH KEV signal triggered (drives the UNKNOWN-
    # deadline explanation in 🔥 SLA-Breach: VcKEV rows aren't in the
    # public CISA catalog so they have no `dateAdded` → no deadline).
    if in_kev_raw and in_vckev_raw:
        kev_source = "CISA+VcKEV"
    elif in_kev_raw:
        kev_source = "CISA"
    elif in_vckev_raw:
        kev_source = "VcKEV"
    else:
        kev_source = ""
    exploit_info = rec.get("exploitInfo") or []
    exploit_maturity = rec.get("exploitMaturity")
    has_exploit = bool(exploit_info) or bool(exploit_maturity)

    if in_kev:
        cra_trigger = "KEV"
    elif has_exploit:
        cra_trigger = "Known Exploit"
    else:
        cra_trigger = "Unknown"

    raw_risk = rec.get("risk")
    cvss_score = _safe_float(raw_risk) / 10.0 if raw_risk is not None else 0.0

    severity = str(rec.get("severity") or "UNKNOWN").upper()

    # Reachability — reuse cve_impact's 4-label scheme for consistency
    reach_raw = rec.get("reachabilityScore")
    reach_is_null = reach_raw is None
    reach_score = _safe_float(reach_raw, default=0.0) if not reach_is_null else 0.0
    reach_label = _reachability_label(reach_score, reach_is_null)

    return {
        "cve_id": _extract_cve_id(rec),
        "finding_row_id": str(
            rec.get("id") or ""
        ),  # numeric row identifier for /exploits URL
        "title": str(rec.get("title") or ""),
        "severity": severity,
        "cvss_score": cvss_score,
        "component": _extract_component_name(rec),
        "component_version": _extract_component_version(rec),
        "project": _extract_project_name(rec),
        "project_version": _extract_project_version(rec),
        "project_version_id": _extract_project_version_id(rec),
        "project_id": _extract_project_id(rec),
        "status": _safe_str(rec.get("status")),
        "cra_trigger": cra_trigger,
        "in_kev": in_kev,
        "kev_source": kev_source,
        "exploit_maturity": str(exploit_maturity or "").lower(),
        "has_known_exploit": has_exploit,
        "epss_score": _safe_float(rec.get("epssScore")),
        "epss_percentile": _safe_float(rec.get("epssPercentile")),
        # Field-name fallback. The /findings v0 API returns the awareness
        # timestamp as `detected`; older shapes used `detectedDate` or
        # `firstDetected`. Without this fallback, CRA's
        # `max(cisa_dateAdded, detected_date)` formula yields UNKNOWN for
        # rows that are inVcKev but not in the public CISA KEV catalog
        # (which is the majority — see the kev_source breakdown).
        "detected_date": str(
            rec.get("detected")
            or rec.get("detectedDate")
            or rec.get("firstDetected")
            or ""
        ),
        "reachability_label": reach_label,
        "reachability_score": reach_score,
        "reachability_evidence": "",  # Future-proofed; not exposed by current API
    }


# ---------------------------------------------------------------------------
# Private pipeline helpers
# ---------------------------------------------------------------------------


def _assemble_findings_filter(
    *,
    threshold_filter: str,
    include_status: list[str],
    exclude_status: list[str],
) -> str:
    """Semicolon-join threshold + status RSQL fragments.

    RSQL semicolon is logical AND; comma is OR.  A threshold_filter that
    contains a comma (multiple clauses ORed together) is wrapped in parens
    so the AND binding is correct.
    """
    fragments: list[str] = []
    if threshold_filter:
        fragments.append(
            f"({threshold_filter})" if "," in threshold_filter else threshold_filter
        )
    if include_status:
        fragments.append(f"status=in=({','.join(include_status)})")
    if exclude_status:
        fragments.append(f"status=out=({','.join(exclude_status)})")
    return ";".join(f for f in fragments if f)


def _chunked(iterable: Any, *, size: int) -> Any:
    """Yield successive chunks from ``iterable`` of at most ``size`` items."""
    buf: list[Any] = []
    for item in iterable:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def _merge_a_and_b(
    fetch_a_rows: list[dict[str, Any]], fetch_b_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge Fetch A and Fetch B with no duplicates, keyed by per-row id.

    Priority A > B on duplicate ``id`` (spec line 410: 'rows in both → take
    from A'). The dedup key MUST be ``id`` (the per-finding-row unique
    identifier) — NOT ``findingId``, which is the CVE label and collapses
    sibling rows for the same CVE on different products/versions. The CRA
    report's whole purpose is helping the customer identify *which products*
    are affected, so per-row distinctness is load-bearing.
    """
    seen = {r.get("id", "") for r in fetch_a_rows if r.get("id")}
    out = list(fetch_a_rows)
    for r in fetch_b_rows:
        rid = r.get("id", "")
        if rid and rid in seen:
            continue
        out.append(r)
        if rid:
            seen.add(rid)
    return out


def _build_folder_scope_filter(
    config: Config, folder_project_ids: set[str] | None
) -> str:
    """Return an RSQL fragment scoping a /findings query to a folder tree.

    The CRA recipe runs *after* the engine resolves --folder via
    ``_resolve_folder_scope``, which walks the folder tree and produces
    ``self._folder_project_ids`` (the set of project IDs under that tree).
    The engine plumbs that set in via ``additional_data["folder_project_ids"]``
    so this transform can match engine semantics — names are accepted, and
    the tree walk is honored (the legacy ``folderId={raw}`` query param the
    transform used previously matched neither names nor subfolders).

    Args:
        config: Config — read here only to detect whether --folder was
            requested at all (so we can fail-fast on misuse).
        folder_project_ids: Resolved set of project IDs from the engine. May
            be ``None`` when CRA is invoked outside an engine context (e.g.
            unit tests).

    Returns:
        ``"projectId=in=(id1,id2,...)"`` when there's a resolved set, or
        an empty string when --folder is not in use.

    Raises:
        RuntimeError if --folder is set but the engine has not pre-resolved
        the project ID set — that combination would silently expand scope.
    """
    if not getattr(config, "folder_filter", None):
        return ""
    if not folder_project_ids:
        raise RuntimeError(
            f"--folder={config.folder_filter!r} is set but the CRA transform "
            "did not receive a pre-resolved folder_project_ids set from the "
            "engine. Refusing to fall back to portfolio-wide scope."
        )
    ids = ",".join(sorted(folder_project_ids))
    return f"projectId=in=({ids})"


def _resolve_project_version_filter(api_client: Any, config: Config) -> str:
    """Return the RSQL fragment for project/version scoping, or empty string.

    Resolution order:
      1. config.version_filter set → ``projectVersion=={version_filter}``
         (used directly; no API call needed)
      2. config.project_filter set → resolve project ID via
         ``api_client.resolve_project``, then fetch
         ``/public/v0/projects/{pid}`` to read
         ``defaultBranch.latestVersion.id``  →  ``projectVersion=={vid}``
      3. Neither set → empty string (portfolio-wide query, no scoping)

    Fail-fast contract: a *requested* project scope that cannot be resolved
    raises RuntimeError rather than silently expanding to the entire tenant.
    A typo'd --project name turning into a portfolio-wide CRA notification
    would be a serious correctness/blast-radius bug for this recipe.
    """
    version_filter = getattr(config, "version_filter", None)
    if version_filter:
        return f"projectVersion=={version_filter}"

    project_filter = getattr(config, "project_filter", None)
    if not project_filter:
        return ""

    pid = api_client.resolve_project(project_filter)
    if pid is None:
        raise RuntimeError(
            f"--project={project_filter!r} did not resolve to a project ID. "
            "Check the project name (case-insensitive exact match) or pass "
            "the numeric ID directly. Refusing to fall back to portfolio-wide "
            "scope for a CRA notification report."
        )

    try:
        url = f"{api_client.base_url}/public/v0/projects/{pid}"
        resp = api_client.client.get(url)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(
            f"--project={project_filter!r} resolved to id {pid} but the "
            f"project detail fetch failed: {exc}. Refusing to fall back to "
            "portfolio-wide scope."
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(
            f"--project={project_filter!r} returned an unexpected response "
            f"shape for project {pid}. Refusing to fall back to portfolio-wide "
            "scope."
        )

    default_branch = data.get("defaultBranch") or {}
    latest_version = (
        default_branch.get("latestVersion") or {}
        if isinstance(default_branch, dict)
        else {}
    )
    vid = latest_version.get("id") if isinstance(latest_version, dict) else None

    if not vid:
        raise RuntimeError(
            f"--project={project_filter!r} (id {pid}) has no "
            "defaultBranch.latestVersion. Pass --project-version explicitly "
            "or pick a project that has at least one analyzed version."
        )

    return f"projectVersion=={vid}"


def _fetch_c_snapshot(
    api_client: Any,
    config: Config,
    folder_project_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Status-agnostic /findings fetch — paginated, projected to 6 fields.

    Fetches ALL findings (no status filter) so the snapshot can track
    KEV/exploitInfo state across any status.  Each row is projected to
    {id, findingId, inKev, inVcKev, exploitInfo, status} to keep memory
    bounded.

    Mirrors the pagination shape from _cve_updates._fetch_cve_updates.
    """
    url = f"{api_client.base_url}/public/v0/findings"
    params: dict[str, Any] = {
        "limit": 100,
        "offset": 0,
    }
    folder_scope = _build_folder_scope_filter(config, folder_project_ids)
    pv_scope = _resolve_project_version_filter(api_client, config)
    combined = ";".join(f for f in [folder_scope, pv_scope] if f)
    if combined:
        params["filter"] = combined

    results: list[dict[str, Any]] = []
    while True:
        try:
            response = api_client.client.get(url, params=params, timeout=60)
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict) and "data" in payload:
                batch = payload["data"]
            elif isinstance(payload, list):
                batch = payload
            else:
                batch = []
        except Exception as exc:
            raise RuntimeError(
                f"Fetch C snapshot pagination failed at offset={params['offset']}: "
                f"{exc}. Refusing to persist a partial snapshot baseline."
            ) from exc

        if not batch:
            break

        for rec in batch:
            results.append(
                {
                    "id": rec.get("id", ""),
                    "findingId": rec.get("findingId", ""),
                    "inKev": bool(rec.get("inKev")),
                    "inVcKev": bool(rec.get("inVcKev")),
                    "exploitInfo": list(rec.get("exploitInfo") or []),
                    "status": str(rec.get("status") or ""),
                }
            )

        if len(batch) < 100:
            break

        params["offset"] += 100

    logger.info("Fetch C: collected %d snapshot rows", len(results))
    return results


def _fetch_findings(
    api_client: Any,
    rsql_filter: str,
    config: Config,
    folder_project_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Paginated /findings fetch with the given RSQL filter.

    Applies folder/project-version scope from config alongside the provided
    filter. Folder scoping is done via the RSQL ``projectId=in=(...)`` term
    built from the engine-resolved tree of project IDs (NOT a raw
    ``folderId`` query param — that ignores subfolders and silently drops
    name-based filters). Project scoping is done via the RSQL
    ``projectVersion=={vid}`` fragment.

    Returns raw API records (not projected) so callers can build output rows.
    """
    url = f"{api_client.base_url}/public/v0/findings"
    params: dict[str, Any] = {
        "limit": 100,
        "offset": 0,
    }

    folder_scope = _build_folder_scope_filter(config, folder_project_ids)
    pv_scope = _resolve_project_version_filter(api_client, config)
    combined_filter = ";".join(f for f in [folder_scope, pv_scope, rsql_filter] if f)
    if combined_filter:
        params["filter"] = combined_filter

    results: list[dict[str, Any]] = []
    while True:
        try:
            response = api_client.client.get(url, params=params, timeout=60)
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict) and "data" in payload:
                batch = payload["data"]
            elif isinstance(payload, list):
                batch = payload
            else:
                batch = []
        except Exception as exc:
            raise RuntimeError(
                f"_fetch_findings pagination failed at offset={params['offset']} "
                f"(filter={rsql_filter!r}): {exc}. A partial CRA notification "
                "report is more dangerous than a hard failure — refusing to "
                "render an incomplete result."
            ) from exc

        if not batch:
            break

        results.extend(batch)

        if len(batch) < 100:
            break

        params["offset"] += 100

    logger.info(
        "_fetch_findings: collected %d rows (filter=%r)", len(results), rsql_filter
    )
    return results


# ---------------------------------------------------------------------------
# Main transform — B3 orchestrator
# ---------------------------------------------------------------------------


def cra_compliance_transform(
    raw_data: Any,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """CRA Compliance morning-queue pipeline orchestrator.

    Stage 0–7 as documented in the module docstring.  The transform is
    self-driving: it fetches its own data from the API rather than
    relying on the recipe's pre-fetched ``raw_data`` payload.

    Args:
        raw_data: Unused in the morning-queue pipeline; accepted for
            signature compatibility with the report engine.
        config: Application configuration.
        additional_data: Must contain ``api_client``; may contain
            ``recipe_parameters`` dict for YAML defaults.

    Returns:
        ``{"main": pd.DataFrame, "sla_breach": pd.DataFrame,
        "newly_above": pd.DataFrame, "re_emerged": pd.DataFrame,
        "still_in_triage": pd.DataFrame, "full_snapshot": pd.DataFrame}``
        — ``"main"`` is the backward-compatible flat CSV/XLSX table;
        the 5 section keys are the morning-queue DataFrames (Phase C1).
    """
    additional_data = additional_data or {}
    api_client = additional_data.get("api_client")
    recipe_params: dict[str, Any] = additional_data.get("recipe_parameters") or {}
    folder_project_ids: set[str] | None = additional_data.get("folder_project_ids")

    # ------------------------------------------------------------------
    # Stage 0 — Resolve effective config (CLI overrides YAML defaults)
    # ------------------------------------------------------------------
    threshold: set[str] = set(
        config.exploit_maturity_threshold
        or recipe_params.get("exploit_maturity_threshold", [])
    )
    include_status: list[str] = list(
        config.include_status or recipe_params.get("include_status", [])
    )
    exclude_status: list[str] = list(
        config.exclude_status or recipe_params.get("exclude_status", [])
    )
    scope_h = snapshot.scope_hash(
        getattr(config, "domain", None) or "",
        config.folder_filter or "",
        config.project_filter or "",
        config.version_filter or "",
    )

    # ------------------------------------------------------------------
    # Stage 1 — Resolve --since window (CRA-specific, NOT global period)
    # ------------------------------------------------------------------
    since_start, since_end = window.parse_since_window(config.since, scope_hash=scope_h)

    # ------------------------------------------------------------------
    # Stage 2 — Fetch C: status-agnostic baseline for snapshot-diff
    # ------------------------------------------------------------------
    if config.snapshot_diff != "off":
        if api_client is None:
            logger.warning(
                "snapshot_diff=%r but api_client is None; skipping Fetch C",
                config.snapshot_diff,
            )
            fetch_c_rows: list[dict[str, Any]] = []
            row_id_to_cve: dict[str, str] = {}
            current_kev_rows: set[str] = set()
            current_signals: dict[str, list[str]] = {}
            fetch_c_succeeded = False
        else:
            try:
                fetch_c_rows = _fetch_c_snapshot(
                    api_client, config, folder_project_ids=folder_project_ids
                )
                fetch_c_succeeded = True
            except RuntimeError as exc:
                logger.warning(
                    "Fetch C failed; Stage 1B crossings will be empty and "
                    "snapshot baseline will NOT be updated: %s",
                    exc,
                )
                fetch_c_rows = []
                fetch_c_succeeded = False
            row_id_to_cve = {str(r["id"]): r["findingId"] for r in fetch_c_rows}
            current_kev_rows = {
                str(r["id"]) for r in fetch_c_rows if r.get("inKev") or r.get("inVcKev")
            }
            current_signals = {
                str(r["id"]): list(r.get("exploitInfo") or []) for r in fetch_c_rows
            }
    else:
        fetch_c_rows = []
        row_id_to_cve = {}
        current_kev_rows = set()
        current_signals = {}
        fetch_c_succeeded = False

    # ------------------------------------------------------------------
    # Stage 3 — Stage 1 maturity crossings (/cves/updates in --since window)
    # ------------------------------------------------------------------
    if api_client is not None:
        # Build a config copy scoped to the CRA --since window (not the
        # global --period / start_date+end_date from the recipe).
        #
        # Clear folder_filter on the copy: _fetch_cve_updates passes it
        # raw as the `folderId` query param, which silently fails on
        # folder NAMES (the server treats "EU Products" as a malformed
        # ID → empty/error response) and ignores subfolder trees. The
        # CRA path does folder scoping client-side via the engine-resolved
        # `folder_project_ids` post-filter (R2-3) so this raw pass-through
        # would short-circuit the result set BEFORE that filter runs.
        # Round 3 review M2-1.
        cra_window_config = config.model_copy(
            update={
                "start_date": since_start,
                "end_date": since_end,
                "folder_filter": None,
            }
        )
        raw_updates = _cve_updates._fetch_cve_updates(api_client, cra_window_config)
        normalized = [_cve_updates.normalize_update(r) for r in raw_updates]

        # Project-scope filter (raises clear error on unresolved name)
        if config.project_filter:
            project_id = api_client.resolve_project(config.project_filter)
            if project_id is None:
                raise RuntimeError(
                    f"--project={config.project_filter!r} did not resolve to "
                    "a project ID. Check the project name (case-insensitive "
                    "exact match) or pass the numeric ID directly."
                )
            normalized = [
                u
                for u in normalized
                if any(str(p.get("id")) == str(project_id) for p in u.projects)
            ]

        # Folder-scope filter: mirror Fetch A/B/C's pattern (F11) — use the
        # engine-resolved folder_project_ids tree-walk result instead of
        # /cves/updates' folderId param, which silently fails on folder
        # names and ignores subfolders. Client-side post-filter matches
        # the project-scope path above for consistency.
        if folder_project_ids:
            normalized = [
                u
                for u in normalized
                if any(str(p.get("id")) in folder_project_ids for p in u.projects)
            ]

        maturity_crossed = _cve_updates.threshold_crossings_from_updates(
            normalized, threshold
        )
    else:
        maturity_crossed = set()

    # ------------------------------------------------------------------
    # Stage 4 — Stage 1 snapshot-diff crossings vs prior state
    # ------------------------------------------------------------------
    prior = snapshot.load_state(scope_h)
    # snapshot-diff returns ROW IDs (per-finding) — see snapshot.py docstrings
    # for why row-level is required for KEV/token crossings.
    kev_crossed_rows = snapshot.snapshot_diff_kev_crossings(
        prior,
        current_kev_rows=current_kev_rows,
        row_id_to_cve=row_id_to_cve,
        threshold=threshold,
    )
    token_crossed_rows = snapshot.snapshot_diff_token_crossings(
        prior,
        current_signals=current_signals,
        row_id_to_cve=row_id_to_cve,
        threshold=threshold,
    )
    stage1_crossed_row_ids: set[str] = kev_crossed_rows | token_crossed_rows
    # maturity_crossed stays CVE-level because /cves/updates is itself CVE-
    # level — when the platform says CVE-X moved POC→weaponized, every
    # finding row for that CVE crosses at the same moment.
    stage1_crossed_cves: set[str] = set(maturity_crossed)

    # Provenance: CVE-keyed for maturity (the only source that's CVE-level);
    # row-keyed for snapshot-diff (which IS per-row). The section builders
    # check the row's cve_id first, then its finding_row_id, to resolve
    # "updates" vs "snapshot-diff".
    crossing_sources: dict[str, str] = {}
    for cve in maturity_crossed:
        crossing_sources[cve] = "updates"
    for row_id in stage1_crossed_row_ids:
        crossing_sources.setdefault(row_id, "snapshot-diff")

    # ------------------------------------------------------------------
    # Stage 5 — Fetch A: above-threshold inventory
    # ------------------------------------------------------------------
    effective_threshold: set[str] = threshold  # default; overridden below
    if api_client is not None:
        filter_str, effective_threshold = tiers.build_threshold_filter(
            threshold, strategy=config.unfilterable_tier_strategy
        )
        fetch_a_filter = _assemble_findings_filter(
            threshold_filter=filter_str,
            include_status=include_status,
            exclude_status=exclude_status,
        )
        fetch_a_rows = _fetch_findings(
            api_client,
            fetch_a_filter,
            config,
            folder_project_ids=folder_project_ids,
        )
    else:
        fetch_a_rows = []

    # ------------------------------------------------------------------
    # Stage 6 — Fetch B: resolved add-back (chunked at 50)
    #
    # Both crossing sources need add-back coverage:
    #   * stage1_crossed_cves — CVE-level (from /cves/updates)
    #   * stage1_crossed_row_ids — row-level (from snapshot-diff)
    # Without converting the row-id set back to CVE IDs for the Fetch B
    # query, snapshot-diff crossings on previously-resolved findings would
    # never reach 🔁 Re-emerged (the resolved row is filtered out of Fetch A
    # by status, and never re-fetched here). Round 2 multi-review caught
    # this as a regression from F4's CVE→row-id split.
    # ------------------------------------------------------------------
    snapshot_diff_cves: set[str] = {
        row_id_to_cve[rid] for rid in stage1_crossed_row_ids if rid in row_id_to_cve
    }
    fetch_a_cves: set[str] = {r.get("findingId", "") for r in fetch_a_rows}
    resolved_addback_cves: set[str] = (
        stage1_crossed_cves | snapshot_diff_cves
    ) - fetch_a_cves
    fetch_b_rows: list[dict[str, Any]] = []
    if resolved_addback_cves and api_client is not None:
        for chunk in _chunked(sorted(resolved_addback_cves), size=50):
            cve_filter = f"cveId=in=({','.join(chunk)})"
            fetch_b_rows.extend(
                _fetch_findings(
                    api_client,
                    cve_filter,
                    config,
                    folder_project_ids=folder_project_ids,
                )
            )

    # ------------------------------------------------------------------
    # Stage 7 — Merge + section assembly (Phase C1) + persist
    # ------------------------------------------------------------------
    merged_rows = _merge_a_and_b(fetch_a_rows, fetch_b_rows)

    # Build output rows from raw API records.  _row_from_record_all does NOT
    # filter by status so resolved findings from Fetch B are preserved for
    # the re_emerged section.  The raw inKev / inVcKev / exploitInfo /
    # exploitMaturity fields are also re-added to each row so that
    # cra_sections.assemble_sections and derive_tiers() can inspect them.
    output_rows: list[dict[str, Any]] = []
    for rec in merged_rows:
        row = _row_from_record_all(rec)
        row["inKev"] = rec.get("inKev", False)
        row["inVcKev"] = rec.get("inVcKev", False)
        row["exploitInfo"] = list(rec.get("exploitInfo") or [])
        row["exploitMaturity"] = rec.get("exploitMaturity")
        output_rows.append(row)

    # C4 — filter to REACHABLE-only when configured
    if getattr(config, "reachable_only", False):
        output_rows = [
            r for r in output_rows if r.get("reachability_label") == "REACHABLE"
        ]

    # Fetch CISA KEV catalog entries for any KEV/VcKEV findings in the set.
    # `kev_due_date_source="none"` suppresses CISA enrichment AND prevents
    # rows from being routed to the 🔥 SLA-Breach section (Round 2 review:
    # an empty catalog with rows still in 🔥 produced a confusing UNKNOWN-
    # deadline view; the operator-facing semantic of "none" is "skip the
    # SLA model entirely").
    kev_due_date_source = getattr(config, "kev_due_date_source", "cisa")
    kev_sla_enabled = kev_due_date_source != "none"
    if not kev_sla_enabled:
        kev_catalog = {}
    else:
        kev_cve_ids = {
            r["cve_id"] for r in output_rows if r.get("inKev") or r.get("inVcKev")
        }
        kev_catalog = get_kev_due_dates(kev_cve_ids)

    # Assemble the 5 morning-queue sections (C1 done).
    sections_dict = cra_sections.assemble_sections(
        output_rows,
        stage1_crossed_cves=stage1_crossed_cves,
        stage1_crossed_row_ids=stage1_crossed_row_ids,
        crossing_sources=crossing_sources,
        effective_threshold=effective_threshold,
        kev_catalog=kev_catalog,
        kev_sla_enabled=kev_sla_enabled,
        config=config,
    )

    # ------------------------------------------------------------------
    # Phase C2 — /exploits fan-out for threat-actor evidence
    #
    # Only fetch for the 4 queue sections (NOT full_snapshot, which could
    # explode the per-finding API call count). Priority ordering ensures
    # the most urgent findings are enriched first when the 500-fetch
    # budget is exhausted: sla_breach → newly_above → re_emerged →
    # still_in_triage.
    # ------------------------------------------------------------------
    _QUEUE_SECTION_KEYS: tuple[str, ...] = (
        "sla_breach",
        "newly_above",
        "re_emerged",
        "still_in_triage",
    )
    if api_client is not None:
        queue_targets: list[tuple[str, str]] = []
        for section_key in _QUEUE_SECTION_KEYS:
            df = sections_dict[section_key]
            if df.empty:
                continue
            # Use numeric finding_row_id (rec["id"]) for the /exploits URL path,
            # NOT cve_id ("CVE-2026-…") which is the label string (findingId on
            # the API response). The endpoint requires the row identifier:
            #   /findings/{pv_id}/{numeric_finding_row_id}/exploits
            _id_col = (
                "finding_row_id"
                if "finding_row_id" in df.columns
                else "cve_id"  # fallback for DataFrames missing the new column
            )
            for qrow in df[["project_version_id", _id_col]].itertuples(index=False):
                pv_id = str(getattr(qrow, "project_version_id", "") or "")
                finding_id = str(getattr(qrow, _id_col, "") or "")
                if pv_id and finding_id:
                    queue_targets.append((pv_id, finding_id))

        if queue_targets:
            evidence_map = cra_evidence.fetch_threat_evidence(api_client, queue_targets)
            sections_dict = cra_evidence.merge_evidence_into_sections(
                sections_dict, evidence_map, _QUEUE_SECTION_KEYS
            )
        else:
            # No targets — still add the evidence columns (empty) so
            # downstream renderers can rely on their presence.
            sections_dict = cra_evidence.merge_evidence_into_sections(
                sections_dict, {}, _QUEUE_SECTION_KEYS
            )
    # TODO(D1/D2): when api_client is None (offline / test path), the
    # evidence columns (threat_actor_names, ransomware_families,
    # botnet_names) are absent from the queue-section DataFrames.
    # Renderers must either treat missing columns as empty OR the caller
    # path must guarantee merge_evidence_into_sections is invoked even
    # in the api_client-None branch with an empty evidence map.

    # ------------------------------------------------------------------
    # Phase C3 — /activity fan-out (opt-in via --with-triage-age)
    #
    # Fetches /public/v0/projects/{pid}/findings/activity?cve=<cve_id>
    # for still_in_triage and re_emerged section findings.
    # - still_in_triage: triage_age_days overridden with precise
    #   triage_started_at from activity (C1 detected-date is the fallback)
    # - re_emerged: resolution_date column added from the latest resolution event
    # ------------------------------------------------------------------
    if getattr(config, "with_triage_age", False) and api_client is not None:
        _ACTIVITY_SECTION_KEYS = ("still_in_triage", "re_emerged")
        activity_targets: list[tuple[str, str]] = []
        for section_key in _ACTIVITY_SECTION_KEYS:
            df = sections_dict[section_key]
            if df.empty:
                continue
            # Activity endpoint uses PROJECT id (not project_version_id).
            for act_row in df[["project_id", "cve_id"]].itertuples(index=False):
                proj_id = str(getattr(act_row, "project_id", "") or "")
                cve_id_val = str(getattr(act_row, "cve_id", "") or "")
                if proj_id and cve_id_val:
                    activity_targets.append((proj_id, cve_id_val))

        if activity_targets:
            _sections_now = cra_sections._utcnow()
            activity_map = cra_evidence.fetch_triage_activity(
                api_client, activity_targets
            )
            sections_dict = cra_evidence.merge_triage_activity_into_sections(
                sections_dict, activity_map, now=_sections_now
            )

    # Build the flat "main" DataFrame for CSV/XLSX backward compat.
    # Per multi-review M1-6: main must carry the morning-queue model so that
    # spreadsheet consumers (and Forge paths that reuse CSV) see the same
    # contract as the HTML/MD renderers — primary_section, SLA columns,
    # crossing provenance, evidence columns. Strategy: concatenate the 5
    # section DataFrames (which each carry their section-specific derived
    # columns) and dedup by per-finding-row id, keeping the highest-priority
    # queue assignment via the SECTION_KEYS order. The result is one row
    # per finding with primary_section telling the consumer which queue it
    # belongs to (or "full_snapshot" for the audit-appendix-only rows).
    section_frames = [
        sections_dict[k].assign(primary_section=k)
        for k in cra_sections.SECTION_KEYS
        if not sections_dict[k].empty
    ]
    if section_frames:
        # Re-assert primary_section after concat because some sections already
        # set it during _build_*; we want the highest-priority assignment.
        combined = pd.concat(section_frames, ignore_index=True)
        if "finding_row_id" in combined.columns:
            # Keep first occurrence — section_frames are concatenated in
            # SECTION_KEYS priority order (sla_breach > newly_above > ...).
            combined = combined.drop_duplicates(subset=["finding_row_id"], keep="first")
        combined["_severity_rank"] = combined["severity"].apply(_severity_rank)
        main_df = (
            combined.sort_values(
                ["_severity_rank", "cvss_score"],
                ascending=[True, False],
            )
            .drop(columns=["_severity_rank"])
            .reset_index(drop=True)
        )
    else:
        main_df = pd.DataFrame(columns=_OUTPUT_COLUMNS + ["primary_section"])

    # Snapshot persistence — only on full Fetch C success and only when mode
    # is "on". A partial Fetch C (pagination error mid-way) MUST NOT overwrite
    # the prior baseline, or the next run's KEV/token crossing detection will
    # produce mass false positives or miss real crossings.
    if config.snapshot_diff == "on" and fetch_c_succeeded:
        new_state = snapshot.State(
            schema_version=2,
            inkev_rows=current_kev_rows,
            exploitinfo_signals=current_signals,
            last_run_at=window._fmt_z(window._utcnow()),
        )
        snapshot.save_state(scope_h, new_state)

    return {
        "main": main_df,
        # Surface the actual --since window so HTML/MD renderers can show
        # the real delta horizon instead of the hard-coded "24h" fallback.
        # The engine forwards top-level keys from the transform result into
        # additional_data, which is what the renderers read.
        "since_start": since_start,
        "since_end": since_end,
        # effective_threshold reflects the CLI override AND the
        # unfilterable-tier-strategy resolution (e.g. drop-tier may have
        # removed ransomware/threat_actor). Renderers prefer this over
        # recipe_params for the "Threshold Tiers" header so the report
        # reports what was actually used, not the YAML default.
        "effective_threshold": sorted(effective_threshold),
        **sections_dict,
    }
