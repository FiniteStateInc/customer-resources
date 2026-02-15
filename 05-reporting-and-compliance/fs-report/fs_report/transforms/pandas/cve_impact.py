"""
Pandas transform for the CVE Impact report.

Consumes pre-aggregated CVE records from ``/public/v0/cves`` and produces:
- A flat DataFrame (one row per CVE) for CSV/XLSX export
- A list of per-CVE dossier dicts for HTML rendering (only when ``--cve`` is specified)

When ``--cve`` is specified the engine also enriches with per-finding
reachability data fetched from ``/public/v0/findings``.
"""

from __future__ import annotations

import ast
import logging
import re
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)


def cve_impact_pandas_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform ``/cves`` endpoint data into CVE-centric impact report.

    Args:
        data: Raw CVE records from ``/public/v0/cves`` (list of dicts or DF).
        config: Application configuration (includes ``cve_filter``).
        additional_data: Optional dict that may contain:
            - ``reachability``: mapping of cveId -> list of finding dicts
              (only present when ``--cve`` was specified).

    Returns:
        Dictionary with keys:
        - ``main``: flat DataFrame for CSV/XLSX (one row per unique CVE)
        - ``dossiers``: list of per-CVE dossier dicts (populated only when
          ``config.cve_filter`` is set, empty list otherwise)
        - ``mode``: ``"dossier"`` when ``--cve`` is set, ``"summary"`` otherwise
        - ``summary``: portfolio-level summary statistics dict
    """
    additional_data = additional_data or {}
    reachability_map: dict[str, list[dict[str, Any]]] = additional_data.get(
        "reachability", {}
    )
    enriched_exploit_map: dict[str, list[dict[str, Any]]] = additional_data.get(
        "exploit_details", {}
    )

    # Accept list-of-dicts or DataFrame ---------------------------------
    records: list[dict[str, Any]]
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return _empty_result()
        records = data.to_dict("records")  # type: ignore[assignment]
    elif not data:
        return _empty_result()
    else:
        records = list(data)

    if not records:
        return _empty_result()

    # Determine mode from config ----------------------------------------
    cve_filter_list: list[str] | None = None
    if config.cve_filter:
        cve_filter_list = [
            c.strip().upper() for c in config.cve_filter.split(",") if c.strip()
        ]
    mode = "dossier" if cve_filter_list else "summary"

    # Defensive post-filter by --cve (API already filters, but this
    # ensures correctness when transform is called directly in tests
    # or if the API filter is approximate).
    if cve_filter_list:
        records = [
            r for r in records if str(r.get("cveId", "")).upper() in cve_filter_list
        ]
        if not records:
            logger.warning(f"No CVE records match --cve filter: {config.cve_filter}")
            return _empty_result()

    # Build one output row per CVE record -------------------------------
    rows: list[dict[str, Any]] = []

    for rec in records:
        cve_id = rec.get("cveId", "")
        if not cve_id:
            continue

        # Severity / risk -----------------------------------------------
        severity = str(rec.get("severity", "UNKNOWN")).upper()
        risk = _safe_float(rec.get("risk", 0))

        # CWE -----------------------------------------------------------
        cwe = _extract_cwe_from_list(rec.get("cwes"))

        # EPSS -----------------------------------------------------------
        epss_percentile = _safe_float(rec.get("epssPercentile", 0))
        epss_score = _safe_float(rec.get("epssScore", 0))

        # KEV / exploits -------------------------------------------------
        in_kev = bool(rec.get("inKev", False))
        exploit_info = _ensure_list(rec.get("exploitInfo"))
        exploit_details = _collect_exploit_details(exploit_info)

        # Projects & components ------------------------------------------
        affected_projects = _ensure_list(rec.get("affectedProjects"))
        affected_components = _ensure_list(rec.get("affectedComponents"))

        project_names = sorted(
            {p.get("name", "Unknown") for p in affected_projects if isinstance(p, dict)}
        )
        project_count = len(project_names)

        components = sorted(
            {
                f"{c.get('name', 'Unknown')}:{c.get('version', '')}"
                for c in affected_components
                if isinstance(c, dict)
            }
        )

        # Build lookup maps for IDs (used to make links clickable)
        project_id_map = _build_project_id_map(affected_projects)
        component_map = _build_component_map(affected_components)

        # Dates ----------------------------------------------------------
        first_detected = str(rec.get("firstDetected", ""))
        last_detected = str(rec.get("lastDetected", ""))

        # Reachability (from enrichment, dossier mode only) ---------------
        reach_findings = reachability_map.get(cve_id, [])
        reachable_projects: list[str] = []
        unreachable_count = 0
        unknown_count = 0
        project_details: list[dict[str, Any]] = []
        attack_vector = ""
        vuln_functions: list[str] = []

        if reach_findings:
            project_details = _build_project_details_from_findings(
                reach_findings, project_id_map, component_map
            )
            reachable_projects = [
                p["project_name"]
                for p in project_details
                if p["reachability_label"] == "REACHABLE"
            ]
            unreachable_count = sum(
                1 for p in project_details if p["reachability_label"] == "UNREACHABLE"
            )
            unknown_count = sum(
                1 for p in project_details if p["reachability_label"] == "INCONCLUSIVE"
            )
            # Title from first finding
            title = str(reach_findings[0].get("title", "")) if reach_findings else ""

            # --- Enrich from findings data ---

            # Exploit info: /cves endpoint often returns empty exploitInfo;
            # use the dedicated /findings/{id}/exploits endpoint data
            # from additional_data["exploit_details"], which has actual
            # source/url/description metadata.
            enriched_exploits = enriched_exploit_map.get(cve_id, [])
            if enriched_exploits:
                exploit_details = _collect_exploit_details(enriched_exploits)
            else:
                # Fallback: check hasKnownExploit boolean on findings
                for f in reach_findings:
                    if f.get("hasKnownExploit") or f.get("has_known_exploit"):
                        # We know exploits exist but don't have details
                        if not exploit_details:
                            exploit_details = [
                                {
                                    "source": "Finite State",
                                    "url": "",
                                    "description": "Known exploit detected "
                                    "(details unavailable)",
                                }
                            ]
                        break

            # Attack vector: pick the worst across all findings
            attack_vector = _worst_attack_vector(reach_findings)

            # Vulnerable functions: extract from reachability factors
            vuln_functions = _extract_vuln_functions_from_findings(reach_findings)

        else:
            # No reachability enrichment -- use project count as unknown
            unknown_count = project_count
            title = ""
            # Build lightweight project details from /cves data
            for p in affected_projects:
                if isinstance(p, dict):
                    pname = p.get("name", "Unknown")
                    pid = p.get("id")
                    latest_vid = _get_latest_version_id(p)
                    latest_vname = _get_latest_version_name(p)
                    # Find components for this project
                    proj_components = component_map.get(str(pid), [])
                    comp_str = (
                        ", ".join(
                            f"{c['name']}:{c['version']}" for c in proj_components
                        )
                        if proj_components
                        else ""
                    )
                    # For BOM URL, prefer vcId (version-component ID used in
                    # componentId= param) over generic component id.
                    # Also match component to this project's version.
                    matched_comp = _match_component_for_project(
                        proj_components, latest_vid
                    )
                    project_details.append(
                        {
                            "project_name": pname,
                            "project_id": pid,
                            "project_version": latest_vname,
                            "project_version_id": latest_vid,
                            "component": comp_str,
                            "component_id": matched_comp,
                            "reachability_label": "INCONCLUSIVE",
                            "reachability_score": 0.0,
                            "triage_status": "",
                            "detected": first_detected,
                        }
                    )
            project_details.sort(key=lambda x: x["project_name"])

        has_exploit = len(exploit_details) > 0
        exploit_count = len(exploit_details)

        # CVE description from enrichment --------------------------------
        cve_descriptions: dict[str, str] = additional_data.get("cve_descriptions", {})
        description = cve_descriptions.get(cve_id, "")

        rows.append(
            {
                "CVE ID": cve_id,
                "Severity": severity,
                "CVSS": risk,
                "Title": title,
                "CWE": cwe,
                "EPSS Percentile": round(epss_percentile, 4),
                "EPSS Score": round(epss_score, 6),
                "KEV": in_kev,
                "Has Exploit": has_exploit,
                "Exploits": exploit_count,
                "Affected Projects": project_count,
                "Reachable In": len(reachable_projects),
                "Unreachable In": unreachable_count,
                "Inconclusive In": unknown_count,
                "Project Names": ", ".join(project_names),
                "Reachable Projects": ", ".join(sorted(reachable_projects)),
                "Components": ", ".join(components),
                "First Detected": first_detected,
                "Last Detected": last_detected,
                # Internal fields for dossier rendering
                "_exploit_details": exploit_details,
                "_project_details": project_details,
                "_attack_vector": attack_vector,
                "_vuln_functions": vuln_functions,
                "_description": description,
            }
        )

    if not rows:
        return _empty_result()

    # Sort by CVSS descending, then by project count --------------------
    rows.sort(key=lambda r: (-r["CVSS"], -r["Affected Projects"]))

    # Build flat DataFrame for CSV/XLSX ---------------------------------
    csv_columns = _csv_columns()
    main_df = pd.DataFrame(rows)[csv_columns]

    # Build dossiers for HTML (only in dossier mode) --------------------
    dossiers: list[dict[str, Any]] = []
    if mode == "dossier":
        for row in rows:
            dossiers.append(
                {
                    "cve_id": row["CVE ID"],
                    "severity": row["Severity"],
                    "cvss": row["CVSS"],
                    "title": row["Title"],
                    "description": row["_description"],
                    "cwe": row["CWE"],
                    "epss_percentile": row["EPSS Percentile"],
                    "epss_score": row["EPSS Score"],
                    "kev": row["KEV"],
                    "has_exploit": row["Has Exploit"],
                    "exploit_count": row["Exploits"],
                    "affected_count": row["Affected Projects"],
                    "reachable_count": row["Reachable In"],
                    "unreachable_count": row["Unreachable In"],
                    "unknown_count": row["Inconclusive In"],
                    "exploit_details": row["_exploit_details"],
                    "project_details": row["_project_details"],
                    "attack_vector": row["_attack_vector"],
                    "vuln_functions": ", ".join(row["_vuln_functions"]),
                    "first_detected": row["First Detected"],
                    "last_detected": row["Last Detected"],
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{row['CVE ID']}",
                    "cwe_url": (
                        f"https://cwe.mitre.org/data/definitions/"
                        f"{row['CWE'].replace('CWE-', '')}.html"
                        if row["CWE"].startswith("CWE-")
                        else ""
                    ),
                }
            )

    # Track extra output files (prompts) for user-visible listing
    extra_generated_files: list[str] = []

    # AI guidance and prompt export (dossier mode only) ------------------
    if mode == "dossier" and dossiers:
        _prompts_path = _enrich_dossiers_with_ai(dossiers, rows, config)
        if _prompts_path:
            extra_generated_files.append(_prompts_path)

    # Build summary statistics ------------------------------------------
    summary = _build_summary(rows)

    logger.info(
        f"CVE Impact: {len(rows)} unique CVEs across "
        f"{summary['total_projects']} projects (mode={mode})"
    )

    return {
        "main": main_df,
        "dossiers": dossiers,
        "mode": mode,
        "summary": summary,
        "_extra_generated_files": extra_generated_files,
    }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "CVE ID",
    "Severity",
    "CVSS",
    "Title",
    "CWE",
    "EPSS Percentile",
    "EPSS Score",
    "KEV",
    "Has Exploit",
    "Exploits",
    "Affected Projects",
    "Reachable In",
    "Unreachable In",
    "Inconclusive In",
    "Project Names",
    "Reachable Projects",
    "Components",
    "First Detected",
    "Last Detected",
]


def _csv_columns() -> list[str]:
    """Return the canonical CSV column list."""
    return list(_CSV_COLUMNS)


def _empty_result() -> dict[str, Any]:
    """Return an empty result dict."""
    return {
        "main": pd.DataFrame(columns=_csv_columns()),
        "dossiers": [],
        "mode": "summary",
        "summary": {
            "total_cves": 0,
            "total_projects": 0,
            "severity_counts": {},
            "total_reachable": 0,
            "total_unreachable": 0,
            "total_unknown": 0,
        },
    }


def _safe_float(val: Any) -> float:
    """Safely convert to float, returning 0.0 on failure."""
    try:
        return float(val) if val is not None else 0.0
    except (ValueError, TypeError):
        return 0.0


def _ensure_list(val: Any) -> list[Any]:
    """Ensure the value is a list."""
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        try:
            parsed = ast.literal_eval(val)
            if isinstance(parsed, list):
                return parsed
        except (ValueError, SyntaxError):
            pass
    return []


def _extract_cwe_from_list(cwes: Any) -> str:
    """Extract the first CWE from a cwes list or string."""
    items = _ensure_list(cwes)
    if items:
        cwe = str(items[0]).replace("CWE-CWE-", "CWE-")
        return cwe
    if isinstance(cwes, str):
        match = re.search(r"CWE-\d+", cwes)
        if match:
            return match.group(0)
    return ""


def _collect_exploit_details(
    exploit_info: list[Any],
) -> list[dict[str, str]]:
    """Collect and deduplicate exploit details from exploit endpoint data.

    The /findings/{pvId}/{findingId}/exploits endpoint returns exploit
    objects with these fields (among others):
        - url: link to exploit (e.g. GitHub PoC repo)
        - name: human-readable description / title
        - refsource: source identifier (e.g. "github-exploits", "nist-nvd2")
        - exploit_maturity: e.g. "poc", "weaponized"
        - exploit_type: e.g. "denial-of-service"

    We normalise these into {source, url, description} dicts for display,
    and also preserve maturity/type when available.
    """
    seen_urls: set[str] = set()
    details: list[dict[str, str]] = []
    for item in exploit_info:
        if not isinstance(item, dict):
            continue
        url = item.get("url", "")
        if url and url in seen_urls:
            continue
        if url:
            seen_urls.add(url)
        # Map from API field names to our normalised display fields
        source = str(item.get("refsource", "") or item.get("source", "Unknown"))
        description = str(item.get("name", "") or item.get("description", ""))[:300]
        detail: dict[str, str] = {
            "source": source,
            "url": url,
            "description": description,
        }
        maturity = item.get("exploit_maturity", "")
        if maturity:
            detail["maturity"] = str(maturity)
        exploit_type = item.get("exploit_type", "")
        if exploit_type:
            detail["type"] = str(exploit_type)
        details.append(detail)
    return details


def _get_latest_version_name(project: dict[str, Any]) -> str:
    """Extract the latest version name from an affectedProjects entry."""
    branch = project.get("defaultBranch")
    if isinstance(branch, dict):
        latest = branch.get("latestVersion")
        if isinstance(latest, dict):
            return str(latest.get("name", ""))
    return ""


def _get_latest_version_id(project: dict[str, Any]) -> Any:
    """Extract the latest version ID from an affectedProjects entry."""
    branch = project.get("defaultBranch")
    if isinstance(branch, dict):
        latest = branch.get("latestVersion")
        if isinstance(latest, dict):
            return latest.get("id")
    return None


def _build_project_id_map(
    affected_projects: list[Any],
) -> dict[str, dict[str, Any]]:
    """Build a name->info lookup from affectedProjects.

    Returns mapping of project_name -> {id, version_id, version_name}.
    """
    result: dict[str, dict[str, Any]] = {}
    for p in affected_projects:
        if not isinstance(p, dict):
            continue
        name = p.get("name", "Unknown")
        result[name] = {
            "id": p.get("id"),
            "version_id": _get_latest_version_id(p),
            "version_name": _get_latest_version_name(p),
        }
    return result


def _build_component_map(
    affected_components: list[Any],
) -> dict[str, list[dict[str, Any]]]:
    """Build a project_id->components lookup from affectedComponents.

    Returns mapping of str(projectId) -> list of component info dicts.
    """
    result: dict[str, list[dict[str, Any]]] = {}
    for c in affected_components:
        if not isinstance(c, dict):
            continue
        pid = str(c.get("projectId", ""))
        if pid not in result:
            result[pid] = []
        result[pid].append(
            {
                "id": c.get("id"),
                "vcId": c.get("vcId"),
                "name": c.get("name", "Unknown"),
                "version": c.get("version", ""),
                "projectVersionId": c.get("projectVersionId"),
            }
        )
    return result


def _match_component_for_project(
    components: list[dict[str, Any]], version_id: Any
) -> Any:
    """Pick the best component ID for a BOM URL.

    Prefers ``vcId`` (version-component ID used in the ``componentId=`` URL
    param).  When multiple components exist, tries to match the one whose
    ``projectVersionId`` matches the given *version_id*.
    """
    if not components:
        return None

    # Try to find a component that matches this specific version
    if version_id:
        vid_str = str(version_id)
        for c in components:
            if str(c.get("projectVersionId", "")) == vid_str:
                return c.get("vcId") or c.get("id")

    # Fall back to first component's vcId or id
    first = components[0]
    return first.get("vcId") or first.get("id")


def _worst_attack_vector(findings: list[dict[str, Any]]) -> str:
    """Return the worst (most exposed) attack vector across findings.

    Rank: NETWORK > ADJACENT > LOCAL > PHYSICAL.
    """
    rank = {"NETWORK": 0, "ADJACENT": 1, "LOCAL": 2, "PHYSICAL": 3}
    best = ""
    best_rank = 99
    for f in findings:
        av = str(f.get("attackVector") or f.get("attack_vector") or "").upper()
        r = rank.get(av, 99)
        if r < best_rank:
            best = av
            best_rank = r
    return best


def _extract_vuln_functions_from_findings(
    findings: list[dict[str, Any]],
) -> list[str]:
    """Extract unique vulnerable function names from findings' factors."""
    funcs: list[str] = []
    seen: set[str] = set()
    for f in findings:
        factors = f.get("factors") or f.get("reachability_factors") or []
        if isinstance(factors, str):
            try:
                factors = ast.literal_eval(factors)
            except (ValueError, SyntaxError):
                factors = []
        if not isinstance(factors, list):
            continue
        for factor in factors:
            if isinstance(factor, dict) and factor.get("entity_type") == "vuln_func":
                name = factor.get("entity_name", "")
                if name and name not in seen:
                    seen.add(name)
                    funcs.append(name)
    return funcs


def _build_project_details_from_findings(
    findings: list[dict[str, Any]],
    project_id_map: dict[str, dict[str, Any]] | None = None,
    component_map: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Build per-project detail rows from findings enrichment data.

    Groups by project name and picks the worst reachability per project.
    Sorts reachable-first.  Enriches with IDs from the ``/cves`` endpoint
    maps when available.
    """
    project_id_map = project_id_map or {}
    component_map = component_map or {}
    projects: dict[str, dict[str, Any]] = {}

    for f in findings:
        pname = _nested_get(f, "project", "name", default="Unknown")
        reach_score = _safe_float(f.get("reachabilityScore", 0))
        reach_label = (
            "REACHABLE"
            if reach_score > 0
            else ("UNREACHABLE" if reach_score < 0 else "INCONCLUSIVE")
        )

        comp_name = _nested_get(f, "component", "name", default="Unknown")
        comp_version = _nested_get(f, "component", "version", default="")
        component = f"{comp_name}:{comp_version}" if comp_version else comp_name

        pv_version = _nested_get(f, "projectVersion", "version", default="")
        detected = str(f.get("detected", ""))

        # Triage/VEX status from finding
        triage_status = str(f.get("status") or "").upper()

        # IDs from finding — prefer vcId for BOM URL (componentId= param)
        project_id: Any = _nested_get(f, "project", "id") or None
        pv_id: Any = _nested_get(f, "projectVersion", "id") or None
        comp_vc_id: Any = _nested_get(f, "component", "vcId") or None
        comp_id: Any = _nested_get(f, "component", "id") or None

        # Fall back to /cves project map if finding didn't have IDs
        if not project_id and pname in project_id_map:
            pinfo = project_id_map[pname]
            project_id = pinfo.get("id")
            if not pv_id:
                pv_id = pinfo.get("version_id")

        if pname not in projects:
            projects[pname] = {
                "project_name": pname,
                "project_id": project_id or None,
                "project_version": pv_version,
                "project_version_id": pv_id or None,
                "component": component,
                "component_id": comp_vc_id or comp_id or None,
                "reachability_label": reach_label,
                "reachability_score": reach_score,
                "triage_status": triage_status,
                "detected": detected,
            }
        else:
            existing = projects[pname]
            if reach_score > existing["reachability_score"]:
                existing["reachability_label"] = reach_label
                existing["reachability_score"] = reach_score
            # Keep the most "actioned" triage status
            if triage_status and not existing.get("triage_status"):
                existing["triage_status"] = triage_status

    # Sort: REACHABLE first, then INCONCLUSIVE, then UNREACHABLE
    order = {"REACHABLE": 0, "INCONCLUSIVE": 1, "UNREACHABLE": 2}
    return sorted(
        projects.values(),
        key=lambda p: (order.get(p["reachability_label"], 9), p["project_name"]),
    )


def _nested_get(d: dict[str, Any], parent: str, child: str, default: str = "") -> str:
    """Get a nested dict value, handling flat keys too."""
    # Nested dict
    parent_val = d.get(parent)
    if isinstance(parent_val, dict):
        return str(parent_val.get(child, default))
    # Flat key (e.g. "project.name" from cache)
    flat_key = f"{parent}.{child}"
    if flat_key in d:
        return str(d.get(flat_key, default))
    return default


_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

_ATTACK_VECTOR_RANK = {
    "NETWORK": 0,
    "ADJACENT": 1,
    "LOCAL": 2,
    "PHYSICAL": 3,
}


def _build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build portfolio-level summary statistics."""
    severity_counts: dict[str, int] = {}
    all_projects: set[str] = set()

    for row in rows:
        sev = row["Severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for pname in row["Project Names"].split(", "):
            if pname:
                all_projects.add(pname)

    total_reachable = sum(r["Reachable In"] for r in rows)
    total_unreachable = sum(r["Unreachable In"] for r in rows)
    total_unknown = sum(r["Inconclusive In"] for r in rows)

    # Top CVEs by project count for chart
    top_cves = [
        {
            "cve_id": r["CVE ID"],
            "count": r["Affected Projects"],
            "severity": r["Severity"],
        }
        for r in rows[:20]
    ]

    # Reachability by severity for chart
    reach_by_severity: dict[str, dict[str, int]] = {}
    for row in rows:
        sev = row["Severity"]
        if sev not in reach_by_severity:
            reach_by_severity[sev] = {"reachable": 0, "unreachable": 0, "unknown": 0}
        reach_by_severity[sev]["reachable"] += row["Reachable In"]
        reach_by_severity[sev]["unreachable"] += row["Unreachable In"]
        reach_by_severity[sev]["unknown"] += row["Inconclusive In"]

    # Worst severity / CVSS across all CVEs (for dossier cards)
    worst_severity = "UNKNOWN"
    worst_cvss = 0.0
    for row in rows:
        sev = row["Severity"]
        cvss = row["CVSS"]
        if _SEVERITY_RANK.get(sev, 99) < _SEVERITY_RANK.get(worst_severity, 99):
            worst_severity = sev
        if cvss > worst_cvss:
            worst_cvss = cvss

    # Worst attack vector (from dossier enrichment data)
    worst_attack_vector = "N/A"
    for row in rows:
        av = row.get("_attack_vector", "")
        if av and _ATTACK_VECTOR_RANK.get(av, 99) < _ATTACK_VECTOR_RANK.get(
            worst_attack_vector, 99
        ):
            worst_attack_vector = av

    return {
        "total_cves": len(rows),
        "total_projects": len(all_projects),
        "severity_counts": severity_counts,
        "total_reachable": total_reachable,
        "total_unreachable": total_unreachable,
        "total_unknown": total_unknown,
        "top_cves": top_cves,
        "reach_by_severity": reach_by_severity,
        "worst_severity": worst_severity,
        "worst_cvss": worst_cvss,
        "worst_attack_vector": worst_attack_vector,
    }


# ---------------------------------------------------------------------------
# AI guidance and prompt generation
# ---------------------------------------------------------------------------


def _build_cve_prompt(
    dossier: dict[str, Any], row: dict[str, Any], nvd_snippet: str = ""
) -> str:
    """Build an LLM prompt for remediation guidance for one CVE.

    This is a standalone function that does NOT require an API key or
    LLMClient instantiation.  It produces the same prompt that ``--ai``
    would send to Claude, so users can paste it into any LLM.

    Args:
        dossier: CVE dossier dict with severity, cvss, description, etc.
        row: Corresponding row dict from the output table.
        nvd_snippet: Optional pre-formatted NVD fix version data
            (from NVDClient.format_for_prompt).
    """
    cve_id = dossier["cve_id"]
    severity = dossier["severity"]
    cvss = dossier["cvss"]
    description = dossier.get("description") or dossier.get("title") or ""
    cwe = dossier.get("cwe", "")
    epss = dossier.get("epss_percentile", 0)
    attack_vector = dossier.get("attack_vector", "")
    vuln_functions = dossier.get("vuln_functions", "")
    components_str = row.get("Components", "")
    kev = dossier.get("kev", False)
    first_detected = dossier.get("first_detected", "")

    # Calculate finding age if first_detected is available
    age_str = ""
    if first_detected:
        try:
            from datetime import datetime

            detected_dt = datetime.fromisoformat(first_detected.replace("Z", "+00:00"))
            age_days = (datetime.now(detected_dt.tzinfo) - detected_dt).days
            age_str = f" ({age_days} days ago)"
        except (ValueError, TypeError):
            pass

    # Affected projects with reachability
    project_lines: list[str] = []
    for p in dossier.get("project_details", []):
        line = (
            f"- {p['project_name']} ({p.get('project_version', '')}): "
            f"{p.get('reachability_label', 'INCONCLUSIVE')}"
        )
        if p.get("component"):
            line += f" — component: {p['component']}"
        project_lines.append(line)

    # Exploit info
    exploit_lines: list[str] = []
    for exp in dossier.get("exploit_details", []):
        exploit_lines.append(
            f"- Source: {exp.get('source', 'Unknown')}, "
            f"URL: {exp.get('url', 'N/A')}"
        )

    nvd_section = ""
    if nvd_snippet:
        nvd_section = f"\n{nvd_snippet}\n"

    prompt = f"""You are a security remediation advisor. Provide specific remediation guidance for the following CVE.

## CVE: {cve_id}
- Severity: {severity} (CVSS {cvss})
- CWE: {cwe or 'N/A'}
- EPSS: {epss * 100:.1f}th percentile
- Attack Vector: {attack_vector or 'N/A'}
- In CISA KEV: {'Yes' if kev else 'No'}
- First Detected: {first_detected or 'Unknown'}{age_str}

## Description
{description or 'No description available.'}

## Affected Components
{components_str or 'N/A'}

## Vulnerable Functions (from binary analysis)
{vuln_functions or 'None identified'}

## Affected Projects ({len(project_lines)})
{chr(10).join(project_lines) if project_lines else 'N/A'}

## Known Exploits
{chr(10).join(exploit_lines) if exploit_lines else 'None known'}
{nvd_section}
Respond in this exact format:
FIX_VERSION: <specific version number. If NVD data says "FIXED in >= X", recommend X. If NVD data says a version is "STILL VULNERABLE", the fix must be AFTER that version — do NOT recommend the vulnerable version. Cross-reference the installed component version against the NVD affected ranges. For well-known libraries (OpenSSL, curl, busybox, zlib, etc.), recall the specific patch version from security advisories. Only state "verify latest stable release" if no version data is available.>
RATIONALE: <1 sentence explaining why this fix or version is recommended, citing NVD data or advisory if available>
GUIDANCE: <1-3 sentence upgrade/remediation guidance>
WORKAROUND: <1-3 sentences: if no straightforward upgrade is available, suggest firmware-specific mitigations such as disabling affected services, network segmentation, restricting exposed interfaces, or configuration hardening. If a direct upgrade is available, state "Upgrade recommended.">
CODE_SEARCH: <grep/search patterns to find affected code in firmware — use specific vulnerable function names if known>
CONFIDENCE: <high (exact fix version confirmed via NVD data or advisory), medium (version estimated from known patterns), low (uncertain — verify independently)>"""

    return prompt


def _enrich_dossiers_with_ai(
    dossiers: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    config: Config,
) -> str | None:
    """Enrich dossier dicts with AI guidance and/or exportable prompts.

    Modifies dossiers in-place, adding:
    - ``ai_guidance``: dict with fix_version, guidance, etc. (when ``--ai``)
    - ``ai_prompt``: raw prompt string (when ``--ai-prompts``)

    Also writes a prompts markdown file when ``--ai-prompts`` is set.

    Returns:
        Path to the prompts file if written, else None.
    """
    want_live_ai = getattr(config, "ai", False)
    want_prompts = getattr(config, "ai_prompts", False)

    if not want_live_ai and not want_prompts:
        return None

    # --- Initialise NVD client for fix-version enrichment ---
    nvd = None
    try:
        from fs_report.nvd_client import NVD_ATTRIBUTION, NVDClient

        cache_dir = getattr(config, "cache_dir", None)
        cache_ttl = getattr(config, "cache_ttl", 0) or 0
        nvd_api_key = getattr(config, "nvd_api_key", None)
        nvd = NVDClient(
            api_key=nvd_api_key,
            cache_dir=cache_dir,
            cache_ttl=max(cache_ttl, 86400),
        )
        logger.info(NVD_ATTRIBUTION)

        # Batch-fetch NVD data for all dossier CVEs upfront
        cve_ids = [d["cve_id"] for d in dossiers if d.get("cve_id")]
        if cve_ids:
            logger.info(f"Fetching NVD fix data for {len(cve_ids)} CVEs...")
            nvd.get_batch(cve_ids, progress=True)
    except Exception as e:
        logger.info(f"NVD client unavailable (fix-version enrichment disabled): {e}")

    # Build row lookup by CVE ID for prompt construction
    row_by_cve: dict[str, dict[str, Any]] = {}
    for r in rows:
        row_by_cve[r["CVE ID"]] = r

    # Build prompts for every dossier
    prompts: list[tuple[str, str, str]] = []  # (cve_id, components, prompt_text)
    for d in dossiers:
        cve_id = d["cve_id"]
        row = row_by_cve.get(cve_id, {})

        # Get NVD fix snippet for this CVE
        nvd_snippet = ""
        if nvd:
            nvd_snippet = nvd.format_for_prompt(cve_id)

        prompt = _build_cve_prompt(d, row, nvd_snippet=nvd_snippet)

        if want_prompts:
            d["ai_prompt"] = prompt
            components_label = row.get("Components", "")[:80]
            prompts.append((cve_id, components_label, prompt))

        if want_live_ai:
            guidance = _call_llm_for_cve(prompt, cve_id, config)
            if guidance:
                d["ai_guidance"] = guidance

    # Write prompts file
    if want_prompts and prompts:
        return _write_prompts_file(prompts, config)
    return None


def _call_llm_for_cve(
    prompt: str,
    cve_id: str,
    config: Config,
) -> dict[str, str] | None:
    """Call the LLM for a single CVE and return parsed guidance."""
    try:
        from fs_report.llm_client import LLMClient
    except ImportError:
        logger.warning("LLM package not available; skipping AI guidance")
        return None

    cache_dir = getattr(config, "cache_dir", None)
    cache_ttl = getattr(config, "cache_ttl", 0) or 0
    provider = getattr(config, "ai_provider", None)

    # AI remediation data is stable — enforce minimum 7-day cache TTL
    cache_ttl = max(cache_ttl, 7 * 24 * 3600)

    try:
        llm = LLMClient(cache_dir=cache_dir, cache_ttl=cache_ttl, provider=provider)
    except (ValueError, ImportError) as e:
        logger.warning(f"LLM client init failed: {e}")
        return None

    try:
        text = llm._call_llm(prompt, "component", 500)
        return _parse_ai_response(text)
    except Exception as e:
        logger.warning(f"AI guidance failed for {cve_id}: {e}")
        return None


def _parse_ai_response(text: str) -> dict[str, str]:
    """Parse structured LLM response into a guidance dict.

    Supports multi-line field values — continuation lines that don't
    start with a recognized prefix are appended to the previous field.
    """
    field_map = {
        "FIX_VERSION": "fix_version",
        "RATIONALE": "rationale",
        "GUIDANCE": "guidance",
        "WORKAROUND": "workaround",
        "CODE_SEARCH": "code_search_hints",
        "CONFIDENCE": "confidence",
    }
    result: dict[str, str] = {v: "" for v in field_map.values()}
    current_key: str | None = None

    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        matched = False
        for prefix, key in field_map.items():
            if line.startswith(f"{prefix}:"):
                result[key] = line.split(":", 1)[1].strip()
                current_key = key
                matched = True
                break
        if not matched and current_key is not None:
            result[current_key] += " " + line

    # Trim and normalize
    for k in result:
        result[k] = result[k].strip()
    result["confidence"] = result.get("confidence", "medium").lower()

    return result


def _write_prompts_file(
    prompts: list[tuple[str, str, str]],
    config: Config,
) -> str:
    """Write a markdown file with all AI prompts for copy-paste use.

    Returns:
        Path to the written prompts file.
    """
    from datetime import datetime
    from pathlib import Path

    output_dir = Path(config.output_dir)
    recipe_dir = output_dir / "CVE Impact"
    recipe_dir.mkdir(parents=True, exist_ok=True)

    prompts_path = recipe_dir / "CVE Impact_prompts.md"
    lines: list[str] = [
        "# CVE Impact - AI Remediation Prompts\n",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} "
        f"| CVEs: {len(prompts)}\n",
        "\nPaste each prompt into your preferred LLM for remediation guidance.\n",
    ]

    for cve_id, components, prompt_text in prompts:
        label = f"{cve_id}"
        if components:
            label += f" ({components})"
        lines.append(f"\n---\n\n## {label}\n\n")
        lines.append(f"```\n{prompt_text}\n```\n")

    prompts_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"AI prompts written to {prompts_path}")
    return str(prompts_path)
