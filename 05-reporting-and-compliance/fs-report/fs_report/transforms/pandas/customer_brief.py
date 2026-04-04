"""
Pandas transform for the Customer Brief report.

Produces an external-facing project security brief for customers and regulators.
Requires --project scope (enforced by recipe YAML).

Returns a dict with:
- ``main``: flat DataFrame (one row per finding) for CSV fallback
- ``summary``: KPI card counts
- ``top_findings``: top 50 critical/high open findings
- ``triage_summary``: counts by triage status
- ``remediation_highlights``: P0/P1 component groups
- ``sbom_stats``: component count and ecosystem breakdown
- ``scan_metadata``: project/version/date metadata
"""

from __future__ import annotations

import base64
import logging
import time as _time
from pathlib import Path
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

_OPEN_STATUSES = {"OPEN", "NO_STATUS", "IN_TRIAGE", "UNKNOWN"}
_TRIAGED_STATUSES = {
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
    "AFFECTED",
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
}


def _extract_bool(record: dict[str, Any], *keys: str) -> bool:
    import math

    for key in keys:
        val = record.get(key)
        if isinstance(val, bool):
            return val
        if isinstance(val, float) and math.isnan(val):
            continue
        if isinstance(val, str):
            return val.lower() in ("true", "1", "yes")
        if val is not None and val is not False:
            return bool(val)
    return False


def _exploit_from_info(val: Any) -> bool:
    """Return True if the exploitInfo array/string indicates at least one exploit."""
    if isinstance(val, list):
        return len(val) > 0
    if isinstance(val, str):
        return val not in ("", "[]", "null")
    return False


def _extract_exploit_categories(val: Any) -> list[str]:
    """Extract exploit category tokens from the exploitInfo field."""
    if isinstance(val, list):
        cats: list[str] = []
        for item in val:
            if isinstance(item, dict):
                name = item.get("name") or item.get("category") or ""
                if name:
                    cats.append(str(name).lower())
            elif isinstance(item, str) and item:
                cats.append(item.lower())
        return cats
    if isinstance(val, str) and val not in ("", "[]", "null"):
        return [val.lower()]
    return []


_EXPLOIT_CATEGORY_LABELS: dict[str, str] = {
    "kev": "In KEV",
    "vckev": "VulnCheck KEV",
    "weaponized": "Weaponized",
    "poc": "PoC",
    "threatactors": "Threat Actors",
    "ransomware": "Ransomware",
    "botnets": "Botnets",
    "commercial": "Commercial",
    "reported": "Reported",
}


def _safe_str(val: Any, default: str = "") -> str:
    """Return *val* as a string, treating None / NaN / non-str as *default*."""
    if val is None:
        return default
    if isinstance(val, float):
        import math

        if math.isnan(val):
            return default
        return str(val)
    if isinstance(val, str):
        return val
    return str(val)


def _normalize_findings(raw_findings: list[dict[str, Any]]) -> pd.DataFrame:
    """Flatten nested finding records to a single-level DataFrame."""
    _EMPTY_COLS = [
        "finding_id",
        "cve_id",
        "title",
        "severity",
        "cvss_score",
        "status",
        "component",
        "component_version",
        "project_name",
        "project_id",
        "project_version",
        "project_version_id",
        "in_kev",
        "has_exploit",
        "attack_vector",
        "epss_score",
        "epss_percentile",
        "detected_date",
        "exploit_categories",
        "reachability_score",
        "description",
        "remediation",
        "mitigation",
    ]
    if not raw_findings:
        return pd.DataFrame(columns=_EMPTY_COLS)

    rows = []
    for rec in raw_findings:
        component = rec.get("component") or {}
        if not isinstance(component, dict):
            component = {}
        project = rec.get("project") or {}
        if not isinstance(project, dict):
            project = {}
        cve = rec.get("cve") or {}
        if not isinstance(cve, dict):
            cve = {}
        # projectVersion may be a nested dict with {id, version, ...}
        pv_raw = rec.get("projectVersion") or {}
        if isinstance(pv_raw, dict):
            pv_version = _safe_str(pv_raw.get("version"))
            pv_id = _safe_str(pv_raw.get("id"))
        else:
            pv_version = _safe_str(pv_raw)
            pv_id = ""

        risk_raw = rec.get("risk") or 0
        try:
            cvss_score = float(risk_raw) / 10.0
        except (ValueError, TypeError):
            cvss_score = 0.0

        epss_raw = rec.get("epssScore") or rec.get("epss_score") or 0
        try:
            epss_score = float(epss_raw)
        except (ValueError, TypeError):
            epss_score = 0.0

        epss_pct_raw = rec.get("epssPercentile") or rec.get("epss_percentile") or 0
        try:
            epss_percentile = float(epss_pct_raw)
        except (ValueError, TypeError):
            epss_percentile = 0.0

        reach_raw = rec.get("reachabilityScore") or rec.get("reachability_score") or 0
        try:
            reachability_score = float(reach_raw)
        except (ValueError, TypeError):
            reachability_score = 0.0

        exploit_info_raw = rec.get("exploitInfo") or rec.get("exploit_info")
        exploit_categories = _extract_exploit_categories(exploit_info_raw)

        raw_av = (
            _safe_str(rec.get("attackVector"))
            or _safe_str(rec.get("attack_vector"))
            or _safe_str(cve.get("attackVector"))
        )
        attack_vector = raw_av.upper() if raw_av else ""

        row = {
            "finding_id": _safe_str(rec.get("id")) or _safe_str(rec.get("findingId")),
            "cve_id": (
                _safe_str(rec.get("cveId"))
                or _safe_str(rec.get("cve_id"))
                or _safe_str(cve.get("id"))
                or _safe_str(cve.get("cveId"))
                or _safe_str(rec.get("title"))
                or _safe_str(rec.get("name"))
            ),
            "title": _safe_str(rec.get("title")) or _safe_str(rec.get("name")),
            "severity": _safe_str(rec.get("severity"), "UNKNOWN").upper(),
            "cvss_score": cvss_score,
            "status": _safe_str(rec.get("status"), "UNKNOWN").upper(),
            "component": (
                _safe_str(component.get("name"))
                or _safe_str(rec.get("componentName"))
                or _safe_str(rec.get("component_name"))
            ),
            "component_version": (
                _safe_str(component.get("version"))
                or _safe_str(rec.get("componentVersion"))
                or _safe_str(rec.get("component_version"))
            ),
            "project_name": (
                _safe_str(project.get("name"))
                or _safe_str(rec.get("projectName"))
                or _safe_str(rec.get("project_name"))
            ),
            "project_id": (
                _safe_str(project.get("id"))
                or _safe_str(rec.get("projectId"))
                or _safe_str(rec.get("project_id"))
            ),
            "project_version": (
                _safe_str(project.get("version"))
                or pv_version
                or _safe_str(rec.get("project_version"))
            ),
            "project_version_id": (
                _safe_str(project.get("versionId"))
                or _safe_str(rec.get("projectVersionId"))
                or pv_id
            ),
            "in_kev": _extract_bool(rec, "inKev", "in_kev"),
            "has_exploit": (
                _extract_bool(rec, "hasKnownExploit", "has_exploit", "hasExploit")
                or _exploit_from_info(rec.get("exploitInfo") or rec.get("exploit_info"))
            ),
            "attack_vector": attack_vector,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "exploit_categories": exploit_categories,
            "reachability_score": reachability_score,
            "detected_date": (
                _safe_str(rec.get("detectedDate"))
                or _safe_str(rec.get("detected_date"))
                or _safe_str(rec.get("detected"))
            ),
            "description": _safe_str(rec.get("description")),
            "remediation": _safe_str(rec.get("remediation")),
            "mitigation": _safe_str(rec.get("mitigation")),
        }
        rows.append(row)

    return pd.DataFrame(rows)


def _filter_detailed_findings(
    df: pd.DataFrame,
    all_severities: bool = False,
    max_findings: int = 100,
) -> pd.DataFrame:
    """Filter findings for detailed mode cards.

    Default: Critical + High + Medium-with-exploits, open only, no cap.
    all_severities=True: all severity levels, open only, capped.
    """
    if df.empty:
        return df

    open_mask = df["status"].isin(_OPEN_STATUSES)

    if all_severities:
        filtered = df[open_mask].sort_values("cvss_score", ascending=False)
        filtered = filtered.head(max_findings)
    else:
        sev_mask = df["severity"].isin({"CRITICAL", "HIGH"}) | (
            (df["severity"] == "MEDIUM") & (df["has_exploit"] == True)  # noqa: E712
        )
        filtered = df[open_mask & sev_mask].sort_values("cvss_score", ascending=False)

    return filtered


def _reachability_label(score: float) -> str:
    """Convert numeric reachability score to display label."""
    if score > 0:
        return "REACHABLE"
    if score < 0:
        return "UNREACHABLE"
    return "UNKNOWN"


def _build_component_description_map(
    components_data: list[Any],
) -> dict[tuple[str, str], str]:
    """Build (name, version) -> description lookup from components query data."""
    desc_map: dict[tuple[str, str], str] = {}
    for comp in components_data:
        if not isinstance(comp, dict):
            continue
        name = _safe_str(comp.get("name"))
        version = _safe_str(comp.get("version"))
        desc = _safe_str(comp.get("description"))
        if name and desc:
            desc_map[(name, version)] = desc
    return desc_map


def _fetch_cve_aliases(
    df: pd.DataFrame,
    api_client: Any | None,
) -> dict[str, list[str]]:
    """Fetch CVE aliases for FS-prefixed findings via per-finding API calls.

    Uses GET /public/v0/findings/{pvId}/{fId}/cves.
    Only calls for non-CVE-prefixed finding IDs.
    Returns mapping of finding_id -> list of alias CVE IDs.
    """
    if api_client is None or df.empty:
        return {}

    aliases: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()

    for _, row in df.iterrows():
        cve_id = str(row.get("cve_id", ""))
        if cve_id.startswith("CVE-"):
            continue

        fid = str(row.get("finding_id", ""))
        pvid = str(row.get("project_version_id", ""))
        if not fid or not pvid:
            continue

        key = (pvid, fid)
        if key in seen:
            continue
        seen.add(key)

        try:
            resp = api_client.get(f"/public/v0/findings/{pvid}/{fid}/cves")
            if isinstance(resp, list):
                alias_ids = [
                    str(item.get("cveId", ""))
                    for item in resp
                    if isinstance(item, dict) and item.get("cveId")
                ]
                if alias_ids:
                    aliases[fid] = alias_ids
            _time.sleep(0.5)
        except Exception:
            logger.debug(
                "Failed to fetch CVE aliases for %s/%s", pvid, fid, exc_info=True
            )

    return aliases


def _build_detail_cards(
    df: pd.DataFrame,
    comp_desc_map: dict[tuple[str, str], str],
    cve_aliases: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Build per-finding detail card dicts for template rendering."""
    if df.empty:
        return []

    cards: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        finding_id = str(row.get("finding_id", ""))
        comp_name = str(row.get("component", ""))
        comp_ver = str(row.get("component_version", ""))

        # Exploit maturity: map category tokens to display labels, falling back to raw token
        raw_cats = row.get("exploit_categories", [])
        exploit_maturity = []
        if isinstance(raw_cats, list):
            for cat in raw_cats:
                label = _EXPLOIT_CATEGORY_LABELS.get(str(cat).lower(), str(cat))
                exploit_maturity.append(label)

        cards.append(
            {
                "cve_id": str(row.get("cve_id", "")),
                "severity": str(row.get("severity", "")),
                "cvss_score": float(row.get("cvss_score", 0)),
                "epss_percentile": float(row.get("epss_percentile", 0)),
                "component": comp_name,
                "component_version": comp_ver,
                "component_description": comp_desc_map.get((comp_name, comp_ver), ""),
                "description": str(row.get("description", "")),
                "remediation": str(row.get("remediation", "")),
                "mitigation": str(row.get("mitigation", "")),
                "exploit_maturity": exploit_maturity,
                "reachability_label": _reachability_label(
                    float(row.get("reachability_score", 0))
                ),
                "in_kev": bool(row.get("in_kev", False)),
                "has_exploit": bool(row.get("has_exploit", False)),
                "attack_vector": str(row.get("attack_vector", "")),
                "status": str(row.get("status", "")),
                "cve_aliases": cve_aliases.get(finding_id, []),
                "finding_id": finding_id,
                "project_id": str(row.get("project_id", "")),
                "project_version_id": str(row.get("project_version_id", "")),
            }
        )

    return cards


def customer_brief_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config | None = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Transform for Customer Brief report."""
    if additional_data is None:
        additional_data = {}

    # data may arrive as a DataFrame (from data_transformer) or list[dict] (from tests)
    if isinstance(data, pd.DataFrame):
        if data.empty:
            raw_findings: list[dict[str, Any]] = []
        else:
            raw_findings = data.to_dict(orient="records")  # type: ignore[assignment]
    else:
        raw_findings = data if isinstance(data, list) else []
    df = _normalize_findings(raw_findings)
    total = len(df)

    # ---- KPI cards ----
    if total == 0:
        open_count = 0
        critical_count = 0
        high_count = 0
        pct_triaged = 0.0
        kev_count = 0
    else:
        open_count = int(df["status"].isin(_OPEN_STATUSES).sum())
        critical_count = int((df["severity"] == "CRITICAL").sum())
        high_count = int((df["severity"] == "HIGH").sum())
        triaged_count = int(df["status"].isin(_TRIAGED_STATUSES).sum())
        pct_triaged = round(triaged_count / total * 100, 1)
        kev_count = int(df["in_kev"].sum())

    if total == 0:
        medium_count = 0
        low_count = 0
        exploit_count = 0
    else:
        medium_count = int((df["severity"] == "MEDIUM").sum())
        low_count = int((df["severity"] == "LOW").sum())
        exploit_count = int(df["has_exploit"].sum())

    summary: dict[str, Any] = {
        "total_findings": total,
        "open_count": open_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "pct_triaged": pct_triaged,
        "kev_count": kev_count,
        "exploit_count": exploit_count,
    }

    # ---- Top findings (open/in-triage, critical+high, sorted by CVSS, top 50) ----
    if total > 0:
        top_mask = df["status"].isin(_OPEN_STATUSES) & df["severity"].isin(
            {"CRITICAL", "HIGH"}
        )
        top_df = df[top_mask].sort_values("cvss_score", ascending=False).head(50)
        top_findings: list[dict[str, Any]] = top_df[  # type: ignore[assignment]
            [
                "finding_id",
                "cve_id",
                "severity",
                "component",
                "component_version",
                "cvss_score",
                "in_kev",
                "has_exploit",
                "status",
                "reachability_score",
                "project_id",
                "project_version_id",
            ]
        ].to_dict(orient="records")
    else:
        top_findings = []

    # ---- Triage status summary ----
    if total > 0:
        sc = df["status"].value_counts().to_dict()
    else:
        sc = {}
    triage_summary: dict[str, Any] = {
        "untriaged": sc.get("OPEN", 0) + sc.get("NO_STATUS", 0) + sc.get("UNKNOWN", 0),
        "in_triage": sc.get("IN_TRIAGE", 0),
        "not_affected": sc.get("NOT_AFFECTED", 0),
        "false_positive": sc.get("FALSE_POSITIVE", 0),
        "affected": sc.get("AFFECTED", 0),
        "resolved": sc.get("RESOLVED", 0) + sc.get("RESOLVED_WITH_PEDIGREE", 0),
    }

    # ---- Remediation highlights (gate-based, consistent with Triage Prioritization) ----
    gate_highlights: dict[str, list[dict[str, Any]]] = {"GATE_1": [], "GATE_2": []}
    if total > 0:
        from fs_report.transforms.pandas.triage_prioritization import (
            _normalize_columns,
            apply_tiered_gates,
        )

        # Build a raw-style DataFrame for _normalize_columns.
        # Use the original input data (pre-normalization) so that API column
        # names like "hasKnownExploit", "reachabilityScore" are preserved.
        if isinstance(data, pd.DataFrame) and not data.empty:
            gate_df = _normalize_columns(data.copy())
        elif raw_findings:
            gate_df = _normalize_columns(pd.DataFrame(raw_findings))
        else:
            gate_df = pd.DataFrame()

        if not gate_df.empty:
            gate_df = apply_tiered_gates(gate_df)

            # Ensure we have the columns needed for grouping.
            # _normalize_columns produces component_name; overwrite the
            # raw "component" dict column with the clean string version.
            if "component_name" in gate_df.columns:
                gate_df["component"] = gate_df["component_name"]
            if "cve_id" not in gate_df.columns:
                gate_df["cve_id"] = gate_df.get("cveId", gate_df.get("findingId", ""))
            if "cvss_score" not in gate_df.columns:
                gate_df["cvss_score"] = df["cvss_score"].values if total > 0 else 0.0

            for gate_name in ["GATE_1", "GATE_2"]:
                gate_mask = gate_df["gate_assignment"] == gate_name
                if gate_mask.any():
                    groups = (
                        gate_df[gate_mask]
                        .groupby("component", as_index=False)
                        .agg(
                            finding_count=("finding_id", "count"),
                            top_cve=("cve_id", "first"),
                            worst_cvss=("cvss_score", "max"),
                        )
                        .sort_values("worst_cvss", ascending=False)
                        .head(5)
                    )
                    gate_highlights[gate_name] = groups.to_dict(orient="records")  # type: ignore[assignment]

    remediation_highlights: dict[str, Any] = {
        "gate_1": gate_highlights["GATE_1"],
        "gate_2": gate_highlights["GATE_2"],
    }

    # ---- SBOM stats (from components additional query) ----
    sbom_stats: dict[str, Any] = {"total_components": 0}
    raw_components = additional_data.get("components", [])
    if raw_components:
        version_ids = (
            set(df["project_version_id"].dropna().astype(str).unique())
            if total > 0
            else set()
        )
        matched = 0
        for comp in raw_components:
            if not isinstance(comp, dict):
                continue
            # projectVersion may be a nested dict {id, version, ...} or a scalar
            pv_field = comp.get("projectVersion") or comp.get("projectVersionId") or ""
            if isinstance(pv_field, dict):
                pv = _safe_str(pv_field.get("id"))
            else:
                pv = _safe_str(pv_field)
            if not version_ids or pv in version_ids:
                matched += 1
        sbom_stats = {"total_components": matched}

    # ---- Scan metadata ----
    scan_metadata: dict[str, Any] = {
        "project_name": "",
        "version_name": "",
        "scan_date_range": "",
    }
    if total > 0:
        scan_metadata["project_name"] = df["project_name"].iloc[0]
        scan_metadata["version_name"] = df["project_version"].iloc[0]
        dates = df["detected_date"].dropna()
        dates = dates[dates != ""]
        if not dates.empty:
            scan_metadata["scan_date_range"] = f"{dates.min()} to {dates.max()}"

    # ---- Organization name (derived from domain) ----
    domain = getattr(config, "domain", "") if config else ""
    organization = ""
    if domain:
        subdomain = domain.split(".")[0] if "." in domain else domain
        organization = subdomain.replace("-", " ").title()
    scan_metadata["organization"] = organization

    # ---- Severity distribution ----
    severity_distribution: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
    }
    if total > 0:
        vc = df["severity"].value_counts().to_dict()
        for sev in severity_distribution:
            severity_distribution[sev] = int(vc.get(sev, 0))

    # ---- Component license distribution (from components additional_data) ----
    component_license_distribution: list[dict[str, Any]] = []
    if raw_components:
        license_counter: dict[str, int] = {}
        for comp in raw_components:
            if not isinstance(comp, dict):
                continue
            lic_str = (
                _safe_str(comp.get("declaredLicenses"))
                or _safe_str(comp.get("concludedLicenses"))
                or _safe_str(comp.get("licenses"))
            )
            if lic_str:
                for part in lic_str.split(","):
                    part = part.strip()
                    if part:
                        license_counter[part] = license_counter.get(part, 0) + 1
        for lic, cnt in sorted(
            license_counter.items(), key=lambda x: x[1], reverse=True
        )[:10]:
            component_license_distribution.append({"license": lic, "count": cnt})

    # ---- Component risk ranking (top 10 by weighted score) ----
    component_risk_ranking: list[dict[str, Any]] = []
    if total > 0:
        comp_group = df.groupby(["component", "component_version"], as_index=False).agg(
            critical=("severity", lambda s: int((s == "CRITICAL").sum())),
            high=("severity", lambda s: int((s == "HIGH").sum())),
            medium=("severity", lambda s: int((s == "MEDIUM").sum())),
            low=("severity", lambda s: int((s == "LOW").sum())),
            total=("severity", "count"),
        )
        comp_group["risk_score"] = (
            comp_group["critical"] * 10
            + comp_group["high"] * 7
            + comp_group["medium"] * 4
            + comp_group["low"] * 1
        )
        comp_group = comp_group.sort_values("risk_score", ascending=False).head(10)
        component_risk_ranking = comp_group.to_dict(orient="records")  # type: ignore[assignment]

    # ---- Reachability summary ----
    reachability_summary: dict[str, Any] = {
        "reachable": 0,
        "unreachable": 0,
        "inconclusive": 0,
        "has_data": False,
    }
    if total > 0 and "reachability_score" in df.columns:
        rs = df["reachability_score"].fillna(0)
        has_any = (rs != 0).any()
        if has_any:
            reachability_summary = {
                "reachable": int((rs > 0).sum()),
                "unreachable": int((rs < 0).sum()),
                "inconclusive": int((rs == 0).sum()),
                "has_data": True,
            }

    # ---- Exploit maturity summary ----
    exploit_maturity_summary: dict[str, Any] = dict.fromkeys(
        _EXPLOIT_CATEGORY_LABELS, 0
    )
    exploit_maturity_summary["total_with_exploits"] = 0
    if total > 0:
        all_cats: list[str] = []
        for cats in df["exploit_categories"]:
            if isinstance(cats, list):
                all_cats.extend(cats)
        for cat in all_cats:
            if cat in exploit_maturity_summary:
                exploit_maturity_summary[cat] += 1
        exploit_maturity_summary["total_with_exploits"] = int(
            df["exploit_categories"]
            .apply(lambda c: len(c) > 0 if isinstance(c, list) else False)
            .sum()
        )

    # ---- Top security risks (top 10 all-severity open findings by CVSS) ----
    top_security_risks: list[dict[str, Any]] = []
    if total > 0:
        open_mask = df["status"].isin(_OPEN_STATUSES)
        risk_df = df[open_mask].sort_values("cvss_score", ascending=False).head(10)
        top_security_risks = risk_df[  # type: ignore[assignment]
            [
                "finding_id",
                "cve_id",
                "severity",
                "component",
                "component_version",
                "cvss_score",
                "epss_percentile",
                "in_kev",
                "has_exploit",
                "status",
            ]
        ].to_dict(orient="records")

    # ---- total_components for summary ----
    summary["total_components"] = sbom_stats.get("total_components", 0)

    # ---- Base64-encoded brand assets for PDF cover ----
    _assets_dir = Path(__file__).resolve().parent.parent.parent / "templates" / "assets"
    cover_image_b64 = ""
    logo_image_b64 = ""
    try:
        cover_path = _assets_dir / "cover.jpg"
        if cover_path.is_file():
            cover_image_b64 = base64.b64encode(cover_path.read_bytes()).decode("ascii")
    except Exception:
        logger.debug("Could not load cover.jpg for PDF cover", exc_info=True)
    try:
        logo_path = _assets_dir / "fs-logo.png"
        if logo_path.is_file():
            logo_image_b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    except Exception:
        logger.debug("Could not load fs-logo.png for PDF cover", exc_info=True)

    # ---- Mode (summary vs detailed) ----
    recipe_params = additional_data.get("recipe_parameters", {})
    mode = recipe_params.get("mode", "summary")

    result = {
        "main": df,
        "summary": summary,
        "top_findings": top_findings,
        "triage_summary": triage_summary,
        "remediation_highlights": remediation_highlights,
        "sbom_stats": sbom_stats,
        "scan_metadata": scan_metadata,
        "domain": domain,
        "organization": organization,
        "cover_image_b64": cover_image_b64,
        "logo_image_b64": logo_image_b64,
        "severity_distribution": severity_distribution,
        "component_license_distribution": component_license_distribution,
        "component_risk_ranking": component_risk_ranking,
        "reachability_summary": reachability_summary,
        "exploit_maturity_summary": exploit_maturity_summary,
        "top_security_risks": top_security_risks,
        "mode": mode,
    }

    if mode == "detailed":
        all_sev = recipe_params.get("all_severities", False)
        max_det = recipe_params.get("max_detailed_findings", 100)
        detailed_df = _filter_detailed_findings(
            df, all_severities=all_sev, max_findings=max_det
        )
        # Component descriptions from additional query
        raw_components = additional_data.get("components", [])
        comp_desc_map = _build_component_description_map(
            raw_components if isinstance(raw_components, list) else []
        )

        api_client = additional_data.get("api_client")
        cve_aliases = _fetch_cve_aliases(detailed_df, api_client)

        result["detailed_findings"] = _build_detail_cards(
            detailed_df, comp_desc_map, cve_aliases
        )
    else:
        result["detailed_findings"] = []

    return result
