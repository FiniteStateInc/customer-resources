"""
Pandas transform for the Assessment Overview report.

Produces an internal management snapshot for a project or folder.
Requires --project or --folder scope (enforced by recipe YAML).

Returns a dict with:
- ``main``: flat DataFrame (one row per finding)
- ``summary``: KPI card counts
- ``exploit_intel``: exploit intelligence summary
- ``triage_pipeline``: triage status counts
- ``remediation_progress``: P0/P1 component groups
- ``scan_metadata``: project/version/scan date metadata
- ``project_cards``: per-project breakdown (folder scope only)
- ``severity_distribution``: counts by severity level
- ``exploit_maturity_summary``: counts by exploit category
- ``reachability_summary``: reachable/unreachable/inconclusive
- ``top_security_risks``: top 10 open findings by CVSS
- ``component_risk_ranking``: top 10 components by weighted score
- ``sbom_stats``: component count from SBOM data
- ``component_license_distribution``: top 10 licenses
- ``findings_by_tier``: findings grouped by severity tier
"""

from __future__ import annotations

import logging
import math
from datetime import date
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
_EPSS_HIGH_THRESHOLD = 0.5

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

_TIER_COLS = [
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
    "project_name",
    "project_id",
    "project_version_id",
]


def _safe_str(val: Any, default: str = "") -> str:
    """Convert a value to string, treating NaN/None as *default*."""
    if val is None:
        return default
    if isinstance(val, float) and math.isnan(val):
        return default
    s = str(val).strip()
    return s if s else default


def _exploit_from_info(val: Any) -> bool:
    """Return True if the exploitInfo array/string indicates at least one exploit."""
    if isinstance(val, list):
        return len(val) > 0
    if isinstance(val, str):
        return val not in ("", "[]", "null")
    return False


def _extract_bool(record: dict[str, Any], *keys: str) -> bool:
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
        "exploit_categories",
        "reachability_score",
        "detected_date",
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
            rec.get("attackVector")
            or rec.get("attack_vector")
            or cve.get("attackVector")
            or ""
        )
        attack_vector = str(raw_av).upper() if raw_av else ""

        row = {
            "finding_id": rec.get("id") or rec.get("findingId") or "",
            "cve_id": (
                rec.get("cveId")
                or rec.get("cve_id")
                or cve.get("id")
                or cve.get("cveId")
                or rec.get("title")
                or rec.get("name")
                or ""
            ),
            "title": _safe_str(rec.get("title")) or _safe_str(rec.get("name")),
            "severity": _safe_str(rec.get("severity"), "UNKNOWN").upper(),
            "cvss_score": cvss_score,
            "status": _safe_str(rec.get("status"), "UNKNOWN").upper(),
            "component": (
                component.get("name")
                or rec.get("componentName")
                or rec.get("component_name")
                or ""
            ),
            "component_version": (
                component.get("version")
                or rec.get("componentVersion")
                or rec.get("component_version")
                or ""
            ),
            "project_name": (
                project.get("name")
                or rec.get("projectName")
                or rec.get("project_name")
                or ""
            ),
            "project_id": (
                project.get("id") or rec.get("projectId") or rec.get("project_id") or ""
            ),
            "project_version": (
                project.get("version") or pv_version or rec.get("project_version") or ""
            ),
            "project_version_id": (
                project.get("versionId") or rec.get("projectVersionId") or pv_id or ""
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
            "detected_date": rec.get("detected")
            or rec.get("detectedDate")
            or rec.get("detected_date")
            or "",
        }
        rows.append(row)

    return pd.DataFrame(rows)


def assessment_overview_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config | None = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Transform for Assessment Overview report."""
    if additional_data is None:
        additional_data = {}

    if isinstance(data, pd.DataFrame):
        if data.empty:
            raw_findings: list[dict[str, Any]] = []
        else:
            raw_findings = [
                {str(k): v for k, v in r.items()}
                for r in data.to_dict(orient="records")
            ]
    else:
        raw_findings = data if isinstance(data, list) else []
    df = _normalize_findings(raw_findings)
    total = len(df)

    # ---- KPI cards ----
    if total == 0:
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        epss_high_count = 0
        open_count = 0
        triaged_count = 0
        exploit_count = 0
    else:
        critical_count = int((df["severity"] == "CRITICAL").sum())
        high_count = int((df["severity"] == "HIGH").sum())
        medium_count = int((df["severity"] == "MEDIUM").sum())
        low_count = int((df["severity"] == "LOW").sum())
        epss_high_count = int((df["epss_score"] >= _EPSS_HIGH_THRESHOLD).sum())
        open_count = int(df["status"].isin(_OPEN_STATUSES).sum())
        triaged_count = int(df["status"].isin(_TRIAGED_STATUSES).sum())
        exploit_count = int(df["has_exploit"].sum())

    summary: dict[str, Any] = {
        "total_findings": total,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "epss_high_count": epss_high_count,
        "open_count": open_count,
        "triaged_count": triaged_count,
        "exploit_count": exploit_count,
    }

    # ---- Exploit intelligence ----
    if total > 0:
        kev_count = int(df["in_kev"].sum())
        has_exploit_count = int(df["has_exploit"].sum())
        epss_count = int((df["epss_score"] >= _EPSS_HIGH_THRESHOLD).sum())
    else:
        kev_count = 0
        has_exploit_count = 0
        epss_count = 0

    exploit_intel: dict[str, Any] = {
        "kev_count": kev_count,
        "has_exploit_count": has_exploit_count,
        "epss_high_count": epss_count,
    }

    # ---- Triage pipeline ----
    if total > 0:
        sc = df["status"].value_counts().to_dict()
        exploitable_count = int(
            (df["status"].isin(_OPEN_STATUSES) & df["has_exploit"]).sum()
        )
    else:
        sc = {}
        exploitable_count = 0

    # Check for VEX recommendations in additional_data
    vex_recs = additional_data.get("vex_recommendations", [])
    vex_summary: dict[str, Any] = {}
    if vex_recs and isinstance(vex_recs, list):
        vex_summary = {
            "count": len(vex_recs),
            "top_components": list(
                {
                    r.get("component", "") or r.get("componentName", "")
                    for r in vex_recs[:10]
                    if isinstance(r, dict)
                }
            )[:5],
        }

    triage_pipeline: dict[str, Any] = {
        "in_triage": sc.get("IN_TRIAGE", 0),
        "affected": sc.get("AFFECTED", 0),
        "exploitable": exploitable_count,
        "vex_summary": vex_summary,
    }

    # ---- Remediation progress ----
    p0_items: list[dict[str, Any]] = []
    p1_items: list[dict[Any, Any]] = []
    top_p0_cves: list[dict[Any, Any]] = []

    if total > 0:
        active_mask = df["status"].isin(_OPEN_STATUSES)

        # P0: CRITICAL with exploit or KEV
        p0_mask = (
            active_mask
            & (df["severity"] == "CRITICAL")
            & (df["has_exploit"] | df["in_kev"])
        )
        if p0_mask.any():
            p0_df = df[p0_mask]
            p0_groups = (
                p0_df.groupby("component", as_index=False)
                .agg(
                    finding_count=("finding_id", "count"),
                    top_cve=("cve_id", "first"),
                    worst_cvss=("cvss_score", "max"),
                    project=("project_name", "first"),
                )
                .sort_values("worst_cvss", ascending=False)
                .head(5)
            )
            p0_items = p0_groups.to_dict(orient="records")  # type: ignore[assignment]
            # Top 5 P0 CVEs (include link fields for CVE deep links)
            top_p0_cves = (
                p0_df[
                    [
                        "finding_id",
                        "cve_id",
                        "component",
                        "cvss_score",
                        "project_name",
                        "project_id",
                        "project_version_id",
                    ]
                ]
                .sort_values("cvss_score", ascending=False)
                .head(5)
                .to_dict(orient="records")
            )

        # P1: HIGH with network attack vector
        p1_mask = (
            active_mask
            & (df["severity"] == "HIGH")
            & (df["attack_vector"] == "NETWORK")
        )
        if p1_mask.any():
            p1_groups = (
                df[p1_mask]
                .groupby("component", as_index=False)
                .agg(
                    finding_count=("finding_id", "count"),
                    top_cve=("cve_id", "first"),
                    worst_cvss=("cvss_score", "max"),
                )
                .sort_values("worst_cvss", ascending=False)
                .head(5)
            )
            p1_items = p1_groups.to_dict(orient="records")

    remediation_progress: dict[str, Any] = {
        "p0_count": len(p0_items),
        "p1_count": len(p1_items),
        "p0_components": p0_items,
        "p1_components": p1_items,
        "top_p0_cves": top_p0_cves,
    }

    # ---- Scan metadata ----
    today = date.today()
    scan_metadata: dict[str, Any] = {
        "project_name": "",
        "version_name": "",
        "scan_date": "",
        "days_since_scan": None,
    }
    if total > 0:
        scan_metadata["project_name"] = df["project_name"].iloc[0]
        scan_metadata["version_name"] = df["project_version"].iloc[0]
        dates = df["detected_date"].dropna()
        dates = dates[dates != ""]
        if not dates.empty:
            latest = dates.max()
            scan_metadata["scan_date"] = str(latest)
            try:
                scan_dt = pd.to_datetime(latest, errors="coerce")
                if scan_dt is not None and not pd.isna(scan_dt):
                    days = (today - scan_dt.date()).days
                    scan_metadata["days_since_scan"] = max(0, days)
            except Exception:
                pass

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

    # ---- Reachability summary ----
    reachability_summary: dict[str, Any] = {
        "reachable": 0,
        "unreachable": 0,
        "inconclusive": 0,
        "has_data": False,
    }
    if total > 0 and "reachability_score" in df.columns:
        rs = df["reachability_score"]
        has_any = (rs != 0).any()
        if has_any:
            reachability_summary = {
                "reachable": int((rs > 0).sum()),
                "unreachable": int((rs < 0).sum()),
                "inconclusive": int((rs == 0).sum()),
                "has_data": True,
            }

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
                "project_id",
                "project_version_id",
            ]
        ].to_dict(orient="records")

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
            pv_field = comp.get("projectVersion") or comp.get("projectVersionId") or ""
            if isinstance(pv_field, dict):
                pv = _safe_str(pv_field.get("id"))
            else:
                pv = _safe_str(pv_field)
            if not version_ids or pv in version_ids:
                matched += 1
        sbom_stats = {"total_components": matched}

    # ---- Component license distribution (from components additional_data) ----
    component_license_distribution: list[dict[str, Any]] = []
    if raw_components:
        # Scope licenses to version IDs present in findings
        version_ids_lic = (
            set(df["project_version_id"].dropna().astype(str).unique())
            if total > 0
            else set()
        )
        license_counter: dict[str, int] = {}
        for comp in raw_components:
            if not isinstance(comp, dict):
                continue
            pv_field = comp.get("projectVersion") or comp.get("projectVersionId") or ""
            if isinstance(pv_field, dict):
                pv = _safe_str(pv_field.get("id"))
            else:
                pv = _safe_str(pv_field)
            if version_ids_lic and pv not in version_ids_lic:
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

    # ---- Component inventory for expandable SBOM list ----
    component_inventory: list[dict[str, str]] = []
    if raw_components:
        for comp in raw_components:
            if not isinstance(comp, dict):
                continue
            pv_field = comp.get("projectVersion") or comp.get("projectVersionId") or ""
            if isinstance(pv_field, dict):
                pv = _safe_str(pv_field.get("id"))
            else:
                pv = _safe_str(pv_field)
            if version_ids and pv not in version_ids:
                continue
            component_inventory.append(
                {
                    "name": _safe_str(comp.get("name"), "Unknown"),
                    "version": _safe_str(comp.get("version"), ""),
                    "type": _safe_str(comp.get("type"), ""),
                    "license": (
                        _safe_str(comp.get("declaredLicenses"))
                        or _safe_str(comp.get("concludedLicenses"))
                        or ""
                    ),
                }
            )
        component_inventory.sort(key=lambda c: c["name"].lower())

    # ---- total_components for summary ----
    summary["total_components"] = sbom_stats.get("total_components", 0)

    # ---- Findings by tier (severity-based priority allocation, cap 2000) ----
    findings_by_tier: dict[str, list[dict[str, Any]]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFORMATIONAL": [],
    }
    if total > 0:
        tier_cap = 2000
        tier_used = 0
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            if tier_used >= tier_cap:
                break
            sev_mask = df["severity"] == sev
            sev_df = df[sev_mask].sort_values("cvss_score", ascending=False)
            remaining = tier_cap - tier_used
            sev_df = sev_df.head(remaining)
            tier_cols = [c for c in _TIER_COLS if c in sev_df.columns]
            findings_by_tier[sev] = sev_df[tier_cols].to_dict(orient="records")  # type: ignore[assignment]
            tier_used += len(sev_df)

    # ---- Project cards (folder scope only) ----
    project_cards: list[dict[str, Any]] = []
    if total > 0 and getattr(config, "folder_filter", None):
        for proj_name, proj_df in df.groupby("project_name"):
            proj_critical = int((proj_df["severity"] == "CRITICAL").sum())
            proj_high = int((proj_df["severity"] == "HIGH").sum())
            proj_medium = int((proj_df["severity"] == "MEDIUM").sum())
            proj_low = int((proj_df["severity"] == "LOW").sum())
            proj_open = int(proj_df["status"].isin(_OPEN_STATUSES).sum())
            proj_total = len(proj_df)

            # Top 5 findings by CVSS
            top5 = (
                proj_df.sort_values("cvss_score", ascending=False)
                .head(5)[
                    [
                        "finding_id",
                        "cve_id",
                        "severity",
                        "cvss_score",
                        "component",
                    ]
                ]
                .to_dict(orient="records")
            )

            # Riskiest component (by weighted score)
            comp_scores = proj_df.groupby("component", as_index=False).agg(
                critical=("severity", lambda s: int((s == "CRITICAL").sum())),
                high=("severity", lambda s: int((s == "HIGH").sum())),
                medium=("severity", lambda s: int((s == "MEDIUM").sum())),
                low=("severity", lambda s: int((s == "LOW").sum())),
            )
            comp_scores["risk_score"] = (
                comp_scores["critical"] * 10
                + comp_scores["high"] * 7
                + comp_scores["medium"] * 4
                + comp_scores["low"] * 1
            )
            comp_scores = comp_scores.sort_values("risk_score", ascending=False)
            if not comp_scores.empty:
                riskiest_component = comp_scores.iloc[0]["component"]
                riskiest_score = int(comp_scores.iloc[0]["risk_score"])
            else:
                riskiest_component = ""
                riskiest_score = 0

            project_cards.append(
                {
                    "project_name": proj_name,
                    "total": proj_total,
                    "critical": proj_critical,
                    "high": proj_high,
                    "medium": proj_medium,
                    "low": proj_low,
                    "open": proj_open,
                    "top_findings": top5,
                    "riskiest_component": riskiest_component,
                    "riskiest_score": riskiest_score,
                }
            )
        project_cards.sort(key=lambda c: c["critical"], reverse=True)

    domain = getattr(config, "domain", "") if config else ""
    # domain may also be injected via additional_data (from report_engine)
    if not domain:
        domain = additional_data.get("domain", "")

    return {
        "main": df,
        "summary": summary,
        "exploit_intel": exploit_intel,
        "triage_pipeline": triage_pipeline,
        "remediation_progress": remediation_progress,
        "scan_metadata": scan_metadata,
        "project_cards": project_cards,
        "domain": domain,
        "severity_distribution": severity_distribution,
        "exploit_maturity_summary": exploit_maturity_summary,
        "reachability_summary": reachability_summary,
        "top_security_risks": top_security_risks,
        "component_risk_ranking": component_risk_ranking,
        "sbom_stats": sbom_stats,
        "component_license_distribution": component_license_distribution,
        "component_inventory": component_inventory,
        "findings_by_tier": findings_by_tier,
    }
