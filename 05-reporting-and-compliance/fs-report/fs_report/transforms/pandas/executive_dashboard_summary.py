"""Executive Dashboard summary-mode transform.

Consumes the dict produced by ReportEngine._fetch_exec_dashboard_summary
and emits the `additional_data` shape the existing Jinja template
expects (sca_summary, license_bar, license_kpis, policy_health,
findings_by_folder, findings_by_project, project_table, exploit_intel,
findings_by_type, open_issues_pie, risk_donut, top_risk_products,
severity_trends, finding_age), plus top-level `mode`, `partial_report`,
and `failed_projects` keys.

Re-uses builders from executive_dashboard.py where the data shape is
identical (Policy Health, License Bar, License KPIs). Summary-specific
builders live in this module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def _gather_all_components(projects: list[dict]) -> list[dict]:
    """Concatenate components across all in-scope projects.

    Used to feed License Bar / License KPIs / Policy Health builders,
    which expect a flat component list.
    """
    out: list[dict] = []
    for proj in projects:
        for comp in proj.get("components", []) or []:
            out.append(comp)
    return out


def _build_sca_summary_from_rollups(
    projects: list[dict],
    start_date: Any,
    end_date: Any,
) -> dict[str, Any]:
    """SCA Summary KPIs derived from the per-project data we already fetched.

    Source precedence:
      * **findings** — ``summary_counts.severities.total`` (live per-version
        aggregate from the platform). Falls back to ``latestVersion.findings``
        when the summary-count call failed for this project.
      * **components / violations / warnings** — summed from the per-project
        ``components`` list that the batched /components fetch populated.
        Falls back to ``latestVersion`` rollups when the component list
        is missing.

    The fallback matters because the structured-table cache for /projects
    (``PROJECT_FIELDS`` in sqlite_cache.py) does not preserve
    ``latestVersion.{findings,components,violations,warnings}``, so a
    pure-rollup aggregation on cached data silently reports zero.
    """
    projects_count = len(projects)
    total_findings = 0
    total_components = 0
    total_violations = 0
    total_warnings = 0
    for proj in projects:
        lv = proj.get("latestVersion") or {}

        # Findings: prefer live summary_counts total; fall back to rollup.
        sev = (proj.get("summary_counts") or {}).get("severities") or {}
        if sev:
            total_findings += int(sev.get("total") or 0)
        else:
            total_findings += int(lv.get("findings") or 0)

        # Components / violations / warnings: prefer fetched list; fall back.
        comps = proj.get("components")
        if comps:
            total_components += len(comps)
            for c in comps:
                total_violations += int(c.get("violations") or 0)
                total_warnings += int(c.get("warnings") or 0)
        else:
            total_components += int(lv.get("components") or 0)
            total_violations += int(lv.get("violations") or 0)
            total_warnings += int(lv.get("warnings") or 0)

    return {
        "projects": projects_count,
        "components": total_components,
        "findings": total_findings,
        "violations": total_violations,
        "warnings": total_warnings,
        "findings_delta": None,
        "components_delta": None,
        "violations_delta": None,
        "warnings_delta": None,
    }


# ---------------------------------------------------------------------------
# Per-project aggregations (from summary_counts payloads)
# ---------------------------------------------------------------------------

_SEVERITY_LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
_SEVERITY_KEY_LOOKUP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "none",
}
_SEVERITY_COLORS_SUMMARY = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#f57c00",
    "MEDIUM": "#fbc02d",
    "LOW": "#7cb342",
    "NONE": "#9e9e9e",
}


def _severity_vec(proj: dict) -> dict[str, int]:
    sc = (proj.get("summary_counts") or {}).get("severities") or {}
    by = sc.get("bySeverity") or {}
    return {
        label: int(by.get(_SEVERITY_KEY_LOOKUP[label], 0) or 0)
        for label in _SEVERITY_LABELS
    }


def _build_findings_by_folder_from_summaries(projects: list[dict]) -> dict[str, Any]:
    """Stacked bar: findings by folder × severity."""
    folder_totals: dict[str, dict[str, int]] = {}
    for proj in projects:
        folder_name = (proj.get("folder") or {}).get("name") or "(unfoldered)"
        sev = _severity_vec(proj)
        bucket = folder_totals.setdefault(
            folder_name, dict.fromkeys(_SEVERITY_LABELS, 0)
        )
        for lbl in _SEVERITY_LABELS:
            bucket[lbl] += sev[lbl]

    labels = sorted(folder_totals.keys())
    datasets = [
        {
            "label": lbl,
            "data": [folder_totals[f][lbl] for f in labels],
            "backgroundColor": _SEVERITY_COLORS_SUMMARY[lbl],
        }
        for lbl in _SEVERITY_LABELS
    ]
    return {"labels": labels, "datasets": datasets}


def _build_findings_by_project_from_summaries(
    projects: list[dict],
    max_projects: int = 0,
) -> dict[str, Any]:
    """Stacked bar: findings by project × severity. Top-N ordered by total desc.
    Overflow goes into an 'Other' bucket."""
    enriched = []
    for proj in projects:
        sev = _severity_vec(proj)
        total = sum(sev.values())
        enriched.append((proj.get("name", ""), total, sev))
    enriched.sort(key=lambda t: t[1], reverse=True)

    if max_projects and max_projects > 0 and len(enriched) > max_projects:
        top = enriched[:max_projects]
        rest = enriched[max_projects:]
        other_sev = dict.fromkeys(_SEVERITY_LABELS, 0)
        for _, _, sev in rest:
            for lbl in _SEVERITY_LABELS:
                other_sev[lbl] += sev[lbl]
        top.append(("Other", sum(other_sev.values()), other_sev))
        enriched = top

    labels = [name for name, _, _ in enriched]
    datasets = [
        {
            "label": lbl,
            "data": [sev[lbl] for _, _, sev in enriched],
            "backgroundColor": _SEVERITY_COLORS_SUMMARY[lbl],
        }
        for lbl in _SEVERITY_LABELS
    ]
    return {"labels": labels, "datasets": datasets}


_EXPLOIT_ORDER = [
    ("KEV", "kev"),
    ("VC KEV", "vckev"),
    ("PoC", "poc"),
    ("Weaponized", "weaponized"),
    ("Ransomware", "ransomware"),
    ("Botnets", "botnets"),
    ("Threat Actors", "threatactors"),
    ("Commercial", "commercial"),
    ("Reported", "reported"),
]


def _build_exploit_intel_expanded(projects: list[dict]) -> dict[str, Any]:
    """Exploit Intelligence: 9 categories summed across projects."""
    totals = {key: 0 for _, key in _EXPLOIT_ORDER}
    for proj in projects:
        exp = (proj.get("summary_counts") or {}).get("exploit") or {}
        by = exp.get("byExploit") or {}
        for _, key in _EXPLOIT_ORDER:
            totals[key] += int(by.get(key, 0) or 0)

    return {
        "labels": [label for label, _ in _EXPLOIT_ORDER],
        "data": [totals[key] for _, key in _EXPLOIT_ORDER],
    }


_TRIAGE_STATUS_ORDER = [
    ("No Status", "noStatus", "#9e9e9e"),
    ("Not Affected", "notAffected", "#4caf50"),
    ("False Positive", "falsePositive", "#2196f3"),
    ("In Triage", "inTriage", "#fbc02d"),
    ("Resolved", "resolved", "#388e3c"),
    ("Resolved w/ Pedigree", "resolvedWithPedigree", "#558b2f"),
    ("Exploitable", "exploitable", "#d32f2f"),
]


def _build_findings_by_triage_status(projects: list[dict]) -> dict[str, Any]:
    """Pie: findings by VEX triage status (summed across projects).

    Template passes `backgroundColor` straight to Chart.js, so it MUST
    be emitted here.
    """
    totals = {key: 0 for _, key, _ in _TRIAGE_STATUS_ORDER}
    for proj in projects:
        status = (proj.get("summary_counts") or {}).get("status") or {}
        by = status.get("byStatus") or {}
        for _, key, _ in _TRIAGE_STATUS_ORDER:
            totals[key] += int(by.get(key, 0) or 0)

    return {
        "labels": [label for label, _, _ in _TRIAGE_STATUS_ORDER],
        "data": [totals[key] for _, key, _ in _TRIAGE_STATUS_ORDER],
        "backgroundColor": [color for _, _, color in _TRIAGE_STATUS_ORDER],
    }


_CATEGORY_ORDER = [
    ("CVEs", "cve"),
    ("Config Issues", "configIssues"),
    ("Credentials", "credentials"),
    ("Crypto Material", "cryptoMaterial"),
    ("SAST", "sastAnalysis"),
]


def _build_findings_by_type_from_summaries(projects: list[dict]) -> dict[str, Any]:
    """Horizontal bar: findings by category (sum byCategory)."""
    totals = {key: 0 for _, key in _CATEGORY_ORDER}
    for proj in projects:
        cat = (proj.get("summary_counts") or {}).get("category") or {}
        by = cat.get("byCategory") or {}
        for _, key in _CATEGORY_ORDER:
            totals[key] += int(by.get(key, 0) or 0)

    return {
        "labels": [label for label, _ in _CATEGORY_ORDER],
        "data": [totals[key] for _, key in _CATEGORY_ORDER],
    }


def _score_project(sev: dict[str, int], kev: int) -> float:
    """Risk score matching executive_dashboard.py:_build_risk_donut_and_table.
    Formula: min(100, critical*10 + high*5 + medium*2 + low*0.5).
    KEV is tracked separately in top_risk_products as the `kev` column
    and does not contribute to the score.
    """
    return min(
        100.0,
        sev["CRITICAL"] * 10 + sev["HIGH"] * 5 + sev["MEDIUM"] * 2 + sev["LOW"] * 0.5,
    )


def _build_risk_donut_and_top_products_from_summaries(
    projects: list[dict],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Donut + top 15 products table, matching executive_dashboard.py shape.

    Donut buckets projects by max severity; top table uses risk_score.
    """
    bucket_order = ["Critical", "High", "Medium", "Low", "None"]
    bucket_colors = [
        _SEVERITY_COLORS_SUMMARY["CRITICAL"],
        _SEVERITY_COLORS_SUMMARY["HIGH"],
        _SEVERITY_COLORS_SUMMARY["MEDIUM"],
        _SEVERITY_COLORS_SUMMARY["LOW"],
        _SEVERITY_COLORS_SUMMARY["NONE"],
    ]
    buckets = dict.fromkeys(bucket_order, 0)
    project_scores: dict[str, dict[str, Any]] = {}

    for proj in projects:
        sev = _severity_vec(proj)
        exp = (proj.get("summary_counts") or {}).get("exploit") or {}
        kev = int((exp.get("byExploit") or {}).get("kev", 0) or 0)
        total = sum(sev.values())

        # Bucket by max severity present
        if sev["CRITICAL"] > 0:
            buckets["Critical"] += 1
        elif sev["HIGH"] > 0:
            buckets["High"] += 1
        elif sev["MEDIUM"] > 0:
            buckets["Medium"] += 1
        elif sev["LOW"] > 0:
            buckets["Low"] += 1
        else:
            buckets["None"] += 1

        project_scores[proj.get("name", "")] = {
            "score": _score_project(sev, kev),
            "critical": sev["CRITICAL"],
            "high": sev["HIGH"],
            "medium": sev["MEDIUM"],
            "low": sev["LOW"],
            "total": total,
            "kev": kev,
        }

    donut_labels = []
    donut_data = []
    donut_colors = []
    for label, color in zip(bucket_order, bucket_colors, strict=True):
        if buckets[label] > 0:
            donut_labels.append(label)
            donut_data.append(buckets[label])
            donut_colors.append(color)

    donut = {
        "labels": donut_labels,
        "data": donut_data,
        "backgroundColor": donut_colors,
        "total_artifacts": len(projects),
    }

    sorted_projects = sorted(
        project_scores.items(), key=lambda kv: kv[1]["score"], reverse=True
    )[:15]
    top_products = [
        {
            "project": name,
            "risk_score": round(info["score"], 1),
            "critical": info["critical"],
            "high": info["high"],
            "medium": info["medium"],
            "low": info["low"],
            "total": info["total"],
            "kev": info["kev"],
        }
        for name, info in sorted_projects
    ]
    return donut, top_products


def _build_project_table_from_summaries(projects: list[dict]) -> list[dict[str, Any]]:
    """Per-project severity + KEV table, sorted by total desc."""
    rows = []
    for proj in projects:
        sev = _severity_vec(proj)
        exp = (proj.get("summary_counts") or {}).get("exploit") or {}
        kev = int((exp.get("byExploit") or {}).get("kev", 0) or 0)
        total = sum(sev.values())
        rows.append(
            {
                "project": proj.get("name", ""),
                "critical": sev["CRITICAL"],
                "high": sev["HIGH"],
                "medium": sev["MEDIUM"],
                "low": sev["LOW"],
                "total": total,
                "kev": kev,
            }
        )
    rows.sort(key=lambda r: r["total"], reverse=True)
    return rows


# ---------------------------------------------------------------------------
# Time-based builders (from /versions history; no extra API calls)
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    """Wrapped for test override."""
    return datetime.now(UTC)


def _parse_iso(s: str) -> datetime | None:
    if not s or not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _month_iter(start_iso: str, end_iso: str) -> list[tuple[int, int]]:
    """Yield (year, month) tuples for each month in [start..end] inclusive."""
    start = (
        _parse_iso(f"{start_iso}T00:00:00Z")
        if len(start_iso) == 10
        else _parse_iso(start_iso)
    )
    end = (
        _parse_iso(f"{end_iso}T23:59:59Z")
        if len(end_iso) == 10
        else _parse_iso(end_iso)
    )
    if start is None or end is None:
        return []
    months: list[tuple[int, int]] = []
    y, m = start.year, start.month
    while (y, m) <= (end.year, end.month):
        months.append((y, m))
        m += 1
        if m > 12:
            m = 1
            y += 1
    return months


def _month_end_findingcount(versions: list[dict], year: int, month: int) -> int:
    """Return findingCount of the version whose `created` is the latest
    timestamp <= end-of-month. 0 if no such version exists."""
    # End of month (last day, 23:59:59 UTC)
    if month == 12:
        next_y, next_m = year + 1, 1
    else:
        next_y, next_m = year, month + 1
    # Inclusive end: one microsecond before the first of next month
    cutoff = datetime(next_y, next_m, 1, tzinfo=UTC)

    best: tuple[datetime, int] | None = None
    for v in versions:
        created = _parse_iso(v.get("created", ""))
        if created is None:
            continue
        if created < cutoff:
            if best is None or created > best[0]:
                best = (created, int(v.get("findingCount") or 0))
    return best[1] if best else 0


def _build_severity_trends_total(
    projects: list[dict], start_date: Any, end_date: Any
) -> dict[str, Any]:
    """Month-end inventory of findingCount summed across projects.

    Summary mode plots a single 'Total Findings' line. Per-severity
    (Critical/High) breakdown remains --detailed only.
    """
    if not start_date or not end_date:
        return {"labels": [], "datasets": [], "month_count": 0}

    months = _month_iter(str(start_date), str(end_date))
    if not months:
        return {"labels": [], "datasets": [], "month_count": 0}

    monthly_totals: list[int] = []
    for year, month in months:
        total = 0
        for proj in projects:
            hist = proj.get("versions_history") or []
            total += _month_end_findingcount(hist, year, month)
        monthly_totals.append(total)

    labels = [f"{y}-{m:02d}" for y, m in months]
    return {
        "labels": labels,
        "month_count": len(labels),
        # Expose the requested window so the template can title the chart
        # by the actual period instead of a derived month count (a 30-day
        # window that crosses a month boundary produces 2 labels, making
        # "2 Months" misleading when the user asked for 30 days).
        "start_date": str(start_date),
        "end_date": str(end_date),
        "datasets": [
            {
                "label": "Total Findings",
                "data": monthly_totals,
                "borderColor": "#1976d2",
                "backgroundColor": "#1976d233",
                "tension": 0.3,
                "fill": False,
            }
        ],
    }


_AGE_BUCKETS = [
    ("0-30d", 30),
    ("30-90d", 90),
    ("90-180d", 180),
    ("180d-1y", 365),
    ("1y+", None),  # open-ended
]


def _build_finding_age_by_version_age(projects: list[dict]) -> dict[str, Any]:
    """Bucket each project's latest-version finding count by the age
    (in days) of that version's `created` timestamp.

    Semantic: 'findings living in code of age X'. Executive interpretation:
    how stale is the codebase our current issues live in.

    Finding count is sourced from ``summary_counts.severities.total`` (live,
    per-version); falls back to ``latestVersion.findings`` when the
    summary-count call failed. The cached ``/projects`` response strips
    the rollup field, so reading from ``latestVersion.findings`` alone
    produces zeros on every warm-cache run.
    """
    now = _now_utc()
    buckets = {label: 0 for label, _ in _AGE_BUCKETS}

    for proj in projects:
        lv = proj.get("latestVersion") or {}
        lv_id = lv.get("id")
        sev = (proj.get("summary_counts") or {}).get("severities") or {}
        if sev:
            findings = int(sev.get("total") or 0)
        else:
            findings = int(lv.get("findings") or 0)
        if not lv_id or findings == 0:
            continue

        # Find the version created date from the history
        hist = proj.get("versions_history") or []
        match = next((v for v in hist if str(v.get("id")) == str(lv_id)), None)
        if match is None:
            continue
        created = _parse_iso(match.get("created", ""))
        if created is None:
            continue

        age_days = (now - created).days
        for label, upper in _AGE_BUCKETS:
            if upper is None:
                # 1y+ catch-all
                buckets[label] += findings
                break
            if age_days < upper:
                buckets[label] += findings
                break

    return {
        "labels": [label for label, _ in _AGE_BUCKETS],
        "data": [buckets[label] for label, _ in _AGE_BUCKETS],
    }


def executive_dashboard_summary_transform(
    data: Any,
    additional_data: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Top-level summary-mode transform.

    Args:
        data: Unused (pandas DataFrame placeholder for interface parity).
        additional_data: Dict from _fetch_exec_dashboard_summary — has
            'projects', 'mode', 'partial_report', 'failed_projects'.
        start_date / end_date: optional, used for Severity Trends window.
    """
    from fs_report.transforms.pandas.executive_dashboard import (
        _build_license_bar,
        _build_license_kpis,
        _build_policy_health,
    )

    ad = additional_data or {}
    projects = ad.get("projects") or []
    start_date = kwargs.get("start_date")
    end_date = kwargs.get("end_date")

    # Components across all projects — for reused builders
    all_components = _gather_all_components(projects)
    # Policy Health's existing signature expects project_ids filter; pass empty
    # set so it counts every component passed in.
    policy_health = _build_policy_health(all_components, set())
    license_bar = _build_license_bar(all_components, set())
    license_kpis = _build_license_kpis(all_components, set())

    # Summary-specific builders
    sca_summary = _build_sca_summary_from_rollups(projects, start_date, end_date)
    findings_by_folder = _build_findings_by_folder_from_summaries(projects)
    # Recipe parameter: limit number of projects in the findings-by-project chart
    recipe_params = ad.get("recipe_parameters") or {}
    max_projects = int(recipe_params.get("max_projects", 0) or 0)

    findings_by_project = _build_findings_by_project_from_summaries(
        projects, max_projects=max_projects
    )
    project_table = _build_project_table_from_summaries(projects)
    exploit_intel = _build_exploit_intel_expanded(projects)
    findings_by_type = _build_findings_by_type_from_summaries(projects)
    open_issues_pie = _build_findings_by_triage_status(projects)
    risk_donut, top_risk_products = _build_risk_donut_and_top_products_from_summaries(
        projects
    )
    severity_trends = _build_severity_trends_total(projects, start_date, end_date)
    finding_age = _build_finding_age_by_version_age(projects)

    return {
        "mode": "summary",
        "partial_report": bool(ad.get("partial_report")),
        "failed_projects": list(ad.get("failed_projects") or []),
        "sca_summary": sca_summary,
        "policy_health": policy_health,
        "license_bar": license_bar,
        "license_kpis": license_kpis,
        "findings_by_folder": findings_by_folder,
        "findings_by_project": findings_by_project,
        "project_table": project_table,
        "exploit_intel": exploit_intel,
        "findings_by_type": findings_by_type,
        "open_issues_pie": open_issues_pie,
        "risk_donut": risk_donut,
        "top_risk_products": top_risk_products,
        "severity_trends": severity_trends,
        "finding_age": finding_age,
    }
