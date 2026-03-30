# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Component Remediation Package transform — zero-day scenario, component-centric.

Groups findings by (component_name, component_version_name) — not by CVE — and
produces actionable remediation guidance for each affected component version across
the portfolio.  Designed for zero-day scenarios where no CVE may exist yet.

Key differences from remediation_package.py:
- No CVE-centric scoring or OSV fix-version lookup
- No SBOM fetching
- Simpler priority model: severity × blast-radius
- AI prompts are component-focused ("zero-day" framing)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity rank map
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}

_SUPPRESSED_STATUSES: set[str] = {"FALSE_POSITIVE", "NOT_AFFECTED"}

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def component_remediation_package_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a component-centric zero-day remediation package.

    Args:
        data: Raw findings data (list of dicts or DataFrame).
        config: Application config object (may have component_filter,
            component_version, component_match attributes).
        additional_data: Dict with ``recipe_parameters``, etc.

    Returns:
        Dict with keys:
        ``main`` (flat DataFrame), ``actions`` (list of component action dicts),
        ``suppressed`` (list of suppressed finding dicts),
        ``summary`` (portfolio-level summary dict),
        ``ai_prompts`` (list of prompt dicts, only in prompt mode),
        ``mode`` ("component").
    """
    additional_data = additional_data or {}
    recipe_params = additional_data.get("recipe_parameters", {})
    cfg = additional_data.get("config", config)
    component_search_results = additional_data.get("component_search_results")

    # Convert to DataFrame — empty data is OK if component search results exist
    if isinstance(data, list):
        df = pd.DataFrame(data) if data else pd.DataFrame()
    else:
        df = data.copy()

    has_findings = not df.empty

    if has_findings:
        logger.info("Component Remediation Package: processing %d findings", len(df))

        # Step 1: Normalize columns
        df = _normalize_fields(df)

        # Step 2: Apply component filter (name / version)
        if cfg and getattr(cfg, "component_filter", None):
            df = _apply_component_filter(df, cfg.component_filter, cfg=cfg)

        if cfg and getattr(cfg, "component_version", None):
            from fs_report.transforms.pandas.component_impact import (
                _filter_by_version_range,
            )

            df = _filter_by_version_range(df, cfg.component_version)

        # Separate suppressed findings
        include_suppressed = recipe_params.get("include_suppressed", False)
        if "status" in df.columns:
            suppressed_mask = df["status"].isin(_SUPPRESSED_STATUSES)
            suppressed_df = df[suppressed_mask].copy()
            if not include_suppressed:
                df = df[~suppressed_mask].copy()
        else:
            suppressed_df = pd.DataFrame()

        has_findings = not df.empty
    else:
        suppressed_df = pd.DataFrame()

    # If no findings remain, check if we can build from component search
    # results alone (zero-day scenario — component exists but no CVEs yet).
    if not has_findings and not component_search_results:
        logger.info(
            "Component Remediation Package: no findings and no component "
            "search results — nothing to report"
        )
        return _empty_result()

    # Build actions from findings if available
    if has_findings:
        df = _compute_priority_score(df)
        actions = _build_actions(df, recipe_params)
        main_df = _build_main_df(df)
    else:
        actions = []
        main_df = pd.DataFrame()

    # Merge in zero-day actions from component search results for
    # component versions that have NO findings-based action yet.
    if component_search_results:
        existing_keys = {
            (a["component_name"], a["component_version_name"]) for a in actions
        }
        actions = _merge_search_actions(
            actions, component_search_results, existing_keys, recipe_params
        )

    if not actions:
        return _empty_result()

    # Build CSV rows from actions — includes both findings-based and zero-day
    # For zero-day actions, main_df is empty so we build project-level rows
    if main_df.empty and actions:
        main_df = _build_main_df_from_actions(actions)

    # Build summary
    component_name_label = (
        getattr(cfg, "component_filter", None) if cfg else None
    ) or ""
    version_range_label = (
        getattr(cfg, "component_version", None) if cfg else None
    ) or ""
    summary = _build_summary(actions, component_name_label, version_range_label)

    # AI modes:
    #   --ai         → live LLM calls per action (ai_live)
    #   --ai-prompts → generate copy-paste prompts, no LLM call
    ai_live = recipe_params.get("ai_live", False) or (cfg and getattr(cfg, "ai", False))
    ai_prompts_enabled = (
        ai_live
        or recipe_params.get("ai_prompts", False)
        or (cfg and getattr(cfg, "ai_prompts", False))
    )

    threat_context = getattr(cfg, "threat_context", None) if cfg else None

    all_prompts: list[dict[str, Any]] = []
    if ai_prompts_enabled:
        for action in actions:
            # For zero-day actions (no CVEs), always generate prompt
            # For findings-based actions, only CRITICAL and HIGH
            if action["is_zero_day"] or action["max_severity"] in (
                "CRITICAL",
                "HIGH",
            ):
                prompt = _build_ai_prompt(action, threat_context=threat_context)
                action["ai_prompt"] = prompt
                all_prompts.append(prompt)

    # Live LLM enrichment: call the LLM with each action's prompt
    if ai_live and all_prompts:
        _enrich_actions_with_llm(actions, cfg)

    # Build suppressed list
    suppressed_list: list[dict[str, Any]] = []
    if not suppressed_df.empty:
        for _, row in suppressed_df.iterrows():
            suppressed_list.append(
                {
                    "component_name": row.get("component_name", ""),
                    "component_version_name": row.get("component_version_name", ""),
                    "cve_id": row.get("cve_id", ""),
                    "severity": row.get("severity", ""),
                    "status": row.get("status", ""),
                    "project_name": row.get("project_name", ""),
                }
            )

    result: dict[str, Any] = {
        "main": main_df,
        "actions": actions,
        "suppressed": suppressed_list,
        "summary": summary,
        "mode": "component",
    }
    if ai_prompts_enabled:
        result["ai_prompts"] = all_prompts

    return result


# ---------------------------------------------------------------------------
# Empty result sentinel
# ---------------------------------------------------------------------------


def _empty_result() -> dict[str, Any]:
    return {
        "main": pd.DataFrame(),
        "actions": [],
        "suppressed": [],
        "summary": {},
        "mode": "component",
    }


# ---------------------------------------------------------------------------
# Field normalisation
# ---------------------------------------------------------------------------


def _normalize_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Extract and normalise nested API fields into flat columns."""
    df = df.copy()

    def _col(
        df: pd.DataFrame,
        target: str,
        *candidates: str,
        nested_key: str = "name",
    ) -> pd.DataFrame:
        for col in candidates:
            if col in df.columns:
                df[target] = df[col].apply(
                    lambda x: (
                        x.get(nested_key, "")
                        if isinstance(x, dict)
                        else (str(x) if x is not None else "")
                    )
                )
                return df
        if target not in df.columns:
            df[target] = ""
        return df

    # Component name
    df = _col(df, "component_name", "componentName", "component.name", "component")

    # Component version — handle nested dict {"name": "1.2.3"}
    df = _col(
        df,
        "component_version_name",
        "componentVersionName",
        "componentVersion",
        "component.version",
        nested_key="name",
    )
    # Fallback: if component is a dict with a "version" sub-key
    if (
        "component_version_name" not in df.columns
        or df["component_version_name"].eq("").all()
    ):
        if "componentVersion" in df.columns:
            df["component_version_name"] = df["componentVersion"].apply(
                lambda x: (
                    x.get("name", "")
                    if isinstance(x, dict)
                    else (str(x) if x is not None else "")
                )
            )
        elif "component" in df.columns:
            df["component_version_name"] = df["component"].apply(
                lambda x: (x.get("version", "") if isinstance(x, dict) else "")
            )

    # Project
    df = _col(df, "project_name", "projectName", "project.name", "project")
    df = _col(
        df,
        "project_version_name",
        "versionName",
        "projectVersionName",
        "projectVersion.name",
    )

    # CVE
    df = _col(df, "cve_id", "cveId", "findingId", "cve.id", "cve")

    # Severity (already a string field usually)
    if "severity" not in df.columns:
        df["severity"] = "UNKNOWN"

    # Status
    if "status" not in df.columns:
        df["status"] = None

    # Risk / CVSS
    if "risk" in df.columns:
        df["cvss_score"] = pd.to_numeric(df["risk"], errors="coerce") / 10.0
    else:
        df["cvss_score"] = None

    # Reachability score
    if "reachabilityScore" in df.columns:
        df["reachability_score"] = pd.to_numeric(
            df["reachabilityScore"], errors="coerce"
        ).fillna(0)
    elif "reachability_score" not in df.columns:
        df["reachability_score"] = 0

    # Title / name
    if "title" not in df.columns:
        if "name" in df.columns:
            df["title"] = df["name"]
        else:
            df["title"] = ""

    return df


# ---------------------------------------------------------------------------
# Component filter (delegates to shared utility)
# ---------------------------------------------------------------------------


def _apply_component_filter(
    df: pd.DataFrame, component_filter: str, cfg: object | None = None
) -> pd.DataFrame:
    from fs_report.transforms.pandas._component_filter import (
        apply_component_filter,
    )

    match_mode = getattr(cfg, "component_match", "contains") if cfg else "contains"
    return apply_component_filter(
        df,
        component_filter,
        match_mode=match_mode,
        name_col="component_name",
        version_col="component_version_name",
    )


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------


def _compute_priority_score(df: pd.DataFrame) -> pd.DataFrame:
    """Add a ``severity_rank`` column derived from the severity field."""
    df = df.copy()
    df["severity_rank"] = (
        df["severity"].str.upper().map(_SEVERITY_RANK).fillna(0).astype(int)
    )
    return df


def _score_action(
    group: pd.DataFrame,
    weights: dict[str, float] | None = None,
) -> float:
    """Compute a priority score for one component-version action group.

    Formula:
        base = max severity rank (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1)
        +2  if any finding has reachability_score > 0
        × min(affected_project_count, 3)   [blast radius, capped at 3]
    """
    if weights is None:
        weights = {}

    network_reachable_bonus = float(weights.get("network_reachable", 2.0))

    base = int(group["severity_rank"].max()) if "severity_rank" in group.columns else 0

    reachability_col = "reachability_score"
    has_reachable = (
        (pd.to_numeric(group[reachability_col], errors="coerce").fillna(0) > 0).any()
        if reachability_col in group.columns
        else False
    )

    bonus = network_reachable_bonus if has_reachable else 0.0

    project_col = "project_name"
    blast_radius = (
        min(group[project_col].nunique(), 3) if project_col in group.columns else 1
    )
    blast_radius = max(blast_radius, 1)

    return (base + bonus) * blast_radius


# ---------------------------------------------------------------------------
# Action building
# ---------------------------------------------------------------------------


def _build_actions(
    df: pd.DataFrame,
    recipe_params: dict[str, Any],
) -> list[dict[str, Any]]:
    """Group findings by (component_name, component_version_name) → action list."""
    weights: dict[str, float] = recipe_params.get("weights", {})

    df = df.copy()
    group_keys = ["component_name", "component_version_name"]
    # Ensure columns exist
    for k in group_keys:
        if k not in df.columns:
            df[k] = ""

    actions: list[dict[str, Any]] = []

    for (comp_name, comp_ver), group in df.groupby(
        group_keys, dropna=False, sort=False
    ):
        comp_name_str = str(comp_name) if comp_name is not None else ""
        comp_ver_str = str(comp_ver) if comp_ver is not None else ""

        # Affected projects
        affected_projects: list[str] = sorted(
            {str(p) for p in group["project_name"].dropna().unique() if str(p)}
        )

        # CVE IDs (may be empty for zero-day)
        cve_ids: list[str] = sorted(
            {
                str(c)
                for c in group["cve_id"].dropna().unique()
                if str(c) not in ("", "nan", "None")
            }
        )

        # CVSS scores
        if "cvss_score" in group.columns:
            cvss_scores: list[float] = sorted(
                [
                    float(v)
                    for v in pd.to_numeric(
                        group["cvss_score"], errors="coerce"
                    ).dropna()
                ],
                reverse=True,
            )
        else:
            cvss_scores = []

        # Severity
        severity_rank = (
            int(group["severity_rank"].max()) if "severity_rank" in group.columns else 0
        )
        rank_to_severity = {v: k for k, v in _SEVERITY_RANK.items()}
        max_severity = rank_to_severity.get(severity_rank, "UNKNOWN")

        # Counts
        finding_count = len(group)
        if "status" in group.columns:
            open_count = int(
                group["status"]
                .apply(lambda s: s is None or str(s).upper() in {"OPEN", "NONE", ""})
                .sum()
            )
        else:
            open_count = finding_count

        # Priority score
        priority_score = _score_action(group, weights=weights)

        # Interim mitigations (static defaults)
        interim_mitigations = _default_interim_mitigations(comp_name_str, cve_ids)

        action: dict[str, Any] = {
            "component_name": comp_name_str,
            "component_version_name": comp_ver_str,
            "affected_projects": affected_projects,
            "finding_count": finding_count,
            "open_count": open_count,
            "max_severity": max_severity,
            "priority_score": priority_score,
            "cvss_scores": cvss_scores,
            "cve_ids": cve_ids,
            "is_zero_day": len(cve_ids) == 0,
            "upgrade_recommendation": "Upgrade to latest stable version",
            "interim_mitigations": interim_mitigations,
            "ai_prompt": None,
        }
        actions.append(action)

    # Sort by priority_score descending, then max_severity as tiebreak
    actions.sort(key=lambda a: a["priority_score"], reverse=True)

    return actions


def _merge_search_actions(
    actions: list[dict[str, Any]],
    search_results: list[dict[str, Any]],
    existing_keys: set[tuple[str, str]],
    recipe_params: dict[str, Any],
) -> list[dict[str, Any]]:
    """Add zero-day action cards from component search results.

    For each (component_name, component_version) in *search_results* that
    does NOT already have an action from findings, create a zero-day action
    card.  This ensures the report is non-empty even when no CVEs exist yet.
    """
    # Group search results by (name, version) → list of project names
    from collections import defaultdict

    comp_projects: dict[tuple[str, str], set[str]] = defaultdict(set)
    for comp in search_results:
        name = comp.get("componentName", comp.get("name", ""))
        version = comp.get("componentVersion", comp.get("version", ""))
        proj = comp.get("project") or {}
        if isinstance(proj, dict):
            proj_name = proj.get("projectName", proj.get("name", ""))
        else:
            proj_name = ""
        if name and proj_name:
            comp_projects[(name, version)].add(proj_name)

    weights: dict[str, float] = recipe_params.get("weights", {})

    for (name, version), projects in comp_projects.items():
        if (name, version) in existing_keys:
            continue  # already covered by findings-based action

        interim = _default_interim_mitigations(name, [])
        action: dict[str, Any] = {
            "component_name": name,
            "component_version_name": version,
            "affected_projects": sorted(projects),
            "finding_count": 0,
            "open_count": 0,
            "max_severity": "UNKNOWN",
            "priority_score": float(weights.get("network_reachable", 2.0)),
            "cvss_scores": [],
            "cve_ids": [],
            "is_zero_day": True,
            "upgrade_recommendation": "Upgrade to latest stable version",
            "interim_mitigations": interim,
            "ai_prompt": None,
        }
        actions.append(action)
        logger.info(
            "Zero-day action card: %s %s (no CVEs, %d project(s))",
            name,
            version,
            len(projects),
        )

    # Re-sort: zero-day cards sort after findings-based, then by project count
    actions.sort(
        key=lambda a: (
            0 if not a["is_zero_day"] else 1,
            -a["priority_score"],
        )
    )

    return actions


def _default_interim_mitigations(component_name: str, cve_ids: list[str]) -> list[str]:
    """Return a default list of interim mitigation steps."""
    mitigations = [
        f"Restrict network access to services using {component_name}",
        "Apply host-based firewall rules to limit exposure",
        "Monitor logs for anomalous activity related to this component",
        "Consider disabling or replacing the affected component if not critical",
    ]
    if cve_ids:
        mitigations.append(f"Review vendor advisories for {', '.join(cve_ids[:3])}")
    else:
        mitigations.append(
            "Monitor vendor and upstream project for patch announcements "
            "(zero-day — no CVE assigned yet)"
        )
    return mitigations


# ---------------------------------------------------------------------------
# Flat DataFrame for CSV / XLSX
# ---------------------------------------------------------------------------


def _build_main_df(df: pd.DataFrame) -> pd.DataFrame:
    """Build a flat DataFrame with one row per finding."""
    cols_map = {
        "component_name": "Component Name",
        "component_version_name": "Component Version",
        "cve_id": "CVE ID",
        "title": "Title",
        "severity": "Severity",
        "cvss_score": "CVSS Score",
        "status": "Status",
        "project_name": "Project",
        "project_version_name": "Project Version",
    }
    if "priority_score" in df.columns:
        cols_map["priority_score"] = "Priority Score"

    available = {k: v for k, v in cols_map.items() if k in df.columns}
    result = df[list(available.keys())].copy()
    result = result.rename(columns=available)
    return result


def _build_main_df_from_actions(actions: list[dict[str, Any]]) -> pd.DataFrame:
    """Build a flat DataFrame from action cards (one row per project per action).

    Used for zero-day scenarios where there are no findings rows.
    """
    rows: list[dict[str, str]] = []
    for action in actions:
        comp = action.get("component_name", "")
        ver = action.get("component_version_name", "")
        severity = action.get("max_severity", "UNKNOWN")
        cve_ids = ", ".join(action.get("cve_ids", [])) or "NONE (zero-day)"
        is_zd = action.get("is_zero_day", False)
        tag = "ZERO-DAY" if is_zd else severity
        for proj in action.get("affected_projects", ["unknown"]):
            rows.append(
                {
                    "Component Name": comp,
                    "Component Version": ver,
                    "Severity": tag,
                    "CVE IDs": cve_ids,
                    "Project": proj,
                    "Upgrade": action.get("upgrade_recommendation", ""),
                }
            )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Live LLM enrichment
# ---------------------------------------------------------------------------


def _enrich_actions_with_llm(
    actions: list[dict[str, Any]],
    cfg: Any,
) -> None:
    """Call the LLM for each action that has a prompt, store response on action.

    Modifies *actions* in place — adds ``ai_guidance`` key with the LLM text.
    """
    try:
        from fs_report.llm_client import LLMClient
    except ImportError:
        logger.warning("LLM client not available, skipping live AI guidance")
        return

    import os
    import time

    from fs_report.llm_client import AI_ENV_VARS

    _is_copilot = getattr(cfg, "ai_provider", None) == "copilot"
    has_creds = _is_copilot or any(os.getenv(v) for v in AI_ENV_VARS)
    if not has_creds:
        logger.info("No AI provider credentials found, skipping live guidance")
        return

    cache_dir = getattr(cfg, "cache_dir", None) if cfg else None
    cache_ttl = getattr(cfg, "ai_cache_ttl", 0) if cfg else 0

    try:
        llm = LLMClient(cache_dir=cache_dir, cache_ttl=cache_ttl)
    except Exception as e:
        logger.warning("Failed to initialize LLM client: %s", e)
        return

    from tqdm import tqdm

    prompts_to_run = [a for a in actions if a.get("ai_prompt")]
    with tqdm(prompts_to_run, desc="AI remediation guidance", unit=" actions") as pbar:
        for action in pbar:
            prompt_data = action["ai_prompt"]
            action_key = prompt_data["id"]
            pbar.set_postfix_str(
                f"{action['component_name']}@{action['component_version_name']}"
            )

            full_prompt = prompt_data["system"] + "\n\n" + prompt_data["user"]
            prev_cached = llm._cached_count
            text = llm.generate_action_analysis(action_key, full_prompt)
            action["ai_guidance"] = text

            if llm._cached_count == prev_cached:
                time.sleep(0.5)  # rate limit non-cached calls

    stats = llm.get_stats()
    logger.info(
        "CRP AI guidance: %d API calls, %d cache hits",
        stats["api_calls"],
        stats["cache_hits"],
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _build_summary(
    actions: list[dict[str, Any]],
    component_name: str,
    version_range: str,
) -> dict[str, Any]:
    """Build portfolio-level summary dict from the actions list."""
    if not actions:
        return {
            "component_name": component_name,
            "version_range": version_range,
            "total_actions": 0,
            "zero_day_actions": 0,
            "cve_actions": 0,
            "affected_project_count": 0,
            "critical_actions": 0,
            "high_actions": 0,
            "generated_at": datetime.now(UTC).isoformat(),
        }

    zero_day_actions = sum(1 for a in actions if a["is_zero_day"])
    cve_actions = sum(1 for a in actions if not a["is_zero_day"])
    critical_actions = sum(1 for a in actions if a["max_severity"] == "CRITICAL")
    high_actions = sum(1 for a in actions if a["max_severity"] == "HIGH")

    all_projects: set[str] = set()
    for a in actions:
        all_projects.update(a["affected_projects"])

    return {
        "component_name": component_name,
        "version_range": version_range,
        "total_actions": len(actions),
        "zero_day_actions": zero_day_actions,
        "cve_actions": cve_actions,
        "affected_project_count": len(all_projects),
        "critical_actions": critical_actions,
        "high_actions": high_actions,
        "generated_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# AI prompt generation (no LLM call)
# ---------------------------------------------------------------------------


def _build_ai_prompt(
    action: dict[str, Any],
    threat_context: str | None = None,
) -> dict[str, Any]:
    """Build a structured prompt dict for an action card.

    Does NOT call the LLM — prompt strings are returned for external use.
    """
    comp = action["component_name"]
    ver = action["component_version_name"]
    projects = ", ".join(action["affected_projects"]) or "unknown"
    cve_list = (
        ", ".join(action["cve_ids"])
        if action["cve_ids"]
        else "NONE (zero-day scenario)"
    )
    severity = action["max_severity"]

    prompt_id = (
        f"crp_{comp}_{ver}".replace(" ", "_").replace("/", "_").replace(":", "_")
    )

    system_prompt = (
        "You are a firmware/embedded security engineer with deep expertise in "
        "supply-chain risk, component vulnerability analysis, and practical "
        "remediation for IoT/embedded devices.  You provide clear, actionable "
        "guidance tailored to embedded/IoT firmware teams who may not have "
        "immediate access to upstream patches."
    )

    threat_section = ""
    if threat_context:
        threat_section = f"\nThreat context: {threat_context}\n"

    user_prompt = f"""Component: {comp} {ver}
Affected projects: {projects}
Known CVEs: {cve_list}
Severity: {severity}
{threat_section}
Provide:
1. UPGRADE PATH: Recommended safe version and migration steps
2. BREAKING CHANGES: What may break on upgrade
3. ECOSYSTEM HEALTH: Maintenance status, community health
4. INTERIM MITIGATIONS: Steps to reduce exposure without upgrading
5. ISOLATION: Network isolation or access control recommendations

Focus on practical, actionable guidance.
If no CVE is listed, treat this as a zero-day scenario.
"""

    return {
        "id": prompt_id,
        "system": system_prompt,
        "user": user_prompt,
        "context": action,
    }
