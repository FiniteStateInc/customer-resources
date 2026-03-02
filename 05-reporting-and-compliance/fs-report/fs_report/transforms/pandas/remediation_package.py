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
Remediation Package transform — developer-friendly, AI-agent-ready output.

Groups vulnerabilities by component (not CVE) and enriches each action with:
- PURLs and dependency paths from SBOM
- Ecosystem-native fix versions from OSV
- Package manager upgrade commands
- Triage priority (reusing tiered-gate scoring)
- LLM-generated guidance (live) and AI agent prompts (prompt mode)
- VEX suppression (not_affected findings separated)
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any, cast

import pandas as pd

logger = logging.getLogger(__name__)

# Sentinel for "parameter not provided" (distinct from None = NVD unavailable)
_UNSET: Any = object()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def remediation_package_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a developer-friendly remediation package.

    Args:
        data: Raw findings data (list of dicts or DataFrame).
        config: Application config object.
        additional_data: Dict with ``recipe_parameters``, ``api_client``,
            ``config``, ``domain``, etc.

    Returns:
        Dict with keys consumed by the HTML template and JSON renderer:
        ``actions_df``, ``suppressed_df``, ``unresolvable_df``,
        ``summary``, ``charts``, ``project_agent_prompt``, ``json_package``.
    """
    additional_data = additional_data or {}
    recipe_params = additional_data.get("recipe_parameters", {})
    api_client = additional_data.get("api_client")
    cfg = additional_data.get("config", config)
    domain = additional_data.get("domain", "")

    # Convert to DataFrame if needed
    if isinstance(data, list):
        if not data:
            return _empty_result()
        df = pd.DataFrame(data)
    else:
        df = data.copy()
        if df.empty:
            return _empty_result()

    logger.info(f"Remediation Package: processing {len(df)} findings")

    # Step 1: Normalize columns (reuse triage pattern)
    df = _normalize_columns(df)

    # Step 1b: Apply scope filters (component and/or CVE)
    if cfg and getattr(cfg, "component_filter", None):
        df = _apply_component_filter(df, cfg.component_filter)
        if df.empty:
            logger.info("Remediation Package: no findings match component filter")
            return _empty_result()

    if cfg and getattr(cfg, "cve_filter", None):
        cve_ids = {c.strip() for c in cfg.cve_filter.split(",") if c.strip()}
        matched = df[df["finding_id"].isin(cve_ids)]
        if matched.empty:
            logger.info("Remediation Package: no findings match CVE filter")
            return _empty_result()
        # Expand to include ALL CVEs on the same components, so the action
        # card shows every CVE resolved by the same upgrade.
        comp_keys = set(
            zip(matched["component_name"], matched["component_version"], strict=False)
        )
        mask = pd.Series(False, index=df.index)
        for name, version in comp_keys:
            mask |= (df["component_name"] == name) & (
                df["component_version"] == version
            )
        before = len(df)
        df = df[mask]
        logger.info(
            f"CVE filter: {len(cve_ids)} CVEs → {len(matched)} direct hits → "
            f"{len(df)} findings (including sibling CVEs on same components)"
        )

    # Step 2: Apply triage gate scoring
    df = _apply_triage_scoring(df, recipe_params)

    # Step 3: Fetch SBOMs and enrich with PURLs + dependency paths
    sbom_map = {}
    if api_client:
        sbom_map = _fetch_sboms(df, api_client, recipe_params)
        df = _enrich_with_sbom(df, sbom_map)

    # Create NVD client once for the entire transform
    nvd_client = _init_nvd_client(cfg)

    # Step 4: Resolve fix versions (OSV → VEX → NVD fallback)
    if recipe_params.get("osv_enabled", True):
        df = _resolve_fix_versions(df, sbom_map, cfg, nvd_client=nvd_client)
    else:
        df = _resolve_fix_versions_no_osv(df, sbom_map, cfg, nvd_client=nvd_client)

    # Step 5: Classify upgrades and generate commands
    df = _classify_and_generate_commands(df)

    # Step 6: Separate VEX-suppressed findings
    suppressed_df = _extract_suppressed(df, sbom_map)
    # Remove suppressed from main set
    suppressed_ids = (
        set(suppressed_df["finding_id"]) if not suppressed_df.empty else set()
    )
    df = df[~df["finding_id"].isin(suppressed_ids)]

    # Step 6b: Deduplicate findings across project versions
    # Same CVE + component from multiple scans of the same project → keep one
    dedup_cols = ["finding_id", "component_name", "component_version", "project_name"]
    dedup_cols = [c for c in dedup_cols if c in df.columns]
    if dedup_cols:
        before = len(df)
        df = df.drop_duplicates(subset=dedup_cols, keep="last")
        if len(df) < before:
            logger.info(
                f"Dedup: {before} → {len(df)} findings "
                f"(removed {before - len(df)} cross-version duplicates)"
            )

    # Step 7: Group by component (collapse CVEs into actions)
    actions_df = _group_by_component(df, recipe_params)

    # Step 8: Flag fix availability (but keep all actions in the main list)
    actions_df["has_fix"] = actions_df["fixed_version"] != ""
    # NOTE: unresolvable_df is built AFTER enrichment (Step 11c) so that
    # fix versions added by validation or LLM are accounted for.

    # Step 9: Assign priorities (all actions, not just fixable ones)
    actions_df = _assign_priorities(actions_df, recipe_params)
    actions_df = actions_df.sort_values(
        ["priority_sort", "max_cvss"],
        ascending=[True, False],
    ).reset_index(drop=True)

    # Step 10: Limit actions
    top_limit = recipe_params.get("top_actions_limit", 100)
    if len(actions_df) > top_limit:
        actions_df = actions_df.head(top_limit)

    # Step 10b: Validate fix versions against OSV
    if recipe_params.get("osv_enabled", True):
        actions_df = _validate_fix_versions(actions_df, cfg)

    # Ensure fix validation columns exist with defaults (when OSV disabled)
    for col, default in [
        ("fix_validated", True),
        ("fix_validation_note", ""),
        ("fix_versions_checked", "[]"),
    ]:
        if col not in actions_df.columns:
            actions_df[col] = default  # type: ignore[call-overload]

    # Step 10c: Extract NVD workaround info
    actions_df = _extract_workaround_info(actions_df, cfg, nvd_client=nvd_client)

    # Build NVD snippets map once for LLM functions and agent prompts
    nvd_snippets_map = _build_nvd_snippets_map(actions_df, nvd_client)

    # Step 11: LLM enrichment
    ai_live = recipe_params.get("ai_live", False)
    ai_prompts = recipe_params.get("ai_prompts", False)
    ai_analysis = recipe_params.get("ai_analysis", False)

    if ai_analysis:
        # Single high-model pass: structured + analysis in one call
        actions_df = _enrich_with_combined_analysis(
            actions_df, cfg, additional_data, nvd_snippets_map=nvd_snippets_map
        )
        ai_prompts = True  # still generate agent prompts for JSON/copy-paste
    elif ai_live:
        actions_df = _enrich_with_llm_guidance(
            actions_df, cfg, additional_data, nvd_snippets_map=nvd_snippets_map
        )
        ai_prompts = True  # show what was sent to the LLM

    # Ensure AI verdict columns exist with defaults (for ai_live=False or no credentials)
    for col, default in [
        ("ai_verdict", "affected"),
        ("ai_confidence", ""),
        ("ai_rationale", ""),
        ("llm_guidance", ""),
        ("llm_workarounds", ""),
        ("llm_breaking_changes", ""),
    ]:
        if col not in actions_df.columns:
            actions_df[col] = default

    # Step 11b: Build structured remediation options per action
    actions_df = _build_remediation_options(actions_df)

    # Step 11c: Rebuild has_fix and extract unresolvable_df AFTER all enrichment
    # (fix versions may have been added by OSV validation or LLM enrichment)
    actions_df["has_fix"] = actions_df["fixed_version"] != ""
    unresolvable_df = actions_df[~actions_df["has_fix"]].copy()

    # Build component detail map from API data
    component_details_raw = additional_data.get("component_details", [])
    component_details_map: dict[tuple[str, str], dict] = {}
    for comp in component_details_raw:
        if isinstance(comp, dict):
            cname = comp.get("name", "")
            cver = comp.get("version", "")
            if cname:
                component_details_map[(cname, cver)] = comp

    if ai_prompts:
        actions_df = _generate_agent_prompts(
            actions_df,
            sbom_map,
            component_details_map,
            cfg,
            nvd_snippets_map=nvd_snippets_map,
        )

    # Ensure ai_analysis column exists
    if "ai_analysis" not in actions_df.columns:
        actions_df["ai_analysis"] = ""

    # Step 12: Generate project-level agent prompt
    project_name = _infer_project_name(df, cfg)
    project_version = _infer_project_version(df)
    project_prompt = ""
    if ai_prompts and not actions_df.empty:
        project_prompt = _generate_project_agent_prompt(
            actions_df, suppressed_df, project_name, project_version
        )

    # Step 13: Build summary
    summary = _build_summary(actions_df, suppressed_df, unresolvable_df)

    # Step 14: Charts removed — this report is concentrated data for humans/agents
    charts: dict[str, Any] = {}

    # Step 15: Build JSON package (for JSON output / IDE plugin)
    json_package = _build_json_package(
        actions_df,
        suppressed_df,
        unresolvable_df,
        summary,
        project_name,
        project_version,
        project_prompt,
        domain,
        sbom_map,
    )

    # Build scope label for scoped packages
    scope_label = _build_scope_label(cfg)

    return {
        # Primary DataFrame for CSV/XLSX (data_transformer picks up "main" key)
        "main": _flatten_for_tabular(actions_df),
        # Template data
        "actions_df": actions_df,
        "suppressed_df": suppressed_df,
        "unresolvable_df": unresolvable_df,
        "remediation_summary": summary,
        "scope_label": scope_label,
        "project_name": project_name,
        "project_version": project_version,
        "project_agent_prompt": project_prompt,
        # Charts
        "charts": charts,
        # JSON package (for file output)
        "json_package": json_package,
    }


# ---------------------------------------------------------------------------
# Scope filters (component / CVE)
# ---------------------------------------------------------------------------


def _apply_component_filter(df: pd.DataFrame, component_filter: str) -> pd.DataFrame:
    """Filter findings to only those matching the component filter.

    Supports ``name@version`` for exact match and ``name`` for all versions.
    Multiple specs are comma-separated.
    """
    specs = [s.strip() for s in component_filter.split(",") if s.strip()]
    if not specs:
        return df

    masks = []
    for spec in specs:
        if "@" in spec:
            name, version = spec.rsplit("@", 1)
            masks.append(
                (df["component_name"] == name) & (df["component_version"] == version)
            )
        else:
            masks.append(df["component_name"] == spec)

    combined = masks[0]
    for m in masks[1:]:
        combined = combined | m

    before = len(df)
    result = df[combined].copy()
    logger.info(f"Component filter: {before} → {len(result)} findings")
    return result


def _build_scope_label(cfg: object | None) -> str:
    """Build a human-readable scope label from config filters."""
    if not cfg:
        return ""
    component_filter = getattr(cfg, "component_filter", None)
    if component_filter:
        return str(component_filter)
    cve_filter = getattr(cfg, "cve_filter", None)
    if cve_filter:
        return str(cve_filter)
    return ""


# ---------------------------------------------------------------------------
# Column normalization (adapted from triage_prioritization)
# ---------------------------------------------------------------------------


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize API columns into a consistent schema.

    Reuses the same patterns as triage_prioritization._normalize_columns
    but kept as a separate function for independent evolution.
    """
    from fs_report.transforms.pandas.triage_prioritization import (
        _normalize_columns as _triage_normalize,
    )

    return _triage_normalize(df)


# ---------------------------------------------------------------------------
# Triage scoring (reuse gate DSL from triage_prioritization)
# ---------------------------------------------------------------------------


def _apply_triage_scoring(df: pd.DataFrame, recipe_params: dict) -> pd.DataFrame:
    """Apply tiered-gate scoring and additive scoring to findings."""
    from fs_report.transforms.pandas.triage_prioritization import (
        apply_tiered_gates,
        assign_risk_bands,
        calculate_additive_score,
    )

    gates = recipe_params.get("gates", [])
    weights = recipe_params.get("scoring_weights", {})

    # Pass raw gate defs (with conditions) to apply_tiered_gates,
    # and weights dict to calculate_additive_score and assign_risk_bands.
    df = apply_tiered_gates(df, gates=gates)
    df = calculate_additive_score(df, weights=weights, gates=gates)
    df = assign_risk_bands(df, weights=weights)

    logger.info(
        f"Triage scoring complete: "
        f"{(df['priority_band'] == 'CRITICAL').sum()} CRITICAL, "
        f"{(df['priority_band'] == 'HIGH').sum()} HIGH, "
        f"{(df['priority_band'] == 'MEDIUM').sum()} MEDIUM, "
        f"{(df['priority_band'] == 'LOW').sum()} LOW"
    )
    return df


# ---------------------------------------------------------------------------
# SBOM fetching and enrichment
# ---------------------------------------------------------------------------


def _fetch_sboms(
    df: pd.DataFrame, api_client: Any, recipe_params: dict
) -> dict[int, Any]:
    """Fetch CycloneDX SBOMs for each project version in the dataset."""
    from fs_report.sbom_parser import parse_cyclonedx

    sbom_format = recipe_params.get("sbom_format", "cyclonedx")
    include_vex = recipe_params.get("include_vex", True)

    version_ids_raw = df["project_version_id"].dropna().unique()
    version_ids: list[int] = [
        int(vid) for vid in version_ids_raw if vid and str(vid) != ""
    ]

    sbom_map = {}
    logger.info(f"Fetching SBOMs for {len(version_ids)} project versions")

    from tqdm import tqdm

    for vid in tqdm(version_ids, desc="Fetching SBOMs", unit=" SBOMs"):
        try:
            raw = api_client.fetch_sbom(vid, sbom_format, include_vex)
            sbom_map[vid] = parse_cyclonedx(raw)
        except Exception as e:
            logger.warning(f"Failed to fetch SBOM for version {vid}: {e}")

    logger.info(f"Fetched {len(sbom_map)} SBOMs")
    return sbom_map


def _enrich_with_sbom(df: pd.DataFrame, sbom_map: dict[int, Any]) -> pd.DataFrame:
    """Enrich findings with PURLs and dependency paths from SBOMs."""
    from fs_report.sbom_parser import (
        classify_dependency,
        format_dependency_path,
        match_component_to_sbom,
    )

    purls = []
    dep_is_direct = []
    dep_paths = []
    dep_path_display = []
    dep_direct_dep = []
    dep_depths = []

    for _, row in df.iterrows():
        vid = row.get("project_version_id", "")
        vid_int = int(vid) if vid and str(vid) != "" else None
        sbom = sbom_map.get(vid_int) if vid_int else None

        if sbom is None:
            purls.append("")
            dep_is_direct.append(True)
            dep_paths.append("[]")
            dep_path_display.append("")
            dep_direct_dep.append("")
            dep_depths.append(1)
            continue

        comp_name = str(row.get("component_name", ""))
        comp_version = str(row.get("component_version", ""))
        matched = match_component_to_sbom(sbom, comp_name, comp_version)

        if matched and matched.purl:
            purls.append(matched.purl)
            dep_info = classify_dependency(sbom, matched.bom_ref)
            dep_is_direct.append(dep_info.is_direct)
            dep_paths.append(json.dumps(dep_info.path))
            dep_path_display.append(format_dependency_path(sbom, dep_info.path))
            dep_direct_dep.append(dep_info.direct_dependency or "")
            dep_depths.append(dep_info.depth)
        else:
            purls.append("")
            dep_is_direct.append(True)
            dep_paths.append("[]")
            dep_path_display.append("")
            dep_direct_dep.append("")
            dep_depths.append(1)

    df["purl"] = purls
    df["dep_is_direct"] = dep_is_direct
    df["dep_path"] = dep_paths
    df["dep_path_display"] = dep_path_display
    df["dep_direct_dependency"] = dep_direct_dep
    df["dep_depth"] = dep_depths

    purl_count = sum(1 for p in purls if p)
    logger.info(f"SBOM enrichment: {purl_count}/{len(df)} findings matched to PURLs")
    return df


# ---------------------------------------------------------------------------
# Fix version resolution
# ---------------------------------------------------------------------------


def _resolve_fix_versions(
    df: pd.DataFrame,
    sbom_map: dict,
    cfg: Any,
    nvd_client: Any = _UNSET,
) -> pd.DataFrame:
    """Resolve fix versions using OSV (primary), SBOM VEX, NVD fallback."""
    from fs_report.nvd_client import NVDCveRecord
    from fs_report.osv_client import OSVClient, OSVFixResult
    from fs_report.purl_utils import best_fix_for_version

    # --- Source 1: OSV batch resolve ---
    unique_purls = [p for p in df["purl"].unique() if p]
    purl_fix_map: dict[str, OSVFixResult] = {}

    if unique_purls:
        cache_dir = getattr(cfg, "cache_dir", None) if cfg else None
        osv = OSVClient(cache_dir=cache_dir)
        try:
            osv_results = osv.batch_resolve(unique_purls)
            for purl, result in osv_results.items():
                if result.has_fix:
                    purl_fix_map[purl] = result
        except Exception as e:
            logger.warning(f"OSV batch resolution failed: {e}")
        finally:
            osv.close()

    # --- Source 3: NVD batch prefetch ---
    nvd_record_map: dict[str, NVDCveRecord] = {}
    if nvd_client is _UNSET:
        nvd_client = _init_nvd_client(cfg)
    if nvd_client:
        cve_ids = [
            str(fid)
            for fid in df["finding_id"].dropna().unique()
            if str(fid).startswith("CVE-")
        ]
        if cve_ids:
            try:
                logger.info(f"Fetching NVD fix data for {len(cve_ids)} CVEs...")
                nvd_client.get_batch(cve_ids, progress=True)
                for cve_id in cve_ids:
                    record = nvd_client.get_cve(cve_id)
                    if record and record.fix_versions:
                        nvd_record_map[cve_id] = record
                logger.info(
                    f"NVD: {len(nvd_record_map)}/{len(cve_ids)} CVEs have fix versions"
                )
            except Exception as e:
                logger.warning(f"NVD fix resolution failed: {e}")

    # --- Apply fixes with fallback chain: OSV → VEX → NVD ---
    fixed_versions = []
    fix_sources = []
    nvd_patch_urls: list[str] = []
    nvd_advisory_urls: list[str] = []
    nvd_descriptions: list[str] = []
    for _, row in df.iterrows():
        purl = row.get("purl", "")
        cve_id = str(row.get("finding_id", ""))

        # Source 1: OSV (branch-aware)
        current = str(row.get("component_version", ""))
        osv_result = purl_fix_map.get(purl)
        if osv_result:
            fix = best_fix_for_version(current, osv_result.all_fixed_versions)
            if not fix:
                fix = osv_result.fixed_version  # fallback to existing behavior
            source = "osv" if fix else ""
        else:
            fix = ""
            source = ""

        # Source 2: SBOM VEX fixed versions (branch-aware)
        if not fix:
            vid = row.get("project_version_id", "")
            vid_int = int(vid) if vid and str(vid) != "" else None
            sbom = sbom_map.get(vid_int)
            if sbom:
                vex = sbom.vex_for_cve(cve_id)
                if vex and vex.fixed_versions:
                    fix = best_fix_for_version(current, vex.fixed_versions)
                    if not fix:
                        fix = vex.fixed_versions[0]  # fallback for non-semver
                    source = "vex" if fix else ""

        # Source 3: NVD (branch-aware)
        if not fix:
            nvd_record = nvd_record_map.get(cve_id)
            if nvd_record:
                nvd_fix = nvd_record.fix_version_for(current)
                if nvd_fix:
                    fix = nvd_fix
                    source = "nvd"

        # Collect NVD patch/advisory URLs and description regardless of fix source
        patch_urls_str = ""
        advisory_urls_str = ""
        description_str = ""
        if nvd_client:
            record = nvd_client.get_cve(cve_id)
            if record:
                if record.patch_urls:
                    patch_urls_str = json.dumps(record.patch_urls[:5])
                if record.advisory_urls:
                    advisory_urls_str = json.dumps(record.advisory_urls[:5])
                description_str = record.description or ""

        fixed_versions.append(fix)
        fix_sources.append(source)
        nvd_patch_urls.append(patch_urls_str)
        nvd_advisory_urls.append(advisory_urls_str)
        nvd_descriptions.append(description_str)

    df["fixed_version"] = fixed_versions
    df["fix_source"] = fix_sources
    df["nvd_patch_urls"] = nvd_patch_urls
    df["nvd_advisory_urls"] = nvd_advisory_urls
    df["nvd_description"] = nvd_descriptions

    resolved = sum(1 for f in fixed_versions if f)
    logger.info(f"Fix resolution: {resolved}/{len(df)} findings have fix versions")
    return df


def _resolve_fix_versions_no_osv(
    df: pd.DataFrame,
    sbom_map: dict,
    cfg: Any,
    nvd_client: Any = _UNSET,
) -> pd.DataFrame:
    """Resolve fix versions using SBOM VEX + NVD (OSV disabled)."""
    from fs_report.nvd_client import NVDCveRecord
    from fs_report.purl_utils import best_fix_for_version

    # NVD batch prefetch
    nvd_record_map: dict[str, NVDCveRecord] = {}
    if nvd_client is _UNSET:
        nvd_client = _init_nvd_client(cfg)
    if nvd_client:
        cve_ids = [
            str(fid)
            for fid in df["finding_id"].dropna().unique()
            if str(fid).startswith("CVE-")
        ]
        if cve_ids:
            try:
                logger.info(f"Fetching NVD fix data for {len(cve_ids)} CVEs...")
                nvd_client.get_batch(cve_ids, progress=True)
                for cve_id in cve_ids:
                    record = nvd_client.get_cve(cve_id)
                    if record and record.fix_versions:
                        nvd_record_map[cve_id] = record
                logger.info(
                    f"NVD: {len(nvd_record_map)}/{len(cve_ids)} CVEs have fix versions"
                )
            except Exception as e:
                logger.warning(f"NVD fix resolution failed: {e}")

    fixed_versions = []
    fix_sources = []
    nvd_patch_urls: list[str] = []
    nvd_advisory_urls: list[str] = []
    nvd_descriptions: list[str] = []

    for _, row in df.iterrows():
        cve_id = str(row.get("finding_id", ""))
        current = str(row.get("component_version", ""))
        vid = row.get("project_version_id", "")
        vid_int = int(vid) if vid and str(vid) != "" else None
        sbom = sbom_map.get(vid_int)

        fix = ""
        source = ""
        # Source 1: VEX (branch-aware)
        if sbom:
            vex = sbom.vex_for_cve(cve_id)
            if vex and vex.fixed_versions:
                fix = best_fix_for_version(current, vex.fixed_versions)
                if not fix:
                    fix = vex.fixed_versions[0]  # fallback for non-semver
                source = "vex" if fix else ""

        # Source 2: NVD (branch-aware)
        if not fix:
            nvd_record = nvd_record_map.get(cve_id)
            if nvd_record:
                nvd_fix = nvd_record.fix_version_for(current)
                if nvd_fix:
                    fix = nvd_fix
                    source = "nvd"

        # Collect NVD patch/advisory URLs and description regardless of fix source
        patch_urls_str = ""
        advisory_urls_str = ""
        description_str = ""
        if nvd_client:
            record = nvd_client.get_cve(cve_id)
            if record:
                if record.patch_urls:
                    patch_urls_str = json.dumps(record.patch_urls[:5])
                if record.advisory_urls:
                    advisory_urls_str = json.dumps(record.advisory_urls[:5])
                description_str = record.description or ""

        fixed_versions.append(fix)
        fix_sources.append(source)
        nvd_patch_urls.append(patch_urls_str)
        nvd_advisory_urls.append(advisory_urls_str)
        nvd_descriptions.append(description_str)

    df["fixed_version"] = fixed_versions
    df["fix_source"] = fix_sources
    df["nvd_patch_urls"] = nvd_patch_urls
    df["nvd_advisory_urls"] = nvd_advisory_urls
    df["nvd_description"] = nvd_descriptions
    return df


# ---------------------------------------------------------------------------
# Fix version validation and workaround extraction
# ---------------------------------------------------------------------------


def _validate_fix_versions(actions_df: pd.DataFrame, cfg: Any) -> pd.DataFrame:
    """Validate that recommended fix versions don't have their own CVEs.

    For each action with a fix version, constructs a versioned PURL and
    queries OSV to check if that version is itself vulnerable.  If so,
    iterates through ``all_fixed_versions`` to find the nearest clean
    alternative (capped at 3 iterations).

    Adds columns: ``fix_validated``, ``fix_validation_note``,
    ``fix_versions_checked``.
    """
    if actions_df.empty:
        actions_df["fix_validated"] = pd.Series(dtype=bool)
        actions_df["fix_validation_note"] = ""
        actions_df["fix_versions_checked"] = "[]"
        return actions_df

    from fs_report.osv_client import OSVClient

    cache_dir = getattr(cfg, "cache_dir", None) if cfg else None
    osv = OSVClient(cache_dir=cache_dir)

    # Collect versioned PURLs to check
    purl_map: dict[int, str] = {}  # df index → versioned purl
    purls_to_check: list[str] = []
    for idx, row in actions_df.iterrows():
        purl = str(row.get("purl", ""))
        fix_ver = str(row.get("fixed_version", ""))
        if not purl or not fix_ver:
            continue
        # Strip existing version from PURL to build base
        base_purl = purl.rsplit("@", 1)[0] if "@" in purl else purl
        versioned = f"{base_purl}@{fix_ver}"
        purl_map[cast(int, idx)] = versioned
        purls_to_check.append(versioned)

    validated = {}
    notes = {}
    checked = {}

    if purls_to_check:
        try:
            vuln_results = osv.batch_check_vulnerable(list(set(purls_to_check)))
        except Exception as e:
            logger.warning(f"Fix version validation failed: {e}")
            vuln_results = {}

        for idx, versioned_purl in purl_map.items():
            is_vuln, vuln_ids = vuln_results.get(versioned_purl, (False, []))
            checked_versions = [versioned_purl.rsplit("@", 1)[-1]]

            if not is_vuln:
                validated[idx] = True
                notes[idx] = f"No known CVEs in {checked_versions[0]}"
            else:
                # Try alternative fix versions from OSV all_fixed_versions
                row = cast("pd.Series[Any]", actions_df.loc[idx])
                all_fixed_raw = str(row.get("all_fixed_versions", "[]"))
                try:
                    all_fixed = json.loads(all_fixed_raw) if all_fixed_raw else []
                except (json.JSONDecodeError, TypeError):
                    all_fixed = []

                base_purl = versioned_purl.rsplit("@", 1)[0]
                found_clean = False
                current_fix = checked_versions[0]

                # Filter to versions > current fix, cap at 3 iterations
                from fs_report.osv_client import _version_gt

                candidates = [v for v in all_fixed if _version_gt(v, current_fix)][:3]

                for alt_ver in candidates:
                    alt_purl = f"{base_purl}@{alt_ver}"
                    checked_versions.append(alt_ver)
                    try:
                        alt_results = osv.batch_check_vulnerable([alt_purl])
                        alt_vuln, _ = alt_results.get(alt_purl, (False, []))
                    except Exception:
                        alt_vuln = True  # assume vulnerable on error
                    if not alt_vuln:
                        # Found a clean version — update the action
                        actions_df.at[idx, "fixed_version"] = alt_ver
                        actions_df.at[idx, "fix_source"] = (
                            str(row.get("fix_source", "")) + "+validated"
                        )
                        validated[idx] = True
                        notes[idx] = (
                            f"Original fix {current_fix} has CVEs "
                            f"({', '.join(vuln_ids[:3])}); "
                            f"upgraded to validated {alt_ver}"
                        )
                        found_clean = True
                        break

                if not found_clean:
                    validated[idx] = False
                    notes[idx] = (
                        f"Fix version {current_fix} has known CVEs "
                        f"({', '.join(vuln_ids[:3])}); "
                        f"no clean alternative found in {len(candidates)} candidates"
                    )

            checked[idx] = json.dumps(checked_versions)

    osv.close()

    # Apply results
    actions_df["fix_validated"] = actions_df.index.map(
        lambda i: validated.get(i, True)  # default True for no-fix actions
    )
    actions_df["fix_validation_note"] = actions_df.index.map(lambda i: notes.get(i, ""))
    actions_df["fix_versions_checked"] = actions_df.index.map(
        lambda i: checked.get(i, "[]")
    )

    validated_count = sum(1 for v in validated.values() if v)
    failed_count = sum(1 for v in validated.values() if not v)
    if validated or failed_count:
        logger.info(
            f"Fix validation: {validated_count} clean, {failed_count} failed "
            f"out of {len(purl_map)} checked"
        )

    return actions_df


def _extract_workaround_info(
    actions_df: pd.DataFrame,
    cfg: Any,
    nvd_client: Any = _UNSET,
) -> pd.DataFrame:
    """Extract NVD workaround URLs for each action's CVEs.

    Looks up CVE IDs in the NVD client (using cache) and aggregates
    ``workaround_urls`` from ``NVDCveRecord``.

    Adds column: ``workaround_urls`` (JSON list).
    """
    if actions_df.empty:
        actions_df["workaround_urls"] = "[]"
        return actions_df

    if nvd_client is _UNSET:
        nvd_client = _init_nvd_client(cfg)
    workaround_urls_col: list[str] = []

    for _, row in actions_df.iterrows():
        cve_ids_raw = str(row.get("cve_ids", "[]"))
        try:
            cve_ids = json.loads(cve_ids_raw)
        except (json.JSONDecodeError, TypeError):
            cve_ids = []

        urls: list[str] = []
        if nvd_client:
            for cve_id in cve_ids:
                if not str(cve_id).startswith("CVE-"):
                    continue
                record = nvd_client.get_cve(str(cve_id))
                if record and record.workaround_urls:
                    urls.extend(record.workaround_urls)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_urls: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        workaround_urls_col.append(json.dumps(unique_urls[:10]))

    actions_df["workaround_urls"] = workaround_urls_col
    urls_found = sum(1 for u in workaround_urls_col if u != "[]")
    if urls_found:
        logger.info(
            f"Workaround URLs: found for {urls_found}/{len(actions_df)} actions"
        )

    return actions_df


def _build_remediation_options(actions_df: pd.DataFrame) -> pd.DataFrame:
    """Build structured multi-option remediation per action.

    Creates ``remediation_options`` (JSON) and ``remediation_options_parsed``
    (list of dicts) columns with up to 3 options per action:
    1. Upgrade to validated fix version
    2. Environmental controls & workarounds
    3. Code-level mitigations
    """
    if actions_df.empty:
        actions_df["remediation_options"] = "[]"
        actions_df["remediation_options_parsed"] = [[] for _ in range(len(actions_df))]
        return actions_df

    options_col: list[str] = []
    parsed_col: list[list[dict]] = []

    for _, row in actions_df.iterrows():
        options: list[dict[str, Any]] = []

        fix_ver = str(row.get("fixed_version", ""))
        fix_validated = bool(row.get("fix_validated", True))
        validation_note = str(row.get("fix_validation_note", ""))
        upgrade_cmd = str(row.get("upgrade_command", ""))
        upgrade_type = str(row.get("upgrade_type", ""))
        breaking_risk = str(row.get("breaking_change_risk", ""))
        llm_breaking = str(row.get("llm_breaking_changes", ""))

        # Option 1: Upgrade
        if fix_ver:
            opt1: dict[str, Any] = {
                "option_number": 1,
                "type": "upgrade",
                "title": f"Upgrade to {fix_ver}",
                "fix_version": fix_ver,
                "fix_validated": fix_validated,
                "validation_note": validation_note
                or (
                    f"No known CVEs in {fix_ver}"
                    if fix_validated
                    else f"Fix version {fix_ver} may have known CVEs"
                ),
                "upgrade_command": upgrade_cmd,
                "upgrade_type": upgrade_type,
                "breaking_change_risk": breaking_risk,
                "breaking_change_notes": llm_breaking,
            }
            options.append(opt1)

        # Option 2: Workarounds
        workaround_urls_raw = str(row.get("workaround_urls", "[]"))
        try:
            workaround_urls = json.loads(workaround_urls_raw)
        except (json.JSONDecodeError, TypeError):
            workaround_urls = []

        llm_workarounds_raw = str(row.get("llm_workarounds", ""))
        workaround_items: list[str] = []
        if llm_workarounds_raw and llm_workarounds_raw.lower() not in ("none", ""):
            # Parse numbered list from LLM
            for line in llm_workarounds_raw.split("\n"):
                line = line.strip().lstrip("0123456789.-) ")
                if line:
                    workaround_items.append(line)

        if workaround_items or workaround_urls:
            opt2: dict[str, Any] = {
                "option_number": 2,
                "type": "workaround",
                "title": "Environmental Controls & Workarounds",
                "workarounds": workaround_items,
                "workaround_urls": workaround_urls,
            }
            options.append(opt2)

        # Option 3: Code-level mitigations
        affected_funcs = str(row.get("affected_functions", ""))
        patch_urls_raw = str(row.get("nvd_patch_urls", "[]"))
        try:
            patch_urls = json.loads(patch_urls_raw)
        except (json.JSONDecodeError, TypeError):
            patch_urls = []
        search_pattern = str(row.get("search_pattern", ""))
        component_name = str(row.get("component_name", ""))

        if affected_funcs or patch_urls or search_pattern:
            opt3: dict[str, Any] = {
                "option_number": 3,
                "type": "code_mitigation",
                "title": "Code-Level Mitigations",
                "affected_functions": affected_funcs,
                "patch_urls": patch_urls,
                "search_pattern": search_pattern or component_name,
            }
            options.append(opt3)

        options_col.append(json.dumps(options, default=str))
        parsed_col.append(options)

    actions_df["remediation_options"] = options_col
    actions_df["remediation_options_parsed"] = pd.array(parsed_col, dtype=object)

    logger.info(
        f"Remediation options: built for {len(actions_df)} actions "
        f"(avg {sum(len(p) for p in parsed_col) / max(len(parsed_col), 1):.1f} options/action)"
    )

    return actions_df


def _init_nvd_client(cfg: Any) -> Any:
    """Initialize NVD client if available, returns None on failure."""
    try:
        from fs_report.nvd_client import NVD_ATTRIBUTION, NVDClient

        cache_dir = getattr(cfg, "cache_dir", None) if cfg else None
        cache_ttl = getattr(cfg, "cache_ttl", 0) if cfg else 0
        nvd_api_key = getattr(cfg, "nvd_api_key", None) if cfg else None
        client = NVDClient(
            api_key=nvd_api_key,
            cache_dir=cache_dir,
            cache_ttl=max(cache_ttl or 0, 86400),  # min 24h cache
        )
        logger.info(NVD_ATTRIBUTION)
        return client
    except Exception as e:
        logger.info(f"NVD client unavailable: {e}")
        return None


def _build_nvd_snippets_map(
    df: pd.DataFrame,
    nvd_client: Any,
) -> dict[str, str]:
    """Build NVD prompt snippets per component from a pre-initialized client.

    Collects unique CVEs from ``df["cve_ids"]``, batch-fetches them, then
    calls ``format_batch_for_prompt()`` for each component.

    Returns:
        ``{comp_key: snippet}`` dict, or ``{}`` if *nvd_client* is None.
    """
    if nvd_client is None:
        return {}

    nvd_snippets_map: dict[str, str] = {}
    all_cve_ids: list[str] = []
    for _, row in df.iterrows():
        cves = json.loads(row.get("cve_ids", "[]"))
        all_cve_ids.extend(c for c in cves if str(c).startswith("CVE-"))
    unique_cves = list(dict.fromkeys(all_cve_ids))
    if unique_cves:
        logger.info(f"Fetching NVD data for {len(unique_cves)} CVEs...")
        nvd_client.get_batch(unique_cves, progress=True)
        for _, row in df.iterrows():
            comp_key = (
                f"{row.get('component_name', '')}:"
                f"{row.get('component_version', '')}"
            )
            cves = json.loads(row.get("cve_ids", "[]"))
            snippet = nvd_client.format_batch_for_prompt(
                [c for c in cves[:10] if str(c).startswith("CVE-")],
            )
            if snippet:
                nvd_snippets_map[comp_key] = snippet
    return nvd_snippets_map


# ---------------------------------------------------------------------------
# Upgrade classification and command generation
# ---------------------------------------------------------------------------


def _classify_and_generate_commands(df: pd.DataFrame) -> pd.DataFrame:
    """Add upgrade_type, breaking_change_risk, upgrade_command, manifest_patterns."""
    from fs_report.purl_utils import (
        breaking_change_risk,
        classify_upgrade,
        ecosystem_from_purl,
        manifest_patterns,
        search_pattern,
        upgrade_command,
        upgrade_instruction,
    )

    upgrade_types = []
    risks = []
    commands = []
    instructions = []
    manifests = []
    search_patterns = []
    ecosystems = []

    for _, row in df.iterrows():
        purl = row.get("purl", "")
        current = str(row.get("component_version", ""))
        fixed = str(row.get("fixed_version", ""))
        ecosystem = ecosystem_from_purl(purl) if purl else "unknown"

        if fixed and current:
            ut = classify_upgrade(current, fixed)
            risk = breaking_change_risk(ut)
        else:
            ut = classify_upgrade("", "")
            risk = "unknown"

        cmd = upgrade_command(purl, fixed) if purl and fixed else None
        instr = upgrade_instruction(purl, fixed) if purl and fixed else ""
        mans = manifest_patterns(purl) if purl else []
        sp = search_pattern(purl) if purl else None

        upgrade_types.append(ut.value)
        risks.append(risk)
        commands.append(cmd or "")
        instructions.append(instr)
        manifests.append(json.dumps(mans))
        search_patterns.append(sp or "")
        ecosystems.append(ecosystem)

    df["upgrade_type"] = upgrade_types
    df["breaking_change_risk"] = risks
    df["upgrade_command"] = commands
    df["upgrade_instruction"] = instructions
    df["manifest_patterns"] = manifests
    df["search_pattern"] = search_patterns
    df["ecosystem"] = ecosystems

    return df


# ---------------------------------------------------------------------------
# VEX suppression
# ---------------------------------------------------------------------------


def _extract_suppressed(df: pd.DataFrame, sbom_map: dict) -> pd.DataFrame:
    """Extract findings that are VEX not_affected or false_positive."""
    suppressed_statuses = {
        "NOT_AFFECTED",
        "FALSE_POSITIVE",
        "RESOLVED",
        "RESOLVED_WITH_PEDIGREE",
    }

    # Check VEX from SBOM
    vex_suppressed_ids = set()
    vex_data = []

    for _, row in df.iterrows():
        vid = row.get("project_version_id", "")
        vid_int = int(vid) if vid and str(vid) != "" else None
        sbom = sbom_map.get(vid_int)
        cve_id = str(row.get("finding_id", ""))

        # Check SBOM VEX
        if sbom:
            vex = sbom.vex_for_cve(cve_id)
            if vex and vex.state in (
                "not_affected",
                "false_positive",
                "resolved",
                "resolved_with_pedigree",
            ):
                vex_suppressed_ids.add(row.get("finding_id", ""))
                vex_data.append(
                    {
                        "finding_id": cve_id,
                        "component_name": row.get("component_name", ""),
                        "component_version": row.get("component_version", ""),
                        "purl": row.get("purl", ""),
                        "vex_state": vex.state,
                        "vex_justification": vex.justification,
                        "detail": vex.detail,
                        "severity": row.get("severity", ""),
                    }
                )
                continue

        # Check finding status field
        status = str(row.get("status", "")).upper()
        if status in suppressed_statuses:
            vex_suppressed_ids.add(row.get("finding_id", ""))
            vex_data.append(
                {
                    "finding_id": cve_id,
                    "component_name": row.get("component_name", ""),
                    "component_version": row.get("component_version", ""),
                    "purl": row.get("purl", ""),
                    "vex_state": status.lower(),
                    "vex_justification": "",
                    "detail": "",
                    "severity": row.get("severity", ""),
                }
            )

    if vex_data:
        return pd.DataFrame(vex_data)
    return pd.DataFrame(
        columns=[
            "finding_id",
            "component_name",
            "component_version",
            "purl",
            "vex_state",
            "vex_justification",
            "detail",
            "severity",
        ]
    )


# ---------------------------------------------------------------------------
# Component grouping (the Snyk insight)
# ---------------------------------------------------------------------------


def _group_by_component(df: pd.DataFrame, recipe_params: dict) -> pd.DataFrame:
    """Group findings by component to collapse CVEs into single actions.

    This is the key transformation: 15 CVEs become 2 dependency bumps.
    """
    if df.empty:
        return pd.DataFrame()

    # Group key: component_name + component_version + purl (+ project for per-project)
    group_key = ["component_name", "component_version", "purl", "project_name"]
    # Only include columns that exist
    group_key = [k for k in group_key if k in df.columns]

    actions = []
    for group_vals, group_df in df.groupby(group_key, dropna=False):
        if isinstance(group_vals, str):  # type: ignore[unreachable]
            group_vals = (group_vals,)  # type: ignore[unreachable]
        group_dict = dict(zip(group_key, group_vals, strict=False))

        # Aggregate CVE list
        cves = group_df["finding_id"].dropna().unique().tolist()

        # Take the best (most severe) finding's data
        best_idx = (
            group_df["triage_score"].idxmax()
            if "triage_score" in group_df.columns
            else group_df.index[0]
        )
        best = group_df.loc[best_idx]

        # Aggregate severity counts
        sev_counts = (
            group_df["severity"].value_counts().to_dict()
            if "severity" in group_df.columns
            else {}
        )

        # Aggregate reachability
        reach_counts = (
            group_df["reachability_label"].value_counts().to_dict()
            if "reachability_label" in group_df.columns
            else {}
        )

        # Collect all affected functions
        all_funcs: set[str] = set()
        if "vuln_functions" in group_df.columns:
            for funcs in group_df["vuln_functions"].dropna():
                if funcs:
                    all_funcs.update(
                        f.strip() for f in str(funcs).split(",") if f.strip()
                    )

        # Collect all CWEs
        all_cwes: set[str] = set()
        if "cwes" in group_df.columns:
            for cwe_val in group_df["cwes"].dropna():
                if isinstance(cwe_val, list):
                    all_cwes.update(str(c) for c in cwe_val)
                elif isinstance(cwe_val, str) and cwe_val not in ("", "[]"):
                    all_cwes.update(
                        c.strip() for c in cwe_val.strip("[]").split(",") if c.strip()
                    )

        # Build resolves list (per-CVE detail)
        resolves = []
        all_patch_urls: set[str] = set()
        all_advisory_urls: set[str] = set()
        for _, frow in group_df.iterrows():
            # Collect NVD URLs
            try:
                patch_urls = (
                    json.loads(frow.get("nvd_patch_urls", ""))
                    if frow.get("nvd_patch_urls")
                    else []
                )
            except (json.JSONDecodeError, TypeError):
                patch_urls = []
            try:
                advisory_urls = (
                    json.loads(frow.get("nvd_advisory_urls", ""))
                    if frow.get("nvd_advisory_urls")
                    else []
                )
            except (json.JSONDecodeError, TypeError):
                advisory_urls = []
            all_patch_urls.update(patch_urls)
            all_advisory_urls.update(advisory_urls)

            resolves.append(
                {
                    "cve_id": str(frow.get("finding_id", "")),
                    "severity": str(frow.get("severity", "")),
                    "cvss": (
                        float(frow["risk"]) / 10.0
                        if pd.notna(frow.get("risk"))
                        else 0.0
                    ),
                    "epss": float(frow.get("epss_score", 0) or 0),
                    "in_kev": bool(frow.get("in_kev", False)),
                    "reachability": str(frow.get("reachability_label", "UNKNOWN")),
                    "affected_functions": [
                        f.strip()
                        for f in str(frow.get("vuln_functions", "")).split(",")
                        if f.strip()
                    ],
                    "exploit_available": bool(frow.get("has_exploit", False)),
                    "cwes": (
                        frow["cwes"]
                        if isinstance(frow.get("cwes"), list)
                        else [
                            c.strip()
                            for c in str(frow.get("cwes", "")).strip("[]").split(",")
                            if c.strip()
                        ]
                    ),
                    "patch_urls": patch_urls,
                    "advisory_urls": advisory_urls,
                    "description": str(frow.get("nvd_description", "")),
                }
            )

        # Max triage score and CVSS across all CVEs in this group
        max_score = (
            float(group_df["triage_score"].max())
            if "triage_score" in group_df.columns
            else 0.0
        )
        max_cvss = max((r["cvss"] for r in resolves), default=0.0)
        max_epss = max((r["epss"] for r in resolves), default=0.0)
        any_kev = any(r["in_kev"] for r in resolves)
        any_exploit = any(r["exploit_available"] for r in resolves)
        # Worst band = most severe band across all findings in the group
        _band_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        if "priority_band" in group_df.columns:
            worst_band = min(
                group_df["priority_band"].dropna().unique(),
                key=lambda b: _band_order.get(str(b), 99),
                default="INFO",
            )
            worst_band = str(worst_band)
        else:
            worst_band = "INFO"

        action = {
            "component_name": group_dict.get("component_name", ""),
            "component_version": group_dict.get("component_version", ""),
            "purl": group_dict.get("purl", ""),
            "project_name": group_dict.get("project_name", ""),
            "project_version_id": str(best.get("project_version_id", "")),
            "fixed_version": str(best.get("fixed_version", "")),
            "fix_source": str(best.get("fix_source", "")),
            "ecosystem": str(best.get("ecosystem", "unknown")),
            "upgrade_type": str(best.get("upgrade_type", "unknown")),
            "breaking_change_risk": str(best.get("breaking_change_risk", "unknown")),
            "upgrade_command": str(best.get("upgrade_command", "")),
            "upgrade_instruction": str(best.get("upgrade_instruction", "")),
            "manifest_patterns": str(best.get("manifest_patterns", "[]")),
            "search_pattern": str(best.get("search_pattern", "")),
            "dep_is_direct": bool(best.get("dep_is_direct", True)),
            "dep_path": str(best.get("dep_path", "[]")),
            "dep_path_display": str(best.get("dep_path_display", "")),
            "dep_direct_dependency": str(best.get("dep_direct_dependency", "")),
            "dep_depth": int(best.get("dep_depth", 1)),
            "cve_count": len(cves),
            "cve_ids": json.dumps(cves),
            "resolves": json.dumps(resolves),
            "resolves_parsed": resolves,  # actual list for HTML template iteration
            "max_triage_score": max_score,
            "max_cvss": max_cvss,
            "max_epss": max_epss,
            "any_kev": any_kev,
            "any_exploit": any_exploit,
            "worst_band": worst_band,
            "severity_counts": json.dumps(sev_counts),
            "reachability_counts": json.dumps(reach_counts),
            "affected_functions": ", ".join(sorted(all_funcs)),
            "cwes": json.dumps(sorted(all_cwes)),
            # NVD reference URLs (aggregated across all CVEs in this group)
            "patch_urls": json.dumps(sorted(all_patch_urls)),
            "advisory_urls": json.dumps(sorted(all_advisory_urls)),
            # Effort estimation heuristic
            "effort_estimate": _estimate_effort(
                str(best.get("upgrade_type", "unknown")),
                bool(best.get("dep_is_direct", True)),
                len(cves),
            ),
        }
        actions.append(action)

    actions_df = pd.DataFrame(actions)
    logger.info(f"Component grouping: {len(df)} findings → {len(actions_df)} actions")
    return actions_df


def _estimate_effort(upgrade_type: str, is_direct: bool, cve_count: int) -> str:
    """Heuristic effort estimation based on upgrade characteristics."""
    if upgrade_type == "patch" and is_direct:
        return "trivial"
    elif upgrade_type == "patch":
        return "small"
    elif upgrade_type == "minor" and is_direct:
        return "small"
    elif upgrade_type == "minor":
        return "medium"
    elif upgrade_type == "major":
        return "large" if not is_direct else "medium"
    return "unknown"


# ---------------------------------------------------------------------------
# Priority assignment
# ---------------------------------------------------------------------------


def _assign_priorities(df: pd.DataFrame, recipe_params: dict) -> pd.DataFrame:
    """Map triage bands to P0-P3 priorities."""
    band_map = recipe_params.get(
        "band_to_priority",
        {
            "CRITICAL": "P0",
            "HIGH": "P1",
            "MEDIUM": "P2",
            "LOW": "P3",
            "INFO": "P3",
        },
    )
    priority_sort = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

    df["priority"] = df["worst_band"].map(band_map).fillna("P3")
    df["priority_sort"] = df["priority"].map(priority_sort).fillna(3)

    return df


# ---------------------------------------------------------------------------
# LLM guidance (live mode)
# ---------------------------------------------------------------------------


def _enrich_with_llm_guidance(
    df: pd.DataFrame,
    cfg: Any,
    additional_data: dict,
    nvd_snippets_map: dict[str, str] | None = _UNSET,
) -> pd.DataFrame:
    """Generate live LLM guidance for each action, including fix versions.

    Follows the same pattern as triage_prioritization: batch-prefetch NVD
    data, build per-component snippets, then pass to the LLM for fix-version
    determination and remediation guidance.
    """
    try:
        from fs_report.llm_client import LLMClient
    except ImportError:
        logger.warning("LLM client not available, skipping AI guidance")
        df["llm_guidance"] = ""
        return df

    # Check for AI credentials
    import os

    has_creds = any(
        os.getenv(v) for v in ("ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN")
    )
    if not has_creds:
        logger.info("No AI provider credentials found, skipping live guidance")
        df["llm_guidance"] = ""
        return df

    cache_dir = getattr(cfg, "cache_dir", None) if cfg else None
    cache_ttl = getattr(cfg, "ai_cache_ttl", 0) if cfg else 0

    try:
        llm = LLMClient(cache_dir=cache_dir, cache_ttl=cache_ttl)
    except Exception as e:
        logger.warning(f"Failed to initialize LLM client: {e}")
        df["llm_guidance"] = ""
        return df

    # --- Build NVD snippets per component (reuse pre-built map or build on demand) ---
    if nvd_snippets_map is _UNSET:
        nvd_snippets_map = _build_nvd_snippets_map(df, _init_nvd_client(cfg))

    # --- Build component list for batch guidance ---
    components_list = []
    for _, row in df.iterrows():
        cve_ids = json.loads(row.get("cve_ids", "[]"))
        components_list.append(
            {
                "component_name": str(row.get("component_name", "")),
                "component_version": str(row.get("component_version", "")),
                "cve_ids": cve_ids[:10],
            }
        )

    # --- Generate batch guidance with NVD snippets ---
    ai_results = llm.generate_batch_component_guidance(
        components_list,
        nvd_snippets_map=nvd_snippets_map if nvd_snippets_map else None,
    )

    # --- Apply guidance, verdict, and AI fix versions ---
    guidances = []
    verdicts = []
    confidences = []
    rationales = []
    ai_fix_count = 0
    for _, row in df.iterrows():
        comp_key = f"{row.get('component_name', '')}:{row.get('component_version', '')}"
        result = ai_results.get(comp_key, {})
        guidances.append(str(result.get("guidance", "")))
        verdicts.append(str(result.get("verdict", "affected")))
        confidences.append(str(result.get("confidence", "medium")))
        rationales.append(str(result.get("rationale", "")))

        # Fill fix-version gaps with LLM-determined versions
        if not row.get("fixed_version"):
            ai_fix = str(result.get("fix_version", "")).strip()
            if ai_fix and ai_fix.lower() not in ("unknown", "n/a", "none", ""):
                df.at[row.name, "fixed_version"] = ai_fix
                df.at[row.name, "fix_source"] = "ai"
                df.at[row.name, "has_fix"] = True
                ai_fix_count += 1

    df["llm_guidance"] = guidances
    df["ai_verdict"] = verdicts
    df["ai_confidence"] = confidences
    df["ai_rationale"] = rationales
    if ai_fix_count:
        logger.info(f"AI guidance resolved {ai_fix_count} additional fix versions")

    stats = llm.get_stats()
    logger.info(
        f"LLM guidance: {stats['api_calls']} API calls, "
        f"{stats['cache_hits']} cache hits"
    )
    return df


# ---------------------------------------------------------------------------
# AI analysis enrichment (summary model deep analysis)
# ---------------------------------------------------------------------------


def _enrich_with_ai_analysis(
    df: pd.DataFrame,
    cfg: Any,
) -> pd.DataFrame:
    """Generate deep AI analysis for each action using the summary model.

    Requires the ``agent_prompt`` column to already be populated. Each action's
    agent prompt is sent to the summary (high-capability) model which produces
    a detailed markdown analysis.
    """
    if "agent_prompt" not in df.columns:
        logger.info("No agent_prompt column — skipping AI analysis")
        df["ai_analysis"] = ""
        return df

    try:
        from fs_report.llm_client import LLMClient
    except ImportError:
        logger.warning("LLM client not available, skipping AI analysis")
        df["ai_analysis"] = ""
        return df

    # Check for AI credentials
    import hashlib
    import os

    has_creds = any(
        os.getenv(v) for v in ("ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN")
    )
    if not has_creds:
        logger.info("No AI provider credentials found, skipping AI analysis")
        df["ai_analysis"] = ""
        return df

    cache_dir = getattr(cfg, "cache_dir", None) if cfg else None
    cache_ttl = getattr(cfg, "ai_cache_ttl", 0) if cfg else 0

    try:
        llm = LLMClient(cache_dir=cache_dir, cache_ttl=cache_ttl)
    except Exception as e:
        logger.warning(f"Failed to initialize LLM client: {e}")
        df["ai_analysis"] = ""
        return df

    # Build (action_key, agent_prompt) tuples
    actions: list[tuple[str, str]] = []
    for _, row in df.iterrows():
        prompt = str(row.get("agent_prompt", ""))
        if not prompt:
            continue
        comp = str(row.get("component_name", ""))
        ver = str(row.get("component_version", ""))
        cve_ids = str(row.get("cve_ids", "[]"))
        key_hash = hashlib.sha256(cve_ids.encode()).hexdigest()[:12]
        action_key = f"action:{comp}:{ver}:{key_hash}"
        actions.append((action_key, prompt))

    if not actions:
        df["ai_analysis"] = ""
        return df

    results = llm.generate_batch_action_analysis(actions)

    # Map results back to DataFrame rows
    analyses = []
    for _, row in df.iterrows():
        prompt = str(row.get("agent_prompt", ""))
        if not prompt:
            analyses.append("")
            continue
        comp = str(row.get("component_name", ""))
        ver = str(row.get("component_version", ""))
        cve_ids = str(row.get("cve_ids", "[]"))
        key_hash = hashlib.sha256(cve_ids.encode()).hexdigest()[:12]
        action_key = f"action:{comp}:{ver}:{key_hash}"
        analyses.append(results.get(action_key, ""))

    df["ai_analysis"] = analyses

    stats = llm.get_stats()
    logger.info(
        f"AI analysis: {stats['api_calls']} API calls, "
        f"{stats['cache_hits']} cache hits"
    )
    return df


# ---------------------------------------------------------------------------
# Combined analysis enrichment (single high-model pass)
# ---------------------------------------------------------------------------


def _build_combined_context_prompt(row: Any, nvd_snippet: str = "") -> str:
    """Build comprehensive context for combined structured+analysis LLM call."""
    resolves = json.loads(row.get("resolves", "[]"))
    cve_lines = []
    for r in resolves[:10]:
        line = (
            f"- {r['cve_id']}: {r['severity']} | CVSS {r['cvss']:.1f} | "
            f"EPSS {r['epss']:.1%} | {r['reachability']}"
        )
        if r.get("exploit_available"):
            line += " | EXPLOIT AVAILABLE"
        if r.get("in_kev"):
            line += " | IN CISA KEV"
        cve_lines.append(line)

    dep_context = (
        f"Direct dependency\nPath: {row.get('dep_path_display', '')}"
        if row.get("dep_is_direct", True)
        else f"Transitive via {row.get('dep_direct_dependency', 'unknown')}\n"
        f"Path: {row.get('dep_path_display', '')}"
    )

    references = _build_references_block(row, resolves)

    sections = [
        f"## Component\nPackage: {row.get('purl', '')}\n"
        f"Current version: {row.get('component_version', '')}\n"
        f"Ecosystem: {row.get('ecosystem', '')}",
        "## Vulnerabilities\n" + "\n".join(cve_lines),
    ]

    fix_ver = row.get("fixed_version", "")
    fix_src = row.get("fix_source", "")
    if fix_ver:
        sections.append(
            f"## Pre-resolved Fix Version (verify this!)\n"
            f"Version: {fix_ver} (source: {fix_src})\n"
            f"WARNING: This version may be for a different branch/series than "
            f"the installed version {row.get('component_version', '')}. "
            f"Validate carefully."
        )

    if nvd_snippet:
        sections.append(f"## NVD Data\n{nvd_snippet}")

    sections.append(f"## Dependency Context\n{dep_context}")

    upgrade_inst = row.get("upgrade_instruction", "")
    if upgrade_inst:
        sections.append(
            f"## Upgrade Info\n{upgrade_inst}\n"
            f"Type: {row.get('upgrade_type', '')} "
            f"({row.get('breaking_change_risk', '')} risk)"
        )

    aff = row.get("affected_functions", "")
    if aff:
        sections.append(f"## Affected Functions\n{aff}")

    if references:
        sections.append(f"## References\n{references}")

    # Workaround & mitigation references from NVD
    workaround_urls_raw = str(row.get("workaround_urls", "[]"))
    try:
        workaround_urls = json.loads(workaround_urls_raw)
    except (json.JSONDecodeError, TypeError):
        workaround_urls = []
    if workaround_urls:
        url_lines = "\n".join(f"- {u}" for u in workaround_urls[:5])
        sections.append(f"## Workaround & Mitigation References\n{url_lines}")

    # Fix version validation context
    fix_validated = row.get("fix_validated")
    fix_validation_note = str(row.get("fix_validation_note", ""))
    if fix_validated is not None and not fix_validated:
        sections.append(
            f"## Fix Version Validation WARNING\n"
            f"The recommended fix version has known CVEs. {fix_validation_note}\n"
            f"Consider recommending a later version."
        )

    return "\n\n".join(sections)


def _enrich_with_combined_analysis(
    df: pd.DataFrame,
    cfg: Any,
    additional_data: dict,
    nvd_snippets_map: dict[str, str] | None = _UNSET,
) -> pd.DataFrame:
    """Single high-model pass: structured verdict + deep analysis per action.

    Replaces both ``_enrich_with_llm_guidance`` (Haiku) and
    ``_enrich_with_ai_analysis`` (Opus) when ``ai_analysis=True``.
    """
    try:
        from fs_report.llm_client import LLMClient
    except ImportError:
        logger.warning("LLM client not available, skipping combined analysis")
        df["ai_analysis"] = ""
        return df

    import hashlib
    import os

    has_creds = any(
        os.getenv(v) for v in ("ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN")
    )
    if not has_creds:
        logger.info("No AI provider credentials found, skipping combined analysis")
        df["ai_analysis"] = ""
        return df

    cache_dir = getattr(cfg, "cache_dir", None) if cfg else None
    cache_ttl = getattr(cfg, "ai_cache_ttl", 0) if cfg else 0

    try:
        llm = LLMClient(cache_dir=cache_dir, cache_ttl=cache_ttl)
    except Exception as e:
        logger.warning(f"Failed to initialize LLM client: {e}")
        df["ai_analysis"] = ""
        return df

    # --- Build NVD snippets per component (reuse pre-built map or build on demand) ---
    if nvd_snippets_map is _UNSET or nvd_snippets_map is None:
        nvd_snippets_map = _build_nvd_snippets_map(df, _init_nvd_client(cfg))

    # --- Build (action_key, context_prompt) tuples ---
    _deployment_ctx = (
        additional_data.get("deployment_context") if additional_data else None
    )
    _ctx_hash = _deployment_ctx.context_hash() if _deployment_ctx else ""

    actions: list[tuple[str, str]] = []
    action_keys_by_idx: dict[int, str] = {}
    for idx, (_, row) in enumerate(df.iterrows()):
        comp = str(row.get("component_name", ""))
        ver = str(row.get("component_version", ""))
        cve_ids_str = str(row.get("cve_ids", "[]"))
        key_hash = hashlib.sha256(cve_ids_str.encode()).hexdigest()[:12]
        action_key = (
            f"combined:{comp}:{ver}:{key_hash}:{_ctx_hash}"
            if _ctx_hash
            else f"combined:{comp}:{ver}:{key_hash}"
        )
        action_keys_by_idx[idx] = action_key

        comp_key = f"{comp}:{ver}"
        nvd_snippet = nvd_snippets_map.get(comp_key, "")
        context_prompt = _build_combined_context_prompt(row, nvd_snippet)
        actions.append((action_key, context_prompt))

    if not actions:
        df["ai_analysis"] = ""
        return df

    # --- Run batch combined analysis ---
    results = llm.generate_batch_combined_analysis(actions)

    # --- Map results back to DataFrame ---
    verdicts = []
    confidences = []
    rationales = []
    guidances = []
    analyses = []
    llm_workarounds = []
    llm_breaking_changes = []
    ai_fix_count = 0

    for idx, (_, row) in enumerate(df.iterrows()):
        action_key = action_keys_by_idx[idx]
        structured, markdown = results.get(action_key, ({}, ""))

        verdicts.append(str(structured.get("verdict", "affected")))
        confidences.append(str(structured.get("confidence", "")))
        rationales.append(str(structured.get("rationale", "")))
        guidances.append(str(structured.get("guidance", "")))
        analyses.append(markdown)
        llm_workarounds.append(str(structured.get("workarounds", "")))
        llm_breaking_changes.append(str(structured.get("breaking_changes", "")))

        # Override fix_version when Opus provides a corrected version
        ai_fix = str(structured.get("fix_version", "")).strip()
        verdict = structured.get("verdict", "affected")

        if verdict == "not_affected":
            # Clear fix version for not-affected items
            if ai_fix.lower() in ("none", "n/a", ""):
                df.at[row.name, "fixed_version"] = ""
                df.at[row.name, "fix_source"] = ""
                df.at[row.name, "has_fix"] = False
        elif ai_fix and ai_fix.lower() not in (
            "unknown",
            "n/a",
            "none",
            "",
            "verify latest stable release",
        ):
            current_fix = str(row.get("fixed_version", ""))
            if not current_fix or current_fix != ai_fix:
                df.at[row.name, "fixed_version"] = ai_fix
                df.at[row.name, "fix_source"] = "ai"
                df.at[row.name, "has_fix"] = True
                ai_fix_count += 1

    df["ai_verdict"] = verdicts
    df["ai_confidence"] = confidences
    df["ai_rationale"] = rationales
    df["llm_guidance"] = guidances
    df["ai_analysis"] = analyses
    df["llm_workarounds"] = llm_workarounds
    df["llm_breaking_changes"] = llm_breaking_changes

    # --- Regenerate upgrade fields for corrected fix versions ---
    # When the AI changes fixed_version, the pre-computed upgrade_instruction,
    # upgrade_command, upgrade_type, and breaking_change_risk are stale.
    if ai_fix_count:
        logger.info(f"Combined analysis corrected {ai_fix_count} fix versions")
        _regenerate_upgrade_fields(df)

    # Clear upgrade fields for not_affected actions
    not_affected_mask = df["ai_verdict"] == "not_affected"
    if not_affected_mask.any():
        df.loc[not_affected_mask, "upgrade_instruction"] = ""
        df.loc[not_affected_mask, "upgrade_command"] = ""

    stats = llm.get_stats()
    logger.info(
        f"Combined analysis: {stats['api_calls']} API calls, "
        f"{stats['cache_hits']} cache hits"
    )
    return df


def _regenerate_upgrade_fields(df: pd.DataFrame) -> None:
    """Regenerate upgrade_instruction/command/type/risk from current fix versions.

    Called after the combined analysis corrects fix versions so that these
    derived fields match the AI-corrected version, not the original NVD one.
    """
    from fs_report.purl_utils import (
        breaking_change_risk,
        classify_upgrade,
        upgrade_command,
        upgrade_instruction,
    )

    for idx, row in df.iterrows():
        fix = str(row.get("fixed_version", ""))
        if not fix:
            continue
        purl = str(row.get("purl", ""))
        current = str(row.get("component_version", ""))
        ut = classify_upgrade(current, fix)
        risk = breaking_change_risk(ut)
        cmd = upgrade_command(purl, fix) if purl else ""
        instr = upgrade_instruction(purl, fix) if purl else ""

        df.at[idx, "upgrade_type"] = ut.value
        df.at[idx, "breaking_change_risk"] = risk
        df.at[idx, "upgrade_command"] = cmd or ""
        df.at[idx, "upgrade_instruction"] = instr


# ---------------------------------------------------------------------------
# Agent prompt generation (prompt mode)
# ---------------------------------------------------------------------------

_PROJECT_PROMPT_TEMPLATE = """You are performing security remediation on {project_name} (version {project_version}).

This remediation package contains {total_components} components covering {total_cves} CVEs.
{fixable_count} have known fix versions, {investigate_count} require investigation.
{p0_count} are P0/CRITICAL (fix immediately), {p1_count} are P1/HIGH (fix this sprint).

Work through these actions in priority order. For each:
1. If a fix version is known: apply the upgrade, build, and test
2. If no fix version: check upstream for patches, evaluate reachability, consider mitigation
3. Commit with message: "fix(security): [action] [component] - resolves [CVE IDs]"

{actions_block}

{suppressed_block}

After completing all upgrades, regenerate the SBOM and verify no P0/P1 findings remain."""


def _generate_agent_prompts(
    df: pd.DataFrame,
    sbom_map: dict,
    component_details: dict | None = None,
    cfg: Any = None,
    nvd_snippets_map: dict[str, str] | None = _UNSET,
) -> pd.DataFrame:
    """Generate per-action AI agent prompts.

    Uses the same prompt that --ai-analysis sends to the LLM,
    so users can send these to their own LLM for identical results.
    """
    from fs_report.llm_client import build_combined_analysis_wrapper

    # Resolve deployment context from cfg's additional_data if available
    _deployment_ctx = getattr(cfg, "_deployment_context", None)
    wrapper = build_combined_analysis_wrapper(_deployment_ctx)

    # Build NVD snippets (reuse pre-built map or build on demand)
    if nvd_snippets_map is _UNSET or nvd_snippets_map is None:
        nvd_snippets_map = _build_nvd_snippets_map(df, _init_nvd_client(cfg))

    prompts = []
    for _, row in df.iterrows():
        comp_key = (
            f"{row.get('component_name', '')}:" f"{row.get('component_version', '')}"
        )
        nvd_snippet = nvd_snippets_map.get(comp_key, "")
        context = _build_combined_context_prompt(row, nvd_snippet)
        prompt = wrapper + context
        prompts.append(prompt)

    df = df.copy()
    df["agent_prompt"] = prompts
    return df


def _build_references_block(row: Any, resolves: list[dict]) -> str:
    """Build a references block from NVD patch/advisory URLs."""
    lines: list[str] = []

    # Aggregated action-level URLs
    try:
        patch_urls = (
            json.loads(row.get("patch_urls", "[]")) if row.get("patch_urls") else []
        )
    except (json.JSONDecodeError, TypeError):
        patch_urls = []
    try:
        advisory_urls = (
            json.loads(row.get("advisory_urls", "[]"))
            if row.get("advisory_urls")
            else []
        )
    except (json.JSONDecodeError, TypeError):
        advisory_urls = []

    if patch_urls:
        lines.append("Patch references:")
        for url in patch_urls[:8]:
            lines.append(f"- {url}")

    if advisory_urls:
        lines.append("Advisory references:")
        for url in advisory_urls[:5]:
            lines.append(f"- {url}")

    if not lines:
        # Fall back to NVD search link
        cve_ids = [r.get("cve_id", "") for r in resolves[:3] if r.get("cve_id")]
        if cve_ids:
            lines.append("No patch URLs found in NVD. Search upstream advisories for:")
            for cve_id in cve_ids:
                lines.append(f"- {cve_id}: https://nvd.nist.gov/vuln/detail/{cve_id}")

    return "\n".join(lines) if lines else "No reference URLs available."


def _build_component_detail_block(comp_detail: dict) -> str:
    """Build a component detail section from API component data."""
    if not comp_detail:
        return ""

    lines: list[str] = ["## Component Detail (from platform)"]

    comp_type = comp_detail.get("type", "")
    if comp_type:
        lines.append(f"Type: {comp_type}")

    supplier = comp_detail.get("supplier", "")
    if supplier:
        lines.append(f"Supplier: {supplier}")

    licenses = comp_detail.get("declaredLicenses") or comp_detail.get("licenses", "")
    if licenses:
        lines.append(f"License: {licenses}")

    findings_count = comp_detail.get("findings")
    if findings_count is not None:
        lines.append(f"Total findings on this component: {findings_count}")

    source = comp_detail.get("source") or comp_detail.get("origin", [])
    if source:
        lines.append(
            f"Detection source: {', '.join(source) if isinstance(source, list) else source}"
        )

    bom_ref = comp_detail.get("bomRef", "")
    if bom_ref:
        lines.append(f"SBOM ref: {bom_ref}")

    return "\n".join(lines) if len(lines) > 1 else ""


def _generate_project_agent_prompt(
    actions_df: pd.DataFrame,
    suppressed_df: pd.DataFrame,
    project_name: str,
    project_version: str,
) -> str:
    """Generate a project-level meta-prompt covering all actions."""
    total_components = len(actions_df)
    cve_counts = (
        actions_df["cve_count"].sum() if "cve_count" in actions_df.columns else 0
    )
    fixable = (
        actions_df[actions_df.get("has_fix", pd.Series(False, index=actions_df.index))]
        if "has_fix" in actions_df.columns
        else pd.DataFrame()
    )
    p0 = (
        actions_df[actions_df["priority"] == "P0"]
        if "priority" in actions_df.columns
        else pd.DataFrame()
    )
    p1 = (
        actions_df[actions_df["priority"] == "P1"]
        if "priority" in actions_df.columns
        else pd.DataFrame()
    )

    # Build actions block
    action_blocks = []
    for priority_label in ["P0", "P1", "P2", "P3"]:
        prio_df = (
            actions_df[actions_df["priority"] == priority_label]
            if "priority" in actions_df.columns
            else pd.DataFrame()
        )
        if prio_df.empty:
            continue

        lines = [f"\n## {priority_label} Actions ({len(prio_df)})"]
        for _, row in prio_df.iterrows():
            cves = json.loads(row.get("cve_ids", "[]"))
            cve_str = ", ".join(cves[:5])
            if len(cves) > 5:
                cve_str += f" (+{len(cves) - 5} more)"
            fix_ver = row.get("fixed_version", "")
            if row.get("ai_verdict") == "not_affected":
                lines.append(
                    f"- VERIFY NOT-AFFECTED {row.get('component_name', '?')} "
                    f"{row.get('component_version', '?')} "
                    f"[{row.get('ecosystem', '?')}] "
                    f"(AI: likely false positive — resolves: {cve_str})"
                )
            elif fix_ver:
                lines.append(
                    f"- UPGRADE {row.get('component_name', '?')} "
                    f"{row.get('component_version', '?')} → {fix_ver} "
                    f"[{row.get('ecosystem', '?')}] "
                    f"(resolves: {cve_str})"
                )
            else:
                lines.append(
                    f"- INVESTIGATE {row.get('component_name', '?')} "
                    f"{row.get('component_version', '?')} "
                    f"[{row.get('ecosystem', '?')}] "
                    f"(no known fix — resolves: {cve_str})"
                )
            if row.get("upgrade_instruction"):
                lines.append(f"  Command: {row['upgrade_instruction']}")
        action_blocks.append("\n".join(lines))

    actions_block = "\n".join(action_blocks)

    suppressed_block = ""
    if not suppressed_df.empty:
        suppressed_block = (
            f"\n## Suppressed ({len(suppressed_df)} findings — no action needed)\n"
            "These findings were assessed as not exploitable via VEX analysis."
        )

    return _PROJECT_PROMPT_TEMPLATE.format(
        project_name=project_name,
        project_version=project_version,
        total_components=total_components,
        total_cves=int(cve_counts),
        fixable_count=len(fixable),
        investigate_count=total_components - len(fixable),
        p0_count=len(p0),
        p1_count=len(p1),
        actions_block=actions_block,
        suppressed_block=suppressed_block,
    )


# ---------------------------------------------------------------------------
# Summary, charts, JSON output
# ---------------------------------------------------------------------------


def _build_summary(
    actions_df: pd.DataFrame,
    suppressed_df: pd.DataFrame,
    unresolvable_df: pd.DataFrame,
) -> dict[str, Any]:
    """Build the summary statistics dict."""
    by_priority = {}
    by_ecosystem = {}
    if not actions_df.empty:
        if "priority" in actions_df.columns:
            by_priority = actions_df["priority"].value_counts().to_dict()
        if "ecosystem" in actions_df.columns:
            by_ecosystem = actions_df["ecosystem"].value_counts().to_dict()

    total_cves = (
        int(actions_df["cve_count"].sum())
        if not actions_df.empty and "cve_count" in actions_df.columns
        else 0
    )

    return {
        "total_components": len(actions_df),
        "total_actions": len(actions_df),  # backward compat
        "total_cves_resolved": total_cves,
        "suppressed_count": len(suppressed_df),
        "unresolvable_count": len(unresolvable_df),
        "by_priority": by_priority,
        "by_ecosystem": by_ecosystem,
    }


def _build_charts(
    actions_df: pd.DataFrame,
    suppressed_df: pd.DataFrame,
    unresolvable_df: pd.DataFrame,
) -> dict[str, pd.DataFrame]:
    """Build chart DataFrames for the HTML template."""
    charts = {}

    # Priority distribution
    if not actions_df.empty and "priority" in actions_df.columns:
        prio_counts = actions_df["priority"].value_counts().reset_index()
        prio_counts.columns = ["priority", "count"]
        charts["priority_distribution"] = prio_counts

    # Ecosystem breakdown
    if not actions_df.empty and "ecosystem" in actions_df.columns:
        eco_counts = actions_df["ecosystem"].value_counts().reset_index()
        eco_counts.columns = ["ecosystem", "count"]
        charts["ecosystem_breakdown"] = eco_counts

    # Fix coverage
    fix_data = pd.DataFrame(
        [
            {"category": "Fixable", "count": len(actions_df)},
            {"category": "Suppressed (VEX)", "count": len(suppressed_df)},
            {"category": "No Fix Available", "count": len(unresolvable_df)},
        ]
    )
    charts["fix_coverage"] = fix_data

    return charts


def _build_json_package(
    actions_df: pd.DataFrame,
    suppressed_df: pd.DataFrame,
    unresolvable_df: pd.DataFrame,
    summary: dict,
    project_name: str,
    project_version: str,
    project_prompt: str,
    domain: str,
    sbom_map: dict,
) -> dict[str, Any]:
    """Build the complete JSON remediation package for file output / IDE plugin."""
    # Find SBOM serial number
    sbom_serial = ""
    for sbom in sbom_map.values():
        if sbom.serial_number:
            sbom_serial = sbom.serial_number
            break

    package: dict[str, Any] = {
        "schema_version": "2.0.0",
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(),
            "generator": "fs-report",
            "project_name": project_name,
            "project_version": project_version,
            "sbom_serial_number": sbom_serial,
            "platform_domain": domain,
        },
        "summary": summary,
        "project_agent_prompt": project_prompt,
        "actions": [],
        "suppressed": [],
        "unresolvable": [],
    }

    # Build actions
    for idx, row in actions_df.iterrows():
        action = {
            "action_id": f"ACT-{idx:04d}",
            "priority": str(row.get("priority", "P3")),
            "action_type": "upgrade" if row.get("fixed_version") else "investigate",
            "component": {
                "purl": str(row.get("purl", "")),
                "name": str(row.get("component_name", "")),
                "current_version": str(row.get("component_version", "")),
                "fixed_version": str(row.get("fixed_version", "")),
                "ecosystem": str(row.get("ecosystem", "")),
            },
            "dependency_path": {
                "is_direct": bool(row.get("dep_is_direct", True)),
                "path": json.loads(str(row.get("dep_path", "[]"))),
                "depth": int(row.get("dep_depth", 1)),
                "direct_dependency": str(row.get("dep_direct_dependency", "")),
                "display": str(row.get("dep_path_display", "")),
            },
            "resolves": json.loads(str(row.get("resolves", "[]"))),
            "remediation": {
                "upgrade_command": str(row.get("upgrade_command", "")),
                "upgrade_instruction": str(row.get("upgrade_instruction", "")),
                "upgrade_type": str(row.get("upgrade_type", "")),
                "breaking_change_risk": str(row.get("breaking_change_risk", "")),
                "manifest_patterns": json.loads(
                    str(row.get("manifest_patterns", "[]"))
                ),
                "search_pattern": str(row.get("search_pattern", "")),
            },
            "context": {
                "llm_guidance": str(row.get("llm_guidance", "")),
                "ai_verdict": str(row.get("ai_verdict", "")),
                "ai_confidence": str(row.get("ai_confidence", "")),
                "ai_rationale": str(row.get("ai_rationale", "")),
                "affected_functions": str(row.get("affected_functions", "")),
                "cve_count": int(row.get("cve_count", 0)),
                "ai_analysis": str(row.get("ai_analysis", "")),
            },
            "fix_validated": bool(row.get("fix_validated", True)),
            "fix_validation_note": str(row.get("fix_validation_note", "")),
            "workaround_urls": json.loads(str(row.get("workaround_urls", "[]"))),
            "remediation_options": json.loads(
                str(row.get("remediation_options", "[]"))
            ),
            "effort_estimate": str(row.get("effort_estimate", "unknown")),
        }
        if "agent_prompt" in row and row["agent_prompt"]:
            action["agent_prompt"] = str(row["agent_prompt"])

        package["actions"].append(action)

    # Build suppressed
    for _, row in suppressed_df.iterrows():
        package["suppressed"].append(
            {
                "cve_id": str(row.get("finding_id", "")),
                "component_purl": str(row.get("purl", "")),
                "component_name": str(row.get("component_name", "")),
                "vex_state": str(row.get("vex_state", "")),
                "vex_justification": str(row.get("vex_justification", "")),
                "detail": str(row.get("detail", "")),
            }
        )

    # Build unresolvable
    for _, row in unresolvable_df.iterrows():
        package["unresolvable"].append(
            {
                "component_name": str(row.get("component_name", "")),
                "component_version": str(row.get("component_version", "")),
                "purl": str(row.get("purl", "")),
                "cve_count": int(row.get("cve_count", 0)),
                "cve_ids": json.loads(str(row.get("cve_ids", "[]"))),
                "worst_band": str(row.get("worst_band", "")),
                "max_cvss": float(row.get("max_cvss", 0)),
            }
        )

    return package


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flatten_for_tabular(actions_df: pd.DataFrame) -> pd.DataFrame:
    """Flatten actions DataFrame for CSV/XLSX output."""
    if actions_df.empty:
        return actions_df

    display_cols = [
        "priority",
        "component_name",
        "component_version",
        "fixed_version",
        "fix_validated",
        "fix_validation_note",
        "ecosystem",
        "upgrade_type",
        "breaking_change_risk",
        "upgrade_instruction",
        "cve_count",
        "max_cvss",
        "max_epss",
        "any_kev",
        "any_exploit",
        "worst_band",
        "affected_functions",
        "dep_is_direct",
        "dep_path_display",
        "effort_estimate",
        "project_name",
    ]
    available = [c for c in display_cols if c in actions_df.columns]
    return actions_df[available].copy()


def _infer_project_name(df: pd.DataFrame, cfg: Any) -> str:
    """Infer the project name from the data or config."""
    if "project_name" in df.columns:
        names = df["project_name"].dropna().unique()
        if len(names) == 1:
            return str(names[0])
        elif len(names) > 1:
            return ", ".join(str(n) for n in names[:3])
    if cfg and hasattr(cfg, "project_filter") and cfg.project_filter:
        return str(cfg.project_filter)
    return "Unknown Project"


def _infer_project_version(df: pd.DataFrame) -> str:
    """Infer the project version from the data."""
    if "version_name" in df.columns:
        versions = df["version_name"].dropna().unique()
        if len(versions) == 1:
            return str(versions[0])
    return ""


def _empty_result() -> dict[str, Any]:
    """Return an empty result set."""
    return {
        "main": pd.DataFrame(),
        "actions_df": pd.DataFrame(),
        "suppressed_df": pd.DataFrame(),
        "unresolvable_df": pd.DataFrame(),
        "remediation_summary": {
            "total_components": 0,
            "total_actions": 0,  # backward compat
            "total_cves_resolved": 0,
            "suppressed_count": 0,
            "unresolvable_count": 0,
            "by_priority": {},
            "by_ecosystem": {},
        },
        "scope_label": "",
        "project_name": "",
        "project_version": "",
        "project_agent_prompt": "",
        "charts": {},
        "json_package": {
            "schema_version": "2.0.0",
            "actions": [],
            "suppressed": [],
            "unresolvable": [],
        },
    }
