"""
Pandas transform for the False Positive Analysis report.

Consumes findings from ``/public/v0/findings`` and produces:

- FP candidate list: open findings that trigger one or more signals
- VEX recommendations for each candidate
- Signal-level detail for analyst review
- Charts and summary statistics

Tier 1 — three mechanical checks:
1. Cross-project FP propagation — same CVE+component already triaged FP elsewhere
2. NVD version-range mismatch — component version outside NVD affected range
3. Rejected/Disputed CVE — NVD vuln_status indicates Rejected or Disputed

Tier 2 — AI applicability analysis (when ``--ai`` is active):
4. Component-identity verdict — AI determines whether the scanned component
   is the product NVD's CVEs target, or a different product with a colliding
   name (e.g. musl mistaken for glibc).
5. Per-CVE applicability fan-out — for components whose identity is
   ``mismatched``, classify each attributed CVE as ``does_not_apply`` or
   ``might_still_apply``.

Per-finding triage guidance lives in the Triage Prioritization report, not
here. FPA is intentionally focused on detecting false positives.
"""

from __future__ import annotations

import logging
import math
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OPEN_STATUSES = {"OPEN", "IN_TRIAGE", "NO_STATUS", "UNKNOWN"}
_TRIAGED_FP_STATUSES = {"FALSE_POSITIVE", "NOT_AFFECTED"}
_TRIAGED_STATUSES = {"FALSE_POSITIVE", "NOT_AFFECTED", "AFFECTED", "RESOLVED"}

_JUSTIFICATION_MAP = {
    "cross_project_propagation": "CODE_NOT_PRESENT",
    "nvd_version_mismatch": "CODE_NOT_PRESENT",
    "rejected_cve": "CODE_NOT_PRESENT",
    "disputed_cve": "CODE_NOT_PRESENT",
    "ai_component_not_affected": "CODE_NOT_PRESENT",
}

# Ordered severity levels for consistent display / sorting
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

# Cap CVE counts in AI prompts. Components like the Linux kernel can carry
# 3000+ CVEs; passing the full list (and full NVD enrichment) blows past
# Anthropic's 1M-token context. The identity prompt only samples 15 CVEs in
# the list — keep its NVD snippet aligned to that same sample. The per-CVE
# applicability fan-out runs over all CVEs but is chunked so each call stays
# well under the model's input limit.
_IDENTITY_PROMPT_CVE_SAMPLE = 15
_PER_CVE_FANOUT_CHUNK_SIZE = 50


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def _safe_val(val: Any) -> Any:
    """Return None if val is NaN, otherwise val."""
    if isinstance(val, float) and math.isnan(val):
        return None
    return val


def _normalize_finding(rec: dict[str, Any]) -> dict[str, Any]:
    """Extract canonical columns from a raw API finding dict."""
    # CVE / finding ID
    cve_id = _safe_val(rec.get("cveId"))
    if not cve_id:
        cve_obj = rec.get("cve")
        if isinstance(cve_obj, dict):
            cve_id = _safe_val(cve_obj.get("id"))
        elif isinstance(cve_obj, str):
            cve_id = cve_obj or None
    if not cve_id:
        cve_id = _safe_val(rec.get("findingId"))
    if not cve_id:
        cve_id = _safe_val(rec.get("title")) or "N/A"

    finding_id = _safe_val(rec.get("findingId")) or cve_id

    # Component
    comp = rec.get("component")
    component_name = _safe_val(rec.get("componentName"))
    if not component_name and isinstance(comp, dict):
        component_name = _safe_val(comp.get("name")) or _safe_val(comp.get("id"))
    if not component_name:
        component_name = "Unknown"

    component_version = _safe_val(rec.get("componentVersion")) or _safe_val(
        rec.get("componentVersionName")
    )
    if not component_version and isinstance(comp, dict):
        component_version = _safe_val(comp.get("version"))
    if not component_version:
        component_version = "Unknown"

    # Project
    proj = rec.get("project")
    project_name = _safe_val(rec.get("projectName"))
    if not project_name and isinstance(proj, dict):
        project_name = _safe_val(proj.get("name")) or _safe_val(proj.get("id"))
    if not project_name:
        project_name = "Unknown"

    # Project version
    pv = rec.get("projectVersion")
    project_version_id = _safe_val(rec.get("projectVersionId"))
    if not project_version_id and isinstance(pv, dict):
        project_version_id = _safe_val(pv.get("id"))
    if not project_version_id:
        project_version_id = ""
    project_version_id = str(project_version_id)

    # Severity / status
    severity = str(_safe_val(rec.get("severity")) or "UNKNOWN").upper()
    status = str(_safe_val(rec.get("status")) or "UNKNOWN").upper()

    # Reachability
    reach_raw = _safe_val(rec.get("reachabilityScore"))
    reachability_score: int | float = 0
    if reach_raw is not None:
        try:
            reachability_score = int(reach_raw)
        except (ValueError, TypeError):
            reachability_score = 0

    # Risk (0-100 API scale)
    risk_raw = _safe_val(rec.get("risk"))
    risk: int | float = 0
    if risk_raw is not None:
        try:
            risk = int(risk_raw)
        except (ValueError, TypeError):
            risk = 0

    return {
        "id": _safe_val(rec.get("id")),
        "finding_id": str(finding_id),
        "cve_id": str(cve_id),
        "component_name": str(component_name),
        "component_version": str(component_version),
        "project_name": str(project_name),
        "project_version_id": project_version_id,
        "severity": severity,
        "status": status,
        "reachability_score": reachability_score,
        "risk": risk,
        "title": str(_safe_val(rec.get("title")) or ""),
    }


# ---------------------------------------------------------------------------
# Mechanical checks — each returns list[dict] of signal dicts
# ---------------------------------------------------------------------------


def _check_cross_project_propagation(
    finding: dict[str, Any], triaged_df: pd.DataFrame
) -> list[dict[str, Any]]:
    """Check 1: Same CVE+component already triaged FP in another project."""
    if triaged_df.empty:
        return []

    cve = finding.get("cve_id", "")
    comp_name = finding.get("component_name", "")
    comp_ver = finding.get("component_version", "")

    mask = (
        (triaged_df["cve_id"] == cve)
        & (triaged_df["component_name"] == comp_name)
        & (triaged_df["component_version"] == comp_ver)
        & (triaged_df["status"].isin(_TRIAGED_FP_STATUSES))
    )
    matches = triaged_df[mask]

    if matches.empty:
        return []

    projects = ", ".join(sorted(matches["project_name"].unique()))
    return [
        {
            "signal_type": "cross_project_propagation",
            "confidence": "MEDIUM",
            "reason": f"Same CVE+component triaged FP in: {projects}",
        }
    ]


def _check_nvd_version_range(
    finding: dict[str, Any], nvd_client: Any
) -> list[dict[str, Any]]:
    """Check 3: Component version outside NVD affected range."""
    if nvd_client is None:
        return []

    cve_id = finding.get("cve_id", "")
    if not cve_id or cve_id == "N/A":
        return []

    try:
        nvd_record = nvd_client.get(cve_id)
    except Exception:
        return []

    if nvd_record is None:
        return []

    comp_name = finding.get("component_name", "")
    comp_ver = finding.get("component_version", "")

    affected_ranges = getattr(nvd_record, "affected_ranges", None)
    if not affected_ranges:
        return []

    fix_version = None
    try:
        fix_version = nvd_record.fix_version_for(comp_name, comp_ver)
    except Exception:
        return []

    if fix_version is None:
        return []

    return [
        {
            "signal_type": "nvd_version_mismatch",
            "confidence": "MEDIUM",
            "reason": (
                f"{comp_name}=={comp_ver} outside NVD affected range "
                f"(fix: {fix_version})"
            ),
        }
    ]


def _check_rejected_cve(
    finding: dict[str, Any], nvd_client: Any
) -> list[dict[str, Any]]:
    """Check 4: NVD vuln_status indicates Rejected or Disputed."""
    if nvd_client is None:
        return []

    cve_id = finding.get("cve_id", "")
    if not cve_id or cve_id == "N/A":
        return []

    try:
        nvd_record = nvd_client.get(cve_id)
    except Exception:
        return []

    if nvd_record is None:
        return []

    vuln_status = getattr(nvd_record, "vuln_status", "") or ""

    if "Rejected" in vuln_status:
        return [
            {
                "signal_type": "rejected_cve",
                "confidence": "HIGH",
                "reason": f"{cve_id} is Rejected in NVD",
            }
        ]
    if "Disputed" in vuln_status:
        return [
            {
                "signal_type": "disputed_cve",
                "confidence": "MEDIUM",
                "reason": f"{cve_id} is Disputed in NVD",
            }
        ]
    return []


# ---------------------------------------------------------------------------
# Confidence rollup
# ---------------------------------------------------------------------------


def _rollup_confidence(signals: list[dict[str, Any]]) -> str | None:
    """Roll up per-signal confidence levels into a single finding confidence."""
    if not signals:
        return None

    levels = [s.get("confidence", "LOW") for s in signals]

    if "HIGH" in levels:
        return "HIGH"
    medium_count = levels.count("MEDIUM")
    if medium_count >= 2:
        return "HIGH"
    if medium_count == 1:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# VEX recommendation builder
# ---------------------------------------------------------------------------


def _build_vex_recommendation(
    finding: dict[str, Any],
    signals: list[dict[str, Any]],
    confidence: str,
) -> dict[str, Any] | None:
    """Build a VEX recommendation dict for a candidate finding.

    Only HIGH-confidence candidates get a ``NOT_AFFECTED`` recommendation.
    MEDIUM/LOW candidates return ``None`` — they surface in the report as a
    review note, but produce no VEX artifact for autotriage to apply.
    """
    if confidence != "HIGH":
        return None

    first_signal_type = signals[0]["signal_type"] if signals else ""
    justification = _JUSTIFICATION_MAP.get(first_signal_type, "CODE_NOT_PRESENT")

    signal_types = [s["signal_type"] for s in signals]

    # Build reason: for AI signals, include the detailed guidance/action
    # so that autotriage writes the LLM's analysis into the VEX reason field.
    reason_parts: list[str] = []
    for sig in signals:
        ai_detail = sig.get("ai_guidance", "") or sig.get("ai_action", "")
        if ai_detail:
            reason_parts.append(ai_detail)
        elif sig.get("reason"):
            reason_parts.append(sig["reason"])
    reasons = "; ".join(reason_parts)

    return {
        "id": finding.get("id"),
        "finding_id": finding.get("finding_id", finding.get("cve_id", "")),
        "component_name": finding.get("component_name", ""),
        "component_version": finding.get("component_version", ""),
        "project_name": finding.get("project_name", ""),
        "project_version_id": finding.get("project_version_id", ""),
        "recommended_vex_status": "NOT_AFFECTED",
        "justification": justification,
        "reason": reasons,
        "fp_confidence": confidence,
        "fp_signals": signal_types,
    }


# ---------------------------------------------------------------------------
# Chart builder
# ---------------------------------------------------------------------------


def _build_charts(
    candidates_df: pd.DataFrame,
    signals_df: pd.DataFrame,
) -> dict[str, Any]:
    """Build chart data from candidates and signals."""
    charts: dict[str, Any] = {}

    # FP candidates by signal type
    if not signals_df.empty and "signal_type" in signals_df.columns:
        type_counts = signals_df["signal_type"].value_counts()
        charts["fp_by_signal_type"] = {
            "labels": list(type_counts.index),
            "values": [int(v) for v in type_counts.values],
        }
    else:
        charts["fp_by_signal_type"] = {"labels": [], "values": []}

    # FP candidates by severity
    if not candidates_df.empty and "severity" in candidates_df.columns:
        sev_counts = candidates_df["severity"].value_counts()
        ordered = [s for s in _SEVERITY_ORDER if s in sev_counts.index]
        charts["fp_by_severity"] = {
            "labels": ordered,
            "values": [int(sev_counts[s]) for s in ordered],
        }
    else:
        charts["fp_by_severity"] = {"labels": [], "values": []}

    # FP candidates by component (top 10)
    if not candidates_df.empty and "component_name" in candidates_df.columns:
        comp_counts = candidates_df["component_name"].value_counts().head(10)
        charts["fp_by_component"] = {
            "labels": list(comp_counts.index),
            "values": [int(v) for v in comp_counts.values],
        }
    else:
        charts["fp_by_component"] = {"labels": [], "values": []}

    return charts


# ---------------------------------------------------------------------------
# Empty result helper
# ---------------------------------------------------------------------------


def _empty_result() -> dict[str, Any]:
    return {
        "main": pd.DataFrame(),
        "summary": {
            "total_findings": 0,
            "total_open_findings": 0,
            "total_triaged_findings": 0,
            "fp_candidates": 0,
            "ai_detections": 0,
        },
        "candidates": pd.DataFrame(),
        "signals": pd.DataFrame(),
        "vex_recommendations": [],
        "identity_assertions": [],
        "fp_charts": {},
    }


# ---------------------------------------------------------------------------
# Main transform
# ---------------------------------------------------------------------------


def false_positive_analysis_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config | None = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Transform ``/findings`` data into a False Positive Analysis report.

    Runs three mechanical checks against each open finding, rolls up confidence,
    and produces VEX recommendations for FP candidates.

    Returns dict with keys: main, summary, candidates, signals,
    vex_recommendations, charts.
    """
    # ------------------------------------------------------------------
    # 1. Normalise input to list of dicts
    # ------------------------------------------------------------------
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return _empty_result()
        records: list[dict[str, Any]] = [
            {str(k): v for k, v in r.items()} for r in data.to_dict(orient="records")
        ]
    elif not data:
        return _empty_result()
    else:
        records = list(data)

    if not records:
        return _empty_result()

    # ------------------------------------------------------------------
    # 2. Normalise each finding
    # ------------------------------------------------------------------
    normalised = [_normalize_finding(rec) for rec in records]
    df = pd.DataFrame(normalised)

    # ------------------------------------------------------------------
    # 3. Split open vs triaged
    # ------------------------------------------------------------------
    open_mask = df["status"].isin(_OPEN_STATUSES)
    triaged_mask = df["status"].isin(_TRIAGED_STATUSES)

    open_df = df[open_mask].copy()
    triaged_df = df[triaged_mask].copy()

    # ------------------------------------------------------------------
    # 4. Extract optional NVD client
    # ------------------------------------------------------------------
    nvd_client = None
    if additional_data and isinstance(additional_data, dict):
        nvd_client = additional_data.get("nvd_client")

    # ------------------------------------------------------------------
    # 5. Run mechanical checks on each open finding
    # ------------------------------------------------------------------
    # Collect signals keyed by finding_id so AI tier can append later
    finding_signals: dict[str, list[dict[str, Any]]] = {}
    # Keep a lookup of finding dicts by finding_id for rollup phase
    finding_lookup: dict[str, dict[str, Any]] = {}
    mechanical_detections = 0

    for _, row in open_df.iterrows():
        finding: dict[str, Any] = {str(k): v for k, v in row.to_dict().items()}
        fid = str(finding.get("finding_id", ""))
        signals: list[dict[str, Any]] = []

        # Check 1: Cross-project FP propagation
        signals.extend(_check_cross_project_propagation(finding, triaged_df))

        # Check 2: NVD version-range mismatch
        signals.extend(_check_nvd_version_range(finding, nvd_client))

        # Check 3: Rejected/Disputed CVE
        signals.extend(_check_rejected_cve(finding, nvd_client))

        finding_lookup[fid] = finding
        if signals:
            finding_signals[fid] = signals
            mechanical_detections += len(signals)
        else:
            # Ensure entry exists so AI tier can add signals for this finding
            finding_signals[fid] = []

    # ------------------------------------------------------------------
    # 5b. AI tier — component identity + per-CVE applicability
    # ------------------------------------------------------------------
    ai_detections = 0
    ai_component_prompts: list[dict[str, str]] = []
    ai_triage_prompts: list[dict[str, str]] = []
    ai_component_results: list[dict[str, str]] = []
    identity_assertions: list[dict[str, Any]] = []

    ai_enabled = config is not None and (
        getattr(config, "ai", False) or getattr(config, "ai_prompts", False)
    )
    if ai_enabled and not open_df.empty:
        try:
            # Build component groups from open findings
            comp_groups = open_df.groupby(
                ["component_name", "component_version"], sort=False
            )
            components_list: list[dict[str, Any]] = []
            for (cname, cver), grp in comp_groups:
                cve_ids = grp["cve_id"].dropna().unique().tolist()
                if cve_ids:
                    components_list.append(
                        {
                            "component_name": cname,
                            "component_version": cver,
                            "cve_ids": cve_ids,
                        }
                    )

            ai_prompts_only = getattr(config, "ai_prompts", False) and not getattr(
                config, "ai", False
            )

            # Build identity prompts for export (same prompt the live call uses).
            # Kept for --ai-prompts air-gapped workflow. Build eagerly so the
            # prompts file is written even when we won't call the LLM.
            def _identity_prompt_text(comp: dict[str, Any], nvd_snippet: str) -> str:
                cve_section = "\n".join(
                    f"- {cve}" for cve in comp["cve_ids"][:_IDENTITY_PROMPT_CVE_SAMPLE]
                )
                nvd_block = f"\n{nvd_snippet}\n" if nvd_snippet else ""
                return (
                    f"You are a security analyst determining whether a scanned "
                    f"software component is actually the product that NVD associates "
                    f"with its CVEs, or a different product that happens to share a "
                    f"name or path.\n\n"
                    f"Scanned component: {comp['component_name']} version "
                    f"{comp['component_version']}\n\n"
                    f"CVEs attributed to it (sample):\n{cve_section}\n{nvd_block}\n"
                    f"Answer in this exact format:\n"
                    f"IDENTITY: <confirmed | mismatched | ambiguous>\n"
                    f'LIKELY_PRODUCT: <e.g., "musl libc">\n'
                    f'NVD_PRODUCT: <e.g., "GNU glibc">\n'
                    f"EVIDENCE: <1-3 sentences>\n"
                    f"CONFIDENCE: <high | medium | low>\n"
                )

            # NVD enrichment (optional). Only fetch / snippet the sampled CVEs
            # used in the identity prompt — passing every CVE for components
            # with thousands of attributed CVEs (e.g. Linux kernel) builds a
            # multi-MB prompt and blows past the LLM context window.
            nvd_snippets_map: dict[str, str] = {}
            _nvd = additional_data.get("nvd_client") if additional_data else None
            if _nvd and components_list:
                identity_cves_per_comp: list[list[str]] = [
                    comp["cve_ids"][:_IDENTITY_PROMPT_CVE_SAMPLE]
                    for comp in components_list
                ]
                all_cves: list[str] = []
                for ids in identity_cves_per_comp:
                    all_cves.extend(ids)
                unique_cves = list(dict.fromkeys(all_cves))
                if unique_cves:
                    logger.info(f"Fetching NVD data for {len(unique_cves)} CVEs...")
                    _nvd.get_batch(unique_cves, progress=True)
                    for comp, ids in zip(
                        components_list, identity_cves_per_comp, strict=True
                    ):
                        comp_key = (
                            f"{comp['component_name']}:{comp['component_version']}"
                        )
                        snippet = _nvd.format_batch_for_prompt(ids)
                        if snippet:
                            nvd_snippets_map[comp_key] = snippet

            # Build component-identity prompts for export (both --ai and --ai-prompts)
            for comp in components_list:
                comp_key = f"{comp['component_name']}:{comp['component_version']}"
                ai_component_prompts.append(
                    {
                        "component": (
                            f"{comp['component_name']} {comp['component_version']}"
                        ),
                        "prompt": _identity_prompt_text(
                            comp, nvd_snippets_map.get(comp_key, "")
                        ),
                    }
                )

            # Write prompts file when --ai-prompts is set (or --ai as a side effect),
            # preserves existing air-gapped workflow.
            if ai_component_prompts:
                _output_dir = getattr(config, "output_dir", None)
                if _output_dir:
                    from datetime import datetime
                    from pathlib import Path

                    _recipe_dir = Path(_output_dir) / "False Positive Analysis"
                    _recipe_dir.mkdir(parents=True, exist_ok=True)
                    _prompts_path = _recipe_dir / "False Positive Analysis_prompts.md"
                    _lines = [
                        "# False Positive Analysis - AI Prompts\n",
                        f"Generated: "
                        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n",
                        f"\n{len(ai_component_prompts)} component identity prompts. "
                        "If a prompt answer is IDENTITY: mismatched, run the "
                        "per-CVE applicability fan-out prompt (constructed from "
                        "the LIKELY_PRODUCT / NVD_PRODUCT answers) to classify "
                        "each CVE.\n",
                        "\n---\n\n# Component Identity Prompts\n",
                    ]
                    for p in ai_component_prompts:
                        _lines.append(f"\n## {p['component']}\n\n")
                        _lines.append(f"```\n{p['prompt']}\n```\n")
                    _prompts_path.write_text("".join(_lines), encoding="utf-8")
                    logger.info(
                        f"Wrote {len(ai_component_prompts)} identity prompts to "
                        f"{_prompts_path}"
                    )

            if not ai_prompts_only and components_list:
                from fs_report.llm_client import LLMClient

                llm = LLMClient(
                    cache_dir=getattr(config, "cache_dir", None),
                    cache_ttl=getattr(config, "cache_ttl", 0),
                    provider=getattr(config, "ai_provider", None),
                    model_high=getattr(config, "ai_model_high", None),
                    model_low=getattr(config, "ai_model_low", None),
                    deployment_context=(
                        additional_data.get("deployment_context")
                        if additional_data
                        else None
                    ),
                )

                # --- Identity verdict per component (always) ---
                # Each component is wrapped in its own try/except so a single
                # oversized prompt or API failure (e.g. Linux kernel with
                # thousands of CVEs hitting the LLM context limit) doesn't
                # abort the entire AI tier and silently drop all results.
                for comp in components_list:
                    comp_key = f"{comp['component_name']}:{comp['component_version']}"
                    try:
                        identity = llm.generate_component_identity_verdict(
                            component_name=comp["component_name"],
                            component_version=comp["component_version"],
                            cve_ids=comp["cve_ids"][:_IDENTITY_PROMPT_CVE_SAMPLE],
                            nvd_fix_snippet=nvd_snippets_map.get(comp_key, ""),
                        )
                    except Exception:
                        logger.warning(
                            "Component identity AI call failed for %s %s; "
                            "skipping component",
                            comp["component_name"],
                            comp["component_version"],
                            exc_info=True,
                        )
                        continue
                    ai_component_results.append(
                        {
                            "component": comp["component_name"],
                            "version": comp["component_version"],
                            "verdict": identity.get("identity", ""),
                            "confidence": identity.get("confidence", ""),
                            "rationale": identity.get("evidence", ""),
                            "guidance": (
                                f"Likely product: {identity.get('likely_product', '')}; "
                                f"NVD product: {identity.get('nvd_product', '')}"
                            ).strip("; "),
                            "fix_version": "",
                            "workaround": "",
                        }
                    )

                    if identity.get("identity") == "mismatched":
                        # --- Per-CVE fan-out ---
                        # Chunk the CVE list and fetch a fresh NVD snippet
                        # scoped to each chunk so we never build a prompt
                        # that exceeds the model's input limit.
                        cve_verdicts: dict[str, dict[str, str]] = {}
                        all_cve_ids = comp["cve_ids"]
                        for i in range(0, len(all_cve_ids), _PER_CVE_FANOUT_CHUNK_SIZE):
                            chunk = all_cve_ids[i : i + _PER_CVE_FANOUT_CHUNK_SIZE]
                            chunk_snippet = ""
                            if _nvd:
                                try:
                                    _nvd.get_batch(chunk, progress=False)
                                    chunk_snippet = _nvd.format_batch_for_prompt(chunk)
                                except Exception:
                                    logger.warning(
                                        "NVD batch fetch failed for fan-out chunk; "
                                        "continuing without snippet",
                                        exc_info=True,
                                    )
                            try:
                                chunk_verdicts = llm.generate_per_cve_applicability(
                                    component_name=comp["component_name"],
                                    component_version=comp["component_version"],
                                    likely_product=identity.get("likely_product", ""),
                                    nvd_product=identity.get("nvd_product", ""),
                                    cve_ids=chunk,
                                    nvd_fix_snippet=chunk_snippet,
                                )
                                cve_verdicts.update(chunk_verdicts)
                            except Exception:
                                logger.warning(
                                    "Per-CVE fan-out failed for %s %s chunk %d-%d; "
                                    "marking chunk as might_still_apply",
                                    comp["component_name"],
                                    comp["component_version"],
                                    i,
                                    i + len(chunk),
                                    exc_info=True,
                                )
                                for cve_id in chunk:
                                    cve_verdicts[cve_id] = {
                                        "verdict": "might_still_apply",
                                        "rationale": "Fan-out call failed.",
                                    }

                        assertion_cve_list: list[dict[str, Any]] = []
                        for cve_id in comp["cve_ids"]:
                            verdict_info = cve_verdicts.get(
                                cve_id,
                                {
                                    "verdict": "might_still_apply",
                                    "rationale": "No classification returned.",
                                },
                            )
                            assertion_cve_list.append(
                                {
                                    "cve_id": cve_id,
                                    "verdict": verdict_info["verdict"],
                                    "rationale": verdict_info["rationale"],
                                }
                            )
                            # Attach signal to finding for does_not_apply
                            if verdict_info["verdict"] == "does_not_apply":
                                # Find the finding_id(s) for this CVE+component
                                for fid, f in finding_lookup.items():
                                    if (
                                        f.get("cve_id") == cve_id
                                        and f.get("component_name")
                                        == comp["component_name"]
                                        and f.get("component_version")
                                        == comp["component_version"]
                                    ):
                                        signal = {
                                            "signal_type": "ai_component_not_affected",
                                            "confidence": identity.get(
                                                "confidence", "medium"
                                            ).upper(),
                                            "reason": (
                                                f"{cve_id}: scanned {comp['component_name']} "
                                                f"is {identity.get('likely_product', 'different product')}, "
                                                f"not {identity.get('nvd_product', 'NVD product')}. "
                                                f"{verdict_info['rationale']}"
                                            ),
                                            "ai_guidance": verdict_info["rationale"],
                                            "ai_action": (
                                                "Mark NOT_AFFECTED with justification "
                                                "CODE_NOT_PRESENT."
                                            ),
                                            "ai_fix_version": "",
                                            "ai_workaround": "",
                                        }
                                        finding_signals.setdefault(fid, []).append(
                                            signal
                                        )
                                        ai_detections += 1

                        identity_assertions.append(
                            {
                                "component_name": comp["component_name"],
                                "component_version": comp["component_version"],
                                "identity": "mismatched",
                                "likely_product": identity.get("likely_product", ""),
                                "nvd_product": identity.get("nvd_product", ""),
                                "evidence": identity.get("evidence", ""),
                                "confidence": identity.get("confidence", ""),
                                "cve_verdicts": assertion_cve_list,
                            }
                        )
                    # Components with confirmed/ambiguous identity are left
                    # alone here. FPA is the focused FP-detection action; any
                    # per-finding triage belongs in Triage Prioritization, not
                    # duplicated inside this report.

        except ImportError:
            logger.warning("AI tier skipped: required modules not available")
        except Exception:
            logger.warning(
                "AI tier failed; mechanical results preserved", exc_info=True
            )

    # ------------------------------------------------------------------
    # 6. Confidence rollup — build candidates and VEX from combined signals
    # ------------------------------------------------------------------
    all_signals: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    vex_recommendations: list[dict[str, Any]] = []

    for fid, signals in finding_signals.items():
        if not signals:
            continue

        finding = finding_lookup.get(fid, {})
        confidence = _rollup_confidence(signals)
        signal_types = ", ".join(s["signal_type"] for s in signals)

        # Record signals with finding reference
        for sig in signals:
            all_signals.append(
                {
                    "finding_id": finding.get("finding_id", ""),
                    "cve_id": finding.get("cve_id", ""),
                    "component_name": finding.get("component_name", ""),
                    **sig,
                }
            )

        # Extract AI-specific fields from signals
        ai_verdict = ""
        ai_rationale = ""
        for sig in signals:
            if sig["signal_type"].startswith("ai_"):
                ai_verdict = "not_affected"
                # Use the detailed guidance/action for ai_rationale, falling
                # back to reason only if no richer detail is available.
                ai_rationale = (
                    sig.get("ai_guidance", "")
                    or sig.get("ai_action", "")
                    or sig.get("reason", "")
                )
                break

        # Primary reason = reason from the highest-confidence signal
        primary_reason = ""
        for sig in sorted(
            signals,
            key=lambda s: {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
                s.get("confidence", "LOW"), 0
            ),
            reverse=True,
        ):
            if sig.get("reason"):
                primary_reason = sig["reason"]
                break

        # Recommended action based on confidence
        if confidence == "HIGH":
            recommended_action = "Mark NOT_AFFECTED"
        elif confidence == "MEDIUM":
            recommended_action = "Review — likely FP"
        else:
            recommended_action = "Review"

        # Build candidate row
        candidate = dict(finding)
        candidate["fp_confidence"] = confidence
        candidate["fp_signals"] = signal_types
        candidate["primary_reason"] = primary_reason
        candidate["ai_verdict"] = ai_verdict
        candidate["ai_rationale"] = ai_rationale
        candidate["recommended_action"] = recommended_action
        candidate_rows.append(candidate)

        # Build VEX recommendation (HIGH confidence only; MEDIUM/LOW are
        # surfaced in the report but produce no VEX artifact)
        vex_rec = _build_vex_recommendation(finding, signals, confidence)  # type: ignore[arg-type]
        if vex_rec is not None:
            vex_recommendations.append(vex_rec)

    # ------------------------------------------------------------------
    # 7. Build output DataFrames
    # ------------------------------------------------------------------
    candidates_df = pd.DataFrame(candidate_rows) if candidate_rows else pd.DataFrame()
    if not candidates_df.empty:
        sort_cols = [
            c
            for c in ["component_name", "component_version", "severity"]
            if c in candidates_df.columns
        ]
        if sort_cols:
            candidates_df = candidates_df.sort_values(sort_cols).reset_index(drop=True)
    signals_df = pd.DataFrame(all_signals) if all_signals else pd.DataFrame()

    # ------------------------------------------------------------------
    # 8. Charts and summary
    # ------------------------------------------------------------------
    charts = _build_charts(candidates_df, signals_df)

    # Build summary breakdown dicts
    by_signal_type: dict[str, int] = {}
    if not signals_df.empty and "signal_type" in signals_df.columns:
        by_signal_type = {
            str(k): v for k, v in signals_df["signal_type"].value_counts().items()
        }
    by_severity: dict[str, int] = {}
    by_component: dict[str, int] = {}
    if not candidates_df.empty:
        if "severity" in candidates_df.columns:
            by_severity = {
                str(k): v for k, v in candidates_df["severity"].value_counts().items()
            }
        if "component_name" in candidates_df.columns:
            by_component = {
                str(k): v
                for k, v in candidates_df["component_name"]
                .value_counts()
                .head(10)
                .items()
            }

    summary: dict[str, Any] = {
        "total_findings": len(df),
        "total_open_findings": len(open_df),
        "total_triaged_findings": len(triaged_df),
        "fp_candidates_found": len(candidates_df),
        "mechanical_detections": mechanical_detections,
        "ai_detections": ai_detections,
        "by_signal_type": by_signal_type,
        "by_severity": by_severity,
        "by_component": by_component,
    }

    return {
        "main": candidates_df,
        "summary": summary,
        "candidates": candidates_df,
        "signals": signals_df,
        "vex_recommendations": vex_recommendations,
        "identity_assertions": identity_assertions,
        "ai_component_prompts": ai_component_prompts,
        "ai_component_results": ai_component_results,
        "ai_triage_prompts": ai_triage_prompts,
        "ai_finding_prompts": {p["finding_id"]: p["prompt"] for p in ai_triage_prompts},
        "fp_charts": charts,
    }
