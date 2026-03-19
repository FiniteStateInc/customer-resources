"""
Pandas transform for the False Positive Analysis report.

Consumes findings from ``/public/v0/findings`` and produces:

- FP candidate list: open findings that trigger one or more signals
- VEX recommendations for each candidate
- Signal-level detail for analyst review
- Charts and summary statistics

Tier 1 — five mechanical checks:
1. Cross-project FP propagation — same CVE+component already triaged FP elsewhere
2. Historical component patterns — high FP ratio for same component+version
3. NVD version-range mismatch — component version outside NVD affected range
4. Rejected/Disputed CVE — NVD vuln_status indicates Rejected or Disputed
5. Unreachable code — negative reachability score

Tier 2 — AI applicability analysis (when ``--ai`` is active):
6. Component-level LLM guidance — AI determines component not affected
7. Finding-level LLM guidance — AI determines individual finding not affected
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
    "historical_component_pattern": "CODE_NOT_PRESENT",
    "nvd_version_mismatch": "CODE_NOT_PRESENT",
    "rejected_cve": "CODE_NOT_PRESENT",
    "disputed_cve": "CODE_NOT_PRESENT",
    "unreachable_code": "CODE_NOT_REACHABLE",
    "ai_component_not_affected": "COMPONENT_NOT_PRESENT",
    "ai_finding_not_affected": "CODE_NOT_PRESENT",
}

# Ordered severity levels for consistent display / sorting
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


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
            "confidence": "HIGH",
            "reason": f"Same CVE+component triaged FP in: {projects}",
        }
    ]


def _check_historical_patterns(
    finding: dict[str, Any],
    triaged_df: pd.DataFrame,
    min_triaged: int = 5,
    fp_ratio_threshold: float = 0.6,
) -> list[dict[str, Any]]:
    """Check 2: High FP ratio for the same component+version in triage history."""
    if triaged_df.empty:
        return []

    comp_name = finding.get("component_name", "")
    comp_ver = finding.get("component_version", "")

    mask = (triaged_df["component_name"] == comp_name) & (
        triaged_df["component_version"] == comp_ver
    )
    component_triaged = triaged_df[mask]

    total = len(component_triaged)
    if total < min_triaged:
        return []

    fp_count = component_triaged["status"].isin(_TRIAGED_FP_STATUSES).sum()
    ratio = fp_count / total

    if ratio < fp_ratio_threshold:
        return []

    return [
        {
            "signal_type": "historical_component_pattern",
            "confidence": "MEDIUM",
            "reason": (
                f"{comp_name}=={comp_ver}: {fp_count}/{total} "
                f"triaged findings are FP ({ratio:.0%})"
            ),
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


def _check_unreachable_code(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Check 5: Negative reachability score indicates unreachable code."""
    score = finding.get("reachability_score", 0)
    if score < 0:
        return [
            {
                "signal_type": "unreachable_code",
                "confidence": "HIGH",
                "reason": f"UNREACHABLE (score={score})",
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
) -> dict[str, Any]:
    """Build a VEX recommendation dict for a candidate finding."""
    first_signal_type = signals[0]["signal_type"] if signals else ""
    justification = _JUSTIFICATION_MAP.get(first_signal_type, "CODE_NOT_PRESENT")

    signal_types = [s["signal_type"] for s in signals]
    reasons = "; ".join(s.get("reason", "") for s in signals)

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

    Runs five mechanical checks against each open finding, rolls up confidence,
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
    # 4. Extract recipe parameters and optional NVD client
    # ------------------------------------------------------------------
    recipe_params: dict[str, Any] = {}
    nvd_client = None
    if additional_data and isinstance(additional_data, dict):
        recipe_params = additional_data.get("recipe_parameters", {}) or {}
        nvd_client = additional_data.get("nvd_client")

    min_triaged = int(recipe_params.get("min_triaged", 5))
    fp_ratio_threshold = float(recipe_params.get("fp_ratio_threshold", 0.6))

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

        # Check 2: Historical component patterns
        signals.extend(
            _check_historical_patterns(
                finding, triaged_df, min_triaged, fp_ratio_threshold
            )
        )

        # Check 3: NVD version-range mismatch
        signals.extend(_check_nvd_version_range(finding, nvd_client))

        # Check 4: Rejected/Disputed CVE
        signals.extend(_check_rejected_cve(finding, nvd_client))

        # Check 5: Unreachable code
        signals.extend(_check_unreachable_code(finding))

        finding_lookup[fid] = finding
        if signals:
            finding_signals[fid] = signals
            mechanical_detections += len(signals)
        else:
            # Ensure entry exists so AI tier can add signals for this finding
            finding_signals[fid] = []

    # ------------------------------------------------------------------
    # 5b. AI tier — component + finding level applicability analysis
    # ------------------------------------------------------------------
    ai_detections = 0
    ai_component_prompts: list[dict[str, str]] = []
    ai_triage_prompts: list[dict[str, str]] = []

    ai_enabled = config is not None and (
        getattr(config, "ai", False) or getattr(config, "ai_prompts", False)
    )
    if ai_enabled and not open_df.empty:
        try:
            from fs_report.transforms.pandas.triage_prioritization import (
                _build_component_prompt,
                _build_triage_prompt,
                _load_gates,
                _normalize_columns,
                apply_tiered_gates,
            )

            # _normalize_columns expects raw API columns; open_df already has
            # canonical names from _normalize_finding, which is the same schema
            # _normalize_columns produces, so it's safe to pass directly.
            scored_df = _normalize_columns(open_df.copy())

            gates = _load_gates(config, additional_data)
            scored_df = apply_tiered_gates(scored_df, gates)

            # Build component groups for batch guidance
            comp_groups = scored_df.groupby(
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

            # --ai-prompts only: generate prompts for export but don't call LLM
            ai_prompts_only = getattr(config, "ai_prompts", False) and not getattr(
                config, "ai", False
            )

            # Generate component-level prompts (one per unique component+version)
            ai_component_prompts = []
            if components_list:
                for comp in components_list:
                    comp_key = f"{comp['component_name']} {comp['component_version']}"
                    prompt_text = _build_component_prompt(
                        component_name=comp["component_name"],
                        component_version=comp["component_version"],
                        cve_ids=comp["cve_ids"],
                    )
                    ai_component_prompts.append(
                        {
                            "component": comp_key,
                            "prompt": prompt_text,
                        }
                    )

            # Generate per-finding prompts
            if components_list:
                for _, row in scored_df.iterrows():
                    fid = str(row.get("finding_id", ""))
                    if fid:
                        prompt_text = _build_triage_prompt(row)
                        component = f"{row.get('component_name', '')} {row.get('component_version', '')}".strip()
                        ai_triage_prompts.append(
                            {
                                "finding_id": fid,
                                "component": component,
                                "prompt": prompt_text,
                            }
                        )

            # Write prompts file for --ai-prompts (and --ai as a side effect)
            if ai_component_prompts or ai_triage_prompts:
                _output_dir = getattr(config, "output_dir", None)
                if _output_dir:
                    from datetime import datetime
                    from pathlib import Path

                    _recipe_dir = Path(_output_dir) / "False Positive Analysis"
                    _recipe_dir.mkdir(parents=True, exist_ok=True)
                    _prompts_path = _recipe_dir / "False Positive Analysis_prompts.md"
                    _lines = [
                        "# False Positive Analysis — AI Prompts\n",
                        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n",
                        f"\n{len(ai_component_prompts)} component prompts, "
                        f"{len(ai_triage_prompts)} finding prompts.\n",
                        "\nStart with component prompts — if the LLM says `not_affected`, "
                        "all findings on that component are likely FP and you can skip "
                        "the individual finding prompts for it.\n",
                    ]
                    if ai_component_prompts:
                        _lines.append("\n---\n\n# Component Applicability Prompts\n")
                        for p in ai_component_prompts:
                            _lines.append(f"\n## {p['component']}\n\n")
                            _lines.append(f"```\n{p['prompt']}\n```\n")
                    if ai_triage_prompts:
                        _lines.append("\n---\n\n# Per-Finding Prompts\n")
                        for p in ai_triage_prompts:
                            _lines.append(
                                f"\n## {p['finding_id']} ({p['component']})\n\n"
                            )
                            _lines.append(f"```\n{p['prompt']}\n```\n")
                    _prompts_path.write_text("".join(_lines), encoding="utf-8")
                    logger.info(
                        f"Wrote {len(ai_component_prompts)} component + "
                        f"{len(ai_triage_prompts)} finding prompts to {_prompts_path}"
                    )

            if not ai_prompts_only and components_list:
                from fs_report.llm_client import LLMClient

                llm = LLMClient(
                    cache_dir=getattr(config, "cache_dir", None),
                    cache_ttl=getattr(config, "cache_ttl", 0),
                    provider=getattr(config, "llm_provider", None),
                    model_high=getattr(config, "model_high", None),
                    model_low=getattr(config, "model_low", None),
                    deployment_context=(
                        additional_data.get("deployment_context")
                        if additional_data
                        else None
                    ),
                )

                # --- Component-level analysis ---
                ai_components = llm.generate_batch_component_guidance(components_list)
                not_affected_components: set[str] = set()
                for comp_key, guidance in ai_components.items():
                    if guidance.get("verdict") == "not_affected":
                        not_affected_components.add(comp_key)

                # Apply component-level verdicts to individual findings
                for _, row in scored_df.iterrows():
                    comp_key = f"{row['component_name']}:{row['component_version']}"
                    fid = str(row.get("finding_id", ""))
                    if comp_key in not_affected_components and fid in finding_signals:
                        guidance = ai_components[comp_key]
                        signal = {
                            "signal_type": "ai_component_not_affected",
                            "confidence": guidance.get("confidence", "medium").upper(),
                            "reason": guidance.get(
                                "rationale", "AI: component not affected"
                            ),
                        }
                        finding_signals[fid].append(signal)
                        ai_detections += 1

                # --- Finding-level analysis ---
                remaining = scored_df[
                    ~scored_df.apply(
                        lambda r: (
                            f"{r['component_name']}:{r['component_version']}"
                            in not_affected_components
                        ),
                        axis=1,
                    )
                ]
                if "triage_score" in remaining.columns:
                    remaining = remaining.nlargest(200, "triage_score", keep="all")
                else:
                    remaining = remaining.head(200)

                finding_prompts: list[tuple[str, str]] = []
                for _, row in remaining.iterrows():
                    fid = str(row.get("finding_id", ""))
                    if fid:
                        prompt = _build_triage_prompt(row)
                        finding_prompts.append((fid, prompt))

                if finding_prompts:
                    ai_findings = llm.generate_batch_finding_guidance(finding_prompts)
                    for fid, guidance in ai_findings.items():
                        if (
                            guidance.get("applicability") == "not_affected"
                            or guidance.get("verdict") == "not_affected"
                        ):
                            signal = {
                                "signal_type": "ai_finding_not_affected",
                                "confidence": guidance.get(
                                    "confidence", "medium"
                                ).upper(),
                                "reason": guidance.get(
                                    "rationale", "AI: finding not affected"
                                ),
                            }
                            if fid in finding_signals:
                                finding_signals[fid].append(signal)
                                ai_detections += 1

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
                ai_rationale = sig.get("reason", "")
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

        # Build VEX recommendation
        vex_rec = _build_vex_recommendation(finding, signals, confidence)  # type: ignore[arg-type]
        vex_recommendations.append(vex_rec)

    # ------------------------------------------------------------------
    # 7. Build output DataFrames
    # ------------------------------------------------------------------
    candidates_df = pd.DataFrame(candidate_rows) if candidate_rows else pd.DataFrame()
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
        "ai_component_prompts": ai_component_prompts,
        "ai_triage_prompts": ai_triage_prompts,
        "fp_charts": charts,
    }
