"""
Pandas transform for Triage Prioritization report.

Implements a tiered-gates scoring model that prioritizes findings based on
real-world exploitability and reachability rather than CVSS alone.

Gate 1 (CRITICAL): Reachable + (Exploit OR KEV) — imminent threat
Gate 2 (HIGH): Single strong signal + amplifying factor
Additive scoring: Points-based scoring for remaining findings
"""

import logging
from typing import Any

import numpy as np
import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

BAND_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
BAND_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
    "INFO": "#6c757d",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

# Additive scoring weights
POINTS_REACHABLE = 30       # reachabilityScore > 0
POINTS_UNKNOWN = 0          # reachabilityScore == 0
POINTS_UNREACHABLE = -15    # reachabilityScore < 0

POINTS_EXPLOIT = 25         # Has known exploit
POINTS_KEV_ONLY = 20        # In KEV but no exploit info

POINTS_VECTOR_NETWORK = 15
POINTS_VECTOR_ADJACENT = 10
POINTS_VECTOR_LOCAL = 5
POINTS_VECTOR_PHYSICAL = 0

EPSS_MAX_POINTS = 20        # 20 × percentile
CVSS_MAX_POINTS = 10        # 10 × (score/10)

# Band thresholds for additive scoring
BAND_HIGH_THRESHOLD = 70
BAND_MEDIUM_THRESHOLD = 40
BAND_LOW_THRESHOLD = 25


# =============================================================================
# Main Entry Point
# =============================================================================

def triage_prioritization_transform(
    data: list[dict[str, Any]],
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Main transform entry point for Triage Prioritization report.

    Args:
        data: Raw findings data from the API
        config: Config object (optional)
        additional_data: Extra data dict (optional)

    Returns:
        Dictionary with multiple DataFrames for template rendering
    """
    logger.info(f"Triage prioritization transform: processing {len(data)} findings")

    if not data:
        logger.warning("No findings data provided")
        return _empty_result()

    # Build the main DataFrame
    df = pd.DataFrame(data)
    logger.debug(f"Initial DataFrame shape: {df.shape}, columns: {list(df.columns)}")

    # Normalize columns — handle both nested and flat structures
    df = _normalize_columns(df)
    logger.debug(f"After normalization: {df.shape}, columns: {list(df.columns)}")

    # Apply tiered gates scoring
    df = apply_tiered_gates(df)

    # Apply additive scoring for findings that didn't hit any gate
    df = calculate_additive_score(df)

    # Assign risk bands
    df = assign_risk_bands(df)

    # Sort by band priority then score (descending)
    band_priority = {b: i for i, b in enumerate(BAND_ORDER)}
    df["_band_priority"] = df["priority_band"].map(band_priority).fillna(99)
    df = df.sort_values(
        ["_band_priority", "triage_score"],
        ascending=[True, False],
    ).drop(columns=["_band_priority"])

    # Build the various aggregation views
    project_summary_df = build_project_summaries(df)
    portfolio_summary = build_portfolio_summary(df)
    cvss_band_matrix = build_cvss_vs_band_matrix(df)
    gate_funnel = build_gate_funnel_data(df)
    top_components = build_top_components(df)
    factor_radar = build_factor_radar_data(df)

    # Build VEX triage recommendations
    vex_recommendations = build_vex_recommendations(df)

    logger.info(
        f"Triage complete: {len(df)} findings scored — "
        f"CRITICAL={portfolio_summary.get('CRITICAL', 0)}, "
        f"HIGH={portfolio_summary.get('HIGH', 0)}, "
        f"MEDIUM={portfolio_summary.get('MEDIUM', 0)}, "
        f"LOW={portfolio_summary.get('LOW', 0)}, "
        f"INFO={portfolio_summary.get('INFO', 0)}"
    )

    # AI remediation guidance (optional, --ai flag)
    ai_portfolio_summary = ""
    ai_project_summaries: dict[str, str] = {}
    ai_component_guidance: dict[str, dict[str, Any]] = {}

    ai_config = _get_ai_config(config, additional_data)
    if ai_config.get("enabled"):
        ai_portfolio_summary, ai_project_summaries, ai_component_guidance = (
            _generate_ai_guidance(
                df=df,
                portfolio_summary=portfolio_summary,
                project_summary_df=project_summary_df,
                top_components=top_components,
                ai_depth=ai_config.get("depth", "summary"),
                cache_dir=ai_config.get("cache_dir"),
                cache_ttl=ai_config.get("cache_ttl", 0),
            )
        )

    # Defensive recompute of reachability_label from reachability_score
    # (ensures label is consistent with score after all transformations)
    df["reachability_label"] = df["reachability_score"].apply(
        lambda x: "REACHABLE" if x > 0 else ("UNREACHABLE" if x < 0 else "UNKNOWN")
    )

    # Debug: log label vs score consistency for top findings
    top_10 = df.nlargest(10, "triage_score")
    for _, row in top_10.iterrows():
        logger.debug(
            f"  {row.get('finding_id', '?'):30s}  score={row.get('reachability_score', '?')!r:>8s}"
            f"  label={row.get('reachability_label', '?')!r:>14s}"
            f"  type(score)={type(row.get('reachability_score', None)).__name__}"
        )

    # Select columns for the main output table
    output_columns = [
        "finding_id", "internal_id", "severity",
        "component_name", "component_version", "component_id",
        "project_name", "project_id", "project_version_id", "version_name",
        "priority_band", "triage_score", "gate_assignment",
        "reachability_label", "reachability_score", "vuln_functions",
        "has_exploit", "in_kev",
        "attack_vector", "epss_percentile", "risk",
    ]
    # Only keep columns that exist
    output_columns = [c for c in output_columns if c in df.columns]
    findings_df = df[output_columns].copy()

    # Determine if this is a single-project report
    unique_projects = df["project_name"].unique()
    is_single_project = len(unique_projects) <= 1
    single_project_name = str(unique_projects[0]) if is_single_project and len(unique_projects) == 1 else None

    return {
        "findings_df": findings_df,
        "project_summary_df": project_summary_df,
        "portfolio_summary": portfolio_summary,
        "cvss_band_matrix": cvss_band_matrix,
        "gate_funnel": gate_funnel,
        "top_components": top_components,
        "factor_radar": factor_radar,
        "vex_recommendations": vex_recommendations,
        "band_colors": BAND_COLORS,
        "is_single_project": is_single_project,
        "single_project_name": single_project_name,
        "ai_portfolio_summary": ai_portfolio_summary,
        "ai_project_summaries": ai_project_summaries,
        "ai_component_guidance": ai_component_guidance,
    }


# =============================================================================
# Column Normalization
# =============================================================================

def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize columns from various API formats into a consistent schema."""
    df = df.copy()

    # --- Component fields ---
    # Note: component.vcId is the "version component" ID used in BOM URLs
    # (componentId= param). component.id is a different internal PK.
    # For pre-flattened data, fall back to component.id if vcId isn't present.
    if "component.name" in df.columns:
        df["component_name"] = df["component.name"]
        df["component_version"] = df.get("component.version", "Unknown")
        if "component.vcId" in df.columns:
            df["component_id"] = df["component.vcId"].astype(str)
        elif "component.id" in df.columns:
            df["component_id"] = df["component.id"].astype(str)
        else:
            df["component_id"] = ""
    elif "component" in df.columns:
        df["component_name"] = df["component"].apply(
            lambda x: x.get("name", "Unknown") if isinstance(x, dict) else "Unknown"
        )
        df["component_version"] = df["component"].apply(
            lambda x: x.get("version", "Unknown") if isinstance(x, dict) else "Unknown"
        )
        df["component_id"] = df["component"].apply(
            lambda x: str(x.get("vcId", "")) if isinstance(x, dict) else ""
        )
    else:
        if "component_name" not in df.columns:
            df["component_name"] = "Unknown"
        if "component_version" not in df.columns:
            df["component_version"] = "Unknown"
        if "component_id" not in df.columns:
            df["component_id"] = ""

    # --- Project fields ---
    if "project.name" in df.columns:
        df["project_name"] = df["project.name"]
    elif "project" in df.columns:
        df["project_name"] = df["project"].apply(
            lambda x: x.get("name", "Unknown") if isinstance(x, dict) else "Unknown"
        )
    else:
        if "project_name" not in df.columns:
            df["project_name"] = "Unknown"

    # --- Project ID (for platform deep links) ---
    if "project.id" in df.columns:
        df["project_id"] = df["project.id"].astype(str)
    elif "project" in df.columns:
        df["project_id"] = df["project"].apply(
            lambda x: str(x.get("id", "")) if isinstance(x, dict) else str(x) if x else ""
        )
    elif "projectId" in df.columns:
        df["project_id"] = df["projectId"].astype(str)
    else:
        if "project_id" not in df.columns:
            df["project_id"] = ""

    if "projectVersion.id" in df.columns:
        df["project_version_id"] = df["projectVersion.id"]
    elif "projectVersion" in df.columns:
        df["project_version_id"] = df["projectVersion"].apply(
            lambda x: x.get("id", "") if isinstance(x, dict) else ""
        )
    else:
        if "project_version_id" not in df.columns:
            df["project_version_id"] = ""

    # --- Project version name (for display in findings detail) ---
    if "projectVersion.version" in df.columns:
        df["version_name"] = df["projectVersion.version"]
    elif "projectVersion" in df.columns:
        df["version_name"] = df["projectVersion"].apply(
            lambda x: x.get("version", "") if isinstance(x, dict) else ""
        )
    else:
        if "version_name" not in df.columns:
            df["version_name"] = ""

    # --- Finding ID ---
    if "findingId" in df.columns:
        df["finding_id"] = df["findingId"]
    elif "finding_id" not in df.columns:
        df["finding_id"] = df.get("id", "")

    # --- Internal finding ID (numeric PK for platform deep links) ---
    if "id" in df.columns:
        df["internal_id"] = df["id"].astype(str)
    else:
        if "internal_id" not in df.columns:
            df["internal_id"] = ""

    # --- Exploit info ---
    # Use hasKnownExploit boolean if available (direct from API), fall back to exploitInfo array
    if "hasKnownExploit" in df.columns or "has_known_exploit" in df.columns:
        col = "hasKnownExploit" if "hasKnownExploit" in df.columns else "has_known_exploit"
        df["has_exploit"] = df[col].fillna(False).astype(bool)
    elif "exploitInfo" in df.columns:
        df["has_exploit"] = df["exploitInfo"].apply(
            lambda x: isinstance(x, list) and len(x) > 0
        )
    elif "exploit_info" in df.columns:
        df["has_exploit"] = df["exploit_info"].apply(
            lambda x: (isinstance(x, list) and len(x) > 0)
            if not isinstance(x, str) else (x not in ("", "[]", "null"))
        )
    else:
        df["has_exploit"] = False

    # --- KEV ---
    if "inKev" in df.columns:
        df["in_kev"] = df["inKev"].fillna(False).astype(bool)
    elif "in_kev" in df.columns:
        df["in_kev"] = df["in_kev"].fillna(False).astype(bool)
    else:
        df["in_kev"] = False

    # --- Reachability ---
    if "reachabilityScore" in df.columns:
        df["reachability_score"] = pd.to_numeric(df["reachabilityScore"], errors="coerce").fillna(0)
    elif "reachability_score" in df.columns:
        df["reachability_score"] = pd.to_numeric(df["reachability_score"], errors="coerce").fillna(0)
    else:
        df["reachability_score"] = 0.0

    # Three-tier reachability label:
    #   positive score → REACHABLE (vulnerable function found in binary)
    #   negative score → UNREACHABLE
    #   zero / null    → UNKNOWN (inconclusive or not analyzed)
    df["reachability_label"] = df["reachability_score"].apply(
        lambda x: "REACHABLE" if x > 0 else ("UNREACHABLE" if x < 0 else "UNKNOWN")
    )

    # Reachability factors (array of evidence explaining the score)
    if "factors" in df.columns:
        # Preserve factors as-is (list of dicts from API, or JSON string from cache)
        def _parse_factors(x: Any) -> list:
            if isinstance(x, list):
                return x
            if isinstance(x, str) and x not in ("", "null", "[]"):
                import json as _json
                try:
                    return _json.loads(x)
                except (ValueError, TypeError):
                    return []
            return []
        df["reachability_factors"] = df["factors"].apply(_parse_factors)
    else:
        df["reachability_factors"] = [[] for _ in range(len(df))]

    # Extract primary vulnerable function from factors (for display)
    def _extract_vuln_functions(factors: list) -> str:
        funcs = []
        for f in factors:
            if isinstance(f, dict) and f.get("entity_type") == "vuln_func":
                name = f.get("entity_name", "")
                if name and name not in funcs:
                    funcs.append(name)
        return ", ".join(funcs) if funcs else ""

    df["vuln_functions"] = df["reachability_factors"].apply(_extract_vuln_functions)

    # Diagnostic logging for reachability
    reach_counts = df["reachability_label"].value_counts().to_dict()
    logger.info(
        f"Reachability distribution: "
        f"REACHABLE={reach_counts.get('REACHABLE', 0)}, "
        f"UNREACHABLE={reach_counts.get('UNREACHABLE', 0)}, "
        f"UNKNOWN={reach_counts.get('UNKNOWN', 0)}"
    )
    if reach_counts.get("REACHABLE", 0) == 0 and reach_counts.get("UNREACHABLE", 0) == 0:
        # All unknown — check if reachabilityScore column was present at all
        score_col = "reachabilityScore" if "reachabilityScore" in df.columns else "reachability_score"
        if score_col in df.columns:
            non_null = df[score_col].notna().sum()
            non_zero = (df[score_col] != 0).sum() if non_null > 0 else 0
            logger.warning(
                f"All reachability labels are UNKNOWN. "
                f"Column '{score_col}' has {non_null} non-null values, {non_zero} non-zero values. "
                f"Sample values: {df[score_col].head(5).tolist()}"
            )
        else:
            logger.warning(
                "No reachabilityScore column found in data. "
                f"Available columns: {sorted(df.columns.tolist())}"
            )

    # --- EPSS ---
    if "epssPercentile" in df.columns:
        df["epss_percentile"] = pd.to_numeric(df["epssPercentile"], errors="coerce").fillna(0)
    elif "epss_percentile" not in df.columns:
        df["epss_percentile"] = 0.0
    else:
        df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce").fillna(0)

    if "epssScore" in df.columns:
        df["epss_score"] = pd.to_numeric(df["epssScore"], errors="coerce").fillna(0)
    elif "epss_score" not in df.columns:
        df["epss_score"] = 0.0

    # --- Attack vector ---
    if "attackVector" in df.columns:
        df["attack_vector"] = df["attackVector"].fillna("UNKNOWN").astype(str).str.upper()
    elif "attack_vector" in df.columns:
        df["attack_vector"] = df["attack_vector"].fillna("UNKNOWN").astype(str).str.upper()
    else:
        df["attack_vector"] = "UNKNOWN"

    # --- Severity ---
    if "severity" in df.columns:
        df["severity"] = df["severity"].fillna("NONE").astype(str).str.upper()
    else:
        df["severity"] = "NONE"

    # --- Risk (CVSS-like score from API) ---
    if "risk" in df.columns:
        df["risk"] = pd.to_numeric(df["risk"], errors="coerce").fillna(0)
    else:
        df["risk"] = 0.0

    return df


# =============================================================================
# Tiered Gates
# =============================================================================

def apply_tiered_gates(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply Gate 1 and Gate 2 classification.

    Gate 1 (CRITICAL): Reachable (score > 0) AND (has exploit OR in KEV)
    Gate 2 (HIGH): (Reachable OR has exploit/KEV) AND (NETWORK vector OR EPSS >= 0.9 OR CVSS >= 9.0)
    """
    df = df.copy()
    df["gate_assignment"] = "NONE"

    # Gate 1: Reachable + Exploit/KEV → CRITICAL
    gate1_mask = (
        (df["reachability_score"] > 0) &
        (df["has_exploit"] | df["in_kev"])
    )
    df.loc[gate1_mask, "gate_assignment"] = "GATE_1"
    logger.debug(f"Gate 1 (CRITICAL): {gate1_mask.sum()} findings")

    # Gate 2: NOT unreachable AND (Reachable OR exploit/KEV) AND amplifier
    # Unreachable findings (score < 0) are excluded — they should never be HIGH.
    # Inconclusive (score == 0) CAN qualify if they have exploit/KEV + amplifier.
    not_unreachable = df["reachability_score"] >= 0  # reachable or inconclusive
    has_strong_signal = (
        (df["reachability_score"] > 0) |
        df["has_exploit"] |
        df["in_kev"]
    )
    has_amplifier = (
        (df["attack_vector"] == "NETWORK") |
        (df["epss_percentile"] >= 0.9) |
        (df["risk"] >= 9.0)
    )
    gate2_mask = (
        not_unreachable & has_strong_signal & has_amplifier
        & (df["gate_assignment"] == "NONE")
    )
    df.loc[gate2_mask, "gate_assignment"] = "GATE_2"
    logger.debug(f"Gate 2 (HIGH): {gate2_mask.sum()} findings")

    return df


# =============================================================================
# Additive Scoring
# =============================================================================

def calculate_additive_score(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate additive triage score for findings that didn't hit a gate.
    Gate-assigned findings get a fixed high score to ensure proper ordering.
    """
    df = df.copy()
    df["triage_score"] = 0.0

    # Reachability points
    df["_pts_reachability"] = df["reachability_score"].apply(
        lambda x: POINTS_REACHABLE if x > 0 else (POINTS_UNREACHABLE if x < 0 else POINTS_UNKNOWN)
    )

    # Exploit/KEV points
    df["_pts_exploit"] = 0
    df.loc[df["has_exploit"], "_pts_exploit"] = POINTS_EXPLOIT
    df.loc[(~df["has_exploit"]) & df["in_kev"], "_pts_exploit"] = POINTS_KEV_ONLY

    # Attack vector points
    vector_points = {
        "NETWORK": POINTS_VECTOR_NETWORK,
        "ADJACENT": POINTS_VECTOR_ADJACENT,
        "LOCAL": POINTS_VECTOR_LOCAL,
        "PHYSICAL": POINTS_VECTOR_PHYSICAL,
    }
    df["_pts_vector"] = df["attack_vector"].map(vector_points).fillna(0)

    # EPSS points (0–20 scaled by percentile)
    df["_pts_epss"] = (df["epss_percentile"] * EPSS_MAX_POINTS).clip(0, EPSS_MAX_POINTS)

    # CVSS points (0–10 scaled by risk/10)
    df["_pts_cvss"] = (df["risk"] / 10.0 * CVSS_MAX_POINTS).clip(0, CVSS_MAX_POINTS)

    # Sum additive score
    df["triage_score"] = (
        df["_pts_reachability"]
        + df["_pts_exploit"]
        + df["_pts_vector"]
        + df["_pts_epss"]
        + df["_pts_cvss"]
    ).round(1)

    # Override gated findings with high fixed scores for proper ordering
    df.loc[df["gate_assignment"] == "GATE_1", "triage_score"] = 100.0
    df.loc[df["gate_assignment"] == "GATE_2", "triage_score"] = 85.0

    # Clean up temporary columns
    temp_cols = [c for c in df.columns if c.startswith("_pts_")]
    df = df.drop(columns=temp_cols)

    return df


# =============================================================================
# Risk Band Assignment
# =============================================================================

def assign_risk_bands(df: pd.DataFrame) -> pd.DataFrame:
    """Map gate assignments and additive scores to priority bands."""
    df = df.copy()

    def _band(row: pd.Series) -> str:
        if row["gate_assignment"] == "GATE_1":
            return "CRITICAL"
        if row["gate_assignment"] == "GATE_2":
            return "HIGH"
        score = row["triage_score"]
        if score >= BAND_HIGH_THRESHOLD:
            return "HIGH"
        if score >= BAND_MEDIUM_THRESHOLD:
            return "MEDIUM"
        if score >= BAND_LOW_THRESHOLD:
            return "LOW"
        return "INFO"

    df["priority_band"] = df.apply(_band, axis=1)
    return df


# =============================================================================
# Aggregation Views
# =============================================================================

def build_project_summaries(df: pd.DataFrame) -> pd.DataFrame:
    """Build per-project band counts and total scores."""
    if df.empty:
        return pd.DataFrame(columns=["project_name", "folder_name"] + BAND_ORDER + ["total_findings", "avg_score"])

    # Cross-tabulate project × band
    ct = pd.crosstab(df["project_name"], df["priority_band"]).reindex(columns=BAND_ORDER, fill_value=0)
    ct["total_findings"] = ct.sum(axis=1)

    # Average triage score per project
    avg_scores = df.groupby("project_name")["triage_score"].mean().round(1)
    ct["avg_score"] = avg_scores

    ct = ct.reset_index()

    # Add project_id and project_version_id for platform deep links
    if "project_id" in df.columns:
        pid_map = df.groupby("project_name")["project_id"].first()
        ct["project_id"] = ct["project_name"].map(pid_map).fillna("")
    else:
        ct["project_id"] = ""

    if "project_version_id" in df.columns:
        pvid_map = df.groupby("project_name")["project_version_id"].first()
        ct["project_version_id"] = ct["project_name"].map(pvid_map).fillna("")
    else:
        ct["project_version_id"] = ""

    # Add folder_name if available
    if "folder_name" in df.columns:
        folder_map = df.groupby("project_name")["folder_name"].first()
        ct["folder_name"] = ct["project_name"].map(folder_map).fillna("")
    else:
        ct["folder_name"] = ""

    # Sort by CRITICAL desc, then HIGH desc, then total
    ct = ct.sort_values(
        ["CRITICAL", "HIGH", "total_findings"],
        ascending=[False, False, False],
    )

    return ct


def build_portfolio_summary(df: pd.DataFrame) -> dict[str, Any]:
    """Build portfolio-level totals."""
    band_counts = df["priority_band"].value_counts()
    summary = {band: int(band_counts.get(band, 0)) for band in BAND_ORDER}
    summary["total"] = len(df)
    summary["avg_score"] = round(float(df["triage_score"].mean()), 1) if not df.empty else 0
    return summary


def build_cvss_vs_band_matrix(df: pd.DataFrame) -> dict[str, Any]:
    """
    Build CVSS severity × priority band cross-tabulation for bubble chart.

    Layout:
      X-axis = CVSS severity (CRITICAL → NONE, left to right)
      Y-axis = Priority band (CRITICAL at top → INFO at bottom)
    """
    if df.empty:
        return {"rows": BAND_ORDER, "cols": SEVERITY_ORDER, "data": []}

    ct = pd.crosstab(df["severity"], df["priority_band"])
    ct = ct.reindex(index=SEVERITY_ORDER, columns=BAND_ORDER, fill_value=0)

    # Invert band index so CRITICAL=top (highest y value)
    num_bands = len(BAND_ORDER)

    matrix_data = []
    for sev_idx, sev in enumerate(SEVERITY_ORDER):
        for band_idx, band in enumerate(BAND_ORDER):
            value = int(ct.loc[sev, band]) if sev in ct.index and band in ct.columns else 0
            if value > 0:
                matrix_data.append({
                    "x": sev_idx,                          # CVSS on x-axis
                    "y": (num_bands - 1) - band_idx,       # Invert: CRITICAL=top
                    "v": value,
                    "severity": sev,
                    "band": band,
                })

    return {
        "rows": list(reversed(BAND_ORDER)),   # y-axis labels top-to-bottom: CRITICAL, HIGH, ...
        "cols": SEVERITY_ORDER,                # x-axis labels: CRITICAL, HIGH, MEDIUM, LOW, NONE
        "data": matrix_data,
    }


def build_gate_funnel_data(df: pd.DataFrame) -> dict[str, Any]:
    """Build gate classification funnel data."""
    gate_counts = df["gate_assignment"].value_counts()
    additive = df[df["gate_assignment"] == "NONE"]
    additive_bands = additive["priority_band"].value_counts()

    return {
        "gate_1_critical": int(gate_counts.get("GATE_1", 0)),
        "gate_2_high": int(gate_counts.get("GATE_2", 0)),
        "additive_high": int(additive_bands.get("HIGH", 0)),
        "additive_medium": int(additive_bands.get("MEDIUM", 0)),
        "additive_low": int(additive_bands.get("LOW", 0)),
        "additive_info": int(additive_bands.get("INFO", 0)),
        "total": len(df),
    }


def build_top_components(df: pd.DataFrame, top_n: int = 15) -> pd.DataFrame:
    """Build top N riskiest components with band breakdown."""
    if df.empty:
        return pd.DataFrame()

    # Aggregate by component
    component_agg = df.groupby(["component_name", "component_version"]).agg(
        total_findings=("finding_id", "count"),
        avg_score=("triage_score", "mean"),
        max_score=("triage_score", "max"),
    ).reset_index()

    # Add representative IDs for platform deep links
    for col_name in ("project_id", "project_version_id", "component_id"):
        if col_name in df.columns:
            id_map = df.groupby(["component_name", "component_version"])[col_name].first().reset_index()
            id_map.columns = ["component_name", "component_version", col_name]
            component_agg = component_agg.merge(id_map, on=["component_name", "component_version"], how="left")
        else:
            component_agg[col_name] = ""

    # Get band counts per component
    band_ct = pd.crosstab(
        [df["component_name"], df["component_version"]],
        df["priority_band"],
    ).reindex(columns=BAND_ORDER, fill_value=0).reset_index()

    # Merge
    result = component_agg.merge(band_ct, on=["component_name", "component_version"], how="left")

    # Sort by severity: CRITICAL count desc, then HIGH, then avg_score
    for band in BAND_ORDER:
        if band not in result.columns:
            result[band] = 0

    result = result.sort_values(
        ["CRITICAL", "HIGH", "avg_score"],
        ascending=[False, False, False],
    ).head(top_n)

    result["avg_score"] = result["avg_score"].round(1)

    return result


def build_factor_radar_data(df: pd.DataFrame, top_n: int = 5) -> dict[str, Any]:
    """
    Build per-project factor profile data for radar chart.
    Axes: Reachability, Exploits, Attack Vector, EPSS, CVSS
    Each axis is 0–100 normalized.
    """
    if df.empty:
        return {"labels": [], "datasets": []}

    # Get top N projects by average triage score
    project_scores = df.groupby("project_name")["triage_score"].mean()
    top_projects = project_scores.nlargest(top_n).index.tolist()

    datasets = []
    for project in top_projects:
        proj_df = df[df["project_name"] == project]

        # Calculate normalized factor scores, clamped to 0–100
        reachability = (proj_df["reachability_score"] > 0).mean() * 100
        exploits = proj_df["has_exploit"].mean() * 100
        vector = (proj_df["attack_vector"] == "NETWORK").mean() * 100

        # EPSS percentile: API returns 0–1 fraction
        raw_epss = proj_df["epss_percentile"].mean()
        epss = min(raw_epss * 100, 100) if raw_epss <= 1.0 else min(raw_epss, 100)

        # CVSS/risk: API returns 0–10 scale
        raw_cvss = proj_df["risk"].mean()
        cvss = min((raw_cvss / 10.0) * 100, 100) if raw_cvss <= 10.0 else min(raw_cvss, 100)

        datasets.append({
            "label": project,
            "data": [
                round(max(0, min(reachability, 100)), 1),
                round(max(0, min(exploits, 100)), 1),
                round(max(0, min(vector, 100)), 1),
                round(max(0, min(epss, 100)), 1),
                round(max(0, min(cvss, 100)), 1),
            ],
        })

    return {
        "labels": ["Reachability", "Exploits", "Attack Vector", "EPSS", "CVSS"],
        "datasets": datasets,
    }


# =============================================================================
# VEX Recommendations
# =============================================================================

def build_vex_recommendations(df: pd.DataFrame) -> list[dict[str, Any]]:
    """
    Build VEX triage status recommendations based on priority bands.

    Maps priority bands to VEX statuses:
      CRITICAL/HIGH → EXPLOITABLE (requires immediate action)
      MEDIUM → IN_TRIAGE (needs investigation)
      LOW/INFO with reachability < 0 → NOT_AFFECTED (unreachable)
      LOW/INFO otherwise → IN_TRIAGE (needs investigation)

    Includes reachability evidence (score, label, vulnerable functions,
    factor summaries) in the reason field when available.
    """
    if df.empty:
        return []

    recommendations = []
    for _, row in df.iterrows():
        band = row.get("priority_band", "INFO")
        reach_score = row.get("reachability_score", 0)
        reach_label = (
            "REACHABLE" if reach_score > 0
            else ("UNREACHABLE" if reach_score < 0 else "UNKNOWN")
        )
        vuln_funcs = row.get("vuln_functions", "")
        factors = row.get("reachability_factors", [])

        # Build reachability detail string
        reach_detail = f"Reachability={reach_label} (score={reach_score})"
        if vuln_funcs:
            reach_detail += f", vulnerable functions: {vuln_funcs}"
        if isinstance(factors, list) and factors:
            summaries = [
                f.get("summary", "")
                for f in factors
                if isinstance(f, dict) and f.get("summary")
            ]
            if summaries:
                reach_detail += ". Evidence: " + "; ".join(summaries[:3])

        if band in ("CRITICAL", "HIGH"):
            vex_status = "EXPLOITABLE"
            reason = (
                f"Triage band={band} (score={row.get('triage_score', 0)}, "
                f"gate={row.get('gate_assignment', 'NONE')}). "
                f"{reach_detail}. "
                f"Exploit={row.get('has_exploit', False)}, "
                f"KEV={row.get('in_kev', False)}."
            )
        elif band == "MEDIUM":
            vex_status = "IN_TRIAGE"
            reason = (
                f"Triage band=MEDIUM (score={row.get('triage_score', 0)}). "
                f"{reach_detail}. "
                f"Requires further investigation."
            )
        elif reach_label == "UNREACHABLE":
            vex_status = "NOT_AFFECTED"
            reason = (
                f"Triage band={band}. {reach_detail}. "
                f"Binary analysis confirms code path is not reachable in deployed firmware."
            )
        else:
            vex_status = "IN_TRIAGE"
            reason = (
                f"Triage band={band} (score={row.get('triage_score', 0)}). "
                f"{reach_detail}. "
                f"Low priority, reachability inconclusive."
            )

        recommendations.append({
            "id": row.get("id", ""),  # Internal numeric PK (used for API calls)
            "finding_id": row.get("finding_id", ""),  # CVE ID (human-readable)
            "project_version_id": row.get("project_version_id", ""),
            "folder_name": row.get("folder_name", ""),
            "current_vex_status": str(row["status"]) if row.get("status") and str(row.get("status", "")) not in ("", "nan", "None") else None,
            "current_severity": row.get("severity", ""),
            "priority_band": band,
            "triage_score": row.get("triage_score", 0),
            "recommended_vex_status": vex_status,
            "reason": reason,
            "reachability_score": reach_score,
            "reachability_label": reach_label,
            "vuln_functions": vuln_funcs,
            "component_name": row.get("component_name", ""),
            "component_version": row.get("component_version", ""),
        })

    return recommendations


# =============================================================================
# AI Remediation Guidance
# =============================================================================

def _get_ai_config(config: Any, additional_data: dict[str, Any] | None) -> dict[str, Any]:
    """Extract AI configuration from config/additional_data."""
    result = {"enabled": False, "depth": "summary", "cache_dir": None, "cache_ttl": 0}

    # Try config object first
    if config and hasattr(config, "ai"):
        result["enabled"] = bool(config.ai)
        result["depth"] = getattr(config, "ai_depth", "summary")
        result["cache_dir"] = getattr(config, "cache_dir", None)
        result["cache_ttl"] = getattr(config, "cache_ttl", 0) or 0
    # Fall back to additional_data['config']
    elif additional_data and "config" in additional_data:
        cfg = additional_data["config"]
        if hasattr(cfg, "ai"):
            result["enabled"] = bool(cfg.ai)
            result["depth"] = getattr(cfg, "ai_depth", "summary")
            result["cache_dir"] = getattr(cfg, "cache_dir", None)
            result["cache_ttl"] = getattr(cfg, "cache_ttl", 0) or 0

    return result


def _generate_ai_guidance(
    df: pd.DataFrame,
    portfolio_summary: dict[str, Any],
    project_summary_df: pd.DataFrame,
    top_components: pd.DataFrame,
    ai_depth: str = "summary",
    cache_dir: str | None = None,
    cache_ttl: int = 0,
) -> tuple[str, dict[str, str], dict[str, dict[str, Any]]]:
    """
    Generate AI remediation guidance at all requested scopes.

    Args:
        cache_ttl: Cache TTL in seconds. 0 = no AI caching (regenerate every run).

    Returns:
        Tuple of (portfolio_summary_text, project_summaries_dict, component_guidance_dict)
    """
    try:
        from fs_report.llm_client import LLMClient
    except ImportError:
        logger.warning("anthropic package not available; skipping AI guidance")
        return "", {}, {}

    try:
        llm = LLMClient(cache_dir=cache_dir, cache_ttl=cache_ttl)
    except (ValueError, ImportError) as e:
        logger.warning(f"LLM client init failed: {e}")
        return "", {}, {}

    # --- Build reachability summary for portfolio prompt ---
    reachability_summary = None
    if "reachability_score" in df.columns:
        reachable_count = int((df["reachability_score"] > 0).sum())
        unreachable_count = int((df["reachability_score"] < 0).sum())
        unknown_count = int((df["reachability_score"] == 0).sum())
        # Collect top vulnerable functions across all reachable findings
        top_vuln_funcs = []
        if "vuln_functions" in df.columns:
            all_funcs = (
                df.loc[df["reachability_score"] > 0, "vuln_functions"]
                .dropna()
                .str.split(",")
                .explode()
                .str.strip()
            )
            top_vuln_funcs = (
                all_funcs[all_funcs != ""]
                .value_counts()
                .head(10)
                .index.tolist()
            )
        reachability_summary = {
            "reachable": reachable_count,
            "unreachable": unreachable_count,
            "unknown": unknown_count,
            "top_vuln_functions": top_vuln_funcs,
        }

    # --- Portfolio summary (only when multiple projects) ---
    project_names = df["project_name"].unique()
    is_single_project = len(project_names) <= 1

    if is_single_project:
        logger.info("Single project — skipping portfolio AI summary (redundant)")
        ai_portfolio = ""
    else:
        logger.info("Generating AI portfolio summary...")
        project_summaries_list = (
            project_summary_df.to_dict("records") if not project_summary_df.empty else []
        )
        top_components_list = (
            top_components.to_dict("records") if not top_components.empty else []
        )
        ai_portfolio = llm.generate_portfolio_summary(
            portfolio_summary, project_summaries_list, top_components_list,
            reachability_summary=reachability_summary,
        )

    # --- Project summaries (always) ---
    logger.info("Generating AI project summaries...")
    ai_projects: dict[str, str] = {}
    for project_name in project_names:
        proj_df = df[df["project_name"] == project_name]
        band_counts = proj_df["priority_band"].value_counts().to_dict()
        findings_list = proj_df.head(50).to_dict("records")
        ai_projects[project_name] = llm.generate_project_summary(
            project_name, findings_list, band_counts
        )

    # --- Component guidance (full depth only) ---
    ai_components: dict[str, dict[str, Any]] = {}
    if ai_depth == "full":
        logger.info("Generating AI component guidance (full depth)...")
        # Group Critical+High findings by component+version
        critical_high = df[df["priority_band"].isin(["CRITICAL", "HIGH"])]
        if not critical_high.empty:
            component_groups = (
                critical_high.groupby(["component_name", "component_version"])
                .agg(
                    cve_ids=("finding_id", list),
                    count=("finding_id", "count"),
                )
                .reset_index()
            )
            components_list = [
                {
                    "component_name": row["component_name"],
                    "component_version": row["component_version"],
                    "cve_ids": row["cve_ids"][:10],  # Limit CVEs per component
                }
                for _, row in component_groups.iterrows()
            ]

            # Build reachability map: finding_id -> reachability info
            reachability_map: dict[str, dict[str, Any]] = {}
            reach_cols = [
                "finding_id", "reachability_score", "reachability_label",
                "vuln_functions",
            ]
            if "reachability_factors" in df.columns:
                reach_cols.append("reachability_factors")
            available_cols = [c for c in reach_cols if c in df.columns]
            if available_cols and "finding_id" in available_cols:
                for _, row in critical_high[available_cols].iterrows():
                    fid = row.get("finding_id", "")
                    if fid:
                        ri = {"finding_id": fid}
                        ri["reachability_score"] = row.get("reachability_score", 0)
                        ri["reachability_label"] = row.get("reachability_label", "UNKNOWN")
                        ri["vuln_functions"] = row.get("vuln_functions", "")
                        if "reachability_factors" in row.index:
                            ri["factors"] = row.get("reachability_factors", [])
                        reachability_map[fid] = ri

            ai_components = llm.generate_batch_component_guidance(
                components_list,
                reachability_map=reachability_map if reachability_map else None,
            )

    stats = llm.get_stats()
    logger.info(
        f"AI guidance complete: {stats['api_calls']} API calls, "
        f"{stats['cache_hits']} cache hits"
    )

    return ai_portfolio, ai_projects, ai_components


# =============================================================================
# Helpers
# =============================================================================

def _empty_result() -> dict[str, Any]:
    """Return an empty result structure."""
    return {
        "findings_df": pd.DataFrame(),
        "project_summary_df": pd.DataFrame(),
        "portfolio_summary": {band: 0 for band in BAND_ORDER},
        "cvss_band_matrix": {"rows": SEVERITY_ORDER, "cols": BAND_ORDER, "data": []},
        "gate_funnel": {
            "gate_1_critical": 0, "gate_2_high": 0,
            "additive_high": 0, "additive_medium": 0,
            "additive_low": 0, "additive_info": 0,
            "total": 0,
        },
        "top_components": pd.DataFrame(),
        "factor_radar": {"labels": [], "datasets": []},
        "vex_recommendations": [],
        "band_colors": BAND_COLORS,
        "is_single_project": False,
        "single_project_name": None,
        "ai_portfolio_summary": "",
        "ai_project_summaries": {},
        "ai_component_guidance": {},
    }
