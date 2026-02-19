"""
Pandas transform for Triage Prioritization report.

Implements a tiered-gates scoring model that prioritizes findings based on
real-world exploitability and reachability rather than CVSS alone.

Gates are defined using a YAML DSL (see DEFAULT_GATES) and can be fully
customized via recipe parameters or --scoring-file.  Default gates:
  Gate 1 (CRITICAL): Reachable + (Exploit OR KEV)
  Gate 2 (HIGH): Not unreachable + NETWORK + EPSS > 90%
Additive scoring: Points-based scoring for remaining findings
"""

import logging
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# =============================================================================
# Constants (defaults — can be overridden via recipe parameters or --scoring-file)
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
POINTS_REACHABLE = 30  # reachabilityScore > 0
POINTS_UNKNOWN = 0  # reachabilityScore == 0 (inconclusive)
POINTS_UNREACHABLE = -15  # reachabilityScore < 0

POINTS_EXPLOIT = 25  # Has known exploit
POINTS_KEV_ONLY = 20  # In KEV but no exploit info

POINTS_VECTOR_NETWORK = 15
POINTS_VECTOR_ADJACENT = 10
POINTS_VECTOR_LOCAL = 5
POINTS_VECTOR_PHYSICAL = 0

EPSS_MAX_POINTS = 20  # 20 × percentile
CVSS_MAX_POINTS = 10  # 10 × (score/10)

POINTS_VEX_RESOLVED = -50  # NOT_AFFECTED, RESOLVED, RESOLVED_WITH_PEDIGREE

# Band thresholds for additive scoring
BAND_HIGH_THRESHOLD = 70
BAND_MEDIUM_THRESHOLD = 40
BAND_LOW_THRESHOLD = 25

# Default weights dict (built from module constants)
DEFAULT_WEIGHTS: dict[str, int | float] = {
    "reachable": POINTS_REACHABLE,
    "unknown": POINTS_UNKNOWN,
    "unreachable": POINTS_UNREACHABLE,
    "exploit": POINTS_EXPLOIT,
    "kev_only": POINTS_KEV_ONLY,
    "vector_network": POINTS_VECTOR_NETWORK,
    "vector_adjacent": POINTS_VECTOR_ADJACENT,
    "vector_local": POINTS_VECTOR_LOCAL,
    "vector_physical": POINTS_VECTOR_PHYSICAL,
    "epss_max": EPSS_MAX_POINTS,
    "cvss_max": CVSS_MAX_POINTS,
    "band_high_threshold": BAND_HIGH_THRESHOLD,
    "band_medium_threshold": BAND_MEDIUM_THRESHOLD,
    "band_low_threshold": BAND_LOW_THRESHOLD,
    "vex_resolved": POINTS_VEX_RESOLVED,
}

# Default gate definitions (DSL format).
# Each gate is evaluated in order; once a finding matches, it is excluded
# from subsequent gates.  Customers can override via recipe parameters.gates
# or --scoring-file.
DEFAULT_GATES: list[dict[str, Any]] = [
    {
        "name": "GATE_1",
        "band": "CRITICAL",
        "score": 100,
        "conditions": {
            "all": [
                {"field": "reachability_score", "op": ">", "value": 0},
                {
                    "any": [
                        {"field": "has_exploit", "op": "==", "value": True},
                        {"field": "in_kev", "op": "==", "value": True},
                    ]
                },
            ]
        },
    },
    {
        "name": "GATE_2",
        "band": "HIGH",
        "score": 85,
        "conditions": {
            "all": [
                {"field": "reachability_score", "op": ">=", "value": 0},
                {"field": "attack_vector", "op": "in", "value": ["NETWORK"]},
                {"field": "epss_percentile", "op": ">", "value": 0.9},
            ]
        },
    },
]

# Supported comparison operators for gate condition DSL
_CONDITION_OPS = {
    ">": lambda s, v: s > v,
    ">=": lambda s, v: s >= v,
    "<": lambda s, v: s < v,
    "<=": lambda s, v: s <= v,
    "==": lambda s, v: s == v,
    "!=": lambda s, v: s != v,
    "in": lambda s, v: s.isin(v) if isinstance(v, list) else s == v,
}


def _evaluate_condition(df: pd.DataFrame, condition: dict[str, Any]) -> pd.Series:
    """Recursively evaluate a gate condition tree against a DataFrame.

    Condition format:
      Leaf:  {"field": "col_name", "op": ">", "value": 0}
      AND:   {"all": [<condition>, ...]}
      OR:    {"any": [<condition>, ...]}

    Returns a boolean pd.Series (one value per row).
    """
    # AND combinator
    if "all" in condition:
        sub_conditions = condition["all"]
        if not sub_conditions:
            return pd.Series(True, index=df.index)
        mask = pd.Series(True, index=df.index)
        for sub in sub_conditions:
            mask = mask & _evaluate_condition(df, sub)
        return mask

    # OR combinator
    if "any" in condition:
        sub_conditions = condition["any"]
        if not sub_conditions:
            return pd.Series(False, index=df.index)
        mask = pd.Series(False, index=df.index)
        for sub in sub_conditions:
            mask = mask | _evaluate_condition(df, sub)
        return mask

    # Leaf condition: {field, op, value}
    field = condition.get("field", "")
    op = condition.get("op", "==")
    value = condition.get("value")

    if field not in df.columns:
        logger.warning(
            f"Gate condition references unknown column '{field}'; treating as False"
        )
        return pd.Series(False, index=df.index)

    op_func = _CONDITION_OPS.get(op)
    if op_func is None:
        logger.warning(
            f"Gate condition uses unknown operator '{op}'; treating as False"
        )
        return pd.Series(False, index=df.index)

    try:
        result: pd.Series[Any] = op_func(df[field], value)
        return result
    except Exception as e:
        logger.warning(f"Gate condition evaluation failed ({field} {op} {value}): {e}")
        return pd.Series(False, index=df.index)


# Human-friendly display labels for common DataFrame column names
_FRIENDLY_LABELS: dict[str, str] = {
    "reachability_score": "reachability score",
    "has_exploit": "known exploit",
    "in_kev": "in CISA KEV",
    "attack_vector": "attack vector",
    "epss_percentile": "EPSS percentile",
    "risk": "CVSS score",
    "severity": "severity",
}

# Unicode-friendly operator symbols for display
_FRIENDLY_OPS: dict[str, str] = {
    ">": ">",
    ">=": "≥",
    "<": "<",
    "<=": "≤",
    "==": "=",
    "!=": "≠",
}


def _humanize_condition(condition: dict[str, Any]) -> str:
    """Convert a gate condition tree to a human-readable string.

    Uses friendly field labels and operator symbols for readability.

    Examples:
        {"field": "reachability_score", "op": ">", "value": 0}
        → "reachability score > 0"

        {"all": [..., {"any": [...]}]}
        → "reachability score > 0 AND (known exploit OR in CISA KEV)"

        {"field": "epss_percentile", "op": ">", "value": 0.9}
        → "EPSS > 90th percentile"
    """
    if "all" in condition:
        parts = [_humanize_condition(sub) for sub in condition["all"]]
        return " AND ".join(parts)

    if "any" in condition:
        parts = [_humanize_condition(sub) for sub in condition["any"]]
        joined = " OR ".join(parts)
        # Wrap in parens if more than one part (for clarity in AND context)
        if len(parts) > 1:
            return f"({joined})"
        return joined

    field = condition.get("field", "?")
    op = condition.get("op", "==")
    value = condition.get("value")

    label = _FRIENDLY_LABELS.get(field, field.replace("_", " "))
    friendly_op = _FRIENDLY_OPS.get(op, op)

    # Boolean equality: "known exploit" / "NOT known exploit"
    if op == "==" and value is True:
        return str(label)
    if op == "==" and value is False:
        return f"NOT {label}"

    # EPSS percentile: "EPSS > 90th percentile"
    if field == "epss_percentile" and isinstance(value, int | float) and 0 < value <= 1:
        pct = round(value * 100)
        return f"EPSS {friendly_op} {pct}th percentile"

    # 'in' with list: "NETWORK attack vector" or "NETWORK or ADJACENT attack vector"
    if op == "in" and isinstance(value, list):
        if len(value) == 1:
            return f"{value[0]} {label}"
        return f"{' or '.join(str(v) for v in value)} {label}"

    return f"{label} {friendly_op} {value}"


def _build_scoring_config(
    gates: list[dict[str, Any]],
    weights: dict[str, int | float],
) -> dict[str, Any]:
    """Build a template-friendly scoring configuration dict.

    Returns a dict with:
      - gates: list of {name, band, score, description} for each gate
      - weights: the resolved additive scoring weights
    """
    gate_summaries = []
    for gate in gates:
        gate_summaries.append(
            {
                "name": gate.get("name", "UNKNOWN"),
                "band": gate.get("band", "UNKNOWN"),
                "score": gate.get("score", 0),
                "description": _humanize_condition(gate.get("conditions", {})),
            }
        )
    return {
        "gates": gate_summaries,
        "weights": dict(weights),
    }


def _build_scoring_methodology(scoring_config: dict[str, Any] | None = None) -> str:
    """Build a scoring methodology text block for LLM prompts.

    Generates a dynamic description from the active scoring configuration
    so that LLM prompts always reflect the actual gates and weights in use.

    Args:
        scoring_config: The dict produced by ``_build_scoring_config()``.
            If None, builds from DEFAULT_GATES/DEFAULT_WEIGHTS.
    """
    if scoring_config is None:
        scoring_config = _build_scoring_config(DEFAULT_GATES, DEFAULT_WEIGHTS)

    lines = [
        "## Scoring Methodology",
        "Findings are prioritized using a tiered-gates model:",
    ]

    # Gate descriptions
    for gate in scoring_config.get("gates", []):
        name = gate.get("name", "UNKNOWN")
        band = gate.get("band", "UNKNOWN")
        desc = gate.get("description", "")
        lines.append(f"- {name} ({band}): {desc}")

    # Additive scoring summary
    w = scoring_config.get("weights", {})
    bonus_parts = []
    if w.get("reachable"):
        bonus_parts.append(f"reachability (+{w['reachable']})")
    if w.get("exploit"):
        bonus_parts.append(f"exploit (+{w['exploit']})")
    if w.get("kev_only"):
        bonus_parts.append(f"KEV (+{w['kev_only']})")
    if w.get("vector_network"):
        bonus_parts.append(f"attack vector (up to +{w['vector_network']})")
    if w.get("epss_max"):
        bonus_parts.append(f"EPSS (up to +{w['epss_max']})")
    if w.get("cvss_max"):
        bonus_parts.append(f"CVSS (up to +{w['cvss_max']})")
    if bonus_parts:
        lines.append(
            f"- Remaining findings scored additively: {', '.join(bonus_parts)}"
        )

    # Penalties (negative modifiers)
    penalty_parts = []
    vex_penalty = w.get("vex_resolved", 0)
    if vex_penalty:
        penalty_parts.append(f"VEX resolved/not-affected ({vex_penalty:+d})")
    unreachable_penalty = w.get("unreachable", 0)
    if unreachable_penalty:
        penalty_parts.append(f"unreachable ({unreachable_penalty:+d})")
    if penalty_parts:
        lines.append(f"- Penalties: {', '.join(penalty_parts)}")

    # Band thresholds
    band_parts = []
    if w.get("band_high_threshold"):
        band_parts.append(f"HIGH >= {w['band_high_threshold']}")
    if w.get("band_medium_threshold"):
        band_parts.append(f"MEDIUM >= {w['band_medium_threshold']}")
    if w.get("band_low_threshold"):
        band_parts.append(f"LOW >= {w['band_low_threshold']}")
        band_parts.append(f"INFO < {w['band_low_threshold']}")
    if band_parts:
        lines.append(f"- Bands: {', '.join(band_parts)}")

    return "\n".join(lines)


def _load_weights(
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, int | float]:
    """Load scoring weights with priority: --scoring-file > recipe parameters > defaults.

    Returns a dict with all weight keys populated.
    """
    weights = dict(DEFAULT_WEIGHTS)

    # Layer 1: recipe parameters (lowest priority override)
    if additional_data:
        recipe_params = additional_data.get("recipe_parameters", {})
        recipe_weights = (
            recipe_params.get("scoring_weights", {}) if recipe_params else {}
        )
        if recipe_weights and isinstance(recipe_weights, dict):
            for k, v in recipe_weights.items():
                if k in weights:
                    weights[k] = v
            logger.debug(
                f"Applied {len(recipe_weights)} weights from recipe parameters"
            )

    # Layer 2: --scoring-file (highest priority override)
    scoring_file = None
    if config and hasattr(config, "scoring_file"):
        scoring_file = getattr(config, "scoring_file", None)
    elif additional_data and "config" in additional_data:
        cfg = additional_data["config"]
        scoring_file = getattr(cfg, "scoring_file", None)

    if scoring_file:
        try:
            import yaml

            path = Path(scoring_file)
            if path.exists():
                with open(path) as f:
                    file_weights = yaml.safe_load(f) or {}
                if isinstance(file_weights, dict):
                    # Support both flat and nested (scoring_weights: {...}) formats
                    if "scoring_weights" in file_weights:
                        file_weights = file_weights["scoring_weights"]
                    for k, v in file_weights.items():
                        if k in weights:
                            weights[k] = v
                    logger.info(f"Applied scoring weights from {scoring_file}")
                else:
                    logger.warning(
                        f"Scoring file {scoring_file} is not a valid YAML dict"
                    )
            else:
                logger.warning(f"Scoring file not found: {scoring_file}")
        except Exception as e:
            logger.warning(f"Failed to load scoring file {scoring_file}: {e}")

    return weights


def _load_gates(
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Load gate definitions with priority: --scoring-file > recipe parameters > defaults.

    Returns a list of gate definition dicts.
    """
    import copy

    gates: list[dict[str, Any]] | None = None

    # Layer 1: recipe parameters (lowest priority override)
    if additional_data:
        recipe_params = additional_data.get("recipe_parameters", {})
        recipe_gates = recipe_params.get("gates") if recipe_params else None
        if recipe_gates and isinstance(recipe_gates, list):
            gates = copy.deepcopy(recipe_gates)
            logger.debug(f"Loaded {len(gates)} gates from recipe parameters")

    # Layer 2: --scoring-file (highest priority override)
    scoring_file = None
    if config and hasattr(config, "scoring_file"):
        scoring_file = getattr(config, "scoring_file", None)
    elif additional_data and "config" in additional_data:
        cfg = additional_data["config"]
        scoring_file = getattr(cfg, "scoring_file", None)

    if scoring_file:
        try:
            import yaml

            path = Path(scoring_file)
            if path.exists():
                with open(path) as f:
                    file_data = yaml.safe_load(f) or {}
                if isinstance(file_data, dict):
                    file_gates = file_data.get("gates")
                    if file_gates and isinstance(file_gates, list):
                        gates = copy.deepcopy(file_gates)
                        logger.info(f"Applied gate definitions from {scoring_file}")
        except Exception as e:
            logger.warning(
                f"Failed to load gates from scoring file {scoring_file}: {e}"
            )

    if gates is None:
        gates = copy.deepcopy(DEFAULT_GATES)
        logger.debug("Using default gate definitions")

    return gates


# =============================================================================
# Main Entry Point
# =============================================================================


def triage_prioritization_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Main transform entry point for Triage Prioritization report.

    Args:
        data: Raw findings data from the API (list of dicts or DataFrame)
        config: Config object (optional)
        additional_data: Extra data dict (optional)

    Returns:
        Dictionary with multiple DataFrames for template rendering
    """
    if isinstance(data, pd.DataFrame):
        logger.info(f"Triage prioritization transform: processing {len(data)} findings")
        if data.empty:
            logger.warning("No findings data provided")
            return _empty_result()
        df = data
    else:
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

    # Load scoring configuration (--scoring-file > recipe parameters > defaults)
    weights = _load_weights(config, additional_data)
    gates = _load_gates(config, additional_data)

    # Apply tiered gates scoring (DSL-driven)
    df = apply_tiered_gates(df, gates=gates)

    # Apply additive scoring for findings that didn't hit any gate
    df = calculate_additive_score(df, weights=weights, gates=gates)

    # Assign risk bands
    df = assign_risk_bands(df, weights=weights)

    # Build scoring config (used by template and prompt generation)
    scoring_config = _build_scoring_config(gates, weights)

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
    vex_override = False
    if config and hasattr(config, "vex_override"):
        vex_override = bool(config.vex_override)
    elif additional_data and "config" in additional_data:
        cfg = additional_data["config"]
        vex_override = bool(getattr(cfg, "vex_override", False))
    vex_recommendations = build_vex_recommendations(df, vex_override=vex_override)

    logger.info(
        f"Triage complete: {len(df)} findings scored — "
        f"CRITICAL={portfolio_summary.get('CRITICAL', 0)}, "
        f"HIGH={portfolio_summary.get('HIGH', 0)}, "
        f"MEDIUM={portfolio_summary.get('MEDIUM', 0)}, "
        f"LOW={portfolio_summary.get('LOW', 0)}, "
        f"INFO={portfolio_summary.get('INFO', 0)}"
    )

    # Track extra output files (prompts, VEX JSON) for user-visible listing
    extra_generated_files: list[str] = []

    # AI prompt generation (optional, --ai-prompts flag)
    ai_triage_prompts: list[dict[str, str]] = []
    ai_portfolio_prompt: str = ""
    ai_project_prompts: dict[str, str] = {}
    ai_component_prompts: dict[str, str] = {}
    want_prompts = False
    if config and hasattr(config, "ai_prompts"):
        want_prompts = bool(config.ai_prompts)
    elif additional_data and "config" in additional_data:
        cfg = additional_data["config"]
        want_prompts = bool(getattr(cfg, "ai_prompts", False))

    if want_prompts:
        # --- Initialise NVD client for fix-version enrichment in prompts ---
        _prompt_nvd = None
        try:
            from fs_report.nvd_client import NVD_ATTRIBUTION, NVDClient

            _prompt_cache_dir = None
            _prompt_cache_ttl = 0
            _prompt_nvd_key = None
            if config and hasattr(config, "cache_dir"):
                _prompt_cache_dir = getattr(config, "cache_dir", None)
                _prompt_cache_ttl = getattr(config, "cache_ttl", 0) or 0
                _prompt_nvd_key = getattr(config, "nvd_api_key", None)
            elif additional_data and "config" in additional_data:
                _pcfg = additional_data["config"]
                _prompt_cache_dir = getattr(_pcfg, "cache_dir", None)
                _prompt_cache_ttl = getattr(_pcfg, "cache_ttl", 0) or 0
                _prompt_nvd_key = getattr(_pcfg, "nvd_api_key", None)
            _prompt_nvd = NVDClient(
                api_key=_prompt_nvd_key,
                cache_dir=_prompt_cache_dir,
                cache_ttl=max(_prompt_cache_ttl, 86400),
            )
            logger.info(NVD_ATTRIBUTION)
            # Batch-fetch NVD data for top finding CVEs
            _prompt_cve_ids = [
                fid
                for fid in df.head(100)["finding_id"].dropna().unique()
                if str(fid).startswith("CVE-")
            ]
            if _prompt_cve_ids:
                logger.info(
                    f"Fetching NVD fix data for {len(_prompt_cve_ids)} CVEs "
                    f"(prompt enrichment)..."
                )
                _prompt_nvd.get_batch(list(_prompt_cve_ids), progress=True)
        except Exception as _nvd_err:
            logger.info(f"NVD unavailable for prompt enrichment: {_nvd_err}")

        # --- Per-finding prompts (top 100 by priority, matching findings table) ---
        prompt_df = df.head(100)
        logger.info(
            f"Generating AI prompts for top {len(prompt_df)} findings by priority"
        )

        prompts_for_file: list[tuple[str, str, str, str]] = []
        for _, row in prompt_df.iterrows():
            _nvd_snip = ""
            if _prompt_nvd:
                fid = row.get("finding_id", "")
                if str(fid).startswith("CVE-"):
                    _nvd_snip = _prompt_nvd.format_for_prompt(str(fid))
            prompt_text = _build_triage_prompt(
                row, nvd_snippet=_nvd_snip, scoring_config=scoring_config
            )
            finding_id = row.get("finding_id", "Unknown")
            component = f"{row.get('component_name', '')} {row.get('component_version', '')}".strip()
            band = row.get("priority_band", "")

            ai_triage_prompts.append(
                {
                    "finding_id": finding_id,
                    "component": component,
                    "priority_band": band,
                    "prompt": prompt_text,
                }
            )
            prompts_for_file.append((finding_id, component, band, prompt_text))

        # --- Portfolio prompt (multi-project only) ---
        project_names = df["project_name"].unique()
        is_multi = len(project_names) > 1

        reachability_summary: dict[str, Any] | None = None
        if "reachability_score" in df.columns:
            reachable_count = int((df["reachability_label"] == "REACHABLE").sum())
            unreachable_count = int((df["reachability_label"] == "UNREACHABLE").sum())
            inconclusive_count = int((df["reachability_label"] == "INCONCLUSIVE").sum())
            unknown_count = int((df["reachability_label"] == "UNKNOWN").sum())
            top_vuln_funcs: list[str] = []
            if "vuln_functions" in df.columns:
                all_funcs = (
                    df.loc[df["reachability_score"] > 0, "vuln_functions"]
                    .dropna()
                    .str.split(",")
                    .explode()
                    .str.strip()
                )
                top_vuln_funcs = (
                    all_funcs[all_funcs != ""].value_counts().head(10).index.tolist()
                )
            reachability_summary = {
                "reachable": reachable_count,
                "unreachable": unreachable_count,
                "inconclusive": inconclusive_count,
                "unknown": unknown_count,
                "top_vuln_functions": top_vuln_funcs,
            }

        if is_multi:
            proj_records: list[dict[str, Any]] = (
                project_summary_df.to_dict("records")  # type: ignore[assignment]
                if not project_summary_df.empty
                else []
            )
            comp_records: list[dict[str, Any]] = (
                top_components.to_dict("records")  # type: ignore[assignment]
                if not top_components.empty
                else []
            )
            ai_portfolio_prompt = _build_portfolio_prompt(
                portfolio_summary,
                proj_records,
                comp_records,
                reachability_summary,
                scoring_config=scoring_config,
            )
            logger.info("Generated portfolio-level AI prompt")

        # --- Per-project prompts ---
        for pname in project_names:
            proj_df = df[df["project_name"] == pname]
            band_counts = proj_df["priority_band"].value_counts().to_dict()
            proj_findings = proj_df.head(50).to_dict("records")
            ai_project_prompts[str(pname)] = _build_project_prompt(
                str(pname), proj_findings, band_counts, scoring_config=scoring_config
            )
        logger.info(f"Generated {len(ai_project_prompts)} project-level AI prompts")

        # --- Per-component prompts (all listed components with findings) ---
        if not top_components.empty:
            # Build reachability map across all findings for component prompts
            reach_map: dict[str, dict[str, Any]] = {}
            reach_cols = ["finding_id", "reachability_score", "vuln_functions"]
            available_cols = [c for c in reach_cols if c in df.columns]
            if "finding_id" in available_cols:
                for _, row in df[available_cols].iterrows():
                    fid = row.get("finding_id", "")
                    if fid:
                        reach_map[fid] = {
                            "finding_id": fid,
                            "reachability_score": row.get("reachability_score", 0),
                            "vuln_functions": row.get("vuln_functions", ""),
                        }

            # Group findings by component to get CVE lists
            comp_groups = (
                df.groupby(["component_name", "component_version"])
                .agg(cve_ids=("finding_id", list), count=("finding_id", "count"))
                .reset_index()
            )
            # Only generate prompts for components in the top_components table
            listed_comps = set()
            for _, tc_row in top_components.iterrows():
                listed_comps.add(
                    (tc_row["component_name"], tc_row["component_version"])
                )

            # Batch-fetch NVD data for component CVEs (many already cached)
            if _prompt_nvd:
                _comp_cves: list[str] = []
                for _, crow in comp_groups.iterrows():
                    ct = (crow["component_name"], crow["component_version"])
                    if ct in listed_comps:
                        _comp_cves.extend(
                            c for c in crow["cve_ids"][:10] if str(c).startswith("CVE-")
                        )
                _comp_cves_unique = list(dict.fromkeys(_comp_cves))
                if _comp_cves_unique:
                    logger.info(
                        f"Fetching NVD fix data for {len(_comp_cves_unique)} "
                        f"component CVEs (prompt enrichment)..."
                    )
                    _prompt_nvd.get_batch(_comp_cves_unique, progress=True)

            for _, crow in comp_groups.iterrows():
                comp_tuple = (crow["component_name"], crow["component_version"])
                if comp_tuple not in listed_comps:
                    continue
                comp_key = f"{crow['component_name']}:{crow['component_version']}"
                cve_ids = crow["cve_ids"][:10]
                reach_info = [reach_map[c] for c in cve_ids if c in reach_map] or None
                # NVD fix snippet for this component's CVEs
                _comp_nvd_snip = ""
                if _prompt_nvd:
                    _comp_nvd_snip = _prompt_nvd.format_batch_for_prompt(cve_ids)
                ai_component_prompts[comp_key] = _build_component_prompt(
                    crow["component_name"],
                    crow["component_version"],
                    cve_ids,
                    reach_info,
                    nvd_fix_snippet=_comp_nvd_snip,
                )
            logger.info(
                f"Generated {len(ai_component_prompts)} component-level AI prompts"
            )

        # Write prompts markdown file (all scopes)
        if config:
            _prompts_path = _write_triage_prompts_file(
                prompts_for_file,
                config,
                portfolio_prompt=ai_portfolio_prompt,
                project_prompts=ai_project_prompts,
                component_prompts=ai_component_prompts,
            )
            if _prompts_path:
                extra_generated_files.append(_prompts_path)

    # AI remediation guidance (optional, --ai flag)
    ai_portfolio_summary = ""
    ai_project_summaries: dict[str, str] = {}
    ai_component_guidance: dict[str, dict[str, Any]] = {}
    ai_finding_guidance: dict[str, dict[str, str]] = {}

    ai_config = _get_ai_config(config, additional_data)
    if ai_config.get("enabled"):
        (
            ai_portfolio_summary,
            ai_project_summaries,
            ai_component_guidance,
            ai_finding_guidance,
        ) = _generate_ai_guidance(
            df=df,
            portfolio_summary=portfolio_summary,
            project_summary_df=project_summary_df,
            top_components=top_components,
            ai_depth=ai_config.get("depth", "summary"),
            cache_dir=ai_config.get("cache_dir"),
            cache_ttl=ai_config.get("cache_ttl", 0),
            provider=ai_config.get("provider"),
            nvd_api_key=ai_config.get("nvd_api_key"),
            scoring_config=scoring_config,
        )

    # Defensive recompute of reachability_label from reachability_score
    # (ensures label is consistent with score after all transformations).
    # Preserve UNKNOWN labels — they indicate reachability was never run,
    # which is distinct from INCONCLUSIVE (ran but score == 0).
    df["reachability_label"] = [
        (
            existing
            if existing == "UNKNOWN"
            else (
                "REACHABLE"
                if score > 0
                else ("UNREACHABLE" if score < 0 else "INCONCLUSIVE")
            )
        )
        for score, existing in zip(
            df["reachability_score"], df["reachability_label"], strict=False
        )
    ]

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
        "finding_id",
        "internal_id",
        "severity",
        "component_name",
        "component_version",
        "component_id",
        "project_name",
        "project_id",
        "project_version_id",
        "version_name",
        "priority_band",
        "triage_score",
        "gate_assignment",
        "reachability_label",
        "reachability_score",
        "vuln_functions",
        "has_exploit",
        "in_kev",
        "attack_vector",
        "epss_percentile",
        "risk",
    ]
    # Only keep columns that exist
    output_columns = [c for c in output_columns if c in df.columns]
    findings_df = df[output_columns].copy()

    # Ensure reachability_label never contains NaN (renders as "nan" in templates)
    if "reachability_label" in findings_df.columns:
        findings_df["reachability_label"] = findings_df["reachability_label"].fillna(
            "UNKNOWN"
        )

    # Determine if this is a single-project report
    unique_projects = df["project_name"].unique()
    is_single_project = len(unique_projects) <= 1
    single_project_name = (
        str(unique_projects[0])
        if is_single_project and len(unique_projects) == 1
        else None
    )

    # Build finding prompt lookup dict (finding_id -> prompt text) for template use
    ai_finding_prompts: dict[str, str] = {
        p["finding_id"]: p["prompt"] for p in ai_triage_prompts
    }

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
        "ai_finding_guidance": ai_finding_guidance,
        "ai_triage_prompts": ai_triage_prompts,
        "ai_portfolio_prompt": ai_portfolio_prompt,
        "ai_project_prompts": ai_project_prompts,
        "ai_component_prompts": ai_component_prompts,
        "ai_finding_prompts": ai_finding_prompts,
        "scoring_config": scoring_config,
        "_extra_generated_files": extra_generated_files,
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
            lambda x: (
                str(x.get("id", "")) if isinstance(x, dict) else str(x) if x else ""
            )
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
        col = (
            "hasKnownExploit"
            if "hasKnownExploit" in df.columns
            else "has_known_exploit"
        )
        df["has_exploit"] = df[col].fillna(False).astype(bool)
    elif "exploitInfo" in df.columns:
        df["has_exploit"] = df["exploitInfo"].apply(
            lambda x: isinstance(x, list) and len(x) > 0
        )
    elif "exploit_info" in df.columns:
        df["has_exploit"] = df["exploit_info"].apply(
            lambda x: (
                (isinstance(x, list) and len(x) > 0)
                if not isinstance(x, str)
                else (x not in ("", "[]", "null"))
            )
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
    # Track which rows had null scores (reachability never ran) vs explicit 0
    # (analysis ran but was inconclusive).
    #
    # The API may return reachability in three formats:
    #   1. Flat "reachabilityScore" field (legacy or direct API response)
    #   2. Flat "reachability_score" field (from SQLite cache, snake_case)
    #   3. Nested "reachability" dict: {"score": N, "label": "...", "factors": [...]}
    #      (newer API response where reachability is a sub-object on the finding)
    #
    # Handle nested "reachability" dict first — extract score and factors before
    # checking for flat fields.
    if (
        "reachability" in df.columns
        and df["reachability"].apply(lambda x: isinstance(x, dict)).any()
    ):
        df["reachabilityScore"] = df["reachability"].apply(
            lambda x: x.get("score") if isinstance(x, dict) else None
        )
        # Extract factors from nested object if not already a top-level column
        if "factors" not in df.columns:
            df["factors"] = df["reachability"].apply(
                lambda x: x.get("factors", []) if isinstance(x, dict) else []
            )

    if "reachabilityScore" in df.columns:
        raw_reach = pd.to_numeric(df["reachabilityScore"], errors="coerce")
    elif "reachability_score" in df.columns:
        raw_reach = pd.to_numeric(df["reachability_score"], errors="coerce")
    else:
        raw_reach = pd.Series([float("nan")] * len(df), index=df.index)

    reach_is_null = raw_reach.isna()
    df["reachability_score"] = raw_reach.fillna(0)

    # Four-tier reachability label:
    #   null (NaN)     → UNKNOWN (reachability was never run)
    #   positive score → REACHABLE (vulnerable function found in binary)
    #   negative score → UNREACHABLE
    #   zero           → INCONCLUSIVE (analysis ran but was inconclusive)
    df["reachability_label"] = [
        (
            "UNKNOWN"
            if is_null
            else (
                "REACHABLE"
                if score > 0
                else ("UNREACHABLE" if score < 0 else "INCONCLUSIVE")
            )
        )
        for score, is_null in zip(df["reachability_score"], reach_is_null, strict=False)
    ]

    # Reachability factors (array of evidence explaining the score)
    if "factors" in df.columns:
        # Preserve factors as-is (list of dicts from API, or JSON string from cache)
        def _parse_factors(x: Any) -> list:
            if isinstance(x, list):
                return x
            if isinstance(x, str) and x not in ("", "null", "[]"):
                import json as _json

                try:
                    return _json.loads(x)  # type: ignore[no-any-return]
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
        f"INCONCLUSIVE={reach_counts.get('INCONCLUSIVE', 0)}, "
        f"UNKNOWN={reach_counts.get('UNKNOWN', 0)}"
    )
    if (
        reach_counts.get("REACHABLE", 0) == 0
        and reach_counts.get("UNREACHABLE", 0) == 0
    ):
        # All unknown — check if reachabilityScore column was present at all
        score_col = (
            "reachabilityScore"
            if "reachabilityScore" in df.columns
            else "reachability_score"
        )
        if score_col in df.columns:
            non_null = df[score_col].notna().sum()
            non_zero = (df[score_col] != 0).sum() if non_null > 0 else 0
            logger.warning(
                f"All reachability labels are INCONCLUSIVE. "
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
        df["epss_percentile"] = pd.to_numeric(
            df["epssPercentile"], errors="coerce"
        ).fillna(0)
    elif "epss_percentile" not in df.columns:
        df["epss_percentile"] = 0.0
    else:
        df["epss_percentile"] = pd.to_numeric(
            df["epss_percentile"], errors="coerce"
        ).fillna(0)

    if "epssScore" in df.columns:
        df["epss_score"] = pd.to_numeric(df["epssScore"], errors="coerce").fillna(0)
    elif "epss_score" not in df.columns:
        df["epss_score"] = 0.0

    # --- Attack vector ---
    if "attackVector" in df.columns:
        df["attack_vector"] = (
            df["attackVector"].fillna("UNKNOWN").astype(str).str.upper()
        )
    elif "attack_vector" in df.columns:
        df["attack_vector"] = (
            df["attack_vector"].fillna("UNKNOWN").astype(str).str.upper()
        )
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

    # --- CWE (weakness type, e.g. CWE-787) ---
    if "cwes" in df.columns:
        import re as _re

        def _extract_cwe(cwes: Any) -> str:
            if isinstance(cwes, list) and cwes:
                cwe = str(cwes[0]).replace("CWE-CWE-", "CWE-")
                return cwe
            if isinstance(cwes, str):
                match = _re.search(r"CWE-\d+", cwes)
                if match:
                    return match.group(0)
            return ""

        df["cwe"] = df["cwes"].apply(_extract_cwe)
    elif "cwe" not in df.columns:
        df["cwe"] = ""

    # --- First detected date (for age-based prioritization) ---
    # API findings use "detected"; CVE endpoint uses "firstDetected";
    # cache may flatten to either "detected" or "first_detected".
    if "firstDetected" in df.columns:
        df["first_detected"] = df["firstDetected"].fillna("").astype(str)
    elif "detected" in df.columns and "first_detected" not in df.columns:
        df["first_detected"] = df["detected"].fillna("").astype(str)
    elif "first_detected" not in df.columns:
        df["first_detected"] = ""

    return df


# =============================================================================
# Tiered Gates
# =============================================================================


def apply_tiered_gates(
    df: pd.DataFrame,
    gates: list[dict[str, Any]] | None = None,
) -> pd.DataFrame:
    """Apply tiered gate classification using DSL-defined gate conditions.

    Gates are evaluated in order.  Once a finding matches a gate it is
    excluded from subsequent gates.

    Args:
        df: Normalized findings DataFrame.
        gates: List of gate definition dicts (DSL format).
               Falls back to DEFAULT_GATES if not provided.

    Each gate dict must have:
        name:       Gate identifier (e.g. "GATE_1")
        band:       Priority band assigned (e.g. "CRITICAL")
        score:      Fixed triage score for matched findings
        conditions: Condition tree with ``all``/``any``/leaf nodes
    """
    df = df.copy()
    df["gate_assignment"] = "NONE"

    gates = gates if gates is not None else DEFAULT_GATES

    for gate in gates:
        name = gate.get("name", "UNKNOWN")
        conditions = gate.get("conditions", {})

        # Evaluate condition tree; only consider findings not yet assigned
        unassigned = df["gate_assignment"] == "NONE"
        condition_mask = _evaluate_condition(df, conditions)
        gate_mask = unassigned & condition_mask

        df.loc[gate_mask, "gate_assignment"] = name
        band = gate.get("band", "?")
        logger.debug(f"{name} ({band}): {gate_mask.sum()} findings")

    return df


# =============================================================================
# Additive Scoring
# =============================================================================


def calculate_additive_score(
    df: pd.DataFrame,
    weights: dict[str, int | float] | None = None,
    gates: list[dict[str, Any]] | None = None,
) -> pd.DataFrame:
    """
    Calculate additive triage score for findings that didn't hit a gate.
    Gate-assigned findings get a fixed high score to ensure proper ordering.

    Args:
        df: DataFrame with ``gate_assignment`` column already populated.
        weights: Additive scoring weights dict.
        gates: Gate definitions (used to read fixed scores per gate).
    """
    w = weights or DEFAULT_WEIGHTS
    g = gates if gates is not None else DEFAULT_GATES
    df = df.copy()
    df["triage_score"] = 0.0

    pts_reachable = w.get("reachable", POINTS_REACHABLE)
    pts_unknown = w.get("unknown", POINTS_UNKNOWN)
    pts_unreachable = w.get("unreachable", POINTS_UNREACHABLE)
    pts_exploit = w.get("exploit", POINTS_EXPLOIT)
    pts_kev_only = w.get("kev_only", POINTS_KEV_ONLY)
    pts_vector_network = w.get("vector_network", POINTS_VECTOR_NETWORK)
    pts_vector_adjacent = w.get("vector_adjacent", POINTS_VECTOR_ADJACENT)
    pts_vector_local = w.get("vector_local", POINTS_VECTOR_LOCAL)
    pts_vector_physical = w.get("vector_physical", POINTS_VECTOR_PHYSICAL)
    epss_max = w.get("epss_max", EPSS_MAX_POINTS)
    cvss_max = w.get("cvss_max", CVSS_MAX_POINTS)

    # Reachability points
    df["_pts_reachability"] = df["reachability_score"].apply(
        lambda x: (
            pts_reachable if x > 0 else (pts_unreachable if x < 0 else pts_unknown)
        )
    )

    # Exploit/KEV points
    df["_pts_exploit"] = 0
    df.loc[df["has_exploit"], "_pts_exploit"] = pts_exploit
    df.loc[(~df["has_exploit"]) & df["in_kev"], "_pts_exploit"] = pts_kev_only

    # Attack vector points
    vector_points = {
        "NETWORK": pts_vector_network,
        "ADJACENT": pts_vector_adjacent,
        "LOCAL": pts_vector_local,
        "PHYSICAL": pts_vector_physical,
    }
    df["_pts_vector"] = df["attack_vector"].map(vector_points).fillna(0)

    # EPSS points (0–max scaled by percentile)
    df["_pts_epss"] = (df["epss_percentile"] * epss_max).clip(0, epss_max)

    # CVSS points (0–max scaled by risk/10)
    df["_pts_cvss"] = (df["risk"] / 10.0 * cvss_max).clip(0, cvss_max)

    # Sum additive score
    df["triage_score"] = (
        df["_pts_reachability"]
        + df["_pts_exploit"]
        + df["_pts_vector"]
        + df["_pts_epss"]
        + df["_pts_cvss"]
    ).round(1)

    # Override gated findings with fixed scores from gate definitions
    for gate_def in g:
        gate_name = gate_def.get("name", "")
        gate_score = float(gate_def.get("score", 0))
        mask = df["gate_assignment"] == gate_name
        if mask.any():
            df.loc[mask, "triage_score"] = gate_score

    # VEX status penalty: demote findings already marked as resolved/not-affected
    vex_penalty = w.get("vex_resolved", POINTS_VEX_RESOLVED)
    if "status" in df.columns:
        resolved_statuses = {"NOT_AFFECTED", "RESOLVED", "RESOLVED_WITH_PEDIGREE"}
        vex_mask = df["status"].astype(str).isin(resolved_statuses)
        df.loc[vex_mask, "triage_score"] += vex_penalty
        if vex_mask.any():
            logger.debug(
                f"VEX resolved penalty ({vex_penalty}): "
                f"applied to {vex_mask.sum()} findings"
            )

    # Clean up temporary columns
    temp_cols = [c for c in df.columns if c.startswith("_pts_")]
    df = df.drop(columns=temp_cols)

    return df


# =============================================================================
# Risk Band Assignment
# =============================================================================


def assign_risk_bands(
    df: pd.DataFrame,
    weights: dict[str, int | float] | None = None,
) -> pd.DataFrame:
    """Map gate assignments and additive scores to priority bands."""
    w = weights or DEFAULT_WEIGHTS
    high_threshold = w.get("band_high_threshold", BAND_HIGH_THRESHOLD)
    medium_threshold = w.get("band_medium_threshold", BAND_MEDIUM_THRESHOLD)
    low_threshold = w.get("band_low_threshold", BAND_LOW_THRESHOLD)
    df = df.copy()

    def _band(row: pd.Series) -> str:
        if row["gate_assignment"] == "GATE_1":
            return "CRITICAL"
        if row["gate_assignment"] == "GATE_2":
            return "HIGH"
        score = row["triage_score"]
        if score >= high_threshold:
            return "HIGH"
        if score >= medium_threshold:
            return "MEDIUM"
        if score >= low_threshold:
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
        return pd.DataFrame(
            columns=["project_name", "folder_name"]
            + BAND_ORDER
            + ["total_findings", "avg_score"]
        )

    # Cross-tabulate project × band
    ct = pd.crosstab(df["project_name"], df["priority_band"]).reindex(
        columns=BAND_ORDER, fill_value=0
    )
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
    summary: dict[str, Any] = {
        band: int(band_counts.get(band, 0)) for band in BAND_ORDER
    }
    summary["total"] = len(df)
    summary["avg_score"] = (
        round(float(df["triage_score"].mean()), 1) if not df.empty else 0.0
    )

    # VEX/triage status distribution
    if "status" in df.columns:
        status_counts = (
            df["status"]
            .fillna("")
            .astype(str)
            .replace({"nan": "", "None": ""})
            .value_counts()
            .to_dict()
        )
        # Separate the "no status" count
        not_triaged = status_counts.pop("", 0)
        summary["vex_status_counts"] = status_counts
        summary["vex_not_triaged"] = int(not_triaged)
    else:
        summary["vex_status_counts"] = {}
        summary["vex_not_triaged"] = len(df)

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
            value = (
                int(ct.loc[sev, band]) if sev in ct.index and band in ct.columns else 0  # type: ignore[arg-type]
            )
            if value > 0:
                matrix_data.append(
                    {
                        "x": sev_idx,  # CVSS on x-axis
                        "y": (num_bands - 1) - band_idx,  # Invert: CRITICAL=top
                        "v": value,
                        "severity": sev,
                        "band": band,
                    }
                )

    return {
        "rows": list(
            reversed(BAND_ORDER)
        ),  # y-axis labels top-to-bottom: CRITICAL, HIGH, ...
        "cols": SEVERITY_ORDER,  # x-axis labels: CRITICAL, HIGH, MEDIUM, LOW, NONE
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
    component_agg = (
        df.groupby(["component_name", "component_version"])
        .agg(
            total_findings=("finding_id", "count"),
            avg_score=("triage_score", "mean"),
            max_score=("triage_score", "max"),
        )
        .reset_index()
    )

    # Add representative IDs for platform deep links
    for col_name in ("project_id", "project_version_id", "component_id"):
        if col_name in df.columns:
            id_map = (
                df.groupby(["component_name", "component_version"])[col_name]
                .first()
                .reset_index()
            )
            id_map.columns = ["component_name", "component_version", col_name]
            component_agg = component_agg.merge(
                id_map, on=["component_name", "component_version"], how="left"
            )
        else:
            component_agg[col_name] = ""

    # Add finding_ids list per component (for Jira ticket creation)
    if "finding_id" in df.columns:
        fid_map = (
            df.groupby(["component_name", "component_version"])["finding_id"]
            .apply(list)
            .reset_index()
        )
        fid_map.columns = ["component_name", "component_version", "finding_ids"]
        component_agg = component_agg.merge(
            fid_map, on=["component_name", "component_version"], how="left"
        )
    else:
        component_agg["finding_ids"] = [[] for _ in range(len(component_agg))]

    # Add internal finding IDs per component (for Jira API calls)
    if "internal_id" in df.columns:
        iid_map = (
            df[df["internal_id"] != ""]
            .groupby(["component_name", "component_version"])["internal_id"]
            .apply(list)
            .reset_index()
        )
        iid_map.columns = [
            "component_name",
            "component_version",
            "finding_internal_ids",
        ]
        component_agg = component_agg.merge(
            iid_map, on=["component_name", "component_version"], how="left"
        )
    if "finding_internal_ids" not in component_agg.columns:
        component_agg["finding_internal_ids"] = [[] for _ in range(len(component_agg))]
    else:
        component_agg["finding_internal_ids"] = component_agg[
            "finding_internal_ids"
        ].apply(lambda x: x if isinstance(x, list) else [])

    # Get band counts per component
    band_ct = (
        pd.crosstab(
            [df["component_name"], df["component_version"]],
            df["priority_band"],
        )
        .reindex(columns=BAND_ORDER, fill_value=0)
        .reset_index()
    )

    # Merge
    result = component_agg.merge(
        band_ct, on=["component_name", "component_version"], how="left"
    )

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
        cvss = (
            min((raw_cvss / 10.0) * 100, 100)
            if raw_cvss <= 10.0
            else min(raw_cvss, 100)
        )

        datasets.append(
            {
                "label": project,
                "data": [
                    round(max(0, min(reachability, 100)), 1),
                    round(max(0, min(exploits, 100)), 1),
                    round(max(0, min(vector, 100)), 1),
                    round(max(0, min(epss, 100)), 1),
                    round(max(0, min(cvss, 100)), 1),
                ],
            }
        )

    return {
        "labels": ["Reachability", "Exploits", "Attack Vector", "EPSS", "CVSS"],
        "datasets": datasets,
    }


# =============================================================================
# VEX Recommendations
# =============================================================================


def build_vex_recommendations(
    df: pd.DataFrame,
    vex_override: bool = False,
) -> list[dict[str, Any]]:
    """
    Build VEX triage status recommendations based on priority bands.

    Maps priority bands to VEX statuses:
      Unreachable (any band) → NOT_AFFECTED (with full reachability factor evidence)
      CRITICAL (not unreachable) → IN_TRIAGE
      All other bands (not unreachable) → skipped (no recommendation emitted)

    If a finding already has a VEX status (current_vex_status is set),
    it is skipped unless vex_override=True.

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
            "REACHABLE"
            if reach_score > 0
            else ("UNREACHABLE" if reach_score < 0 else "INCONCLUSIVE")
        )
        vuln_funcs = row.get("vuln_functions", "")
        factors = row.get("reachability_factors", [])

        # Resolve current VEX status
        current_vex_status: str | None = None
        raw_status = row.get("status")
        if raw_status and str(raw_status) not in ("", "nan", "None"):
            current_vex_status = str(raw_status)

        # Skip findings that already have a VEX status (unless --vex-override)
        if current_vex_status and not vex_override:
            continue

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
                # Include ALL factor summaries (no cap)
                reach_detail += ". Evidence: " + "; ".join(summaries)

        # Determine VEX recommendation
        if reach_score < 0:
            # Unreachable findings (any band) → NOT_AFFECTED
            vex_status = "NOT_AFFECTED"
            reason = (
                f"Triage band={band}. {reach_detail}. "
                f"Binary analysis confirms code path is not reachable in deployed firmware."
            )
        elif band == "CRITICAL":
            # CRITICAL (not unreachable) → IN_TRIAGE
            vex_status = "IN_TRIAGE"
            reason = (
                f"Triage band=CRITICAL (score={row.get('triage_score', 0)}, "
                f"gate={row.get('gate_assignment', 'NONE')}). "
                f"{reach_detail}. "
                f"Exploit={row.get('has_exploit', False)}, "
                f"KEV={row.get('in_kev', False)}. "
                f"Requires immediate triage."
            )
        else:
            # HIGH/MEDIUM/LOW/INFO (not unreachable) → skip
            continue

        # Safely coerce values that may be NaN to their defaults
        severity_val = row.get("severity", "")
        if pd.isna(severity_val):
            severity_val = ""
        project_name_val = row.get("project_name", "")
        if pd.isna(project_name_val):
            project_name_val = ""

        recommendations.append(
            {
                "id": row.get("id", ""),  # Internal numeric PK (used for API calls)
                "finding_id": row.get("finding_id", ""),  # CVE ID (human-readable)
                "severity": str(severity_val),
                "project_name": str(project_name_val),
                "project_id": str(row.get("project_id", "")),
                "project_version_id": row.get("project_version_id", ""),
                "version_name": str(row.get("version_name", "")),
                "folder_name": row.get("folder_name", ""),
                "current_vex_status": current_vex_status,
                "priority_band": band,
                "triage_score": row.get("triage_score", 0),
                "recommended_vex_status": vex_status,
                "reason": reason,
                "reachability_score": reach_score,
                "reachability_label": reach_label,
                "vuln_functions": vuln_funcs,
                "component_name": row.get("component_name", ""),
                "component_version": row.get("component_version", ""),
            }
        )

    return recommendations


# =============================================================================
# AI Prompt Generation (--ai-prompts)
# =============================================================================


def _build_triage_prompt(
    row: pd.Series,
    nvd_snippet: str = "",
    scoring_config: dict[str, Any] | None = None,
) -> str:
    """Build an LLM prompt for triage guidance for one finding.

    This is a standalone function that does NOT require an API key.
    It produces a structured prompt users can paste into any LLM.

    Args:
        row: A pandas Series with finding data.
        nvd_snippet: Optional pre-formatted NVD fix version data
            (from NVDClient.format_for_prompt).
        scoring_config: Active scoring configuration dict.  If provided,
            the prompt describes the actual gates/weights in use.
    """
    finding_id = row.get("finding_id", "Unknown")
    severity = row.get("severity", "Unknown")
    cvss = row.get("risk", 0)
    attack_vector = row.get("attack_vector", "Unknown")
    epss = row.get("epss_percentile", 0)
    reach_score = row.get("reachability_score", 0)
    reach_label = row.get("reachability_label", "INCONCLUSIVE")
    vuln_funcs = row.get("vuln_functions", "")
    has_exploit = row.get("has_exploit", False)
    in_kev = row.get("in_kev", False)
    component = row.get("component_name", "Unknown")
    component_ver = row.get("component_version", "Unknown")
    project = row.get("project_name", "Unknown")
    band = row.get("priority_band", "Unknown")
    score = row.get("triage_score", 0)
    gate = row.get("gate_assignment", "NONE")
    cwe = row.get("cwe", "")
    first_detected = row.get("first_detected", "")

    # Current VEX / triage status (if any)
    raw_status = row.get("status")
    vex_status = (
        str(raw_status)
        if raw_status and str(raw_status) not in ("", "nan", "None")
        else None
    )

    # Build factors summary
    factors = row.get("reachability_factors", [])
    factor_lines: list[str] = []
    if isinstance(factors, list):
        for f in factors:
            if isinstance(f, dict) and f.get("summary"):
                factor_lines.append(
                    f"- {f.get('entity_type', 'unknown')}: {f['summary']}"
                )

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

    nvd_section = ""
    if nvd_snippet:
        nvd_section = f"\n{nvd_snippet}\n"

    prompt = f"""You are a security triage advisor. Provide specific triage and remediation guidance for the following vulnerability finding.
If a current VEX status is present, factor it into your recommendations — for example, findings already marked NOT_AFFECTED or RESOLVED may only need verification rather than new remediation.

## Finding: {finding_id}
- Severity: {severity} (CVSS {cvss})
- CWE: {cwe or 'N/A'}
- Attack Vector: {attack_vector}
- EPSS: {epss * 100:.1f}th percentile
- In CISA KEV: {'Yes' if in_kev else 'No'}
- Known Exploit: {'Yes' if has_exploit else 'No'}
- First Detected: {first_detected or 'Unknown'}{age_str}

## Triage Classification
- Priority Band: {band}
- Triage Score: {score}
- Gate: {gate}
- Current VEX Status: {vex_status or 'None (not yet triaged)'}

{_build_scoring_methodology(scoring_config)}

## Affected Component
{component} {component_ver} (in project: {project})

## Reachability Analysis
- Status: {reach_label} (score={reach_score})
- Vulnerable Functions: {vuln_funcs or 'None identified'}
{chr(10).join(factor_lines) if factor_lines else '- No reachability factors available'}
{nvd_section}
Respond in this exact format:
PRIORITY: <confirm or adjust the priority band with rationale>
ACTION: <specific recommended action: upgrade component, apply patch, configure mitigation, or accept risk>
RATIONALE: <1 sentence explaining why this action is recommended, citing NVD data or advisory if available>
FIX_VERSION: <specific version number. If NVD data says "FIXED in >= X", recommend X. If NVD data says a version is "STILL VULNERABLE", the fix must be AFTER that version — do NOT recommend the vulnerable version. Cross-reference the installed version ({component_ver}) against the NVD affected ranges. Only state "verify latest stable release" if no version data is available.>
WORKAROUND: <1-3 sentences: if no straightforward upgrade is available, suggest firmware-specific mitigations such as disabling affected services, network segmentation, restricting exposed interfaces, or configuration hardening. If a direct upgrade is available, state "Upgrade recommended.">
CODE_SEARCH: <grep/search patterns to find affected code in firmware — use specific vulnerable function names if known>
CONFIDENCE: <high (exact fix version confirmed via NVD data or advisory), medium (version estimated from known patterns), low (uncertain — verify independently)>"""

    return prompt


# =============================================================================
# Offline Prompt Builders (portfolio / project / component — no LLM needed)
# =============================================================================


def _format_projects_bullet(projects: list[dict[str, Any]]) -> str:
    """Format project summaries as compact bullet points instead of JSON."""
    lines = []
    for p in projects:
        name = p.get("project_name", "Unknown")
        total = p.get("total_findings", 0)
        bands = []
        for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = p.get(band, 0)
            if count:
                bands.append(f"{count} {band}")
        band_str = ", ".join(bands) if bands else "no findings"
        avg = p.get("avg_score", 0)
        lines.append(f"- **{name}** -- {total} findings ({band_str}), avg score: {avg}")
    return "\n".join(lines) if lines else "No project data available."


def _format_components_bullet(components: list[dict[str, Any]]) -> str:
    """Format component summaries as compact bullet points instead of JSON."""
    lines = []
    for c in components:
        name = c.get("component_name", c.get("component", "Unknown"))
        version = c.get("component_version", "")
        label = f"{name}:{version}" if version and ":" not in str(name) else str(name)
        total = c.get("total_findings", c.get("findings_count", 0))
        bands = []
        for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = c.get(band, 0)
            if count:
                bands.append(f"{count} {band}")
        band_str = ", ".join(bands) if bands else "no findings"
        avg = c.get("avg_score", "")
        line = f"- **{label}** -- {total} findings ({band_str})"
        if avg:
            line += f", avg score: {avg}"
        lines.append(line)
    return "\n".join(lines) if lines else "No component data available."


def _format_project_components_bullet(
    components: list[dict[str, Any]],
) -> str:
    """Format project-level component summaries as compact bullet points."""
    lines = []
    for c in components:
        comp = c.get("component", "Unknown")
        count = c.get("findings_count", 0)
        bands_list = c.get("bands", [])
        band_counts: dict[str, int] = {}
        for b in bands_list:
            band_counts[b] = band_counts.get(b, 0) + 1
        band_parts = []
        for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if band_counts.get(band, 0):
                band_parts.append(f"{band_counts[band]} {band}")
        band_str = ", ".join(band_parts) if band_parts else "no findings"
        reach_cves = c.get("reachable_cves", [])
        vuln_fns = c.get("vuln_functions", [])
        line = f"- **{comp}** -- {count} findings ({band_str})"
        if reach_cves:
            line += f", {len(reach_cves)} reachable"
        if vuln_fns:
            line += f", vuln functions: {', '.join(str(f) for f in vuln_fns)}"
        lines.append(line)
    return "\n".join(lines) if lines else "No component data available."


def _build_portfolio_prompt(
    portfolio_summary: dict[str, Any],
    project_summaries: list[dict[str, Any]],
    top_components: list[dict[str, Any]],
    reachability_summary: dict[str, Any] | None = None,
    scoring_config: dict[str, Any] | None = None,
) -> str:
    """Build a portfolio-level remediation prompt (offline, no API key needed).

    Mirrors the prompt structure in LLMClient._build_portfolio_prompt so that
    ``--ai-prompts`` produces the same prompt ``--ai`` would send.
    """
    top_projects = project_summaries[:10]
    top_comps = top_components[:10]

    reach_section = ""
    if reachability_summary:
        reach_section = f"""
## Reachability Analysis
- Reachable (confirmed exploitable code paths): {reachability_summary.get('reachable', 0)}
- Unreachable (code not reachable in deployed binaries): {reachability_summary.get('unreachable', 0)}
- Inconclusive (reachability unknown): {reachability_summary.get('unknown', 0)}
- Key vulnerable functions found: {', '.join(reachability_summary.get('top_vuln_functions', [])[:10]) or 'None identified'}

Note: "Reachable" means static/binary analysis confirmed the vulnerable function exists in and is callable from the deployed firmware. This is the strongest signal for real-world exploitability.
"""

    # Build VEX status summary
    vex_section = ""
    vex_counts = portfolio_summary.get("vex_status_counts", {})
    vex_not_triaged = portfolio_summary.get("vex_not_triaged", 0)
    if vex_counts or vex_not_triaged:
        vex_lines = ["\n## VEX / Triage Status"]
        if vex_not_triaged:
            vex_lines.append(f"- Not yet triaged: {vex_not_triaged}")
        for status, count in sorted(vex_counts.items(), key=lambda x: -x[1]):
            vex_lines.append(f"- {status}: {count}")
        vex_section = "\n".join(vex_lines) + "\n"

    return f"""You are a firmware security analyst. Analyze this vulnerability triage data and provide strategic remediation guidance.

## Portfolio Overview
- Total findings: {portfolio_summary.get('total', 0)}
- CRITICAL: {portfolio_summary.get('CRITICAL', 0)}
- HIGH: {portfolio_summary.get('HIGH', 0)}
- MEDIUM: {portfolio_summary.get('MEDIUM', 0)}
- LOW: {portfolio_summary.get('LOW', 0)}
- INFO: {portfolio_summary.get('INFO', 0)}
{vex_section}
{_build_scoring_methodology(scoring_config)}
{reach_section}
## Top Projects by Risk
{_format_projects_bullet(top_projects)}

## Top Risky Components
{_format_components_bullet(top_comps)}

Provide a concise strategic summary (3-5 paragraphs):
1. Overall risk posture assessment — highlight the reachability findings as the most urgent
2. Top 3 remediation priorities (specific components/projects), prioritizing reachable+exploitable findings
3. Quick wins (high-impact, low-effort fixes), especially where specific vulnerable functions are identified
4. Recommended remediation order

Be specific with component names and versions. When vulnerable functions are identified, mention them as they guide developers to the exact code that needs attention. Focus on actionable guidance."""


def _build_project_prompt(
    project_name: str,
    findings: list[dict[str, Any]],
    band_counts: dict[str, int],
    scoring_config: dict[str, Any] | None = None,
) -> str:
    """Build a project-level remediation prompt (offline, no API key needed).

    Mirrors the prompt structure in LLMClient._build_project_prompt.
    """
    import json as _json

    # Group findings by component for conciseness
    component_groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings[:50]:
        comp_key = (
            f"{f.get('component_name', 'Unknown')}:{f.get('component_version', '?')}"
        )
        component_groups.setdefault(comp_key, []).append(f)

    component_summary = []
    for comp_key, comp_findings in sorted(
        component_groups.items(),
        key=lambda x: max(f.get("triage_score", 0) for f in x[1]),
        reverse=True,
    )[:10]:
        reachable_cves = [
            f.get("finding_id", "")
            for f in comp_findings
            if f.get("reachability_score", 0) > 0
        ]
        unreachable_count = sum(
            1 for f in comp_findings if f.get("reachability_score", 0) < 0
        )
        vuln_funcs: set[str] = set()
        for f in comp_findings:
            vf = f.get("vuln_functions", "")
            if vf:
                vuln_funcs.update(fn.strip() for fn in vf.split(",") if fn.strip())

        component_summary.append(
            {
                "component": comp_key,
                "findings_count": len(comp_findings),
                "bands": [f.get("priority_band", "INFO") for f in comp_findings],
                "cves": [f.get("finding_id", "") for f in comp_findings[:5]],
                "reachable_cves": reachable_cves[:5],
                "unreachable_count": unreachable_count,
                "vuln_functions": list(vuln_funcs)[:5],
            }
        )

    reachable_total = sum(1 for f in findings if f.get("reachability_score", 0) > 0)
    unreachable_total = sum(1 for f in findings if f.get("reachability_score", 0) < 0)
    unknown_total = sum(1 for f in findings if f.get("reachability_score", 0) == 0)

    # VEX status distribution for this project's findings
    vex_dist: dict[str, int] = {}
    vex_not_triaged = 0
    for f in findings:
        raw = f.get("status")
        if raw and str(raw) not in ("", "nan", "None"):
            vex_dist[str(raw)] = vex_dist.get(str(raw), 0) + 1
        else:
            vex_not_triaged += 1
    vex_lines = []
    if vex_not_triaged:
        vex_lines.append(f"- Not yet triaged: {vex_not_triaged}")
    for st, cnt in sorted(vex_dist.items(), key=lambda x: -x[1]):
        vex_lines.append(f"- {st}: {cnt}")
    vex_section = (
        "\n## VEX / Triage Status\n" + "\n".join(vex_lines) + "\n" if vex_lines else ""
    )

    return f"""You are a firmware security analyst. Provide remediation guidance for project "{project_name}".

## Risk Band Distribution
{_json.dumps(band_counts, indent=2)}
{vex_section}
{_build_scoring_methodology(scoring_config)}

## Reachability Summary
- Reachable: {reachable_total} (vulnerable code confirmed present and callable in firmware)
- Unreachable: {unreachable_total} (vulnerable code not reachable — lower risk)
- Inconclusive: {unknown_total} (reachability not determined)

## Top Components by Risk
{_format_project_components_bullet(component_summary)}

Note: "reachable" indicates CVEs where binary analysis confirmed the vulnerable code path is callable. Vulnerable functions listed are specific functions identified in the deployed binaries — developers should search for and audit these.

Provide a concise project remediation plan (2-3 paragraphs):
1. Which components to upgrade first — prioritize those with reachable vulnerabilities and known exploits
2. Recommended upgrade order considering dependencies. Mention specific vulnerable functions when known.
3. Any quick wins or workarounds, especially for reachable findings where specific functions are identified

Be specific with component names and versions."""


def _build_component_prompt(
    component_name: str,
    component_version: str,
    cve_ids: list[str],
    reachability_info: list[dict[str, Any]] | None = None,
    cve_details: list[dict[str, Any]] | None = None,
    exploit_details: list[dict[str, Any]] | None = None,
    nvd_fix_snippet: str = "",
) -> str:
    """Build a component-level remediation prompt (offline, no API key needed).

    Mirrors the prompt structure in LLMClient._build_component_prompt.
    """
    cve_section = "\n".join(f"- {cve}" for cve in cve_ids[:10])

    # CVE detail section (parity with live LLMClient prompt)
    cve_detail_section = ""
    if cve_details:
        for detail in cve_details[:5]:
            desc = detail.get("description", "No description available")
            affected = detail.get("affectedFunctions", [])
            cwe = detail.get("cwe", detail.get("cwes", ""))
            if isinstance(cwe, list) and cwe:
                cwe = str(cwe[0])
            cve_detail_section += (
                f"\n### {detail.get('cveId', detail.get('finding_id', 'Unknown'))}\n"
            )
            cve_detail_section += f"Description: {str(desc)[:500]}\n"
            if cwe:
                cve_detail_section += f"CWE: {cwe}\n"
            if affected:
                cve_detail_section += (
                    f"Affected functions: {', '.join(str(f) for f in affected[:10])}\n"
                )

    # Exploit section (parity with live LLMClient prompt)
    exploit_section = ""
    if exploit_details:
        for exploit in exploit_details[:5]:
            exploit_section += f"\n- Source: {exploit.get('source', 'Unknown')}"
            exploit_section += f"\n  URL: {exploit.get('url', 'N/A')}"
            exploit_section += (
                f"\n  Description: {str(exploit.get('description', ''))[:200]}"
            )

    reach_section = ""
    if reachability_info:
        reach_items = []
        all_vuln_funcs: set[str] = set()
        for ri in reachability_info:
            score = ri.get("reachability_score", 0)
            label = (
                "REACHABLE"
                if score > 0
                else ("UNREACHABLE" if score < 0 else "INCONCLUSIVE")
            )
            cve_id = ri.get("finding_id", "Unknown")
            vuln_funcs = ri.get("vuln_functions", "")
            reach_items.append(
                f"- {cve_id}: {label} (score={score})"
                + (f", vulnerable functions: {vuln_funcs}" if vuln_funcs else "")
            )
            if vuln_funcs:
                all_vuln_funcs.update(
                    fn.strip() for fn in vuln_funcs.split(",") if fn.strip()
                )

        reach_section = "\n## Reachability Analysis (from binary analysis)\n"
        reach_section += "\n".join(reach_items[:10])
        if all_vuln_funcs:
            reach_section += (
                f"\n\nVulnerable functions confirmed in firmware binaries: "
                f"{', '.join(sorted(all_vuln_funcs)[:10])}"
            )
        reach_section += (
            "\n\nNote: REACHABLE means binary analysis confirmed these "
            "functions exist in deployed firmware and can be reached. "
            "Include these function names in CODE_SEARCH guidance."
        )

    nvd_section = ""
    if nvd_fix_snippet:
        nvd_section = f"\n{nvd_fix_snippet}\n"

    return f"""You are a security remediation advisor. Provide specific fix guidance for:

Component: {component_name} version {component_version}

CVEs:
{cve_section}

{f"## CVE Details{cve_detail_section}" if cve_detail_section else ""}

{f"## Exploit Information{exploit_section}" if exploit_section else ""}

{reach_section}
{nvd_section}
Respond in this exact format:
FIX_VERSION: <specific version number. If NVD data says "FIXED in >= X", recommend X. If NVD data says a version is "STILL VULNERABLE", the fix must be AFTER that version — do NOT recommend the vulnerable version. For well-known libraries (OpenSSL, curl, busybox, zlib, etc.), recall the specific patch version from security advisories. Only state "verify latest stable release" if no version data is available.>
RATIONALE: <1 sentence explaining why this fix or version is recommended, citing advisory source if known>
GUIDANCE: <1-2 sentence upgrade guidance>
WORKAROUND: <1-3 sentences: if no straightforward upgrade is available, suggest firmware-specific mitigations such as disabling affected services, network segmentation, restricting exposed interfaces, or configuration hardening. If a direct upgrade is available, state "Upgrade recommended.">
CODE_SEARCH: <grep/search patterns to find affected code in firmware — use specific vulnerable function names if known from reachability analysis>
CONFIDENCE: <high (exact fix version confirmed via NVD data or advisory), medium (version estimated from known patterns), low (uncertain — verify independently)>"""


def _write_triage_prompts_file(
    prompts: list[tuple[str, str, str, str]],
    config: Any,
    *,
    portfolio_prompt: str = "",
    project_prompts: dict[str, str] | None = None,
    component_prompts: dict[str, str] | None = None,
) -> str:
    """Write a markdown file with all AI prompts for copy-paste use.

    Args:
        prompts: List of (finding_id, component, band, prompt_text) tuples.
        config: Config object with output_dir.
        portfolio_prompt: Portfolio-level prompt text (optional).
        project_prompts: Dict of project_name -> prompt text (optional).
        component_prompts: Dict of component_key -> prompt text (optional).

    Returns:
        Path to the written prompts file.
    """
    from datetime import datetime

    output_dir = Path(getattr(config, "output_dir", "./output"))
    recipe_dir = output_dir / "Triage Prioritization"
    recipe_dir.mkdir(parents=True, exist_ok=True)

    prompts_path = recipe_dir / "Triage Prioritization_prompts.md"
    lines: list[str] = [
        "# Triage Prioritization - AI Prompts\n",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n",
        "\nPaste each prompt into your preferred LLM for remediation guidance.\n",
    ]

    # Portfolio prompt
    if portfolio_prompt:
        lines.append("\n---\n\n# Portfolio Remediation\n\n")
        lines.append(f"```\n{portfolio_prompt}\n```\n")

    # Project prompts
    if project_prompts:
        lines.append("\n---\n\n# Project Remediation\n")
        for pname, prompt_text in project_prompts.items():
            lines.append(f"\n## {pname}\n\n")
            lines.append(f"```\n{prompt_text}\n```\n")

    # Component prompts
    if component_prompts:
        lines.append("\n---\n\n# Component Remediation\n")
        for comp_key, prompt_text in component_prompts.items():
            lines.append(f"\n## {comp_key}\n\n")
            lines.append(f"```\n{prompt_text}\n```\n")

    # Per-finding prompts
    if prompts:
        lines.append("\n---\n\n# Finding Triage\n")
        for finding_id, component, band, prompt_text in prompts:
            label = f"{finding_id}"
            if component:
                label += f" ({component})"
            label += f" [{band}]"
            lines.append(f"\n## {label}\n\n")
            lines.append(f"```\n{prompt_text}\n```\n")

    prompts_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"AI triage prompts written to {prompts_path}")
    return str(prompts_path)


# =============================================================================
# AI Remediation Guidance
# =============================================================================


def _get_ai_config(
    config: Any, additional_data: dict[str, Any] | None
) -> dict[str, Any]:
    """Extract AI configuration from config/additional_data."""
    # AI remediation data is stable (CVE fix versions don't change often).
    # Always cache AI results for at least 7 days regardless of --cache-ttl,
    # which controls API data freshness, not LLM call caching.
    _AI_MIN_CACHE_TTL = 7 * 24 * 3600  # 7 days in seconds

    result: dict[str, Any] = {
        "enabled": False,
        "depth": "summary",
        "cache_dir": None,
        "cache_ttl": 0,
        "provider": None,
        "nvd_api_key": None,
    }

    # Try config object first
    if config and hasattr(config, "ai"):
        result["enabled"] = bool(config.ai)
        result["depth"] = getattr(config, "ai_depth", "summary")
        result["cache_dir"] = getattr(config, "cache_dir", None)
        result["cache_ttl"] = getattr(config, "cache_ttl", 0) or 0
        result["provider"] = getattr(config, "ai_provider", None)
        result["nvd_api_key"] = getattr(config, "nvd_api_key", None)
    # Fall back to additional_data['config']
    elif additional_data and "config" in additional_data:
        cfg = additional_data["config"]
        if hasattr(cfg, "ai"):
            result["enabled"] = bool(cfg.ai)
            result["depth"] = getattr(cfg, "ai_depth", "summary")
            result["cache_dir"] = getattr(cfg, "cache_dir", None)
            result["cache_ttl"] = getattr(cfg, "cache_ttl", 0) or 0
            result["provider"] = getattr(cfg, "ai_provider", None)
            result["nvd_api_key"] = getattr(cfg, "nvd_api_key", None)

    # Enforce minimum cache TTL for AI calls — these are expensive and stable
    if result["enabled"]:
        result["cache_ttl"] = max(result["cache_ttl"], _AI_MIN_CACHE_TTL)

    return result


def _generate_ai_guidance(
    df: pd.DataFrame,
    portfolio_summary: dict[str, Any],
    project_summary_df: pd.DataFrame,
    top_components: pd.DataFrame,
    ai_depth: str = "summary",
    cache_dir: str | None = None,
    cache_ttl: int = 0,
    provider: str | None = None,
    nvd_api_key: str | None = None,
    scoring_config: dict[str, Any] | None = None,
) -> tuple[str, dict[str, str], dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    """
    Generate AI remediation guidance at all requested scopes.

    Args:
        cache_ttl: Cache TTL in seconds. 0 = no AI caching (regenerate every run).
        provider: LLM provider override ("anthropic", "openai", "copilot").
        nvd_api_key: Optional NVD API key for faster fix-version lookups.
        scoring_config: Active scoring configuration for dynamic prompt generation.

    Returns:
        Tuple of (portfolio_summary_text, project_summaries_dict,
                  component_guidance_dict, finding_guidance_dict)
    """
    try:
        from fs_report.llm_client import LLMClient
    except ImportError:
        logger.warning("LLM package not available; skipping AI guidance")
        return "", {}, {}, {}

    try:
        llm = LLMClient(cache_dir=cache_dir, cache_ttl=cache_ttl, provider=provider)
    except (ValueError, ImportError) as e:
        logger.warning(f"LLM client init failed: {e}")
        return "", {}, {}, {}

    # --- Initialise NVD client for fix-version enrichment ---
    nvd = None
    try:
        from fs_report.nvd_client import NVD_ATTRIBUTION, NVDClient

        nvd = NVDClient(
            api_key=nvd_api_key,
            cache_dir=cache_dir,
            cache_ttl=max(cache_ttl, 86400),  # NVD data is stable; cache ≥ 24 h
        )
        # NVD Terms of Use: log required attribution notice
        logger.info(NVD_ATTRIBUTION)
        if nvd._api_key:  # noqa: SLF001
            logger.info("NVD client initialised with API key (50 req/30s)")
        else:
            logger.info(
                "NVD client initialised without API key (5 req/30s). "
                "Set NVD_API_KEY or use --nvd-api-key for 10x throughput."
            )
    except Exception as e:
        logger.info(f"NVD client unavailable (fix-version enrichment disabled): {e}")

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
                all_funcs[all_funcs != ""].value_counts().head(10).index.tolist()
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
        project_summaries_list: list[dict[str, Any]] = (
            project_summary_df.to_dict("records")  # type: ignore[assignment]
            if not project_summary_df.empty
            else []
        )
        top_components_list: list[dict[str, Any]] = (
            top_components.to_dict("records") if not top_components.empty else []  # type: ignore[assignment]
        )
        ai_portfolio = llm.generate_portfolio_summary(
            portfolio_summary,
            project_summaries_list,
            top_components_list,
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
                "finding_id",
                "reachability_score",
                "reachability_label",
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
                        ri["reachability_label"] = row.get(
                            "reachability_label", "INCONCLUSIVE"
                        )
                        ri["vuln_functions"] = row.get("vuln_functions", "")
                        if "reachability_factors" in row.index:
                            ri["factors"] = row.get("reachability_factors", [])
                        reachability_map[fid] = ri

            # --- Pre-fetch NVD fix data for all component CVEs ---
            nvd_snippets_map: dict[str, str] = {}
            if nvd:
                all_cve_ids: list[str] = []
                for comp in components_list:
                    all_cve_ids.extend(comp.get("cve_ids", []))
                unique_cves = list(dict.fromkeys(all_cve_ids))  # dedupe, keep order
                if unique_cves:
                    logger.info(f"Fetching NVD fix data for {len(unique_cves)} CVEs...")
                    nvd.get_batch(unique_cves, progress=True)
                    # Build per-component NVD snippets
                    for comp in components_list:
                        comp_key = (
                            f"{comp['component_name']}:{comp['component_version']}"
                        )
                        snippet = nvd.format_batch_for_prompt(comp.get("cve_ids", []))
                        if snippet:
                            nvd_snippets_map[comp_key] = snippet

            ai_components = llm.generate_batch_component_guidance(
                components_list,
                reachability_map=reachability_map if reachability_map else None,
                nvd_snippets_map=nvd_snippets_map if nvd_snippets_map else None,
            )

    # --- Finding-level triage guidance (full depth only) ---
    ai_findings: dict[str, dict[str, str]] = {}
    if ai_depth == "full":
        critical_high = df[df["priority_band"].isin(["CRITICAL", "HIGH"])]
        if not critical_high.empty:
            # Limit to top 50 findings by triage score to control cost
            top_findings = critical_high.nlargest(50, "triage_score")
            logger.info(
                f"Generating AI finding guidance for {len(top_findings)} "
                f"CRITICAL/HIGH findings..."
            )

            # Pre-fetch NVD data for finding CVEs (many will already be cached
            # from the component pass above)
            nvd_finding_snippets: dict[str, str] = {}
            if nvd:
                finding_cve_ids = [
                    fid
                    for fid in top_findings["finding_id"].dropna().unique()
                    if fid.startswith("CVE-")
                ]
                if finding_cve_ids:
                    nvd.get_batch(list(finding_cve_ids), progress=True)
                    for fid in finding_cve_ids:
                        snippet = nvd.format_for_prompt(fid)
                        if snippet:
                            nvd_finding_snippets[fid] = snippet

            finding_prompts: list[tuple[str, str]] = []
            for _, row in top_findings.iterrows():
                fid = row.get("finding_id", "")
                if fid:
                    nvd_snippet = nvd_finding_snippets.get(fid, "")
                    prompt = _build_triage_prompt(
                        row, nvd_snippet=nvd_snippet, scoring_config=scoring_config
                    )
                    finding_prompts.append((fid, prompt))

            ai_findings = llm.generate_batch_finding_guidance(finding_prompts)

    stats = llm.get_stats()
    nvd_info = ""
    if nvd:
        nvd_stats = nvd.get_stats()
        nvd_info = (
            f", {nvd_stats['nvd_api_requests']} NVD requests"
            f" ({nvd_stats['nvd_cache_size']} cached)"
        )
    logger.info(
        f"AI guidance complete: {stats['api_calls']} API calls, "
        f"{stats['cache_hits']} cache hits{nvd_info}"
    )

    return ai_portfolio, ai_projects, ai_components, ai_findings


# =============================================================================
# Helpers
# =============================================================================


def _empty_result() -> dict[str, Any]:
    """Return an empty result structure."""
    return {
        "findings_df": pd.DataFrame(),
        "project_summary_df": pd.DataFrame(),
        "portfolio_summary": dict.fromkeys(BAND_ORDER, 0),
        "cvss_band_matrix": {"rows": SEVERITY_ORDER, "cols": BAND_ORDER, "data": []},
        "gate_funnel": {
            "gate_1_critical": 0,
            "gate_2_high": 0,
            "additive_high": 0,
            "additive_medium": 0,
            "additive_low": 0,
            "additive_info": 0,
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
        "ai_finding_guidance": {},
        "ai_triage_prompts": [],
        "ai_portfolio_prompt": "",
        "ai_project_prompts": {},
        "ai_component_prompts": {},
        "ai_finding_prompts": {},
        "scoring_config": _build_scoring_config(DEFAULT_GATES, DEFAULT_WEIGHTS),
    }
