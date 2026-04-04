"""Configuration Analysis Triage transform.

Triages CREDENTIALS, CONFIG_ISSUES, and CRYPTO_MATERIAL findings using a
tiered-gates scoring model with gates tuned for config/secrets severity.
"""

from __future__ import annotations

import copy
import logging
import re
from pathlib import Path
from typing import Any

import pandas as pd

from fs_report.transforms.pandas.triage_prioritization import (
    VEX_RESOLVED_STATUSES,
    _evaluate_condition,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Description parser
# ---------------------------------------------------------------------------

_FINDING_DETAILS_MARKER = "## Finding Details"

_DETAIL_PATTERN = re.compile(
    r"###\s+(\w+)\s*\n\s*```(.*?)```",
    re.DOTALL,
)


def _coerce_value(raw: str) -> Any:
    """Coerce a raw string value to the most specific Python scalar type.

    Precedence: bool → int → float → str.
    """
    stripped = raw.strip()
    if stripped == "True":
        return True
    if stripped == "False":
        return False
    # Try int before float so "42" → int, not float.
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        pass
    return stripped


def parse_finding_details(description: str | None) -> dict[str, Any]:
    """Parse structured fields from a Finite State finding description.

    The API returns a markdown ``description`` field (when
    ``includeAdditionalDetails=true``) whose ``## Finding Details`` section
    contains ``### field_name`` headers each followed by a code-fenced value.

    Parameters
    ----------
    description:
        Raw markdown string from the API, or ``None``.

    Returns
    -------
    dict
        Mapping of field name → typed Python value.  Returns ``{}`` when
        *description* is ``None``, empty, or has no ``## Finding Details``
        section.
    """
    if not description:
        return {}

    marker_idx = description.find(_FINDING_DETAILS_MARKER)
    if marker_idx == -1:
        return {}

    details_section = description[marker_idx + len(_FINDING_DETAILS_MARKER) :]

    result: dict[str, Any] = {}
    for match in _DETAIL_PATTERN.finditer(details_section):
        field_name = match.group(1)
        raw_value = match.group(2)
        result[field_name] = _coerce_value(raw_value)

    return result


def extract_detail_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Expand the ``description`` column into typed ``detail_*`` columns.

    Each row's ``description`` string is parsed via :func:`parse_finding_details`.
    The resulting keys are promoted to new columns prefixed with ``detail_``.
    Rows that lack a particular key receive ``NaN``.  The raw ``description``
    column is dropped.

    Parameters
    ----------
    df:
        Input DataFrame.  Must contain a ``description`` column; if not
        present the DataFrame is returned unchanged.

    Returns
    -------
    pd.DataFrame
        DataFrame with ``detail_*`` columns added and ``description`` removed.
    """
    if df.empty or "description" not in df.columns:
        return df

    parsed = df["description"].apply(parse_finding_details)
    detail_df = pd.DataFrame(parsed.tolist(), index=df.index)
    detail_df.columns = [f"detail_{col}" for col in detail_df.columns]

    result = pd.concat([df.drop(columns=["description"]), detail_df], axis=1)
    return result


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BAND_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
BAND_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
    "INFO": "#6c757d",
}

DEFAULT_GATES: list[dict[str, Any]] = [
    {
        "name": "GATE_1",
        "band": "CRITICAL",
        "score": 100,
        "conditions": {
            "all": [
                {"field": "category", "op": "==", "value": "CRYPTO_MATERIAL"},
                {"field": "detail_private_key", "op": "==", "value": True},
            ]
        },
    },
    {
        "name": "GATE_2",
        "band": "HIGH",
        "score": 85,
        "conditions": {
            "all": [
                {"field": "category", "op": "==", "value": "CREDENTIALS"},
                {"field": "severity", "op": "in", "value": ["critical", "high"]},
            ]
        },
    },
    {
        "name": "GATE_3",
        "band": "MEDIUM",
        "score": 70,
        "conditions": {
            "all": [
                {"field": "category", "op": "==", "value": "CONFIG_ISSUES"},
                {"field": "severity", "op": "in", "value": ["critical", "high"]},
            ]
        },
    },
]

POINTS_VEX_RESOLVED = -50
RISK_MAX_POINTS = 10
BAND_HIGH_THRESHOLD = 70
BAND_MEDIUM_THRESHOLD = 40
BAND_LOW_THRESHOLD = 25

DEFAULT_WEIGHTS: dict[str, int | float] = {
    "severity_critical": 30,
    "severity_high": 20,
    "severity_medium": 10,
    "severity_low": 5,
    "risk_max": 10,
    "vex_resolved": -50,
    "band_high_threshold": 70,
    "band_medium_threshold": 40,
    "band_low_threshold": 25,
}


# ---------------------------------------------------------------------------
# Loader helpers
# ---------------------------------------------------------------------------


def _load_weights(
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, int | float]:
    """Load scoring weights with priority: --scoring-file > recipe parameters > defaults."""
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
    """Load gate definitions with priority: --scoring-file > recipe parameters > defaults."""
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


# ---------------------------------------------------------------------------
# Gate evaluation
# ---------------------------------------------------------------------------


def apply_config_gates(
    df: pd.DataFrame,
    gates: list[dict[str, Any]] | None = None,
    vex_override: bool = False,
) -> pd.DataFrame:
    """Assign gate labels to each row based on ordered gate definitions.

    Parameters
    ----------
    df:
        Input DataFrame with finding columns.
    gates:
        List of gate definitions (defaults to DEFAULT_GATES).
    vex_override:
        When True, resolved VEX findings are still eligible for gate assignment.

    Returns
    -------
    pd.DataFrame
        Copy of *df* with a ``gate_assignment`` column added.
    """
    if gates is None:
        gates = copy.deepcopy(DEFAULT_GATES)

    result = df.copy()
    result["gate_assignment"] = "NONE"

    # Track which rows have already been assigned a gate (first match wins)
    unassigned = pd.Series(True, index=result.index)

    # Exclude resolved VEX findings unless override is set
    if not vex_override and "status" in result.columns:
        resolved_mask = result["status"].astype(str).isin(VEX_RESOLVED_STATUSES)
        unassigned = unassigned & ~resolved_mask

    for gate in gates:
        gate_name = gate.get("name", "UNKNOWN")
        conditions = gate.get("conditions", {})

        if not conditions:
            continue

        match_mask = _evaluate_condition(result, conditions)
        assign_mask = unassigned & match_mask

        result.loc[assign_mask, "gate_assignment"] = gate_name
        # Remove newly assigned rows from the unassigned pool
        unassigned = unassigned & ~assign_mask

    return result


# ---------------------------------------------------------------------------
# Additive scoring
# ---------------------------------------------------------------------------


def calculate_config_score(
    df: pd.DataFrame,
    weights: dict[str, int | float] | None = None,
    gates: list[dict[str, Any]] | None = None,
) -> pd.DataFrame:
    """Compute a triage score for each finding and add a ``triage_score`` column.

    Score components:
    - Severity points: critical=30, high=20, medium=10, low=5, else=0
    - Risk points: (risk / 100.0) * risk_max  (converts 0-100 API risk to 0-10 pts)
    - Gate bonus: the gate's ``score`` field value
    - VEX resolved penalty: -50 for resolved/not-affected/resolved-with-pedigree

    Parameters
    ----------
    df:
        Input DataFrame; must have ``severity``, ``risk``, ``gate_assignment``,
        and optionally ``status`` columns.
    weights:
        Override scoring weights (defaults to DEFAULT_WEIGHTS).
    gates:
        Gate definitions used to look up gate bonus scores (defaults to DEFAULT_GATES).

    Returns
    -------
    pd.DataFrame
        Copy of *df* with ``triage_score`` column added.
    """
    if weights is None:
        weights = dict(DEFAULT_WEIGHTS)
    if gates is None:
        gates = copy.deepcopy(DEFAULT_GATES)

    result = df.copy()

    # Build a gate-name → bonus-score lookup
    gate_bonus_map: dict[str, float] = {
        gate["name"]: float(gate.get("score", 0)) for gate in gates
    }

    # Severity points
    sev_map = {
        "critical": float(weights.get("severity_critical", 30)),
        "high": float(weights.get("severity_high", 20)),
        "medium": float(weights.get("severity_medium", 10)),
        "low": float(weights.get("severity_low", 5)),
    }
    severity_pts = result["severity"].map(sev_map).fillna(0.0)

    # Risk points: API risk is 0-100, convert to 0-10 CVSS, then scale by risk_max
    risk_max = float(weights.get("risk_max", RISK_MAX_POINTS))
    risk_col = (
        result["risk"].astype(float)
        if "risk" in result.columns
        else pd.Series(0.0, index=result.index)
    )
    risk_pts = (risk_col / 100.0) * risk_max

    # Gate bonus
    gate_col = (
        result["gate_assignment"]
        if "gate_assignment" in result.columns
        else pd.Series("NONE", index=result.index)
    )
    gate_pts = gate_col.map(gate_bonus_map).fillna(0.0)

    # VEX resolved penalty
    vex_penalty_val = float(weights.get("vex_resolved", POINTS_VEX_RESOLVED))
    if "status" in result.columns:
        resolved_mask = result["status"].astype(str).isin(VEX_RESOLVED_STATUSES)
        vex_pts = resolved_mask.astype(float) * vex_penalty_val
    else:
        vex_pts = pd.Series(0.0, index=result.index)

    result["triage_score"] = (severity_pts + risk_pts + gate_pts + vex_pts).round(1)

    return result


# ---------------------------------------------------------------------------
# Band assignment
# ---------------------------------------------------------------------------


def assign_config_bands(
    df: pd.DataFrame,
    weights: dict[str, int | float] | None = None,
    gates: list[dict[str, Any]] | None = None,
) -> pd.DataFrame:
    """Assign a risk band to each finding based on gate assignment or triage score.

    Gate-matched findings inherit their gate's band.  Non-gated findings are
    classified by score thresholds:
    - score >= band_high_threshold  → HIGH
    - score >= band_medium_threshold → MEDIUM
    - score >= band_low_threshold   → LOW
    - else                          → INFO

    Parameters
    ----------
    df:
        Input DataFrame; must have ``gate_assignment`` and ``triage_score`` columns.
    weights:
        Override scoring thresholds (defaults to DEFAULT_WEIGHTS).
    gates:
        Gate definitions used to look up gate bands (defaults to DEFAULT_GATES).

    Returns
    -------
    pd.DataFrame
        Copy of *df* with ``band`` column added.
    """
    if weights is None:
        weights = dict(DEFAULT_WEIGHTS)
    if gates is None:
        gates = copy.deepcopy(DEFAULT_GATES)

    result = df.copy()

    # Build gate-name → band lookup
    gate_band_map: dict[str, str] = {
        gate["name"]: gate.get("band", "INFO") for gate in gates
    }

    high_thresh = float(weights.get("band_high_threshold", BAND_HIGH_THRESHOLD))
    medium_thresh = float(weights.get("band_medium_threshold", BAND_MEDIUM_THRESHOLD))
    low_thresh = float(weights.get("band_low_threshold", BAND_LOW_THRESHOLD))

    def _assign_band(row: Any) -> str:
        gate = row["gate_assignment"] if "gate_assignment" in result.columns else "NONE"
        if gate != "NONE" and gate in gate_band_map:
            return gate_band_map[gate]
        score = row["triage_score"] if "triage_score" in result.columns else 0.0
        if score >= high_thresh:
            return "HIGH"
        if score >= medium_thresh:
            return "MEDIUM"
        if score >= low_thresh:
            return "LOW"
        return "INFO"

    result["band"] = result.apply(_assign_band, axis=1)

    return result


# ---------------------------------------------------------------------------
# VEX recommendation generation
# ---------------------------------------------------------------------------


def generate_vex_recommendations(
    df: pd.DataFrame,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Generate VEX triage recommendations for un-triaged config findings.

    Parameters
    ----------
    df:
        DataFrame with finding columns including ``status``, ``triage_score``,
        ``band``, ``gate_assignment``, ``category``, and ``detail_private_key``.
    limit:
        If provided, truncate the result list to this many recommendations.

    Returns
    -------
    list[dict[str, Any]]
        Each dict contains: finding_id, finding_common_id, category, severity,
        triage_score, priority_band, gate, recommended_status, reason.
    """
    if df is None or df.empty:
        return []

    # Exclude already-triaged findings (non-null, non-empty status)
    if "status" in df.columns:
        mask = (
            df["status"].isna()
            | (df["status"].astype(str).str.strip() == "")
            | (df["status"].astype(str) == "None")
        )
        candidates = df[mask].copy()
    else:
        candidates = df.copy()

    if candidates.empty:
        return []

    # Sort by triage_score descending
    if "triage_score" in candidates.columns:
        candidates = candidates.sort_values("triage_score", ascending=False)

    recommendations: list[dict[str, Any]] = []

    for _, row in candidates.iterrows():
        gate = row.get("gate_assignment", "NONE")
        category = row.get("category", "")
        band = row.get("band", "INFO")
        detail_private_key = row.get("detail_private_key")

        # Only recommend when we have high confidence in the action:
        # - Gate 1 (private keys) → IN_TRIAGE (needs human review)
        # - Public keys/certs → NOT_AFFECTED (clear signal from detail_private_key)
        # - Everything else → no recommendation (just scored and displayed)
        if gate == "GATE_1":
            recommended_status = "IN_TRIAGE"
            reason = "Private key detected: requires human review"
        elif category == "CRYPTO_MATERIAL" and detail_private_key is not True:
            recommended_status = "NOT_AFFECTED"
            reason = "Public key or certificate — not a security risk"
        else:
            continue  # No recommendation for other findings

        rec: dict[str, Any] = {
            "id": row.get("id", ""),  # Internal numeric PK (for API calls)
            "finding_id": row.get("findingId", ""),  # Human-readable ID
            "project_version_id": row.get("version_id", ""),
            "project_name": str(row.get("project_name", "")),
            "project_id": str(row.get("project_id", "")),
            "category": category,
            "severity": row.get("severity"),
            "triage_score": row.get("triage_score"),
            "priority_band": band,
            "gate": gate,
            "recommended_vex_status": recommended_status,
            "reason": reason,
        }
        recommendations.append(rec)

    if limit is not None:
        recommendations = recommendations[:limit]

    return recommendations


# ---------------------------------------------------------------------------
# Category inference
# ---------------------------------------------------------------------------

# Detail columns whose presence signals CRYPTO_MATERIAL
_CRYPTO_SIGNALS = frozenset(
    {"detail_material_type", "detail_private_key", "detail_key_size"}
)
# Detail columns whose presence signals CREDENTIALS
_CRED_SIGNALS = frozenset(
    {"detail_password_hash", "detail_user_name", "detail_credential_type"}
)


def _infer_category(df: pd.DataFrame) -> pd.DataFrame:
    """Infer ``category`` from parsed detail columns when the API returns null.

    The Finite State API's RSQL ``category`` filter works server-side, but the
    response payload does not include a populated ``category`` field.  This
    function fills missing categories by checking which ``detail_*`` columns
    are present and non-null:

    - ``detail_material_type`` / ``detail_private_key`` → CRYPTO_MATERIAL
    - ``detail_password_hash`` / ``detail_user_name`` → CREDENTIALS
    - Otherwise → CONFIG_ISSUES
    """
    if df.empty:
        return df

    df = df.copy()

    # If category is already reliably populated, skip inference
    if "category" in df.columns:
        non_null = df["category"].notna() & (df["category"].astype(str) != "None")
        if non_null.all():
            return df
    else:
        df["category"] = None
        non_null = pd.Series(False, index=df.index)

    needs_inference = ~non_null
    if not needs_inference.any():
        return df

    crypto_cols = [c for c in _CRYPTO_SIGNALS if c in df.columns]
    cred_cols = [c for c in _CRED_SIGNALS if c in df.columns]

    for idx in df.index[needs_inference]:
        if any(pd.notna(df.at[idx, c]) for c in crypto_cols):
            df.at[idx, "category"] = "CRYPTO_MATERIAL"
        elif any(pd.notna(df.at[idx, c]) for c in cred_cols):
            df.at[idx, "category"] = "CREDENTIALS"
        else:
            df.at[idx, "category"] = "CONFIG_ISSUES"

    return df


# ---------------------------------------------------------------------------
# Column normalization
# ---------------------------------------------------------------------------


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Flatten nested API dicts into scalar columns.

    Handles:
    - ``component`` dict → ``component_name``, ``component_version``, ``component_id``
    - ``project`` dict → ``project_name``, ``project_id``
    - ``projectVersion`` dict → ``version_id``, ``version_name``
    - ``category`` → uppercase
    - ``severity`` → lowercase
    - ``risk`` → numeric (0–100)
    """
    result = df.copy()

    # Flatten component dict
    if "component" in result.columns:
        result["component_name"] = result["component"].apply(
            lambda v: v.get("name") if isinstance(v, dict) else None
        )
        result["component_version"] = result["component"].apply(
            lambda v: v.get("version") if isinstance(v, dict) else None
        )
        result["component_id"] = result["component"].apply(
            lambda v: v.get("id") if isinstance(v, dict) else None
        )
        result = result.drop(columns=["component"])

    # Flatten project dict
    if "project" in result.columns:
        result["project_name"] = result["project"].apply(
            lambda v: v.get("name") if isinstance(v, dict) else None
        )
        result["project_id"] = result["project"].apply(
            lambda v: v.get("id") if isinstance(v, dict) else None
        )
        result = result.drop(columns=["project"])

    # Flatten projectVersion dict
    if "projectVersion" in result.columns:
        result["version_id"] = result["projectVersion"].apply(
            lambda v: v.get("id") if isinstance(v, dict) else None
        )
        result["version_name"] = result["projectVersion"].apply(
            lambda v: v.get("version") if isinstance(v, dict) else None
        )
        result = result.drop(columns=["projectVersion"])

    # Infer category from parsed detail columns when the API returns null.
    # The API's RSQL category filter works server-side but the response
    # payload does not include a populated ``category`` field.
    result = _infer_category(result)

    # Normalize category and severity
    if "category" in result.columns:
        result["category"] = result["category"].astype(str).str.upper()
    if "severity" in result.columns:
        result["severity"] = result["severity"].astype(str).str.lower()

    # Normalize risk to numeric
    if "risk" in result.columns:
        result["risk"] = pd.to_numeric(result["risk"], errors="coerce").fillna(0)

    return result


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def _build_project_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Group findings by project_name × priority_band, count, add total.

    Returns an empty DataFrame if *df* is empty or lacks required columns.
    """
    if (
        df.empty
        or "project_name" not in df.columns
        or "priority_band" not in df.columns
    ):
        return pd.DataFrame()

    grouped = df.groupby(["project_name", "priority_band"]).size().unstack(fill_value=0)

    # Ensure all band columns present in BAND_ORDER
    for band in BAND_ORDER:
        if band not in grouped.columns:
            grouped[band] = 0

    grouped = grouped[BAND_ORDER]
    grouped["total"] = grouped.sum(axis=1)
    grouped = grouped.sort_values("total", ascending=False)
    grouped = grouped.reset_index()

    return grouped


def _build_portfolio_summary(df: pd.DataFrame) -> dict[str, int]:
    """Count findings per band at portfolio level.

    Returns a dict with BAND_ORDER keys plus ``"total"``.
    """
    counts: dict[str, int] = dict.fromkeys(BAND_ORDER, 0)
    if not df.empty and "priority_band" in df.columns:
        for band, count in df["priority_band"].value_counts().items():
            band_str = str(band)
            if band_str in counts:
                counts[band_str] = int(count)
    counts["total"] = sum(counts[b] for b in BAND_ORDER)
    return counts


def _build_gate_funnel(df: pd.DataFrame) -> dict[str, int]:
    """Count findings per gate_assignment, including a ``"total"`` key."""
    funnel: dict[str, int] = {}
    if not df.empty and "gate_assignment" in df.columns:
        for gate, count in df["gate_assignment"].value_counts().items():
            funnel[str(gate)] = int(count)
    funnel["total"] = int(df.shape[0]) if not df.empty else 0
    return funnel


# ---------------------------------------------------------------------------
# Empty result sentinel
# ---------------------------------------------------------------------------


def _empty_result() -> dict[str, Any]:
    """Return a result dict with all expected keys, populated with empty values."""
    return {
        "findings_df": pd.DataFrame(),
        "project_summary_df": pd.DataFrame(),
        "portfolio_summary": {**dict.fromkeys(BAND_ORDER, 0), "total": 0},
        "gate_funnel": {"total": 0},
        "vex_recommendations": [],
        "band_colors": BAND_COLORS,
        "scoring_config": {"gates": [], "weights": {}},
    }


# ---------------------------------------------------------------------------
# Main transform entry point
# ---------------------------------------------------------------------------


def configuration_analysis_triage_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Any = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Main transform entry point for Configuration Analysis Triage.

    Parameters
    ----------
    data:
        List of finding dicts or a DataFrame.
    config:
        CLI config object (may have ``scoring_file``, ``top`` attributes).
    additional_data:
        Extra context dict; may contain ``"config"`` (CLI config) or
        ``"recipe_parameters"`` (YAML-level weight/gate overrides).

    Returns
    -------
    dict
        Keys: findings_df, project_summary_df, portfolio_summary, gate_funnel,
        vex_recommendations, band_colors, scoring_config.
    """
    # Step 1: convert to DataFrame
    if isinstance(data, pd.DataFrame):
        df = data.copy()
    else:
        df = pd.DataFrame(data) if data else pd.DataFrame()

    # Step 2: early return on empty
    if df.empty:
        return _empty_result()

    # Step 3: resolve config
    cfg = config
    if cfg is None and additional_data:
        cfg = additional_data.get("config")

    # Step 4: load weights and gates
    weights = _load_weights(config=cfg, additional_data=additional_data)
    gates = _load_gates(config=cfg, additional_data=additional_data)

    # Step 5: parse description into detail_* columns, drop raw text
    df = extract_detail_columns(df)

    # Step 6: flatten nested API dicts
    df = _normalize_columns(df)

    # Step 7: gate assignment
    vex_override = False
    df = apply_config_gates(df, gates=gates, vex_override=vex_override)

    # Step 8: scoring
    df = calculate_config_score(df, weights=weights, gates=gates)

    # Step 9: band assignment (adds "band" column)
    df = assign_config_bands(df, weights=weights, gates=gates)

    # Step 10: resolve --triage (VEX limit) and --top (display limit) independently
    vex_limit: int | None = None
    display_limit: int | None = None
    if cfg:
        _triage_val = getattr(cfg, "triage", None)
        if _triage_val:
            try:
                _tv = int(_triage_val)
                if _tv > 0:
                    vex_limit = _tv
            except (TypeError, ValueError):
                pass
        _top_val = getattr(cfg, "top", None)
        if _top_val:
            try:
                _dv = int(_top_val)
                if _dv > 0:
                    display_limit = _dv
            except (TypeError, ValueError):
                pass

    # Generate VEX recs BEFORE renaming band → priority_band
    vex_recs = generate_vex_recommendations(df, limit=vex_limit)

    # Rename band → priority_band for consistency with rest of codebase
    df = df.rename(columns={"band": "priority_band"})

    # Step 11: sort by triage_score descending
    if "triage_score" in df.columns:
        df = df.sort_values("triage_score", ascending=False).reset_index(drop=True)

    # Step 12: build summaries
    project_summary = _build_project_summary(df)
    portfolio_summary = _build_portfolio_summary(df)
    gate_funnel = _build_gate_funnel(df)

    # Step 13: apply --top display limit
    display_df = df
    if display_limit is not None:
        display_df = df.head(display_limit)

    return {
        "findings_df": display_df,
        "project_summary_df": project_summary,
        "portfolio_summary": portfolio_summary,
        "gate_funnel": gate_funnel,
        "vex_recommendations": vex_recs,
        "band_colors": BAND_COLORS,
        "scoring_config": {"gates": gates, "weights": weights},
    }
