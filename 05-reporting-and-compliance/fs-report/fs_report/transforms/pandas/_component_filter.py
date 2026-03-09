"""Shared component filtering utility for all recipe transforms."""

import logging

import pandas as pd

logger = logging.getLogger(__name__)


def apply_component_filter(
    df: pd.DataFrame,
    component_filter: str,
    match_mode: str = "contains",
    name_col: str = "component_name",
    version_col: str = "component_version",
) -> pd.DataFrame:
    """Filter a DataFrame to rows matching the component filter.

    Args:
        df: DataFrame with component columns.
        component_filter: Comma-separated specs. ``name@version`` always uses
            exact match on both name and version.  Plain ``name`` uses
            *match_mode* (``"exact"`` or ``"contains"``).
        match_mode: ``"exact"`` for ``==`` matching, ``"contains"`` for
            case-insensitive substring matching (default).
        name_col: Column name for component name.
        version_col: Column name for component version.

    Returns:
        Filtered copy of the DataFrame.  If *component_filter* is empty
        or the required columns are missing, returns the original DataFrame
        unchanged.
    """
    if match_mode not in ("exact", "contains"):
        logger.warning(
            "Unknown component match mode '%s' — falling back to 'contains'",
            match_mode,
        )
        match_mode = "contains"

    specs = [s.strip() for s in component_filter.split(",") if s.strip()]
    if not specs:
        return df

    # Bail out gracefully if the expected columns aren't present
    if name_col not in df.columns:
        logger.warning(
            "Component filter requested but column '%s' not found — skipping filter",
            name_col,
        )
        return df

    # Detect purl column (various naming conventions)
    purl_col: str | None = None
    for candidate in ("purl", "component.purl", "component_purl"):
        if candidate in df.columns:
            purl_col = candidate
            break

    masks = []
    for spec in specs:
        if "@" in spec:
            # name@version → always exact match on both
            name, version = spec.rsplit("@", 1)
            if version_col not in df.columns:
                logger.warning(
                    "Component filter has version spec '%s' but column '%s' not found "
                    "— matching name only",
                    spec,
                    version_col,
                )
                mask = df[name_col] == name
            else:
                mask = (df[name_col] == name) & (df[version_col] == version)
        elif match_mode == "exact":
            mask = df[name_col] == spec
        else:
            # contains (default) — case-insensitive substring
            mask = (
                df[name_col]
                .astype(str)
                .str.contains(spec, case=False, na=False, regex=False)
            )

        # Also try matching against purl column if present (contains mode only)
        if purl_col is not None and match_mode != "exact":
            purl_mask = (
                df[purl_col]
                .astype(str)
                .str.contains(spec, case=False, na=False, regex=False)
            )
            mask = mask | purl_mask

        masks.append(mask)

    combined = masks[0]
    for m in masks[1:]:
        combined = combined | m

    before = len(df)
    result = df[combined].copy()
    logger.info(
        "Component filter '%s': %d → %d findings", component_filter, before, len(result)
    )
    return result
