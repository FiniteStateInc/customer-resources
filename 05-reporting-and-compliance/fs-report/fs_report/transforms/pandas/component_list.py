"""
Pandas transform functions for Component List report.

Includes license enrichment: copyleft classification, policy status,
license URL, source type mapping, and release date extraction.
"""

from typing import Any

import pandas as pd

from fs_report.models import Config

# =============================================================================
# SOURCE TYPE LABELS
# =============================================================================

SOURCE_LABELS: dict[str, str] = {
    "source_sca": "Source SCA",
    "binary_sca": "Binary SCA",
    "binary_sast": "Binary Analysis",
    "sbom_import": "SBOM Import",
    "configuration_analysis": "Config Analysis",
    "vulnerability_analysis": "Vulnerability Analysis",
}

# =============================================================================
# COPYLEFT FALLBACK LOOKUP
# =============================================================================
# Used when the API response does not include copyleftFamily on LicenseDetail.
# Keys are SPDX identifiers; values are copyleft classifications.

COPYLEFT_LOOKUP: dict[str, str] = {
    # Strong copyleft
    "GPL-1.0-only": "STRONG_COPYLEFT",
    "GPL-1.0-or-later": "STRONG_COPYLEFT",
    "GPL-2.0-only": "STRONG_COPYLEFT",
    "GPL-2.0-or-later": "STRONG_COPYLEFT",
    "GPL-3.0-only": "STRONG_COPYLEFT",
    "GPL-3.0-or-later": "STRONG_COPYLEFT",
    "AGPL-1.0-only": "STRONG_COPYLEFT",
    "AGPL-3.0-only": "STRONG_COPYLEFT",
    "AGPL-3.0-or-later": "STRONG_COPYLEFT",
    "EUPL-1.1": "STRONG_COPYLEFT",
    "EUPL-1.2": "STRONG_COPYLEFT",
    "SSPL-1.0": "STRONG_COPYLEFT",
    "OSL-3.0": "STRONG_COPYLEFT",
    # Weak copyleft
    "LGPL-2.0-only": "WEAK_COPYLEFT",
    "LGPL-2.0-or-later": "WEAK_COPYLEFT",
    "LGPL-2.1-only": "WEAK_COPYLEFT",
    "LGPL-2.1-or-later": "WEAK_COPYLEFT",
    "LGPL-3.0-only": "WEAK_COPYLEFT",
    "LGPL-3.0-or-later": "WEAK_COPYLEFT",
    "MPL-1.0": "WEAK_COPYLEFT",
    "MPL-1.1": "WEAK_COPYLEFT",
    "MPL-2.0": "WEAK_COPYLEFT",
    "EPL-1.0": "WEAK_COPYLEFT",
    "EPL-2.0": "WEAK_COPYLEFT",
    "CDDL-1.0": "WEAK_COPYLEFT",
    "CDDL-1.1": "WEAK_COPYLEFT",
    "CPL-1.0": "WEAK_COPYLEFT",
    "IPL-1.0": "WEAK_COPYLEFT",
    # Permissive
    "MIT": "PERMISSIVE",
    "Apache-2.0": "PERMISSIVE",
    "Apache-1.1": "PERMISSIVE",
    "BSD-2-Clause": "PERMISSIVE",
    "BSD-3-Clause": "PERMISSIVE",
    "BSD-3-Clause-LBNL": "PERMISSIVE",
    "ISC": "PERMISSIVE",
    "Unlicense": "PERMISSIVE",
    "0BSD": "PERMISSIVE",
    "MIT-0": "PERMISSIVE",
    "Zlib": "PERMISSIVE",
    "BSL-1.0": "PERMISSIVE",
    "CC0-1.0": "PERMISSIVE",
    "WTFPL": "PERMISSIVE",
    "PSF-2.0": "PERMISSIVE",
    "Python-2.0": "PERMISSIVE",
    "OpenSSL": "PERMISSIVE",
    "Artistic-2.0": "PERMISSIVE",
    "JSON": "PERMISSIVE",
    "curl": "PERMISSIVE",
    "X11": "PERMISSIVE",
}


# =============================================================================
# POLICY SEVERITY ORDERING (for "most restrictive" logic)
# =============================================================================

_POLICY_ORDER: dict[str, int] = {
    "PERMITTED": 0,
    "WARNING": 1,
    "VIOLATION": 2,
}


def component_list_pandas_transform(
    data: list[dict[str, Any]] | pd.DataFrame, config: Config
) -> dict[str, Any]:
    """
    Transform components data for the Component List report with optional
    project filtering and license enrichment.

    Args:
        data: Raw components data from API (list of dicts or DataFrame)
        config: Configuration including optional project_filter

    Returns:
        Dictionary with 'data' (DataFrame) and 'summary' (dict of
        aggregated metrics for HTML charts / XLSX summary sheet).
    """

    if isinstance(data, pd.DataFrame):
        if data.empty:
            return {"main": pd.DataFrame(), "component_summary": _empty_summary()}
        df = data
    elif not data:
        return {"main": pd.DataFrame(), "component_summary": _empty_summary()}
    else:
        df = pd.DataFrame(data)

    # Flatten nested data structures (project, version, branch, legacy license)
    df = flatten_component_data(df)

    # Enrich with license detail fields (copyleft, policy, URL)
    df = _enrich_license_details(df)

    # Map source types to human-readable labels
    df = _map_source_labels(df)

    # Select and rename required columns
    required_columns = {
        "name": "Component",
        "version": "Version",
        "type": "Type",
        "supplier": "Supplier",
        "declaredLicenses": "Declared License",
        "concludedLicenses": "Concluded License",
        "folder_name": "Folder",
        "project.name": "Project Name",
        "projectVersion.version": "Project Version",
        "branch.name": "Branch",
        "source_label": "Source",
        "findings": "Findings",
        "warnings": "Warnings",
        "violations": "Violations",
        "copyleft_status": "Copyleft Status",
        "license_policy": "Policy Status",
        "license_url": "License URL",
        "status": "Component Status",
        "bomRef": "BOM Reference",
        "releaseDate": "Release Date",
        "created": "Created",
    }

    # Build output DataFrame — only copy needed columns
    output_df = pd.DataFrame()
    for api_col, output_col in required_columns.items():
        if api_col in df.columns:
            output_df[output_col] = df[api_col].values
        else:
            output_df[output_col] = None

    # Sort by Project Name and then by Component name
    output_df = output_df.sort_values(
        ["Project Name", "Component"], ascending=[True, True]
    )

    # Handle missing data gracefully
    output_df = output_df.fillna(
        {
            "Component": "Unknown",
            "Version": "Unknown",
            "Type": "Unknown",
            "Supplier": "Unknown",
            "Declared License": "",
            "Concluded License": "",
            "Project Name": "Unknown",
            "Project Version": "Unknown",
            "Branch": "main",
            "Source": "",
            "Findings": 0,
            "Warnings": 0,
            "Violations": 0,
            "Copyleft Status": "",
            "Policy Status": "",
            "License URL": "",
            "Component Status": "N/A",
            "BOM Reference": "N/A",
            "Release Date": "",
            "Created": "N/A",
        }
    )

    # Convert numeric columns to integers
    for col in ["Findings", "Warnings", "Violations"]:
        output_df[col] = (
            pd.to_numeric(output_df[col], errors="coerce").fillna(0).astype(int)
        )

    # Build summary aggregations for charts (small DataFrames only)
    summary = _build_summary(output_df)

    return {"main": output_df, "component_summary": summary}


# =============================================================================
# LICENSE DETAIL ENRICHMENT
# =============================================================================


def _enrich_license_details(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract copyleft status, policy, and URL from the best available
    license detail array on each component row.

    Precedence: concludedLicenseDetails > declaredLicenseDetails > licenseDetails
    """

    def _extract(row: pd.Series) -> pd.Series:
        details = _best_license_details(row)
        copyleft = None
        policy = None
        url = None

        if details:
            best_policy_rank = -1
            for ld in details:
                if not isinstance(ld, dict):
                    continue

                # Copyleft: take first non-empty value
                if copyleft is None:
                    cf = ld.get("copyleftFamily")
                    if cf:
                        copyleft = cf

                # Policy: take most restrictive
                p = ld.get("policy", "")
                p_rank = _POLICY_ORDER.get(p, -1)
                if p_rank > best_policy_rank:
                    best_policy_rank = p_rank
                    policy = p

                # URL: take first non-empty
                if url is None:
                    u = ld.get("url", "")
                    if u:
                        url = u

        # Copyleft fallback: try SPDX lookup from declared license string
        if not copyleft:
            copyleft = _copyleft_from_spdx(row)

        return pd.Series(
            {
                "copyleft_status": copyleft or "",
                "license_policy": policy or "",
                "license_url": url or "",
            }
        )

    enriched = df.apply(_extract, axis=1)
    df["copyleft_status"] = enriched["copyleft_status"]
    df["license_policy"] = enriched["license_policy"]
    df["license_url"] = enriched["license_url"]
    return df


def _best_license_details(row: pd.Series) -> list[Any] | None:
    """Return the best available license detail array from a component row."""
    for field in (
        "concludedLicenseDetails",
        "declaredLicenseDetails",
        "licenseDetails",
    ):
        val = row.get(field)
        if isinstance(val, list) and len(val) > 0:
            return val
    return None


def _copyleft_from_spdx(row: pd.Series) -> str | None:
    """
    Derive copyleft classification from the SPDX license string using
    the fallback lookup table.  Checks concluded first, then declared,
    then the legacy 'licenses' field.
    """
    for field in ("concludedLicenses", "declaredLicenses", "licenses"):
        spdx_str = row.get(field)
        if not spdx_str or not isinstance(spdx_str, str):
            continue
        # Handle compound expressions like "MIT OR Apache-2.0"
        # Take the most restrictive copyleft across all parts
        parts = [
            p.strip()
            for p in spdx_str.replace(" OR ", ",").replace(" AND ", ",").split(",")
        ]
        best_rank = -1
        best_val = None
        for part in parts:
            cl = COPYLEFT_LOOKUP.get(part)
            if cl:
                rank = {"PERMISSIVE": 0, "WEAK_COPYLEFT": 1, "STRONG_COPYLEFT": 2}.get(
                    cl, -1
                )
                if rank > best_rank:
                    best_rank = rank
                    best_val = cl
        if best_val:
            return best_val
    return None


# =============================================================================
# SOURCE TYPE MAPPING
# =============================================================================


def _map_source_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map source[] array values to human-readable labels."""

    def _to_label(sources: Any) -> str:
        if not isinstance(sources, list):
            return ""
        labels = []
        for s in sources:
            label = SOURCE_LABELS.get(s, s)
            if label and label not in labels:
                labels.append(label)
        return ", ".join(labels)

    if "source" in df.columns:
        df["source_label"] = df["source"].apply(_to_label)
    else:
        df["source_label"] = ""
    return df


# =============================================================================
# SUMMARY AGGREGATIONS (for charts and XLSX summary sheet)
# =============================================================================


def _build_summary(df: pd.DataFrame) -> dict[str, Any]:
    """Build summary metrics from the output DataFrame for charts/KPIs."""
    if df.empty:
        return _empty_summary()

    total = len(df)

    # Unique licenses: combine declared + concluded, split by comma, deduplicate
    license_parts = []
    for col in ("Declared License", "Concluded License"):
        if col in df.columns:
            license_parts.append(
                df[col].dropna().astype(str).str.split(",").explode().str.strip()
            )
    if license_parts:
        all_licenses_series = pd.concat(license_parts, ignore_index=True)
        all_licenses_set = set(all_licenses_series[all_licenses_series != ""])
    else:
        all_licenses_set = set()
    unique_licenses = len(all_licenses_set)

    # Components with no license info
    no_license = int(
        (
            (df["Declared License"].fillna("") == "")
            & (df["Concluded License"].fillna("") == "")
        ).sum()
    )

    # Policy violations
    violation_count = int((df["Policy Status"] == "VIOLATION").sum())
    warning_count = int((df["Policy Status"] == "WARNING").sum())
    permitted_count = int((df["Policy Status"] == "PERMITTED").sum())

    # Copyleft counts
    copyleft_strong = int((df["Copyleft Status"] == "STRONG_COPYLEFT").sum())
    copyleft_weak = int((df["Copyleft Status"] == "WEAK_COPYLEFT").sum())
    copyleft_permissive = int((df["Copyleft Status"] == "PERMISSIVE").sum())
    copyleft_unknown = int(
        total - copyleft_strong - copyleft_weak - copyleft_permissive
    )

    # License distribution (top 15 by count)
    # Use the effective license: concluded if present, else declared
    effective = df["Concluded License"].where(
        df["Concluded License"].fillna("") != "", df["Declared License"]
    )
    license_counts = (
        effective[effective.fillna("") != ""].value_counts().head(15).reset_index()
    )
    license_counts.columns = ["License", "Count"]

    # Policy distribution
    policy_dist = (
        df["Policy Status"][df["Policy Status"].fillna("") != ""]
        .value_counts()
        .reset_index()
    )
    policy_dist.columns = ["Policy", "Count"]

    # Copyleft distribution
    copyleft_dist_data = {
        "Classification": ["Permissive", "Weak Copyleft", "Strong Copyleft", "Unknown"],
        "Count": [
            copyleft_permissive,
            copyleft_weak,
            copyleft_strong,
            copyleft_unknown,
        ],
    }
    copyleft_dist = pd.DataFrame(copyleft_dist_data)
    copyleft_dist = copyleft_dist[copyleft_dist["Count"] > 0]

    # Source distribution
    source_dist = (
        df["Source"][df["Source"].fillna("") != ""].value_counts().reset_index()
    )
    source_dist.columns = ["Source", "Count"]

    return {
        "total_components": total,
        "unique_licenses": unique_licenses,
        "no_license_count": no_license,
        "violation_count": violation_count,
        "warning_count": warning_count,
        "permitted_count": permitted_count,
        "copyleft_strong": copyleft_strong,
        "copyleft_weak": copyleft_weak,
        "copyleft_permissive": copyleft_permissive,
        "copyleft_unknown": copyleft_unknown,
        "license_distribution": license_counts,
        "policy_distribution": policy_dist,
        "copyleft_distribution": copyleft_dist,
        "source_distribution": source_dist,
    }


def _empty_summary() -> dict[str, Any]:
    """Return an empty summary dict for when there is no data."""
    return {
        "total_components": 0,
        "unique_licenses": 0,
        "no_license_count": 0,
        "violation_count": 0,
        "warning_count": 0,
        "permitted_count": 0,
        "copyleft_strong": 0,
        "copyleft_weak": 0,
        "copyleft_permissive": 0,
        "copyleft_unknown": 0,
        "license_distribution": pd.DataFrame(columns=["License", "Count"]),
        "policy_distribution": pd.DataFrame(columns=["Policy", "Count"]),
        "copyleft_distribution": pd.DataFrame(columns=["Classification", "Count"]),
        "source_distribution": pd.DataFrame(columns=["Source", "Count"]),
    }


# =============================================================================
# FLATTEN COMPONENT DATA  (shared with other consumers)
# =============================================================================


def flatten_component_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flatten nested data structures in components DataFrame and extract all required fields.

    Args:
        df: Raw components DataFrame

    Returns:
        Flattened DataFrame with all required fields extracted
    """

    # Handle project data
    if "project" in df.columns:

        def extract_project_name(project: Any) -> str:
            if isinstance(project, dict):
                return str(project.get("name", "Unknown"))
            if isinstance(project, str):
                return project.strip() if project.strip() else "Unknown"
            return "Unknown"

        def extract_project_id(project: Any) -> Any:
            if isinstance(project, dict):
                return project.get("id", "Unknown")
            return "Unknown"

        df["project.name"] = df["project"].apply(extract_project_name)
        df["project.id"] = df["project"].apply(extract_project_id)

    # Handle projectVersion data
    if "projectVersion" in df.columns:

        def extract_project_version(project_version: Any) -> str:
            if isinstance(project_version, dict):
                return str(project_version.get("version", "Unknown"))
            if isinstance(project_version, str):
                return project_version.strip() if project_version.strip() else "Unknown"
            return "Unknown"

        def extract_project_version_id(project_version: Any) -> Any:
            if isinstance(project_version, dict):
                return project_version.get("id", "Unknown")
            return "Unknown"

        df["projectVersion.version"] = df["projectVersion"].apply(
            extract_project_version
        )
        df["projectVersion.id"] = df["projectVersion"].apply(extract_project_version_id)

    # Handle branch data
    if "branch" in df.columns:

        def extract_branch_name(branch: Any) -> str:
            if isinstance(branch, dict):
                return str(branch.get("name", "main"))
            if isinstance(branch, str):
                return branch.strip() if branch.strip() else "main"
            return "main"

        df["branch.name"] = df["branch"].apply(extract_branch_name)

    # Handle license details - extract to declaredLicenses if not present
    if "declaredLicenses" not in df.columns and "licenseDetails" in df.columns:

        def extract_licenses_summary(license_details: Any) -> str | None:
            if isinstance(license_details, list) and license_details:
                licenses = []
                for ld in license_details:
                    if isinstance(ld, dict):
                        spdx = ld.get("spdx", "")
                        if spdx:
                            licenses.append(spdx)
                        elif ld.get("license"):
                            licenses.append(ld.get("license"))
                return ", ".join(licenses) if licenses else None
            return None

        df["declaredLicenses"] = df["licenseDetails"].apply(extract_licenses_summary)

    # Ensure all required columns exist with defaults
    default_columns = {
        "name": "Unknown",
        "version": "Unknown",
        "type": "Unknown",
        "supplier": "Unknown",
        "declaredLicenses": None,  # Auto-detected licenses
        "concludedLicenses": None,  # User-specified licenses
        "findings": 0,
        "warnings": 0,
        "violations": 0,
        "status": None,
        "bomRef": None,
        "created": None,
        "releaseDate": None,
        "project.name": "Unknown",
        "project.id": "Unknown",
        "projectVersion.version": "Unknown",
        "branch.name": "main",
    }

    for col, default_val in default_columns.items():
        if col not in df.columns:
            df[col] = default_val

    return df


# =============================================================================
# PROJECT FILTERING
# =============================================================================


def apply_project_filter(df: pd.DataFrame, project_filter: str) -> pd.DataFrame:
    """
    Apply project filtering based on filter type detection.

    Args:
        df: Components DataFrame
        project_filter: Filter string (project name, ID, or version ID)

    Returns:
        Filtered DataFrame
    """
    if not project_filter or project_filter == "all":
        return df

    # Handle multiple projects (comma-separated)
    if "," in project_filter:
        project_list = [p.strip() for p in project_filter.split(",")]
        filtered_dfs = []
        for project in project_list:
            filtered_df = apply_single_project_filter(df, project)
            filtered_dfs.append(filtered_df)
        return pd.concat(filtered_dfs, ignore_index=True)

    return apply_single_project_filter(df, project_filter)


def apply_single_project_filter(df: pd.DataFrame, project_filter: str) -> pd.DataFrame:
    """
    Apply filtering for a single project identifier.
    """
    try:
        project_id = int(project_filter)
        # Check if it's a project ID
        if "project.id" in df.columns:
            project_match = df[df["project.id"] == str(project_id)]
            if not project_match.empty:
                return project_match
        return pd.DataFrame()
    except ValueError:
        # Not an integer, treat as project name (case-insensitive)
        if "project.name" in df.columns:
            project_match = df[df["project.name"].str.lower() == project_filter.lower()]
            return project_match
        return pd.DataFrame()
