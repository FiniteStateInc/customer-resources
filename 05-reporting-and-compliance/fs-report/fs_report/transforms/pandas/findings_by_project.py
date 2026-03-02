"""
Pandas transform functions for Findings by Project report.
"""

from typing import Any

import pandas as pd

from fs_report.models import Config

_CSV_COLUMNS = [
    "CVE ID",
    "Severity",
    "CVSS",
    "Project Name",
    "Project Version",
    "Folder",
    "Component",
    "Component Version",
    "Status",
    "Reachability",
    "Detected",
    "# of known exploits",
    "# of known weaponization",
    "CWE",
    "Description",
    "CVSS v2 Vector",
    "CVSS v3 Vector",
    "NVD URL",
    "FS Link",
]


def findings_by_project_pandas_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config,
    additional_data: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """
    Transform findings data for the Findings by Project report with optional project filtering.

    Args:
        data: Raw findings data from API (list of dicts or DataFrame)
        config: Configuration including optional project_filter
        additional_data: Optional dict with cve_details and domain for enrichment

    Returns:
        Processed DataFrame with findings organized by project
    """

    if isinstance(data, pd.DataFrame):
        if data.empty:
            return pd.DataFrame()
        df = data.copy()
    elif not data:
        return pd.DataFrame()
    else:
        # Convert to DataFrame
        df = pd.DataFrame(data)

    # Flatten nested data structures first
    df = flatten_findings_data(df)

    # Note: Project filtering is already applied at the API level, so we don't need to filter again here

    # Select and rename required columns
    required_columns = {
        "cvss_score": "CVSS",
        "exploit_count": "# of known exploits",
        "weaponization_count": "# of known weaponization",
        "component.name": "Component",
        "component.version": "Component Version",
        "cwe_id": "CWE",
        "folder_name": "Folder",
        "project.name": "Project Name",
        "project.version": "Project Version",
        "cve_id": "CVE ID",
        "severity": "Severity",
        "detected": "Detected",
        "status": "Status",
        "reachability_label": "Reachability",
    }

    # Create output DataFrame with required columns
    output_df = pd.DataFrame()
    for api_col, output_col in required_columns.items():
        if api_col in df.columns:
            output_df[output_col] = df[api_col]
        else:
            # Handle missing columns gracefully
            output_df[output_col] = None

    # Carry over internal IDs for link construction (not displayed in table)
    for internal_col in ("finding_numeric_id", "project.id", "projectVersion.id"):
        if internal_col in df.columns:
            output_df[internal_col] = df[internal_col].values

    # Free the large intermediate DataFrame now that we've extracted needed columns
    del df

    # --- Enrich with CVE details from additional_data ---
    cve_details: dict[str, dict[str, str]] = {}
    domain = ""
    if additional_data:
        cve_details = additional_data.get("cve_details", {})
        domain = additional_data.get("domain", "")

    # Description, CVSS v2 Vector, CVSS v3 Vector from cve_details lookup
    output_df["Description"] = output_df["CVE ID"].map(
        lambda cve: (
            cve_details.get(cve, {}).get("description", "") if cve_details else ""
        )
    )
    output_df["CVSS v2 Vector"] = output_df["CVE ID"].map(
        lambda cve: (
            cve_details.get(cve, {}).get("cvss_v2_vector", "") if cve_details else ""
        )
    )
    output_df["CVSS v3 Vector"] = output_df["CVE ID"].map(
        lambda cve: (
            cve_details.get(cve, {}).get("cvss_v3_vector", "") if cve_details else ""
        )
    )

    # NVD URL — constructed from CVE ID
    output_df["NVD URL"] = output_df["CVE ID"].apply(
        lambda cve: (
            f"https://nvd.nist.gov/vuln/detail/{cve}" if cve and cve != "N/A" else ""
        )
    )

    # FS Link — constructed from domain + project.id + projectVersion.id + finding_numeric_id
    if (
        domain
        and "project.id" in output_df.columns
        and "projectVersion.id" in output_df.columns
        and "finding_numeric_id" in output_df.columns
    ):
        output_df["FS Link"] = output_df.apply(
            lambda row: (
                (
                    f"https://{domain}/projects/{row.get('project.id', '')}"
                    f"/versions/{row.get('projectVersion.id', '')}"
                    f"/findings?findingId={row.get('finding_numeric_id', '')}"
                )
                if row.get("project.id")
                and row.get("projectVersion.id")
                and row.get("finding_numeric_id")
                else ""
            ),
            axis=1,
        )
    else:
        output_df["FS Link"] = ""

    # Drop internal ID columns (not needed in output)
    output_df = output_df.drop(
        columns=["finding_numeric_id", "project.id", "projectVersion.id"],
        errors="ignore",
    )

    # Apply canonical column ordering
    csv_cols = [c for c in _CSV_COLUMNS if c in output_df.columns]
    output_df = output_df[csv_cols]

    # Sort by CVSS score (descending) and then by Project Name
    output_df = output_df.sort_values(["CVSS", "Project Name"], ascending=[False, True])

    # Handle missing data gracefully
    output_df = output_df.fillna(
        {
            "CVE ID": "N/A",
            "CVSS": 0,
            "# of known exploits": 0,
            "# of known weaponization": 0,
            "Component": "Unknown",
            "Component Version": "Unknown",
            "CWE": "Unknown",
            "Project Name": "Unknown",
            "Project Version": "Unknown",
            "Severity": "",
            "Detected": "",
            "Status": "",
            "Reachability": "UNKNOWN",
            "Description": "",
            "CVSS v2 Vector": "",
            "CVSS v3 Vector": "",
            "NVD URL": "",
            "FS Link": "",
        }
    )

    return output_df


def apply_project_filter(df: pd.DataFrame, project_filter: str) -> pd.DataFrame:
    """
    Apply project filtering based on filter type detection.

    Args:
        df: Findings DataFrame
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
            project_match = df[df["project.id"] == project_id]
            if not project_match.empty:
                return project_match
        return pd.DataFrame()
    except ValueError:
        # Not an integer, treat as project name (case-insensitive)
        if "project.name" in df.columns:
            project_match = df[df["project.name"].str.lower() == project_filter.lower()]
            return project_match
        return pd.DataFrame()


def flatten_findings_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flatten nested data structures in findings DataFrame and extract all required fields.

    Args:
        df: Raw findings DataFrame

    Returns:
        Flattened DataFrame with all required fields extracted
    """
    import ast
    import re

    # Handle component data
    if "component" in df.columns:

        def extract_component_name(component: Any) -> str:
            if isinstance(component, dict):
                return str(component.get("name", "Unknown"))
            if isinstance(component, str):
                try:
                    comp = ast.literal_eval(component)
                    if isinstance(comp, dict):
                        return str(comp.get("name", "Unknown"))
                except Exception:
                    pass
                return component.strip() if component.strip() else "Unknown"
            return "Unknown"

        def extract_component_version(component: Any) -> str:
            if isinstance(component, dict):
                return str(component.get("version", "Unknown"))
            if isinstance(component, str):
                try:
                    comp = ast.literal_eval(component)
                    if isinstance(comp, dict):
                        return str(comp.get("version", "Unknown"))
                except Exception:
                    pass
            return "Unknown"

        df["component.name"] = df["component"].apply(extract_component_name)
        df["component.version"] = df["component"].apply(extract_component_version)

    # Handle project data
    if "project" in df.columns:

        def extract_project_name(project: Any) -> str:
            if isinstance(project, dict):
                return str(project.get("name", "Unknown"))
            if isinstance(project, str):
                try:
                    proj = ast.literal_eval(project)
                    if isinstance(proj, dict):
                        return str(proj.get("name", "Unknown"))
                except Exception:
                    pass
                return project.strip() if project.strip() else "Unknown"
            return "Unknown"

        def extract_project_id(project: Any) -> Any:
            if isinstance(project, dict):
                return project.get("id", "Unknown")
            if isinstance(project, str):
                try:
                    proj = ast.literal_eval(project)
                    if isinstance(proj, dict):
                        return proj.get("id", "Unknown")
                except Exception:
                    pass
            return "Unknown"

        df["project.name"] = df["project"].apply(extract_project_name)
        df["project.id"] = df["project"].apply(extract_project_id)

    # Handle projectVersion data
    if "projectVersion" in df.columns:

        def extract_project_version(project_version: Any) -> str:
            if isinstance(project_version, dict):
                return str(project_version.get("version", "Unknown"))
            if isinstance(project_version, str):
                try:
                    pv = ast.literal_eval(project_version)
                    if isinstance(pv, dict):
                        return str(pv.get("version", "Unknown"))
                except Exception:
                    pass
            return "Unknown"

        def extract_project_version_id(project_version: Any) -> Any:
            if isinstance(project_version, dict):
                return project_version.get("id", "")
            if isinstance(project_version, str):
                try:
                    pv = ast.literal_eval(project_version)
                    if isinstance(pv, dict):
                        return pv.get("id", "")
                except Exception:
                    pass
            return ""

        df["project.version"] = df["projectVersion"].apply(extract_project_version)
        df["projectVersion.id"] = df["projectVersion"].apply(extract_project_version_id)

    # Handle CVE ID from findingId
    if "findingId" in df.columns:
        df["cve_id"] = df["findingId"]

    # Extract finding numeric id (for FS link construction)
    if "id" in df.columns:
        df["finding_numeric_id"] = df["id"]

    # Extract severity (already in API response)
    if "severity" not in df.columns:
        df["severity"] = ""

    # Handle CVSS score from risk field
    if "risk" in df.columns:

        def extract_cvss_score(risk: Any) -> float:
            try:
                score = float(risk)
                # Scale down if > 10 (sometimes API returns scores multiplied by 10)
                if score > 10:
                    score = score / 10.0
                return score
            except Exception:
                return 0.0

        df["cvss_score"] = df["risk"].apply(extract_cvss_score)

    # Handle CWE data from cwes field
    if "cwes" in df.columns:

        def extract_cwe_id(cwes: Any) -> str:
            if isinstance(cwes, list) and cwes:
                # Clean up CWE format (remove "CWE-" prefix if doubled)
                cwe = str(cwes[0]).replace("CWE-CWE-", "CWE-")
                return cwe
            if isinstance(cwes, str):
                try:
                    cwe_list = ast.literal_eval(cwes)
                    if isinstance(cwe_list, list) and cwe_list:
                        cwe = str(cwe_list[0]).replace("CWE-CWE-", "CWE-")
                        return cwe
                except Exception:
                    pass
                # Try regex to find CWE pattern
                match = re.search(r"CWE-\d+", cwes)
                if match:
                    return match.group(0)
            return "Unknown"

        df["cwe_id"] = df["cwes"].apply(extract_cwe_id)

    # Handle exploit info
    if "exploitInfo" in df.columns:

        def count_exploits(exploit_data: Any) -> int:
            if isinstance(exploit_data, list):
                return len(exploit_data)
            else:
                return 0

        def calculate_weaponization_count(exploit_info: Any) -> int:
            if not exploit_info or not isinstance(exploit_info, list):
                return 0
            count = 0
            for item in exploit_info:
                if isinstance(item, dict):
                    # Count botnets, ransomware, and threat actors
                    if any(
                        keyword in str(item).lower()
                        for keyword in ["botnet", "ransomware", "threat", "actor"]
                    ):
                        count += 1
                elif isinstance(item, str):
                    # Count if string contains weaponization keywords
                    if any(
                        keyword in item.lower()
                        for keyword in ["botnet", "ransomware", "threat", "actor"]
                    ):
                        count += 1
            return count

        df["exploit_count"] = df["exploitInfo"].apply(count_exploits)
        df["weaponization_count"] = df["exploitInfo"].apply(
            calculate_weaponization_count
        )
    else:
        df["exploit_count"] = 0
        df["weaponization_count"] = 0

    # Handle reachability score
    if "reachabilityScore" in df.columns:
        raw = pd.to_numeric(df["reachabilityScore"], errors="coerce")
        df["reachability_label"] = raw.apply(
            lambda s: (
                "UNKNOWN"
                if pd.isna(s)
                else (
                    "REACHABLE"
                    if s > 0
                    else ("UNREACHABLE" if s < 0 else "INCONCLUSIVE")
                )
            )
        )
    else:
        df["reachability_label"] = "UNKNOWN"

    # Ensure all required columns exist with defaults
    if "cvss_score" not in df.columns:
        df["cvss_score"] = 0.0
    if "cve_id" not in df.columns:
        df["cve_id"] = "N/A"
    if "cwe_id" not in df.columns:
        df["cwe_id"] = "Unknown"
    if "component.name" not in df.columns:
        df["component.name"] = "Unknown"
    if "component.version" not in df.columns:
        df["component.version"] = "Unknown"
    if "project.name" not in df.columns:
        df["project.name"] = "Unknown"
    if "project.version" not in df.columns:
        df["project.version"] = "Unknown"

    return df
