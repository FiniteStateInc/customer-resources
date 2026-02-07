"""
Pandas transform functions for Component List report.
"""

import pandas as pd
from typing import Any, Dict, List
from fs_report.models import Config


def component_list_pandas_transform(data: List[Dict[str, Any]], config: Config) -> pd.DataFrame:
    """
    Transform components data for the Component List report with optional project filtering.
    
    Args:
        data: Raw components data from API
        config: Configuration including optional project_filter
    
    Returns:
        Processed DataFrame with components organized by project
    """
    
    if not data:
        return pd.DataFrame()
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Flatten nested data structures first (also handles license field normalization)
    df = flatten_component_data(df)
    
    # Select and rename required columns
    required_columns = {
        'name': 'Component',
        'version': 'Version',
        'type': 'Type',
        'supplier': 'Supplier',
        'declaredLicenses': 'Declared License',
        'concludedLicenses': 'Concluded License',
        'folder_name': 'Folder',
        'project.name': 'Project Name',
        'projectVersion.version': 'Project Version',
        'branch.name': 'Branch',
        'findings': 'Findings',
        'warnings': 'Warnings',
        'violations': 'Violations',
        'status': 'Status',
        'bomRef': 'BOM Reference',
        'created': 'Created',
    }
    
    # Create output DataFrame with required columns
    output_df = pd.DataFrame()
    for api_col, output_col in required_columns.items():
        if api_col in df.columns:
            output_df[output_col] = df[api_col]
        else:
            # Handle missing columns gracefully
            output_df[output_col] = None
    
    # Sort by Project Name and then by Component name
    output_df = output_df.sort_values(['Project Name', 'Component'], ascending=[True, True])
    
    # Handle missing data gracefully
    output_df = output_df.fillna({
        'Component': 'Unknown',
        'Version': 'Unknown',
        'Type': 'Unknown',
        'Supplier': 'Unknown',
        'Declared License': '',
        'Concluded License': '',
        'Project Name': 'Unknown',
        'Project Version': 'Unknown',
        'Branch': 'main',
        'Findings': 0,
        'Warnings': 0,
        'Violations': 0,
        'Status': 'N/A',
        'BOM Reference': 'N/A',
        'Created': 'N/A',
    })
    
    # Convert numeric columns to integers
    for col in ['Findings', 'Warnings', 'Violations']:
        output_df[col] = pd.to_numeric(output_df[col], errors='coerce').fillna(0).astype(int)
    
    return output_df


def flatten_component_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flatten nested data structures in components DataFrame and extract all required fields.
    
    Args:
        df: Raw components DataFrame
    
    Returns:
        Flattened DataFrame with all required fields extracted
    """
    
    # Handle project data
    if 'project' in df.columns:
        def extract_project_name(project):
            if isinstance(project, dict):
                return project.get('name', 'Unknown')
            if isinstance(project, str):
                return project.strip() if project.strip() else 'Unknown'
            return 'Unknown'
        
        def extract_project_id(project):
            if isinstance(project, dict):
                return project.get('id', 'Unknown')
            return 'Unknown'
        
        df['project.name'] = df['project'].apply(extract_project_name)
        df['project.id'] = df['project'].apply(extract_project_id)
    
    # Handle projectVersion data
    if 'projectVersion' in df.columns:
        def extract_project_version(project_version):
            if isinstance(project_version, dict):
                return project_version.get('version', 'Unknown')
            if isinstance(project_version, str):
                return project_version.strip() if project_version.strip() else 'Unknown'
            return 'Unknown'
        
        def extract_project_version_id(project_version):
            if isinstance(project_version, dict):
                return project_version.get('id', 'Unknown')
            return 'Unknown'
        
        df['projectVersion.version'] = df['projectVersion'].apply(extract_project_version)
        df['projectVersion.id'] = df['projectVersion'].apply(extract_project_version_id)
    
    # Handle branch data
    if 'branch' in df.columns:
        def extract_branch_name(branch):
            if isinstance(branch, dict):
                return branch.get('name', 'main')
            if isinstance(branch, str):
                return branch.strip() if branch.strip() else 'main'
            return 'main'
        
        df['branch.name'] = df['branch'].apply(extract_branch_name)
    
    # Handle license details - extract to declaredLicenses if not present
    if 'declaredLicenses' not in df.columns and 'licenseDetails' in df.columns:
        def extract_licenses_summary(license_details):
            if isinstance(license_details, list) and license_details:
                licenses = []
                for ld in license_details:
                    if isinstance(ld, dict):
                        spdx = ld.get('spdx', '')
                        if spdx:
                            licenses.append(spdx)
                        elif ld.get('license'):
                            licenses.append(ld.get('license'))
                return ', '.join(licenses) if licenses else None
            return None
        df['declaredLicenses'] = df['licenseDetails'].apply(extract_licenses_summary)
    
    # Ensure all required columns exist with defaults
    default_columns = {
        'name': 'Unknown',
        'version': 'Unknown',
        'type': 'Unknown',
        'supplier': 'Unknown',
        'declaredLicenses': None,  # Auto-detected licenses
        'concludedLicenses': None,  # User-specified licenses
        'findings': 0,
        'warnings': 0,
        'violations': 0,
        'status': None,
        'bomRef': None,
        'created': None,
        'project.name': 'Unknown',
        'project.id': 'Unknown',
        'projectVersion.version': 'Unknown',
        'branch.name': 'main',
    }
    
    for col, default_val in default_columns.items():
        if col not in df.columns:
            df[col] = default_val
    
    return df


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
        if 'project.id' in df.columns:
            project_match = df[df['project.id'] == str(project_id)]
            if not project_match.empty:
                return project_match
        return pd.DataFrame()
    except ValueError:
        # Not an integer, treat as project name (case-insensitive)
        if 'project.name' in df.columns:
            project_match = df[df['project.name'].str.lower() == project_filter.lower()]
            return project_match
        return pd.DataFrame()
