#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "requests>=2.31.0",
#     "pandas>=2.0.0",
#     "rich>=13.0.0",
# ]
# ///
"""
Finite State License Report Generator

A CLI tool that pulls license data from the Finite State REST API and emits
CSV reports.
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import re

import pandas as pd
import requests
from rich.console import Console

console = Console()

# Configuration
TOKEN = os.getenv("FINITE_STATE_AUTH_TOKEN")
DOMAIN = os.getenv("FINITE_STATE_DOMAIN")
if not DOMAIN:
    console.print("[red]Error: FINITE_STATE_DOMAIN environment variable is required[/red]")
    console.print("Set it with: export FINITE_STATE_DOMAIN='your_domain.finitestate.io'")
    sys.exit(1)
HEADERS = {"X-Authorization": TOKEN}
BASE_URL = f"https://{DOMAIN}/api/public/v0"

def validate_environment() -> None:
    """Validate required environment variables."""
    if not TOKEN:
        console.print("[red]Error: FINITE_STATE_AUTH_TOKEN environment variable is required[/red]")
        sys.exit(1)

def fetch_all_projects() -> List[Dict]:
    url = f"{BASE_URL}/projects"
    projects = []
    offset = 0
    limit = 100
    while True:
        resp = requests.get(url, headers=HEADERS, params={"offset": offset, "limit": limit})
        if resp.status_code != 200:
            console.print(f"[red]Failed to fetch projects: {resp.status_code}[/red]")
            try:
                console.print(resp.text)
            except Exception:
                pass
            sys.exit(1)
        data = resp.json()
        if not data or not isinstance(data, list):
            break
        projects.extend(data)
        if len(data) < limit:
            break
        offset += limit
    return projects

def get_project_and_latest_version_id_by_name(project_name: str):
    projects = fetch_all_projects()
    for project in projects:
        if project.get("name") == project_name:
            project_id = project.get("id")
            version_id = (
                project.get("defaultBranch", {})
                .get("latestVersion", {})
                .get("id")
            )
            return project_id, version_id
    return None, None

def get_latest_version_id_by_project_id(project_id: str):
    projects = fetch_all_projects()
    version_id = None
    for project in projects:
        if project.get("id") == project_id:
            version_id = (
                project.get("defaultBranch", {})
                .get("latestVersion", {})
                .get("id")
            )
            break
    return version_id

def get_latest_version_id(project_id: str) -> Optional[str]:
    url = f"{BASE_URL}/projects/{project_id}/versions"
    resp = requests.get(url, headers=HEADERS, params={"offset": 0, "limit": 1})
    if resp.status_code != 200:
        console.print(f"[red]Failed to fetch versions: {resp.status_code}[/red]")
        try:
            console.print(resp.text)
        except Exception:
            pass
        sys.exit(1)
    data = resp.json()
    if isinstance(data, list) and data:
        return data[0].get("id")
    return None

def fetch_components(version_id: str) -> List[Dict]:
    """Fetch components via API using projectVersion filter with pagination."""
    url = f"{BASE_URL}/components"
    components: List[Dict] = []
    offset = 0
    limit = 200
    while True:
        params = {
            "filter": f"projectVersion=={version_id}",
            "offset": offset,
            "limit": limit,
            "sort": "name:asc"
        }
        resp = requests.get(url, headers=HEADERS, params=params)
        if resp.status_code != 200:
            console.print(f"[red]Failed to fetch components: {resp.status_code}[/red]")
            try:
                console.print(resp.text)
            except Exception:
                pass
            sys.exit(1)
        data = resp.json()
        page_items = data if isinstance(data, list) else data.get("items", []) if isinstance(data, dict) else []
        if not page_items:
            break
        components.extend(page_items)
        if len(page_items) < limit:
            break
        offset += limit
    return components

def filter_components_by_project(components: List[Dict[str, Any]], project_id: str) -> List[Dict[str, Any]]:
    """Filter components by project ID."""
    filtered = []
    for component in components:
        if component.get("project", {}).get("id") == project_id:
            filtered.append(component)
    return filtered

def filter_components_by_version(components: List[Dict[str, Any]], version_id: str) -> List[Dict[str, Any]]:
    """Filter components by version ID."""
    filtered = []
    for component in components:
        if component.get("projectVersion", {}).get("id") == version_id:
            filtered.append(component)
    return filtered

def find_project_by_name(components, project_name):
    """Find project ID by name from components data"""
    for component in components:
        if component.get('name') == project_name:
            return component.get('projectId')
    return None

def get_project_name_from_components(components: List[Dict[str, Any]], version_id: str) -> Optional[str]:
    """Get project name from components for a specific version."""
    if not components:
        return None
    for component in components:
        if component.get("project", {}).get("name"):
            return component.get("project", {}).get("name")
        if component.get("projectVersion", {}).get("project", {}).get("name"):
            return component.get("projectVersion", {}).get("project", {}).get("name")
    potential_project_names = []
    for component in components:
        component_name = component.get("name")
        if component_name and component_name != "UNKNOWN":
            if (not "/" in component_name and 
                not "." in component_name and 
                not component_name.startswith("org.") and
                not component_name.startswith("com.") and
                not component_name.startswith("io.") and
                not component_name.startswith("net.") and
                len(component_name) > 2):
                potential_project_names.append(component_name)
    if potential_project_names:
        project_name = max(potential_project_names, key=len)
        return project_name
    return None

def _unused():
    # Placeholder to preserve structure after removing SBOM functions
    return None

def test_available_endpoints() -> None:
    """Test which endpoints are available for debugging."""
    console.print("[blue]Testing available endpoints...[/blue]")
    
    test_endpoints = [
        f"{BASE_URL}/components",
        f"{BASE_URL}/projects",
    ]
    
    for endpoint in test_endpoints:
        try:
            response = requests.get(endpoint, headers=HEADERS, timeout=10)
            if response.status_code == 200:
                console.print(f"[green]✓ {endpoint} - OK[/green]")
            else:
                console.print(f"[yellow]⚠ {endpoint} - {response.status_code}[/yellow]")
        except Exception as e:
            console.print(f"[red]✗ {endpoint} - {e}[/red]")

def fetch_components_api(version_id: str) -> List[Dict]:
    """Fetch components for a specific version."""
    # Try different possible endpoints for components
    possible_endpoints = [
        f"{BASE_URL}/components?versionId={version_id}",
        f"{BASE_URL}/components?projectVersionId={version_id}",
        f"{BASE_URL}/components?version={version_id}"
    ]
    
    for endpoint in possible_endpoints:
        try:
            console.print(f"[blue]Trying component endpoint: {endpoint}[/blue]")
            response = requests.get(endpoint, headers=HEADERS, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    console.print(f"[green]✓ Found components via: {endpoint}[/green]")
                    return data
                elif isinstance(data, dict) and "data" in data:
                    console.print(f"[green]✓ Found components via: {endpoint}[/green]")
                    return data["data"]
                else:
                    console.print(f"[yellow]⚠ Unexpected response format from {endpoint}[/yellow]")
                    continue
            elif response.status_code == 404:
                console.print(f"[yellow]⚠ Endpoint not found: {endpoint}[/yellow]")
                continue
            else:
                console.print(f"[yellow]⚠ Endpoint returned {response.status_code}: {endpoint}[/yellow]")
                continue
        except Exception as e:
            console.print(f"[yellow]⚠ Endpoint failed: {endpoint} - {e}[/yellow]")
            continue
    
    raise Exception("All component API endpoints failed")

def transform_to_dataframe(components: List[Dict], delimiter: str = " | ", project_name: str = None) -> pd.DataFrame:
    """Transform components to pandas DataFrame."""
    rows = []
    seen_components = set()
    
    for component in components:
        component_key = f"{component.get('name', '')}-{component.get('version', '')}"
        
        # Keep first occurrence of duplicate components
        if component_key in seen_components:
            continue
        seen_components.add(component_key)
        
        # Skip project-level components (component name matches project name)
        if project_name and component.get("name") == project_name:
            continue
        
        # Extract license information with preference for declaredLicenses/declaredLicenseDetails
        lic_names = []
        copyleft_statuses = []
        
        # Prefer declaredLicenses string if present (for license names)
        declared_licenses_str = component.get("declaredLicenses")
        if isinstance(declared_licenses_str, str) and declared_licenses_str.strip():
            lic_names = [declared_licenses_str.strip()]
        
        # Always inspect declaredLicenseDetails to capture copyleft, and include license names if none yet
        declared_license_details = component.get("declaredLicenseDetails", [])
        if isinstance(declared_license_details, list) and declared_license_details:
            for license_detail in declared_license_details:
                if isinstance(license_detail, dict):
                    lic_name = license_detail.get("spdx") or license_detail.get("license") or "UNKNOWN"
                    copyleft = license_detail.get("copyleftFamily") or "UNKNOWN"
                    if not lic_names:
                        lic_names.append(lic_name)
                    copyleft_statuses.append(copyleft)
        
        # Also inspect concludedLicenseDetails for copyleft info
        concluded_license_details = component.get("concludedLicenseDetails", [])
        if isinstance(concluded_license_details, list) and concluded_license_details:
            for license_detail in concluded_license_details:
                if isinstance(license_detail, dict):
                    copyleft = license_detail.get("copyleftFamily") or "UNKNOWN"
                    copyleft_statuses.append(copyleft)
        
        # If still no license names, fallback to generic licenses array if available
        if not lic_names:
            licenses = component.get("licenses", [])
            if isinstance(licenses, str) and licenses:
                lic_names.append(licenses)
            elif isinstance(licenses, list) and licenses:
                for license_info in licenses:
                    if isinstance(license_info, dict):
                        lic_name = license_info.get("spdxId") or license_info.get("license") or license_info.get("name") or "UNKNOWN"
                    else:
                        lic_name = str(license_info)
                    lic_names.append(lic_name)
        
        # Deduplicate and clean copyleft statuses
        copyleft_clean = [c for c in copyleft_statuses if isinstance(c, str) and c.strip()]
        copyleft_value = delimiter.join(sorted(set(copyleft_clean))) if copyleft_clean else "UNKNOWN"
        
        
        # Supplier: prefer API field, otherwise infer from name
        supplier = component.get("supplier") or ""
        component_name = component.get("name", "")
        if not supplier:
            if component_name.startswith("//"):
                parts = [p for p in component_name.split("/") if p]
                if len(parts) >= 2:
                    supplier = parts[1]
            elif "/" in component_name:
                supplier = component_name.split("/")[0]
            elif component_name.lower() in ["android", "ios", "windows", "linux", "macos"]:
                supplier = component_name.title()
            elif component_name and not component_name.startswith("//") and "/" not in component_name:
                supplier = component_name
        if not supplier:
            supplier = "UNKNOWN"
        
        # Type: prefer API field, otherwise infer from name patterns
        component_type = component.get("type") or ""
        name_lower = component_name.lower()
        if not component_type:
            if component_name.startswith("//"):
                if any(x in name_lower for x in ["mcu", "firmware", "boot"]):
                    component_type = "firmware"
                elif any(x in name_lower for x in ["lib", "library"]):
                    component_type = "library"
                elif any(x in name_lower for x in ["app", "application"]):
                    component_type = "application"
                else:
                    component_type = "firmware"
            elif any(x in name_lower for x in ["lib", "library", ".so", ".dll"]):
                component_type = "library"
            elif any(x in name_lower for x in ["bin", "exe", "executable"]):
                component_type = "executable"
            elif any(x in name_lower for x in ["firmware", "boot", "kernel"]):
                component_type = "firmware"
            elif any(x in name_lower for x in ["app", "application", "service"]):
                component_type = "application"
            elif any(x in name_lower for x in ["android", "ios", "windows", "linux", "macos"]):
                component_type = "platform"
            elif any(x in name_lower for x in ["framework", "sdk", "api"]):
                component_type = "framework"
            elif any(x in name_lower for x in ["driver", "module", "plugin"]):
                component_type = "driver"
        if not component_type:
            component_type = "UNKNOWN"
        
        # Source: prefer API field (array); join values
        source_field = component.get("source", [])
        if isinstance(source_field, list):
            source_str = delimiter.join(source_field) if source_field else "UNKNOWN"
        elif isinstance(source_field, str) and source_field.strip():
            source_str = source_field.strip()
        else:
            # fallback to purl if available
            purl = component.get("purl", "")
            source_str = purl if purl else "UNKNOWN"
        
        # Software identifiers column removed (not available in current API responses)
        
        # Release date: use component created timestamp if available
        release_date = "UNKNOWN"
        created_ts = component.get("created")
        if isinstance(created_ts, str) and created_ts:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(created_ts.replace('Z', '+00:00'))
                release_date = dt.strftime("%Y-%m-%d")
            except Exception:
                release_date = created_ts
        
        rows.append({
            "component": component.get("name", "UNKNOWN"),
            "version": component.get("version", "UNKNOWN"),
            "findings_count": component.get("findings", 0),
            "type": component_type,
            "supplier": supplier,
            "declared_licenses": delimiter.join(lic_names) if lic_names else "UNKNOWN",
            "release_date": release_date,
            "source": source_str,
            "copyleft_status": copyleft_value
        })
    
    df = pd.DataFrame(rows)
    return df.sort_values(["component", "version"])

def save_csv(df: pd.DataFrame, output_dir: Path) -> None:
    """Save DataFrame as CSV."""
    base_filename = "report_license.csv"
    counter = 0
    while True:
        if counter == 0:
            output_file = output_dir / base_filename
        else:
            name, ext = base_filename.rsplit('.', 1)
            output_file = output_dir / f"{name}_{counter}.{ext}"
        
        if not output_file.exists():
            break
        counter += 1
    
    df.to_csv(output_file, index=False)
    console.print(f"[green]✓ CSV report saved: {output_file}[/green]")

# Removed JSON/HTML output helpers (CSV-only tool)

# Removed individual per-component license fetching (CSV is based on bulk components data)

def get_project_name_from_sbom(sbom_data: Dict) -> Optional[str]:
    """Extract project name from SBOM data (SPDX or CycloneDX format)."""
    if "name" in sbom_data:
        name = sbom_data["name"]
        if name and name != "UNKNOWN":
            cleaned = re.split(r"\s+SBOM$", name)[0]
            cleaned = cleaned.rsplit(' ', 1)[0].strip()
            if cleaned:
                return cleaned
    if "packages" in sbom_data:
        if sbom_data["packages"]:
            for pkg in sbom_data["packages"]:
                pkg_name = pkg.get("name")
                if pkg_name and pkg_name != "UNKNOWN" and not pkg_name.startswith("/"):
                    return pkg_name
            first_package = sbom_data["packages"][0]
            package_name = first_package.get("name")
            if package_name and package_name != "UNKNOWN":
                return package_name
    elif "components" in sbom_data:
        if sbom_data["components"]:
            for comp in sbom_data["components"]:
                comp_name = comp.get("name")
                if comp_name and comp_name != "UNKNOWN" and not comp_name.startswith("/"):
                    return comp_name
            first_component = sbom_data["components"][0]
            component_name = first_component.get("name")
            if component_name and component_name != "UNKNOWN":
                return component_name
    if "metadata" in sbom_data:
        metadata = sbom_data["metadata"]
        if "name" in metadata:
            name = metadata["name"]
            if name and name != "UNKNOWN":
                return name
        if "component" in metadata:
            component = metadata["component"]
            name = component.get("name")
            if name and name != "UNKNOWN":
                return name
    return None

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Generate license CSV from Finite State API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --project-id 3161401371292730239
  %(prog)s --project "WebGoat"
  %(prog)s --version-id 3045724872466332389
        """
    )
    
    # Project selection (mutually exclusive)
    project_group = parser.add_mutually_exclusive_group(required=True)
    project_group.add_argument("--project-id", help="Project ID to fetch latest version")
    project_group.add_argument("--project", help="Project name to resolve and fetch latest version")
    project_group.add_argument("--version-id", help="Specific version ID to process")
    
    # Optional arguments
    parser.add_argument("--out", type=Path, default=None,
                       help="Write CSV to this file (default: stdout)")
    parser.add_argument("--delimiter", default=" | ",
                       help="Delimiter for multiple licenses (default: ' | ')")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug mode to test available endpoints")
    parser.add_argument("--summary", action="store_true",
                       help="Print summary stats to stderr (won't affect CSV)")
    
    args = parser.parse_args()
    
    # Validate environment
    validate_environment()
    
    # Debug mode: test available endpoints (print to stderr)
    if args.debug:
        test_available_endpoints()
        # continue to generate CSV as requested
    
    # Determine project and version information
    project_name = "Unknown Project"
    version_id = None
    project_id = None
    
    if args.project:
        console.print(f"[blue]Searching for project: {args.project}[/blue]")
        project_id, version_id = get_project_and_latest_version_id_by_name(args.project)
        if not project_id:
            console.print(f"[red]Error: Project '{args.project}' not found[/red]")
            sys.exit(1)
        project_name = args.project
    elif args.project_id:
        project_id = args.project_id
        version_id = get_latest_version_id_by_project_id(project_id)
        if not version_id:
            console.print(f"[red]Error: No latest version found for project ID '{project_id}'[/red]")
            sys.exit(1)
        # Get project name from the project data
        projects = fetch_all_projects()
        project_name = None
        for project in projects:
            if project.get("id") == project_id:
                project_name = project.get("name")
                break
        if not project_name:
            project_name = f"Project {project_id}"
    elif args.version_id:
        version_id = args.version_id
        # We'll extract the project name from components after fetching them
        project_name = "Unknown Project"
    
    # Fetch components from API only
    components = []
    # Ensure we have a version_id
    if not version_id and project_id:
        console.print(f"[blue]Getting latest version for project {project_id}...[/blue]")
        version_id = get_latest_version_id(project_id)
        if version_id:
            console.print(f"[blue]Using latest version: {version_id}[/blue]")
    if not version_id:
        console.print("[red]Error: Unable to determine project version. Provide --version-id or --project-id/--project.")
        sys.exit(1)
    console.print("[blue]Fetching components via API...[/blue]")
    components = fetch_components(version_id)
    
    if not components:
        console.print("[red]Error: No components found[/red]")
        sys.exit(1)
    
    fetched_count = len(components)
    console.print(f"[green]✓ Fetched {fetched_count} components[/green]")

    # Debug: show sample component JSON to stderr
    if args.debug and components:
        import sys as _sys, json as _json
        err_console = Console(file=_sys.stderr)
        err_console.print("\n[bold]Debug: sample component payload(s)[/bold]")
        for i, comp in enumerate(components[:3]):
            try:
                err_console.print(_json.dumps(comp, indent=2))
            except Exception:
                err_console.print(str(comp))
    
    # Extract project name from components if unknown
    if project_name == "Unknown Project":
            extracted_project_name = get_project_name_from_components(components, version_id)
            if extracted_project_name:
                project_name = extracted_project_name
    
    # Transform to DataFrame
    df = transform_to_dataframe(components, args.delimiter, project_name)
    included_count = len(df)
    skipped_count = fetched_count - included_count
    if skipped_count > 0:
        console.print(f"[yellow]⚠ Skipped {skipped_count} duplicate/project-level components[/yellow]")

    # Output CSV to file or stdout
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.out, index=False)
        console.print(f"[green]✓ CSV report saved: {args.out}[/green]")
    else:
        # Print header and rows to stdout only
        print(
            "component,version,findings_count,type,supplier,declared_licenses,release_date,source,copyleft_status"
        )
        for _, row in df.iterrows():
            print(
                f"{row['component']},{row['version']},{row['findings_count']},{row['type']},{row['supplier']},{row['declared_licenses']},{row['release_date']},{row['source']},{row['copyleft_status']}"
            )

    # Optional summary to stderr (keeps CSV clean)
    if args.summary:
        import sys as _sys
        from rich.table import Table
        
        total_components = len(df)
        
        # Build (license, copyleft) pairs per component row
        pair_list: List[tuple] = []
        for _, row in df.iterrows():
            licenses = [lic.strip() for lic in row['declared_licenses'].split('|') if lic.strip()] or ['UNKNOWN']
            copyleft_statuses = [status.strip() for status in row['copyleft_status'].split('|') if status.strip()] or ['UNKNOWN']
            for lic in licenses:
                for cpl in copyleft_statuses:
                    pair_list.append((lic, cpl))
        
        # Aggregate counts
        if pair_list:
            pairs_df = pd.DataFrame(pair_list, columns=["license", "copyleft"])  # small helper DF
            counts = (
                pairs_df
                .value_counts()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
            )
        else:
            counts = pd.DataFrame(columns=["license", "copyleft", "count"])  # empty
        
        # Render pretty table to stderr using rich
        err_console = Console(file=_sys.stderr)
        err_console.print()
        err_console.print(f"[bold]Summary[/bold]\nTotal components: {total_components}")
        table = Table(show_header=True, header_style="bold")
        table.add_column("License", style="cyan")
        table.add_column("Copyleft Family", style="magenta")
        table.add_column("Count", justify="right", style="green")
        
        for _, row in counts.iterrows():
            table.add_row(str(row["license"] or "UNKNOWN"), str(row["copyleft"] or "UNKNOWN"), str(int(row["count"]) if row["count"] == row["count"] else 0))
        
        err_console.print(table)

if __name__ == "__main__":
    main() 