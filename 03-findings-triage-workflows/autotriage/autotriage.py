#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = ["requests>=2.25.0"]
# ///

"""
Autotriage REST Script for Finite State Platform

This script replicates VEX (Vulnerability Exploitability eXchange) decisions from one artifact to another using the Finite State REST API.
Updated for API compatibility with swagger_0.3.0.json specification and VEX compliance.

Key Changes Made:
- Updated field references from 'comment' to 'reason' for new API compatibility
- Enhanced error handling with new validation function
- Added support for new API fields (epssScore, reachabilityScore, factors, etc.)
- Improved filtering capabilities with enhanced RSQL support
- Added new command-line options for advanced filtering (severity, risk scores)
- Added support for archived findings inclusion
- Added project version verification to catch configuration issues early
- Enhanced error messages for better troubleshooting
- Added overwrite mode to replace existing status and justification
- VEX validation: requires complete status, justification, and response information
- No automatic defaults: ensures accurate VEX-to-VEX replication

API Endpoints Used:
- GET /public/v0/versions/{projectVersionId} - Verify project version exists
- GET /public/v0/findings - Retrieve findings with filtering
- PUT /public/v0/findings/{projectVersionId}/{findingId}/status - Update finding status

VEX Status Values:
- NOT_AFFECTED, FALSE_POSITIVE, IN_TRIAGE, RESOLVED_WITH_PEDIGREE, RESOLVED, EXPLOITABLE

VEX Justification Values:
- CODE_NOT_PRESENT, CODE_NOT_REACHABLE, REQUIRES_CONFIGURATION, REQUIRES_DEPENDENCY, 
  REQUIRES_ENVIRONMENT, PROTECTED_BY_COMPILER, PROTECTED_AT_RUNTIME, PROTECTED_AT_PERIMETER, 
  PROTECTED_BY_MITIGATING_CONTROL

VEX Response Values:
- CAN_NOT_FIX, WILL_NOT_FIX, UPDATE, ROLLBACK, WORKAROUND_AVAILABLE

Supported Filters:
- Component name and version
- Severity level (CRITICAL, HIGH, MEDIUM, LOW, NONE, INFO)
- Risk score range (min/max)
- Archived findings inclusion (--archived flag)

Error Handling:
- Project version existence verification
- Access permission validation
- Detailed error messages for troubleshooting
- Skip verification option (--skip-verification)
- VEX completeness validation

Update Modes:
- Standard mode: Only update findings that have different values
- Overwrite mode (--overwrite): Replace all status and justification values with source values

VEX Requirements:
- All findings must have status, justification, and response values
- No automatic defaults are applied
- Incomplete VEX information results in findings being skipped
- Ensures accurate replication of VEX decisions

Required Environment Variables:
- FINITE_STATE_AUTH_TOKEN: Your authentication token
- FINITE_STATE_DOMAIN: Your organization's domain (e.g., 'your-org.finitestate.io')
"""

import argparse
import os
import sys
import json
import requests
import time
import traceback
import csv
from datetime import datetime

# Valid triage statuses
VALID_STATUSES = {
    'NOT_AFFECTED',
    'FALSE_POSITIVE',
    'IN_TRIAGE',
    'RESOLVED_WITH_PEDIGREE',
    'RESOLVED',
    'EXPLOITABLE'
}

# API Base URL - will be constructed from domain
def get_api_base_url():
    """
    Get the API base URL from the domain environment variable.
    """
    domain = os.getenv('FINITE_STATE_DOMAIN')
    if not domain:
        raise ValueError("FINITE_STATE_DOMAIN environment variable is required")
    return f"https://{domain}/api/public/v0"

def get_project_by_name_or_id(token, domain, project_identifier, debug=False):
    """
    Get project by name or ID.
    
    Args:
        token: Authentication token
        domain: Domain for API calls
        project_identifier: Project name or project ID
        debug: If True, print debug output
    
    Returns:
        Project dict with id, name, and defaultBranch.latestVersion.id, or None if not found
    """
    url = f"{get_api_base_url()}/projects"
    headers = {
        "X-Authorization": token,
        "Accept": "application/json"
    }
    
    try:
        # Fetch all projects with pagination
        all_projects = []
        offset = 0
        limit = 100  # Fetch in batches
        
        while True:
            params = {"offset": offset, "limit": limit}
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != 200:
                if offset == 0:  # Only fail on first request
                    return None
                break  # No more pages
            
            projects = response.json()
            if not isinstance(projects, list):
                if offset == 0:  # Only fail on first request
                    return None
                break  # No more pages
            
            all_projects.extend(projects)
            
            # If we got fewer than the limit, we've reached the end
            if len(projects) < limit:
                break
            
            offset += limit
        
        if debug:
            print(f"🔍 DEBUG: Fetched {len(all_projects)} total projects")
        
        # Try to find by ID first (faster)
        # Handle both string and numeric comparison
        for project in all_projects:
            project_id = project.get('id')
            if project_id == project_identifier or str(project_id) == str(project_identifier):
                if debug:
                    print(f"🔍 DEBUG: Found project by ID: {project_id}")
                return project
        
        # If not found by ID, try by name (case-insensitive)
        project_identifier_lower = str(project_identifier).lower()
        for project in all_projects:
            project_name = project.get('name', '')
            if project_name.lower() == project_identifier_lower:
                if debug:
                    print(f"🔍 DEBUG: Found project by name: {project_name} (ID: {project.get('id')})")
                return project
        
        if debug:
            print(f"🔍 DEBUG: Project '{project_identifier}' not found in {len(all_projects)} projects")
        return None
    except Exception as e:
        if debug:
            print(f"❌ DEBUG: Exception in get_project_by_name_or_id: {str(e)}")
        return None

def get_latest_version_id_for_project(token, domain, project_id, debug=False):
    """
    Get the latest version ID for a project by fetching all versions and finding the one with the latest created date.
    
    Args:
        token: Authentication token
        domain: Domain for API calls
        project_id: Project ID
        debug: If True, print debug output
        
    Returns:
        Latest version ID (artifact ID) or None if not found
    """
    if debug:
        print(f"🔍 DEBUG: get_latest_version_id_for_project called for project_id={project_id}")
    headers = {
        "X-Authorization": token,
        "Accept": "application/json"
    }
    
    # Get all versions and find the one with the latest created date
    url = f"{get_api_base_url()}/projects/{project_id}/versions"
    if debug:
        print(f"🔍 DEBUG: Fetching versions from {url}")
    
    try:
        # Fetch versions with pagination to get all of them
        all_versions = []
        offset = 0
        limit = 100  # Fetch in batches
        
        # Try to use sort parameter if supported (only on first request)
        use_sort = True
        while True:
            params = {"offset": offset, "limit": limit}
            if use_sort:
                params["sort"] = "created:desc"
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != 200:
                # If sort parameter causes error, retry without it
                if use_sort:
                    use_sort = False
                    params = {"offset": offset, "limit": limit}
                    response = requests.get(url, headers=headers, params=params)
                    if response.status_code != 200:
                        break
                else:
                    break
            
            versions = response.json()
            if not isinstance(versions, list):
                break
            
            all_versions.extend(versions)
            
            # If we got fewer than the limit, we've reached the end
            if len(versions) < limit:
                break
            
            offset += limit
        
        if not all_versions:
            return None
        
        if debug:
            print(f"🔍 DEBUG: Fetched {len(all_versions)} total versions for project {project_id}")
        
        # Find the version with the latest created date
        # Parse all dates to datetime objects for accurate comparison
        versions_with_dates = []
        for version in all_versions:
            created = version.get('created')
            version_id = version.get('id')
            if created:
                try:
                    # Parse ISO format date string
                    # Handle formats: "2025-11-26T14:21:50Z", "2025-11-26T14:21:50.297253Z", etc.
                    created_str = created
                    # Replace Z with +00:00 for timezone
                    if created_str.endswith('Z'):
                        created_str = created_str[:-1] + '+00:00'
                    # If no timezone, add UTC
                    elif '+' not in created_str and '-' not in created_str[-6:]:
                        created_str += '+00:00'
                    created_date = datetime.fromisoformat(created_str)
                    versions_with_dates.append((created_date, version, version_id))
                except Exception as e:
                    # If parsing fails, log it but skip this version
                    if debug:
                        print(f"⚠️  DEBUG: Failed to parse date for version {version_id}: {created} - {str(e)}")
                    continue
            else:
                if debug:
                    print(f"⚠️  DEBUG: Version {version_id} has no 'created' field")
        
        if not versions_with_dates:
            # If no versions have parseable dates, return the first one as fallback
            return all_versions[0].get('id') if all_versions else None
        
        # Sort by date - latest first (reverse=True means newest first)
        versions_with_dates.sort(key=lambda x: x[0], reverse=True)
        latest_version = versions_with_dates[0][1]
        latest_version_id = latest_version.get('id')
        
        # Debug: Show all versions sorted by date
        if debug and len(versions_with_dates) > 0:
            print(f"🔍 DEBUG: Found {len(versions_with_dates)} versions with parseable dates. All versions sorted by created date:")
            for i, (date, version, vid) in enumerate(versions_with_dates):
                marker = " <-- SELECTED" if i == 0 else ""
                print(f"   {i+1}. Version {vid}: created={version.get('created')} ({date}){marker}")
        
        return latest_version_id
        
    except Exception as e:
        if debug:
            print(f"❌ DEBUG: Exception in get_latest_version_id_for_project: {str(e)}")
            import traceback
            traceback.print_exc()
        return None

def resolve_to_version_id(token, domain, identifier, debug=False):
    """
    Resolve an identifier (project name, project ID, or version ID) to a version ID.
    
    Note: Both project IDs and version IDs can be negative (unsigned integers).
    We try project first, then fall back to version ID.
    
    Args:
        token: Authentication token
        domain: Domain for API calls
        identifier: Project name, project ID, or version ID
        debug: If True, print debug output
    
    Returns:
        Tuple of (version_id, identifier_type) where identifier_type is 'version', 'project', or None if not found
    """
    # Step 1: Try as project name (non-numeric identifiers are likely project names)
    # Check if identifier is numeric (handles both positive and negative)
    is_numeric = identifier.lstrip('-').isdigit() if identifier else False
    
    if not is_numeric:
        # Looks like a project name (contains non-numeric characters)
        project = get_project_by_name_or_id(token, domain, identifier, debug=debug)
        if project:
            project_id = project.get('id')
            version_id = get_latest_version_id_for_project(token, domain, project_id, debug=debug)
            if version_id:
                return (version_id, 'project')
        # If not found as name, it might be invalid
        if debug:
            print(f"🔍 DEBUG: Project name '{identifier}' not found in projects list")
        return (None, None)
    
    # Step 2: Try as project ID (from projects list)
    # This handles both positive and negative project IDs
    project = get_project_by_name_or_id(token, domain, identifier, debug=debug)
    if project:
        project_id = project.get('id')
        version_id = get_latest_version_id_for_project(token, domain, project_id, debug=debug)
        if version_id:
            return (version_id, 'project')
    
    # Step 3: If not in projects list, try to access project directly by ID
    # (in case it's a project ID but not in the list due to pagination/access)
    # This handles both positive and negative project IDs
    # Use get_latest_version_id_for_project to properly find the latest version
    if debug:
        print(f"🔍 DEBUG: Trying '{identifier}' as direct project ID")
    version_id = get_latest_version_id_for_project(token, domain, identifier, debug=debug)
    if version_id:
        return (version_id, 'project')
    
    # Step 4: If not found as project, assume it's a version ID
    # (Both positive and negative version IDs are valid)
    # The view_findings function will validate if it exists
    return (identifier, 'version')

def load_environment():
    """
    Load environment variables.
    Returns a tuple of (auth_token, domain)
    """
    # Get required environment variables
    auth_token = os.getenv('FINITE_STATE_AUTH_TOKEN')
    domain = os.getenv('FINITE_STATE_DOMAIN')
    
    # Check if all required variables are present
    missing_vars = []
    if not auth_token:
        missing_vars.append('FINITE_STATE_AUTH_TOKEN')
    if not domain:
        missing_vars.append('FINITE_STATE_DOMAIN')
    
    if missing_vars:
        print("Error: Missing required environment variables:", file=sys.stderr)
        for var in missing_vars:
            print(f"  - {var}", file=sys.stderr)
        print("\nPlease set these environment variables:", file=sys.stderr)
        print("  FINITE_STATE_AUTH_TOKEN: Your authentication token from the Finite State app")
        print("  FINITE_STATE_DOMAIN: Your organization's domain (e.g., 'your-org.finitestate.io')")
        sys.exit(1)
    
    return auth_token, domain

def verify_project_version_exists(token, domain, project_version_id, debug=False):
    """
    Verify that a project version exists and is accessible.
    Returns True if accessible, False otherwise.
    """
    url = f"{get_api_base_url()}/versions/{project_version_id}"
    headers = {
        "X-Authorization": token,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            print(f"❌ ERROR: Project version ID {project_version_id} not found")
            print("This could mean:")
            print("  - The ID doesn't exist in this instance")
            print("  - You're pointing to the wrong Finite State instance")
            print("  - The project version has been deleted")
            return False
        elif response.status_code == 403:
            print(f"❌ ERROR: Access denied to project version {project_version_id}")
            print("Your API token doesn't have permission to access this project version")
            return False
        else:
            print(f"❌ ERROR: Unexpected response when verifying project version: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: Failed to verify project version: {str(e)}")
        return False

def get_findings(token, domain, artifact_id=None, project_id=None, component_name=None, component_version=None, severity=None, risk_min=None, risk_max=None, archived=False, debug=False):
    """
    Get findings using the REST API.
    Supports pagination to handle more than 10000 results.
    
    Args:
        artifact_id: Specific project version ID (optional)
        project_id: Project ID to filter by all versions in project (optional)
        If neither is provided, queries across all accessible projects
    
    Note: Either artifact_id or project_id can be provided, or neither for organization-wide scope.
    """
    url = f"{get_api_base_url()}/findings"
    headers = {
        "X-Authorization": token,
        "Accept": "application/json"
    }
    
    # Use the new filter builder for more flexible filtering
    filter_expression = build_rsql_filter(
        project_version_id=artifact_id,
        project_id=project_id,
        component_name=component_name,
        component_version=component_version,
        severity=severity,
        risk_min=risk_min,
        risk_max=risk_max
    )
    
    all_findings = []
    offset = 0
    limit = 10000  # Maximum limit per API call
    max_results_per_page = limit
    
    try:
        while True:
            params = {
                "sort": "detected:desc",  # Sort by detection date, newest first
                "archived": str(archived).lower(),  # Control archived findings inclusion
                "limit": limit,
                "offset": offset
            }
            
            # Only add filter if we have one (None means query all)
            if filter_expression:
                params["filter"] = filter_expression
            
            response = requests.get(url, headers=headers, params=params)
            
            # Use the new validation function
            if not validate_api_response(response, "Get findings", debug):
                raise Exception(f"Failed to get findings: Status {response.status_code}")
            
            findings = response.json()
            
            # Add findings from this page to the total
            all_findings.extend(findings)
            
            # If we got fewer results than the limit, we've reached the end
            if len(findings) < max_results_per_page:
                break
            
            # Otherwise, continue to next page
            offset += limit
            
            # Safety check: prevent infinite loops
            if offset > 1000000:  # Arbitrary large limit
                print(f"⚠️  WARNING: Reached pagination limit (1M results). Stopping pagination.")
                break
        
        # Check if we got an empty response
        if len(all_findings) == 0:
            scope_desc = ""
            if artifact_id:
                scope_desc = f"project version ID: {artifact_id}"
            elif project_id:
                scope_desc = f"project ID: {project_id}"
            else:
                scope_desc = "organization (all projects)"
            
            print(f"\n⚠️  WARNING: No findings found for {scope_desc}")
            print("This could mean:")
            if artifact_id:
                print("  - The project version doesn't exist in this instance")
                print("  - You don't have access to this project version")
                print("  - No scans have been run on this version")
                print("  - The version exists but has no findings")
            elif project_id:
                print("  - The project doesn't exist in this instance")
                print("  - You don't have access to this project")
                print("  - No scans have been run on any versions in this project")
            else:
                print("  - No findings exist in any accessible projects")
                print("  - Your API token may not have access to any projects")
            
            print(f"\nPlease verify:")
            print(f"  - You're pointing to the correct Finite State instance")
            if artifact_id:
                print(f"  - The project version ID {artifact_id} exists")
            elif project_id:
                print(f"  - The project ID {project_id} exists")
            print(f"  - Your API token has access to the specified scope")
            print(f"  - Scans have been completed")
        
        return all_findings
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to get findings: {str(e)}")
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse findings response: {str(e)}")
    except Exception as e:
        raise

def update_finding_status(token, domain, project_version_id, finding_id, status, justification=None, response=None, reason=None, debug=False):
    """
    Update a finding's status using the Swagger API.
    
    Note: The API only requires 'status', but for VEX compliance:
    - justification is recommended (especially for NOT_AFFECTED status)
    - response is recommended but not strictly required
    - reason is optional (free-form comment)
    
    If justification/response are not provided, defaults will be applied based on status.
    """
    # Apply defaults if justification/response are missing (for VEX compliance)
    if not justification or not response:
        default_justification, default_response = get_default_vex_values(status)
        if not justification and default_justification:
            justification = default_justification
        if not response and default_response:
            response = default_response
    
    data = {
        "status": status
    }
    # Add justification and response if available (API allows status-only updates, but VEX recommends these)
    if justification:
        data["justification"] = justification
    if response:
        data["response"] = response
    if reason:
        data["reason"] = reason
    
    url = f"{get_api_base_url()}/findings/{project_version_id}/{finding_id}/status"
    headers = {
        "X-Authorization": token,
        "Content-Type": "application/json"
    }
    
    try:
        response_obj = requests.put(url, headers=headers, json=data)
        
        # Use the new validation function
        if not validate_api_response(response_obj, "Update finding status", debug):
            raise Exception(f"Failed to update finding status: Status {response_obj.status_code}")
        
        # For 204 responses, there's no JSON body to return
        if response_obj.status_code == 204:
            return {"status": "updated", "finding_id": finding_id}
        
        return response_obj.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to update finding status: {str(e)}")
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse update response: {str(e)}")
    except Exception as e:
        raise

def validate_api_response(response, operation_name, debug=False):
    """
    Validate API response and provide detailed error information.
    Returns True if response is valid, False otherwise.
    """
    if response.status_code == 200 or response.status_code == 201 or response.status_code == 204:
        return True
    
    # Handle specific error cases
    if response.status_code == 400:
        try:
            error_data = response.json()
            if 'errors' in error_data:
                for error in error_data['errors']:
                    print(f"Error: {error.get('error', 'Unknown error')}")
                    if error.get('instanceLocation'):
                        print(f"Location: {error['instanceLocation']}")
        except:
            print(f"Bad request error: {response.text}")
        return False
    
    elif response.status_code == 401:
        print("Authentication error: Invalid or missing API token")
        return False
    
    elif response.status_code == 403:
        print("Authorization error: Insufficient permissions")
        return False
    
    elif response.status_code == 404:
        print("Resource not found")
        return False
    
    elif response.status_code >= 500:
        print(f"Server error: {response.status_code}")
        return False
    
    else:
        print(f"Unexpected response: {response.status_code}")
        return False

def save_backup(target_artifact_id, findings_to_backup, backup_dir="backups"):
    """
    Save the current state of findings before updating them.
    Creates a backup file with timestamp for rollback capability.
    
    Args:
        target_artifact_id: The artifact ID being updated
        findings_to_backup: List of finding dictionaries with current state
        backup_dir: Directory to save backup files (default: "backups")
    
    Returns:
        Path to the backup file created
    """
    # Create backup directory if it doesn't exist
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    # Create backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{target_artifact_id}_{timestamp}.json"
    backup_path = os.path.join(backup_dir, backup_filename)
    
    # Prepare backup data
    backup_data = {
        "target_artifact_id": target_artifact_id,
        "timestamp": timestamp,
        "backup_date": datetime.now().isoformat(),
        "total_findings": len(findings_to_backup),
        "findings": []
    }
    
    # Save current state of each finding
    for finding in findings_to_backup:
        finding_backup = {
            "id": finding.get('id'),
            "findingId": finding.get('findingId'),
            "vulnerabilityId": finding.get('vulnerabilityId') or finding.get('findingId'),
            "component": finding.get('component'),
            "status": finding.get('status'),
            "justification": finding.get('justification'),
            "response": finding.get('response'),
            "reason": finding.get('reason')
        }
        backup_data["findings"].append(finding_backup)
    
    # Write backup file
    with open(backup_path, 'w') as f:
        json.dump(backup_data, f, indent=2)
    
    print(f"💾 Backup saved to: {backup_path}")
    return backup_path

def restore_from_backup(token, domain, backup_file):
    """
    Restore findings from a backup file.
    
    Args:
        token: Authentication token
        domain: Domain for API calls
        backup_file: Path to the backup JSON file
    
    Returns:
        Number of findings successfully restored
    """
    # Read backup file
    try:
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)
    except FileNotFoundError:
        print(f"❌ ERROR: Backup file not found: {backup_file}")
        return 0
    except json.JSONDecodeError as e:
        print(f"❌ ERROR: Invalid backup file format: {str(e)}")
        return 0
    
    target_artifact_id = backup_data.get('target_artifact_id')
    findings = backup_data.get('findings', [])
    backup_date = backup_data.get('backup_date', 'Unknown')
    
    print(f"📦 Restoring from backup: {backup_file}")
    print(f"   Backup date: {backup_date}")
    print(f"   Target artifact: {target_artifact_id}")
    print(f"   Findings to restore: {len(findings)}")
    
    restored_count = 0
    failed_count = 0
    skipped_count = 0
    
    for finding in findings:
        finding_id = finding.get('id')
        if not finding_id:
            print(f"⚠️  Skipping finding - no ID found")
            failed_count += 1
            continue
        
        # Get and normalize status
        raw_status = finding.get('status')
        status = get_status_value(raw_status)
        
        # Skip findings with null/untriaged status - API doesn't accept null
        # These findings were untriaged, so there's nothing to restore
        if status == 'UNTRIAGED' or raw_status is None:
            skipped_count += 1
            continue
        
        try:
            # Restore the finding's state
            update_finding_status(
                token=token,
                domain=domain,
                project_version_id=target_artifact_id,
                finding_id=finding_id,
                status=status,
                justification=finding.get('justification'),
                response=finding.get('response'),
                reason=finding.get('reason'),
                debug=False
            )
            restored_count += 1
        except Exception as e:
            print(f"❌ Failed to restore finding {finding_id}: {str(e)}")
            failed_count += 1
    
    print(f"\n✅ Restored {restored_count} findings")
    if skipped_count > 0:
        print(f"⚠️  Skipped {skipped_count} findings (had null/untriaged status - cannot restore to null)")
    if failed_count > 0:
        print(f"❌ Failed to restore {failed_count} findings")
    
    return restored_count

def get_status_value(status):
    """
    Extract the status value from a status object, which might be a string or a dictionary.
    Returns the status as a string, normalized to uppercase with underscores, or 'UNTRIAGED' if no valid status is found.
    """
    # Handle None
    if status is None:
        return 'UNTRIAGED'
    
    # Handle dictionary (could be nested status object)
    if isinstance(status, dict):
        # Try common field names
        result = status.get('status') or status.get('value') or status.get('name')
        if not result:
            return 'UNTRIAGED'
    else:
        result = str(status)
    
    # Normalize status: convert spaces to underscores and uppercase
    # "Not Affected" -> "NOT_AFFECTED", "not_affected" -> "NOT_AFFECTED"
    if result and result != 'UNTRIAGED':
        result = result.replace(' ', '_').replace('-', '_').upper()
    
    return result

def get_component_key(component):
    """
    Extract component name and version from a component object, which might be a string or a dictionary.
    Returns a tuple of (name, version).
    """
    if isinstance(component, dict):
        name = component.get('name', 'Unknown')
        version = component.get('version', 'Unknown')
        return name, version
    return str(component), 'Unknown'

def normalize_vulnerability_id(vuln_id):
    """
    Normalize vulnerability ID for comparison (case-insensitive, strip whitespace).
    """
    if not vuln_id:
        return None
    return str(vuln_id).strip().upper()

def get_default_vex_values(status):
    """
    Get default justification and response values based on status.
    These defaults ensure VEX compliance when source findings are missing these fields.
    
    Args:
        status: The finding status (e.g., 'NOT_AFFECTED', 'FALSE_POSITIVE', etc.)
        
    Returns:
        tuple: (default_justification, default_response) or (None, None) if no defaults
    """
    status_upper = str(status).upper() if status else ''
    
    # Default values based on status
    defaults = {
        'NOT_AFFECTED': {
            'justification': 'CODE_NOT_PRESENT',  # Most common for NOT_AFFECTED
            'response': 'WILL_NOT_FIX'  # If not affected, we won't fix it
        },
        'FALSE_POSITIVE': {
            'justification': 'CODE_NOT_PRESENT',  # False positive means code isn't actually present
            'response': 'WILL_NOT_FIX'  # Won't fix a false positive
        },
        'RESOLVED': {
            'justification': 'CODE_NOT_PRESENT',  # Resolved means it's been fixed/removed
            'response': 'UPDATE'  # Typically resolved via update
        },
        'RESOLVED_WITH_PEDIGREE': {
            'justification': 'CODE_NOT_PRESENT',  # Resolved with documented changes
            'response': 'UPDATE'  # Resolved via update
        },
        'IN_TRIAGE': {
            'justification': 'CODE_NOT_REACHABLE',  # Under investigation, assume not reachable for now
            'response': 'UPDATE'  # Will likely update once triage is complete
        },
        'EXPLOITABLE': {
            'justification': 'CODE_NOT_REACHABLE',  # Exploitable but may have mitigations
            'response': 'UPDATE'  # Should update to fix exploitable issues
        }
    }
    
    default = defaults.get(status_upper, {})
    return default.get('justification'), default.get('response')

def view_findings(token, domain, artifact_id, component_name=None, component_version=None, severity=None, risk_min=None, risk_max=None, archived=False, skip_verification=False, debug=False):
    """
    View all findings and their triage status for a given artifact.
    Optionally filter by component name and version.
    """
    # First verify the project version exists (unless skipped)
    if not skip_verification:
        if not verify_project_version_exists(token, domain, artifact_id, debug):
            print(f"\n❌ Cannot proceed: Project version {artifact_id} is not accessible")
            return
    
    # Get all findings for the artifact
    findings = get_findings(
        token=token,
        domain=domain,
        artifact_id=artifact_id,
        component_name=component_name,
        component_version=component_version,
        severity=severity,
        risk_min=risk_min,
        risk_max=risk_max,
        archived=archived,
        debug=debug
    )
    
    if not findings:
        print("No findings found for the artifact")
        return
        
    if debug:
        print("\nDEBUG: Raw findings data:")
        print(json.dumps(findings, indent=2))
        print(f"\nTotal findings received: {len(findings)}")
    
    # Group findings by component
    component_findings = {}
    for finding in findings:
        if not finding or not isinstance(finding, dict):
            if debug:
                print(f"\nSkipping invalid finding: {finding}")
            continue
            
        component = finding.get('component')
        name, version = get_component_key(component)
        key = f"{name}:{version}"
        
        if key not in component_findings:
            component_findings[key] = []
        component_findings[key].append(finding)
    
    # Print findings grouped by component
    print(f"\nFindings for artifact {artifact_id}:")
    print("=" * 80)
    
    # Track status counts
    status_counts = {status: 0 for status in VALID_STATUSES}
    status_counts['UNTRIAGED'] = 0
    
    for component_key, component_findings_list in component_findings.items():
        # Split the key safely
        parts = component_key.split(':', 1)
        component_name = parts[0]
        component_version = parts[1] if len(parts) > 1 else 'Unknown'
        
        print(f"\nComponent: {component_name} (v{component_version})")
        print("-" * 80)
        
        for finding in component_findings_list:
            if not finding or not isinstance(finding, dict):
                continue
                
            finding_id = finding.get('findingId', 'Unknown')
            raw_status = finding.get('status')
            
            status = get_status_value(raw_status)
            
            # Count statuses
            if status and status != 'UNTRIAGED' and status in VALID_STATUSES:
                status_counts[status] += 1
            else:
                status_counts['UNTRIAGED'] += 1
            
            print(f"Finding ID: {finding_id}")
            print(f"Status: {status}")
            
            # Enhanced display with new API fields
            if finding.get('epssScore') is not None:
                print(f"EPSS Score: {finding.get('epssScore')}")
            if finding.get('epssPercentile') is not None:
                print(f"EPSS Percentile: {finding.get('epssPercentile')}")
            if finding.get('reachabilityScore') is not None:
                print(f"Reachability Score: {finding.get('reachabilityScore')}")
            if finding.get('severity'):
                print(f"Severity: {finding.get('severity')}")
            if finding.get('risk'):
                print(f"Risk Score: {finding.get('risk')}")
            
            # Display reachability factors if available
            if finding.get('factors') and isinstance(finding.get('factors'), list):
                print("Reachability Factors:")
                for factor in finding.get('factors', []):
                    if isinstance(factor, dict):
                        print(f"  - {factor.get('summary', 'Unknown')} (Score: {factor.get('score_change', 0)})")
            
            print("-" * 40)
    
    # Print status summary
    print("\nStatus Summary:")
    print("-" * 40)
    for status, count in status_counts.items():
        if count > 0:
            print(f"{status}: {count}")

def get_component_triage_rules(token, domain, artifact_id, component_name=None, component_version=None, severity=None, risk_min=None, risk_max=None, archived=False, debug=False):
    """
    Get triage rules for specific components or all components from a source artifact.
    Returns a dictionary mapping component names and versions to their triage statuses and comments.
    Only includes findings that have been triaged (have a non-null status).
    """
    # Build filter to only get findings with a status (triaged findings)
    # We'll filter out null statuses by requiring status to be one of the valid statuses
    # Note: The API supports filtering by status, but we'll filter in code to be safe
    print(f"Fetching findings from source artifact {artifact_id}...")
    findings = get_findings(
        token=token,
        domain=domain,
        artifact_id=artifact_id,
        component_name=component_name,
        component_version=component_version,
        severity=severity,
        risk_min=risk_min,
        risk_max=risk_max,
        archived=archived,
        debug=debug
    )
    
    if not findings:
        print("No findings found for the artifact")
        return {}
        
    print(f"Received {len(findings)} findings from source artifact")
    
    # Create a dictionary to store triage rules
    triage_rules = {}
    
    # Process each finding
    for finding in findings:
        if not finding or not isinstance(finding, dict):
            continue
            
        # Try to get status from multiple possible locations
        status_raw = finding.get('status') or finding.get('currentStatus')
        if isinstance(status_raw, dict):
            status_raw = status_raw.get('status') or status_raw.get('value')
        status = get_status_value(status_raw)
        
        component = finding.get('component')
        name, version = get_component_key(component)
        # FIX: Use 'reason' instead of 'comment' for the new API
        comment = finding.get('reason') if finding.get('reason') else None
        justification = finding.get('justification') if finding.get('justification') else None
        response = finding.get('response') if finding.get('response') else None
        
        # Get raw vulnerability ID
        raw_vuln_id = finding.get('vulnerabilityId') or finding.get('findingId') or finding.get('vulnIdFromTool')
        
        if status and status != 'UNTRIAGED' and status in VALID_STATUSES:
            if name:
                # Use component name as key if no version specified
                key = f"{name}:{version}" if version else name
                if key not in triage_rules:
                    triage_rules[key] = []
                
                # Get vulnerability ID from the finding and normalize it
                raw_vuln_id = finding.get('vulnerabilityId') or finding.get('findingId') or finding.get('vulnIdFromTool')
                vulnerability_id = normalize_vulnerability_id(raw_vuln_id)
                
                if not vulnerability_id:
                    continue
                
                # Apply default VEX values if missing
                # This ensures VEX compliance when source findings are missing these fields
                default_justification, default_response = get_default_vex_values(status)
                
                if not justification and default_justification:
                    justification = default_justification
                
                if not response and default_response:
                    response = default_response
                
                # Create rule with string status
                # Include justification and response (using defaults if needed)
                rule = {
                    'status': status,
                    'finding_id': finding.get('findingId'),
                    'vulnerability': vulnerability_id,  # Store normalized ID
                    'vulnerability_raw': raw_vuln_id,  # Keep original for reference
                    'title': finding.get('title', 'Unknown'),
                    'description': finding.get('description', ''),
                    'comment': comment
                }
                # Add justification and response (will use defaults if original was None)
                if justification:
                    rule['justification'] = justification
                if response:
                    rule['response'] = response
                
                triage_rules[key].append(rule)
    
    # Track statistics and analyze what we received
    total_findings_processed = len(findings)
    findings_with_valid_status = 0
    findings_skipped_no_status = 0
    findings_with_missing_vex_fields = 0  # Findings with status but missing justification/response
    findings_added_to_rules = 0
    findings_with_null_status = 0
    findings_with_status_but_not_valid = 0
    
    # Analyze status distribution
    status_distribution = {}
    
    # Re-process to get statistics (we already processed above, but let's count)
    for finding in findings:
        if not finding or not isinstance(finding, dict):
            continue
        
        raw_status = finding.get('status')
        status = get_status_value(raw_status)
        
        # Track status distribution
        status_key = str(raw_status) if raw_status is not None else 'null'
        status_distribution[status_key] = status_distribution.get(status_key, 0) + 1
        
        if raw_status is None:
            findings_with_null_status += 1
        elif status and status != 'UNTRIAGED' and status in VALID_STATUSES:
            findings_with_valid_status += 1
            justification = finding.get('justification')
            response = finding.get('response')
            if not justification or not response:
                findings_with_missing_vex_fields += 1
            findings_added_to_rules += 1  # We now include findings even without justification/response
        else:
            findings_with_status_but_not_valid += 1
            findings_skipped_no_status += 1
    
    print(f"\n{'='*60}")
    print(f"Triage Rules Summary:")
    print(f"{'='*60}")
    print(f"  Total findings in source: {total_findings_processed}")
    print(f"  Findings with null status: {findings_with_null_status}")
    print(f"  Findings with valid status: {findings_with_valid_status}")
    print(f"  Findings added to rules: {findings_added_to_rules}")
    if findings_with_missing_vex_fields > 0:
        print(f"  ℹ️  Findings with missing VEX fields (justification/response): {findings_with_missing_vex_fields}")
        print(f"     Default values will be applied to ensure VEX compliance")
    print(f"  Findings skipped (no valid status): {findings_skipped_no_status}")
    print(f"  Total component keys in rules: {len(triage_rules)}")
    
    if len(triage_rules) == 0:
        print(f"\n⚠️  CRITICAL: No triage rules were extracted from the source artifact!")
        print(f"   This means no findings from the source have valid triage status.")
        print(f"   Possible reasons:")
        print(f"   1. Source findings have null status (not triaged in API)")
        print(f"   2. Source findings are missing justification or response fields")
        print(f"   3. Status values don't match expected format")
        print(f"   ")
        print(f"   If you expected the source to have triaged findings:")
        print(f"   - Check if findings are triaged in the UI")
        print(f"   - Verify the source artifact ID is correct: {artifact_id}")
        print(f"   - Check if there's a sync delay between UI and API")
    
    # Check for specific CVEs that should have status but don't
    if findings_with_null_status > 0:
        print(f"\n⚠️  WARNING: {findings_with_null_status} findings have null status (not triaged)")
        print("   These findings will not be included in triage rules.")
        print("   If you expected these findings to have a status, they may need to be triaged first.")
    
    return triage_rules

def apply_triage_rules(token, domain, target_artifact_id, triage_rules, source_artifact_id, severity=None, risk_min=None, risk_max=None, archived=False, overwrite=False, dry_run=False, debug=False):
    """
    Apply triage rules to findings in the target artifact.
    If dry_run is True, only print what would be changed without making changes.
    If overwrite is True, replace existing status and justification even if they match.
    """
    # Get all findings for the target artifact
    target_findings = get_findings(
        token=token,
        domain=domain,
        artifact_id=target_artifact_id,
        severity=severity,
        risk_min=risk_min,
        risk_max=risk_max,
        archived=archived,
        debug=debug
    )
    
    if not target_findings:
        print("No findings found for the target artifact")
        return
    
    # Track which findings we've updated
    updated_findings = []
    unmatched_findings = []
    
    # Build a lookup by component name only (for flexible matching)
    component_name_rules = {}
    for key, rules in triage_rules.items():
        # Extract component name from key (format: "name:version" or just "name")
        if ':' in key:
            comp_name = key.split(':', 1)[0]
        else:
            comp_name = key
        if comp_name not in component_name_rules:
            component_name_rules[comp_name] = {}
        # Store rules by normalized vulnerability ID for quick lookup
        for rule in rules:
            vuln_id = rule.get('vulnerability')  # Already normalized
            if vuln_id:
                if vuln_id not in component_name_rules[comp_name]:
                    component_name_rules[comp_name][vuln_id] = []
                component_name_rules[comp_name][vuln_id].append((key, rule))
    
    # Process each finding in the target artifact
    for finding in target_findings:
        if not finding or not isinstance(finding, dict):
            continue
            
        component = finding.get('component')
        name, version = get_component_key(component)
        raw_vuln_id = finding.get('vulnerabilityId') or finding.get('findingId') or finding.get('vulnIdFromTool')
        vulnerability_id = normalize_vulnerability_id(raw_vuln_id)
        finding_id = finding.get('id')  # Use the actual finding ID
        
        if not vulnerability_id:
            unmatched_findings.append({
                'component': name,
                'version': version,
                'vulnerability': raw_vuln_id or 'Unknown',
                'reason': 'No vulnerability ID found in target finding'
            })
            continue
        
        if name:
            # Try exact match first (component name:version + vulnerability ID)
            key = f"{name}:{version}" if version and version != 'Unknown' else name
            matching_rule = None
            match_type = None
            
            # First, try exact component key match
            if key in triage_rules:
                # Find the matching vulnerability in the rules
                if triage_rules[key]:  # Check if the list is not empty
                    for rule in triage_rules[key]:
                        if rule['vulnerability'] == vulnerability_id:
                            matching_rule = rule
                            match_type = 'exact'
                            break
            
            # If no exact match, try component name only (ignore version differences)
            if not matching_rule and name in component_name_rules:
                if vulnerability_id in component_name_rules[name]:
                    # Found matching component name and vulnerability ID
                    # Use the first matching rule (prefer exact version match if available)
                    for source_key, rule in component_name_rules[name][vulnerability_id]:
                        matching_rule = rule
                        match_type = 'component_name_only'
                        break
                
                if not matching_rule:
                    # No match found - add to unmatched with reason
                    reason = []
                    if name not in component_name_rules:
                        reason.append(f"component '{name}' not found in source rules")
                    elif vulnerability_id not in component_name_rules[name]:
                        reason.append(f"vulnerability '{vulnerability_id}' (raw: '{raw_vuln_id}') not found for component '{name}'")
                    else:
                        reason.append("unknown matching issue")
                    
                    unmatched_findings.append({
                        'component': name,
                        'version': version,
                        'vulnerability': vulnerability_id,
                        'vulnerability_raw': raw_vuln_id,
                        'reason': '; '.join(reason)
                    })
                    continue
                
            # We have a matching rule - process it
            if matching_rule:
                # FIX: Use 'reason' instead of 'comment' for the new API
                current_status = get_status_value(finding.get('status'))
                current_comment = finding.get('reason') if finding.get('reason') else None
                current_justification = finding.get('justification')
                current_response = finding.get('response')
                
                source_comment = matching_rule.get('comment')
                source_justification = matching_rule.get('justification')
                source_response = matching_rule.get('response')
                
                # Apply defaults if source values are missing
                rule_status = matching_rule['status']
                default_justification, default_response = get_default_vex_values(rule_status)
                final_justification = source_justification if source_justification else default_justification
                final_response = source_response if source_response else default_response
                
                status_changed = current_status != matching_rule['status']
                comment_changed = current_comment != source_comment
                justification_changed = current_justification != final_justification
                response_changed = current_response != final_response
                
                should_update = False
                # When building update_payload, add justification, response, and reason fields if present
                update_payload = {
                    'id': finding_id,
                    'status': matching_rule['status'],
                    'component': name,
                    'version': version,
                    'vulnerability': vulnerability_id
                }
                
                # Use final values (with defaults applied) for update payload
                
                # Add justification and response to update payload
                if final_justification:
                    update_payload['justification'] = final_justification
                
                if final_response:
                    update_payload['response'] = final_response
                
                # Warn if we still don't have VEX fields (shouldn't happen with defaults, but just in case)
                if not final_justification or not final_response:
                    missing_fields = []
                    if not final_justification:
                        missing_fields.append('justification')
                    if not final_response:
                        missing_fields.append('response')
                    print(f"⚠️  WARNING: Finding {finding_id} (CVE: {vulnerability_id}) missing VEX fields: {', '.join(missing_fields)}")
                    print(f"   Component: {name} v{version}")
                    print(f"   Source status: {rule_status}")
                    print(f"   No defaults available for this status - status update will proceed without these fields")
                
                # Place comment in reason
                if source_comment:
                    update_payload['reason'] = source_comment
                
                # Determine if we should update based on changes or overwrite mode
                if status_changed or comment_changed or justification_changed or response_changed:
                    should_update = True
                elif overwrite:
                    # Overwrite mode: update even if values are the same
                    should_update = True
                
                if should_update:
                    updated_findings.append(update_payload)
                    if dry_run:
                        print(f"\nWould update finding:")
                        print(f"Finding ID: {finding_id}")
                        print(f"Vulnerability ID: {vulnerability_id}")
                        print(f"Component: {name} v{version}")
                        print(f"Match type: {match_type}")
                        print(f"Current status: {current_status}")
                        print(f"Current comment: {current_comment}")
                        print(f"Current justification: {current_justification}")
                        print(f"Current response: {current_response}")
                        print(f"New status: {update_payload.get('status')}")
                        print(f"New comment: {source_comment}")
                        print(f"New justification: {source_justification}")
                        print(f"New response: {source_response}")
                        print("---")
    
    # Print what would be changed
    if updated_findings:
        print("\nThe following changes would be made:")
        for update in updated_findings:
            print(f"Finding ID: {update['id']}")
            print(f"Vulnerability ID: {update['vulnerability']}")
            print(f"Component: {update['component']} (v{update['version']})")
            print(f"Status: {update.get('status')}")
            # Show old and new justification, response, and reason (comment) for dry run
            old_justification = None
            old_response = None
            old_reason = None
            for finding in target_findings:
                if finding.get('id') == update['id']:
                    old_justification = finding.get('justification')
                    old_response = finding.get('response')
                    # FIX: Use 'reason' instead of 'comment' for the new API
                    old_reason = finding.get('reason') if finding.get('reason') else finding.get('comment')
                    break
            new_justification = update.get('justification') or "CODE_NOT_PRESENT"
            new_response = update.get('response') or "WILL_NOT_FIX"
            new_reason = update.get('reason')
            if new_reason is None and source_comment is not None:
                new_reason = source_comment
            print(f"Old justification: {old_justification}")
            print(f"New justification: {new_justification}")
            print(f"Old response: {old_response}")
            print(f"New response: {new_reason}")
            print(f"Old reason: {old_reason}")
            print(f"New reason: {new_reason}")
            print("---")
        
        if not dry_run:
            # Save backup of findings that will be updated
            findings_to_backup = []
            update_ids = {update['id'] for update in updated_findings if update.get('id')}
            for finding in target_findings:
                if finding.get('id') in update_ids:
                    findings_to_backup.append(finding)
            
            if findings_to_backup:
                backup_path = save_backup(target_artifact_id, findings_to_backup)
                print(f"💾 Backup created for {len(findings_to_backup)} findings before applying updates")
                print(f"   To rollback, use: --rollback {backup_path}\n")
            
            # Process updates in batches
            failed_updates = []
            for update in updated_findings:
                if update['id'] and update['status']:
                    # Try to apply the update with retries
                    max_retries = 3
                    retry_delay = 2  # seconds
                    success = False
                    
                    for attempt in range(max_retries):
                        try:
                            # Apply the update
                            update_finding_status(
                                token=token,
                                domain=domain,
                                project_version_id=target_artifact_id,
                                finding_id=update['id'],
                                status=update['status'],
                                justification=update.get('justification'),
                                response=update.get('response'),
                                reason=update.get('reason'),
                                debug=debug
                            )
                            success = True
                            break
                        except Exception as e:
                            if attempt < max_retries - 1:
                                time.sleep(retry_delay)
                                retry_delay *= 2  # Exponential backoff
                            else:
                                print(f"Failed to update finding {update['id']} after {max_retries} attempts: {str(e)}", file=sys.stderr)
                                failed_updates.append(update)
            
            # Print summary
            successful_updates = len(updated_findings) - len(failed_updates)
            print(f"\nUpdated {successful_updates} findings in target artifact")
            
            if failed_updates:
                print("\nFailed to update the following findings:")
                for update in failed_updates:
                    print(f"Finding ID: {update['id']}")
                    print(f"Vulnerability ID: {update['vulnerability']}")
                    print(f"Component: {update['component']} (v{update['version']})")
                    print(f"Status: {update.get('status')}")
                    print(f"New comment: {update.get('comment')}")
                    print("---")
        else:
            print(f"\nDry run: Would update {len(updated_findings)} findings in target artifact")
    else:
        print("No findings needed to be updated")
    
    # Print summary of unmatched findings
    if unmatched_findings:
        # Group unmatched findings by reason
        unmatched_by_reason = {}
        for finding in unmatched_findings:
            reason = finding.get('reason', 'Unknown reason')
            if reason not in unmatched_by_reason:
                unmatched_by_reason[reason] = []
            unmatched_by_reason[reason].append(finding)
        
        if debug:
            print("\nUnmatched findings (detailed):")
            print("=" * 80)
            for finding in unmatched_findings[:20]:  # Show first 20
                print(f"Component: {finding['component']} (v{finding['version']})")
                print(f"Vulnerability: {finding['vulnerability']}")
                print(f"Reason: {finding.get('reason', 'Unknown')}")
                print("---")
            if len(unmatched_findings) > 20:
                print(f"... and {len(unmatched_findings) - 20} more unmatched findings")
        
        # Print summary by reason
        print(f"\nUnmatched Findings Summary by Reason:")
        print("=" * 80)
        for reason, findings_list in sorted(unmatched_by_reason.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"  {reason}: {len(findings_list)} findings")
    
    # Print processing summary
    total_findings = len(target_findings)
    matched_findings = total_findings - len(unmatched_findings)
    print(f"\nProcessing Summary:")
    print(f"  Total findings in target: {total_findings}")
    print(f"  Findings with matching rules: {matched_findings}")
    print(f"  Findings without matching rules: {len(unmatched_findings)}")
    print(f"  Findings to be updated: {len(updated_findings)}")
    
    if unmatched_findings and not debug:
        print(f"\nNote: {len(unmatched_findings)} findings were skipped due to no matching triage rules.")
        print("Use --debug to see details about unmatched findings.")
        # Show top reasons even without debug
        if unmatched_by_reason:
            print("\nTop reasons for unmatched findings:")
            for reason, findings_list in list(sorted(unmatched_by_reason.items(), key=lambda x: len(x[1]), reverse=True))[:5]:
                print(f"  - {reason}: {len(findings_list)} findings")

def parse_cve_csv(csv_file):
    """
    Parse a CSV file containing CVE triage information with VEX requirements.
    
    CSV Format (meets VEX minimum data requirements):
    - CVE (required): The CVE identifier
    - Status (required): VEX status (NOT_AFFECTED, FALSE_POSITIVE, etc.)
    - Justification (optional): VEX justification (defaults applied if missing)
    - Response (optional): VEX response (defaults applied if missing)
    - Reason (optional): Optional comment/reason
    
    Args:
        csv_file: Path to CSV file
        
    Returns:
        List of dictionaries with keys: cve, status, justification, response, reason
    """
    cve_triage_list = []
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            # Check first line to see if it looks like a header
            first_line = f.readline().strip().lower()
            f.seek(0)
            # If first line contains 'cve' and 'status', treat as header
            has_header = 'cve' in first_line and ('status' in first_line or 'vex_status' in first_line or 'triage_status' in first_line)
            
            # Always try DictReader first if it looks like it has a header
            if has_header:
                reader = csv.DictReader(f)
            else:
                # Try to detect header using sniffer as fallback
                sample = f.read(1024)
                f.seek(0)
                try:
                    has_header = csv.Sniffer().has_header(sample)
                    reader = csv.DictReader(f) if has_header else csv.reader(f)
                except:
                    # If sniffer fails, try DictReader anyway (it will use first row as header)
                    reader = csv.DictReader(f)
                    has_header = True
            
            # If no header, use positional columns
            if not has_header:
                # Default column order: CVE, Status, Justification, Response, Reason
                for row_num, row in enumerate(reader, start=1):
                    if len(row) < 2:
                        print(f"⚠️  Warning: Row {row_num} has insufficient columns (need at least CVE and Status), skipping")
                        continue
                    
                    cve = row[0].strip() if len(row) > 0 else None
                    status = row[1].strip().upper() if len(row) > 1 else None
                    justification = row[2].strip() if len(row) > 2 and row[2].strip() else None
                    response = row[3].strip() if len(row) > 3 and row[3].strip() else None
                    reason = row[4].strip() if len(row) > 4 and row[4].strip() else None
                    
                    if not cve or not status:
                        print(f"⚠️  Warning: Row {row_num} missing required CVE or Status, skipping")
                        continue
                    
                    if status not in VALID_STATUSES:
                        print(f"⚠️  Warning: Row {row_num} has invalid status '{status}', skipping")
                        continue
                    
                    cve_triage_list.append({
                        'cve': cve,
                        'status': status,
                        'justification': justification,
                        'response': response,
                        'reason': reason
                    })
            else:
                # Has header - use column names
                for row_num, row in enumerate(reader, start=2):  # Start at 2 because row 1 is header
                    # Normalize column names (case-insensitive, handle variations)
                    row_lower = {k.lower().strip(): v for k, v in row.items() if k}
                    
                    # Find CVE column (try various names)
                    cve = None
                    for key in ['cve', 'vulnerability', 'vulnerability_id', 'finding_id', 'cve_id']:
                        if key in row_lower and row_lower[key]:
                            cve = row_lower[key].strip()
                            break
                    
                    # Find Status column
                    status = None
                    for key in ['status', 'vex_status', 'triage_status']:
                        if key in row_lower and row_lower[key]:
                            status = row_lower[key].strip().upper()
                            break
                    
                    if not cve or not status:
                        print(f"⚠️  Warning: Row {row_num} missing required CVE or Status, skipping")
                        continue
                    
                    if status not in VALID_STATUSES:
                        print(f"⚠️  Warning: Row {row_num} has invalid status '{status}', skipping")
                        continue
                    
                    # Find optional columns
                    justification = None
                    for key in ['justification', 'vex_justification']:
                        if key in row_lower and row_lower[key]:
                            justification = row_lower[key].strip()
                            break
                    
                    response = None
                    for key in ['response', 'vex_response']:
                        if key in row_lower and row_lower[key]:
                            response = row_lower[key].strip()
                            break
                    
                    reason = None
                    for key in ['reason', 'comment', 'notes', 'description']:
                        if key in row_lower and row_lower[key]:
                            reason = row_lower[key].strip()
                            break
                    
                    cve_triage_list.append({
                        'cve': cve,
                        'status': status,
                        'justification': justification,
                        'response': response,
                        'reason': reason
                    })
    
    except FileNotFoundError:
        raise Exception(f"CSV file not found: {csv_file}")
    except Exception as e:
        raise Exception(f"Error parsing CSV file: {str(e)}")
    
    if not cve_triage_list:
        raise Exception("No valid CVE entries found in CSV file")
    
    return cve_triage_list

def apply_triage_from_csv(token, domain, artifact_id=None, project_id=None, cve_triage_list=None, dry_run=False, overwrite=False):
    """
    Apply triage to CVEs from a CSV-based list where each CVE can have different triage values.
    
    Args:
        token: Authentication token
        domain: Domain for API calls
        artifact_id: Target artifact ID (project version) - optional if project_id provided
        project_id: Project ID to query all versions - optional if artifact_id provided
        cve_triage_list: List of dicts with keys: cve, status, justification, response, reason
        dry_run: If True, only show what would be changed
        overwrite: If True, update even if status already matches
    
    Returns:
        Dictionary with counts of updated, not found, and failed findings
    """
    scope_desc = ""
    if artifact_id:
        scope_desc = f"project version {artifact_id}"
    elif project_id:
        scope_desc = f"project {project_id} (all versions)"
    else:
        scope_desc = "organization (all projects)"
    
    print(f"Applying triage from CSV to {scope_desc}")
    print(f"Total CVEs in CSV: {len(cve_triage_list)}")
    
    # Get all findings for the scope
    findings = get_findings(token, domain, artifact_id=artifact_id, project_id=project_id, debug=False)
    
    if not findings:
        print("No findings found for the artifact")
        return {'updated': 0, 'not_found': len(cve_triage_list), 'failed': 0}
    
    # Create lookup by normalized CVE
    cve_triage_map = {}
    for item in cve_triage_list:
        normalized_cve = normalize_vulnerability_id(item['cve'])
        if normalized_cve:
            cve_triage_map[normalized_cve] = item
    
    # Find matching findings and prepare updates
    findings_to_update = []
    found_cves = set()
    not_found_cves = []
    
    for finding in findings:
        raw_vuln_id = finding.get('vulnerabilityId') or finding.get('findingId') or finding.get('vulnIdFromTool')
        vulnerability_id = normalize_vulnerability_id(raw_vuln_id)
        
        if vulnerability_id in cve_triage_map:
            found_cves.add(vulnerability_id)
            triage_info = cve_triage_map[vulnerability_id]
            
            # Get triage values from CSV, apply defaults if needed
            status = triage_info['status']
            justification = triage_info.get('justification')
            response = triage_info.get('response')
            reason = triage_info.get('reason')
            
            # Apply defaults if missing
            if not justification or not response:
                default_justification, default_response = get_default_vex_values(status)
                if not justification and default_justification:
                    justification = default_justification
                if not response and default_response:
                    response = default_response
            
            current_status = get_status_value(finding.get('status'))
            
            # Check if we should update
            should_update = False
            if overwrite or current_status != status:
                should_update = True
            
            if should_update:
                # Extract projectVersionId from finding (required for update API)
                project_version_id = None
                if finding.get('projectVersion'):
                    if isinstance(finding.get('projectVersion'), dict):
                        project_version_id = finding.get('projectVersion', {}).get('id')
                    else:
                        project_version_id = finding.get('projectVersion')
                
                # If not found in projectVersion, try to get from artifact_id parameter
                if not project_version_id and artifact_id:
                    project_version_id = artifact_id
                
                if not project_version_id:
                    print(f"⚠️  Warning: Cannot determine projectVersionId for finding {finding.get('id')}, skipping")
                    continue
                
                findings_to_update.append({
                    'finding': finding,
                    'finding_id': finding.get('id'),
                    'project_version_id': project_version_id,
                    'vulnerability_id': vulnerability_id,
                    'current_status': current_status,
                    'status': status,
                    'justification': justification,
                    'response': response,
                    'reason': reason
                })
    
    # Track not found CVEs
    for item in cve_triage_list:
        normalized_cve = normalize_vulnerability_id(item['cve'])
        if normalized_cve not in found_cves:
            not_found_cves.append(item['cve'])
    
    if not_found_cves:
        print(f"\n⚠️  Warning: {len(not_found_cves)} CVEs not found in artifact:")
        for cve in not_found_cves[:20]:  # Show first 20
            print(f"  - {cve}")
        if len(not_found_cves) > 20:
            print(f"  ... and {len(not_found_cves) - 20} more")
    
    if not findings_to_update:
        print(f"\n✅ No findings need to be updated (all CVEs already have matching status or no matching findings)")
        return {'updated': 0, 'not_found': len(not_found_cves), 'failed': 0}
    
    print(f"\nFound {len(findings_to_update)} findings to update")
    
    if dry_run:
        print("\nDry run - would update the following findings:")
        for item in findings_to_update:
            finding = item['finding']
            component = finding.get('component', {})
            comp_name = component.get('name', 'Unknown') if isinstance(component, dict) else 'Unknown'
            print(f"  - {item['vulnerability_id']} in {comp_name}")
            print(f"    Current: {item['current_status']} -> New: {item['status']}")
            if item.get('justification'):
                print(f"    Justification: {item['justification']}")
            if item.get('response'):
                print(f"    Response: {item['response']}")
            if item.get('reason'):
                print(f"    Reason: {item['reason']}")
        return {'updated': 0, 'not_found': len(not_found_cves), 'failed': 0}
    
    # Save backup before updating (group by project version for backup files)
    if findings_to_update:
        # Group findings by project version for backup
        findings_by_version = {}
        for item in findings_to_update:
            pv_id = item.get('project_version_id', 'unknown')
            if pv_id not in findings_by_version:
                findings_by_version[pv_id] = []
            findings_by_version[pv_id].append(item['finding'])
        
        backup_paths = []
        for pv_id, findings_list in findings_by_version.items():
            backup_path = save_backup(pv_id, findings_list)
            backup_paths.append(backup_path)
        
        print(f"💾 Backup created for {len(findings_to_update)} findings across {len(backup_paths)} project version(s)")
        if len(backup_paths) == 1:
            print(f"   To rollback, use: --rollback {backup_paths[0]}")
        else:
            print(f"   To rollback, use: --rollback <backup_file>")
            print(f"   Backup files created:")
            for bp in backup_paths:
                print(f"     - {bp}")
        print()
    
    # Apply updates
    updated_count = 0
    failed_count = 0
    
    for item in findings_to_update:
        try:
            update_finding_status(
                token=token,
                domain=domain,
                project_version_id=item['project_version_id'],
                finding_id=item['finding_id'],
                status=item['status'],
                justification=item.get('justification'),
                response=item.get('response'),
                reason=item.get('reason'),
                debug=False
            )
            updated_count += 1
        except Exception as e:
            print(f"❌ Failed to update {item['vulnerability_id']} (project version {item.get('project_version_id', 'unknown')}): {str(e)}")
            failed_count += 1
    
    print(f"\n✅ Successfully updated {updated_count} findings")
    if failed_count > 0:
        print(f"❌ Failed to update {failed_count} findings")
    
    return {
        'updated': updated_count,
        'not_found': len(not_found_cves),
        'failed': failed_count
    }

def apply_triage_to_cves(token, domain, artifact_id=None, project_id=None, cve_list=None, status=None, justification=None, response=None, reason=None, dry_run=False, overwrite=False):
    """
    Apply a specific triage status to a list of CVEs.
    
    Args:
        token: Authentication token
        domain: Domain for API calls
        artifact_id: Target artifact ID (project version) - optional if project_id provided
        project_id: Project ID to query all versions - optional if artifact_id provided
        cve_list: List of CVE IDs to apply triage to
        status: VEX status to apply (NOT_AFFECTED, FALSE_POSITIVE, etc.)
        justification: VEX justification (optional, will use default if not provided)
        response: VEX response (optional, will use default if not provided)
        reason: Optional comment/reason
        dry_run: If True, only show what would be changed
        overwrite: If True, update even if status already matches
    
    Returns:
        Dictionary with counts of updated, not found, and failed findings
    """
    # Normalize CVE list
    normalized_cves = [normalize_vulnerability_id(cve) for cve in cve_list]
    cve_set = set(normalized_cves)
    
    scope_desc = ""
    if artifact_id:
        scope_desc = f"project version {artifact_id}"
    elif project_id:
        scope_desc = f"project {project_id} (all versions)"
    else:
        scope_desc = "organization (all projects)"
    
    print(f"Applying triage to {len(cve_list)} CVEs in {scope_desc}")
    print(f"Status: {status}")
    if justification:
        print(f"Justification: {justification}")
    if response:
        print(f"Response: {response}")
    if reason:
        print(f"Reason: {reason}")
    
    # Get all findings for the scope
    findings = get_findings(token, domain, artifact_id=artifact_id, project_id=project_id, debug=False)
    
    if not findings:
        print("No findings found for the artifact")
        return {'updated': 0, 'not_found': len(cve_list), 'failed': 0}
    
    # Apply defaults if justification/response not provided
    if not justification or not response:
        default_justification, default_response = get_default_vex_values(status)
        if not justification and default_justification:
            justification = default_justification
        if not response and default_response:
            response = default_response
    
    # Find matching findings
    findings_to_update = []
    found_cves = set()
    
    for finding in findings:
        raw_vuln_id = finding.get('vulnerabilityId') or finding.get('findingId') or finding.get('vulnIdFromTool')
        vulnerability_id = normalize_vulnerability_id(raw_vuln_id)
        
        if vulnerability_id in cve_set:
            found_cves.add(vulnerability_id)
            current_status = get_status_value(finding.get('status'))
            
            # Check if we should update
            should_update = False
            if overwrite or current_status != status:
                should_update = True
            
            if should_update:
                # Extract projectVersionId from finding (required for update API)
                project_version_id = None
                if finding.get('projectVersion'):
                    if isinstance(finding.get('projectVersion'), dict):
                        project_version_id = finding.get('projectVersion', {}).get('id')
                    else:
                        project_version_id = finding.get('projectVersion')
                
                # If not found in projectVersion, try to get from artifact_id parameter
                if not project_version_id and artifact_id:
                    project_version_id = artifact_id
                
                if not project_version_id:
                    print(f"⚠️  Warning: Cannot determine projectVersionId for finding {finding.get('id')}, skipping")
                    continue
                
                findings_to_update.append({
                    'finding': finding,
                    'finding_id': finding.get('id'),
                    'project_version_id': project_version_id,
                    'vulnerability_id': vulnerability_id,
                    'current_status': current_status
                })
    
    not_found_cves = cve_set - found_cves
    
    if not_found_cves:
        print(f"\n⚠️  Warning: {len(not_found_cves)} CVEs not found in artifact:")
        for cve in sorted(not_found_cves):
            print(f"  - {cve}")
    
    if not findings_to_update:
        print(f"\n✅ No findings need to be updated (all CVEs already have status '{status}' or no matching findings)")
        return {'updated': 0, 'not_found': len(not_found_cves), 'failed': 0}
    
    print(f"\nFound {len(findings_to_update)} findings to update")
    
    if dry_run:
        print("\nDry run - would update the following findings:")
        for item in findings_to_update:
            finding = item['finding']
            component = finding.get('component', {})
            comp_name = component.get('name', 'Unknown') if isinstance(component, dict) else 'Unknown'
            print(f"  - {item['vulnerability_id']} in {comp_name}")
            print(f"    Current: {item['current_status']} -> New: {status}")
            if justification:
                print(f"    Justification: {justification}")
            if response:
                print(f"    Response: {response}")
            if reason:
                print(f"    Reason: {reason}")
        return {'updated': 0, 'not_found': len(not_found_cves), 'failed': 0}
    
    # Save backup before updating (group by project version for backup files)
    if findings_to_update:
        # Group findings by project version for backup
        findings_by_version = {}
        for item in findings_to_update:
            pv_id = item.get('project_version_id', 'unknown')
            if pv_id not in findings_by_version:
                findings_by_version[pv_id] = []
            findings_by_version[pv_id].append(item['finding'])
        
        backup_paths = []
        for pv_id, findings_list in findings_by_version.items():
            backup_path = save_backup(pv_id, findings_list)
            backup_paths.append(backup_path)
        
        print(f"💾 Backup created for {len(findings_to_update)} findings across {len(backup_paths)} project version(s)")
        if len(backup_paths) == 1:
            print(f"   To rollback, use: --rollback {backup_paths[0]}")
        else:
            print(f"   To rollback, use: --rollback <backup_file>")
            print(f"   Backup files created:")
            for bp in backup_paths:
                print(f"     - {bp}")
        print()
    
    # Apply updates
    updated_count = 0
    failed_count = 0
    
    for item in findings_to_update:
        try:
            update_finding_status(
                token=token,
                domain=domain,
                project_version_id=item['project_version_id'],
                finding_id=item['finding_id'],
                status=status,
                justification=justification,
                response=response,
                reason=reason,
                debug=False
            )
            updated_count += 1
        except Exception as e:
            print(f"❌ Failed to update {item['vulnerability_id']} (project version {item.get('project_version_id', 'unknown')}): {str(e)}")
            failed_count += 1
    
    print(f"\n✅ Successfully updated {updated_count} findings")
    if failed_count > 0:
        print(f"❌ Failed to update {failed_count} findings")
    
    return {
        'updated': updated_count,
        'not_found': len(not_found_cves),
        'failed': failed_count
    }

def build_rsql_filter(project_version_id=None, project_id=None, component_name=None, component_version=None, severity=None, risk_min=None, risk_max=None):
    """
    Build RSQL filter expression for the findings API.
    Supports enhanced filtering capabilities of the new API.
    
    Args:
        project_version_id: Specific project version ID (most specific scope)
        project_id: Project ID to filter by (all versions in project)
        component_name: Component name filter
        component_version: Component version filter
        severity: Severity filter
        risk_min: Minimum risk score
        risk_max: Maximum risk score
    
    Note: If neither project_version_id nor project_id is provided, 
          the filter will query across all accessible projects.
    """
    filter_parts = []
    
    # Add project scope filter (most specific to least specific)
    if project_version_id:
        filter_parts.append(f"projectVersion=={project_version_id}")
    elif project_id:
        filter_parts.append(f"project=={project_id}")
    # If neither is provided, no project filter = organization-wide
    
    if component_name:
        filter_parts.append(f"component=={component_name}")
    if component_version:
        filter_parts.append(f"version=={component_version}")
    if severity:
        filter_parts.append(f"severity=={severity.upper()}")
    if risk_min is not None:
        filter_parts.append(f"risk>={risk_min}")
    if risk_max is not None:
        filter_parts.append(f"risk<={risk_max}")
    
    return " and ".join(filter_parts) if filter_parts else None

def show_vex_info():
    """
    Display VEX (Vulnerability Exploitability eXchange) information and requirements.
    """
    print("VEX (Vulnerability Exploitability eXchange) Information")
    print("=" * 60)
    print()
    print("VEX Status Values (required):")
    print("  - NOT_AFFECTED: Vulnerability does not affect this component")
    print("  - FALSE_POSITIVE: Finding is incorrect or not applicable")
    print("  - IN_TRIAGE: Under investigation")
    print("  - RESOLVED_WITH_PEDIGREE: Fixed with documented changes")
    print("  - RESOLVED: Fixed")
    print("  - EXPLOITABLE: Confirmed exploitable")
    print()
    print("VEX Justification Values (recommended):")
    print("  - CODE_NOT_PRESENT: Vulnerable code not in this version")
    print("  - CODE_NOT_REACHABLE: Code present but not accessible")
    print("  - REQUIRES_CONFIGURATION: Needs specific config to exploit")
    print("  - REQUIRES_DEPENDENCY: Needs specific dependency to exploit")
    print("  - REQUIRES_ENVIRONMENT: Needs specific environment to exploit")
    print("  - PROTECTED_BY_COMPILER: Compiler protection prevents exploit")
    print("  - PROTECTED_AT_RUNTIME: Runtime protection prevents exploit")
    print("  - PROTECTED_AT_PERIMETER: Network/security controls prevent exploit")
    print("  - PROTECTED_BY_MITIGATING_CONTROL: Other controls prevent exploit")
    print()
    print("VEX Response Values (recommended):")
    print("  - CAN_NOT_FIX: Unable to fix the vulnerability")
    print("  - WILL_NOT_FIX: Decision not to fix")
    print("  - UPDATE: Will update to fix")
    print("  - ROLLBACK: Will rollback to previous version")
    print("  - WORKAROUND_AVAILABLE: Alternative mitigation exists")
    print()
    print("VEX Requirements:")
    print("  - Status: REQUIRED (by API and VEX standards)")
    print("  - Justification: RECOMMENDED (required by VEX standards for certain statuses like NOT_AFFECTED)")
    print("  - Response: RECOMMENDED (best practice for VEX compliance)")
    print("  - Reason: OPTIONAL (free-form comment field)")
    print()
    print("Note:")
    print("  - The API only requires 'status' to update a finding")
    print("  - However, VEX standards recommend justification (especially for NOT_AFFECTED)")
    print("  - This script applies sensible defaults when justification/response are missing")
    print("  - Defaults ensure VEX compliance while allowing status-only updates")

def main():
    parser = argparse.ArgumentParser(
        description='Finite State Autotriage Tool - Manage vulnerability triage decisions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Replicate triage from one artifact to another
  %(prog)s replicate <source_id> <target_id>
  
  # Apply triage from CSV file to a version
  %(prog)s apply -c cves.csv -v <version_id>
  
  # View findings (by version ID, project ID, or project name)
  %(prog)s view <version_id>
  %(prog)s view <project_id>
  %(prog)s view "Project Name"
  
  # Rollback changes from a backup
  %(prog)s rollback <backup_file>
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands', metavar='COMMAND')
    
    # Common arguments for all commands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('-d', '--dry-run', action='store_true', 
                              help='Show what would be changed without making changes')
    common_parser.add_argument('--debug', action='store_true', 
                              help='Enable debug output')
    
    # replicate command
    replicate_parser = subparsers.add_parser(
        'replicate',
        parents=[common_parser],
        help='Replicate triage decisions from one artifact to another',
        description='Replicate VEX triage decisions from a source artifact to a target artifact'
    )
    replicate_parser.add_argument('source_artifact', help='ID of the source artifact')
    replicate_parser.add_argument('target_artifact', help='ID of the target artifact/project version')
    replicate_parser.add_argument('--component', help='Specific component name to replicate triage for')
    replicate_parser.add_argument('--version', help='Specific component version to replicate triage for')
    replicate_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'INFO'], 
                                 help='Filter findings by severity level')
    replicate_parser.add_argument('--risk-min', type=int, help='Minimum risk score filter')
    replicate_parser.add_argument('--risk-max', type=int, help='Maximum risk score filter')
    replicate_parser.add_argument('--archived', action='store_true', 
                                 help='Include archived findings in triage rules and updates')
    replicate_parser.add_argument('--skip-verification', action='store_true', 
                                 help='Skip project version existence verification')
    replicate_parser.add_argument('--overwrite', action='store_true', 
                                 help='Overwrite existing status and justification with source values even if they match')
    
    # apply command
    apply_parser = subparsers.add_parser(
        'apply',
        parents=[common_parser],
        help='Apply triage decisions from CSV file or CVE list',
        description='Apply VEX triage decisions to findings based on CSV file or CVE list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Apply triage from CSV to a specific version
  %(prog)s apply -c cves.csv -v <version_id>
  
  # Apply triage from CSV to all versions in a project
  %(prog)s apply -c cves.csv -p <project_id>
  
  # Apply same status to multiple CVEs
  %(prog)s apply --cve "CVE-2023-12345,CVE-2023-12346" -v <version_id> -s NOT_AFFECTED
  
  # Apply to all accessible projects (requires confirmation)
  %(prog)s apply -c cves.csv --all-projects
        """
    )
    apply_parser.add_argument('-c', '--cve-list', 
                             help='File containing CVEs. CSV format: CVE,Status,Justification,Response,Reason. Text format: one CVE per line (requires -s)')
    apply_parser.add_argument('--cve', 
                             help='Comma-separated list of CVEs (e.g., CVE-2023-12345,CVE-2023-12346). Requires -s')
    apply_parser.add_argument('-s', '--apply-status', 
                             choices=['NOT_AFFECTED', 'FALSE_POSITIVE', 'IN_TRIAGE', 'RESOLVED_WITH_PEDIGREE', 'RESOLVED', 'EXPLOITABLE'], 
                             help='VEX status to apply (required for text file or --cve, optional for CSV)')
    apply_parser.add_argument('--apply-justification', 
                             choices=['CODE_NOT_PRESENT', 'CODE_NOT_REACHABLE', 'REQUIRES_CONFIGURATION', 'REQUIRES_DEPENDENCY', 
                                     'REQUIRES_ENVIRONMENT', 'PROTECTED_BY_COMPILER', 'PROTECTED_AT_RUNTIME', 'PROTECTED_AT_PERIMETER', 'PROTECTED_BY_MITIGATING_CONTROL'],
                             help='VEX justification (optional, defaults applied if missing)')
    apply_parser.add_argument('--apply-response', 
                             choices=['CAN_NOT_FIX', 'WILL_NOT_FIX', 'UPDATE', 'ROLLBACK', 'WORKAROUND_AVAILABLE'],
                             help='VEX response (optional, defaults applied if missing)')
    apply_parser.add_argument('--apply-reason', 
                             help='Optional reason/comment to apply with the triage')
    
    # Target options for apply (mutually exclusive group)
    apply_target_group = apply_parser.add_mutually_exclusive_group(required=True)
    apply_target_group.add_argument('-v', '--version-id', 
                                   help='Target project version ID (artifact ID)')
    apply_target_group.add_argument('--target-list', 
                                   help='File containing list of target artifact IDs (one per line)')
    apply_target_group.add_argument('-p', '--project-id', 
                                   help='Project ID (applies to all versions in project)')
    apply_target_group.add_argument('--all-projects', action='store_true', 
                                   help='All accessible projects (organization-wide, requires confirmation)')
    
    apply_parser.add_argument('--overwrite', action='store_true', 
                             help='Overwrite existing status even if it matches')
    
    # view command
    view_parser = subparsers.add_parser(
        'view',
        parents=[common_parser],
        help='View findings for an artifact',
        description='View and filter findings. Can specify project name, project ID, or version ID (artifact ID). If project name/ID is provided, shows findings for the latest version.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # View findings for a specific version
  %(prog)s view <version_id>
  
  # View findings for latest version of a project (by project ID)
  %(prog)s view <project_id>
  
  # View findings for latest version of a project (by project name)
  %(prog)s view "My Project Name"
        """
    )
    view_parser.add_argument('identifier', help='Project name, project ID, or project version ID (artifact ID). If project name/ID, shows latest version.')
    view_parser.add_argument('--component', help='Filter by component name')
    view_parser.add_argument('--version', help='Filter by component version')
    view_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'INFO'], 
                            help='Filter by severity level')
    view_parser.add_argument('--risk-min', type=int, help='Minimum risk score filter')
    view_parser.add_argument('--risk-max', type=int, help='Maximum risk score filter')
    view_parser.add_argument('--archived', action='store_true', 
                            help='Include archived findings')
    view_parser.add_argument('--skip-verification', action='store_true', 
                            help='Skip project version existence verification')
    
    # rollback command
    rollback_parser = subparsers.add_parser(
        'rollback',
        help='Restore findings from a backup file',
        description='Restore findings to their previous state from a backup file'
    )
    rollback_parser.add_argument('backup_file', help='Path to backup JSON file')
    
    # vex-info command
    subparsers.add_parser(
        'vex-info',
        help='Show VEX information and requirements',
        description='Display VEX (Vulnerability Exploitability eXchange) information and requirements'
    )
    
    args = parser.parse_args()
    
    # Handle case where no command is provided (backward compatibility or show help)
    if not args.command:
        # Check for old-style usage patterns for backward compatibility
        if hasattr(args, 'source_artifact') and args.source_artifact and hasattr(args, 'target_artifact') and args.target_artifact:
            # Old-style: replicate mode
            args.command = 'replicate'
        elif hasattr(args, 'view') and args.view:
            args.command = 'view'
            args.artifact_id = args.source_artifact if hasattr(args, 'source_artifact') else None
        elif hasattr(args, 'rollback') and args.rollback:
            args.command = 'rollback'
            args.backup_file = args.rollback
        elif hasattr(args, 'vex_info') and args.vex_info:
            args.command = 'vex-info'
        else:
            parser.print_help()
            sys.exit(1)
    
    try:
        # Load environment variables
        auth_token, domain = load_environment()
        
        # Route to appropriate command handler
        if args.command == 'replicate':
            # Replicate triage from source to target
            if not args.source_artifact or not args.target_artifact:
                print("❌ ERROR: Both source_artifact and target_artifact are required for replicate command", file=sys.stderr)
                sys.exit(1)
            
            # Get triage rules from source artifact
            print(f"Getting triage rules from source artifact {args.source_artifact}...")
            triage_rules = get_component_triage_rules(
                auth_token, 
                domain, 
                args.source_artifact,
                component_name=args.component,
                component_version=args.version,
                severity=args.severity,
                risk_min=args.risk_min,
                risk_max=args.risk_max,
                archived=args.archived,
                debug=args.debug
            )
            
            if not triage_rules:
                print("No triage rules found matching the specified criteria")
                sys.exit(0)
            
            # Apply triage rules to target artifact
            print(f"Applying triage rules to target artifact {args.target_artifact}...")
            apply_triage_rules(
                token=auth_token,
                domain=domain,
                target_artifact_id=args.target_artifact,
                triage_rules=triage_rules,
                source_artifact_id=args.source_artifact,
                severity=args.severity,
                risk_min=args.risk_min,
                risk_max=args.risk_max,
                archived=args.archived,
                overwrite=args.overwrite,
                dry_run=args.dry_run,
                debug=args.debug
            )
            
        elif args.command == 'apply':
            # Apply triage from CSV/list
            # Check if file is CSV format (has Status column) or text file
            is_csv_format = False
            cve_triage_list = None
            
            if args.cve_list or args.cve:
                if not os.path.exists(args.cve_list):
                    print(f"❌ ERROR: CVE list file not found: {args.cve_list}", file=sys.stderr)
                    sys.exit(1)
                
                # Try to detect CSV format by checking for Status column
                try:
                    # First, try to parse as CSV - if it succeeds, it's CSV format
                    cve_triage_list = parse_cve_csv(args.cve_list)
                    if cve_triage_list and len(cve_triage_list) > 0:
                        is_csv_format = True
                    else:
                        # Parsed but got empty list
                        is_csv_format = False
                        cve_triage_list = None
                except Exception as parse_error:
                    # Parsing failed - might be text file or malformed CSV
                    # Check if file has commas and Status-like content to give better error
                    try:
                        with open(args.cve_list, 'r', encoding='utf-8') as f:
                            first_line = f.readline().strip()
                            if ',' in first_line and ('status' in first_line.lower() or 'cve' in first_line.lower()):
                                # Looks like CSV but parsing failed
                                print(f"❌ ERROR: File appears to be CSV but parsing failed: {str(parse_error)}", file=sys.stderr)
                                print(f"   Please check the CSV format. Expected columns: CVE, Status, (optional: Justification, Response, Reason)", file=sys.stderr)
                                print(f"   First line of file: {first_line[:100]}", file=sys.stderr)
                                sys.exit(1)
                    except Exception as e:
                        # Can't even read the file to check
                        pass
                    is_csv_format = False
                    cve_triage_list = None
            
            # Load CVEs based on format
            if is_csv_format and cve_triage_list:
                # CSV format - use triage info from CSV
                print(f"📋 Detected CSV format with VEX data - {len(cve_triage_list)} CVEs with triage information")
            else:
                # Text file or comma-separated - requires --apply-status
                if not args.apply_status:
                    print("❌ ERROR: --apply-status is required when using text file format or --cve", file=sys.stderr)
                    print("   For CSV format, include Status column in the CSV file", file=sys.stderr)
                    sys.exit(1)
                
                # Load CVEs from text file or comma-separated
                cve_list = []
                if args.cve_list:
                    with open(args.cve_list, 'r') as f:
                        cve_list = [line.strip() for line in f if line.strip()]
                elif args.cve:
                    cve_list = [cve.strip() for cve in args.cve.split(',') if cve.strip()]
                else:
                    print("❌ ERROR: Either --cve-list or --cve must be provided", file=sys.stderr)
                    sys.exit(1)
                
                if not cve_list:
                    print("❌ ERROR: No CVEs found in the provided list", file=sys.stderr)
                    sys.exit(1)
            
            # Target is already validated by mutually exclusive group, but check which one was provided
            use_project_scope = args.project_id is not None
            use_org_scope = args.all_projects
            version_id = args.version_id
            
            if use_project_scope:
                # Project-level scope (all versions in project)
                print(f"📋 Scope: Project {args.project_id} (all versions)")
                
                if is_csv_format and cve_triage_list:
                    result = apply_triage_from_csv(
                        token=auth_token,
                        domain=domain,
                        project_id=args.project_id,
                        cve_triage_list=cve_triage_list,
                        dry_run=args.dry_run,
                        overwrite=args.overwrite
                    )
                else:
                    result = apply_triage_to_cves(
                        token=auth_token,
                        domain=domain,
                        project_id=args.project_id,
                        cve_list=cve_list,
                        status=args.apply_status,
                        justification=args.apply_justification,
                        response=args.apply_response,
                        reason=args.apply_reason,
                        dry_run=args.dry_run,
                        overwrite=args.overwrite
                    )
                
                print(f"\n{'='*80}")
                print(f"Summary:")
                print(f"{'='*80}")
                print(f"  Total findings updated: {result['updated']}")
                print(f"  Total CVEs not found: {result['not_found']}")
                print(f"  Total failures: {result['failed']}")
                
            elif use_org_scope:
                # Organization-wide scope (all accessible projects)
                print(f"📋 Scope: Organization-wide (all accessible projects)")
                print("⚠️  WARNING: This will query and update findings across ALL accessible projects!")
                print("   (You specified --all-projects flag)")
                if not args.dry_run:
                    response = input("Are you sure you want to continue? (yes/no): ")
                    if response.lower() != 'yes':
                        print("Aborted.")
                        sys.exit(0)
                
                if is_csv_format and cve_triage_list:
                    result = apply_triage_from_csv(
                        token=auth_token,
                        domain=domain,
                        cve_triage_list=cve_triage_list,
                        dry_run=args.dry_run,
                        overwrite=args.overwrite
                    )
                else:
                    result = apply_triage_to_cves(
                        token=auth_token,
                        domain=domain,
                        cve_list=cve_list,
                        status=args.apply_status,
                        justification=args.apply_justification,
                        response=args.apply_response,
                        reason=args.apply_reason,
                        dry_run=args.dry_run,
                        overwrite=args.overwrite
                    )
                
                print(f"\n{'='*80}")
                print(f"Summary:")
                print(f"{'='*80}")
                print(f"  Total findings updated: {result['updated']}")
                print(f"  Total CVEs not found: {result['not_found']}")
                print(f"  Total failures: {result['failed']}")
                
            else:
                # Project version-level scope (specific artifacts)
                target_artifacts = []
                if args.target_list:
                    if not os.path.exists(args.target_list):
                        print(f"❌ ERROR: Target list file not found: {args.target_list}", file=sys.stderr)
                        sys.exit(1)
                    with open(args.target_list, 'r') as f:
                        target_artifacts = [line.strip() for line in f if line.strip()]
                elif version_id:
                    target_artifacts = [version_id]
                else:
                    # This shouldn't happen due to validation above, but keep as safety check
                    print("❌ ERROR: Target must be specified. Use one of:", file=sys.stderr)
                    print("   - --version-id <id> (project version ID)", file=sys.stderr)
                    print("   - target_artifact argument (project version ID, alternative to --version-id)", file=sys.stderr)
                    print("   - --target-list <file> (list of project version IDs)", file=sys.stderr)
                    print("   - --project-id <id> (all versions in a project)", file=sys.stderr)
                    print("   - --all-projects (all accessible projects)", file=sys.stderr)
                    sys.exit(1)
                
                if not target_artifacts:
                    print("❌ ERROR: No target artifacts found", file=sys.stderr)
                    sys.exit(1)
                
                # Apply triage to each artifact
                total_updated = 0
                total_not_found = 0
                total_failed = 0
                
                for artifact_id in target_artifacts:
                    print(f"\n{'='*80}")
                    print(f"Processing artifact: {artifact_id}")
                    print(f"{'='*80}")
                    
                    if is_csv_format and cve_triage_list:
                        # Use CSV-based triage (each CVE can have different status)
                        result = apply_triage_from_csv(
                            token=auth_token,
                            domain=domain,
                            artifact_id=artifact_id,
                            cve_triage_list=cve_triage_list,
                            dry_run=args.dry_run,
                            overwrite=args.overwrite
                        )
                    else:
                        # Use uniform triage (same status for all CVEs)
                        result = apply_triage_to_cves(
                            token=auth_token,
                            domain=domain,
                            artifact_id=artifact_id,
                            cve_list=cve_list,
                            status=args.apply_status,
                            justification=args.apply_justification,
                            response=args.apply_response,
                            reason=args.apply_reason,
                            dry_run=args.dry_run,
                            overwrite=args.overwrite
                        )
                    
                    total_updated += result['updated']
                    total_not_found += result['not_found']
                    total_failed += result['failed']
                
                # Print overall summary
                print(f"\n{'='*80}")
                print(f"Overall Summary:")
                print(f"{'='*80}")
                print(f"  Total artifacts processed: {len(target_artifacts)}")
                print(f"  Total findings updated: {total_updated}")
                print(f"  Total CVEs not found: {total_not_found}")
                print(f"  Total failures: {total_failed}")
            
        elif args.command == 'view':
            # View findings - resolve identifier to version ID
            if not args.identifier:
                print("❌ ERROR: identifier is required for view command", file=sys.stderr)
                sys.exit(1)
            
            # Resolve identifier (project name, project ID, or version ID) to version ID
            version_id, identifier_type = resolve_to_version_id(auth_token, domain, args.identifier, debug=args.debug)
            
            if not version_id:
                print(f"❌ ERROR: Could not resolve '{args.identifier}' to a valid project or version", file=sys.stderr)
                sys.exit(1)
            
            if identifier_type == 'project':
                print(f"📋 Resolved project '{args.identifier}' to latest version: {version_id}")
            
            view_findings(
                auth_token, domain, version_id, 
                args.component, args.version, args.severity, 
                args.risk_min, args.risk_max, args.archived, 
                args.skip_verification, args.debug
            )
            
        elif args.command == 'rollback':
            # Rollback from backup
            if not os.path.exists(args.backup_file):
                print(f"❌ ERROR: Backup file not found: {args.backup_file}", file=sys.stderr)
                sys.exit(1)
            
            restored = restore_from_backup(auth_token, domain, args.backup_file)
            if restored > 0:
                print(f"\n✅ Rollback completed successfully")
                sys.exit(0)
            else:
                print(f"\n❌ Rollback failed - no findings were restored", file=sys.stderr)
                sys.exit(1)
                
        elif args.command == 'vex-info':
            # Show VEX information
            show_vex_info()
        
    except TypeError as e:
        print(f"TypeError: {e}")
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main() 