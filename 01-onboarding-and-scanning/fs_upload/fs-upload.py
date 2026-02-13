#!/usr/bin/env python3
"""
Finite State Artifact Upload Script

A simple, functional script for uploading artifacts to the Finite State API
with automatic project/version creation and intuitive file detection.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import requests


class FiniteStateUploader:
    """Main class for handling artifact uploads to Finite State API."""

    def __init__(self, auth_token: str, domain: str, cli_tool_path: Optional[str] = None, use_cli: bool = False):
        """Initialize the uploader with authentication credentials."""
        self.auth_token = auth_token
        # Ensure domain has a scheme (default to https://)
        domain = domain.rstrip('/')
        if not domain.startswith(('http://', 'https://')):
            domain = f"https://{domain}"
        self.domain = domain
        self.base_url = f"{self.domain}/api"
        self.session = requests.Session()
        self.session.headers.update({
            'X-Authorization': auth_token,
            'Content-Type': 'application/json'
        })
        self.errors = []
        self.successes = []
        self.use_cli = use_cli
        # Track versions created in this batch (project_id -> list of version names)
        self.batch_versions = {}
        # Default to finitestate.jar if not specified
        if not cli_tool_path:
            self.cli_tool_path = 'finitestate.jar'
        else:
            self.cli_tool_path = cli_tool_path

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make an HTTP request to the API."""
        # Ensure base_url ends with / and endpoint doesn't start with /
        base = self.base_url.rstrip('/') + '/'
        endpoint_clean = endpoint.lstrip('/')
        url = base + endpoint_clean
        
        # Merge headers with session headers if headers are provided
        if 'headers' in kwargs:
            merged_headers = self.session.headers.copy()
            merged_headers.update(kwargs['headers'])
            kwargs['headers'] = merged_headers
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            # Provide more detailed error information
            error_msg = f"API request failed: {e}"
            if e.response is not None:
                try:
                    error_body = e.response.json()
                    if isinstance(error_body, dict) and 'errors' in error_body:
                        error_details = error_body.get('errors', [])
                        if error_details:
                            error_msg += f"\nError details: {error_details}"
                    elif isinstance(error_body, dict) and 'message' in error_body:
                        error_msg += f"\nError message: {error_body.get('message')}"
                    else:
                        error_msg += f"\nResponse: {e.response.text[:500]}"
                except (ValueError, KeyError):
                    error_msg += f"\nResponse: {e.response.text[:500]}"
            raise Exception(error_msg)
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {e}")

    def find_project(self, project_name: str) -> Optional[Dict]:
        """Find a project by name using RSQL filter."""
        # Quote the value to handle special characters like parentheses, spaces, etc.
        # Escape any quotes in the name itself
        escaped_name = project_name.replace("'", "''").replace('"', '""')
        filter_expr = f"name=='{escaped_name}'"
        response = self._make_request('GET', '/public/v0/projects', params={'filter': filter_expr})
        projects = response.json()
        return projects[0] if projects else None

    def create_project(self, name: str, description: str, project_type: str = 'firmware',
                      folder_id: Optional[str] = None) -> Dict:
        """Create a new project."""
        payload = {
            'name': name,
            'description': description,
            'type': project_type
        }
        # Don't include folder_id during creation to avoid 500 errors
        # We'll move it to the folder after creation if needed

        try:
            response = self._make_request('POST', '/public/v0/projects', json=payload)
            project = response.json()
            
            # If folder_id is specified, move the project to that folder after creation
            if folder_id and project.get('id'):
                try:
                    self.move_project_to_folder(project['id'], folder_id)
                    # Refresh project data to get updated folder info
                    project_response = self._make_request('GET', f"/public/v0/projects/{project['id']}")
                    project = project_response.json()
                except Exception as e:
                    # If moving fails, warn but don't fail the entire operation
                    print(f"Warning: Created project '{name}' but failed to move it to folder '{folder_id}': {e}")
            
            return project
        except Exception as e:
            error_msg = f"Failed to create project '{name}': {e}"
            raise Exception(error_msg)
    
    def move_project_to_folder(self, project_id: str, folder_id: str) -> Dict:
        """Move a project to a folder by updating the project's folderId."""
        # First, get the current project to preserve name and description
        project_response = self._make_request('GET', f'/public/v0/projects/{project_id}')
        current_project = project_response.json()
        
        # Update project with folderId, preserving existing name and description
        payload = {
            'name': current_project.get('name'),
            'description': current_project.get('description'),
            'folderId': str(folder_id)
        }
        try:
            response = self._make_request('PUT', f'/public/v0/projects/{project_id}', json=payload)
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to move project to folder '{folder_id}': {e}")

    def get_or_create_project(self, name: str, project_type: str = 'firmware',
                             folder_id: Optional[str] = None) -> Dict:
        """Get existing project or create a new one.
        
        If folder_id is provided and the project is newly created, it will be moved to the folder.
        This avoids 500 errors that can occur when creating projects directly in folders.
        Existing projects are not moved - they remain in their current folder.
        """
        project = self.find_project(name)
        if project:
            # Project already exists - don't move it, just return it
            return project

        # Create project (will be moved to folder after creation if folder_id is provided)
        return self.create_project(name, name, project_type, folder_id)

    def find_version(self, project_id: str, version_name: str) -> Optional[Dict]:
        """Find a version by name within a project."""
        response = self._make_request('GET', f'/public/v0/projects/{project_id}/versions')
        versions = response.json()
        for version in versions:
            if version.get('version') == version_name:
                return version
        return None

    def get_latest_version(self, project_id: str) -> Optional[Dict]:
        """Get the most recently created version for a project."""
        response = self._make_request('GET', f'/public/v0/projects/{project_id}/versions')
        versions = response.json()
        if not versions:
            return None
        # Sort by created timestamp (most recent first)
        sorted_versions = sorted(versions, key=lambda v: v.get('created', ''), reverse=True)
        return sorted_versions[0] if sorted_versions else None

    def get_all_versions(self, project_id: str) -> List[Dict]:
        """Get all versions for a project."""
        response = self._make_request('GET', f'/public/v0/projects/{project_id}/versions')
        return response.json() or []

    def parse_version_number(self, version_str: str) -> Optional[Tuple[int, ...]]:
        """Parse a version string into a tuple of integers for comparison.
        
        Examples:
            "1.0" -> (1, 0)
            "1.1" -> (1, 1)
            "2.0.0" -> (2, 0, 0)
            "1.0.1" -> (1, 0, 1)
        
        Skips date-like versions (e.g., "2025-11-12") which are not semantic versions.
        """
        try:
            # Skip versions that look like dates (YYYY-MM-DD or YYYY.MM.DD)
            if re.match(r'^\d{4}[-.]\d{1,2}[-.]\d{1,2}', version_str):
                return None
            
            # Try to parse as semantic version (major.minor.patch)
            parts = version_str.split('.')
            if len(parts) == 0:
                return None
            
            # Convert to integers, handling any non-numeric suffixes
            version_parts = []
            for part in parts:
                # Remove any non-numeric suffix (e.g., "1.0-alpha" -> "1.0")
                # But skip if it starts with a dash (likely a date format)
                if part.startswith('-'):
                    break
                numeric_part = re.sub(r'[^0-9].*$', '', part)
                if numeric_part:
                    version_parts.append(int(numeric_part))
                else:
                    break
            
            # Only return if we have at least one part and it's a reasonable version number
            # (not a year like 2025)
            if version_parts and (len(version_parts) > 1 or version_parts[0] < 1000):
                return tuple(version_parts)
            return None
        except (ValueError, AttributeError):
            return None

    def increment_version(self, base_version: str) -> str:
        """Increment a version number.
        
        Examples:
            "1.0" -> "1.1"
            "1.1" -> "1.2"
            "2.0" -> "2.1"
            "1.0.0" -> "1.0.1"
        """
        version_tuple = self.parse_version_number(base_version)
        if not version_tuple:
            # If we can't parse it, just append .1
            return f"{base_version}.1"
        
        # Increment the last component
        version_list = list(version_tuple)
        version_list[-1] += 1
        return '.'.join(str(v) for v in version_list)

    def get_next_version_name(self, project_id: str, base_version: str = '1.0', 
                             include_batch_versions: bool = True) -> str:
        """Get the next version name by finding the highest existing version and incrementing it.
        
        Args:
            include_batch_versions: If True, also consider versions created in this batch.
        """
        try:
            versions = self.get_all_versions(project_id)
            
            # Also include versions created in this batch
            if include_batch_versions and project_id in self.batch_versions:
                for batch_version_name in self.batch_versions[project_id]:
                    # Create a fake version dict for batch versions
                    versions.append({'version': batch_version_name})
            
            if not versions:
                return base_version
            
            # Parse all version numbers and find the highest
            max_version = None
            max_version_tuple = None
            
            for version in versions:
                version_name = version.get('version', '')
                if not version_name:
                    continue
                version_tuple = self.parse_version_number(version_name)
                if version_tuple:
                    if max_version_tuple is None or version_tuple > max_version_tuple:
                        max_version_tuple = version_tuple
                        max_version = version_name
            
            if max_version:
                next_version = self.increment_version(max_version)
                return next_version
            else:
                # If we couldn't parse any versions, increment base_version
                return self.increment_version(base_version)
        except Exception as e:
            # If anything goes wrong, just increment the base version
            return self.increment_version(base_version)

    def create_version(self, project_id: str, version_name: str,
                     release_type: str = 'RELEASE') -> Dict:
        """Create a new version for a project."""
        payload = {
            'version': version_name,
            'releaseType': release_type
        }
        try:
            response = self._make_request('POST', f'/public/v0/projects/{project_id}/versions', json=payload)
            version = response.json()
            if not version or 'id' not in version:
                raise Exception(f"Invalid response when creating version: {version}")
            return version
        except Exception as e:
            raise Exception(f"Failed to create version '{version_name}': {e}")

    def get_or_create_version(self, project_id: str, version_name: str,
                            release_type: str = 'RELEASE', 
                            reuse_latest: bool = False,
                            always_create_new: bool = False) -> Dict:
        """Get existing version or create a new one.
        
        Args:
            reuse_latest: If True, reuse the latest version instead of creating a new one.
                         This prevents new versions from replacing previous ones in the UI.
            always_create_new: If True, always create a new version even if one with the
                              same name exists. Used when version was not explicitly specified.
        """
        # If reuse_latest is True, always reuse the most recent version
        if reuse_latest:
            latest = self.get_latest_version(project_id)
            if latest:
                return latest
            # No versions exist yet, create the first one
            return self.create_version(project_id, version_name, release_type)
        
        # If always_create_new is True, find the next version number and create it
        if always_create_new:
            next_version = self.get_next_version_name(project_id, version_name)
            return self.create_version(project_id, next_version, release_type)
        
        # Check for existing version with the exact name first
        version = self.find_version(project_id, version_name)
        if version:
            # Version exists, reuse it
            return version
        
        # Version doesn't exist, create it
        # Note: Creating a new version may make it the "active" one in the UI,
        # potentially hiding previous versions on the default branch
        return self.create_version(project_id, version_name, release_type)

    def find_folder(self, folder_name: str) -> Optional[Dict]:
        """Find a folder by name using RSQL filter."""
        # Quote the value to handle special characters like parentheses, spaces, etc.
        # Escape any quotes in the name itself
        escaped_name = folder_name.replace("'", "''").replace('"', '""')
        filter_expr = f"name=='{escaped_name}'"
        response = self._make_request('GET', '/public/v0/folders', params={'filter': filter_expr})
        folders = response.json()
        return folders[0] if folders else None

    def verify_folder_exists(self, folder_id: str) -> bool:
        """Verify that a folder ID exists."""
        try:
            response = self._make_request('GET', f'/public/v0/folders/{folder_id}')
            return True
        except Exception as e:
            error_str = str(e)
            # If it's a 404, the folder doesn't exist
            if '404' in error_str:
                return False
            # For other errors, assume it exists (might be a permission issue)
            return True

    def resolve_folder_id(self, folder_input: Optional[str]) -> Optional[str]:
        """Resolve folder ID from folder name or ID."""
        if not folder_input:
            return None

        # Check if it's a numeric ID
        if folder_input.isdigit():
            # Verify the folder exists before returning it
            if self.verify_folder_exists(folder_input):
                return folder_input
            else:
                raise Exception(f"Folder ID '{folder_input}' not found or invalid")

        # Try to find by name
        folder = self.find_folder(folder_input)
        if folder:
            folder_id = folder.get('id')
            if folder_id:
                return str(folder_id)
            else:
                raise Exception(f"Folder '{folder_input}' found but has no ID")
        else:
            raise Exception(f"Folder '{folder_input}' not found")

    def sanitize_filename(self, filename: str) -> Tuple[str, bool]:
        """Sanitize filename to match API pattern: ^[a-zA-Z0-9. -_()]{1,60}$"""
        original = filename
        # Replace invalid characters with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9. -_()]', '_', filename)
        # Truncate to 60 characters
        if len(sanitized) > 60:
            sanitized = sanitized[:60]

        modified = sanitized != original
        return sanitized, modified

    def detect_sbom_type(self, file_path: Path) -> Optional[str]:
        """Detect SBOM format (CDX or SPDX) by examining file content."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Try to parse as JSON
            try:
                data = json.loads(content)
                # Check for CycloneDX
                if data.get('bomFormat') == 'CycloneDX' or 'specVersion' in data:
                    return 'cdx'
                # Check for SPDX JSON
                if 'spdxVersion' in data or 'SPDXID' in data:
                    return 'spdx'
            except json.JSONDecodeError:
                # Check for SPDX tag-value format
                if content.startswith('SPDXVersion:') or 'SPDXID:' in content[:1000]:
                    return 'spdx'

        except Exception:
            pass

        return None

    def upload_binary(self, file_path: Path, project_version_id: str, filename: str) -> bool:
        """Upload a binary file for scanning."""
        sanitized_filename, modified = self.sanitize_filename(filename)
        if modified:
            print(f"Warning: Filename sanitized from '{filename}' to '{sanitized_filename}'")

        url = f'/public/v0/scans'
        # For array parameters, requests will create type=sca&type=sast format
        # Keep projectVersionId as string (as per API spec)
        params = {
            'type': ['sca', 'sast', 'config', 'vulnerability_analysis'],
            'filename': sanitized_filename,
            'projectVersionId': project_version_id  # Keep as string per spec
        }

        try:
            # Check if file exists and get info
            if not file_path.exists():
                raise Exception(f"File does not exist: {file_path}")
            
            file_size = file_path.stat().st_size
            file_size_mb = file_size / 1024 / 1024
            max_size_mb = 50
            max_size_bytes = max_size_mb * 1024 * 1024
            
            # Check file size limit (50MB) - this should not happen if upload_file logic is correct
            # but keeping as a safety check
            if file_size > max_size_bytes:
                error_msg = f"File size ({file_size_mb:.2f} MB) exceeds the API limit of {max_size_mb} MB. Use --use-cli or the script will auto-detect and use CLI for large files."
                self.errors.append(f"{file_path}: {error_msg}")
                return False
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            if len(file_data) != file_size:
                print(f"Warning: Read {len(file_data)} bytes but file size is {file_size} bytes")
                
            # Construct URL manually (matching minimal script approach)
            base = self.base_url.rstrip('/') + '/'
            endpoint_clean = url.lstrip('/')
            full_url = base + endpoint_clean
            
            # Use explicit headers matching minimal script exactly
            upload_headers = {
                'accept': '*/*',
                'Content-Type': 'application/octet-stream',
                'X-Authorization': self.auth_token
            }
            
            # Make request directly with requests (not through session)
            response = requests.post(
                full_url,
                params=params,
                data=file_data,
                headers=upload_headers
            )
            
            response.raise_for_status()
            return True
        except Exception as e:
            error_msg = str(e)
            # Provide more helpful error message for 404
            if '404' in error_msg:
                error_msg = f"404 Not Found - projectVersionId '{project_version_id}' may not exist or be invalid. {error_msg}"
            self.errors.append(f"{file_path}: {error_msg}")
            return False

    def upload_third_party(self, file_path: Path, project_version_id: str, filename: str,
                          third_party_type: str) -> bool:
        """Upload a third-party scan file."""
        sanitized_filename, modified = self.sanitize_filename(filename)
        if modified:
            print(f"Warning: Filename sanitized from '{filename}' to '{sanitized_filename}'")

        url = f'/public/v0/scans/third-party'
        params = {
            'type': [third_party_type],
            'filename': sanitized_filename,
            'projectVersionId': project_version_id
        }

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                headers = {'Content-Type': 'application/octet-stream'}
                # Remove Content-Type from session headers for this request
                original_headers = self.session.headers.copy()
                self.session.headers.pop('Content-Type', None)
                try:
                    response = self._make_request('POST', url, params=params, data=file_data, headers=headers)
                finally:
                    self.session.headers.update(original_headers)
            return True
        except Exception as e:
            self.errors.append(f"{file_path}: {e}")
            return False

    def upload_sbom(self, file_path: Path, project_version_id: str, filename: str,
                   sbom_type: Optional[str] = None) -> bool:
        """Upload an SBOM file."""
        sanitized_filename, modified = self.sanitize_filename(filename)
        if modified:
            print(f"Warning: Filename sanitized from '{filename}' to '{sanitized_filename}'")

        # Auto-detect if not specified
        if not sbom_type:
            sbom_type = self.detect_sbom_type(file_path)
            if not sbom_type:
                self.errors.append(f"{file_path}: Could not detect SBOM format (CDX or SPDX)")
                return False

        url = f'/public/v0/scans/sbom'
        # SBOM endpoint uses int64 for projectVersionId
        params = {
            'type': sbom_type,
            'filename': sanitized_filename,
            'projectVersionId': int(project_version_id)
        }

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                headers = {'Content-Type': 'application/octet-stream'}
                # Remove Content-Type from session headers for this request
                original_headers = self.session.headers.copy()
                self.session.headers.pop('Content-Type', None)
                try:
                    response = self._make_request('POST', url, params=params, data=file_data, headers=headers)
                finally:
                    self.session.headers.update(original_headers)
            return True
        except Exception as e:
            self.errors.append(f"{file_path}: {e}")
            return False

    def collect_files(self, inputs: List[str], recursive: bool = False) -> List[Path]:
        """Collect files from various input types (files, directories, patterns)."""
        files = []
        for input_path in inputs:
            path = Path(input_path).expanduser().resolve()

            if path.is_file():
                files.append(path)
            elif path.is_dir():
                if recursive:
                    files.extend(path.rglob('*'))
                else:
                    files.extend(path.glob('*'))
                # Filter to only files
                files = [f for f in files if f.is_file()]
            else:
                # Try glob pattern
                matches = list(Path('.').glob(str(path)))
                files.extend([m for m in matches if m.is_file()])

        return sorted(set(files))

    def parse_csv(self, csv_path: Path) -> List[Dict]:
        """Parse CSV file with auto-detected headers."""
        rows = []
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                # Try to detect delimiter
                sample = f.read(1024)
                f.seek(0)
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter

                reader = csv.DictReader(f, delimiter=delimiter)
                # Normalize headers (case-insensitive)
                fieldnames = {name.lower(): name for name in reader.fieldnames or []}

                for row_num, row in enumerate(reader, start=2):  # Start at 2 (1 is header)
                    try:
                        normalized_row = {}
                        for key, value in row.items():
                            normalized_key = fieldnames.get(key.lower(), key)
                            normalized_row[normalized_key.lower()] = value.strip() if value else None

                        # Validate required fields
                        if not normalized_row.get('artifact_name'):
                            print(f"Warning: Row {row_num} skipped - missing artifact_name")
                            continue

                        rows.append(normalized_row)
                    except Exception as e:
                        print(f"Warning: Row {row_num} skipped - {e}")
                        continue

        except Exception as e:
            raise Exception(f"Failed to parse CSV: {e}")

        return rows

    def generate_summary(self, uploads: List[Dict]) -> str:
        """Generate a summary of what will be uploaded."""
        lines = ["\nUpload Summary:"]
        lines.append("=" * 60)

        projects = {}
        for upload in uploads:
            proj_name = upload.get('project_name', 'N/A')
            ver_name = upload.get('version', 'N/A')
            scan_type = upload.get('scan_type', 'binary')
            folder_id = upload.get('folder_id')
            folder = 'root' if not folder_id else f"folder_id: {folder_id}"

            key = (proj_name, ver_name, scan_type, folder)
            if key not in projects:
                projects[key] = []
            projects[key].append(upload['file_path'])

        for (proj_name, ver_name, scan_type, folder), files in projects.items():
            lines.append(f"\nProject: {proj_name}")
            lines.append(f"  Version: {ver_name}")
            lines.append(f"  Scan Type: {scan_type}")
            lines.append(f"  Folder: {folder}")
            lines.append(f"  Files ({len(files)}):")
            for f in files:
                lines.append(f"    - {f}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def upload_file_via_cli(self, file_path: Path, project_name: str, version_name: str,
                            scan_type: str = 'binary', third_party_type: Optional[str] = None,
                            sbom_type: Optional[str] = None, branch: Optional[str] = None,
                            release_type: str = 'RELEASE', folder_id: Optional[str] = None) -> bool:
        """Upload a file using the Finite State CLI tool."""
        cli_path = Path(self.cli_tool_path)
        if not cli_path.exists():
            self.errors.append(f"{file_path}: CLI tool not found at {self.cli_tool_path}")
            return False
        
        # Build command
        cmd = ['java', '-jar', str(cli_path)]
        
        # Map scan types to CLI arguments
        if scan_type == 'binary':
            # For binary, use --upload with scan types
            scan_types = ['sca', 'sast', 'config', 'vulnerability_analysis']
            cmd.append(f'--upload={",".join(scan_types)}')
            cmd.append(str(file_path))
        elif scan_type == 'third-party':
            if not third_party_type:
                self.errors.append(f"{file_path}: --third-party-type required for third-party scans")
                return False
            cmd.append(f'--thirdParty={third_party_type}')
            cmd.append(str(file_path))
        elif scan_type == 'sbom':
            cmd.append('--import')
            cmd.append(str(file_path))
        else:
            self.errors.append(f"{file_path}: Unknown scan type: {scan_type}")
            return False
        
        # Add project name and version
        cmd.append(f'--name={project_name}')
        if version_name:
            cmd.append(f'--version={version_name}')
        
        # Add branch if specified
        if branch:
            cmd.append(f'--branch={branch}')
        
        # Add pre-release flag if needed
        if release_type == 'PRE-RELEASE':
            cmd.append('--pre-release')
        
        # Set environment variables
        env = os.environ.copy()
        env['FINITE_STATE_AUTH_TOKEN'] = self.auth_token
        env['FINITE_STATE_DOMAIN'] = self.domain
        # Note: CLI tool doesn't support folder parameter directly
        # The project should already be in the correct folder via API before CLI is called
        # But we can pass folder ID as env var in case the CLI tool supports it
        if folder_id:
            env['FINITE_STATE_FOLDER_ID'] = folder_id
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=3600  # 60 minute timeout
            )
            
            if result.returncode == 0:
                return True
            else:
                error_msg = f"CLI tool exited with code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr[:500]}"
                elif result.stdout:
                    error_msg += f": {result.stdout[:500]}"
                self.errors.append(f"{file_path}: {error_msg}")
                return False
        except subprocess.TimeoutExpired:
            self.errors.append(f"{file_path}: CLI tool timed out after 60 minutes")
            return False
        except Exception as e:
            self.errors.append(f"{file_path}: CLI tool error: {e}")
            return False

    def upload_file(self, file_path: Path, project_name: str, version_name: str,
                   scan_type: str = 'binary', third_party_type: Optional[str] = None,
                   sbom_type: Optional[str] = None, folder_id: Optional[str] = None,
                   project_type: str = 'firmware', release_type: str = 'RELEASE',
                   dry_run: bool = False, reuse_latest_version: bool = False,
                   branch: Optional[str] = None, version_explicit: bool = True) -> bool:
        """Upload a single file with all necessary setup."""
        if dry_run:
            return True
        
        # Check file size - automatically use CLI for files >50MB
        max_size_mb = 50
        max_size_bytes = max_size_mb * 1024 * 1024
        if file_path.exists():
            file_size = file_path.stat().st_size
            file_size_mb = file_size / 1024 / 1024
            if file_size > max_size_bytes and not self.use_cli:
                # File is too large for API, automatically switch to CLI
                cli_path = Path(self.cli_tool_path)
                if not cli_path.exists():
                    error_msg = f"File size ({file_size_mb:.2f} MB) exceeds API limit ({max_size_mb} MB). CLI tool not found at {self.cli_tool_path}. Please install the CLI tool or use --use-cli with --cli-tool-path."
                    self.errors.append(f"{file_path}: {error_msg}")
                    return False
                print(f"Note: File size ({file_size_mb:.2f} MB) exceeds API limit ({max_size_mb} MB), using CLI tool instead")
                self.use_cli = True
        
        # Get or create project (needed for both CLI and API modes to check versions)
        # Project will be created first, then moved to folder if folder_id is provided
        project = self.get_or_create_project(project_name, project_type, folder_id)
        if not project or 'id' not in project:
            self.errors.append(f"{file_path}: Failed to get or create project '{project_name}'")
            return False

        # If version was not explicitly specified, get the next incremented version
        # (including versions created in this batch)
        if not version_explicit:
            version_name = self.get_next_version_name(project['id'], version_name, include_batch_versions=True)

        # Use CLI if enabled (either explicitly or auto-enabled for large files)
        if self.use_cli:
            # Track this version in the batch (CLI will create it)
            if not version_explicit:
                if project['id'] not in self.batch_versions:
                    self.batch_versions[project['id']] = []
                self.batch_versions[project['id']].append(version_name)
            
            # Call CLI tool (it will create project/version if needed)
            success = self.upload_file_via_cli(
                file_path, project_name, version_name,
                scan_type, third_party_type, sbom_type,
                branch, release_type, folder_id
            )
            
            # After CLI tool completes, move project to folder if specified
            # The CLI tool doesn't support folders, so we move it via API afterwards
            if success and folder_id:
                # Re-fetch project in case CLI tool created it
                project = self.find_project(project_name)
                if project and project.get('id'):
                    current_folder_id = project.get('folderId')
                    if str(current_folder_id) != str(folder_id):
                        try:
                            self.move_project_to_folder(project['id'], folder_id)
                        except Exception as e:
                            print(f"Warning: Failed to move project '{project_name}' to folder '{folder_id}' after CLI upload: {e}")
            
            return success

        # Get or create version (API mode)
        # If version was explicitly specified, reuse existing version if found
        # Otherwise, we already have the incremented version name above, so always create new
        if version_explicit:
            # Explicit version: reuse if exists, create if not
            version = self.get_or_create_version(
                project['id'], version_name, release_type, 
                reuse_latest=reuse_latest_version,
                always_create_new=False
            )
        else:
            # Auto-incremented version: always create new (version_name already incremented)
            version = self.create_version(project['id'], version_name, release_type)
            # Track this version in the batch so subsequent files increment from it
            if project['id'] not in self.batch_versions:
                self.batch_versions[project['id']] = []
            self.batch_versions[project['id']].append(version_name)
        
        # Log the version that was created/used
        if not version_explicit and version:
            print(f"Created new version: {version.get('version')}")
        if not version or 'id' not in version:
            self.errors.append(f"{file_path}: Failed to get or create version '{version_name}' for project '{project_name}'")
            return False

        project_version_id = str(version['id'])
        filename = file_path.name

        # Upload based on scan type
        if scan_type == 'binary':
            return self.upload_binary(file_path, str(project_version_id), filename)
        elif scan_type == 'third-party':
            if not third_party_type:
                self.errors.append(f"{file_path}: --third-party-type required for third-party scans")
                return False
            return self.upload_third_party(file_path, str(project_version_id), filename, third_party_type)
        elif scan_type == 'sbom':
            return self.upload_sbom(file_path, str(project_version_id), filename, sbom_type)
        else:
            self.errors.append(f"{file_path}: Unknown scan type: {scan_type}")
            return False

    def process_uploads(self, uploads: List[Dict], dry_run: bool = False, 
                       reuse_latest_version: bool = False) -> None:
        """Process a list of uploads."""
        total = len(uploads)
        for idx, upload in enumerate(uploads, 1):
            file_path = upload['file_path']
            print(f"[{idx}/{total}] Processing {file_path.name}...", end=' ', flush=True)

            success = self.upload_file(
                file_path=file_path,
                project_name=upload['project_name'],
                version_name=upload['version'],
                scan_type=upload.get('scan_type', 'binary'),
                third_party_type=upload.get('third_party_type'),
                sbom_type=upload.get('sbom_type'),
                folder_id=upload.get('folder_id'),
                project_type=upload.get('project_type', 'firmware'),
                release_type=upload.get('release_type', 'RELEASE'),
                dry_run=dry_run,
                reuse_latest_version=reuse_latest_version,
                branch=upload.get('branch'),
                version_explicit=upload.get('version_explicit', True)
            )

            if success:
                print("✓")
                self.successes.append(str(file_path))
            else:
                print("✗")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Upload artifacts to Finite State for scanning',
        epilog='''
Examples:
  # Upload a single file (uses filename as project name if --project not specified)
  fs-upload --project MyProject --version 1.0 file.jar

  # Upload multiple files (each gets its own project based on filename)
  fs-upload file1.jar file2.jar file3.jar

  # Upload all files in current directory (each gets its own project)
  fs-upload

  # Upload with project prefix (creates MyProject-file1, MyProject-file2, etc.)
  fs-upload --project MyProject file1.jar file2.jar

  # Upload using CLI tool (for large files >50MB)
  fs-upload --use-cli --project MyProject --version 1.0 large-file.jar

  # Upload from CSV (project/version per row)
  fs-upload --csv uploads.csv

Environment Variables:
  FINITE_STATE_AUTH_TOKEN    API authentication token
  FINITE_STATE_DOMAIN        Finite State domain (e.g., se-test.finitestate.io)
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--auth-token', 
                           help='Finite State API token (or set FINITE_STATE_AUTH_TOKEN)')
    auth_group.add_argument('--domain', 
                           help='Finite State domain URL (or set FINITE_STATE_DOMAIN)')

    # Project/Version
    project_group = parser.add_argument_group('Project & Version')
    project_group.add_argument('--project', 
                              help='Project name (will be created if it doesn\'t exist). '
                                   'When uploading multiple files, each file gets its own project '
                                   'based on filename (or --project-filename if specified)')
    project_group.add_argument('--version', 
                               help='Version name (will be created if it doesn\'t exist). '
                                    'Defaults to "1.0" if not specified when uploading multiple files')
    project_group.add_argument('--project-type', default='firmware',
                               choices=['application', 'framework', 'library', 'container', 'platform',
                                       'operating-system', 'device', 'device-driver', 'firmware', 'file',
                                       'machine-learning-model', 'data'],
                               help='Project type (default: firmware)')
    project_group.add_argument('--release-type', default='RELEASE',
                               choices=['RELEASE', 'PRE-RELEASE'],
                               help='Version release type (default: RELEASE). '
                                    'WARNING: Using PRE-RELEASE may cause new versions to replace previous ones.')
    project_group.add_argument('--reuse-latest-version', action='store_true',
                               help='Reuse the latest existing version instead of creating a new one. '
                                    'This prevents new versions from replacing previous ones in the UI.')
    project_group.add_argument('--folder', '--folder-id', dest='folder',
                               help='Folder ID or name (will be looked up if name provided)')

    # Scan type
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('--scan-type', default='binary',
                            choices=['binary', 'third-party', 'sbom'],
                            help='Scan type (default: binary)')
    scan_group.add_argument('--third-party-type', 
                            help='Third-party scan type (required for third-party scans)')
    scan_group.add_argument('--sbom-type', choices=['cdx', 'spdx'],
                            help='SBOM format type (cdx or spdx, auto-detected if not specified)')

    # Input
    input_group = parser.add_argument_group('Input')
    input_group.add_argument('files', nargs='*', 
                            help='Files or directories to upload (default: current directory)')
    input_group.add_argument('--csv', type=Path, 
                            help='CSV file with upload specifications (columns: artifact_name, project_name, version, scan_type, destination_folder)')
    input_group.add_argument('--recursive', '-r', action='store_true',
                            help='Recursively process directories')

    # CLI tool option
    cli_group = parser.add_argument_group('CLI Tool Options', 
                                         'Use the Finite State CLI tool instead of the API (useful for large files >50MB)')
    cli_group.add_argument('--use-cli', action='store_true',
                          help='Use the Finite State CLI tool (finitestate.jar) instead of the API')
    cli_group.add_argument('--cli-tool-path', default=None,
                          help='Path to the CLI tool jar file (default: finitestate.jar)')
    cli_group.add_argument('--branch', 
                          help='Branch name for version creation (CLI mode only)')

    # Options
    options_group = parser.add_argument_group('Options')
    options_group.add_argument('--yes', '--auto-accept', action='store_true',
                              help='Skip confirmation prompt')
    options_group.add_argument('--dry-run', action='store_true',
                              help='Preview what would be uploaded without actually uploading')

    args = parser.parse_args()

    # Validate mutually exclusive inputs
    if args.csv and args.files:
        parser.error("Cannot specify both --csv and file arguments")

    # Get authentication
    auth_token = args.auth_token or os.environ.get('FINITE_STATE_AUTH_TOKEN')
    domain = args.domain or os.environ.get('FINITE_STATE_DOMAIN')

    if not auth_token:
        parser.error("--auth-token or FINITE_STATE_AUTH_TOKEN environment variable required")
    if not domain:
        parser.error("--domain or FINITE_STATE_DOMAIN environment variable required")

    # Initialize uploader
    uploader = FiniteStateUploader(
        auth_token, 
        domain,
        cli_tool_path=args.cli_tool_path,
        use_cli=args.use_cli
    )

    # Resolve folder ID if provided
    folder_id = None
    if args.folder:
        try:
            folder_id = uploader.resolve_folder_id(args.folder)
        except Exception as e:
            parser.error(f"Folder error: {e}")

    # Collect uploads
    uploads = []

    if args.csv:
        # Parse CSV
        csv_rows = uploader.parse_csv(args.csv)
        for row in csv_rows:
            file_path = Path(row['artifact_name']).expanduser().resolve()
            if not file_path.exists():
                print(f"Warning: File not found: {file_path}")
                continue

            project_name = args.project or row.get('project_name')
            version_name = args.version or row.get('version')
            
            if not project_name:
                print(f"Warning: Row skipped - project name required (file: {file_path})")
                continue
            if not version_name:
                print(f"Warning: Row skipped - version required (file: {file_path})")
                continue

            row_folder_id = None
            if row.get('destination_folder'):
                row_folder_id = uploader.resolve_folder_id(row.get('destination_folder'))

            upload = {
                'file_path': file_path,
                'project_name': project_name,
                'version': version_name,
                'scan_type': row.get('scan_type') or args.scan_type,
                'folder_id': folder_id or row_folder_id,
                'project_type': args.project_type,
                'release_type': args.release_type,
                'branch': args.branch,
                'version_explicit': True  # CSV always has explicit version
            }

            # Handle per-row scan type specifics
            if upload['scan_type'] == 'third-party':
                if not args.third_party_type:
                    print(f"Warning: Row skipped - --third-party-type required for third-party scans (file: {file_path})")
                    continue
                upload['third_party_type'] = args.third_party_type
            elif upload['scan_type'] == 'sbom':
                upload['sbom_type'] = args.sbom_type

            uploads.append(upload)
    else:
        # Use positional arguments or default to current directory
        inputs = args.files if args.files else ['.']
        files = uploader.collect_files(inputs, args.recursive)

        if not files:
            parser.error("No files found to upload")

        # When uploading multiple files, each gets its own project
        # Use filename (without extension) as project name if not specified
        # Track whether version was explicitly provided
        version_explicit = args.version is not None
        default_version = args.version or '1.0'

        # If project is specified and there's only one file, use project name as-is
        # If project is specified and there are multiple files, use it as prefix
        # If no project is specified, use filename stem
        use_project_as_prefix = args.project and len(files) > 1

        for file_path in files:
            if args.project:
                if use_project_as_prefix:
                    # Multiple files: use project name as prefix with filename
                    project_name = f"{args.project}-{file_path.stem}"
                else:
                    # Single file: use project name as-is
                    project_name = args.project
            else:
                # Use filename (without extension) as project name
                project_name = file_path.stem
            
            upload = {
                'file_path': file_path,
                'project_name': project_name,
                'version': default_version,
                'scan_type': args.scan_type,
                'folder_id': folder_id,
                'project_type': args.project_type,
                'release_type': args.release_type,
                'branch': args.branch,
                'version_explicit': version_explicit
            }

            if args.scan_type == 'third-party':
                if not args.third_party_type:
                    parser.error("--third-party-type required for third-party scans")
                upload['third_party_type'] = args.third_party_type
            elif args.scan_type == 'sbom':
                upload['sbom_type'] = args.sbom_type

            uploads.append(upload)

    # Show summary
    print(uploader.generate_summary(uploads))

    # Confirm unless --yes or --dry-run
    if not args.yes and not args.dry_run:
        response = input("\nProceed with upload? (y/n): ")
        if response.lower() != 'y':
            print("Upload cancelled.")
            return

    # Process uploads
    if args.dry_run:
        print("\n[DRY RUN] No files were actually uploaded.")
    else:
        print("\nStarting uploads...")
        uploader.process_uploads(uploads, args.dry_run, args.reuse_latest_version)

        # Print summary
        print(f"\n{'=' * 60}")
        print(f"Upload complete: {len(uploader.successes)} succeeded, {len(uploader.errors)} failed")
        if uploader.errors:
            print("\nErrors:")
            for error in uploader.errors:
                print(f"  - {error}")


if __name__ == '__main__':
    main()

