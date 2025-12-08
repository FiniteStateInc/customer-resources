"""API client for Finite State API operations."""

from typing import Optional
import requests
from rich.console import Console

console = Console()


def resolve_project_id_to_name(project_id: int, domain: str, auth_token: str) -> Optional[str]:
    """
    Resolve project ID to project name using Finite State API.
    
    Args:
        project_id: Project ID to resolve
        domain: Finite State domain URL
        auth_token: Authentication token
    
    Returns:
        Project name if found, None otherwise
    """
    url = f"{domain}/api/public/v0/projects/{project_id}"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("name")
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error resolving project ID {project_id}: {e}[/red]")
        return None


def resolve_version_id_to_name(project_version_id: int, domain: str, auth_token: str) -> Optional[tuple[str, str]]:
    """
    Resolve project version ID to (project_name, version_name) using Finite State API.
    
    Args:
        project_version_id: Project version ID to resolve
        domain: Finite State domain URL
        auth_token: Authentication token
    
    Returns:
        Tuple of (project_name, version_name) if found, None otherwise
    """
    # First get version details
    url = f"{domain}/api/public/v0/versions/{project_version_id}"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        version_data = response.json()
        
        # Get project name - check if project object has name directly
        project_name = None
        if "project" in version_data:
            if isinstance(version_data["project"], dict):
                project_name = version_data["project"].get("name")
                if not project_name:
                    # Fall back to resolving by ID
                    project_id = version_data["project"].get("id")
                    if project_id:
                        project_name = resolve_project_id_to_name(int(project_id), domain, auth_token)
            elif isinstance(version_data["project"], (int, str)):
                # Project is just an ID, resolve it
                project_name = resolve_project_id_to_name(int(version_data["project"]), domain, auth_token)
        
        # If still no project name, try projectId field
        if not project_name:
            project_id = version_data.get("projectId")
            if project_id:
                project_name = resolve_project_id_to_name(int(project_id), domain, auth_token)
        
        if not project_name:
            console.print(f"[red]Could not find project name for version {project_version_id}[/red]")
            return None
        
        # Get version name - check multiple possible fields
        version_name = version_data.get("name") or version_data.get("version")
        if not version_name:
            console.print(f"[red]Could not find version name in version {project_version_id}[/red]")
            return None
        
        return (project_name, version_name)
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error resolving version ID {project_version_id}: {e}[/red]")
        return None

