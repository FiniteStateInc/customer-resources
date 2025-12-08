"""CLI runner for Finite State CLI operations."""

import subprocess
from pathlib import Path
from rich.console import Console

console = Console()


def upload_sbom(
    project_name: str,
    version_name: str,
    sbom_path: str,
    cli_jar: str,
    java_path: str,
    dry_run: bool
) -> bool:
    """
    Upload SBOM to Finite State using CLI.
    
    Args:
        project_name: Project name
        version_name: Version name
        sbom_path: Path to SBOM JSON file
        cli_jar: Path to finitestate.jar
        java_path: Path to java executable
        dry_run: If True, only print command without executing
    
    Returns:
        True if successful, False otherwise
    """
    sbom_file = Path(sbom_path)
    if not sbom_file.exists():
        console.print(f"[red]SBOM file not found: {sbom_path}[/red]")
        return False
    
    jar_file = Path(cli_jar)
    if not jar_file.exists():
        console.print(f"[red]CLI jar not found: {cli_jar}[/red]")
        return False
    
    # Build command
    cmd = [
        java_path,
        "-jar",
        str(jar_file.absolute()),
        "--import",
        str(sbom_file.absolute()),
        f"--name={project_name}",
        f"--version={version_name}"
    ]
    
    if dry_run:
        console.print(f"[yellow][DRY-RUN] Would run:[/yellow]")
        console.print(f"  {' '.join(cmd)}")
        return True
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            console.print(f"[green]✓[/green] Uploaded SBOM to {project_name}/{version_name}")
            return True
        else:
            console.print(f"[red]✗[/red] Failed to upload SBOM to {project_name}/{version_name}")
            if result.stdout:
                console.print(f"[dim]stdout: {result.stdout}[/dim]")
            if result.stderr:
                console.print(f"[dim]stderr: {result.stderr}[/dim]")
            return False
            
    except subprocess.TimeoutExpired:
        console.print(f"[red]✗[/red] Timeout uploading SBOM to {project_name}/{version_name}")
        return False
    except Exception as e:
        console.print(f"[red]✗[/red] Error uploading SBOM to {project_name}/{version_name}: {e}")
        return False

