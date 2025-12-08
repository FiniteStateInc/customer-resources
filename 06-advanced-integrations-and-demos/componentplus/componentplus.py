#!/usr/bin/env python3
"""Main entry point for component injection script."""

import csv
import os
import sys
from pathlib import Path
from typing import List, Set, Dict, Optional
import logging

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from models import ComponentRecord, TargetVersion, ResolvedTarget, ScriptConfig
from cyclonedx_builder import build_sbom, write_sbom
from api_client import resolve_project_id_to_name, resolve_version_id_to_name
from cli_runner import upload_sbom

console = Console()


def validate_environment() -> tuple[str, str]:
    """
    Validate required environment variables.
    
    Returns:
        Tuple of (auth_token, domain)
    
    Raises:
        SystemExit: If environment variables are missing
    """
    auth_token = os.getenv("FINITE_STATE_AUTH_TOKEN")
    domain = os.getenv("FINITE_STATE_DOMAIN")
    
    if not auth_token or not domain:
        console.print("[red]ERROR: Missing FINITE_STATE_AUTH_TOKEN or FINITE_STATE_DOMAIN[/red]")
        console.print("Configure your Finite State CLI environment first.")
        sys.exit(1)
    
    return auth_token, domain


def load_components_csv(csv_path: str) -> List[ComponentRecord]:
    """
    Load and validate components CSV.
    
    Args:
        csv_path: Path to components CSV file
    
    Returns:
        List of validated component records
    
    Raises:
        SystemExit: If CSV is invalid or cannot be read
    """
    required_columns = {"component_name", "component_version", "supplier_name", "swid_tag_id"}
    components = []
    seen = set()
    invalid_rows = []
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Check columns
            if not required_columns.issubset(reader.fieldnames or []):
                missing = required_columns - set(reader.fieldnames or [])
                console.print(f"[red]ERROR: Missing required columns in components CSV: {missing}[/red]")
                sys.exit(1)
            
            for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                # Trim whitespace from all fields
                component_name = row.get("component_name", "").strip()
                component_version = row.get("component_version", "").strip()
                supplier_name = row.get("supplier_name", "").strip()
                swid_tag_id = row.get("swid_tag_id", "").strip()
                
                # Validate all fields are non-empty
                if not all([component_name, component_version, supplier_name, swid_tag_id]):
                    invalid_rows.append((row_num, "Missing required field"))
                    continue
                
                # Create component record
                comp = ComponentRecord(
                    component_name=component_name,
                    component_version=component_version,
                    supplier_name=supplier_name,
                    swid_tag_id=swid_tag_id
                )
                
                # Deduplicate
                if comp not in seen:
                    seen.add(comp)
                    components.append(comp)
                else:
                    console.print(f"[yellow]Warning: Skipping duplicate component at row {row_num}[/yellow]")
        
        if invalid_rows:
            console.print(f"[yellow]Warning: Skipped {len(invalid_rows)} invalid rows in components CSV[/yellow]")
            for row_num, reason in invalid_rows[:10]:  # Show first 10
                console.print(f"  Row {row_num}: {reason}")
            if len(invalid_rows) > 10:
                console.print(f"  ... and {len(invalid_rows) - 10} more")
        
        if not components:
            console.print("[red]ERROR: No valid components found in CSV[/red]")
            sys.exit(1)
        
        console.print(f"[green]Loaded {len(components)} unique components[/green]")
        return components
        
    except FileNotFoundError:
        console.print(f"[red]ERROR: Components CSV not found: {csv_path}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]ERROR: Failed to read components CSV: {e}[/red]")
        sys.exit(1)


def load_targets_csv(csv_path: str) -> List[TargetVersion]:
    """
    Load and validate targets CSV.
    
    Args:
        csv_path: Path to targets CSV file
    
    Returns:
        List of target versions
    
    Raises:
        SystemExit: If CSV is invalid or cannot be read
    """
    targets = []
    invalid_rows = []
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            
            # Check if we have ID columns or name columns
            has_ids = "project_id" in fieldnames and "project_version_id" in fieldnames
            has_names = "project_name" in fieldnames and "project_version_name" in fieldnames
            
            if not has_ids and not has_names:
                console.print("[red]ERROR: Targets CSV must have either (project_id, project_version_id) or (project_name, project_version_name)[/red]")
                sys.exit(1)
            
            for row_num, row in enumerate(reader, start=2):
                target = TargetVersion()
                
                # If IDs are present, use them (take precedence)
                if has_ids:
                    project_id_str = row.get("project_id", "").strip()
                    version_id_str = row.get("project_version_id", "").strip()
                    
                    if project_id_str and version_id_str:
                        try:
                            target.project_id = int(project_id_str)
                            target.project_version_id = int(version_id_str)
                        except ValueError:
                            invalid_rows.append((row_num, "Invalid ID format"))
                            continue
                
                # If names are present and IDs weren't used, use names
                if has_names and not target.has_ids():
                    target.project_name = row.get("project_name", "").strip()
                    target.project_version_name = row.get("project_version_name", "").strip()
                
                # Validate target
                if not target.is_valid():
                    invalid_rows.append((row_num, "Missing required IDs or names"))
                    continue
                
                targets.append(target)
        
        if invalid_rows:
            console.print(f"[yellow]Warning: Skipped {len(invalid_rows)} invalid rows in targets CSV[/yellow]")
            for row_num, reason in invalid_rows[:10]:
                console.print(f"  Row {row_num}: {reason}")
            if len(invalid_rows) > 10:
                console.print(f"  ... and {len(invalid_rows) - 10} more")
        
        if not targets:
            console.print("[red]ERROR: No valid targets found in CSV[/red]")
            sys.exit(1)
        
        console.print(f"[green]Loaded {len(targets)} targets[/green]")
        return targets
        
    except FileNotFoundError:
        console.print(f"[red]ERROR: Targets CSV not found: {csv_path}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]ERROR: Failed to read targets CSV: {e}[/red]")
        sys.exit(1)


def resolve_targets_to_names(
    targets: List[TargetVersion],
    domain: str,
    auth_token: str
) -> List[ResolvedTarget]:
    """
    Resolve targets to names (resolve IDs if needed).
    
    Args:
        targets: List of target versions (may have IDs or names)
        domain: Finite State domain
        auth_token: Authentication token
    
    Returns:
        List of resolved targets with names
    """
    resolved = []
    resolution_cache: Dict[tuple[Optional[int], Optional[int]], Optional[ResolvedTarget]] = {}
    failed = []
    
    for target in targets:
        # If already has names, use them directly
        if target.has_names():
            resolved.append(ResolvedTarget(
                project_name=target.project_name or "",
                project_version_name=target.project_version_name or ""
            ))
            continue
        
        # If has IDs, resolve them
        if target.has_ids():
            cache_key = (target.project_id, target.project_version_id)
            
            # Check cache
            if cache_key in resolution_cache:
                cached = resolution_cache[cache_key]
                if cached:
                    resolved.append(cached)
                else:
                    failed.append(target)
                continue
            
            # Resolve version ID (this also gets project name)
            result = resolve_version_id_to_name(
                target.project_version_id or 0,
                domain,
                auth_token
            )
            
            if result:
                project_name, version_name = result
                resolved_target = ResolvedTarget(
                    project_name=project_name,
                    project_version_name=version_name
                )
                resolution_cache[cache_key] = resolved_target
                resolved.append(resolved_target)
            else:
                resolution_cache[cache_key] = None
                failed.append(target)
                console.print(f"[red]Failed to resolve project_id={target.project_id}, version_id={target.project_version_id}[/red]")
    
    if failed:
        console.print(f"[yellow]Warning: Failed to resolve {len(failed)} targets[/yellow]")
    
    return resolved


def deduplicate_targets(targets: List[ResolvedTarget]) -> List[ResolvedTarget]:
    """Deduplicate targets by (project_name, project_version_name)."""
    seen: Set[ResolvedTarget] = set()
    unique = []
    
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)
        else:
            console.print(f"[yellow]Warning: Skipping duplicate target: {target.project_name}/{target.project_version_name}[/yellow]")
    
    return unique


@click.command()
@click.option("--components-csv", required=True, type=click.Path(exists=True), help="Path to components CSV file")
@click.option("--targets-csv", required=True, type=click.Path(exists=True), help="Path to targets CSV file")
@click.option("--fs-cli-jar", default="./finitestate.jar", type=click.Path(), help="Path to finitestate.jar (default: ./finitestate.jar)")
@click.option("--dry-run", is_flag=True, help="Print commands without executing")
@click.option("--java-path", default="java", help="Path to java executable (default: java)")
@click.option("--output-dir", default="./sboms", type=click.Path(), help="Output directory for SBOM files (default: ./sboms)")
@click.option("--component-type", default="library", help="Component type for SBOM (default: library)")
@click.option("--log-level", default="INFO", type=click.Choice(["DEBUG", "INFO", "WARN", "ERROR"]), help="Log level")
@click.option("--log-file", type=click.Path(), help="Optional log file path")
def main(
    components_csv: str,
    targets_csv: str,
    fs_cli_jar: str,
    dry_run: bool,
    java_path: str,
    output_dir: str,
    component_type: str,
    log_level: str,
    log_file: Optional[str]
):
    """SBOM-based component injection script for Finite State."""
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(console=console, rich_tracebacks=True),
            *([logging.FileHandler(log_file)] if log_file else [])
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    # Validate environment
    auth_token, domain = validate_environment()
    
    # Load and validate CSVs
    console.print("\n[bold]Loading components CSV...[/bold]")
    components = load_components_csv(components_csv)
    
    console.print("\n[bold]Loading targets CSV...[/bold]")
    targets = load_targets_csv(targets_csv)
    
    # Resolve IDs to names if needed
    console.print("\n[bold]Resolving targets...[/bold]")
    resolved_targets = resolve_targets_to_names(targets, domain, auth_token)
    
    if not resolved_targets:
        console.print("[red]ERROR: No valid resolved targets[/red]")
        sys.exit(1)
    
    # Deduplicate
    unique_targets = deduplicate_targets(resolved_targets)
    console.print(f"[green]Processing {len(unique_targets)} unique targets[/green]")
    
    # Build SBOM
    console.print("\n[bold]Building SBOM...[/bold]")
    sbom = build_sbom(components, component_type)
    
    # Write SBOM
    output_path = Path(output_dir) / "shared_components.cdx.json"
    write_sbom(sbom, str(output_path))
    console.print(f"[green]SBOM written to: {output_path}[/green]")
    
    # Dry-run mode
    if dry_run:
        console.print("\n[bold yellow][DRY-RUN] Upload commands that would be executed:[/bold yellow]")
        for target in unique_targets:
            console.print(f"  java -jar {fs_cli_jar} --import {output_path} --name={target.project_name} --version={target.project_version_name}")
        console.print(f"\n[yellow]Total: {len(unique_targets)} uploads would be performed[/yellow]")
        sys.exit(0)
    
    # Upload SBOMs
    console.print("\n[bold]Uploading SBOMs...[/bold]")
    config = ScriptConfig(
        components_csv=components_csv,
        targets_csv=targets_csv,
        fs_cli_jar=fs_cli_jar,
        java_path=java_path,
        component_type=component_type,
        output_dir=output_dir,
        dry_run=dry_run,
        log_level=log_level,
        log_file=log_file
    )
    
    successes = []
    failures = []
    
    for target in unique_targets:
        success = upload_sbom(
            target.project_name,
            target.project_version_name,
            str(output_path),
            config.fs_cli_jar,
            config.java_path,
            config.dry_run
        )
        
        if success:
            successes.append(target)
        else:
            failures.append(target)
    
    # Print summary
    console.print("\n[bold]Summary:[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Count")
    
    table.add_row("[green]Success[/green]", str(len(successes)))
    table.add_row("[red]Failed[/red]", str(len(failures)))
    table.add_row("[bold]Total[/bold]", str(len(unique_targets)))
    
    console.print(table)
    
    if failures:
        console.print("\n[bold red]Failed targets:[/bold red]")
        for target in failures:
            console.print(f"  - {target.project_name}/{target.project_version_name}")
    
    # Exit with appropriate code
    if failures:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

