#!/usr/bin/env python3
"""
Command-line interface for Finite State Reporter.
"""
import argparse
import os
import sys

from .core.reporter import main


def cli():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate PDF reports from Finite State API data"
    )
    parser.add_argument(
        "-t",
        "--token",
        help="Finite State API token (can also use FINITE_STATE_AUTH_TOKEN environment variable)",
    )
    parser.add_argument(
        "-s",
        "--subdomain",
        help="Finite State subdomain (e.g., 'acme' for acme.finitestate.io) (can also use FINITE_STATE_DOMAIN environment variable)",
    )

    # Create mutually exclusive group for version identification
    version_group = parser.add_mutually_exclusive_group(required=False)
    version_group.add_argument(
        "-pvi",
        "--project-version-id",
        help="Project version ID to generate report for",
    )
    version_group.add_argument(
        "-p",
        "--project",
        help="Project name (must be used with --project-version)",
    )
    parser.add_argument(
        "-pv",
        "--project-version",
        help="Project version (must be used with --project)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="risk_summary_report.pdf",
        help="Output PDF filename (default: risk_summary_report.pdf)",
    )

    parser.add_argument(
        "-d",
        "--detailed-findings",
        action="store_true",
        help="Include detailed findings section in the report (shows Critical/High severity and Medium severity with exploit info by default)",
    )
    parser.add_argument(
        "-a",
        "--all-severities",
        action="store_true",
        help="Include all severity levels in detailed findings (overrides default Critical/High filter). Use with -m to set maximum findings.",
    )
    parser.add_argument(
        "-m",
        "--max-detailed-findings",
        type=int,
        default=100,
        help="Maximum number of detailed findings to include when using --all-severities (default: 100)",
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Organization name to display on the report cover and header (defaults to subdomain if not provided)",
    )

    args = parser.parse_args()

    # Check environment variables for token and subdomain if not provided
    token = args.token
    subdomain = args.subdomain

    if not token:
        token = os.environ.get("FINITE_STATE_AUTH_TOKEN")
        if not token:
            parser.error("--token (-t) is required or set FINITE_STATE_AUTH_TOKEN environment variable")

    if not subdomain:
        domain = os.environ.get("FINITE_STATE_DOMAIN")
        if domain:
            # Extract subdomain from domain (e.g., "acme.finitestate.io" -> "acme")
            subdomain = domain.split(".")[0]
        else:
            parser.error("--subdomain (-s) is required or set FINITE_STATE_DOMAIN environment variable")

    # Validate that project and project-version are used together
    if args.project and not args.project_version:
        parser.error("--project (-p) requires --project-version (-pv)")
    if args.project_version and not args.project:
        parser.error("--project-version (-pv) requires --project (-p)")

    # Validate that max-detailed-findings is only used with all-severities
    if args.max_detailed_findings != 100 and not args.all_severities:
        parser.error(
            "--max-detailed-findings (-m) can only be used with --all-severities (-a)"
        )

    try:
        # Determine version_id from arguments
        version_id = args.project_version_id

        # If project name and version name are provided, lookup the version ID
        if args.project and args.project_version:
            from .core.reporter import FiniteStateReporter

            print(
                f"Looking up version ID for project '{args.project}' and version '{args.project_version}'..."
            )
            reporter = FiniteStateReporter(subdomain, token)
            try:
                version_id = reporter.lookup_version_id_by_names(
                    args.project, args.project_version
                )
                print(f"Found version ID: {version_id}")
            except ValueError as e:
                # Check if this is a project not found error
                error_msg = str(e)
                if "Project" in error_msg and "not found" in error_msg:
                    print("❌ Project not found.", file=sys.stderr)
                    sys.exit(1)
                else:
                    # Re-raise for other ValueError cases
                    raise
        
        # Validate that at least one version identification method is provided
        # (do this after project lookup so we can show proper error for project not found)
        if not version_id:
            parser.error("one of the arguments -pvi/--project-version-id -p/--project is required")

        main(
            token,
            subdomain,
            version_id,
            args.output,
            detailed_findings=args.detailed_findings,
            all_severities=args.all_severities,
            max_detailed_findings=args.max_detailed_findings,
            organization_name=args.name,
        )
        print(f"Report generated successfully: {args.output}")
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli()
