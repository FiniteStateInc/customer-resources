#!/usr/bin/env python3
"""
Apply VEX Triage Recommendations to Finite State Platform.

.. deprecated::
    This standalone script is deprecated.  Use the built-in CLI instead::

        fs-report run --apply-vex-triage <file> [--dry-run]

    This script remains for backward compatibility with existing workflows.
"""

import argparse
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Suppress noisy httpx logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


def main() -> None:
    print(
        "WARNING: This script is deprecated. "
        "Use 'fs-report run --apply-vex-triage <file>' instead.",
        file=sys.stderr,
    )

    parser = argparse.ArgumentParser(
        description="Apply VEX triage recommendations to Finite State Platform "
        "(DEPRECATED — use 'fs-report run --apply-vex-triage' instead)",
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to vex_recommendations.json",
    )
    parser.add_argument("--token", type=str, default=None)
    parser.add_argument("--domain", type=str, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--filter-band", type=str, default=None)
    parser.add_argument("--filter-status", type=str, default=None)
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        choices=range(1, 6),
        metavar="1-5",
    )
    parser.add_argument("--yes", "-y", action="store_true")
    parser.add_argument("--response", type=str, default=None)
    parser.add_argument("--justification", type=str, default=None)
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    auth_token = args.token or os.getenv("FINITE_STATE_AUTH_TOKEN", "")
    if not auth_token:
        logger.error("API token required. Set FINITE_STATE_AUTH_TOKEN or use --token.")
        sys.exit(1)

    domain = args.domain or os.getenv("FINITE_STATE_DOMAIN", "")
    if not domain:
        logger.error("Domain required. Set FINITE_STATE_DOMAIN or use --domain.")
        sys.exit(1)

    filter_bands = args.filter_band.split(",") if args.filter_band else None
    filter_statuses = args.filter_status.split(",") if args.filter_status else None

    # Delegate to the library module
    from fs_report.vex_applier import VexApplier

    applier = VexApplier(
        auth_token=auth_token,
        domain=domain,
        concurrency=args.concurrency,
        dry_run=args.dry_run,
        vex_override=args.overwrite,
        filter_bands=filter_bands,
        filter_statuses=filter_statuses,
    )

    if not args.dry_run and not args.yes:
        # Keep the interactive confirmation for backward compat
        from fs_report.vex_applier import filter_recommendations, load_recommendations

        recs = load_recommendations(args.input)
        recs = filter_recommendations(recs, filter_bands, filter_statuses)
        answer = (
            input(f"\nApply up to {len(recs)} VEX status updates? [y/N]: ")
            .strip()
            .lower()
        )
        if answer != "y":
            print("Aborted.")
            return

    result = applier.apply_file(args.input)

    # Print summary
    rate = result.total / result.elapsed_seconds if result.elapsed_seconds > 0 else 0
    tag = "[DRY RUN] " if result.dry_run else ""
    print(f"\n{'=' * 60}")
    print(f"{tag}VEX Update Results")
    print(f"{'=' * 60}")
    print(f"Total processed:   {result.total}")
    print(f"Succeeded:         {result.succeeded}")
    print(f"Failed:            {result.failed}")
    if result.skipped_invalid:
        print(f"Skipped (invalid): {result.skipped_invalid}")
    if result.skipped_existing:
        print(f"Skipped (existing):{result.skipped_existing}")
    print(f"Time:              {result.elapsed_seconds:.1f}s ({rate:.0f} req/s)")
    print(f"{'=' * 60}")

    if result.results_path:
        logger.info(f"Results written to {result.results_path}")


if __name__ == "__main__":
    main()
