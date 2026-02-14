#!/usr/bin/env python3
"""
Apply VEX Triage Recommendations to Finite State Platform.

Reads VEX recommendations produced by the Triage Prioritization report
and updates finding statuses in the platform via the API.

Usage:
    # Uses FINITE_STATE_AUTH_TOKEN and FINITE_STATE_DOMAIN env vars by default
    python scripts/apply_vex_triage.py \
        --input output/triage_prioritization/vex_recommendations.json \
        [--dry-run] \
        [--filter-band CRITICAL,HIGH] \
        [--batch-size 10] \
        [--yes]

    # Or pass token and domain explicitly
    python scripts/apply_vex_triage.py \
        --input output/triage_prioritization/vex_recommendations.json \
        --token $FINITE_STATE_AUTH_TOKEN \
        --domain platform.finitestate.io \
        [--dry-run]

The script processes the vex_recommendations.json file produced by the
Triage Prioritization report and calls:
    PUT /public/v0/findings/{projectVersionId}/{findingId}/status

VEX Status Mapping:
    CRITICAL/HIGH  → EXPLOITABLE
    MEDIUM         → IN_TRIAGE
    LOW/INFO       → IN_TRIAGE (default) or NOT_AFFECTED (if unreachable)
"""

import argparse
import json
import logging
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import httpx
except ImportError:
    print("Error: httpx is required. Install with: pip install httpx")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None  # type: ignore[assignment, misc]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Suppress noisy httpx request/response logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Valid VEX statuses for the Finite State API
VALID_VEX_STATUSES = {
    "EXPLOITABLE",
    "IN_TRIAGE",
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
}

# Valid API enum values for the `response` field
VALID_VEX_RESPONSES = {
    "CAN_NOT_FIX",
    "WILL_NOT_FIX",
    "UPDATE",
    "ROLLBACK",
    "WORKAROUND_AVAILABLE",
}

# Valid API enum values for the `justification` field
VALID_VEX_JUSTIFICATIONS = {
    "CODE_NOT_PRESENT",
    "CODE_NOT_REACHABLE",
    "REQUIRES_CONFIGURATION",
    "REQUIRES_DEPENDENCY",
    "REQUIRES_ENVIRONMENT",
    "PROTECTED_BY_COMPILER",
    "PROTECTED_AT_RUNTIME",
    "PROTECTED_AT_PERIMETER",
    "PROTECTED_BY_MITIGATING_CONTROL",
}

# API workaround: all statuses require response + justification even when
# not semantically meaningful. These defaults are auto-filled when the user
# does not provide explicit overrides.
# See fs-smartsheets engine.py for the same workaround.
DEFAULT_API_RESPONSE = "WILL_NOT_FIX"
DEFAULT_API_JUSTIFICATION = "CODE_NOT_PRESENT"


def get_smart_defaults(
    vex_status: str,
    reachability_label: str = "INCONCLUSIVE",
) -> tuple[str, str]:
    """Pick contextually appropriate response/justification enum defaults.

    Args:
        vex_status: The VEX status being set (e.g., EXPLOITABLE, NOT_AFFECTED).
        reachability_label: REACHABLE, UNREACHABLE, or INCONCLUSIVE from triage data.

    Returns:
        (response_enum, justification_enum) tuple.
    """
    if vex_status == "NOT_AFFECTED":
        if reachability_label == "UNREACHABLE":
            return (DEFAULT_API_RESPONSE, "CODE_NOT_REACHABLE")
        return (DEFAULT_API_RESPONSE, DEFAULT_API_JUSTIFICATION)

    # For EXPLOITABLE, IN_TRIAGE, and all others: use generic defaults.
    return (DEFAULT_API_RESPONSE, DEFAULT_API_JUSTIFICATION)


def load_recommendations(input_path: str) -> list[dict[str, object]]:
    """Load VEX recommendations from JSON file."""
    path = Path(input_path)
    if not path.exists():
        logger.error(f"File not found: {input_path}")
        sys.exit(1)

    with open(path) as f:
        recs: list[dict[str, object]] = json.load(f)

    logger.info(f"Loaded {len(recs)} VEX recommendations from {input_path}")
    return recs


def filter_recommendations(
    recs: list[dict],
    filter_bands: list[str] | None = None,
    filter_statuses: list[str] | None = None,
) -> list[dict]:
    """Filter recommendations by band and/or VEX status."""
    filtered = recs

    if filter_bands:
        bands_upper = [b.upper() for b in filter_bands]
        filtered = [r for r in filtered if r.get("priority_band", "") in bands_upper]
        logger.info(f"Filtered to {len(filtered)} recommendations for bands: {bands_upper}")

    if filter_statuses:
        statuses_upper = [s.upper() for s in filter_statuses]
        filtered = [r for r in filtered if r.get("recommended_vex_status", "") in statuses_upper]
        logger.info(f"Filtered to {len(filtered)} recommendations for statuses: {statuses_upper}")

    return filtered


def validate_recommendations(recs: list[dict]) -> tuple[list[dict], list[dict]]:
    """Validate recommendations have required fields. Returns (valid, invalid)."""
    valid = []
    invalid = []

    for rec in recs:
        internal_id = rec.get("id", "")
        _finding_id = rec.get("finding_id", "")  # noqa: F841 – kept for debugging
        pv_id = rec.get("project_version_id", "")
        vex_status = rec.get("recommended_vex_status", "")

        errors = []
        if not internal_id:
            errors.append("missing id (internal primary key)")
        if not pv_id:
            errors.append("missing project_version_id")
        if vex_status not in VALID_VEX_STATUSES:
            errors.append(f"invalid VEX status: {vex_status}")

        if errors:
            rec["_validation_errors"] = errors
            invalid.append(rec)
        else:
            valid.append(rec)

    if invalid:
        logger.warning(f"{len(invalid)} recommendations have validation errors")
        for inv in invalid[:5]:
            logger.warning(
                f"  Finding {inv.get('finding_id', '?')}: {inv.get('_validation_errors')}"
            )
        if len(invalid) > 5:
            logger.warning(f"  ... and {len(invalid) - 5} more")

    return valid, invalid


# Retry configuration (matches fs-smartsheets pattern)
# 500s are not retried — they typically indicate bad data, not transient issues
RETRY_STATUS_CODES = {429, 502, 503, 504}
MAX_RETRIES = 6
MAX_RETRY_DELAY = 64  # seconds


def apply_vex_status(
    client: httpx.Client,
    base_url: str,
    project_version_id: str,
    finding_id: str,
    vex_status: str,
    reason: str,
    response_enum: str | None = None,
    justification_enum: str | None = None,
    reachability_label: str = "INCONCLUSIVE",
) -> dict:
    """
    Update a finding's VEX status via the API with retry on rate-limit/server errors.

    PUT /public/v0/findings/{projectVersionId}/{findingId}/status

    Retries on 429 (rate limit), 502, 503, 504 with exponential backoff
    and jitter, matching the fs-smartsheets retry strategy.

    API workaround: the endpoint requires `response` and `justification`
    enum fields on every request, even when they are not semantically
    meaningful for a given status. We auto-fill smart defaults when the
    caller does not provide explicit overrides.
    """
    url = f"{base_url}/api/public/v0/findings/{project_version_id}/{finding_id}/status"

    # Determine response + justification enums
    default_resp, default_just = get_smart_defaults(vex_status, reachability_label)
    final_response = response_enum or default_resp
    final_justification = justification_enum or default_just

    body = {
        "status": vex_status,
        "response": final_response,
        "justification": final_justification,
    }

    # Include free-text reason/comment if available
    if reason:
        body["reason"] = reason

    logger.debug(f"PUT {url} body={body}")

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.put(url, json=body)
            resp.raise_for_status()
            return {"success": True, "status_code": resp.status_code}
        except httpx.HTTPStatusError as e:
            if e.response.status_code in RETRY_STATUS_CODES and attempt < MAX_RETRIES - 1:
                delay = min(2 ** attempt, MAX_RETRY_DELAY) + random.uniform(0, 1)
                logger.warning(
                    f"Rate limited ({e.response.status_code}) on {finding_id}, "
                    f"retry {attempt + 1}/{MAX_RETRIES} in {delay:.1f}s"
                )
                time.sleep(delay)
                continue
            return {
                "success": False,
                "status_code": e.response.status_code,
                "error": str(e),
                "response_body": e.response.text[:500],
            }
        except httpx.RequestError as e:
            if attempt < MAX_RETRIES - 1:
                delay = min(2 ** attempt, MAX_RETRY_DELAY) + random.uniform(0, 1)
                logger.warning(
                    f"Connection error on {finding_id}, "
                    f"retry {attempt + 1}/{MAX_RETRIES} in {delay:.1f}s"
                )
                time.sleep(delay)
                continue
            return {"success": False, "error": str(e)}

    return {"success": False, "error": "Max retries exceeded"}


def print_summary(recs: list[dict]) -> None:
    """Print a summary of recommendations before applying."""
    band_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}

    for rec in recs:
        band = rec.get("priority_band", "UNKNOWN")
        status = rec.get("recommended_vex_status", "UNKNOWN")
        band_counts[band] = band_counts.get(band, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1

    print("\n" + "=" * 60)
    print("VEX Triage Recommendations Summary")
    print("=" * 60)
    print(f"\nTotal findings: {len(recs)}")

    print("\nBy Priority Band:")
    for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = band_counts.get(band, 0)
        if count > 0:
            print(f"  {band:10s}: {count:5d}")

    print("\nBy VEX Status:")
    for status in sorted(status_counts.keys()):
        count = status_counts[status]
        print(f"  {status:25s}: {count:5d}")

    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply VEX triage recommendations to Finite State Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to vex_recommendations.json from Triage Prioritization report",
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="Finite State API token (default: $FINITE_STATE_AUTH_TOKEN)",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default=None,
        help="Finite State domain, e.g. platform.finitestate.io (default: $FINITE_STATE_DOMAIN)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making API calls",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite findings that already have a VEX status set. "
             "By default, findings with an existing status are skipped.",
    )
    parser.add_argument(
        "--filter-band",
        type=str,
        default=None,
        help="Comma-separated bands to apply (e.g., CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--filter-status",
        type=str,
        default=None,
        help="Comma-separated VEX statuses to apply (e.g., EXPLOITABLE)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        choices=range(1, 6),
        metavar="1-5",
        help="Number of parallel API requests, 1-5 (default: 5). "
             "Values above 5 are not supported — they overwhelm the server.",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )
    parser.add_argument(
        "--response",
        type=str,
        default=None,
        choices=sorted(VALID_VEX_RESPONSES),
        help=(
            "Override the VEX response enum for all updates. "
            "If not set, smart defaults are chosen per status/reachability. "
            f"(API workaround default: {DEFAULT_API_RESPONSE})"
        ),
    )
    parser.add_argument(
        "--justification",
        type=str,
        default=None,
        choices=sorted(VALID_VEX_JUSTIFICATIONS),
        help=(
            "Override the VEX justification enum for all updates. "
            "If not set, smart defaults are chosen per status/reachability. "
            f"(API workaround default: {DEFAULT_API_JUSTIFICATION})"
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Resolve token and domain from args or environment variables
    auth_token = args.token or os.getenv("FINITE_STATE_AUTH_TOKEN", "")
    if not auth_token:
        logger.error(
            "API token required. Set FINITE_STATE_AUTH_TOKEN environment variable or use --token."
        )
        sys.exit(1)

    domain = args.domain or os.getenv("FINITE_STATE_DOMAIN", "")
    if not domain:
        logger.error(
            "Domain required. Set FINITE_STATE_DOMAIN environment variable or use --domain."
        )
        sys.exit(1)

    # Normalize domain (strip protocol and trailing slash)
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    # Load recommendations
    recs = load_recommendations(args.input)
    if not recs:
        logger.info("No recommendations to process")
        return

    # Filter by band/status
    filter_bands = args.filter_band.split(",") if args.filter_band else None
    filter_statuses = args.filter_status.split(",") if args.filter_status else None
    recs = filter_recommendations(recs, filter_bands, filter_statuses)

    if not recs:
        logger.info("No recommendations after filtering")
        return

    # Skip findings that already have a VEX status (unless --overwrite)
    if not args.overwrite:
        def _has_status(r: dict) -> bool:
            v = r.get("current_vex_status")
            return v is not None and v != "" and not (isinstance(v, float))

        already_set = [r for r in recs if _has_status(r)]
        recs = [r for r in recs if not _has_status(r)]
        if already_set:
            status_counts: dict[str, int] = {}
            for r in already_set:
                s = str(r["current_vex_status"])
                status_counts[s] = status_counts.get(s, 0) + 1
            breakdown = ", ".join(f"{s}: {c}" for s, c in sorted(status_counts.items()))
            logger.info(
                f"Skipping {len(already_set)} findings with existing VEX status "
                f"({breakdown}). Use --overwrite to update them."
            )
        if not recs:
            logger.info("No findings without an existing status to update")
            return

    # Validate
    valid_recs, invalid_recs = validate_recommendations(recs)
    if not valid_recs:
        logger.error("No valid recommendations to apply")
        return

    # Summary
    print_summary(valid_recs)

    # Confirmation
    if args.dry_run:
        print("\n[DRY RUN] No changes will be made.")
        for rec in valid_recs[:10]:
            reach = rec.get("reachability_label", "INCONCLUSIVE")
            default_resp, default_just = get_smart_defaults(
                rec["recommended_vex_status"], reach
            )
            resp_display = args.response or default_resp
            just_display = args.justification or default_just
            print(
                f"  Would set finding {rec['finding_id']} "
                f"(PV: {rec['project_version_id']}) "
                f"→ {rec['recommended_vex_status']} "
                f"[response={resp_display}, justification={just_display}] "
                f"(band: {rec['priority_band']}, score: {rec.get('triage_score', '?')})"
            )
        if len(valid_recs) > 10:
            print(f"  ... and {len(valid_recs) - 10} more")
        return

    if not args.yes:
        answer = input(f"\nApply {len(valid_recs)} VEX status updates? [y/N]: ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    # Apply updates concurrently
    base_url = f"https://{domain}"
    concurrency = args.concurrency
    logger.info(f"Applying {len(valid_recs)} updates with concurrency={concurrency}")

    succeeded = 0
    failed = 0
    results = []
    start_time = time.monotonic()

    def _update_one(rec: dict) -> dict:
        """Process a single VEX update in a thread."""
        internal_id = rec["id"]
        finding_id = rec.get("finding_id", internal_id)
        pv_id = rec["project_version_id"]
        vex_status = rec["recommended_vex_status"]
        reason = rec.get("reason", "")
        reachability_label = rec.get("reachability_label", "INCONCLUSIVE")

        # Each thread gets its own client to avoid connection sharing issues
        client = httpx.Client(
            headers={
                "X-Authorization": auth_token,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        try:
            result = apply_vex_status(
                client, base_url, pv_id, internal_id, vex_status, reason,
                response_enum=args.response,
                justification_enum=args.justification,
                reachability_label=reachability_label,
            )
        finally:
            client.close()

        result["id"] = internal_id
        result["finding_id"] = finding_id
        result["project_version_id"] = pv_id
        result["vex_status"] = vex_status
        return result

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(_update_one, rec): rec
            for rec in valid_recs
        }

        total = len(valid_recs)
        pbar = tqdm(
            total=total,
            desc="Applying VEX updates",
            unit="finding",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]  {postfix}",
        ) if tqdm is not None else None

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            if result["success"]:
                succeeded += 1
            else:
                failed += 1
                logger.warning(
                    f"Failed: {result['finding_id']} (id={result['id']}): "
                    f"{result.get('error', 'unknown error')}"
                )

            if pbar:
                pbar.set_postfix_str(f"ok={succeeded} fail={failed}", refresh=False)
                pbar.update(1)

        if pbar:
            pbar.close()

    elapsed = time.monotonic() - start_time

    # Final summary
    rate = len(results) / elapsed if elapsed > 0 else 0
    print(f"\n{'=' * 60}")
    print("VEX Update Results")
    print(f"{'=' * 60}")
    print(f"Total processed: {len(results)}")
    print(f"Succeeded:       {succeeded}")
    print(f"Failed:          {failed}")
    if invalid_recs:
        print(f"Skipped (invalid): {len(invalid_recs)}")
    print(f"Time:            {elapsed:.1f}s ({rate:.0f} req/s)")

    # Breakdown of failures by HTTP status code
    if failed > 0:
        error_codes: dict[str, int] = {}
        for r in results:
            if not r.get("success"):
                code = str(r.get("status_code", "connection_error"))
                error_codes[code] = error_codes.get(code, 0) + 1
        print("\nFailures by error code:")
        for code, count in sorted(error_codes.items()):
            print(f"  HTTP {code}: {count}")

    print(f"{'=' * 60}")

    # Write results log
    results_path = Path(args.input).parent / "vex_apply_results.json"
    with open(results_path, "w") as f:
        json.dump(
            {
                "summary": {
                    "total": len(results),
                    "succeeded": succeeded,
                    "failed": failed,
                    "skipped_invalid": len(invalid_recs),
                },
                "results": results,
                "invalid": [
                    {k: v for k, v in r.items() if not k.startswith("_")}
                    for r in invalid_recs
                ],
            },
            f,
            indent=2,
            default=str,
        )
    logger.info(f"Results written to {results_path}")


if __name__ == "__main__":
    main()
