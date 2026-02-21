"""VEX triage application module.

Applies VEX recommendations produced by the Triage Prioritization report
to the Finite State platform via the API.

This module is the library counterpart of ``scripts/apply_vex_triage.py``.
It contains no ``sys.exit()``, ``input()`` prompts, or ``argparse`` —
all interaction is handled by the caller (CLI layer or script).
"""

from __future__ import annotations

import dataclasses
import json
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# Suppress noisy per-request httpx/httpcore logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# ── Constants ────────────────────────────────────────────────────────

VALID_VEX_STATUSES = {
    "EXPLOITABLE",
    "IN_TRIAGE",
    "NOT_AFFECTED",
    "FALSE_POSITIVE",
    "RESOLVED",
    "RESOLVED_WITH_PEDIGREE",
}

VALID_VEX_RESPONSES = {
    "CAN_NOT_FIX",
    "WILL_NOT_FIX",
    "UPDATE",
    "ROLLBACK",
    "WORKAROUND_AVAILABLE",
}

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
# not semantically meaningful.
DEFAULT_API_RESPONSE = "WILL_NOT_FIX"
DEFAULT_API_JUSTIFICATION = "CODE_NOT_PRESENT"

# Retry configuration (matches fs-smartsheets pattern).
# 500s are not retried — they typically indicate bad data, not transient issues.
RETRY_STATUS_CODES = {429, 502, 503, 504}
MAX_RETRIES = 6
MAX_RETRY_DELAY = 64  # seconds


# ── Pure helpers ─────────────────────────────────────────────────────


def get_smart_defaults(
    vex_status: str,
    reachability_label: str = "INCONCLUSIVE",
) -> tuple[str, str]:
    """Pick contextually appropriate response/justification enum defaults.

    Args:
        vex_status: The VEX status being set (e.g., EXPLOITABLE, NOT_AFFECTED).
        reachability_label: REACHABLE, UNREACHABLE, or INCONCLUSIVE.

    Returns:
        ``(response_enum, justification_enum)`` tuple.
    """
    if vex_status == "NOT_AFFECTED":
        if reachability_label == "UNREACHABLE":
            return (DEFAULT_API_RESPONSE, "CODE_NOT_REACHABLE")
        return (DEFAULT_API_RESPONSE, DEFAULT_API_JUSTIFICATION)

    return (DEFAULT_API_RESPONSE, DEFAULT_API_JUSTIFICATION)


def load_recommendations(input_path: str) -> list[dict[str, object]]:
    """Load VEX recommendations from a JSON file.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"VEX recommendations file not found: {input_path}")

    with open(path) as f:
        recs: list[dict[str, object]] = json.load(f)

    logger.info("Loaded %d VEX recommendations from %s", len(recs), input_path)
    return recs


def filter_recommendations(
    recs: list[dict],
    filter_bands: list[str] | None = None,
    filter_statuses: list[str] | None = None,
) -> list[dict]:
    """Filter recommendations by priority band and/or VEX status."""
    filtered = recs

    if filter_bands:
        bands_upper = [b.upper() for b in filter_bands]
        filtered = [r for r in filtered if r.get("priority_band", "") in bands_upper]
        logger.info(
            "Filtered to %d recommendations for bands: %s", len(filtered), bands_upper
        )

    if filter_statuses:
        statuses_upper = [s.upper() for s in filter_statuses]
        filtered = [
            r for r in filtered if r.get("recommended_vex_status", "") in statuses_upper
        ]
        logger.info(
            "Filtered to %d recommendations for statuses: %s",
            len(filtered),
            statuses_upper,
        )

    return filtered


def validate_recommendations(recs: list[dict]) -> tuple[list[dict], list[dict]]:
    """Validate recommendations have required fields.

    Returns:
        ``(valid, invalid)`` lists.
    """
    valid = []
    invalid = []

    for rec in recs:
        internal_id = rec.get("id", "")
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
        logger.warning("%d recommendations have validation errors", len(invalid))
        for inv in invalid[:5]:
            logger.warning(
                "  Finding %s: %s",
                inv.get("finding_id", "?"),
                inv.get("_validation_errors"),
            )
        if len(invalid) > 5:
            logger.warning("  ... and %d more", len(invalid) - 5)

    return valid, invalid


# ── Low-level API call ───────────────────────────────────────────────


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
    """Update a finding's VEX status via the API with retry on transient errors.

    PUT /public/v0/findings/{projectVersionId}/{findingId}/status

    Retries on 429 (rate limit), 502, 503, 504 with exponential backoff
    and jitter.
    """
    url = f"{base_url}/api/public/v0/findings/{project_version_id}/{finding_id}/status"

    default_resp, default_just = get_smart_defaults(vex_status, reachability_label)
    final_response = response_enum or default_resp
    final_justification = justification_enum or default_just

    body: dict[str, str] = {
        "status": vex_status,
        "response": final_response,
        "justification": final_justification,
    }
    if reason:
        body["reason"] = reason

    logger.debug("PUT %s body=%s", url, body)

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.put(url, json=body)
            resp.raise_for_status()
            return {"success": True, "status_code": resp.status_code}
        except httpx.HTTPStatusError as e:
            if (
                e.response.status_code in RETRY_STATUS_CODES
                and attempt < MAX_RETRIES - 1
            ):
                delay = min(2**attempt, MAX_RETRY_DELAY) + random.uniform(0, 1)
                logger.warning(
                    "Rate limited (%d) on %s, retry %d/%d in %.1fs",
                    e.response.status_code,
                    finding_id,
                    attempt + 1,
                    MAX_RETRIES,
                    delay,
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
                delay = min(2**attempt, MAX_RETRY_DELAY) + random.uniform(0, 1)
                logger.warning(
                    "Connection error on %s, retry %d/%d in %.1fs",
                    finding_id,
                    attempt + 1,
                    MAX_RETRIES,
                    delay,
                )
                time.sleep(delay)
                continue
            return {"success": False, "error": str(e)}

    return {"success": False, "error": "Max retries exceeded"}


# ── Result dataclass ─────────────────────────────────────────────────


@dataclasses.dataclass
class VexApplyResult:
    """Outcome of a VEX application run."""

    total: int
    succeeded: int
    failed: int
    skipped_invalid: int
    skipped_existing: int
    elapsed_seconds: float
    results: list[dict]
    results_path: str | None
    dry_run: bool


# ── Orchestrator ─────────────────────────────────────────────────────


class VexApplier:
    """Apply VEX triage recommendations to the Finite State platform."""

    def __init__(
        self,
        auth_token: str,
        domain: str,
        *,
        concurrency: int = 5,
        dry_run: bool = False,
        vex_override: bool = False,
        filter_bands: list[str] | None = None,
        filter_statuses: list[str] | None = None,
    ) -> None:
        # Normalize domain
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        self.base_url = f"https://{domain}"
        self.auth_token = auth_token
        self.concurrency = concurrency
        self.dry_run = dry_run
        self.vex_override = vex_override
        self.filter_bands = filter_bands
        self.filter_statuses = filter_statuses

    # ── public API ───────────────────────────────────────────────────

    def apply_file(self, path: str) -> VexApplyResult:
        """Load → filter → skip-existing → validate → apply → write results log."""
        recs = load_recommendations(path)
        output_dir = str(Path(path).parent)
        return self.apply_recommendations(recs, output_dir=output_dir)

    def apply_recommendations(
        self,
        recs: list[dict],
        output_dir: str | None = None,
    ) -> VexApplyResult:
        """Run the full pipeline from an in-memory recommendation list."""
        start_time = time.monotonic()

        if not recs:
            return VexApplyResult(
                total=0,
                succeeded=0,
                failed=0,
                skipped_invalid=0,
                skipped_existing=0,
                elapsed_seconds=0.0,
                results=[],
                results_path=None,
                dry_run=self.dry_run,
            )

        # Filter
        recs = filter_recommendations(recs, self.filter_bands, self.filter_statuses)

        # Skip existing
        skipped_existing = 0
        if not self.vex_override:
            before = len(recs)
            recs = [r for r in recs if not _has_existing_status(r)]
            skipped_existing = before - len(recs)
            if skipped_existing:
                logger.info(
                    "Skipping %d findings with existing VEX status "
                    "(use vex_override=True to update them).",
                    skipped_existing,
                )

        # Validate
        valid_recs, invalid_recs = validate_recommendations(recs)

        if not valid_recs:
            elapsed = time.monotonic() - start_time
            return VexApplyResult(
                total=0,
                succeeded=0,
                failed=0,
                skipped_invalid=len(invalid_recs),
                skipped_existing=skipped_existing,
                elapsed_seconds=elapsed,
                results=[],
                results_path=None,
                dry_run=self.dry_run,
            )

        # Dry run — no HTTP calls
        if self.dry_run:
            logger.info(
                "[DRY RUN] Would apply %d VEX updates (skipped %d invalid, "
                "%d existing).",
                len(valid_recs),
                len(invalid_recs),
                skipped_existing,
            )
            elapsed = time.monotonic() - start_time
            dry_results = [
                {
                    "id": r["id"],
                    "finding_id": r.get("finding_id", r["id"]),
                    "project_version_id": r["project_version_id"],
                    "vex_status": r["recommended_vex_status"],
                    "success": True,
                    "dry_run": True,
                }
                for r in valid_recs
            ]
            results_path = self._write_results(
                dry_results, invalid_recs, skipped_existing, output_dir
            )
            return VexApplyResult(
                total=len(valid_recs),
                succeeded=len(valid_recs),
                failed=0,
                skipped_invalid=len(invalid_recs),
                skipped_existing=skipped_existing,
                elapsed_seconds=elapsed,
                results=dry_results,
                results_path=results_path,
                dry_run=True,
            )

        # Apply concurrently
        logger.info(
            "Applying %d VEX updates with concurrency=%d",
            len(valid_recs),
            self.concurrency,
        )
        succeeded = 0
        failed = 0
        results: list[dict] = []

        from rich.progress import (
            BarColumn,
            MofNCompleteColumn,
            Progress,
            SpinnerColumn,
            TextColumn,
            TimeElapsedColumn,
            TimeRemainingColumn,
        )

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("ETA"),
            TimeRemainingColumn(),
            TextColumn("{task.fields[status]}"),
        )

        with progress, ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            task_id = progress.add_task(
                "Applying VEX updates",
                total=len(valid_recs),
                status="",
            )
            futures = {
                executor.submit(self._update_one, rec): rec for rec in valid_recs
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result["success"]:
                    succeeded += 1
                else:
                    failed += 1
                    logger.warning(
                        "Failed: %s (id=%s): %s",
                        result["finding_id"],
                        result["id"],
                        result.get("error", "unknown error"),
                    )
                progress.update(
                    task_id,
                    advance=1,
                    status=f"ok={succeeded} fail={failed}",
                )

        elapsed = time.monotonic() - start_time
        results_path = self._write_results(
            results, invalid_recs, skipped_existing, output_dir
        )

        return VexApplyResult(
            total=len(results),
            succeeded=succeeded,
            failed=failed,
            skipped_invalid=len(invalid_recs),
            skipped_existing=skipped_existing,
            elapsed_seconds=elapsed,
            results=results,
            results_path=results_path,
            dry_run=False,
        )

    # ── internals ────────────────────────────────────────────────────

    def _update_one(self, rec: dict) -> dict:
        """Process a single VEX update in a thread."""
        internal_id = rec["id"]
        finding_id = rec.get("finding_id", internal_id)
        pv_id = rec["project_version_id"]
        vex_status = rec["recommended_vex_status"]
        reason = rec.get("reason", "")
        reachability_label = rec.get("reachability_label", "INCONCLUSIVE")

        client = httpx.Client(
            headers={
                "X-Authorization": self.auth_token,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        try:
            result = apply_vex_status(
                client,
                self.base_url,
                pv_id,
                internal_id,
                vex_status,
                reason,
                reachability_label=reachability_label,
            )
        finally:
            client.close()

        result["id"] = internal_id
        result["finding_id"] = finding_id
        result["project_version_id"] = pv_id
        result["vex_status"] = vex_status
        return result

    def _write_results(
        self,
        results: list[dict],
        invalid_recs: list[dict],
        skipped_existing: int,
        output_dir: str | None,
    ) -> str | None:
        """Write ``vex_apply_results.json`` beside the input file."""
        if output_dir is None:
            return None

        results_path = Path(output_dir) / "vex_apply_results.json"
        succeeded = sum(1 for r in results if r.get("success"))
        failed = sum(1 for r in results if not r.get("success"))

        with open(results_path, "w") as f:
            json.dump(
                {
                    "summary": {
                        "total": len(results),
                        "succeeded": succeeded,
                        "failed": failed,
                        "skipped_invalid": len(invalid_recs),
                        "skipped_existing": skipped_existing,
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
        logger.info("Results written to %s", results_path)
        return str(results_path)


def _has_existing_status(r: dict) -> bool:
    """Return True if the finding already has a VEX status set."""
    v = r.get("current_vex_status")
    return v is not None and v != "" and not isinstance(v, float)
