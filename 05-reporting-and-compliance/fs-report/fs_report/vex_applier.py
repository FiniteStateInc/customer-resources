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
import re
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

# VEX fields are emitted only when semantically valid for the status
# (CycloneDX VEX): justification → not_affected; response → actioned states.
# fs-report follows the alloy contract — a status-only body is accepted — so we
# do NOT force response/justification to satisfy helix's stricter Zod schema.
_JUSTIFICATION_STATUSES = {"NOT_AFFECTED"}
_RESPONSE_STATUSES = {"EXPLOITABLE", "RESOLVED", "RESOLVED_WITH_PEDIGREE"}

# not_affected should carry a justification even though the API makes it
# optional; fall back rather than emit a bare not_affected.
FALLBACK_NOT_AFFECTED_JUSTIFICATION = "CODE_NOT_PRESENT"

# Retry configuration (matches fs-smartsheets pattern).
# 500s are not retried — they typically indicate bad data, not transient issues.
RETRY_STATUS_CODES = {429, 502, 503, 504}
MAX_RETRIES = 6
MAX_RETRY_DELAY = 64  # seconds

# Max distinct findingIds per bulk request chunk. The platform's bulk-VEX
# endpoint documents a 500-item cap (BulkVexItem.findings maxItems=500); larger
# batches make the server exceed the client read timeout (a 5000-item batch
# times out, marking the whole chunk failed). Keep at the documented cap.
MAX_BULK_BATCH = 500

# A rec is bulk-eligible only when its project_version_id AND id are integer-like
# (the bulk endpoint types projectVersionId as integer; the single endpoint
# accepts arbitrary string ids).
_INT_ID = re.compile(r"^-?[0-9]+$")


# ── Pure helpers ─────────────────────────────────────────────────────


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
    filter_projects: list[str] | None = None,
) -> list[dict]:
    """Filter recommendations by priority band, VEX status, and/or project.

    ``filter_projects`` accepts project names or project IDs — a
    recommendation is kept if its ``project_name`` or ``project_id``
    matches any entry (case-insensitive for names).
    """
    filtered = recs

    if filter_projects:
        names_lower = {p.lower() for p in filter_projects}
        ids_set = set(filter_projects)
        filtered = [
            r
            for r in filtered
            if str(r.get("project_name", "")).lower() in names_lower
            or str(r.get("project_id", "")) in ids_set
        ]
        logger.info(
            "Filtered to %d recommendations for projects: %s",
            len(filtered),
            filter_projects,
        )

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

        justification = rec.get("justification", "")

        errors = []
        if not internal_id:
            errors.append("missing id (internal primary key)")
        if not pv_id:
            errors.append("missing project_version_id")
        if vex_status not in VALID_VEX_STATUSES:
            errors.append(f"invalid VEX status: {vex_status}")
        if justification and justification not in VALID_VEX_JUSTIFICATIONS:
            errors.append(f"invalid justification: {justification}")
        response = rec.get("response")
        if response and response not in VALID_VEX_RESPONSES:
            errors.append(f"invalid response: {response}")

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


def build_status_body(
    vex_status: str,
    reason: str | None,
    response_enum: str | None = None,
    justification_enum: str | None = None,
    reachability_label: str = "INCONCLUSIVE",
) -> dict[str, str]:
    """Build the JSON body for a VEX status update (alloy contract).

    Shared by single-PUT and bulk-PUT callers. Emits only the fields that are
    semantically valid for *vex_status*: ``justification`` for NOT_AFFECTED;
    ``response`` for actioned states (EXPLOITABLE/RESOLVED/RESOLVED_WITH_PEDIGREE).
    A value supplied for a field that does not apply to the status is dropped
    (logged), never sent. The platform requires only ``status``.

    Enum validity of *response_enum*/*justification_enum* is the caller's /
    ``validate_recommendations``' concern; this function only gates by status.
    """
    body: dict[str, str] = {"status": vex_status}

    if vex_status in _JUSTIFICATION_STATUSES:
        body["justification"] = justification_enum or (
            "CODE_NOT_REACHABLE"
            if reachability_label == "UNREACHABLE"
            else FALLBACK_NOT_AFFECTED_JUSTIFICATION
        )
    elif justification_enum:
        logger.debug(
            "Dropping justification=%s not valid for status=%s",
            justification_enum,
            vex_status,
        )

    if vex_status in _RESPONSE_STATUSES:
        if response_enum:
            body["response"] = response_enum
    elif response_enum:
        logger.debug(
            "Dropping response=%s not valid for status=%s",
            response_enum,
            vex_status,
        )

    if reason:
        body["reason"] = reason
    return body


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

    body = build_status_body(
        vex_status,
        reason,
        response_enum=response_enum,
        justification_enum=justification_enum,
        reachability_label=reachability_label,
    )

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


def apply_vex_status_bulk(
    client: httpx.Client,
    base_url: str,
    project_version_id: str | int,
    items: list[dict],
) -> dict:
    """PUT a batch of VEX status updates via the bulk endpoint.

    PUT /public/v0/findings/{projectVersionId}/status/set/bulk

    Each item in *items* must already contain a ``"findingId"`` key plus the
    body fields produced by :func:`build_status_body`.  This function does NOT
    build items; it only sends them.

    On success (HTTP 200) returns the parsed response body
    ``{status, summary, results}`` as-is.  On failure — including a 200 whose
    body is malformed JSON or not a JSON object — returns
    ``{"success": False, "status_code": <int|absent>, "error": str,
    "response_body": <text[:500]>}``, mirroring
    :func:`apply_vex_status`'s failure dict.  Never raises.

    A larger 120s write timeout is applied to this single PUT (matching
    ``fetch_sbom``) since a ≤MAX_BULK_BATCH-item body needs more than the
    shared client's default; the client default stays low for single PUTs.
    """
    url = f"{base_url}/api/public/v0/findings/{project_version_id}/status/set/bulk"
    body: dict = {"findings": items}

    logger.debug("PUT %s items=%d", url, len(items))

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.put(url, json=body, timeout=120.0)
            resp.raise_for_status()
            try:
                parsed = resp.json()
            except (json.JSONDecodeError, ValueError) as e:
                # A 200 with a malformed/non-JSON body must NOT raise — honor the
                # "never raise, return failure dict" contract.
                return {
                    "success": False,
                    "status_code": 200,
                    "error": f"malformed JSON in 200 response: {e}",
                    "response_body": resp.text[:500],
                }
            if not isinstance(parsed, dict):
                return {
                    "success": False,
                    "status_code": 200,
                    "error": (
                        f"unexpected 200 response body: expected object, "
                        f"got {type(parsed).__name__}"
                    ),
                    "response_body": resp.text[:500],
                }
            return parsed
        except httpx.HTTPStatusError as e:
            if (
                e.response.status_code in RETRY_STATUS_CODES
                and attempt < MAX_RETRIES - 1
            ):
                delay = min(2**attempt, MAX_RETRY_DELAY) + random.uniform(0, 1)
                logger.warning(
                    "Rate limited (%d) on bulk PUT %s, retry %d/%d in %.1fs",
                    e.response.status_code,
                    project_version_id,
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
                    "Connection error on bulk PUT %s, retry %d/%d in %.1fs",
                    project_version_id,
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
        filter_projects: list[str] | None = None,
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
        self.filter_projects = filter_projects

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
        recs = filter_recommendations(
            recs, self.filter_bands, self.filter_statuses, self.filter_projects
        )

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

        # Route each rec: integer pvId+id → bulk (grouped by version, chunked);
        # everything else → single-PUT. Nothing is dropped for id shape.
        bulk_by_version, single_recs = _route_recommendations(valid_recs)

        client = httpx.Client(
            headers={
                "X-Authorization": self.auth_token,
                "Content-Type": "application/json",
            },
            timeout=30.0,  # default for single PUTs; bulk PUT overrides to 120s
        )
        with (
            progress,
            client,
            ThreadPoolExecutor(max_workers=self.concurrency) as executor,
        ):
            task_id = progress.add_task(
                "Applying VEX updates",
                total=len(valid_recs),
                status="",
            )

            # Submit one future per (version, chunk) bulk batch + one per single rec.
            # Each future returns a list of result rows (one per INPUT rec it owns).
            futures = []
            for pv_id, version_recs in bulk_by_version.items():
                for chunk in _chunk_by_distinct_id(version_recs, MAX_BULK_BATCH):
                    futures.append(
                        executor.submit(self._apply_batch, pv_id, chunk, client)
                    )
            for rec in single_recs:
                futures.append(executor.submit(self._apply_single, rec, client))

            for future in as_completed(futures):
                rows = future.result()
                results.extend(rows)
                for result in rows:
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
                        if result.get("response_body"):
                            logger.warning("  Response: %s", result["response_body"])
                progress.update(
                    task_id,
                    advance=len(rows),
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

    def _apply_single(self, rec: dict, client: httpx.Client) -> list[dict]:
        """Apply one VEX update via the single-PUT endpoint (non-bulk path).

        Returns a one-element list (one result row) so the dispatch loop can
        treat single PUTs and bulk batches uniformly.
        """
        internal_id = rec["id"]
        finding_id = rec.get("finding_id", internal_id)
        pv_id = rec["project_version_id"]
        vex_status = rec["recommended_vex_status"]
        reason = rec.get("reason", "")
        reachability_label = rec.get("reachability_label", "INCONCLUSIVE")
        justification = rec.get("justification")

        result = apply_vex_status(
            client,
            self.base_url,
            pv_id,
            internal_id,
            vex_status,
            reason,
            response_enum=rec.get("response"),
            justification_enum=justification,
            reachability_label=reachability_label,
        )

        result["id"] = internal_id
        result["finding_id"] = finding_id
        result["project_version_id"] = pv_id
        result["vex_status"] = vex_status
        return [result]

    def _apply_batch(
        self, pv_id: str, batch_recs: list[dict], client: httpx.Client
    ) -> list[dict]:
        """Apply one chunk of bulk-eligible recs for a single version.

        Wire-dedupes by ``findingId`` (a duplicate id in one bulk request is a
        hard 400): sends one item per distinct findingId (the first rec's built
        body), then fans each per-item result back to every input rec sharing
        that findingId, so the returned list has exactly one row per INPUT rec.
        Duplicate recs whose built body differs from the first rec's are
        *superseded* (not sent) and reported as failed.
        """
        # Group input recs by findingId, preserving order.
        groups: dict[str, list[dict]] = {}
        for rec in batch_recs:
            finding_id = str(rec["id"])
            groups.setdefault(finding_id, []).append(rec)

        # Build one wire item per distinct findingId (first rec's verdict) and
        # classify each rec in the group as primary/identical (conflicting=False)
        # or superseded (conflicting=True, built body differs from the first's).
        items: list[dict] = []
        # finding_id → [(rec, is_superseded), ...] in input order
        plans: dict[str, list[tuple[dict, bool]]] = {}
        for finding_id, recs in groups.items():
            primary_body = _build_item_body(recs[0])
            classified: list[tuple[dict, bool]] = []
            for rec in recs:
                conflicting = _build_item_body(rec) != primary_body
                classified.append((rec, conflicting))
                if conflicting:
                    logger.warning(
                        "Superseded conflicting duplicate for findingId %s "
                        "(id=%s) — first verdict in the batch wins.",
                        finding_id,
                        rec.get("id"),
                    )
            items.append({**primary_body, "findingId": finding_id})
            plans[finding_id] = classified

        response = apply_vex_status_bulk(client, self.base_url, pv_id, items)

        # Batch-level failure → one failed row per INPUT rec carrying the error.
        # A failure is either an explicit ``success is False`` dict OR any 200
        # body that does not carry a ``results`` list (a well-formed success
        # ALWAYS has ``results``).  Treating an unexpected shape as a batch-level
        # failure prevents silently emitting zero rows for the batch.
        results_field = response.get("results")
        is_explicit_failure = response.get("success") is False
        if is_explicit_failure or not isinstance(results_field, list):
            if is_explicit_failure:
                error = response.get("error", "bulk request failed")
            else:
                error = (
                    "bulk response missing a 'results' list "
                    f"(unexpected shape: {sorted(response.keys())})"
                )
                logger.warning(
                    "Bulk PUT for version %s returned an unexpected shape "
                    "(no 'results' list); marking %d rec(s) failed.",
                    pv_id,
                    len(batch_recs),
                )
            rows: list[dict] = []
            for classified in plans.values():
                for rec, _conflicting in classified:
                    row = _base_row(rec, pv_id)
                    row["success"] = False
                    row["error"] = error
                    if response.get("response_body"):
                        row["response_body"] = response["response_body"]
                    rows.append(row)
            return rows

        # Index the per-item results by findingId, then fan each back to every
        # input rec sharing that findingId (one result row per INPUT rec).
        # ``results_field`` is a verified list at this point.
        by_finding: dict[str, dict] = {}
        for item_result in results_field:
            if isinstance(item_result, dict):
                by_finding[str(item_result.get("findingId"))] = item_result

        rows = []
        for finding_id, classified in plans.items():
            item_result = by_finding.get(finding_id)
            for rec, conflicting in classified:
                row = _base_row(rec, pv_id)
                if conflicting:
                    row["success"] = False
                    row["error"] = "superseded: conflicting duplicate in batch"
                else:
                    _map_item_result(row, item_result)
                rows.append(row)
        return rows

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


# ── Routing / batching helpers ───────────────────────────────────────


def _is_bulk_eligible(rec: dict) -> bool:
    """A rec is bulk-eligible iff its pvId AND id are both integer-like."""
    return bool(
        _INT_ID.match(str(rec["project_version_id"])) and _INT_ID.match(str(rec["id"]))
    )


def _route_recommendations(
    valid_recs: list[dict],
) -> tuple[dict[str, list[dict]], list[dict]]:
    """Split recs into bulk groups (by project_version_id) and single-PUT recs.

    Returns ``(bulk_by_version, single_recs)``. ``bulk_by_version`` maps each
    integer ``project_version_id`` (as ``str``) to its bulk-eligible recs in
    input order; ``single_recs`` are everything else (UUID pvId or non-integer
    id) in input order. Nothing is dropped.
    """
    bulk_by_version: dict[str, list[dict]] = {}
    single_recs: list[dict] = []
    for rec in valid_recs:
        if _is_bulk_eligible(rec):
            pv_id = str(rec["project_version_id"])
            bulk_by_version.setdefault(pv_id, []).append(rec)
        else:
            single_recs.append(rec)
    return bulk_by_version, single_recs


def _chunk_by_distinct_id(recs: list[dict], max_distinct: int) -> list[list[dict]]:
    """Chunk *recs* so each chunk holds at most *max_distinct* distinct findingIds.

    Recs sharing a findingId always land in the same chunk (a distinct id is
    counted once), so wire-dedupe within a chunk never sees an id split across
    chunks. Input order is preserved.
    """
    chunks: list[list[dict]] = []
    current: list[dict] = []
    seen: set[str] = set()
    for rec in recs:
        finding_id = str(rec["id"])
        if finding_id not in seen and len(seen) >= max_distinct:
            chunks.append(current)
            current = []
            seen = set()
        current.append(rec)
        seen.add(finding_id)
    if current:
        chunks.append(current)
    return chunks


def _build_item_body(rec: dict) -> dict[str, str]:
    """Build the bulk item body fields (no findingId) for *rec*."""
    return build_status_body(
        rec["recommended_vex_status"],
        rec.get("reason", ""),
        justification_enum=rec.get("justification"),
        response_enum=rec.get("response"),
        reachability_label=rec.get("reachability_label", "INCONCLUSIVE"),
    )


def _base_row(rec: dict, pv_id: str) -> dict:
    """Build the common result-row scaffold (the legacy ``_update_one`` shape)."""
    internal_id = rec["id"]
    return {
        "id": internal_id,
        "finding_id": rec.get("finding_id", internal_id),
        "project_version_id": pv_id,
        "vex_status": rec["recommended_vex_status"],
    }


def _map_item_result(row: dict, item_result: dict | None) -> None:
    """Fold a bulk per-item result into *row* (in place).

    The per-item ``status`` is recorded under ``applied_status`` (never the bare
    ``status`` key, which would hijack ``summarize_apply_result``'s by_status
    grouping). A not-found / failed item maps to ``success=False`` with the bulk
    error text preserved, or the canonical ``NOT_FOUND`` token when absent. A
    successful item carries ``status_code=200`` so bulk-mapped rows match the
    single-PUT success rows in ``vex_apply_results.json``.
    """
    if item_result is None:
        # findingId present in the batch but absent from the response.
        row["success"] = False
        row["error"] = "NOT_FOUND"
        return
    success = bool(item_result.get("success"))
    row["success"] = success
    applied_status = item_result.get("status")
    if applied_status is not None:
        row["applied_status"] = applied_status
    if success:
        # Parity with the single-PUT success row, which carries status_code=200.
        row["status_code"] = 200
    else:
        row["error"] = item_result.get("error") or "NOT_FOUND"
