"""Run execution router — start runs, SSE progress, status polling."""

import asyncio
import io
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.parse
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from sse_starlette.sse import EventSourceResponse

from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.shell_context import build_shell_context
from fs_report.web.state import WebAppState, recipe_override
from fs_report.workflow_store import coerce_bool as _coerce_touched_flag

if TYPE_CHECKING:
    from fs_report.models import CompoundRecipe, Recipe

logger = logging.getLogger(__name__)

router = APIRouter(tags=["run"])


def _relative_output_path(file_path: str, base: Path) -> str | None:
    """Path of a generated file relative to the served output ``base``, or None.

    ``resolve()`` first so a run launched with a RELATIVE output_dir (the
    default ``"./output"``) still maps under the resolved base — otherwise
    ``relative_to`` raises and the report would be treated as unservable.
    Returns None (with a debug log, not a silent swallow) when the file isn't
    under ``base`` — e.g. an output_dir override pointing elsewhere. Single
    source of truth for both the report_url link and the history file records.

    The result uses forward slashes (``as_posix()``) on every platform: it
    feeds a URL (``/output/<segs>``) and is stored as the history ``path``, so a
    Windows backslash separator would corrupt both (e.g. ``/output/runs%5C...``).
    """
    try:
        return Path(file_path).resolve().relative_to(base).as_posix()
    except ValueError:
        logger.debug("generated file %s is not under output base %s", file_path, base)
        return None


def _output_url(rel: str) -> str:
    """Build the ``/output/<encoded-segs>`` URL for a forward-slash relative path.

    Each path segment is percent-encoded (``safe=""``) so spaces / special
    chars in a recipe name don't corrupt the URL.  Single source of truth for
    the report_url the monitor links to — shared by the single-run path
    (``_execute_run``) and the per-step / aggregate links in
    ``_execute_workflow``.  ``rel`` MUST already be forward-slash (``as_posix``)
    — see the Windows-backslash guard in :func:`_relative_output_path`.
    """
    encoded_segs = "/".join(urllib.parse.quote(seg, safe="") for seg in rel.split("/"))
    return "/output/" + encoded_segs


def _collect_html_files(generated_files: list[str], output_dir_abs: Path) -> list[str]:
    """Return the forward-slash HTML paths (relative to ``output_dir_abs``).

    Shared HTML-first artifact collection: the same logic the single-run path
    uses, so a workflow step's report_url is an HTML-first ``/output/...`` link
    consistent with Report History.
    """
    html_files: list[str] = []
    for f in generated_files:
        if Path(f).suffix != ".html":
            continue
        html_rel = _relative_output_path(f, output_dir_abs)
        if html_rel is not None:
            html_files.append(html_rel)
    return html_files


def _build_history_files(
    generated_files: list[str],
    output_dir_abs: Path,
    run_output_abs: Path,
    bundle_recipe: str | None = None,
) -> list[dict[str, str]]:
    """Build the ``report_history`` file records for ``generated_files``.

    Factored out of ``_execute_run`` so the single-run path and each
    successful workflow step record history identically.  ``recipe`` is the
    first path segment relative to the per-run/per-step output dir (the recipe
    sub-dir), falling back to the file stem for files written directly under
    the dir.  Paths are forward-slash (``as_posix``) so the ``/reports/file``
    URL is never corrupted on Windows.

    B12 #3: when ``bundle_recipe`` is set (a COMPOUND/COMPARISON run — one
    combined deliverable), every file is tagged with that bundle name instead of
    the per-child section sub-dir.  Otherwise Report History's ``categorize()``
    keys on each file's child-section name and can't resolve the BUNDLE's
    nav_category — the bundle splinters into mis-categorized per-section rows.
    """
    history_files: list[dict[str, str]] = []
    for f in generated_files:
        rel_str = _relative_output_path(f, output_dir_abs)
        if rel_str is None:
            continue
        rel = Path(rel_str)
        fp = Path(f).resolve()
        if bundle_recipe is not None:
            recipe = bundle_recipe
        else:
            try:
                rel_to_run = fp.relative_to(run_output_abs)
                recipe = (
                    rel_to_run.parts[0]
                    if len(rel_to_run.parts) >= 2
                    else rel_to_run.stem
                )
            except ValueError:
                recipe = rel.parts[-2] if len(rel.parts) >= 2 else rel.stem
        history_files.append(
            {
                "recipe": recipe,
                "path": rel_str,
                "format": fp.suffix.lstrip("."),
            }
        )
    return history_files


# In-memory store of active/completed runs
_runs: dict[str, dict[str, Any]] = {}
# Re-entrant lock that guards all dict-level iteration and mutation of _runs.
# RLock is used (rather than Lock) so that _evict_old_runs() can be called
# both from start_run() (which holds the lock) and from _execute_run()'s
# finally-block without deadlocking.
_RUNS_LOCK = threading.RLock()
# Serialise sys.stderr redirect so concurrent worker threads cannot clobber
# each other's save/restore of the process-global file descriptor.
_stderr_lock = threading.Lock()

_MAX_RUNS = 50

# Per-run summary persistence (spec §4): a finished run writes a lightweight
# ``<runs_dir>/<run_id>.json`` so its final canvas re-renders forever, even after
# eviction from ``_runs``.  ``runs_dir`` defaults to ``~/.fs-report/runs/`` and is
# overridable via ``FS_REPORT_RUNS_DIR`` (mirroring report_history's
# ``FS_REPORT_HISTORY_DIR``), read at import so a child process inherits the test
# suite's isolation and the conftest fixture can monkeypatch this global.  Keyed
# by ``run_id`` in a FIXED dir — immune to per-run ``output_dir`` overrides,
# findable without globbing, and decoupled from ``run_output.mkdir`` so a run
# that fails before that still persists (spec §4.2 / §10).
_RUNS_DIR = Path(
    os.environ.get("FS_REPORT_RUNS_DIR", str(Path.home() / ".fs-report" / "runs"))
)
# Run ids are ``uuid4().hex[:8]`` — accept that charset (+ ``-``/``_`` for any
# future scheme) and reject anything else BEFORE joining into a filesystem path,
# so a crafted ``/run/{run_id}`` can never escape ``_RUNS_DIR`` (defense-in-depth;
# mirrors the run-id sanitization in ``run_log``).  Multi-review R-PR130.
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_-]+$")

# Override keys start_run collects from the run form, grouped by coercion.
# Pulled out as module constants so the override-collection loops and the
# authoritative "present-keys" computation (PR #117 review r6) share ONE source
# of truth and can't drift.  These are a SUPERSET of the card-config override
# keys (a recipe_override only ever holds card-config keys), so global-only
# fields here — output_dir, ai_analysis — never appear in a saved override and
# are harmless in the present-keys set.
_RUN_STR_KEYS: tuple[str, ...] = (
    "period",
    "output_dir",
    "cache_ttl",
    "project_filter",
    "folder_filter",
    "version_filter",
    "finding_types",
    "cve_filter",
    "component_filter",
    "baseline_version",
    "current_version",
    "ai_depth",
    "product_type",
    "network_exposure",
    "regulatory",
    "deployment_notes",
    # SP3: uploaded-file paths (scoring weights / AI deployment context).
    "scoring_file",
    "context_file",
    "start",
    "end",
    "tp_gate",
    "component_match",
    "component_version",
    "license_filter",
    "threat_context",
    "baseline_date",
    "detected_after",
    "scan_types",
    "scan_statuses",
    # SP2: destructive VEX-write status filter (comma-joined multi-select, like
    # scan_types/scan_statuses; coerced to list[str] in _build_engine_config).
    "autotriage_status",
    # PR3.3a: comparison run-time Left/Right scope overrides (Decision 11 —
    # run-only, never persisted to a recipe YAML).
    "left_scope",
    "right_scope",
)
_RUN_BOOL_KEYS: tuple[str, ...] = (
    "overwrite",
    "current_version_only",
    "ai",
    "ai_prompts",
    "ai_analysis",
    "open_only",
    "detailed",
    "standalone",
    "vex_override",
    # SP2: auto-apply VEX toggle (maps ON -> autotriage="high" in
    # _build_engine_config). dry_run is intentionally NOT here — it is a
    # transient per-launch param, never a persisted override.
    "autotriage",
)
_RUN_INT_KEYS: tuple[str, ...] = ("top", "triage")
# All override-allowlist keys start_run knows about, for the present-keys set.
_RUN_OVERRIDE_KEYS: tuple[str, ...] = _RUN_STR_KEYS + _RUN_BOOL_KEYS + _RUN_INT_KEYS


def _evict_old_runs() -> None:
    """Evict oldest completed entries from ``_runs`` so it stays bounded at ~50.

    Never evicts running entries — they must remain visible until they finish.
    Safe to call from either the main thread (after *start_run* registers a new
    entry) or the worker thread (after ``_execute_run`` marks status='completed').

    Holds ``_RUNS_LOCK`` for both the snapshot read AND the pop loop so that
    concurrent calls from worker threads cannot race with
    ``_get_active_runs_list`` or with each other.  ``_RUNS_LOCK`` is an
    ``RLock``, so re-entrant calls (e.g. from ``start_run`` which already holds
    the lock) are safe.
    """
    with _RUNS_LOCK:
        snapshot = list(_runs.items())
        if len(snapshot) <= _MAX_RUNS:
            return
        completed = sorted(
            ((rid, r) for rid, r in snapshot if r["status"] == "completed"),
            key=lambda x: x[1].get("started_at", 0),
        )
        to_evict = len(snapshot) - _MAX_RUNS
        for rid, _ in completed[:to_evict]:
            _runs.pop(rid, None)


def _run_summary_path(run_id: str) -> Path:
    """Path of a run's persisted summary — ``<runs_dir>/<run_id>.json``.

    Reads the module-level ``_RUNS_DIR`` on every call so a test that
    monkeypatches it (per-test isolation) is honored.
    """
    return _RUNS_DIR / f"{run_id}.json"


class RunEventHub:
    """Multi-subscriber fan-out for a run's live SSE event stream (B3 #12).

    The old model stored ONE ``asyncio.Queue`` per run; ``run_events`` drained it
    with ``queue.get()``, removing each event as it was pulled. A second viewer
    (e.g. opening a running run via /runs) therefore competed for events and got
    only the static buffered history — no live updates. The hub fans EVERY
    published event to ALL current subscribers and keeps a bounded replay buffer
    so any late-joiner can reconstruct the run so far.

    Drop-in for the producer side: ``put_nowait`` matches ``asyncio.Queue`` so
    the emitters (SSELogHandler, the section-hook stderr drain, and
    ``_record_canvas_event``) need no change — they already push via
    ``loop.call_soon_threadsafe``, so ``put_nowait`` and ``subscribe`` /
    ``unsubscribe`` all run on the event loop and the subscriber set needs no
    cross-thread lock.

    Concurrency / lifecycle:
    * ``subscribe()`` returns a fresh **bounded** queue and registers it;
      ``run_events`` snapshots ``buffer`` and subscribes in the SAME loop tick
      (no ``await`` between) so an event can't slip into both the replay and the
      live queue (no double / lost delivery).
    * ``unsubscribe()`` on disconnect / terminal ``done`` — bounded retention.
    * **Slow-consumer policy = drop-oldest.** A per-subscriber queue that fills
      (a stalled / disconnected client) drops its OLDEST event to make room, so
      the producer never blocks and memory stays bounded. Because drop-oldest
      keeps the NEWEST events, the terminal ``done`` (always last) is preserved.
      The shared replay buffer is likewise capped drop-oldest.
    """

    _BUFFER_CAP = 5000
    _SUB_QUEUE_CAP = 2000

    def __init__(self) -> None:
        self.buffer: list[dict[str, str]] = []
        self._subscribers: set[asyncio.Queue[dict[str, str]]] = set()

    def put_nowait(self, event: dict[str, str]) -> None:
        """Producer side (drop-in for ``asyncio.Queue.put_nowait``): record in
        the bounded replay buffer + fan out to every subscriber."""
        self.buffer.append(event)
        if len(self.buffer) > self._BUFFER_CAP:
            del self.buffer[: len(self.buffer) - self._BUFFER_CAP]
        for q in list(self._subscribers):
            self._offer(q, event)

    @staticmethod
    def _offer(q: "asyncio.Queue[dict[str, str]]", event: dict[str, str]) -> None:
        """Non-blocking put with drop-oldest on overflow (slow-consumer policy)."""
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            try:
                q.get_nowait()  # drop the oldest event to make room
            except asyncio.QueueEmpty:  # pragma: no cover - racey, defensive
                pass
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:  # pragma: no cover - racey, defensive
                pass

    def subscribe(self) -> "asyncio.Queue[dict[str, str]]":
        q: asyncio.Queue[dict[str, str]] = asyncio.Queue(maxsize=self._SUB_QUEUE_CAP)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue[dict[str, str]]") -> None:
        self._subscribers.discard(q)


def _record_canvas_event(
    run_id: str,
    queue: RunEventHub,
    loop: asyncio.AbstractEventLoop,
    event: str,
    data: str,
) -> None:
    """The SINGLE recorder every canvas-event emit routes through (spec §4.1).

    Two effects, in order:

    1. **Synchronous, lock-guarded append** of ``{event, data}`` to the run
       record's ``events`` list — the complete, ordered, viewer-independent,
       race-free history.  This runs in the calling (worker) thread at emit
       time, so ``events`` is correct even when NO SSE client ever connected and
       the queue is never drained.  It is COMPLETELY SEPARATE from the SSE
       ``buffer``/``queue`` (which stay byte-for-byte as-is) — ``events`` is
       written-by-emitters / read-only by :func:`_persist_run_summary` + the
       terminal-mode render; the SSE path never touches it (so a live client is
       never double-delivered — multi-review R2 critical).

    2. **Schedule the event onto the SSE queue** via ``call_soon_threadsafe``
       exactly as the inline emits did before — the live path is unchanged.

    ``event`` is a CANVAS event only — ``step`` / ``progress`` / ``done``.
    ``log``/stderr events must NOT route through here (they push straight to the
    queue) so the persisted history stays log-free and small (spec §4.1).
    """
    with _RUNS_LOCK:
        rec = _runs.get(run_id)
        if rec is not None:
            rec.setdefault("events", []).append({"event": event, "data": data})
    loop.call_soon_threadsafe(queue.put_nowait, {"event": event, "data": data})


def _persist_run_summary(run_id: str) -> None:
    """Write ``<runs_dir>/<run_id>.json`` from the finalized record (spec §4.3).

    Called from each executor's ``finally`` — AFTER all terminal-``done``
    emission (so ``events`` already holds the terminal done) and BEFORE
    ``_evict_old_runs`` (so a run evicted in its own finally is already on disk).
    Reads ``kind`` / ``scope`` / ``workflow_name`` / ``recipes`` / ``replay`` /
    ``result`` / ``started_at`` / ``canvas_nodes`` / the synchronous ``events``
    list, stamps ``finished_at``, and writes atomically (tmp + replace) so a
    concurrent ``/runs`` scan never reads a half-written file.

    Defensive: a run that never registered a record is simply not persisted, and
    ANY failure logs + is swallowed — persistence must never break the run or
    its terminal ``done``.
    """
    try:
        with _RUNS_LOCK:
            rec = _runs.get(run_id)
            if rec is None:
                return
            events = list(rec.get("events", []))
            # Persist ONLY a run that reached a terminal ``done`` (R-PR130).  An
            # interrupted run (a BaseException — e.g. KeyboardInterrupt — that
            # unwinds through the executor ``finally`` without emitting a done)
            # has no terminal event; persisting it would render a never-settling
            # canvas.  Per spec §10/§13 such runs re-open as the expired panel,
            # not a broken terminal canvas — so skip the write.
            if not any(e.get("event") == "done" for e in events):
                return
            finished_at = time.time()
            # Stamp finish time on the LIVE record too, so ``_list_all_runs``
            # orders a just-finished (not-yet-evicted) run by its finish time —
            # not its start time (R-PR130: the newest-first / most-recent bug).
            rec["finished_at"] = finished_at
            summary = {
                "run_id": run_id,
                "kind": rec.get("kind", "report"),
                "scope": rec.get("scope", ""),
                "workflow_name": rec.get("workflow_name", ""),
                "recipes": rec.get("recipes", []),
                "replay": rec.get("replay"),
                # Named ``result`` (NOT ``status``) to avoid the lifecycle-field +
                # SSE-done-payload "status" collision (spec §4.2).
                "result": rec.get("result"),
                "started_at": rec.get("started_at"),
                "finished_at": finished_at,
                "canvas_nodes": rec.get("canvas_nodes", []),
                "events": events,
            }
        _RUNS_DIR.mkdir(parents=True, exist_ok=True)
        path = _run_summary_path(run_id)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(summary), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        logger.warning("Failed to persist run summary for %s", run_id, exc_info=True)


def _load_run_summary(run_id: str) -> dict[str, Any] | None:
    """Read + parse ``<runs_dir>/<run_id>.json``; None if missing/corrupt.

    Guarded so a corrupt or partial file falls through to the caller's expired
    / skip-this-entry path rather than 500ing (spec §5.1 / §6).  Never raises.
    """
    # Path-safety guard (R-PR130): a run_id that isn't a plain slug can't be a
    # real run and must never reach the filesystem join — fall through to expired.
    if not _SAFE_RUN_ID.match(run_id):
        return None
    path = _run_summary_path(run_id)
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        # Structural validation (R-PR130): accept only a dict whose load-bearing
        # lists are actually lists.  A type-wrong-but-parseable summary degrades
        # to the expired panel rather than rendering a broken terminal canvas.
        if not isinstance(data, dict):
            return None
        if not isinstance(data.get("events", []), list):
            return None
        if not isinstance(data.get("canvas_nodes", []), list):
            return None
        return data
    except Exception:
        logger.warning("Failed to read run summary %s", run_id, exc_info=True)
        return None


def _run_age(ts: float | None) -> str:
    """Compact relative age ('just now' / '5m' / '3h' / '2d') for a timestamp."""
    if not ts:
        return ""
    seconds = int(time.time() - ts)
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _run_index_row(
    run_id: str,
    *,
    kind: str,
    scope: str,
    workflow_name: str,
    recipes: list[str],
    result: str | None,
    status: str,
    started_at: float | None,
    finished_at: float | None,
) -> dict[str, Any]:
    """Build one /runs index row (shared by the active + persisted sources).

    ``name`` is the workflow name, else the first recipe + ``+N`` for the rest.
    ``status`` is ``running`` (live) or ``finished``; ``result`` is the terminal
    outcome (None while running).  ``sort_ts`` orders the list newest-first.
    """
    recipes = recipes or []
    if workflow_name:
        name = workflow_name
    elif recipes:
        extra = len(recipes) - 1
        name = str(recipes[0]) + (f" +{extra}" if extra > 0 else "")
    else:
        name = "Run"
    sort_ts = finished_at or started_at or 0.0
    return {
        "run_id": run_id,
        "kind": kind or "report",
        "scope": scope or "",
        "name": name,
        "result": result,
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "sort_ts": sort_ts,
        "age": _run_age(sort_ts),
    }


def _collect_runs() -> tuple[list[dict[str, Any]], int]:
    """Merge active (``_runs``) + persisted (``<runs_dir>/*.json``) runs.

    Returns ``(rows, degraded)`` — index rows deduped by ``run_id`` (the live
    record always wins — the active canvas is authoritative — spec §6/§10),
    newest-first by ``finished_at``/``started_at``, plus the count of corrupt /
    unreadable summaries skipped (so the page can surface an inline notice
    rather than silently under-reporting — R-PR130).  Degrades gracefully: a
    bad entry or an unreadable runs_dir is skipped (logged), never raising.
    """
    rows: dict[str, dict[str, Any]] = {}
    degraded = 0
    # Persisted (lower priority) first — the ``*.json`` glob skips the atomic
    # ``*.json.tmp`` write file.  Each entry is loaded through the SAME
    # ``_load_run_summary`` the ``/run/{id}`` read path uses — applying the
    # identical run-id path-safety + structural (list-type) guards — so the index
    # never lists a run that would open to the expired panel and never emits an
    # unsafe ``/run/<id>`` link (R-PR130 round 2: validation parity).  The
    # FILENAME stem is the authoritative run_id (the writer names files
    # ``<run_id>.json``), so a hand-crafted in-file ``run_id`` can't forge a link.
    try:
        if _RUNS_DIR.is_dir():
            for path in _RUNS_DIR.glob("*.json"):
                rid = path.stem
                data = _load_run_summary(rid)
                if data is None:  # missing / corrupt / unsafe id / wrong-typed
                    degraded += 1
                    continue
                rows[rid] = _run_index_row(
                    rid,
                    kind=data.get("kind", "report"),
                    scope=data.get("scope", ""),
                    workflow_name=data.get("workflow_name", ""),
                    recipes=data.get("recipes", []),
                    result=data.get("result"),
                    status="finished",
                    started_at=data.get("started_at"),
                    finished_at=data.get("finished_at"),
                )
    except Exception:
        # The directory scan itself failed (e.g. permissions) — surface it as a
        # degraded entry so the index shows the notice instead of looking empty
        # (R-PR130 round 2). Count is unknown; one notice is enough to flag it.
        degraded += 1
        logger.warning("Failed to scan runs_dir %s", _RUNS_DIR, exc_info=True)
    # Active (higher priority) — overwrites a persisted row with the same id.
    # ``finished_at`` is read from the record (stamped by _persist_run_summary on
    # completion), so a just-finished but not-yet-evicted run orders by its
    # finish time, not its start time (R-PR130).  A running run has no
    # ``finished_at`` → orders by ``started_at`` (correct).
    with _RUNS_LOCK:
        snapshot = list(_runs.items())
    for rid, rec in snapshot:
        rows[rid] = _run_index_row(
            rid,
            kind=rec.get("kind", "report"),
            scope=rec.get("scope", ""),
            workflow_name=rec.get("workflow_name", ""),
            recipes=rec.get("recipes", []),
            result=rec.get("result"),
            status="running" if rec.get("status") == "running" else "finished",
            started_at=rec.get("started_at"),
            finished_at=rec.get("finished_at"),
        )
    out = list(rows.values())
    out.sort(key=lambda r: r.get("sort_ts") or 0.0, reverse=True)
    return out, degraded


def _list_all_runs() -> list[dict[str, Any]]:
    """The merged run-index rows (newest-first) — see :func:`_collect_runs`.

    Thin wrapper used where the degraded count isn't needed (the ``/run``
    most-recent redirect).
    """
    return _collect_runs()[0]


# Recipe groups that drive conditional field visibility (mirrors TUI prerun.py)
CVE_RECIPES = {"cve impact"}
TRIAGE_RECIPES = {"triage prioritization"}
# SP3: recipes that consume --scoring-file (verified config.scoring_file readers).
SCORING_RECIPES = {
    "triage prioritization",
    "scan quality",
    "configuration analysis triage",
}
# B11 #18: the scoring file means different things per consumer. Scan Quality
# reads staleness thresholds (scan-age tiers); TP / Config Analysis Triage read
# triage scoring weights. Split so the card/prerun/inspector label + hint can be
# accurate instead of the generic "scoring weights / staleness thresholds".
STALENESS_SCORING_RECIPES = {"scan quality"}
TRIAGE_SCORING_RECIPES = SCORING_RECIPES - STALENESS_SCORING_RECIPES
VERSION_RECIPES = {"version comparison"}
COMPONENT_RECIPES = {"component list"}
REMEDIATION_RECIPES = {"remediation package"}
FPA_RECIPES = {"false positive analysis"}
COMPONENT_REMEDIATION_RECIPES = {"component remediation package"}
COMPONENT_SCOPED_RECIPES = {
    "component impact",
    "component remediation package",
    "component vulnerability analysis",
}
COMPONENT_RECOMMENDED_RECIPES = {"component impact", "component remediation package"}
LICENSE_RECIPES = {"license report"}
SECURITY_PROGRESS_RECIPES = {"security progress"}
EXEC_DASHBOARD_RECIPES = {"executive dashboard"}

# ── Config-card field-visibility sets (report-config-card-gating) ──────────────
# All gates below stay ``bool(selected & SET)`` (positive allow-lists) so an
# unknown / zero-config recipe returns every flag False (test_zero_config_recipe).
# Never use ``selected - INERT`` — that returns True for unknown recipes.
# "executive dashboard" (_ED) is unioned into the generic-findings filter sets
# because its opt-in detailed mode runs the /findings pipeline
# (report_engine.py:4999-5002), making open_only / current_version_only /
# detected_after / standalone functional there. ED is deliberately NOT added to
# FINDING_TYPES_RECIPES (forced to "all") or PERIOD_RECIPES (not operational).
_ED = {"executive dashboard"}
# Recipes routed through /public/v0/findings (report_engine.py:5376+).
GENERIC_FINDINGS_RECIPES = {
    "executive summary",
    "component vulnerability analysis",
    "findings by project",
    "triage prioritization",
    "remediation package",
    "component impact",
    "component remediation package",
    "false positive analysis",
    "configuration analysis triage",
    "assessment overview",
    "customer brief",
    "customer brief detailed",
}
# The 8 apply_component_filter consumers (spec Appendix A); widened from 3.
COMPONENT_FILTER_RECIPES = {
    "component list",
    "component vulnerability analysis",
    "findings by project",
    "triage prioritization",
    "remediation package",
    "component impact",
    "component remediation package",
    "license report",
}
COMPONENT_VERSION_RECIPES = {"component impact", "component remediation package"}
FINDING_TYPES_RECIPES = {
    "executive summary",
    "component vulnerability analysis",
    "findings by project",
    "version comparison",
    "component impact",
    "component remediation package",
    "false positive analysis",
    "security progress",
    "assessment overview",
    "customer brief",
    "customer brief detailed",
}
CURRENT_VERSION_ONLY_RECIPES = (
    GENERIC_FINDINGS_RECIPES
    | _ED
    | {"component list", "license report", "cve component evidence", "cve impact"}
)
# open_only lives only at report_engine.py 5593/6556 (generic findings); the
# Security Progress / Version Comparison alt path never applies it → SP excluded.
OPEN_ONLY_RECIPES = GENERIC_FINDINGS_RECIPES | _ED
# --detected-after is applied generically on the /findings fetch for every
# NON-operational generic-findings recipe (report_engine.py:5648-5656 — the
# "Assessment reports without date vars" branch), plus the /components and /cves
# fetch paths.  Operational recipes (Executive Summary uses --period instead) and
# Security Progress / Version Comparison (alt fetch path) never apply it.
DETECTED_AFTER_RECIPES = (
    (GENERIC_FINDINGS_RECIPES - {"executive summary"})
    | _ED
    | {"component list", "license report", "cve component evidence", "cve impact"}
)
PERIOD_RECIPES = {
    "executive summary",
    "scan analysis",
    "user activity",
    "security progress",
    "version comparison",
}
SCAN_FILTER_RECIPES = {"scan analysis", "scan quality"}
STANDALONE_RECIPES = GENERIC_FINDINGS_RECIPES | _ED
AI_RECIPES = {
    "cve impact",
    "triage prioritization",
    "remediation package",
    "false positive analysis",
    "component remediation package",
}
# Deployment context reaches the LLM for 4 of the 5 AI recipes — NOT Component
# Remediation Package (crp builds its LLMClient without deployment_context=).
DEPLOYMENT_CONTEXT_RECIPES = {
    "cve impact",
    "triage prioritization",
    "remediation package",
    "false positive analysis",
}
# top / triage consumed by both Triage Prioritization and Config Analysis Triage.
TRIAGE_TAB_RECIPES = {"triage prioritization", "configuration analysis triage"}
# tp_gate, vex_override — Triage Prioritization only.
TP_ONLY_RECIPES = {"triage prioritization"}
# B7 (#10B): the recipes whose autotriage can write VEX recommendations. ONE
# shared source of truth so the UI gate (``show_vex_apply``) and the validation
# recipe-check can't drift (M3-1). Both TP and FP autotriage apply interactively;
# workflow-context permission is FP-only (validate_destructive_overrides) — TP
# autotriage in a workflow stays blocked.
AUTOTRIAGE_RECIPES = {"triage prioritization", "false positive analysis"}

# Effective-scope resolver (#26/#14/#15). Lives in the renderer-importable shared
# module (fs_report.scope_resolution) so the web routers AND the HTML renderers
# read ONE source without a circular import on this web router. (A portfolio-
# recipe set that forces those recipes portfolio-wide was deferred to the
# recipe-scope audit — see the module docstring — so no such constant is
# imported here.)
from fs_report.scope_resolution import compute_effective_scope  # noqa: E402


def is_version_comparison_only(recipe_names: list[str]) -> bool:
    """True iff every selected recipe is (same-server) Version Comparison.

    Version Comparison ignores the scope ``version_filter`` — it diffs an
    explicit baseline/current version-ID pair, or auto-discovers every version
    of a project (``_fetch_version_comparison_data``).  A stale *global* scope
    ``version_filter`` (e.g. a version that only exists in some OTHER project)
    must therefore never be applied to it: the engine's recipe-agnostic
    pre-flight version-name resolution would otherwise abort the whole run with
    "Could not resolve version name '<v>' in project <p>".  Serve never
    configures a cross-server compare client (the only comparison mode that DOES
    consume ``version_filter``, as its primary version), so dropping it here is
    unconditionally safe in the web path.

    Matching is slug-based (not raw display name) because ``start_run`` dedupes
    and the engine filters recipes by ``slug()`` — so slug variants like
    ``version-comparison`` / ``version_comparison`` reach the engine and run VC,
    and must get the same scope cleanup as the canonical ``Version Comparison``.
    """
    from fs_report.slug import slug

    vc_slugs = {slug(name) for name in VERSION_RECIPES}
    names = [slug(r) for r in recipe_names if r.strip()]
    return bool(names) and all(n in vc_slugs for n in names)


def clean_version_comparison_scope(
    cfg: dict[str, Any], recipe_names: list[str]
) -> dict[str, Any]:
    """Return *cfg* with scope keys Version Comparison can't use removed.

    No-op (returns *cfg* unchanged) unless EVERY recipe is Version Comparison
    (:func:`is_version_comparison_only`).  For a VC-only run it returns a shallow
    copy with:

    * ``version_filter`` dropped — VC never consumes it (see that function); a
      stale global scope version would abort the run in pre-flight.
    * a *lone* ``baseline_version`` XOR ``current_version`` dropped — an explicit
      pair needs BOTH version IDs.  A single one is ambiguous, so per the product
      decision it falls back to auto-discovery (compare all versions, latest vs
      previous) rather than failing the engine's both-or-neither check.  A
      COMPLETE pair (both set) is preserved untouched.

    The input dict is never mutated.
    """
    if not is_version_comparison_only(recipe_names):
        return cfg
    cleaned = dict(cfg)
    cleaned.pop("version_filter", None)
    # Strip-aware truthiness so a whitespace-only id ("   ") counts as unset and
    # a lone half-pair is still detected (it would otherwise slip through and
    # diverge from the documented "lone half-pair → auto-discovery" rule).
    bv = str(cleaned.get("baseline_version") or "").strip()
    cv = str(cleaned.get("current_version") or "").strip()
    if bool(bv) != bool(cv):
        cleaned.pop("baseline_version", None)
        cleaned.pop("current_version", None)
    return cleaned


# Scope keys that follow PRESENT-KEY clearing semantics in ``start_run`` (#27).
_SCOPE_PRESENT_KEYS: tuple[str, ...] = (
    "project_filter",
    "folder_filter",
    "version_filter",
)


def apply_scope_present_keys(
    overrides: dict[str, Any], present_scope_keys: set[str]
) -> dict[str, Any]:
    """Record present-but-empty SCOPE keys as explicit clears (#27).

    Returns a NEW dict; ``overrides`` is not mutated.

    The run bar / fast-run send a scope key PRESENT-but-empty on an explicit
    "all projects / all folders / all versions" selection.  ``start_run``'s
    non-empty ``if val`` collection drops those, so the later state∪overrides
    merge (:func:`_execute_run`) would inherit a STALE state scope — the
    confirmed #27 leak (an "all" CVA run silently scoped to a stale prior scope,
    4307→146 findings).

    For each scope key the form actually CARRIED (``present_scope_keys``) that is
    not already a non-empty override, record an explicit ``""`` so the merge
    CLEARS the inherited state value.  A key the form did NOT carry (omitted) is
    left untouched, so a state-derived (global Settings) scope still inherits —
    distinguishing "user chose all" (present-empty → clear) from "no scope field
    sent" (absent → inherit).  Mirrors the present-key clearing the authoritative
    prerun modal already applies; this extends it to minimal run-bar/fast-run
    launches.
    """
    out = dict(overrides)
    for key in _SCOPE_PRESENT_KEYS:
        if key in present_scope_keys and key not in out:
            out[key] = ""
    return out


def _recipe_requires_cve(recipe_names: list[str]) -> bool:
    """True if ANY selected recipe declares the engine ``requires_cve`` flag.

    Field visibility (the static ``*_RECIPES`` name sets) and run-time gating
    (the engine ``requires_*`` flags) are two parallel sources of truth, and
    reviewers keep flagging that they can drift.  This bridges the one field
    that matters: a recipe that *declares* ``requires_cve`` always shows the CVE
    field even if its name isn't in ``CVE_RECIPES``.  Guarded: a recipe-load
    failure degrades to ``False`` (fall back to the static-set behaviour) rather
    than raising.  Loaded inline to avoid an import cycle with the recipe loader.
    """
    try:
        from fs_report.recipe_loader import RecipeLoader

        recipes = RecipeLoader(use_bundled=True, scan_user_recipes=True).load_recipes()
    except Exception:
        return False
    selected = {r.lower() for r in recipe_names}
    for r in recipes:
        if r.name.lower() in selected and bool(getattr(r, "requires_cve", False)):
            return True
    return False


def _recipe_requires_component(recipe_names: list[str]) -> bool:
    """True if ANY selected recipe declares ``requires_component`` (B4 #25).

    The visibility bridge for component, mirroring :func:`_recipe_requires_cve`:
    a recipe that *declares* ``requires_component`` must always SHOW the
    component field — visibility can never hide a declared-required input (else
    a recipe could be marked needs-setup while hiding the field that satisfies
    it). Guarded: a load failure degrades to the static-set behaviour.
    """
    try:
        from fs_report.recipe_loader import RecipeLoader

        recipes = RecipeLoader(use_bundled=True, scan_user_recipes=True).load_recipes()
    except Exception:
        return False
    selected = {r.lower() for r in recipe_names}
    for r in recipes:
        if r.name.lower() in selected and bool(getattr(r, "requires_component", False)):
            return True
    return False


def compute_prerun_fields(
    recipe_names: list[str],
    *,
    requires_cve_names: frozenset[str] | None = None,
    requires_component_names: frozenset[str] | None = None,
    compound_children: dict[str, list[str]] | None = None,
    is_comparison: bool = False,
) -> dict[str, bool]:
    """Compute the conditional field-visibility flags for the prerun form.

    Returns the **full** set of ``show_*`` booleans the configure modal computes
    so the modal, the Command Center card back, and the Builder inspector share
    one source of truth and can't drift: ``show_cve``, ``show_ai``,
    ``show_deployment_context``, ``show_triage``, ``show_tp_gate``,
    ``show_vex_apply``, ``show_scoring``, ``show_finding_types``,
    ``show_version_fields``, ``show_project_required``, ``show_component``,
    ``show_component_match``, ``show_component_version``,
    ``show_component_recommended``, ``show_license``, ``show_threat_context``,
    ``show_period``, ``show_current_version_only``, ``show_open_only``,
    ``show_detected_after``, ``show_standalone``, ``show_scan_filters``,
    ``show_baseline_date``, ``show_detailed``, ``show_left_right_override``.

    Field-visibility gating (report-config-card-gating)
    ---------------------------------------------------
    All gates are positive allow-lists (``bool(selected & SET)``) so an unknown /
    zero-config recipe returns every flag ``False`` (``test_zero_config_recipe``).
    The sets are defined above; see the spec for the per-recipe verification map.

    Keyed off the lowercase recipe name against the recipe group constants
    above, matching the canonical lowercase key convention.

    ``show_cve`` additionally unions in the engine ``requires_cve`` flag:
    visibility must never hide a *declared required* input, so a ``requires_cve``
    recipe always shows the CVE field even if its name isn't in ``CVE_RECIPES``.
    By default this calls :func:`_recipe_requires_cve` (which loads the recipe
    corpus).  A caller that already holds the corpus — e.g. ``build_shell_context``
    looping over every recipe — can pass ``requires_cve_names`` (a frozenset of
    lowercase names that declare ``requires_cve``) to skip the per-call reload and
    avoid an O(N) corpus re-scan; when supplied, the union uses it instead.

    Compound expansion (PR2.3a)
    ---------------------------
    When *compound_children* is supplied (a mapping of lowercase compound name
    → list of child recipe names), any name in *recipe_names* that is a key in
    this map is **expanded** into its child names before the ``show_*`` set
    computation.  This ensures a plain compound's prerun form reflects the union
    of its children's requirements — matching what dispatch enforces — without
    the form needing to know about compound internals.  Backward-compatible:
    when ``compound_children=None`` (the default) behaviour is identical to
    before PR2.3a.

    Comparison (PR3.3a)
    -------------------
    When *is_comparison* is ``True`` — i.e. the recipe is an axis-bearing
    ``CompoundRecipe`` (a meta-compare bundle) — two additional flags are forced
    on regardless of the child recipe set:
    - ``show_finding_types``: comparisons expose the finding-type selector at
      run time (Decision 11: run-only, never persisted).
    - ``show_left_right_override``: renders the Left/Right scope-ref override
      fields pre-filled with the baked axis defaults, allowing the user to
      override them for this run only.
    All other flags are computed normally from the child names.  Non-comparison
    calls are unaffected (``is_comparison=False`` is the default).
    """
    # Expand compound recipes into their children before computing visibility.
    if compound_children:
        expanded: list[str] = []
        for name in recipe_names:
            child_list = compound_children.get(name.lower())
            if child_list is not None:
                expanded.extend(child_list)
            else:
                expanded.append(name)
        effective_names = expanded
    else:
        effective_names = recipe_names

    selected = {r.lower() for r in effective_names}
    requires_cve = (
        bool(selected & requires_cve_names)
        if requires_cve_names is not None
        else _recipe_requires_cve(effective_names)
    )
    requires_component = (
        bool(selected & requires_component_names)
        if requires_component_names is not None
        else _recipe_requires_component(effective_names)
    )
    return {
        "show_cve": bool(selected & (CVE_RECIPES | REMEDIATION_RECIPES))
        or requires_cve,
        # AI enrichment toggle/depth/prompts — the 5 AI-capable recipes.
        "show_ai": bool(selected & AI_RECIPES),
        # Deployment context (4 text fields + context-file) reaches the LLM for
        # 4 of those 5 — NOT Component Remediation Package.
        "show_deployment_context": bool(selected & DEPLOYMENT_CONTEXT_RECIPES),
        # top / triage — Triage Prioritization AND Config Analysis Triage.
        "show_triage": bool(selected & TRIAGE_TAB_RECIPES),
        # tp_gate / vex_override — Triage Prioritization only.
        "show_tp_gate": bool(selected & TP_ONLY_RECIPES),
        # VEX auto-apply — any autotriage-capable recipe (TP or FP), B7 #10B.
        "show_vex_apply": bool(selected & AUTOTRIAGE_RECIPES),
        # Workflow autotriage (Builder inspector) — FP Analysis ONLY: in a
        # workflow only FP autotriage is permitted (TP stays interactive-only),
        # so the Builder gates its autotriage control on this, not show_vex_apply.
        "show_workflow_autotriage": bool(selected & FPA_RECIPES),
        # SP3: scoring-file control shows for its verified consumers.
        "show_scoring": bool(selected & SCORING_RECIPES),
        # B11 #18: per-consumer scoring-file meaning. Pure-staleness (Scan
        # Quality) vs pure-triage-weights (TP / Config Analysis Triage); a mixed
        # compound trips neither → the generic label/hint.
        "scoring_is_staleness": bool(selected & STALENESS_SCORING_RECIPES)
        and not bool(selected & TRIAGE_SCORING_RECIPES),
        "scoring_is_triage": bool(selected & TRIAGE_SCORING_RECIPES)
        and not bool(selected & STALENESS_SCORING_RECIPES),
        # PR3.3a: comparisons always expose finding-types at run time (Decision 11).
        "show_finding_types": is_comparison or bool(selected & FINDING_TYPES_RECIPES),
        "show_version_fields": bool(selected & VERSION_RECIPES),
        "show_project_required": bool(selected & REMEDIATION_RECIPES),
        # Component name filter + its match-mode — the 8 apply_component_filter
        # consumers; component_version is the narrower version-range pair.
        "show_component": bool(selected & COMPONENT_FILTER_RECIPES)
        or requires_component,
        "show_component_match": bool(selected & COMPONENT_FILTER_RECIPES),
        "show_component_version": bool(selected & COMPONENT_VERSION_RECIPES),
        "show_component_recommended": bool(selected & COMPONENT_RECOMMENDED_RECIPES),
        "show_license": bool(selected & LICENSE_RECIPES),
        # threat_context is a Component-Remediation-Package-only knob (AI tab).
        "show_threat_context": bool(selected & COMPONENT_REMEDIATION_RECIPES),
        # Operational date window — only recipes whose pipeline trims by period.
        "show_period": bool(selected & PERIOD_RECIPES),
        # Generic-findings filters (∪ ED detailed mode).
        "show_current_version_only": bool(selected & CURRENT_VERSION_ONLY_RECIPES),
        "show_open_only": bool(selected & OPEN_ONLY_RECIPES),
        "show_detected_after": bool(selected & DETECTED_AFTER_RECIPES),
        "show_standalone": bool(selected & STANDALONE_RECIPES),
        # Scan ingest filters — Scan Analysis / Scan Quality only.
        "show_scan_filters": bool(selected & SCAN_FILTER_RECIPES),
        "show_baseline_date": bool(selected & SECURITY_PROGRESS_RECIPES),
        "show_detailed": bool(selected & EXEC_DASHBOARD_RECIPES),
        # PR3.3a: Left/Right scope-ref override fields (comparison-only).  When
        # True, prerun.html renders two text inputs pre-filled with the baked axis
        # values so the user can override them for this run only (never persisted).
        "show_left_right_override": is_comparison,
    }


def validate_run_overrides(overrides: dict[str, Any]) -> list[str]:
    """Validate a single run-override dict; return human-readable error strings.

    Empty list means all checks passed.  Missing / empty / whitespace values
    are treated as "unset, skip".  All applicable errors are collected (the
    caller should 400 with the full list).

    Rules checked:
    - ``component_match`` must be "contains" or "exact" (if set).
    - ``tp_gate`` must be "GATE_1", "GATE_2", or "NONE" (if set).
    - ``start`` / ``end`` (custom range): both-or-neither; each must be ISO
      YYYY-MM-DD; start <= end.
    - ``period``: must not be the literal "custom" (use start/end instead);
      must be parseable by PeriodParser.  Period + start/end together is
      rejected (ambiguous).
    - ``scan_types`` / ``scan_statuses``: comma-split, upper-cased; every
      token must be in the canonical valid set.
    """
    from datetime import datetime as _dt

    from fs_report.period_parser import PeriodParser

    errors: list[str] = []

    def _is_set(v: Any) -> bool:
        return v is not None and str(v).strip() != ""

    # ── component_match ──────────────────────────────────────────────
    # component_match / tp_gate are intentionally case-SENSITIVE: their values
    # come from controlled <select> options (the three SP1 launch surfaces emit
    # the canonical engine casing — lowercase "contains"/"exact", uppercase
    # GATE_1/GATE_2/NONE) and flow straight to the engine, which compares against
    # those exact strings.  Accepting other casings here would let a non-canonical
    # value reach the engine and silently mis-behave, so we reject it loudly.
    cm = overrides.get("component_match")
    if _is_set(cm) and str(cm).strip() not in {"contains", "exact"}:
        errors.append(
            f"component_match must be 'contains' or 'exact', got {str(cm).strip()!r}"
        )

    # ── tp_gate ──────────────────────────────────────────────────────
    tg = overrides.get("tp_gate")
    if _is_set(tg) and str(tg).strip() not in {"GATE_1", "GATE_2", "NONE"}:
        errors.append(
            f"tp_gate must be one of GATE_1, GATE_2, NONE, got {str(tg).strip()!r}"
        )

    # ── start / end (custom date range) ─────────────────────────────
    start_raw = overrides.get("start")
    end_raw = overrides.get("end")
    start_set = _is_set(start_raw)
    end_set = _is_set(end_raw)

    if start_set != end_set:
        errors.append(
            "both 'start' and 'end' must be provided together for a custom date range"
        )
    else:
        start_dt = None
        end_dt = None
        if start_set:
            try:
                start_dt = _dt.strptime(str(start_raw).strip(), "%Y-%m-%d")
            except ValueError:
                errors.append(
                    f"start must be ISO YYYY-MM-DD, got {str(start_raw).strip()!r}"
                )
        if end_set:
            try:
                end_dt = _dt.strptime(str(end_raw).strip(), "%Y-%m-%d")
            except ValueError:
                errors.append(
                    f"end must be ISO YYYY-MM-DD, got {str(end_raw).strip()!r}"
                )
        if start_dt is not None and end_dt is not None and start_dt > end_dt:
            errors.append(
                f"start ({str(start_raw).strip()}) must be <= end ({str(end_raw).strip()})"
            )

    # ── period ───────────────────────────────────────────────────────
    period_raw = overrides.get("period")
    period_set = _is_set(period_raw)

    if period_set:
        period_str = str(period_raw).strip()
        if period_str.lower() == "custom":
            errors.append(
                "period 'custom' is not valid here — use 'start' and 'end' to specify a"
                " custom date range"
            )
        else:
            # Period vs range exclusivity: if period is set AND (start or end is
            # set), the combination is ambiguous — reject it.
            if start_set or end_set:
                errors.append(
                    "specify either a named period or a custom start/end range, not both"
                )
            else:
                try:
                    PeriodParser.parse_period(period_str)
                except ValueError:
                    errors.append(
                        f"unrecognized period {period_str!r} — use a value like '7d',"
                        " '30d', 'Q1', 'january-2024', 'ytd', etc."
                    )

    # ── baseline_date / detected_after (independent single ISO dates) ──
    for _date_key in ("baseline_date", "detected_after"):
        _date_raw = overrides.get(_date_key)
        if _is_set(_date_raw):
            try:
                _dt.strptime(str(_date_raw).strip(), "%Y-%m-%d")
            except ValueError:
                errors.append(
                    f"{_date_key} must be ISO YYYY-MM-DD, got {str(_date_raw).strip()!r}"
                )

    # ── top / triage (non-negative integers) ─────────────────────────
    for _int_key in ("top", "triage"):
        _int_raw = overrides.get(_int_key)
        if _is_set(_int_raw):
            try:
                _parsed_int = int(str(_int_raw))
                if _parsed_int < 0:
                    raise ValueError("negative")
            except (ValueError, TypeError):
                errors.append(
                    f"{_int_key} must be a non-negative integer, got {str(_int_raw)!r}"
                )

    # ── scan_types ───────────────────────────────────────────────────
    scan_types_raw = overrides.get("scan_types")
    if _is_set(scan_types_raw):
        from fs_report.cli.run import VALID_SCAN_TYPES

        tokens = [
            t.strip().upper() for t in str(scan_types_raw).split(",") if t.strip()
        ]
        invalid = sorted(set(tokens) - VALID_SCAN_TYPES)
        if invalid:
            errors.append(
                f"invalid scan_types: {', '.join(invalid)}; valid values are"
                f" {', '.join(sorted(VALID_SCAN_TYPES))}"
            )

    # ── scan_statuses ────────────────────────────────────────────────
    scan_statuses_raw = overrides.get("scan_statuses")
    if _is_set(scan_statuses_raw):
        from fs_report.cli.run import VALID_SCAN_STATUSES

        tokens = [
            t.strip().upper() for t in str(scan_statuses_raw).split(",") if t.strip()
        ]
        invalid = sorted(set(tokens) - VALID_SCAN_STATUSES)
        if invalid:
            errors.append(
                f"invalid scan_statuses: {', '.join(invalid)}; valid values are"
                f" {', '.join(sorted(VALID_SCAN_STATUSES))}"
            )

    # ── autotriage_status (SP2 VEX-write status filter) ──────────────
    autotriage_status_raw = overrides.get("autotriage_status")
    if _is_set(autotriage_status_raw):
        from fs_report.vex_applier import VALID_VEX_STATUSES

        tokens = [
            t.strip().upper()
            for t in str(autotriage_status_raw).split(",")
            if t.strip()
        ]
        invalid = sorted(set(tokens) - VALID_VEX_STATUSES)
        if invalid:
            errors.append(
                f"invalid autotriage_status: {', '.join(invalid)}; valid values are"
                f" {', '.join(sorted(VALID_VEX_STATUSES))}"
            )

    # ── left_scope / right_scope (comparison run-only overrides) ──────
    # PR3.3a: a meta-compare run may override the baked axis with a scope-ref
    # string (Decision 11).  Validate the grammar synchronously here — using the
    # SAME parser the engine applies (scope_ref.parse, aliased to
    # _parse_scope_ref in report_engine) — so a malformed override is rejected
    # with a 400 at submit instead of starting a doomed run that only fails at
    # the engine's _process_axis_compound precheck.  This mirrors the save-time
    # hard-block (_build_scope_ref) for the run-time path.
    if _is_set(overrides.get("left_scope")) or _is_set(overrides.get("right_scope")):
        from fs_report.scope_ref import ScopeRefError
        from fs_report.scope_ref import parse as _parse_scope_ref

        _parsed: dict[str, Any] = {}
        for _scope_key in ("left_scope", "right_scope"):
            _scope_raw = overrides.get(_scope_key)
            if not _is_set(_scope_raw):
                continue
            try:
                _parsed[_scope_key] = _parse_scope_ref(str(_scope_raw).strip())
            except ScopeRefError as _exc:
                _label = "Left" if _scope_key == "left_scope" else "Right"
                errors.append(f"{_label} scope override is invalid: {_exc}")

        # Self-comparison guard (parity with the save-time hard-block): when BOTH
        # sides are overridden and resolve to the same canonical ref, reject at
        # submit rather than starting a run that only warns/fails mid-engine.
        # (Only checkable when both overrides are present; a single override
        # paired with the baked axis is resolved later by the engine.)
        _l, _r = _parsed.get("left_scope"), _parsed.get("right_scope")
        if _l is not None and _r is not None and _l == _r:
            errors.append(
                "Left and Right scope overrides are identical (self-comparison)"
            )

    return errors


def validate_destructive_overrides(
    overrides: dict[str, Any],
    *,
    recipes: list[str],
    is_workflow: bool = False,
    dry_run: bool = False,
) -> list[str]:
    """Recipe-aware checks for the SP2 destructive VEX-write fields (autotriage).

    Separate from :func:`validate_run_overrides` (which is value-only and
    recipe-agnostic) because these rules need the selected recipe(s) / launch
    context. Returns human-readable error strings; empty == OK. Callers 400 with
    the full list. (spec §8)

    Rules:
    - **Workflow context** (``is_workflow=True``): autotriage is allowed ONLY as
      a per-step override on a **False Positive Analysis** step (the B7 #10B SP2
      relaxation). TP-in-workflow stays blocked (TP autotriage is
      interactive-only), and autotriage with no FP recipe in context — notably
      the workflow GLOBAL block (``recipes=[]``) — is blocked, so the opt-in can
      never be a global that silently autotriages every step.
    - **Interactive**: autotriage requires an **autotriage-capable** recipe in
      the selection — Triage Prioritization or False Positive Analysis
      (``AUTOTRIAGE_RECIPES``); allowed in a multi-recipe run that includes one.
    - ``autotriage_status`` / ``dry_run`` are meaningful only with ``autotriage``.
    """
    errors: list[str] = []
    autotriage_on = bool(overrides.get("autotriage"))
    status_raw = overrides.get("autotriage_status")
    status_set = status_raw not in (None, "", [])
    recipes_lc = {r.strip().lower() for r in recipes}

    if is_workflow:
        # B7 (#10B): the SP2 relaxation — FP-Analysis autotriage IS allowed in a
        # workflow, but ONLY as a per-step override on an FP step. Everything
        # else stays blocked: TP-in-workflow (TP autotriage is interactive-only)
        # and autotriage with no FP recipe in context — crucially the workflow
        # GLOBAL block (called with recipes=[]), so the opt-in can never be a
        # global that silently autotriages every step.
        if autotriage_on or status_set:
            if not (recipes_lc & FPA_RECIPES):
                errors.append(
                    "autotriage (VEX auto-apply) in a workflow is allowed only on "
                    "a False Positive Analysis step"
                )
                return errors
            if status_set and not autotriage_on:
                errors.append("autotriage_status requires autotriage to be enabled")
        return errors

    if autotriage_on:
        if not (recipes_lc & AUTOTRIAGE_RECIPES):
            errors.append(
                "autotriage (VEX auto-apply) requires a Triage Prioritization "
                "or False Positive Analysis recipe in the run"
            )
    else:
        if status_set:
            errors.append("autotriage_status requires autotriage to be enabled")
        if dry_run:
            errors.append("dry_run requires autotriage to be enabled")
    return errors


def stale_upload_path_errors(effective: dict[str, Any]) -> list[str]:
    """Re-check that uploaded scoring/context files still exist and are valid.

    SP3 §5: this runs at **run-start only** (`start_run` + workflow run) — NOT in
    `validate_run_overrides`, which also gates card/workflow *save* (where a
    not-yet-needed path shouldn't block). An upload can be deleted or edited
    between save and run; re-validate content so a since-corrupted file → a clean
    400, never a silent transform fallback.
    """
    errors: list[str] = []
    sf = effective.get("scoring_file")
    if sf and str(sf).strip():
        from fs_report.scoring_support import validate_scoring_yaml

        errs, _ = validate_scoring_yaml(str(sf))
        if errs:
            errors.append(f"scoring file no longer valid — re-upload ({errs[0]})")
    cf = effective.get("context_file")
    if cf and str(cf).strip():
        from fs_report.deployment_context import load_context_file

        try:
            load_context_file(str(cf))
        except (FileNotFoundError, ValueError) as e:
            errors.append(f"context file no longer valid — re-upload ({e})")
    return errors


def should_validate_context_file(recipe_names: list[str]) -> bool:
    """Whether a run of *recipe_names* should re-validate the effective
    ``context_file`` path at run-start (report-config-card-gating).

    Validate iff some selected recipe will actually read the deployment context.
    A recipe that does not consume it (``show_deployment_context`` False — e.g.
    Component Remediation Package, whose card no longer shows the field) won't
    read ``context_file``, so a stale/deleted path must NOT 400 the run on a
    field the user can no longer clear. Returns True when **any** recipe in the
    set consumes it, or when any name resolves to a compound (a child may consume
    it). Used by both the single-run path (``start_run``) and the workflow run
    path (``run_workflow``) — for a workflow, pass the step recipe names. Empty
    input → True (validate; nothing to safely skip). ``scoring_file`` gating is
    unaffected by this work, so it is always validated as before.
    """
    if not recipe_names:
        return True
    from fs_report.models import CompoundRecipe  # noqa: PLC0415
    from fs_report.slug import slug as _slug  # noqa: PLC0415

    # Resolve each ref to its CANONICAL recipe name via the slug-keyed index, so
    # the consumption check works whether callers pass display names or slug-form
    # refs (compute_prerun_fields keys on lowercase names). A compound ref → a
    # child may consume it → validate. Unknown refs fall through as-is (they
    # match no set → contribute nothing).
    index = _load_canvas_recipes_index()
    canonical: list[str] = []
    for name in recipe_names:
        obj = index.get(_slug(name))
        if isinstance(obj, CompoundRecipe):
            return True
        canonical.append(obj.name if obj is not None else name)
    return bool(compute_prerun_fields(canonical).get("show_deployment_context", False))


def merge_with_period_range_clearing(
    base: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    """Merge ``incoming`` over ``base`` with date-mode conflict clearing.

    Returns a NEW dict; neither input is mutated.

    Rules:
    - If ``incoming`` carries BOTH a non-empty ``start`` AND ``end`` →
      drop ``period`` from ``base`` before merging (range wins, clears period).
    - Else if ``incoming`` carries a non-empty ``period`` →
      drop ``start`` and ``end`` from ``base`` before merging (period wins,
      clears range).
    - Otherwise (``incoming`` sets neither date mode) → plain merge, no
      clearing.

    "Non-empty" = not ``None`` and not whitespace-only.
    """

    def _is_nonempty(v: Any) -> bool:
        return v is not None and str(v).strip() != ""

    start_in = _is_nonempty(incoming.get("start"))
    end_in = _is_nonempty(incoming.get("end"))
    period_in = _is_nonempty(incoming.get("period"))

    effective_base = dict(base)

    if start_in and end_in:
        # Incoming has a custom range → clear any saved period from base.
        effective_base.pop("period", None)
    elif period_in:
        # Incoming has a named period → clear any saved range from base.
        effective_base.pop("start", None)
        effective_base.pop("end", None)
    # else: neither → plain merge, no clearing.

    return {**effective_base, **incoming}


def _parse_cache_ttl(value: Any) -> int:
    """Parse cache TTL from form input, supporting '4h', '2d', '30m', or bare int."""
    from fs_report.sqlite_cache import parse_ttl

    s = str(value).strip()
    if not s:
        return 0
    try:
        return parse_ttl(s)
    except (ValueError, TypeError):
        logger.warning(f"Invalid cache TTL '{s}', defaulting to 4h")
        return 4 * 3600


class SSELogHandler(logging.Handler):
    """Captures Python logging records and pushes them into an asyncio queue."""

    def __init__(self, queue: RunEventHub, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._queue = queue
        self._loop = loop

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            level = record.levelname.lower()
            self._loop.call_soon_threadsafe(
                self._queue.put_nowait,
                {
                    "event": "log",
                    "data": json.dumps({"level": level, "message": msg}),
                },
            )
        except Exception:
            pass


def _split_status_list(raw: Any) -> list[str] | None:
    """Coerce a comma-joined VEX-status multi-select to an uppercased list.

    Mirrors how ``scan_types`` is split, but returns a ``list[str]`` because
    ``Config.autotriage_status`` is ``list[str] | None`` (SP2). Empty -> None.
    """
    if not raw:
        return None
    items = raw if isinstance(raw, list) else str(raw).split(",")
    out = [str(s).strip().upper() for s in items if str(s).strip()]
    return out or None


def _build_engine_config(
    effective: dict[str, Any],
    *,
    output_dir: Path,
    token: str,
    domain: str,
) -> Any:
    """Build a run ``Config`` from an ``effective`` config dict (shared helper).

    Single source of truth for the ``create_config(...)`` kwargs used by BOTH
    the single-run path (``_execute_run``) and each workflow step
    (``_run_one_recipe_step``), so the kwargs block can't drift between them.
    ``period`` is read straight from ``effective``.  SP1 normalized models never
    carry ``period == "custom"`` or a ``custom_range`` key; a custom date range is
    expressed as top-level ``start`` + ``end`` keys in the effective config.

    Keys threaded (always-pass style, preserving ``create_config`` defaults):
    ``period``, ``start``, ``end``, ``finding_types``, ``token``, ``domain``,
    ``output``, ``project_filter``, ``folder_filter``, ``version_filter``,
    ``cache_ttl``, ``cache_dir``, ``current_version_only``, ``overwrite``,
    ``ai``, ``ai_depth``, ``ai_prompts``, ``ai_analysis``, ``product_type``,
    ``network_exposure``, ``regulatory``, ``deployment_notes``, ``cve_filter``,
    ``component_filter``, ``component_match``, ``component_version``,
    ``license_filter``, ``threat_context``, ``tp_gate``, ``baseline_date``,
    ``detected_after``, ``scan_types``, ``scan_statuses``, ``open_only``,
    ``detailed``, ``standalone``, ``vex_override``, ``top``, ``triage``,
    ``verbose``, ``logo``.

    Pass-through-present-keys for ``baseline_version`` / ``current_version``:
    they are forwarded ONLY when present in ``effective`` (with the same
    ``or None`` clearing the single-run path applies).  ``_execute_run``'s
    effective always carries them (so the call stays byte-for-byte equivalent to
    today); the workflow effective never does (so it falls through to
    ``create_config``'s ``None`` default — identical to passing ``None``).

    PR3.3a: ``left_scope`` / ``right_scope`` are also present-key-only — they
    are comparison run-only overrides (Decision 11) that only appear in the
    effective dict when explicitly submitted via the prerun form; absent means
    "use the baked axis value" so the engine's ``_process_axis_compound`` applies
    the pinned values unchanged.
    """
    from fs_report.cli.run import create_config

    # Normalize project_filter to its STRIPPED value up front (empty → unset) so
    # the SAME value drives both the precedence decision AND the create_config
    # call. A whitespace-only project ("   ") is not a real selection: it must
    # never carry through to the engine (where a truthy "   " would be applied as
    # a project) and must never wrongly suppress the folder. (Finding 3)
    project_filter = (effective.get("project_filter") or "").strip() or None

    # Folder-targeting precedence — project wins (design §3, authoritative).
    # When a SPECIFIC project is selected the folder was only a UI filter and
    # must NOT reach the engine (which would otherwise enforce the stricter
    # project-must-be-in-folder intersection). Dropping it HERE — the single
    # config-building chokepoint for the single-run path, every workflow step,
    # prerun, replay, and any future API caller — means no caller can construct
    # a config carrying an ambiguous combined scope, regardless of client
    # behavior. ``project_filter`` is already strip-normalized above (a
    # whitespace-only value is not a real selection). Folder-only (no project)
    # keeps its folder_filter (the recursive folder-tree target).
    project_set = bool(project_filter)
    folder_filter = None if project_set else (effective.get("folder_filter") or None)

    # Invariant: a version requires a project (design §3). ``version_filter`` is a
    # project-scoped version ID — it is meaningless, and the engine rejects it,
    # without a project to resolve it against. Whenever the (stripped)
    # ``project_filter`` is empty — folder-only OR portfolio-wide — drop any
    # inherited/leftover ``version_filter`` so no caller can construct a
    # project-less folder+version (or portfolio+version) scope. This is the single
    # chokepoint for the single-run path, every workflow step (whose effective
    # config is built through here), prerun, and replay — so it also covers a
    # workflow whose GLOBAL scope is folder-only with a version (the case the
    # narrow folder-only-step clear in ``_effective_step_config`` missed). When a
    # project IS set the version is kept untouched. This is orthogonal to the
    # VC-only ``clean_version_comparison_scope`` (which drops version even WITH a
    # project, because Version Comparison never consumes the scope version).
    version_filter = (effective.get("version_filter") or None) if project_set else None

    kwargs: dict[str, Any] = {
        "period": effective.get("period") or None,
        "start": effective.get("start") or None,
        "end": effective.get("end") or None,
        "finding_types": effective.get("finding_types", "cve"),
        "token": token,
        "domain": domain,
        "output": output_dir,
        "project_filter": project_filter,
        "folder_filter": folder_filter,
        "version_filter": version_filter,
        "cache_ttl": _parse_cache_ttl(effective.get("cache_ttl", "4")),
        "cache_dir": effective.get("cache_dir") or None,
        "current_version_only": bool(effective.get("current_version_only", True)),
        "overwrite": bool(effective.get("overwrite", False)),
        "ai": bool(effective.get("ai", False)),
        "ai_depth": str(effective.get("ai_depth", "summary")),
        "ai_prompts": bool(effective.get("ai_prompts", False)),
        "ai_analysis": bool(effective.get("ai_analysis", False)),
        "product_type": effective.get("product_type") or None,
        "network_exposure": effective.get("network_exposure") or None,
        "regulatory": effective.get("regulatory") or None,
        "deployment_notes": effective.get("deployment_notes") or None,
        # SP3: uploaded-file paths threaded as create_config params.
        "scoring_file": effective.get("scoring_file") or None,
        "context_file": effective.get("context_file") or None,
        "cve_filter": effective.get("cve_filter") or None,
        "component_filter": effective.get("component_filter") or None,
        # `or "contains"` (not `or None`): create_config's default is "contains",
        # so an unset/empty value must restore that default, not pass None.
        "component_match": effective.get("component_match") or "contains",
        "component_version": effective.get("component_version") or None,
        "license_filter": effective.get("license_filter") or None,
        "threat_context": effective.get("threat_context") or None,
        "tp_gate": effective.get("tp_gate") or None,
        "baseline_date": effective.get("baseline_date") or None,
        "detected_after": effective.get("detected_after") or None,
        "scan_types": effective.get("scan_types") or None,
        "scan_statuses": effective.get("scan_statuses") or None,
        "open_only": bool(effective.get("open_only", False)),
        "detailed": bool(effective.get("detailed", False)),
        "standalone": bool(effective.get("standalone", False)),
        "vex_override": bool(effective.get("vex_override", False)),
        # SP2 (destructive VEX-write apply). autotriage toggle ON -> "high"
        # (parity with the CLI's bare --autotriage default). autotriage_status is
        # the comma-joined multi-select coerced to list[str] HERE — the one place
        # the conversion happens — because Config.autotriage_status is list[str]
        # (unlike scan_types, which stays a string). dry_run is deliberately NOT
        # threaded: it is a transient per-launch param, never in create_config.
        "autotriage": "high" if effective.get("autotriage") else None,
        "autotriage_status": _split_status_list(effective.get("autotriage_status")),
        "top": int(effective.get("top", 0)),
        "triage": int(effective.get("triage", 0)),
        "verbose": bool(effective.get("verbose", False)),
        "logo": effective.get("logo") or None,
    }
    # Pass-through-present-keys: only the single-run path carries these.
    if "baseline_version" in effective:
        kwargs["baseline_version"] = effective.get("baseline_version") or None
    if "current_version" in effective:
        kwargs["current_version"] = effective.get("current_version") or None
    # PR3.3a: comparison run-time Left/Right scope overrides (Decision 11 —
    # run-only, never persisted).  Present means the user supplied an explicit
    # override; absent means the engine uses the baked axis value unchanged.
    if "left_scope" in effective:
        kwargs["left_scope"] = effective.get("left_scope") or None
    if "right_scope" in effective:
        kwargs["right_scope"] = effective.get("right_scope") or None
    return create_config(**kwargs)


def _execute_run(
    run_id: str,
    recipe_names: list[str],
    state_data: dict[str, Any],
    overrides: dict[str, Any],
    queue: RunEventHub,
    loop: asyncio.AbstractEventLoop,
    cancel_event: threading.Event | None = None,
    dry_run: bool = False,
    compound_total: int | None = None,
) -> None:
    """Worker thread: run recipes and push events to the SSE queue.

    ``dry_run`` is the SP2 transient per-launch flag: when the effective config
    enables ``autotriage``, the post-report VEX apply runs in preview mode
    (no platform writes) so the run produces a preview the user can commit.

    ``compound_total`` is the Pass-4 Run-canvas flag: when not None, this run is
    a COMPOUND bundle of ``compound_total`` child sections (one combined
    deliverable). The engine's per-section hooks (``on_section_start`` /
    ``on_section_complete``) become the SOLE progress source — the coarse
    per-recipe tick (``on_recipe_complete``) and this function's own initial /
    final ``progress`` emits are suppressed so the monitor/toolbar reflect real
    sections-done (``n/num_children``), never a misleading ``1/1`` (spec §5.3).
    """
    from fs_report.report_engine import ReportCancelled, ReportEngine
    from fs_report.slug import slug

    is_compound = compound_total is not None

    # Merge state with overrides.  Use the period↔range clearing merge (NOT a
    # plain dict merge): ``state_data`` always carries a ``period`` (the "30d"
    # DEFAULTS baseline), so a run that supplies a custom ``start``/``end`` in
    # ``overrides`` (with no ``period``) would otherwise end up with BOTH — and
    # ``create_config`` gives ``period`` precedence, silently discarding the
    # custom range.  Dropping the inherited ``period`` when the override sets a
    # range (and vice-versa) mirrors the workflow path's _effective_step_config.
    effective = merge_with_period_range_clearing(state_data, overrides)

    from fs_report.logging_utils import create_file_handler

    # Install SSE log handler
    handler = SSELogHandler(queue, loop)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    old_level = root_logger.level
    if root_logger.level > logging.INFO:
        root_logger.setLevel(logging.INFO)

    captured_stderr = io.StringIO()

    file_handler: logging.FileHandler | None = None
    try:
        token = effective.get("token", "")
        domain = effective.get("domain", "")

        if not token or not domain:
            _runs[run_id]["result"] = "error"
            # Route through the recorder so this in-worker early failure (before
            # run_output.mkdir) still persists its error canvas (spec §10).
            _record_canvas_event(
                run_id,
                queue,
                loop,
                "done",
                '{"status":"error","error":"Missing token or domain"}',
            )
            return

        file_handler = create_file_handler(run_id, token)
        root_logger.addHandler(file_handler)

        # Store log filename for later retrieval
        log_filename = Path(file_handler.baseFilename).name
        _runs[run_id]["log_file"] = log_filename

        output_dir = effective.get("output_dir", "./output")
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%S")
        run_output = Path(output_dir).expanduser() / "runs" / f"{ts}_{run_id}"
        # output/runs/ grows with each run and is intentionally NOT pruned here:
        # auto-deleting would orphan report_history entries and silently remove
        # user-generated reports.  Retention / cleanup is a separate explicit op.
        run_output.mkdir(parents=True, exist_ok=True)

        # Single-run path always carries baseline_version/current_version in the
        # effective dict (state ∪ overrides), so the shared helper forwards them
        # — keeping this config byte-for-byte equivalent to the inline block.
        effective.setdefault("baseline_version", None)
        effective.setdefault("current_version", None)
        # Version Comparison ignores the scope version_filter and needs a
        # COMPLETE baseline/current pair: drop a stale global scope version (so
        # it can't abort pre-flight version-name resolution) and any lone
        # half-pair (so the run falls into auto-discovery — compare all versions
        # — instead of the engine's both-or-neither failure).  Done BEFORE the
        # scope log below so the audit log reflects what actually runs, not a
        # stale "@ v2.0" that was already dropped from the engine config.
        effective = clean_version_comparison_scope(effective, recipe_names)
        # Version requires a project (engine invariant — _build_engine_config
        # drops a project-less version): normalize the worker's effective scope
        # ONCE here so every downstream reader of it — the audit scope log below
        # AND the Report History scope_dict — stays honest and never describes a
        # version-scoped run the engine won't execute (M2-1). Covers a launch
        # that cleared the project (present-empty) while a stale state version
        # was still inherited.
        if not str(effective.get("project_filter") or "").strip():
            effective.pop("version_filter", None)

        scope_parts = []
        for k in ("project_filter", "folder_filter", "version_filter"):
            v = effective.get(k)
            if v:
                scope_parts.append(f"{k}={v}")
        if scope_parts:
            logger.info("Scope: %s", ", ".join(scope_parts))
        else:
            logger.info("Scope: (entire portfolio)")

        config = _build_engine_config(
            effective, output_dir=run_output, token=token, domain=domain
        )

        total = len(recipe_names)

        def _on_recipe_done(completed: int, total_count: int, name: str) -> None:
            _runs[run_id]["progress"] = {
                "completed": completed,
                "total": total_count,
                "recipe": name,
            }
            # Route through the recorder so the plain-report node-lighting
            # progress (the SOLE per-recipe signal) is captured for replay
            # (spec §4.1 — this inline site bypassed the helpers before).
            _record_canvas_event(
                run_id,
                queue,
                loop,
                "progress",
                json.dumps(
                    {"completed": completed, "total": total_count, "recipe": name}
                ),
            )

        def _on_recipe_start(idx_started: int, total_count: int, name: str) -> None:
            # T5: light the plain-report canvas node "running" the moment the
            # recipe starts, so a single-report run shows live "underway" feedback
            # (cyan glow + message) instead of a static dim node until completion.
            # step_id MUST equal the report node id == the recipe NAME
            # (build_canvas_nodes §4.2) — the same key the on_recipe_complete
            # ``progress.recipe`` signal later flips to "done".  Recorded via
            # _emit_step so terminal-mode replay (/run/{id}) shows it too.
            _emit_step(
                run_id,
                queue,
                loop,
                step_index=idx_started,
                step_id=name,
                state="running",
                message=f"running {name}",
            )

        # Pass-4 compound section hooks (used only when ``is_compound``). The
        # engine fires these once per compound child (non-axis ``_process_compound``);
        # they emit the per-section ``step`` events that light the canvas child
        # nodes + bump the real ``n/num_children`` progress.  ``step_id`` MUST be
        # ``slug(name)`` to match the child node id ``build_canvas_nodes`` produced
        # (the node-id ↔ step-id invariant — a mismatch silently breaks lighting).
        _sections_done = 0

        def _on_section_start(idx: int, name: str) -> None:
            sid = slug(name)
            _emit_step(run_id, queue, loop, step_index=idx, step_id=sid, state="queued")
            _emit_step(
                run_id,
                queue,
                loop,
                step_index=idx,
                step_id=sid,
                state="running",
                message=f"running {name}",
            )

        def _on_section_complete(idx: int, name: str, ok: bool) -> None:
            nonlocal _sections_done
            sid = slug(name)
            _emit_step(
                run_id,
                queue,
                loop,
                step_index=idx,
                step_id=sid,
                state="done" if ok else "error",
                message=("" if ok else f"{name} failed"),
            )
            _sections_done += 1
            _emit_workflow_progress(
                run_id, queue, loop, _sections_done, compound_total or 0
            )

        # SP3: build the deployment context (context_file + product_type/etc.)
        # and pass it to the engine — without this, context_file and SP1's
        # deployment fields never reach AI prompts on the web. Shared with the CLI.
        from fs_report.deployment_context import build_deployment_context

        deployment_ctx = build_deployment_context(config)
        engine = ReportEngine(
            config,
            cancel_event=cancel_event,
            # For a compound, suppress the coarse outer per-recipe tick — the
            # section hooks are the SOLE progress source (spec §5.3).
            on_recipe_complete=(None if is_compound else _on_recipe_done),
            on_recipe_start=(None if is_compound else _on_recipe_start),
            on_section_start=(_on_section_start if is_compound else None),
            on_section_complete=(_on_section_complete if is_compound else None),
            deployment_context=deployment_ctx,
        )
        engine.recipe_loader.recipe_filter = [name.lower() for name in recipe_names]

        # Initial coarse ``progress``.  For a compound, the section hook
        # (``_emit_workflow_progress``) is the only progress writer that bumps
        # completion — but emit an initial ``0/num_children`` here so the
        # monitor shows real 0/N immediately (not an indeterminate 1/1) before
        # the first section fires.  The FINAL coarse suppression stays as-is.
        if is_compound:
            _emit_workflow_progress(run_id, queue, loop, 0, compound_total or 0)
        else:
            _runs[run_id]["progress"] = {"completed": 0, "total": total, "recipe": ""}
            _record_canvas_event(
                run_id,
                queue,
                loop,
                "progress",
                json.dumps({"completed": 0, "total": total}),
            )

        with _stderr_lock:
            old_stderr = sys.stderr
            sys.stderr = captured_stderr
            try:
                run_result = engine.run()
                success = run_result.success
            finally:
                sys.stderr = old_stderr

        stderr_output = captured_stderr.getvalue().strip()
        if stderr_output:
            for line in stderr_output.splitlines():
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {
                        "event": "log",
                        "data": json.dumps({"level": "info", "message": line}),
                    },
                )

        # Suppress this function's own coarse FINAL ``progress`` for a compound —
        # the section hook already drove progress to ``num_children/num_children``;
        # a ``total/total`` here would clobber it with a misleading 1/1 (spec §5.3).
        if not is_compound:
            _runs[run_id]["progress"] = {
                "completed": total,
                "total": total,
                "recipe": "",
            }
            _record_canvas_event(
                run_id,
                queue,
                loop,
                "progress",
                json.dumps({"completed": total, "total": total}),
            )

        status = "success" if success else "error"
        # Surface the engine's actionable error (e.g. "child 'Remediation
        # Package' requires --project") instead of the generic fallback — applies
        # to ALL kinds (spec §5.3/§6.6).
        error_msg = (
            "" if success else (run_result.error_message or "Report generation failed")
        )
        _runs[run_id]["result"] = status

        # Collect HTML report paths relative to the BASE output dir for direct linking.
        # run_output is a subdir of output_dir, so relative paths will be
        # runs/<ts>_<run_id>/<recipe>/<file> — these resolve via /output/{path:path}.
        output_dir_abs = Path(output_dir).expanduser().resolve()
        html_files = _collect_html_files(engine.generated_files, output_dir_abs)

        # Store primary report URL on the run record so the monitor can link to it.
        # Only set report_url when the run's output dir equals the app-state served
        # output dir.  If an output_dir override points to a different path the
        # /output/{path} route cannot serve those files and the link would 404.
        served_output_dir = (
            Path(state_data.get("output_dir", "./output")).expanduser().resolve()
        )
        run_output_dir = output_dir_abs  # already resolved above
        output_dir_matches = (
            "output_dir" not in overrides or run_output_dir == served_output_dir
        )
        if success and html_files and output_dir_matches:
            _runs[run_id]["report_url"] = _output_url(html_files[0])

        # Record successful run in history DB
        history_run_id = ""
        if success and engine.generated_files:
            try:
                from fs_report.report_history import append_run

                run_output_abs = Path(run_output).resolve()
                # B12 #3: a compound/comparison bundle records ONE combined
                # deliverable — tag its files with the bundle recipe (recipe_names
                # is the single bundle name here) so Report History groups +
                # categorizes it as the bundle, not its child sections.
                history_files = _build_history_files(
                    engine.generated_files,
                    output_dir_abs,
                    run_output_abs,
                    bundle_recipe=(recipe_names[0] if is_compound else None),
                )
                if not history_files:
                    raise ValueError("No files to record")
                scope_dict = {
                    k: effective.get(k)
                    for k in (
                        "project_filter",
                        "folder_filter",
                        "version_filter",
                        "period",
                    )
                    if effective.get(k)
                }
                if engine.resolved_project_name:
                    scope_dict["project_name"] = engine.resolved_project_name
                history_run_id = append_run(
                    output_dir=str(output_dir_abs),
                    domain=effective.get("domain", ""),
                    recipes=recipe_names,
                    scope=scope_dict,
                    files=history_files,
                    log_file=_runs[run_id].get("log_file", ""),
                )
            except Exception:
                logger.warning("Failed to record run in history", exc_info=True)

        # ── SP2: post-report VEX auto-apply ──────────────────────────
        # The engine does NOT apply VEX; orchestrate it here (mirrors the CLI
        # post-report block). Only when the report SUCCEEDED and the effective
        # config enables autotriage. dry_run -> preview (no writes); the user
        # commits later via the apply-for-real endpoint.
        vex_done: dict[str, Any] = {}
        if success and effective.get("autotriage"):
            try:
                from fs_report.vex_apply_support import (
                    apply_vex_from_run,
                    summarize_apply_result,
                )

                _filter = _split_status_list(effective.get("autotriage_status"))
                _override = bool(effective.get("vex_override", False))
                result, recs_path = apply_vex_from_run(
                    domain=domain,
                    auth_token=token,
                    generated_files=engine.generated_files,
                    dry_run=dry_run,
                    vex_override=_override,
                    filter_statuses=_filter,
                )
                if result is not None and recs_path is not None:
                    _runs[run_id]["vex_apply"] = {
                        "state": "preview" if dry_run else "applied",
                        "recs_path": recs_path,
                        "domain": domain,
                        "vex_override": _override,
                        "autotriage_status": _filter,
                        "summary": summarize_apply_result(result),
                    }
                    vex_done = (
                        {"vex_preview": True} if dry_run else {"vex_applied": True}
                    )
            except Exception:
                logger.warning(
                    "VEX auto-apply failed (report already generated)", exc_info=True
                )
                _runs[run_id]["vex_apply"] = {"state": "error"}
                vex_done = {"vex_error": True}

        log_file = _runs[run_id].get("log_file", "")
        # Servable combined-HTML URL for the deliverable. Computed payload-local
        # (does NOT touch the record's report_url set above): the URL is servable
        # IFF there are html_files AND the run's output dir matches the served
        # root.  html_files exist on a partial bundle too (any_failed), so this
        # is set for both a successful and a partial deliverable; None when the
        # output dir is overridden off the served root (the /output route can't
        # serve it → no 404) or there are no files (spec — fix ①).
        deliverable_url = (
            _output_url(html_files[0]) if (html_files and output_dir_matches) else None
        )
        done_payload = {
            "status": status,
            "error": error_msg,
            "files": html_files,
            "report_url": deliverable_url,
            "history_run_id": history_run_id,
            "log_file": log_file,
            **vex_done,
        }
        # Terminal ``done`` through the recorder so the persisted ``events``
        # carry the deliverable url + files for terminal-mode re-render (§4.1).
        _record_canvas_event(run_id, queue, loop, "done", json.dumps(done_payload))

    except ReportCancelled:
        _runs[run_id]["result"] = "cancelled"
        _record_canvas_event(run_id, queue, loop, "done", '{"status":"cancelled"}')
    except SystemExit:
        _runs[run_id]["result"] = "error"
        _record_canvas_event(
            run_id,
            queue,
            loop,
            "done",
            '{"status":"error","error":"Configuration error"}',
        )
    except Exception as e:
        _runs[run_id]["result"] = "error"
        _record_canvas_event(
            run_id,
            queue,
            loop,
            "done",
            json.dumps({"status": "error", "error": str(e)}),
        )
    finally:
        root_logger.removeHandler(handler)
        if file_handler is not None:
            root_logger.removeHandler(file_handler)
            file_handler.close()
        root_logger.setLevel(old_level)
        _runs[run_id]["status"] = "completed"
        # Persist the run summary so its final canvas re-renders forever — AFTER
        # the terminal ``done`` (so ``events`` holds it, incl. the early-failure
        # ``return`` path) and BEFORE eviction (so a run evicted in its own
        # finally is already on disk) — spec §4.3 / §10.
        _persist_run_summary(run_id)
        # Evict again here so sessions that finish many runs without starting
        # new ones don't accumulate stale completed entries indefinitely.
        _evict_old_runs()


# ───────────────────────────── Workflow run (Pass 3) ─────────────────────────
#
# `_execute_workflow` is the sequential workflow executor.  It shares
# `_execute_run`'s queue / SSELogHandler / cancel_event / per-run output-dir
# machinery, but runs ONE recipe per step (a per-step config) rather than the
# multi-recipe shared-config path of `_execute_run`.  MCP-tool steps are never
# executed locally — they emit a `skipped` step event (reason=export_only).

# Global-block keys that are engine run-config inputs.  `start` and `end` are
# included — they are real engine keys (SP1) that flow through `_build_engine_config`
# just like `period`.  A step override that sets `start`+`end` will clear the
# global `period` (and vice-versa) via `merge_with_period_range_clearing` in
# `_effective_step_config`.  `period` IS included (it is an engine key).
_WORKFLOW_GLOBAL_ENGINE_KEYS: tuple[str, ...] = (
    "project_filter",
    # Folder targeting (design §6): a workflow GLOBAL folder scope (folder ID)
    # is an engine run-config input, threaded through _build_engine_config like
    # project_filter. Step-override precedence (project wins) is applied in
    # _effective_step_config so a step can never carry both.
    "folder_filter",
    "version_filter",
    "period",
    "start",
    "end",
    "ai",
    "ai_depth",
    "cache_ttl",
    # SP3: a workflow GLOBAL scoring/context file applies to all steps.
    "scoring_file",
    "context_file",
)

# Override keys that are workflow-only specials (consumed by the executor loop,
# NOT passed to the engine config).
_WORKFLOW_SPECIAL_OVERRIDE_KEYS: frozenset[str] = frozenset({"error_policy"})

# Workflow effective-config keys that must be COERCED from their (possibly
# string) override/global values to a typed bool/int — the single-run path
# coerces these in ``start_run`` (str→bool / str→int), but a workflow's
# ``overrides`` (reachable via the inline ``{model}`` run path or a hand-authored
# saved workflow) are raw, so an override like ``{"ai": "false"}`` would reach
# ``bool("false")`` → True without this.  Mirrors ``start_run``'s coercion.
_WORKFLOW_BOOL_KEYS: frozenset[str] = frozenset(
    {
        "ai",
        "ai_prompts",
        "overwrite",
        "current_version_only",
        "open_only",
        "detailed",
        "standalone",
        "vex_override",
        # B7 (#10B): the destructive FP autotriage opt-in MUST coerce str→bool so
        # a hand-authored / inline ``"autotriage": "false"`` is False, not truthy
        # — else a string false would trigger an unintended VEX write.
        "autotriage",
    }
)
_WORKFLOW_INT_KEYS: frozenset[str] = frozenset({"top", "triage"})


def _coerce_workflow_value(key: str, value: Any) -> Any:
    """Coerce a workflow effective-config ``value`` to its typed form.

    Same semantics as ``start_run``'s form coercion: bool keys treat the
    strings ``"true"/"on"/"1"/"yes"`` (case-insensitive) as True (so a string
    ``"false"``/``"0"`` becomes False, not the truthy ``bool("false")``); int
    keys parse via ``int()`` (a non-numeric string is left unchanged so the
    engine's own defaulting / validation applies).  Non-coerced keys pass
    through unchanged.
    """
    if key in _WORKFLOW_BOOL_KEYS:
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "on", "1", "yes")
    if key in _WORKFLOW_INT_KEYS:
        if isinstance(value, bool):
            return value
        try:
            return int(str(value))
        except (ValueError, TypeError):
            return value
    return value


class WorkflowPreflightError(ValueError):
    """A runnable workflow step failed the server-side preflight (spec §10).

    Carries ``step_id`` / ``step_index`` so the run endpoint can return a 400
    that names the offending step.
    """

    def __init__(self, step_id: str, step_index: int, message: str) -> None:
        self.step_id = step_id
        self.step_index = step_index
        super().__init__(message)


def _recipe_meta() -> dict[str, dict[str, bool]]:
    """Map lowercase recipe name → its requirement flags.

    Flags: ``requires_project`` / ``requires_project_or_folder`` /
    ``requires_cve``.  Guarded — a recipe-load failure degrades to ``{}`` so a
    broken corpus doesn't crash preflight (the engine's own gate is the
    backstop).  Loaded inline to avoid an import cycle with the recipe loader.
    """
    try:
        from fs_report.recipe_loader import RecipeLoader

        recipes = RecipeLoader(use_bundled=True, scan_user_recipes=True).load_recipes()
    except Exception:
        return {}
    out: dict[str, dict[str, bool]] = {}
    for r in recipes:
        out[r.name.lower()] = {
            "requires_project": bool(getattr(r, "requires_project", False)),
            "requires_project_or_folder": bool(
                getattr(r, "requires_project_or_folder", False)
            ),
            "requires_cve": bool(getattr(r, "requires_cve", False)),
            "requires_component": bool(getattr(r, "requires_component", False)),
        }
    return out


def _effective_step_config(
    model: dict[str, Any], step: dict[str, Any]
) -> dict[str, Any]:
    """Return the effective engine-config dict for a recipe ``step``.

    Merges ``global`` engine keys ← step ``overrides`` using
    ``merge_with_period_range_clearing`` so that when a step override sets
    ``start``+``end`` the global ``period`` is dropped (and vice-versa).
    This is NOT ``compute_prerun_fields`` (that computes UI visibility flags
    only — spec §6.2).  ``custom_range`` and the workflow-special
    ``error_policy`` are NOT engine keys and are excluded.
    """
    g = model.get("global", {}) or {}
    # Build the global-derived dict (coerced, non-empty values only).
    global_effective: dict[str, Any] = {}
    for k in _WORKFLOW_GLOBAL_ENGINE_KEYS:
        if k in g and g[k] is not None and g[k] != "":
            global_effective[k] = _coerce_workflow_value(k, g[k])
    # Build the step-override dict (coerced, non-special, non-empty values only).
    overrides = step.get("overrides", {}) or {}
    step_overrides_effective: dict[str, Any] = {}
    for k, v in overrides.items():
        if k in _WORKFLOW_SPECIAL_OVERRIDE_KEYS:
            continue
        if v is None or v == "":
            continue
        step_overrides_effective[k] = _coerce_workflow_value(k, v)
    # C1: when the USER explicitly set the Global-Properties date mode, that
    # choice OVERRIDES a step's card period. Read the touched flags off the
    # GLOBAL block (they are NOT engine keys — read-and-strip), and when one is
    # set, drop the step's date keys so the step contributes no date mode and the
    # global period/range flows through unchanged via the merge below. Untouched
    # ⇒ today's step-wins behavior. The flags themselves never enter
    # ``effective`` (they were never copied into global_effective —
    # _WORKFLOW_GLOBAL_ENGINE_KEYS omits them — and we never read them into the
    # step dict).
    period_touched = _coerce_touched_flag(g.get("period_touched"))
    # range_touched only overrides a step's date keys when BOTH global bounds are
    # present — a hand-edited range_touched:true with one bound can't force an
    # incomplete range (the frontend only sets it with both). Otherwise fall back
    # to today's step-wins so a partial range never silently drops the step date.
    range_touched = _coerce_touched_flag(g.get("range_touched")) and bool(
        str(g.get("start") or "").strip() and str(g.get("end") or "").strip()
    )
    if period_touched or range_touched:
        for _date_key in ("period", "start", "end"):
            step_overrides_effective.pop(_date_key, None)
    # Combine via merge_with_period_range_clearing so start/end ↔ period
    # conflicts are resolved (whichever side sets both clears the other mode).
    effective = merge_with_period_range_clearing(
        global_effective, step_overrides_effective
    )
    # Step folder overrides an INHERITED global project (Finding 5). When the
    # step's OWN override explicitly sets ``folder_filter`` and does NOT set its
    # own ``project_filter``, the user retargeted that step to a FOLDER — so the
    # only ``project_filter`` in ``effective`` is the INHERITED global one. Left
    # in place, the project-wins precedence below would silently drop the step's
    # folder and run the global project instead. Clear the inherited global
    # project for this step so folder-wins applies. (An empty project OVERRIDE is
    # discarded above before the merge, so this is the only place the intent is
    # recoverable.) The normal rule stays intact when the step sets its OWN
    # project: ``step_sets_project`` is True, so we don't clear, and project-wins
    # still drops the folder.
    step_sets_folder = bool(
        str(step_overrides_effective.get("folder_filter") or "").strip()
    )
    step_sets_project = bool(
        str(step_overrides_effective.get("project_filter") or "").strip()
    )
    step_sets_version = bool(
        str(step_overrides_effective.get("version_filter") or "").strip()
    )
    if step_sets_folder and not step_sets_project:
        effective.pop("project_filter", None)
        # A version is project-specific; a folder-only step has no project to
        # version. The inherited global ``version_filter`` would otherwise leave
        # the step at folder + a stale version, which the engine rejects (a
        # version requires a project). Clear it alongside the inherited project
        # so a folder-only step runs as folder-only. (A step setting its OWN
        # project keeps ``step_sets_project`` True, so we don't reach here and
        # its inherited/own version is preserved.)
        effective.pop("version_filter", None)
    # A version ID is scoped to ONE project (round-5). When a step retargets to
    # its OWN ``project_filter`` (different provenance from the inherited global
    # version), that inherited ``version_filter`` belongs to the GLOBAL project,
    # not the step's — running ``StepProj`` + a version ID of ``GlobalProj`` is
    # an invalid pairing the engine rejects. Drop it UNLESS the step supplies
    # its OWN version (same provenance as its project → valid pair). The general
    # "no project ⇒ no version" rule in ``_build_engine_config`` can't catch this
    # (a project IS present), so the provenance-aware drop must happen here.
    if step_sets_project and not step_sets_version:
        effective.pop("version_filter", None)
    # Folder-targeting step-override precedence — project wins (design §6,
    # round-2). When the step's EFFECTIVE config (global ← override) carries a
    # specific project the folder was only a UI filter and must NOT travel with
    # it (the engine would otherwise enforce the stricter
    # project-must-be-in-folder intersection). Drop it HERE — the workflow step's
    # config chokepoint — mirroring _build_engine_config so a step can never
    # carry both filters into the engine OR be read with both by the preflight.
    # Folder-only (no effective project) keeps its folder_filter.
    if str(effective.get("project_filter") or "").strip():
        effective.pop("folder_filter", None)
    return effective


def _folder_in_list(folder_input: str, folders: list[dict[str, Any]]) -> bool:
    """True iff ``folder_input`` resolves to a folder by ID or name.

    Mirrors the engine's ``_resolve_folder`` matching (exact ID, then
    case-insensitive name) so preflight rejects exactly what the engine would
    fail to resolve — no new API path, just the same shape over an already
    fetched folders list.
    """
    target = folder_input.strip()
    if not target:
        return False
    low = target.lower()
    for f in folders:
        if str(f.get("id", "")) == target:
            return True
        if str(f.get("name", "") or "").lower() == low:
            return True
    return False


def workflow_preflight(model: dict[str, Any], state: WebAppState | None = None) -> None:
    """Validate EVERY runnable (recipe) step against its EFFECTIVE config.

    Authoritative server-side preflight (spec §10): for each ``runnable_locally``
    recipe step, the merged effective config (``global`` ← ``overrides``) must
    satisfy the recipe's ``scope_req`` (a ``requires_project`` recipe needs an
    effective ``project_filter``; ``requires_project_or_folder`` needs project
    OR folder) and each requirement predicate (a ``requires_cve`` recipe needs
    an effective ``cve_filter``).

    Folder resolution (Finding 4): when a step's effective config targets a
    ``folder_filter`` AND ``state`` supplies domain/token, the folder is resolved
    by ID or name (reusing ``shell_context._fetch_folders`` + the engine's
    ID/name matching) so a typo'd / stale folder fails preflight with an
    actionable error instead of passing here and aborting later in the engine.
    Best-effort: if the folders list can't be confirmed (no creds / transient
    fetch failure) the resolution check is skipped and the engine gate is the
    backstop — never blocking on a miss we couldn't verify.

    Computed over the merged effective config — NOT a ``needs_setup(state, …)``
    call (that reads ``WebAppState.recipe_overrides``, the wrong source for a
    workflow).  Raises :class:`WorkflowPreflightError` on the first unmet step.
    """
    meta = _recipe_meta()

    # Fetch the folders list ONCE for the whole preflight (best-effort, memoized)
    # so a multi-step workflow doesn't re-hit the API per step.  ``folders_ok``
    # gates the resolution check: only validate folder existence when the fetch
    # SUCCEEDED — a transient/unconfigured miss skips the check (engine backstop).
    folders_ok = False
    folders: list[dict[str, Any]] = []
    if state is not None and state.domain and state.token:
        from fs_report.web.shell_context import _fetch_folders

        try:
            folders_ok, folders = _fetch_folders(state.domain, state.token)
        except Exception:  # pragma: no cover - defensive; _fetch_folders is guarded
            folders_ok, folders = False, []

    # C2 — target-aware prompt: distinguish two distinct "no target" cases so the
    # per-step failure below reads as an actionable prompt instead of a bare
    # "requires a project":
    #   * GENERAL (``target_agnostic``): the workflow has no saved target BY
    #     DESIGN — the target is chosen per run, so prompt to "pick a target for
    #     this run". Coerced via the shared helper so a hand-edited string
    #     ``"false"`` is correctly NOT general.
    #   * TARGET-BOUND but with no global scope set: the workflow is meant to carry
    #     a baked scope that simply isn't set — prompt to "set the workflow's
    #     global scope" (NOT conflated with general).
    _g = model.get("global", {}) or {}
    _agnostic = _coerce_touched_flag(_g.get("target_agnostic"))
    _no_global_target = (
        not str(_g.get("project_filter") or "").strip()
        and not str(_g.get("folder_filter") or "").strip()
    )

    for i, step in enumerate(model.get("steps", [])):
        if step.get("kind") != "recipe" or not step.get("runnable_locally"):
            continue
        ref = str(step.get("ref", ""))
        flags = meta.get(ref.lower())
        if flags is None:
            # Recipe metadata unavailable — let the engine gate be the backstop.
            continue
        eff = _effective_step_config(model, step)
        project = str(eff.get("project_filter") or "").strip()
        # Folder targeting (design §6): ``folder_filter`` is now a real workflow
        # global/override engine key, so ``eff`` carries the folder scope (folder
        # ID) when one is targeted. _effective_step_config already applies the
        # project-wins precedence (folder dropped when the step's effective
        # project is set), so a folder-only step satisfies
        # requires_project_or_folder while a step with a project satisfies it via
        # the project — never both.
        folder = str(eff.get("folder_filter") or "").strip()
        step_id = str(step.get("id", f"s{i + 1}"))

        if flags["requires_project"] and not project:
            # A PROJECT is required — a folder can NOT satisfy this step, so never
            # suggest "project or folder" here (that would mislead).
            if _agnostic:
                raise WorkflowPreflightError(
                    step_id,
                    i,
                    f"Step {step_id!r} ({ref}) needs a project — pick a target "
                    "(a project) for this run.",
                )
            if _no_global_target:
                raise WorkflowPreflightError(
                    step_id,
                    i,
                    f"Step {step_id!r} ({ref}) needs a project — set the "
                    "workflow's global scope to a project.",
                )
            raise WorkflowPreflightError(
                step_id,
                i,
                f"Step {step_id!r} ({ref}) requires a project — set the step's "
                "project or the global project.",
            )
        if flags["requires_project_or_folder"] and not project and not folder:
            # A folder CAN satisfy this step, so "project or folder" is accurate.
            if _agnostic:
                raise WorkflowPreflightError(
                    step_id,
                    i,
                    f"Step {step_id!r} ({ref}) needs a project or folder — pick "
                    "a target for this run.",
                )
            if _no_global_target:
                raise WorkflowPreflightError(
                    step_id,
                    i,
                    f"Step {step_id!r} ({ref}) needs a project or folder — set "
                    "the workflow's global scope.",
                )
            raise WorkflowPreflightError(
                step_id,
                i,
                f"Step {step_id!r} ({ref}) requires a project or folder.",
            )
        # Folder resolution (Finding 4): a step targeting a folder must resolve
        # it (by ID or name).  Only enforce when we actually confirmed the
        # folders list (folders_ok) — otherwise the engine gate is the backstop.
        if folder and folders_ok and not _folder_in_list(folder, folders):
            raise WorkflowPreflightError(
                step_id,
                i,
                f"Step {step_id!r} ({ref}) targets folder {folder!r}, which "
                "does not exist — check the folder ID or name.",
            )
        if flags["requires_cve"] and not str(eff.get("cve_filter") or "").strip():
            raise WorkflowPreflightError(
                step_id,
                i,
                f"Step {step_id!r} ({ref}) requires CVE IDs (cve_filter).",
            )
        if (
            flags.get("requires_component")
            and not str(eff.get("component_filter") or "").strip()
        ):
            raise WorkflowPreflightError(
                step_id,
                i,
                f"Step {step_id!r} ({ref}) requires a component (component_filter).",
            )


class CompoundPreflightError(ValueError):
    """A compound run failed the server-side preflight (parallel to §10).

    The compound analog of :class:`WorkflowPreflightError`. A compound is one
    recipe-doc that fans N child sections into one deliverable, so the offending
    "step" is a CHILD SECTION. ``step_id`` / ``step_index`` name that section so
    the run endpoint can return the same 400 shape the workflow preflight uses
    (``{"error", "step_id", "step_index"}``) — one error contract for both
    Builder run paths.
    """

    def __init__(self, step_id: str, step_index: int, message: str) -> None:
        self.step_id = step_id
        self.step_index = step_index
        super().__init__(message)


def compound_preflight(
    compound: "CompoundRecipe",
    effective: dict[str, Any],
    state: WebAppState | None = None,
) -> None:
    """Authoritative server-side preflight for a compound inline run.

    The compound analog of :func:`workflow_preflight` (spec §10): a compound is
    one recipe-doc whose child SECTIONS each carry their own dispatch
    requirements. At dispatch ``ReportEngine._process_compound`` enforces, per
    child, ``requires_project`` / ``requires_project_or_folder`` /
    ``requires_cve`` / ``requires_component`` against the section's EFFECTIVE
    scope (run-level ▸ section override). This preflight mirrors that check
    server-side so a target-bound compound launched with no resolvable target
    fails fast with an actionable 400 instead of a mid-run engine abort.

    Effective target (parallel to the workflow): the run's effective scope is
    ``effective`` — the form/state config (``state ∪ overrides``) the run path
    already computed — OVERLAID on the compound's saved ``global`` block scope
    (``compound.global_``), exactly as the workflow effective target is the
    model ``global`` scope. ``cve_filter`` / ``component_filter`` are NOT
    section-overridable (not in :data:`COMPOUND_OVERRIDE_WHITELIST`), so those
    requirements read the run-level effective config only — matching the engine.

    Target-agnostic distinction (product decision 2026-06-16; cf. ``565941c``
    scope-pill tooltip): the per-child target-requirement gate runs for GENERAL
    and TARGET-BOUND compounds ALIKE — mirroring the workflow, which rejects an
    unmet requirement fail-fast regardless of ``target_agnostic``. A general
    compound containing a section that ``requires_*`` a target, launched with no
    resolvable runtime target, is REJECTED here (not allowed through to fail late
    at the engine). ``target_agnostic`` changes ONLY the rejection WORDING:
      * a GENERAL compound (``compound.global_['target_agnostic']`` truthy) picks
        its target per run (inline-run form POST), so the message prompts to
        "pick a target … for this run" (the workflow's general wording, adapted);
      * a TARGET-BOUND compound's saved global scope is simply unset, so the
        message prompts to "set the compound's global scope".
    A GENERAL compound whose sections need NO target still RUNS with no target
    (no requirement ⇒ no rejection). ``target_agnostic`` is coerced via the
    shared :func:`_coerce_touched_flag` so a hand-edited ``"false"`` is correctly
    NOT general. The CVE / component required-filter gates are orthogonal to the
    target and apply regardless (mirroring the workflow, which enforces
    ``requires_cve`` / ``requires_component`` unconditionally).

    Folder resolution (parallel to Finding 4): when a compound's effective scope
    targets a ``folder_filter`` AND ``state`` supplies domain/token, the folder is
    resolved by ID or name (best-effort) so a typo'd / stale folder fails here
    with an actionable error instead of aborting later in the engine — for general
    and bound alike (mirrors the workflow's unconditional folder check). Skipped
    only when the folders list can't be confirmed (no creds / transient fetch
    failure) — the engine gate is the backstop.

    Raises :class:`CompoundPreflightError` on the first unsatisfied child.
    """
    from fs_report.compound_overrides import effective_child_config
    from fs_report.recipe_requirements import recipe_requirements
    from fs_report.slug import slug

    # Axis (meta-compare) compounds resolve BOTH scopes via the axis, not the
    # single-scope requires_* gates — the engine skips these checks for them
    # (report_engine.py:_process_compound axis branch). Mirror that: no
    # single-target preflight applies to an axis compound.
    if compound.axis is not None:
        return

    # ── Saved compound global ▸ overlaid by the run's form/state scope ───────
    # The saved authored target lives in ``compound.global_`` (the workflow's
    # ``model['global']`` analog); the run can overlay a form/state scope via
    # ``effective``. The effective target is the OVERLAY: a form scope wins, else
    # the saved global scope stands — the same precedence the workflow uses
    # (global scope ▸ untouched ⇒ no target).
    _g = compound.global_ or {}
    _eff_project = str(
        effective.get("project_filter") or _g.get("project_filter") or ""
    ).strip()
    _eff_folder = str(
        effective.get("folder_filter") or _g.get("folder_filter") or ""
    ).strip()

    # GENERAL vs TARGET-BOUND-but-unset — the requirement gate runs for BOTH
    # (product decision 2026-06-16); ``_agnostic`` only swaps the rejection
    # WORDING (do NOT conflate — distinct prompts):
    #   * GENERAL (``target_agnostic``): the target is chosen per run (form POST),
    #     so an unmet requirement prompts to "pick a target … for this run".
    #   * TARGET-BOUND with no resolvable target: the saved global scope is unset,
    #     so an unmet requirement prompts to "set the compound's global scope".
    # Coerced via the shared helper so a hand-edited string ``"false"`` is
    # correctly NOT general.
    _agnostic = _coerce_touched_flag(_g.get("target_agnostic"))

    # Per-child requirements, evaluated against each section's EFFECTIVE scope —
    # exactly as ``_process_compound`` does (the bundle's effective requirement
    # is the OR-union of the children's, but a section override can satisfy its
    # OWN scope requirement, so check per child rather than only the union).
    # Resolve children through the shared slug-keyed corpus index so the answer
    # can't diverge from dispatch; an unresolvable child is skipped (engine gate
    # is the backstop). ``recipe_requirements`` also applies the name-based rules
    # (e.g. "Remediation Package").
    recipes_index = _load_canvas_recipes_index()

    # Fetch the folders list ONCE (best-effort, memoized) for the folder
    # resolution check below — only enforce existence when the fetch SUCCEEDED.
    folders_ok = False
    folders: list[dict[str, Any]] = []
    if state is not None and state.domain and state.token:
        from fs_report.web.shell_context import _fetch_folders

        try:
            folders_ok, folders = _fetch_folders(state.domain, state.token)
        except Exception:  # pragma: no cover - defensive; _fetch_folders guarded
            folders_ok, folders = False, []

    for i, section in enumerate(compound.sections):
        ref = str(getattr(section, "recipe", "") or "")
        child = recipes_index.get(slug(ref)) if ref else None
        if child is None:
            # Unresolvable child — let the engine's defensive resolve fail it.
            continue
        reqs = recipe_requirements(child)

        # Section-scope overlay: a section that retargets project/folder
        # satisfies its OWN scope requirement even when the bundle carries no
        # run-level target (mirrors _process_compound's _eff_project/_folder).
        _sec_ov = effective_child_config({}, getattr(section, "overrides", None))
        sec_project = str(_sec_ov.get("project_filter") or _eff_project or "").strip()
        sec_folder = str(_sec_ov.get("folder_filter") or _eff_folder or "").strip()
        step_id = str(ref or f"section{i + 1}")

        # Target gates (project / project-or-folder / folder resolution) apply to
        # GENERAL and TARGET-BOUND compounds ALIKE — mirroring the workflow, which
        # rejects an unmet requirement fail-fast regardless of target_agnostic
        # (product decision 2026-06-16). ``target_agnostic`` changes ONLY the
        # rejection WORDING, not whether the gate runs:
        #   * GENERAL → the runtime target is chosen per run (form POST), so prompt
        #     to "pick a target … for this run" (the workflow's general wording,
        #     adapted compound→section);
        #   * TARGET-BOUND → the saved global scope is simply unset, so prompt to
        #     "set the compound's global scope".
        # A GENERAL compound whose sections need NO target still runs with no
        # target (no requirement ⇒ no rejection). A section that DID retarget its
        # own scope still satisfies the gate; the engine re-checks at dispatch.
        if reqs.requires_project and not sec_project:
            # A PROJECT is required — a folder can NOT satisfy this, so never
            # suggest "project or folder" here (that would mislead).
            if _agnostic:
                raise CompoundPreflightError(
                    step_id,
                    i,
                    f"Section {step_id!r} ({ref}) needs a project — pick a "
                    "target (a project) for this run.",
                )
            raise CompoundPreflightError(
                step_id,
                i,
                f"Section {step_id!r} ({ref}) needs a project — set the "
                "compound's global scope to a project.",
            )
        if reqs.requires_project_or_folder and not sec_project and not sec_folder:
            # A folder CAN satisfy this, so "project or folder" is accurate.
            if _agnostic:
                raise CompoundPreflightError(
                    step_id,
                    i,
                    f"Section {step_id!r} ({ref}) needs a project or folder — "
                    "pick a target for this run.",
                )
            raise CompoundPreflightError(
                step_id,
                i,
                f"Section {step_id!r} ({ref}) needs a project or folder — "
                "set the compound's global scope.",
            )
        # Folder resolution (Finding 4 parallel): the effective folder must
        # resolve (by ID or name). Only enforce when the folders list was actually
        # confirmed — otherwise the engine gate is the backstop. Applies to general
        # and bound alike (mirrors the workflow's unconditional folder check).
        if (
            sec_folder
            and not sec_project
            and folders_ok
            and not _folder_in_list(sec_folder, folders)
        ):
            raise CompoundPreflightError(
                step_id,
                i,
                f"Section {step_id!r} ({ref}) targets folder {sec_folder!r}, "
                "which does not exist — check the folder ID or name.",
            )
        # cve_filter / component_filter are NOT section-overridable, so read the
        # run-level effective config only (matching the engine).
        if reqs.requires_cve and not str(effective.get("cve_filter") or "").strip():
            raise CompoundPreflightError(
                step_id,
                i,
                f"Section {step_id!r} ({ref}) requires CVE IDs (cve_filter).",
            )
        if (
            reqs.requires_component
            and not str(effective.get("component_filter") or "").strip()
        ):
            raise CompoundPreflightError(
                step_id,
                i,
                f"Section {step_id!r} ({ref}) requires a component "
                "(component_filter).",
            )


def _folder_scope_label(folder: str, domain: str, token: str) -> str:
    """Best-effort ``folder: <name>`` label, falling back to ``folder: <id>``.

    Folder NAME in scope labels (Finding 6): the persisted scope carries the
    folder ID, but the monitor/history label reads better with the folder name.
    Resolves the name via ``shell_context._fetch_folders`` (memoized, the same
    cheap lookup the shell uses) and the engine's ID/name matching. Cosmetic and
    non-fatal: any miss (no creds / transient failure / unknown ID) falls back
    to the ID, and the function never raises.
    """
    fid = folder.strip()
    if not fid:
        return ""
    if domain and token:
        try:
            from fs_report.web.shell_context import _fetch_folders

            ok, folders = _fetch_folders(domain, token)
            if ok:
                low = fid.lower()
                for f in folders:
                    if str(f.get("id", "")) == fid:
                        name = str(f.get("name", "") or "")
                        return f"folder: {name or fid}"
                # Allow a NAME-valued scope too (defensive) → echo the name.
                for f in folders:
                    if str(f.get("name", "") or "").lower() == low:
                        return f"folder: {str(f.get('name', '') or fid)}"
        except Exception:  # pragma: no cover - defensive
            pass
    return f"folder: {fid}"


def _run_scope_label(
    effective: dict[str, Any], domain: str = "", token: str = ""
) -> str:
    """The monitor / canvas-source-node scope STRING, built from the shared
    resolver so the single-run path (``start_run``) and the workflow path
    (``_workflow_scope``) use ONE precedence (Theme 3a — no drift). Project →
    ``Name @ version``; folder → the established ``folder: <name>`` monitor idiom
    (best-effort name resolution); neither → lowercase ``portfolio`` (the
    terminal/source-node convention).

    The report-shell topbar (#15) instead consumes ``compute_effective_scope``'s
    STRUCTURED output directly (UI Title-case label + active-filter chips) — the
    PRECEDENCE is shared via the helper, the per-surface presentation differs by
    design (process monitor vs report meta).
    """
    sc = compute_effective_scope(effective)
    if sc["scope_kind"] == "project":
        version = sc["version"]
        return str(sc["label"]) + (f" @ {version}" if version else "")
    if sc["scope_kind"] == "folder":
        return _folder_scope_label(
            str(effective.get("folder_filter") or "").strip(), domain, token
        )
    return "portfolio"


def _workflow_scope(
    model: dict[str, Any], state_data: dict[str, Any] | None = None
) -> str:
    """Build the monitor/canvas scope label from the global scope.

    Folder targeting (design §6): a folder-scoped workflow renders ``folder:
    <name>`` (resolved best-effort from the folder ID — Finding 6) instead of
    "portfolio" so a folder-only run doesn't mislabel as Portfolio. Precedence is
    project-wins (matching _build_engine_config): a project (with optional
    version) takes the label; a folder-only global shows the folder; neither
    falls back to "portfolio". Mirrors the single-run scope label in
    ``start_run``.  ``state_data`` (domain/token) enables the folder-name
    resolution; without it the label falls back to ``folder: <id>``.
    """
    sd = state_data or {}
    return _run_scope_label(
        model.get("global", {}) or {},
        str(sd.get("domain", "")),
        str(sd.get("token", "")),
    )


def _step_title(step: dict[str, Any]) -> str:
    """Display title for a step row (recipe canonical name or MCP tool title)."""
    ref = str(step.get("ref", "")) or "step"
    if step.get("kind") == "mcp_tool":
        try:
            from fs_report.web.workflow_meta import get_mcp_tool

            tool = get_mcp_tool(ref)
            if tool is not None:
                return str(tool.get("title", ref))
        except Exception:
            pass
    return ref


def _load_canvas_recipes_index() -> dict[str, "Recipe"]:
    """Load the recipe corpus once and return a slug-keyed index.

    Mirrors the engine's index pattern (report_engine.py:2262):
    ``{slug(r.name): r for r in RecipeLoader(...).load_recipes()}``. Loads
    bundled + user recipes so workflow/compound refs resolve the same way the
    engine resolves them. Degrades to an empty dict on any load failure —
    :func:`build_canvas_nodes` must never raise, and an empty index still
    yields renderable (degraded) nodes.
    """
    try:
        from fs_report.recipe_loader import RecipeLoader
        from fs_report.slug import slug

        loader = RecipeLoader(use_bundled=True, scan_user_recipes=True)
        return {slug(r.name): r for r in loader.load_recipes()}
    except Exception:
        logger.warning("Failed to load recipe index for Run canvas", exc_info=True)
        return {}


def _source_node(scope: str) -> dict[str, Any]:
    """The index-0 ``source`` node prepended to every canvas.

    ``title`` is the shared scope string verbatim (lowercase ``portfolio`` /
    ``project @ version`` / ``folder: X``). The literal id ``"source"`` cannot
    collide with any real SSE ``step_id``.
    """
    return {
        "id": "source",
        "title": scope,
        "kind": "source",
        "category": "",
        "icon": "database",
        "formats": [],
        "runnable": False,
    }


def _recipe_node(
    *,
    node_id: str,
    title: str,
    recipe: "Recipe | None",
    name_for_icon: str | None,
    runnable: bool,
) -> dict[str, Any]:
    """Build a ``recipe`` node, degrading gracefully when *recipe* is None.

    Per spec §4.4, a recipe missing from the index still renders: a
    category-default (or ``file-text``) icon, ``category="Uncategorized"``, and
    empty ``formats``. Never raises.
    """
    from fs_report.web import recipe_meta

    if recipe is not None:
        category = recipe.nav_category or "Uncategorized"
        formats = [f.upper() for f in (recipe.output.formats or [])]
        # ``ai`` is not a field on the base ``Recipe`` model (it lives on the
        # application ``Config``); read defensively so a recipe that DOES carry
        # an ``ai`` flag still gets the badge while the common case never raises.
        if getattr(recipe, "ai", False):
            formats.append("AI")
        icon = recipe_meta.icon_for(name_for_icon, category)
    else:
        category = "Uncategorized"
        formats = []
        icon = recipe_meta.icon_for(name_for_icon, None)
    return {
        "id": node_id,
        "title": title,
        "kind": "recipe",
        "category": category,
        "icon": icon,
        "formats": formats,
        "runnable": runnable,
    }


def build_canvas_nodes(
    record: dict[str, Any], recipes_index: dict[str, "Recipe"]
) -> list[dict[str, Any]]:
    """Build the normalized Run-canvas node list for *record* (spec §4.2).

    Pure function: no SSE, no threads, no engine calls. Produces the node list
    the canvas template + JS render BEFORE the SSE stream arrives. Each node
    carries an ``id`` that MUST equal the SSE ``step_id`` that will light it —
    that node-id ↔ step-id invariant (spec §4.2) is the load-bearing
    correctness property:

    - **workflow** node id = ``str(step.get("id", f"s{i+1}"))`` — exactly the
      key the executor uses (``_execute_workflow``), NOT the recipe slug.
    - **compound** child node id = ``slug(child.name)`` (the RESOLVED child;
      falls back to ``slug(section.recipe)`` only when the child is absent from
      the index) — ALWAYS equal to the ``on_section_*`` hook's
      ``step_id = slug(child.name)`` even for a non-canonical section ref.
    - **plain report** node id = the recipe NAME, so the per-recipe
      ``progress.recipe`` event can match it.

    Always prepends a ``source`` node at index 0. Degrades (never raises) when a
    recipe is missing from *recipes_index* or a compound fails to resolve — the
    engine remains the real backstop.
    """
    from fs_report.models import CompoundRecipe
    from fs_report.slug import slug

    scope = str(record.get("scope", "") or "")
    nodes: list[dict[str, Any]] = [_source_node(scope)]
    kind = record.get("kind", "report")

    if kind == "workflow":
        steps = record.get("steps", []) or []
        for i, step in enumerate(steps):
            node_id = str(step.get("id", f"s{i + 1}"))
            title = _step_title(step)
            ref = str(step.get("ref", ""))
            if step.get("kind") == "recipe" and step.get("runnable_locally"):
                recipe = recipes_index.get(slug(ref))
                if recipe is not None:
                    nodes.append(
                        _recipe_node(
                            node_id=node_id,
                            title=title,
                            recipe=recipe,
                            name_for_icon=recipe.name,
                            runnable=True,
                        )
                    )
                else:
                    # Declared runnable but absent from the index — still render.
                    nodes.append(
                        _recipe_node(
                            node_id=node_id,
                            title=title,
                            recipe=None,
                            name_for_icon=ref or title,
                            runnable=False,
                        )
                    )
            elif step.get("kind") == "mcp_tool":
                from fs_report.web.workflow_meta import get_mcp_tool

                icon = "plug"
                try:
                    tool = get_mcp_tool(ref)
                    if tool is not None and tool.get("icon"):
                        icon = str(tool["icon"])
                except Exception:
                    pass
                nodes.append(
                    {
                        "id": node_id,
                        "title": title,
                        "kind": "mcp_tool",
                        "category": "",
                        "icon": icon,
                        "formats": [],
                        "runnable": False,
                    }
                )
            else:
                # Unresolvable recipe ref (kind recipe but not runnable_locally,
                # or an unknown kind) — render as a non-runnable recipe node.
                nodes.append(
                    _recipe_node(
                        node_id=node_id,
                        title=title,
                        recipe=None,
                        name_for_icon=ref or title,
                        runnable=False,
                    )
                )
        return nodes

    if kind == "compound":
        recipes = record.get("recipes", []) or []
        compound = recipes_index.get(slug(str(recipes[0]))) if recipes else None
        if isinstance(compound, CompoundRecipe):
            for section in compound.sections:
                child = recipes_index.get(slug(section.recipe))
                nodes.append(
                    _recipe_node(
                        # Use the RESOLVED child's name so the id ALWAYS equals
                        # the section hook's ``step_id = slug(child.name)`` — a
                        # non-canonical ``section.recipe`` ref (slug/alias/case)
                        # would otherwise desync the node-id ↔ step-id invariant
                        # and silently break node lighting (spec §4.2).
                        node_id=(
                            slug(child.name)
                            if child is not None
                            else slug(section.recipe)
                        ),
                        title=(child.name if child is not None else section.recipe),
                        recipe=child,
                        name_for_icon=(
                            child.name if child is not None else section.recipe
                        ),
                        # Children are sections of one file; the frontend decides
                        # clickability by kind, not this flag (spec §4.4).
                        runnable=True,
                    )
                )
            nodes.append(
                {
                    "id": "deliverable",
                    "title": compound.name,
                    "kind": "deliverable",
                    "category": compound.nav_category or "Uncategorized",
                    "icon": "file-check",
                    "formats": [f.upper() for f in (compound.output.formats or [])],
                    # Lit by the terminal ``done``, not a step event.
                    "runnable": False,
                }
            )
            return nodes
        # Degraded compound: empty recipes / not in index / not a CompoundRecipe.
        logger.warning(
            "Run canvas: compound run %r did not resolve to a CompoundRecipe; "
            "degrading to source + deliverable",
            recipes[0] if recipes else None,
        )
        nodes.append(
            {
                "id": "deliverable",
                "title": str(recipes[0]) if recipes else "Report",
                "kind": "deliverable",
                "category": "Uncategorized",
                "icon": "file-check",
                "formats": [],
                "runnable": False,
            }
        )
        return nodes

    # Plain report (default): record["recipes"] is a list of recipe NAME strings.
    for name in record.get("recipes", []) or []:
        recipe = recipes_index.get(slug(str(name)))
        # Key the node on the CANONICAL recipe name (resolved) so it matches the
        # ``progress.recipe`` events that light it — those carry ``recipe.name``
        # (the executor's ``on_recipe_complete`` emits the canonical name). A
        # non-canonical submitted token (e.g. "scan-quality" / "SCAN QUALITY")
        # would otherwise never light. Fall back to the raw token when the recipe
        # is unresolved. (R4 M3-1 — the plain-report analog of the compound
        # node-id ↔ step-id fix.)
        canonical = recipe.name if recipe is not None else str(name)
        nodes.append(
            _recipe_node(
                node_id=canonical,
                title=canonical,
                recipe=recipe,
                name_for_icon=canonical,
                runnable=True,
            )
        )
    return nodes


def _register_workflow_run(
    run_id: str,
    model: dict[str, Any],
    state_data: dict[str, Any],
    queue: RunEventHub,
    cancel_event: threading.Event,
    replay: dict[str, Any],
) -> None:
    """Register a fully monitor-compatible ``_runs`` entry for a workflow run.

    Populates EVERY field the monitor reads (``_get_active_runs_list`` /
    ``running_reports`` / ``run_progress_page``): ``status``, ``result``,
    ``recipes`` (= step TITLES — indexed unconditionally), ``scope`` (global
    project @ version), ``progress`` ({completed, total}), ``report_url`` (None
    until done), ``started_at``, ``buffer``, ``cancel_event``, ``log_file`` —
    plus the workflow extras ``kind`` / ``workflow_name`` (both consumed by the
    monitor: the Running Reports panel renders a workflow row by name + a segment
    sparkline) and ``steps`` (not read by the monitor). A workflow renders as ONE
    monitor row.

    ``progress.total`` is the TOTAL step count (so the row's ``recipes`` label
    and the ``completed/total`` ratio agree — the monitor renders the workflow
    as one run of N steps).  ``completed`` starts at **0** and the executor bumps
    it as EACH step (runnable or skipped) reaches a terminal state, so the ratio
    grows 0/N → N/N naturally (M1-4 + M3-1 — no pre-counting of skipped steps as
    done up front, which would show e.g. 3/5 before any recipe runs).
    """
    steps = model.get("steps", [])
    total = len(steps)
    _wf_index = _load_canvas_recipes_index()
    with _RUNS_LOCK:
        _runs[run_id] = {
            "status": "running",
            "result": None,
            "recipes": [_step_title(s) for s in steps],
            "scope": _workflow_scope(model, state_data),
            "progress": {"completed": 0, "total": total},
            "report_url": None,
            "started_at": time.time(),
            "queue": queue,
            "cancel_event": cancel_event,
            "log_file": "",
            # Workflow extras. ``kind`` + ``workflow_name`` ARE consumed by the
            # monitor (the Running Reports panel renders a workflow row by name +
            # a segment sparkline — see _running_reports.html); ``steps`` is not.
            "kind": "workflow",
            "workflow_name": (model.get("name") or "").strip(),
            "steps": steps,
            # Pass 4 Run canvas: node ids == the executor's per-step SSE step_ids
            # (``str(step["id"])``), so the canvas lights each step as it runs.
            # ``replay`` re-POSTs /api/workflows/run (JSON), NOT /api/run (spec §8).
            "canvas_nodes": [],  # built below from the now-complete record
            "replay": replay,
        }
        _runs[run_id]["canvas_nodes"] = build_canvas_nodes(_runs[run_id], _wf_index)
    _evict_old_runs()


def _emit_step(
    run_id: str,
    queue: RunEventHub,
    loop: asyncio.AbstractEventLoop,
    *,
    step_index: int,
    step_id: str,
    state: str,
    message: str = "",
    files: list[str] | None = None,
    report_url: str | None = None,
    reason: str | None = None,
) -> None:
    """Emit a ``step`` canvas event through the recorder (spec §6.3 / §4.1).

    Routes through :func:`_record_canvas_event` so the event is captured in the
    run's persist-only ``events`` list AND scheduled onto the SSE queue.
    """
    payload: dict[str, Any] = {
        "step_index": step_index,
        "step_id": step_id,
        "state": state,
        "message": message,
        "files": files or [],
        "report_url": report_url,
    }
    if state == "skipped" and reason is not None:
        payload["reason"] = reason
    _record_canvas_event(run_id, queue, loop, "step", json.dumps(payload))


def _emit_workflow_progress(
    run_id: str,
    queue: RunEventHub,
    loop: asyncio.AbstractEventLoop,
    completed: int,
    total: int,
) -> None:
    """Update the run's runnable-step progress + emit a ``progress`` event.

    The ``progress`` event routes through :func:`_record_canvas_event` (persist
    + SSE); the ``_runs[id]["progress"]`` field stays the monitor's live source.
    """
    _runs[run_id]["progress"] = {"completed": completed, "total": total}
    _record_canvas_event(
        run_id,
        queue,
        loop,
        "progress",
        json.dumps({"completed": completed, "total": total}),
    )


def _run_one_recipe_step(
    *,
    run_id: str,
    recipe_ref: str,
    effective_engine: dict[str, Any],
    state_data: dict[str, Any],
    step_output: Path,
    output_dir_abs: Path,
    cancel_event: threading.Event,
) -> tuple[bool, list[str], str | None, str]:
    """Run a SINGLE recipe through the engine for one workflow step.

    Builds the per-step config the same way ``_execute_run`` does, runs exactly
    that recipe (``recipe_filter = [name]``), then collects the HTML-first
    ``/output/...`` artifact + appends a ``report_history`` record on success.

    Returns ``(success, html_files, report_url, message)``.
    """
    from fs_report.report_engine import ReportEngine

    token = state_data.get("token", "")
    domain = state_data.get("domain", "")

    # Work on a copy of effective_engine so any future mutation doesn't disturb
    # the caller's dict (it is also read later for the history scope).
    effective_engine = dict(effective_engine)
    # Same VC scope hygiene as the single-run path: a stale global version_filter
    # (or a lone version half-pair) must not poison a Version Comparison step.
    effective_engine = clean_version_comparison_scope(effective_engine, [recipe_ref])

    # Shared engine-config builder (same as the single-run path so the kwargs
    # block can't drift).  The workflow effective dict never carries
    # baseline_version/current_version, so they fall through to create_config's
    # None default — see _build_engine_config.
    config = _build_engine_config(
        effective_engine, output_dir=step_output, token=token, domain=domain
    )

    # SP3: build + pass the deployment context for workflow steps too (so a
    # Builder context_file / deployment fields reach AI prompts on a local run).
    from fs_report.deployment_context import build_deployment_context

    engine = ReportEngine(
        config,
        cancel_event=cancel_event,
        deployment_context=build_deployment_context(config),
    )
    engine.recipe_loader.recipe_filter = [recipe_ref.lower()]

    captured_stderr = io.StringIO()
    with _stderr_lock:
        old_stderr = sys.stderr
        sys.stderr = captured_stderr
        try:
            success = engine.run().success
        finally:
            sys.stderr = old_stderr

    html_files = _collect_html_files(engine.generated_files, output_dir_abs)
    report_url = _output_url(html_files[0]) if (success and html_files) else None

    # ── B7 (#10B): FP-Analysis autotriage VEX-apply (the SP2 workflow
    # relaxation) ───────────────────────────────────────────────────────
    # Runs BEFORE append_run so the audit provenance is on the history row.
    # Gated: success + this step's recipe IS False Positive Analysis + the step
    # carries the explicit, persisted ``autotriage`` opt-in. DEFAULT-OFF — an
    # absent flag never writes VEX, and there is NO interactive prompt (a
    # saved/exported workflow is headless; the persisted opt-in IS the
    # authorization). Applies the FP recs file only (recipe_dirs=(FP,)).
    vex_provenance: dict[str, Any] | None = None
    vex_note = ""  # surfaced on the step message when the apply failed / no-op'd
    recipe_is_fp = recipe_ref.strip().lower() in FPA_RECIPES
    if success and recipe_is_fp and effective_engine.get("autotriage"):
        try:
            from fs_report.vex_apply_support import (
                FP_RECIPE_NAME,
                apply_vex_from_run,
                summarize_apply_result,
            )

            _filter = _split_status_list(effective_engine.get("autotriage_status"))
            _override = bool(effective_engine.get("vex_override", False))
            _dry = bool(effective_engine.get("dry_run", False))
            result, recs_path = apply_vex_from_run(
                domain=domain,
                auth_token=token,
                generated_files=engine.generated_files,
                dry_run=_dry,
                vex_override=_override,
                filter_statuses=_filter,
                recipe_dirs=(FP_RECIPE_NAME,),
            )
            if result is not None and recs_path is not None:
                vex_provenance = {
                    "state": "preview" if _dry else "applied",
                    "actor": f"workflow:{run_id}",
                    "run_id": run_id,
                    "recipe": recipe_ref,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "recs_path": recs_path,
                    "vex_override": _override,
                    "autotriage_status": _filter,
                    "summary": summarize_apply_result(result),
                }
                # Audit (run record): a workflow may have >1 FP step → keep a list.
                if run_id in _runs:
                    _runs[run_id].setdefault("vex_applies", []).append(vex_provenance)
                logger.info(
                    "VEX %s by workflow run %s on recipe %r (recs=%s)",
                    "previewed" if _dry else "applied",
                    run_id,
                    recipe_ref,
                    recs_path,
                )
            else:
                # Autotriage was requested but the FP recipe produced no
                # recommendations file — a no-op, surfaced so it isn't silent.
                vex_note = "autotriage: no VEX recommendations to apply"
        except Exception:
            logger.warning(
                "Workflow FP autotriage VEX apply failed (report generated)",
                exc_info=True,
            )
            # Surface the failure on the step (M1-3) — a user who enabled a
            # destructive write must not see a green step while nothing was
            # written; the report itself still generated.
            vex_note = "VEX auto-apply FAILED (report generated)"
            if run_id in _runs:
                _runs[run_id].setdefault("vex_applies", []).append(
                    {
                        "state": "error",
                        "actor": f"workflow:{run_id}",
                        "recipe": recipe_ref,
                    }
                )

    # Append a report_history record on success (same call the single-run path
    # uses) so workflow outputs show up in Report History + Recent Activity.
    if success and engine.generated_files:
        try:
            from fs_report.report_history import append_run

            history_files = _build_history_files(
                engine.generated_files, output_dir_abs, step_output.resolve()
            )
            if history_files:
                scope_dict = {
                    k: effective_engine.get(k)
                    for k in (
                        "project_filter",
                        "folder_filter",
                        "version_filter",
                        "period",
                        "start",
                        "end",
                    )
                    if effective_engine.get(k)
                }
                if getattr(engine, "resolved_project_name", None):
                    scope_dict["project_name"] = engine.resolved_project_name
                # B7: audit provenance on the persisted history row (M1-6). The
                # row is written AFTER the apply above, so the provenance is ready.
                if vex_provenance is not None:
                    scope_dict["vex_apply"] = vex_provenance
                append_run(
                    output_dir=str(output_dir_abs),
                    domain=domain,
                    recipes=[recipe_ref],
                    scope=scope_dict,
                    files=history_files,
                    log_file=state_data.get("_log_file", ""),
                )
        except Exception:
            logger.warning("Failed to record workflow step in history", exc_info=True)

    msg = recipe_ref if success else f"{recipe_ref} failed"
    # B7 (M1-3): surface an autotriage failure / no-op on the step message so a
    # deliberately-enabled destructive write that didn't happen isn't a silent
    # green step (the report itself still succeeded).
    if vex_note:
        msg = f"{msg} — {vex_note}"
    return success, html_files, report_url, msg


def _execute_workflow(
    run_id: str,
    model: dict[str, Any],
    state_data: dict[str, Any],
    queue: RunEventHub,
    loop: asyncio.AbstractEventLoop,
    cancel_event: threading.Event,
) -> None:
    """Worker thread: run a workflow's steps sequentially (spec §6.2).

    Shares ``_execute_run``'s SSE log handler, cancel semantics, and per-run
    output dir.  Recipe steps run one-at-a-time through the engine; MCP-tool
    steps are skipped (export-only).  Each step emits ``step`` SSE events; the
    final ``done`` event carries the overall status (success|error|cancelled).
    """
    from fs_report.logging_utils import create_file_handler
    from fs_report.slug import slug as make_slug

    handler = SSELogHandler(queue, loop)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    old_level = root_logger.level
    if root_logger.level > logging.INFO:
        root_logger.setLevel(logging.INFO)

    file_handler: logging.FileHandler | None = None
    overall_status = "success"

    # Terminal-done guarantee (CRITICAL): the SSE consumer (run_events) loops
    # until a `done` event arrives — without one it pings forever and the run
    # hangs as running/completed with a None result.  ``done_emitted`` tracks
    # whether the SINGLE terminal `done` has been sent; every normal exit path
    # emits it via ``_emit_done`` (which also sets _runs result), and the
    # ``finally`` block below emits a fallback `done` if NOTHING did — so even a
    # BaseException (SystemExit / KeyboardInterrupt that escapes `except
    # Exception`) still terminates the stream.
    done_emitted = False

    def _emit_done(status: str, error: str = "") -> None:
        nonlocal done_emitted
        if done_emitted:
            return
        done_emitted = True
        _runs[run_id]["result"] = status
        payload: dict[str, Any] = {"status": status}
        if error:
            payload["error"] = error
        # Surface the log file so the progress page's "View Log" link works for
        # a workflow reached via /run/{id} (set by the time we terminate).
        log_file = _runs[run_id].get("log_file")
        if log_file:
            payload["log_file"] = log_file
        # Through the recorder so the terminal ``done`` is captured for replay
        # (spec §4.1) — including the early-``return`` missing-token path, whose
        # done is then persisted from the finally.
        _record_canvas_event(run_id, queue, loop, "done", json.dumps(payload))

    try:
        token = state_data.get("token", "")
        domain = state_data.get("domain", "")
        if not token or not domain:
            _emit_done("error", "Missing token or domain")
            return

        file_handler = create_file_handler(run_id, token)
        root_logger.addHandler(file_handler)
        log_filename = Path(file_handler.baseFilename).name
        _runs[run_id]["log_file"] = log_filename
        state_data = {**state_data, "_log_file": log_filename}

        output_dir = state_data.get("output_dir", "./output")
        output_dir_abs = Path(output_dir).expanduser().resolve()
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%S")
        run_output = Path(output_dir).expanduser() / "runs" / f"{ts}_{run_id}"
        run_output.mkdir(parents=True, exist_ok=True)

        steps = model.get("steps", [])
        total_steps = len(steps)
        # progress is counted over TOTAL steps (so the monitor's recipes label and
        # the completed/total ratio agree — finding 8).  ``steps_done`` starts at
        # 0 and is bumped as EACH step (runnable OR skipped) reaches a terminal
        # state — done / error / every skipped variant (export_only / halted /
        # cancelled) — so the ratio grows 0/N → N/N naturally and a cancelled run
        # still ends with completed == total (M1-4 + M3-1).
        steps_done = 0
        aggregate_report_url: str | None = None
        halted = False
        cancelled = False

        _emit_workflow_progress(run_id, queue, loop, steps_done, total_steps)

        for i, step in enumerate(steps):
            step_id = str(step.get("id", f"s{i + 1}"))

            # Cancel check between steps (the in-flight engine honors it too).
            if cancel_event.is_set():
                cancelled = True

            if cancelled:
                _emit_step(
                    run_id,
                    queue,
                    loop,
                    step_index=i,
                    step_id=step_id,
                    state="skipped",
                    message="cancelled",
                    reason="cancelled",
                )
                # A skipped step still reaches a terminal state — count EVERY
                # step (runnable or not) so a cancelled run ends with
                # completed == total (M1-4 + M3-1).
                steps_done += 1
                _emit_workflow_progress(run_id, queue, loop, steps_done, total_steps)
                continue
            if halted:
                _emit_step(
                    run_id,
                    queue,
                    loop,
                    step_index=i,
                    step_id=step_id,
                    state="skipped",
                    message="skipped — an earlier step failed (halt)",
                    reason="halted",
                )
                steps_done += 1
                _emit_workflow_progress(run_id, queue, loop, steps_done, total_steps)
                continue

            # MCP-tool step → never executed locally (export-only).
            if step.get("kind") != "recipe" or not step.get("runnable_locally"):
                if step.get("kind") == "mcp_tool":
                    _emit_step(
                        run_id,
                        queue,
                        loop,
                        step_index=i,
                        step_id=step_id,
                        state="skipped",
                        message="runs via Forge agent — export to run",
                        reason="export_only",
                    )
                else:
                    # Unresolvable recipe ref — not runnable locally.
                    _emit_step(
                        run_id,
                        queue,
                        loop,
                        step_index=i,
                        step_id=step_id,
                        state="skipped",
                        message="step is not runnable locally",
                        reason="export_only",
                    )
                # A skipped (export-only / unresolvable) step is terminal — count
                # it so the ratio reaches total (M1-4).
                steps_done += 1
                _emit_workflow_progress(run_id, queue, loop, steps_done, total_steps)
                continue

            # Runnable recipe step.
            ref = str(step.get("ref", ""))
            step_slug = make_slug(ref)
            step_output = run_output / f"step-{i + 1:02d}-{step_slug}"
            step_output.mkdir(parents=True, exist_ok=True)
            effective_engine = _effective_step_config(model, step)

            running_msg = f"running {ref}"

            _emit_step(
                run_id, queue, loop, step_index=i, step_id=step_id, state="queued"
            )
            _emit_step(
                run_id,
                queue,
                loop,
                step_index=i,
                step_id=step_id,
                state="running",
                message=running_msg,
            )

            try:
                success, html_files, report_url, msg = _run_one_recipe_step(
                    run_id=run_id,
                    recipe_ref=ref,
                    effective_engine=effective_engine,
                    state_data=state_data,
                    step_output=step_output,
                    output_dir_abs=output_dir_abs,
                    cancel_event=cancel_event,
                )
            except Exception as exc:  # engine raised — treat as a failed step
                from fs_report.report_engine import ReportCancelled

                if isinstance(exc, ReportCancelled):
                    cancelled = True
                    _emit_step(
                        run_id,
                        queue,
                        loop,
                        step_index=i,
                        step_id=step_id,
                        state="skipped",
                        message="cancelled",
                        reason="cancelled",
                    )
                    # This step reached a terminal (skipped/cancelled) state —
                    # count it so the ratio stays coherent (M1-4 + M3-1).
                    steps_done += 1
                    _emit_workflow_progress(
                        run_id, queue, loop, steps_done, total_steps
                    )
                    continue
                logger.warning("Workflow step %s failed", step_id, exc_info=True)
                success, html_files, report_url, msg = (
                    False,
                    [],
                    None,
                    f"{ref}: {exc}",
                )

            steps_done += 1
            _emit_workflow_progress(run_id, queue, loop, steps_done, total_steps)

            if success:
                if report_url is not None:
                    aggregate_report_url = report_url
                _emit_step(
                    run_id,
                    queue,
                    loop,
                    step_index=i,
                    step_id=step_id,
                    state="done",
                    message=msg,
                    files=html_files,
                    report_url=report_url,
                )
            else:
                overall_status = "error"
                _emit_step(
                    run_id,
                    queue,
                    loop,
                    step_index=i,
                    step_id=step_id,
                    state="error",
                    message=msg,
                )
                # error_policy from the step overrides (default halt).
                policy = (step.get("overrides", {}) or {}).get("error_policy", "halt")
                if policy == "halt":
                    halted = True

        if cancelled or cancel_event.is_set():
            overall_status = "cancelled"

        if aggregate_report_url is not None and overall_status != "cancelled":
            _runs[run_id]["report_url"] = aggregate_report_url

        _emit_done(overall_status)
    except SystemExit:
        # Parity with _execute_run: Click/typer code (create_config) can raise
        # SystemExit, which is a BaseException and would escape `except
        # Exception`.  Treat it as a configuration error so a terminal `done`
        # still fires.
        _emit_done("error", "Configuration error")
    except Exception as exc:
        _emit_done("error", str(exc))
    finally:
        root_logger.removeHandler(handler)
        if file_handler is not None:
            root_logger.removeHandler(file_handler)
            file_handler.close()
        root_logger.setLevel(old_level)
        # Last-resort terminal `done`: if NO handler above emitted one (e.g. a
        # KeyboardInterrupt or any other BaseException unwinding through here),
        # emit an error `done` + set the result so the SSE stream terminates and
        # the run doesn't hang.  No-op when a terminal `done` already fired.
        _emit_done("error", "Workflow terminated unexpectedly")
        _runs[run_id]["status"] = "completed"
        # Persist after the terminal ``done`` (events complete), before eviction
        # — so any past workflow run re-renders its terminal canvas (§4.3).
        _persist_run_summary(run_id)
        _evict_old_runs()


class _EffectiveStateView:
    """Read-only ``state``-like view that resolves a single recipe's override.

    The prerun template pre-fills every field via ``state.get(key, default)``.
    For a **single-recipe** modal we want it to show that recipe's *effective*
    config (saved per-card override merged over global ``state``) so the modal
    reflects saved per-card settings (§7/§10).  Wrapping ``state`` keeps the
    template identical: only ``.get`` needs to consult the override first.
    Attribute access (``state.domain`` etc.) passes through to the wrapped
    state.  Multi-recipe modals use the raw ``state`` and are unchanged.
    """

    def __init__(self, state: WebAppState, override: dict[str, Any]) -> None:
        self._state = state
        self._override = override

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._override:
            return self._override[key]
        return self._state.get(key, default)

    def __getitem__(self, key: str) -> Any:
        if key in self._override:
            return self._override[key]
        return self._state[key]

    def __contains__(self, key: str) -> bool:
        if key in self._override:
            return True
        return key in self._state

    def __getattr__(self, name: str) -> Any:
        return getattr(self._state, name)


@router.post("/api/run/prerun")
async def prerun_form(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Return the adaptive pre-run form as an HTML partial."""
    form = await request.form()
    recipe_names = [
        r.strip() for r in str(form.get("recipes", "")).split(",") if r.strip()
    ]
    workflow_title = str(form.get("workflow_title", ""))

    # Inline imports here to break the run <-> command_center import cycle:
    # command_center.py imports compute_prerun_fields from this module.
    from fs_report.web.routers.command_center import _load_recipe
    from fs_report.web.state import needs_setup as _needs_setup

    # For a single plain compound, expand the prerun fields from its children
    # so the modal can't diverge from what dispatch enforces (PR2.3a).
    compound_children_map: dict[str, list[str]] | None = None
    requires_cve = False
    requires_component = False
    recipe_needs_setup = False
    # PR3.3a: comparison-specific prerun fields.
    is_comparison = False
    is_compound = False
    axis_left_default: str = ""
    axis_right_default: str = ""
    # Task D (T1): the authored compound `global` block (period / AI / depth /
    # finding-types / scope), used below to prefill the inline-run drawer from
    # the saved doc.  None ⇒ no authored global → fall through to Settings.
    compound_global: dict[str, Any] | None = None

    if len(recipe_names) == 1:
        recipe_obj = _load_recipe(recipe_names[0])
        if recipe_obj is not None:
            from fs_report.models import CompoundRecipe as _CompoundRecipe
            from fs_report.recipe_requirements import (
                compound_prerun_inputs as _compound_prerun_inputs,
            )

            # Task D (T1): capture the compound's authored `global` block so the
            # inline-run drawer prefills period/AI/depth/finding-types from the
            # saved doc (axis comparisons too — their scope is baked, but other
            # globals like AI/period still prefill).  Plain Recipes have no
            # global_ attribute, so guard on CompoundRecipe.
            if isinstance(recipe_obj, _CompoundRecipe):
                compound_global = recipe_obj.global_ or None

            # PR3.3a: detect axis-bearing compound (meta-compare bundle).
            if isinstance(recipe_obj, _CompoundRecipe) and recipe_obj.axis is not None:
                from fs_report.recipe_requirements import (
                    compound_child_names as _compound_child_names,
                )

                is_comparison = True
                axis_left_default = recipe_obj.axis.left or ""
                axis_right_default = recipe_obj.axis.right or ""
                # Comparison scope is baked; expand children for other show_*
                # flags (AI, triage, etc.) using compound_child_names directly.
                # NOTE: compound_prerun_inputs returns None for axis compounds
                # (it guards recipe.axis is None), so we bypass it here.
                compound_children_map = {
                    recipe_names[0].lower(): _compound_child_names(recipe_obj)
                }
            else:
                result = _compound_prerun_inputs(recipe_obj, _load_recipe)
                if result is not None:
                    # Plain compound: derive requirements from children.
                    is_compound = True
                    reqs, child_names = result
                    requires_cve = reqs.requires_cve
                    requires_component = reqs.requires_component
                    # Build map so compute_prerun_fields expands the compound name.
                    compound_children_map = {recipe_names[0].lower(): child_names}
                else:
                    requires_cve = bool(getattr(recipe_obj, "requires_cve", False))
                    requires_component = bool(
                        getattr(recipe_obj, "requires_component", False)
                    )

            recipe_needs_setup = _needs_setup(state, recipe_obj)

    fields = compute_prerun_fields(
        recipe_names,
        compound_children=compound_children_map,
        is_comparison=is_comparison,
    )

    # Kind-aware run-button label for the inline-run drawer (Task D): a compound
    # / comparison runs as one doc, so "Run 1 recipe" reads wrong — use the kind.
    # Plain single/multi-recipe modals keep the existing "Run N recipe(s)" form.
    if is_comparison:
        submit_label = "Run comparison"
    elif is_compound:
        submit_label = "Run compound"
    else:
        _n_recipes = len(recipe_names)
        submit_label = f"Run {_n_recipes} recipe{'s' if _n_recipes != 1 else ''}"

    # Single-recipe modals pre-fill from EFFECTIVE values (per-card override
    # merged over global state) so the modal reflects saved per-card config,
    # and carry the recipe's requires_cve flag + computed needs_setup so the
    # "Save as this report's default" affordance (single-recipe only) can
    # default-on for needs-setup recipes and validate the required card input.
    # Multi-recipe modals stay on the raw state (no single recipe to key on)
    # and never show the checkbox.
    #
    # Task D (T1): for a compound (the inline-run drawer's single recipe) the
    # authored `global` block prefills the fragment — period/AI/ai_depth/
    # finding_types/scope read via state.get(key) resolve from compound_global
    # first, falling back to Settings.  The compound global's flat keys
    # (period/start/end/ai/ai_depth/finding_types/current_version_only +
    # project_filter/folder_filter/version_filter) match the template's
    # state.get(...) keys verbatim (normalize_compound_global), so wrapping
    # state in _EffectiveStateView(state, compound_global) prefills cleanly.
    # A plain recipe keeps the per-card override prefill (unchanged).
    if len(recipe_names) == 1:
        state_view: WebAppState | _EffectiveStateView
        if compound_global:
            state_view = _EffectiveStateView(state, compound_global)
        else:
            override = recipe_override(state, recipe_names[0])
            state_view = _EffectiveStateView(state, override) if override else state
    else:
        state_view = state

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "pages/prerun.html",
        {
            "nonce": nonce,
            "state": state_view,
            "recipe_names": recipe_names,
            "workflow_title": workflow_title,
            "requires_cve": requires_cve,
            "requires_component": requires_component,
            "needs_setup": recipe_needs_setup,
            # PR3.3a: baked axis defaults for L/R-override fields.
            "axis_left_default": axis_left_default,
            "axis_right_default": axis_right_default,
            # Task D: kind-aware run-button label.
            "submit_label": submit_label,
            **fields,
        },
    )


@router.post("/api/run")
async def start_run(
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Start a report run. Returns the run_id."""
    from fs_report.slug import slug as _slug

    form = await request.form()
    # Dedupe (order-preserving) by the engine's normalized key: the same recipe
    # twice in one launch is meaningless (the engine runs by corpus, producing
    # identical output) AND would yield two canvas nodes with the same id → a
    # duplicate DOM id + a shared runStates slot that can't light independently.
    # Dedupe by ``slug`` (not the raw string) so case/slug VARIANTS of the same
    # recipe (e.g. "Scan Quality" + "scan-quality") also collapse to one node —
    # the engine's recipe_filter normalizes them to the same recipe anyway. The
    # UI selects recipes as a set, so this only guards a crafted POST. (R2 M3-1,
    # R3 M2-1.)
    recipe_names = []
    _seen_slugs: set[str] = set()
    for _r in str(form.get("recipes", "")).split(","):
        _r = _r.strip()
        if not _r:
            continue
        _k = _slug(_r)
        if _k not in _seen_slugs:
            _seen_slugs.add(_k)
            recipe_names.append(_r)

    if not recipe_names:
        return JSONResponse({"error": "No recipes specified"}, status_code=400)

    # Collect overrides from form (only non-empty string values become an
    # override; empty/cleared string fields are intentionally NOT added here so
    # they fall through to the engine/global default — but their PRESENCE in the
    # form is still tracked below for the authoritative present-keys logic).
    overrides: dict[str, Any] = {}
    for key in _RUN_STR_KEYS:
        val = form.get(key)
        if val:
            overrides[key] = str(val)

    for key in _RUN_BOOL_KEYS:
        val = form.get(key)
        if val is not None:
            overrides[key] = str(val).lower() in ("true", "on", "1", "yes")

    # Integer overrides — present+non-empty but non-numeric → immediate 400
    # (mirrors the card-config save which raises CardConfigCoercionError for the
    # same input; silently dropping a bad value would diverge from that path).
    for key in _RUN_INT_KEYS:
        val = form.get(key)
        if val is not None and str(val).strip():
            # Present and non-empty: must be int-parseable.
            try:
                overrides[key] = int(str(val))
            except (ValueError, TypeError):
                _err_msg = f"{key} must be a non-negative integer, got {str(val)!r}"
                return JSONResponse(
                    {"error": _err_msg, "errors": [_err_msg]}, status_code=400
                )

    # #27 present-key scope clearing: an explicit "all projects / all folders /
    # all versions" selection arrives as a scope key PRESENT-but-empty (the
    # client present-key contract in fast-run.js / the run bar). The non-empty
    # ``if val`` collection above dropped it, so record an explicit "" for every
    # scope key the form CARRIED — clearing any stale inherited state scope at
    # the state∪overrides merge. An OMITTED scope key is left alone so a
    # state-derived (global Settings) scope still inherits.
    overrides = apply_scope_present_keys(
        overrides, {k for k in _SCOPE_PRESENT_KEYS if k in form}
    )

    # Single-recipe MINIMAL launches (__openFR: recipes + scope only) merge the
    # recipe's saved per-card override UNDER the form-collected overrides, so a
    # body-click / run-bar / palette-Enter run inherits the saved per-card
    # config.  Net precedence: global defaults < per-card override < explicit
    # form params.  Multi-recipe runs (palette workflows) skip this — no single
    # recipe to key the override on.  Canonical lowercase recipe-name key.
    #
    # The configure modal is AUTHORITATIVE (PR #117 review r5, narrowed r6).  It
    # pre-fills every field it RENDERS from EFFECTIVE values (override ∪ global,
    # via _EffectiveStateView), and (r6) its submit now carries EVERY rendered
    # field — including cleared ones as present-but-empty.  But the modal renders
    # many override fields only conditionally ({% if show_ai %} etc.), while a
    # recipe can still carry a saved per-card override for a field the modal does
    # NOT render (set via the card-back Advanced tab, which is not show_ai
    # gated).  So the r5 blanket skip was too broad: it silently dropped a saved
    # override for a non-rendered field on a modal launch.
    #
    # Narrower fix: the modal is authoritative ONLY for the override keys the
    # form actually CARRIES (present, value-independent — a present-but-empty
    # field counts).  Suppress the saved override for those present keys (the
    # form's non-empty value wins; a present-but-empty field added nothing to
    # ``overrides`` above, so it falls through to the engine/global default — the
    # clear is honored).  KEEP the saved override for keys the form did NOT carry
    # (fields the modal never rendered).  Non-authoritative (minimal) launches
    # are UNCHANGED — full override merge, as before.  Presence is read from the
    # raw ``form`` (not the non-empty ``overrides`` dict) so cleared fields still
    # count.  The ``_authoritative`` marker is control-only — not an override
    # key, so it never reaches the run config.
    authoritative = str(form.get("_authoritative", "")).lower() in (
        "true",
        "on",
        "1",
        "yes",
    )
    if len(recipe_names) == 1:
        recipe_ov = recipe_override(state, recipe_names[0])
        if authoritative:
            present_keys = {k for k in _RUN_OVERRIDE_KEYS if k in form}
            recipe_ov_kept = {
                k: v for k, v in recipe_ov.items() if k not in present_keys
            }
            # merge_with_period_range_clearing: if the form carries start+end it
            # clears any saved period from base; if it carries a named period it
            # clears any saved start/end — preventing a stale date-mode from the
            # saved override silently winning over a fresh submission.
            overrides = merge_with_period_range_clearing(recipe_ov_kept, overrides)
        else:
            overrides = merge_with_period_range_clearing(recipe_ov, overrides)

    # Request-time validation: validate the FINAL merged overrides (post
    # single-recipe saved-override merge) so that a stale per-card override
    # carrying an invalid value (e.g. period="custom", bad scan enum) is caught
    # with a synchronous 400 instead of failing later in the background thread.
    # For multi-recipe runs ``overrides`` is unchanged from the form payload,
    # so validation still covers the submitted values.
    errors = validate_run_overrides(overrides)
    if errors:
        return JSONResponse(
            {"error": "; ".join(errors), "errors": errors}, status_code=400
        )

    # ── SP3: run-start re-check that uploaded scoring/context files are still
    # present + valid (effective = override over the Settings global). Run-start
    # only — never blocks a card-config save (spec §5). ──
    # report-config-card-gating: a single PLAIN recipe that does not consume the
    # deployment context (show_deployment_context False — e.g. Component
    # Remediation Package, whose card no longer shows the field) won't read
    # context_file at run time, so a stale/deleted path for it must not 400 the
    # run on a field the user can no longer clear from that card. Compounds (a
    # child may consume it) and multi-recipe runs keep validating it. scoring_file
    # gating is unchanged by this work, so its validation is left exactly as-is.
    _check_context = should_validate_context_file(recipe_names)
    _upload_eff = {
        "scoring_file": overrides.get("scoring_file") or state.get("scoring_file"),
        "context_file": (
            (overrides.get("context_file") or state.get("context_file"))
            if _check_context
            else None
        ),
    }
    _stale = stale_upload_path_errors(_upload_eff)
    if _stale:
        return JSONResponse(
            {"error": "; ".join(_stale), "errors": _stale}, status_code=400
        )

    # ── SP2: destructive VEX-write gate ──────────────────────────────
    # dry_run is a transient per-launch param (NOT an override). confirm is the
    # server-enforced acknowledgement for a real write.
    dry_run_req = str(form.get("dry_run", "")).lower() in ("true", "on", "1", "yes")
    confirm_req = str(form.get("confirm", "")).lower() in ("true", "on", "1", "yes")
    destructive_errors = validate_destructive_overrides(
        overrides, recipes=recipe_names, is_workflow=False, dry_run=dry_run_req
    )
    if destructive_errors:
        return JSONResponse(
            {"error": "; ".join(destructive_errors), "errors": destructive_errors},
            status_code=400,
        )
    # A REAL (non-dry-run) autotriage write requires an explicit confirm — even on
    # a minimal/quick launch that merged a saved per-card autotriage override. The
    # client routes through the confirm dialog; this 400 (with needs_confirm) is
    # the backstop so a scripted POST can't silently write. (spec §8)
    if bool(overrides.get("autotriage")) and not dry_run_req and not confirm_req:
        _msg = (
            "This run will write VEX statuses to the platform. Resubmit with "
            "confirm=true to proceed."
        )
        return JSONResponse(
            {"error": _msg, "errors": [_msg], "needs_confirm": True},
            status_code=400,
        )

    # Persist selected recipes for next visit
    state["selected_recipes"] = recipe_names
    state.save()

    run_id = uuid.uuid4().hex[:8]
    queue = RunEventHub()
    loop = asyncio.get_event_loop()
    cancel_event = threading.Event()

    # Build a richer scope label for the monitor row.  Use the EFFECTIVE merged
    # config (state ∪ overrides) the same way ``_execute_run`` does, so a run
    # whose scope comes from GLOBAL Settings (in ``state``, not the form) shows
    # its real scope on the canvas/monitor — not a misleading "portfolio".
    eff = merge_with_period_range_clearing(state.to_dict(), overrides)
    # A Version-Comparison-only run drops the scope version_filter (and a lone
    # baseline/current); clean the effective view so the monitor scope label and
    # the replay scope below reflect what actually runs — not a stale "@ v2.0".
    eff = clean_version_comparison_scope(eff, recipe_names)
    # Hand the EFFECTIVE config to the shared label builder (#26 — one precedence
    # for start_run AND _workflow_scope, no drift). The leaked project_filter is
    # already cleared by the #27 present-key fix, so the resolver reports the
    # honest effective scope, not a stale pinned project.
    scope = _run_scope_label(eff, str(eff.get("domain", "")), str(eff.get("token", "")))

    # ── Pass 4 Run canvas: detect a compound run + build the kind / canvas_nodes
    # / replay metadata the monitor + canvas read (spec §4/§8). A single recipe
    # that resolves (slug-keyed) to a ``CompoundRecipe`` is a compound bundle —
    # one combined deliverable of N child sections; everything else is a plain
    # report.
    from fs_report.models import CompoundRecipe
    from fs_report.slug import slug

    _recipes_index = _load_canvas_recipes_index()
    _resolved = (
        _recipes_index.get(slug(recipe_names[0])) if len(recipe_names) == 1 else None
    )
    is_compound = isinstance(_resolved, CompoundRecipe)
    kind = "compound" if is_compound else "report"
    # ``isinstance`` inline (not the ``is_compound`` bool) so mypy narrows
    # ``_resolved`` to CompoundRecipe before reading ``.sections``.
    compound_total = (
        len(_resolved.sections) if isinstance(_resolved, CompoundRecipe) else None
    )

    # ── Compound target preflight (parallel to the workflow preflight) ───────
    # A compound is one recipe-doc that fans N child sections into one
    # deliverable. Mirror the workflow's authoritative server-side preflight: a
    # compound launched with a child whose requires_* target is unmet fails fast
    # with a 400 (naming the offending child SECTION) instead of aborting mid-run
    # in the engine. This runs for GENERAL (target_agnostic) and target-bound
    # compounds alike (product decision 2026-06-16); target_agnostic only swaps
    # the rejection wording ("pick a target for this run" vs "set the compound's
    # global scope"). A general compound whose sections need no target still runs.
    # ``eff`` is the run's effective scope (state ∪ form overrides); the saved
    # ``compound.global_`` scope is the target-bound fallback inside the
    # preflight. ``state`` supplies domain/token so a targeted folder can be
    # resolved (best-effort, skipped if creds are absent). Same 400 shape as the
    # workflow path so the two Builder run paths share one error contract.
    if isinstance(_resolved, CompoundRecipe):
        try:
            compound_preflight(_resolved, eff, state)
        except CompoundPreflightError as exc:
            return JSONResponse(
                {
                    "error": str(exc),
                    "step_id": exc.step_id,
                    "step_index": exc.step_index,
                },
                status_code=400,
            )

    # Replay blob (spec §8): report/compound re-runs re-POST the FORM endpoint
    # /api/run with the comma-joined recipes + the user's explicit form overrides
    # (the exact minimal field set the original launch carried — byte-identical
    # to the pre-canvas replay for the common case) PLUS the EFFECTIVE scope
    # (project/version/folder from state ∪ overrides).  Adding the effective
    # scope captures a state-derived (global Settings) scope for a faithful
    # replay (M3-2) — not omitted (which would replay portfolio-wide); when the
    # scope already came from the form it's already in ``overrides``, so this
    # adds nothing and the common-case replay is unchanged.  Non-scope state
    # defaults (period/output_dir/cache_ttl/…) are deliberately NOT snapshotted
    # — they flow from state on replay exactly as on the original launch.
    # ``dry_run`` / ``confirm`` are transient (never in ``overrides``) and so are
    # naturally excluded.  A truthy ``autotriage`` (a real form override) stays
    # in ``fields`` so the frontend routes a replay through the confirm dialog.
    fields: dict[str, Any] = {"recipes": ",".join(recipe_names)}
    fields.update(overrides)
    for _k in ("project_filter", "version_filter", "folder_filter"):
        _v = eff.get(_k)
        if _v not in (None, "", False) and _k not in fields:
            fields[_k] = _v
    # Version requires a project (engine invariant — _build_engine_config drops a
    # project-less version): never let a project-less version reach the replay
    # blob, so a re-run isn't described as version-scoped when the engine would
    # ignore that version. Covers a caller that clears project (present-empty)
    # while a stale state version_filter is still inherited into ``eff`` (M2-1).
    if not str(eff.get("project_filter") or "").strip():
        fields.pop("version_filter", None)
    # Keep the replay faithful to what actually runs: a VC run drops the scope
    # version_filter and a lone baseline/current, so the replay must not carry
    # them either (a re-run would otherwise diverge or re-trigger the pre-flight
    # failure).  ``eff`` is already cleaned, so the scope loop never re-added
    # version_filter; this also strips a lone pair that arrived via overrides.
    fields = clean_version_comparison_scope(fields, recipe_names)
    replay = {
        "endpoint": "/api/run",
        "encoding": "form",
        "fields": fields,
    }

    # Guard the dict write with the lock so concurrent calls from other request
    # handlers (or the eviction loop) cannot race with us.
    with _RUNS_LOCK:
        _runs[run_id] = {
            "status": "running",
            "queue": queue,
            "recipes": recipe_names,
            "started_at": time.time(),
            "cancel_event": cancel_event,
            # ``scope`` is the human label derived from compute_effective_scope
            # (#26/#15) — the single source the Running Reports monitor, the
            # /runs index, and the run-canvas source node all render.
            "scope": scope,
            # Compound: seed real 0/N progress at registration so the monitor
            # shows 0/N before the worker thread starts (not an indeterminate
            # single job).  Non-compound stays None until _execute_run emits.
            "progress": (
                {"completed": 0, "total": compound_total} if is_compound else None
            ),
            "kind": kind,
            "canvas_nodes": [],  # built below from the now-complete record
            "replay": replay,
        }
        # build_canvas_nodes reads kind/scope/recipes — all set on the record
        # above — so the node ids match the SSE step_ids the executor will emit.
        _runs[run_id]["canvas_nodes"] = build_canvas_nodes(
            _runs[run_id], _recipes_index
        )

    # Evict oldest completed entries so _runs doesn't grow unboundedly during a
    # long-lived serve session.  Never evict running entries.
    # Called OUTSIDE the _RUNS_LOCK block above: _evict_old_runs() acquires
    # _RUNS_LOCK internally (RLock allows re-entrance, but keeping this outside
    # makes the lock discipline explicit and avoids any surprise nesting).
    _evict_old_runs()

    thread = threading.Thread(
        target=_execute_run,
        args=(
            run_id,
            recipe_names,
            state.to_dict(),
            overrides,
            queue,
            loop,
            cancel_event,
            dry_run_req,
            compound_total,
        ),
        daemon=True,
    )
    thread.start()

    return JSONResponse({"run_id": run_id, "kind": kind})


@router.get("/api/run/{run_id}/vex-preview")
async def vex_preview(run_id: str) -> JSONResponse:
    """Return the run's persisted SP2 VEX apply preview / result (spec §7).

    The run record carries a ``vex_apply`` dict when the run did a dry-run
    preview or a real apply. The monitor fetches this on the SSE
    ``vex_preview`` / ``vex_applied`` flag to render the panel.
    """
    rec = _runs.get(run_id)
    if rec is None:
        return JSONResponse({"error": "run not found"}, status_code=404)
    vex = rec.get("vex_apply")
    if not vex:
        return JSONResponse({"error": "no VEX apply for this run"}, status_code=404)
    return JSONResponse(
        {
            "run_id": run_id,
            "state": vex.get("state"),
            "autotriage_status": vex.get("autotriage_status"),
            "vex_override": vex.get("vex_override"),
            "summary": vex.get("summary"),
        }
    )


@router.post("/api/run/{run_id}/vex-apply")
async def vex_apply_for_real(
    run_id: str,
    request: Request,
    state: WebAppState = Depends(get_state),
) -> JSONResponse:
    """Commit a previewed VEX apply for real (spec §7; server-enforced confirm).

    Requires ``confirm: true`` (400 otherwise). Re-applies the run's persisted
    recs file — no report re-run — reusing the persisted status filter +
    vex_override so the commit matches the preview. 409 if the run is gone /
    evicted or already applied.
    """
    confirm_raw: Any = ""
    try:
        body = await request.json()
        confirm_raw = body.get("confirm", "")
    except Exception:
        try:
            form = await request.form()
            confirm_raw = form.get("confirm", "")
        except Exception:
            confirm_raw = ""
    if str(confirm_raw).lower() not in ("true", "on", "1", "yes"):
        return JSONResponse(
            {"error": "confirm=true required to write VEX to the platform"},
            status_code=400,
        )

    rec = _runs.get(run_id)
    if rec is None:
        return JSONResponse({"error": "run expired — re-run to apply"}, status_code=409)
    vex = rec.get("vex_apply")
    if not vex or not vex.get("recs_path"):
        return JSONResponse(
            {"error": "no VEX preview to apply for this run"}, status_code=409
        )
    if vex.get("state") == "applied":
        return JSONResponse({"error": "already applied"}, status_code=409)

    token = state.token
    domain = vex.get("domain") or state.domain
    if not token or not domain:
        return JSONResponse({"error": "missing token or domain"}, status_code=400)

    from fs_report.vex_apply_support import apply_recs_file, summarize_apply_result

    try:
        result = apply_recs_file(
            vex["recs_path"],
            domain=domain,
            auth_token=token,
            dry_run=False,
            vex_override=bool(vex.get("vex_override", False)),
            filter_statuses=vex.get("autotriage_status"),
        )
    except Exception:
        logger.warning("apply-for-real VEX write failed", exc_info=True)
        return JSONResponse(
            {"error": "VEX apply failed; see server log"}, status_code=500
        )

    summary = summarize_apply_result(result)
    vex["state"] = "applied"
    vex["summary"] = summary
    return JSONResponse({"run_id": run_id, "state": "applied", "summary": summary})


@router.get("/api/run/{run_id}/events")
async def run_events(run_id: str) -> EventSourceResponse:
    """SSE stream for a running report."""
    if run_id not in _runs:
        return EventSourceResponse(
            iter(
                [
                    {
                        "event": "done",
                        "data": '{"status":"error","error":"Run not found"}',
                    }
                ]
            )
        )

    run = _runs[run_id]
    hub: RunEventHub = run["queue"]

    async def event_generator():  # type: ignore[no-untyped-def]
        # Subscribe + snapshot the replay buffer in the SAME loop tick (no await
        # between the two) so a concurrently-published event lands in EXACTLY one
        # of replay/live — never both (double-deliver) nor neither (lost). #12.
        q = hub.subscribe()
        replay = list(hub.buffer)
        try:
            # Replay history so a late-joiner (e.g. a second viewer via /runs)
            # reconstructs the run so far — the producer fills the buffer, so the
            # snapshot is complete regardless of which viewer drains live events.
            for event in replay:
                yield event
                # The run may have finished before this viewer connected; the
                # terminal done is in the replay → stop, don't wait forever.
                if event.get("event") == "done":
                    return
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30.0)
                    yield event
                    if event.get("event") == "done":
                        break
                except TimeoutError:
                    # Send keep-alive ping
                    yield {"event": "ping", "data": ""}
        finally:
            hub.unsubscribe(q)

    return EventSourceResponse(event_generator())


def _get_active_runs_list() -> list[dict[str, Any]]:
    """Return the canonical active-run list used by both the JSON and HTML fragment endpoints.

    Selection rule: all running runs are always visible; plus the most-recent
    completed runs needed to fill the monitor panel up to 4 total rows.
    Concretely: ``slots_for_completed = max(0, 4 − len(running_runs))``.
    More than 4 rows are returned only when more than 4 runs are currently
    running (all of them must remain visible).

    Within the running group and within the completed group, entries are sorted
    newest ``started_at`` first.  Running rows sort before completed rows when
    timestamps collide (tie-breaker only).

    Thread-safety: holds ``_RUNS_LOCK`` only for the brief snapshot
    construction, then releases the lock before the heavier per-row formatting
    work on the snapshot copy.  This avoids holding the lock while building
    dicts and sorting, while still preventing
    ``RuntimeError: dictionary changed size during iteration``.
    """
    now = time.time()
    running_rows: list[dict[str, Any]] = []
    completed_rows: list[dict[str, Any]] = []

    # Hold the lock only long enough to take a consistent snapshot.
    with _RUNS_LOCK:
        snapshot = list(_runs.items())

    for run_id, run in snapshot:
        age = now - run.get("started_at", now)
        status = run["status"]
        row = {
            "run_id": run_id,
            "status": status,
            "result": run.get("result"),
            "recipes": run["recipes"],
            "started_at": run.get("started_at", 0),
            "elapsed": round(age),
            "progress": run.get("progress"),
            "scope": run.get("scope", ""),
            "report_url": run.get("report_url"),
            # SP: workflow rows render by name + a segment sparkline; the poller
            # branches on ``kind`` (default "report" for ad-hoc runs).
            "kind": run.get("kind", "report"),
            "workflow_name": run.get("workflow_name", ""),
        }
        if status == "running":
            running_rows.append(row)
        else:
            completed_rows.append(row)

    # Sort each group newest-first.
    running_rows.sort(key=lambda r: -r["started_at"])
    completed_rows.sort(key=lambda r: -r["started_at"])

    # Always include all running rows; fill remaining slots with newest completed.
    slots_for_completed = max(0, 4 - len(running_rows))
    return running_rows + completed_rows[:slots_for_completed]


@router.get("/api/runs/active")
async def active_runs() -> JSONResponse:
    """Return all running runs plus completed runs filling up to 4 total rows, newest first.

    All running runs are always included; the remaining slots up to 4 total are
    filled with the most-recent completed runs
    (``slots = max(0, 4 − len(running))``).  Uses the same selection logic as
    /api/running so the command-centre poller and the rendered DOM always agree
    on which run_ids are present — preventing spurious full re-renders
    ("breathing").
    """
    return JSONResponse(_get_active_runs_list())


@router.get("/api/running")
async def running_reports(request: Request) -> object:
    """Return an HTML fragment showing currently running (and recently done) reports."""
    runs_list = _get_active_runs_list()
    running_count = sum(1 for r in runs_list if r["status"] == "running")
    done_count = sum(
        1
        for r in runs_list
        if r["status"] != "running" and r.get("result") == "success"
    )
    failed_count = sum(
        1 for r in runs_list if r["status"] != "running" and r.get("result") == "error"
    )

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "components/_running_reports.html",
        {
            "runs": runs_list,
            "running_count": running_count,
            "done_count": done_count,
            "failed_count": failed_count,
        },
    )


@router.get("/api/run/{run_id}/status")
async def run_status(run_id: str) -> JSONResponse:
    """JSON poll fallback for run status."""
    if run_id not in _runs:
        return JSONResponse({"error": "Run not found"}, status_code=404)

    run = _runs[run_id]
    return JSONResponse(
        {
            "status": run["status"],
            "recipes": run["recipes"],
        }
    )


def _resolve_log_path(run_id: str) -> Path | None:
    """Resolve the on-disk log file for ``run_id`` (in-memory first, then glob).

    Thin wrapper over :func:`fs_report.logging_utils.resolve_log_path` that
    supplies the run router's in-memory ``log_file`` (recorded by
    ``_execute_run``) as the explicit-filename hint, then falls back to the
    shared glob resolver.  Sharing the resolver with ``serve_history_log`` keeps
    the glob-escape + newest-match behaviour identical across every log viewer.
    """
    from fs_report.logging_utils import resolve_log_path

    run = _runs.get(run_id)
    log_filename = run.get("log_file") if run else None
    return resolve_log_path(run_id, log_filename)


@router.get("/api/run/{run_id}/log")
async def run_log(run_id: str, download: int = 0) -> PlainTextResponse:
    """Serve the log file for a run as plain text.

    ``?download=1`` returns the log as a file attachment (Content-Disposition)
    so the run-log page's Download button saves ``fs-report-<run_id>.log``.
    Without it the log is returned inline (backward-compatible — existing
    callers/tests rely on the raw inline text).
    """
    log_path = _resolve_log_path(run_id)
    if log_path is None:
        return PlainTextResponse("Log file not found.", status_code=404)

    text = log_path.read_text(encoding="utf-8")
    if download:
        # Sanitize run_id for the Content-Disposition filename so a crafted
        # run_id can't inject quotes/CR/LF or otherwise produce a malformed
        # header.  Keep only [A-Za-z0-9_-]; everything else is dropped.
        safe_run_id = re.sub(r"[^A-Za-z0-9_-]", "", run_id)
        return PlainTextResponse(
            text,
            headers={
                "Content-Disposition": (
                    f'attachment; filename="fs-report-{safe_run_id}.log"'
                )
            },
        )
    return PlainTextResponse(text)


@router.post("/api/run/{run_id}/cancel")
async def cancel_run(run_id: str) -> JSONResponse:
    """Signal a running report to cancel."""
    run = _runs.get(run_id)
    if not run or run["status"] != "running":
        return JSONResponse(
            {"error": "Run not found or already completed"}, status_code=404
        )

    cancel_event: threading.Event | None = run.get("cancel_event")
    if cancel_event is not None:
        cancel_event.set()
    return JSONResponse({"cancelled": True})


@router.get("/runs")
async def runs_index_page(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the per-run index (``pages/runs.html``) — spec §6.

    The persistent, full-page superset of the Command-Center "Running Reports"
    panel and the run-granularity complement to Report History.  Lists the
    merged active + persisted runs (``_list_all_runs``), each row → ``/run/{id}``.
    Offline-capable (local data — no ``/setup`` redirect), like Report History.
    """
    runs, degraded = _collect_runs()
    ctx = build_shell_context(state, nonce, crumb="Runs", active_view="runs")
    ctx["state"] = state
    ctx["runs"] = runs
    ctx["degraded"] = degraded
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/runs.html", ctx)


@router.get("/api/runs/list")
async def runs_list_fragment(request: Request) -> object:
    """Return the swappable /runs body fragment (for the manual Refresh)."""
    runs, degraded = _collect_runs()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "components/_runs_list.html", {"runs": runs, "degraded": degraded}
    )


# IMPORTANT (route-ordering footgun — spec §7 / multi-review R1 M1-16): the
# static ``/run`` MUST be registered BEFORE the parameterized ``/run/{run_id}``
# below, or Starlette could try to match ``/run`` as ``run_id=""`` (rendering the
# expired panel instead of redirecting).  Decorators register in source order, so
# keep this function ABOVE ``run_progress_page``.
@router.get("/run")
async def run_most_recent_redirect() -> RedirectResponse:
    """``GET /run`` (no id) → 302 to the most-recent run's canvas (spec §7).

    "Most recent" is resolved across ``_runs`` + ``<runs_dir>/*.json`` (newest by
    ``finished_at``/``started_at``).  With no runs at all → ``/runs`` (which shows
    its own empty state).
    """
    rows = _list_all_runs()
    if rows:
        return RedirectResponse(f"/run/{rows[0]['run_id']}", status_code=302)
    return RedirectResponse("/runs", status_code=302)


@router.get("/run/{run_id}")
async def run_progress_page(
    run_id: str,
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the Run canvas (``pages/run.html``) for a specific run.

    The canvas serves both run kinds honestly per kind: a workflow walks its
    steps in a serpentine; a compound report fans its sections into one combined
    deliverable.  The static node layer is server-rendered from the run record's
    ``canvas_nodes`` (built by :func:`build_canvas_nodes`); the Alpine
    controller (``run-page.js``) lights each node by matching the SSE
    ``step_id`` to ``node["id"]`` (the node-id ↔ step-id invariant, spec §4.2).

    Precedence (spec §5.1):
      1. **In ``_runs``** → the LIVE canvas exactly as before (``terminal``
         false; run-page.js opens the SSE stream).
      2. **Else ``<runs_dir>/<run_id>.json`` exists** → TERMINAL mode: render the
         canvas from the persisted summary (``terminal`` true + ``events`` +
         ``result`` + timing); run-page.js replays the events with no socket.
      3. **Else** → the friendly in-shell "This run has expired" panel
         (``expired`` branch), with links to Report History and the run log.

    A corrupt/partial ``_run.json`` is guarded (``_load_run_summary`` returns
    None) → falls through to expired, never 500.  Because the ``window.__RUN``
    bootstrap references the canvas vars unconditionally, ALL template keys are
    supplied with safe defaults so every branch renders without a Jinja
    ``UndefinedError``.

    ``active_view="run"`` so the sidebar Run item highlights (spec §9) — this
    IS now a navigable sidebar destination.
    """
    run = _runs.get(run_id)
    # Terminal fallback: only consult the persisted summary when the run is NOT
    # live (in-memory always wins — spec §5.1 / §10).
    summary = _load_run_summary(run_id) if run is None else None

    ctx = build_shell_context(state, nonce, crumb="Run", active_view="run")
    # NOTE: do NOT overwrite ctx["recipes"] — that is the launcher/palette
    # catalog (recipe OBJECTS with .label) injected into window.__CC.recipes by
    # build_shell_context.  The canvas reads canvas_nodes, not recipes.
    ctx["run_id"] = run_id
    # Source of canvas vars: the live record, else the persisted summary, else
    # safe empties for the expired panel.
    src: dict[str, Any] = run or summary or {}
    ctx["expired"] = run is None and summary is None
    ctx["terminal"] = run is None and summary is not None
    ctx["kind"] = src.get("kind", "report")
    ctx["canvas_nodes"] = src.get("canvas_nodes", [])
    ctx["scope"] = src.get("scope", "")
    ctx["workflow_name"] = src.get("workflow_name", "")
    ctx["replay"] = src.get("replay")
    # Terminal-mode extras (empty/None for live + expired — the bootstrap reads
    # them always).  ``events`` is the persisted canvas-event history run-page.js
    # replays; ``result`` + timing settle the orb + elapsed without a socket.
    ctx["events"] = summary.get("events", []) if summary is not None else []
    ctx["result"] = src.get("result")
    ctx["started_at"] = src.get("started_at")
    ctx["finished_at"] = summary.get("finished_at") if summary is not None else None

    templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/run.html", ctx)


# Cap the on-page log to a bounded tail so a verbose log can't blow up the
# rendered HTML.  The Download endpoint always serves the FULL file.
_LOG_PAGE_MAX_LINES = 500
_LOG_PAGE_MAX_BYTES = 256 * 1024


def _read_log_tail(log_path: Path) -> tuple[str, bool]:
    """Read only the last ``_LOG_PAGE_MAX_BYTES`` of ``log_path`` then line-cap.

    Bounded read: ``seek(size - CAP_BYTES)`` and read to EOF so a pathologically
    large log never loads fully into memory — at most ~``_LOG_PAGE_MAX_BYTES``
    (256 KiB) is read regardless of file size.  If we seeked past the start, the
    first (likely partial) line is dropped.  The decoded tail is then passed
    through the existing line cap.  Returns ``(display_text, truncated)``; the
    Download endpoint still serves the FULL file.
    """
    size = log_path.stat().st_size
    seeked = size > _LOG_PAGE_MAX_BYTES
    with log_path.open("rb") as fh:
        if seeked:
            fh.seek(size - _LOG_PAGE_MAX_BYTES)
        raw = fh.read()
    text = raw.decode("utf-8", errors="replace")
    if seeked:
        # Drop the first (likely partial) line we sliced into mid-way — but only
        # when there's a later newline to keep.  If the whole slice is a single
        # newline-less line (one pathologically long log line), dropping it would
        # render an empty body, so keep the partial line instead.
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1 :]
    display_text, line_truncated = _tail_for_page(text)
    return display_text, seeked or line_truncated


def _tail_for_page(text: str) -> tuple[str, bool]:
    """Return ``(display_text, truncated)`` capped to the last lines.

    Keeps at most the last ``_LOG_PAGE_MAX_LINES`` lines so a verbose log doesn't
    bloat the page.  The byte bound is enforced by :func:`_read_log_tail` (which
    only ever reads ``_LOG_PAGE_MAX_BYTES`` off disk); this just trims line
    count.  The full log is still available via the Download endpoint.
    """
    lines = text.splitlines(keepends=True)
    truncated = len(lines) > _LOG_PAGE_MAX_LINES
    if truncated:
        lines = lines[-_LOG_PAGE_MAX_LINES:]
    return "".join(lines), truncated


@router.get("/run/{run_id}/log")
async def run_log_page(
    run_id: str,
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the shell-styled run-log page for a completed run.

    Resolves the log the same way ``run_log`` does (in-memory ``log_file`` then
    ``LOG_DIR`` glob) and renders it inside the Command Center shell with a
    support-contact callout + Download button.  The run log is not a sidebar
    destination, so ``active_view`` is empty.  A missing log degrades to a
    graceful in-shell "log not found" state (still with the support contact),
    not a bare 404 string.  The log text is passed as a plain string and
    rendered through Jinja autoescaping — never as raw HTML.

    Outcome-aware: this page is reachable for SUCCESSFUL runs too (the progress
    page's "View Log" shows on any completion), so the template only frames the
    page as a failure (failure eyebrow + "something went wrong" support copy)
    when the run actually errored (``result == "error"``).  Success/cancelled
    runs — and the glob-only path where the run isn't in ``_runs`` (outcome
    unknown) — get a neutral "Run log" view.  The support contact + Download
    stay available in all cases; we just don't claim "failed" when it wasn't.

    The on-page log is capped to a bounded tail (see ``_read_log_tail`` — only
    ~256 KiB is read off disk regardless of file size); the Download endpoint
    always serves the full file.
    """
    run = _runs.get(run_id)
    log_path = _resolve_log_path(run_id)
    # Bounded read: only the tail (~_LOG_PAGE_MAX_BYTES) is loaded into memory,
    # so a pathologically large log never loads fully here.  The Download
    # endpoint still serves the full file.
    if log_path is not None:
        display_text, log_truncated = _read_log_tail(log_path)
        log_found = True
    else:
        display_text, log_truncated = "", False
        log_found = False

    ctx = build_shell_context(state, nonce, crumb="Run Log", active_view="")
    ctx["run_id"] = run_id
    # NOTE: do NOT overwrite ctx["recipes"] — that is the launcher/palette
    # catalog (recipe OBJECTS with .label) injected into window.__CC.recipes.
    # The run's recipe-NAME list goes under a distinct key so the ⌘K palette
    # keeps working on this page.
    ctx["run_recipes"] = run.get("recipes") if run else None
    ctx["scope"] = run.get("scope") if run else None
    ctx["log_text"] = display_text
    ctx["log_found"] = log_found
    ctx["log_truncated"] = log_truncated
    # Outcome flag: only an errored run is framed as a failure.  When the run is
    # not in _runs (glob-only resolution → outcome unknown), default neutral.
    ctx["run_errored"] = bool(run and run.get("result") == "error")

    templates = request.app.state.templates
    return templates.TemplateResponse(request, "pages/run_log.html", ctx)
