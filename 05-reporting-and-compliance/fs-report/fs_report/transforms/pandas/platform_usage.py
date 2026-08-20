"""Pandas transform for the Platform Usage report.

Answers a superuser's question: how is this org actually using the platform?
Inventory (folders / projects / versions), activity + freshness (when was each
project last scanned), and hygiene (what is unowned, orphaned, empty, or
duplicated). Deliberately carries **no** per-user or seat-based metric — that is
what the User Activity report is for.

Data sources, all org-wide:

* ``/public/v0/scans``    — the recipe's primary query, delivered as ``data``.
  Assessment category, so report_engine's generic scan branch widens the fetch
  to the full scan history rather than the ``--period`` window; the lifetime
  scan counts depend on that.
* ``/public/v0/projects`` — fetched here TWICE (``archived=false`` then
  ``archived=true``), because the endpoint returns one or the other and this
  report states both counts.
* ``/public/v0/versions`` — the cross-project versions endpoint. Fetched
  independently of scans so a version that was uploaded but never scanned still
  appears; ``project -> versions`` cannot be reconstructed from scans alone.
* ``/public/v0/folders``  — folder inventory + ``parentFolderId`` for breadcrumbs.

Platform gaps this transform works around, each disclosed in ``usage_notes`` so
a reader is never told a column means more than it does:

* **No owner field.** Projects and folders carry ``createdBy`` (an email), which
  is the recording user, not an owner of record. The hygiene flag is therefore
  "no creator recorded", not "no owner assigned".
* **No tags/labels.** The projects API exposes ``type``
  (application / firmware / container / …) and ``priorities``, neither of which
  is a free-form tag. The report shows ``project_type`` and says so.
* **No artifact type or ingestion method on a version.** Both are derived from
  the version's scans — ``scan.type`` (SCA / SOURCE_SCA / SAST / CONFIG /
  SBOM_IMPORT / VULNERABILITY_ANALYSIS / SPDX / SARIF) and ``scan.mechanism``
  (API_UPLOAD / UI_UPLOAD / CLT_UPLOAD / …). A
  version with no scans has neither, which is exactly the hygiene flag
  "Version never scanned".
* **No org-wide dependency endpoint.** Project dependencies are only readable
  per version (``/public/v0/project-versions/{id}/dependencies``), so the
  dependency tree is resolved only for the projects where it changes the
  answer: those holding versions but no completed scan of their own. Such a
  project is an assembly — its scanning happens in the projects it depends on —
  and reporting it as "Never scanned / Stale" is the misleading part this walk
  exists to fix. Because a scoped run's scan fetch is narrowed API-side, the
  walk also re-fetches ``/public/v0/scans`` for the dependency projects that
  fall outside the scope; without that, ``--folder`` would reintroduce the very
  mislabelling on the runs most likely to hit it.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd

from fs_report.models import Config

logger = logging.getLogger(__name__)

# ── Scan status classification ────────────────────────────────────────────
#
# Deliberately simpler than scan_analysis's heuristic, which additionally treats
# a non-COMPLETED *external* scan (SOURCE_SCA / JAR / SBOM_IMPORT) as a failed
# attempt because those complete at creation time. That call is right for a
# throughput report and wrong here: this report's subject is freshness, and
# counting a just-uploaded SBOM as a failure would flap the failed-scan rate on
# every in-flight import. Anything neither completed nor a recorded error counts
# as in progress, and usage_notes says so.
COMPLETED_STATUSES: frozenset[str] = frozenset({"COMPLETED"})
FAILED_STATUSES: frozenset[str] = frozenset({"ERROR", "UPLOAD_FAILED"})

# Freshness bucket labels. NEVER_SCANNED is not a threshold — it is the absence
# of any completed scan, kept distinct from "very old" so a project that was
# never scanned is never reported as merely dormant.
BUCKET_CURRENT = "Current"
BUCKET_AGING = "Aging"
BUCKET_STALE = "Stale"
BUCKET_DORMANT = "Dormant"
BUCKET_NEVER = "Never scanned"
BUCKET_ORDER: tuple[str, ...] = (
    BUCKET_CURRENT,
    BUCKET_AGING,
    BUCKET_STALE,
    BUCKET_DORMANT,
    BUCKET_NEVER,
)

NO_FOLDER_LABEL = "(no folder)"

#: Reader-facing names for the ``scan.mechanism`` enum, used for the ingestion
#: chart's category labels only — every row keeps its raw ``mechanism`` beside
#: the label so CSV, XLSX and JSON consumers still join against the API value.
#: The same vocabulary drives the table chips in ``platform_usage.html``; keep
#: the two in step, or the chart and the table beside it name the same thing
#: differently. An unlisted value falls through to itself.
INGESTION_LABELS: dict[str, str] = {
    "UI_UPLOAD": "GUI",
    "API_UPLOAD": "API",
    "UNKNOWN": "Unknown",
}

#: Recipe-overridable thresholds (spec §4: "thresholds should be configurable,
#: not hardcoded"). Every one is a whole number of days except trend_months.
_DEFAULTS: dict[str, int] = {
    "current_days": 30,
    "aging_days": 90,
    "stale_days": 180,
    "activity_window_days": 30,
    "scan_window_days": 90,
    "stale_project_days": 90,
    "no_new_version_days": 180,
    "trend_months": 12,
    # Ceiling on the per-version dependency walk, which has no bulk endpoint.
    # Counts ROOT versions resolved, not HTTP calls — one root can fan out.
    "dependency_lookup_versions": 250,
}


# ── small helpers ─────────────────────────────────────────────────────────


def _as_records(data: list[dict[str, Any]] | pd.DataFrame) -> list[dict[str, Any]]:
    """Normalise the primary query payload to a list of dicts."""
    if isinstance(data, pd.DataFrame):
        if data.empty:
            return []
        # to_dict types its keys as Hashable; every column here is a string.
        return [
            {str(k): v for k, v in record.items()}
            for record in data.to_dict(orient="records")
        ]
    return list(data or [])


def _nested(record: dict[str, Any], outer: str, key: str) -> str:
    """Read ``record[outer][key]`` as a string, tolerating None/non-dict."""
    inner = record.get(outer)
    if isinstance(inner, dict):
        value = inner.get(key)
        return "" if value is None else str(value)
    return ""


def _parse_ts(value: Any) -> datetime | None:
    """Parse an API timestamp to an aware UTC datetime, or None."""
    if value is None or value == "":
        return None
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    if not isinstance(parsed, pd.Timestamp) or pd.isna(parsed):
        return None
    result: datetime = parsed.to_pydatetime()
    return result


def _date_str(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value is not None else ""


def _month_key(value: datetime) -> str:
    return value.strftime("%Y-%m")


def _enum(value: Any) -> str:
    """Read an API enum field as a string, treating missing values as absent.

    ``str(value or "")`` is NOT sufficient here. The primary query is delivered as
    a DataFrame, so an absent ``type`` / ``mechanism`` arrives as a float ``NaN``
    — which is TRUTHY, so ``NaN or ""`` yields the NaN and ``str()`` turns it into
    the literal ``"nan"``. That string then joined into artifact_types /
    ingestion_methods and surfaced as a "nan" value in the rendered table and the
    CSV.
    """
    if value is None:
        return ""
    if isinstance(value, float) and value != value:  # NaN
        return ""
    text = str(value).strip()
    return "" if text.lower() in ("nan", "none", "<na>") else text


def _joined(values: set[str]) -> str:
    """Render a set of enum-ish values as a stable, comma-separated string."""
    return ", ".join(sorted(v for v in values if v))


def _ellipsize_tail(value: str, limit: int = 30) -> str:
    """Keep the TAIL of a folder breadcrumb, matching the JS ``ellipsizeTail``.

    The shared "Root > …" prefix is not what distinguishes one folder from
    another — the leaf (the team) is. Mirrored here so the declared chart's
    server-SVG/PDF path truncates identically to the interactive one instead
    of rendering the raw (unbounded) breadcrumb and risking overflow.
    """
    return value if len(value) <= limit else "…" + value[-(limit - 1) :]


def _fetch_all(
    api_client: Any,
    endpoint: str,
    *,
    archived: bool | None = None,
    filter_expr: str | None = None,
    label: str = "",
) -> list[dict[str, Any]] | None:
    """Fetch every page of *endpoint*. Returns ``None`` if the fetch FAILED.

    ``None`` and ``[]`` mean different things and the caller must keep them
    apart: ``[]`` is "this organization genuinely has none of these", ``None`` is
    "we do not know". Collapsing both to ``[]`` let a single transient API error
    render a confident, plausible report of an empty organization — zero
    projects, zero versions — beside a populated scan history, with nothing in
    the output saying a fetch had failed.

    ``skip_cache_store=True`` for the same reason ``api/versions_history.py``
    passes it: the structured-table cache only knows the findings-shaped
    endpoints and logs "Unknown endpoint" for /versions and /folders. The API
    client's own raw/SQLite layer still applies.

    ``excluded`` is only sent to endpoints that define it. /folders and
    /versions have no such parameter, and sending an undefined filter risks
    silently narrowing the very inventory whose completeness this report asserts.
    """
    from fs_report.models import QueryConfig, QueryParams

    supports_excluded = endpoint.endswith("/projects")
    query = QueryConfig(
        endpoint=endpoint,
        params=QueryParams(
            limit=10000,
            archived=archived,
            filter=filter_expr,
            excluded=False if supports_excluded else None,
        ),
    )
    try:
        rows = api_client.fetch_all_with_resume(
            query, show_progress=False, skip_cache_store=True
        )
    except Exception as exc:
        logger.error(
            "Platform Usage: %s fetch FAILED: %s", label or endpoint, exc, exc_info=True
        )
        return None
    return list(rows) if isinstance(rows, list) else []


def _resolve_params(additional_data: dict[str, Any] | None) -> dict[str, int]:
    """Merge recipe ``parameters`` over the defaults, ignoring bad values.

    A non-numeric or non-positive override falls back to the default rather than
    producing a bucket nothing can land in.
    """
    resolved = dict(_DEFAULTS)
    supplied = (additional_data or {}).get("recipe_parameters") or {}
    if not isinstance(supplied, dict):
        return resolved
    for key, default in _DEFAULTS.items():
        if key not in supplied:
            continue
        try:
            value = int(supplied[key])
        except (TypeError, ValueError):
            logger.warning(
                "Platform Usage: parameter %s=%r is not an integer; using %d",
                key,
                supplied[key],
                default,
            )
            continue
        if value <= 0:
            logger.warning(
                "Platform Usage: parameter %s=%d must be positive; using %d",
                key,
                value,
                default,
            )
            continue
        resolved[key] = value

    # The buckets must stay strictly increasing or a project could match two.
    if not resolved["current_days"] < resolved["aging_days"] < resolved["stale_days"]:
        logger.warning(
            "Platform Usage: freshness thresholds must increase "
            "(current<aging<stale), got %d/%d/%d; using defaults",
            resolved["current_days"],
            resolved["aging_days"],
            resolved["stale_days"],
        )
        for key in ("current_days", "aging_days", "stale_days"):
            resolved[key] = _DEFAULTS[key]
    return resolved


def _bucket(days: int | None, params: dict[str, int]) -> str:
    """Bucket "days since last completed scan"; None means never scanned."""
    if days is None:
        return BUCKET_NEVER
    if days <= params["current_days"]:
        return BUCKET_CURRENT
    if days <= params["aging_days"]:
        return BUCKET_AGING
    if days <= params["stale_days"]:
        return BUCKET_STALE
    return BUCKET_DORMANT


def _folder_paths(folders: list[dict[str, Any]]) -> dict[str, str]:
    """Map folder id -> "Root > Team A" breadcrumb.

    Same-named folders in different trees are common, so every folder label in
    this report is a full path. A parent id absent from the fetched set (the
    caller lacks VIEW_FOLDER on it) terminates the walk there rather than
    dropping the folder, and a parent cycle is broken by the visited set.
    """
    by_id = {str(f.get("id", "")): f for f in folders if f.get("id")}
    paths: dict[str, str] = {}
    for fid in by_id:
        parts: list[str] = []
        seen: set[str] = set()
        cursor: str | None = fid
        while cursor and cursor in by_id and cursor not in seen:
            seen.add(cursor)
            record = by_id[cursor]
            parts.append(str(record.get("name") or cursor))
            parent = record.get("parentFolderId")
            cursor = str(parent) if parent else None
        paths[fid] = " > ".join(reversed(parts))
    return paths


def _month_series(end: datetime, months: int) -> list[str]:
    """Trailing *months* month keys, ending with the month containing *end*."""
    keys: list[str] = []
    year, month = end.year, end.month
    for _ in range(months):
        keys.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return list(reversed(keys))


# ── per-entity aggregation ────────────────────────────────────────────────


class _ScanRollup:
    """Per-version, per-project and per-month scan aggregates, in one pass."""

    def __init__(self, scans: list[dict[str, Any]]) -> None:
        self.version_scan_count: Counter[str] = Counter()
        self.version_latest_status: dict[str, str] = {}
        self.version_latest_at: dict[str, datetime] = {}
        self.version_types: dict[str, set[str]] = {}
        self.version_mechanisms: dict[str, set[str]] = {}
        # COMPLETED-only, unlike version_latest_at. Freshness inherited through a
        # dependency edge must obey the same "completed scans only" rule the
        # project-level column does, or an assembly would read fresh off a
        # dependency's failed upload.
        self.version_completed_at: dict[str, datetime] = {}

        self.project_scan_count: Counter[str] = Counter()
        self.project_completed_at: dict[str, datetime] = {}
        self.project_types: dict[str, set[str]] = {}
        self.project_mechanisms: dict[str, set[str]] = {}

        self.month_completed: Counter[str] = Counter()
        self.month_failed: Counter[str] = Counter()
        self.month_other: Counter[str] = Counter()

        self.unparseable_timestamps = 0

        for scan in scans:
            status = _enum(scan.get("status")).upper()
            scan_type = _enum(scan.get("type"))
            mechanism = _enum(scan.get("mechanism"))
            project_id = _nested(scan, "project", "id")
            version_id = _nested(scan, "projectVersion", "id")
            created = _parse_ts(scan.get("created"))
            completed = _parse_ts(scan.get("completed"))
            # Order by when a scan finished where that is known, else by when it
            # started — an in-flight scan has no completion time but is still
            # the version's most recent scan.
            occurred = completed or created

            if version_id:
                self.version_scan_count[version_id] += 1
                self.version_types.setdefault(version_id, set()).add(scan_type)
                self.version_mechanisms.setdefault(version_id, set()).add(mechanism)
                previous = self.version_latest_at.get(version_id)
                if occurred is not None and (previous is None or occurred > previous):
                    self.version_latest_at[version_id] = occurred
                    self.version_latest_status[version_id] = status
                elif version_id not in self.version_latest_status:
                    self.version_latest_status[version_id] = status

            if project_id:
                self.project_scan_count[project_id] += 1
                self.project_types.setdefault(project_id, set()).add(scan_type)
                self.project_mechanisms.setdefault(project_id, set()).add(mechanism)

            # Freshness is defined on COMPLETED scans only (spec §4), against
            # the completion timestamp — a scan that started long ago and
            # finished yesterday makes the project fresh as of yesterday.
            if status in COMPLETED_STATUSES:
                finished = completed or created
                if finished is None:
                    self.unparseable_timestamps += 1
                    continue
                if project_id:
                    prior = self.project_completed_at.get(project_id)
                    if prior is None or finished > prior:
                        self.project_completed_at[project_id] = finished
                if version_id:
                    prior_version = self.version_completed_at.get(version_id)
                    if prior_version is None or finished > prior_version:
                        self.version_completed_at[version_id] = finished
                self.month_completed[_month_key(finished)] += 1
            elif occurred is None:
                self.unparseable_timestamps += 1
            elif status in FAILED_STATUSES:
                self.month_failed[_month_key(occurred)] += 1
            else:
                self.month_other[_month_key(occurred)] += 1

    def days_since_completed(self, project_id: str, now: datetime) -> int | None:
        """Whole days since this project's most recent COMPLETED scan.

        None means no scan has ever completed for it. Whole days — not a raw
        timestamp comparison — because this single value drives BOTH the
        freshness bucket column and the Active/Stale tiles. Mixing the two bases
        made a project last scanned 30.5 days ago read as bucket "Current" while
        the "Active 30d" tile excluded it; a tile that contradicts the column
        beside it is worse than either rounding rule.
        """
        latest = self.project_completed_at.get(project_id)
        return None if latest is None else (now - latest).days


def _descendants(node: Any) -> list[Any]:
    """Every node below *node*, depth-first, excluding *node* itself."""
    out: list[Any] = []
    for child in node.children:
        out.append(child)
        out.extend(_descendants(child))
    return out


#: Consecutive resolver failures that end the walk, no matter how many
#: versions resolved successfully before or after them. Reset to zero on
#: every success. One failure is a bad version; three IN A ROW is a client
#: that has stopped being able to do dependency lookups at all (expired
#: token, an outage mid-walk), and hammering it once per remaining version
#: buys nothing.
_DEPENDENCY_FAILURE_LIMIT = 3

#: Project ids per top-up scan query. Matches the batch size report_engine uses
#: on the same endpoint for the same reason — a long ``project=in=(…)`` filter
#: returns 414 URL Too Long.
_DEPENDENCY_SCAN_BATCH = 25

#: Ceiling on DISTINCT out-of-scope dependency projects the top-up will query.
#: The dependency walk is already bounded by dependency_lookup_versions, but a
#: --folder run over a widely-shared library tree can still resolve many
#: distinct out-of-scope projects from a modest number of root versions, so
#: this caps the fan-out independently rather than relying on that bound
#: alone. Anything past the cap is disclosed rather than silently dropped.
_DEPENDENCY_SCAN_TOPUP_LIMIT = 500


def _dependency_trees(
    api_client: Any,
    project_ids: list[str],
    versions_by_project: dict[str, list[dict[str, Any]]],
    project_by_id: dict[str, dict[str, Any]],
    budget: int,
) -> tuple[dict[str, dict[str, list[tuple[str, str]]]], int, int, int]:
    """Resolve the dependency tree of each candidate project, transitively.

    Called only for projects that hold versions but have no completed scan of
    their own — the case where the report is otherwise misleading, because such
    a project is an assembly whose scanning happens one edge down. An assembly
    of assemblies still bottoms out at something scanned, hence transitive.

    Returns ``(trees, root_versions_skipped, resolver_failures, capped_versions)``
    where *trees* is
    ``project_id -> own_version_id -> [(dep_project_id, dep_version_id)]``.
    Structure only, deliberately: which scans those versions have is resolved
    separately, because on a scoped run some of them are not in the scan set yet.
    *capped_versions* counts root versions where the per-version dependency
    fetch hit its own page limit (100), so that version's tree is itself a
    lower bound independent of the walk's overall budget.
    """
    from fs_report.dependency_resolver import DependencyResolver

    resolver = DependencyResolver(api_client)
    trees: dict[str, dict[str, list[tuple[str, str]]]] = {}
    examined = 0
    skipped = 0
    failures = 0
    consecutive_failures = 0

    for project_id in project_ids:
        name = str(project_by_id.get(project_id, {}).get("name") or "")
        per_version: dict[str, list[tuple[str, str]]] = {}
        for version in versions_by_project.get(project_id, []):
            version_id = str(version.get("id") or "")
            if not version_id:
                continue
            if examined >= budget:
                skipped += 1
                continue
            examined += 1
            # DependencyResolver swallows per-request failures itself, so what
            # reaches here is a structural problem. One bad version must not cost
            # every other project its dependency figures, so the walk continues;
            # a run of failures with nothing resolved BETWEEN successes does end
            # it — including a client that goes bad partway through a long walk,
            # not only one that never worked at all.
            try:
                deps = _descendants(resolver.resolve(project_id, name, version_id))
            except Exception as exc:
                failures += 1
                consecutive_failures += 1
                logger.warning(
                    "Platform Usage: dependency lookup failed for %s/%s: %s",
                    name or project_id,
                    version_id,
                    exc,
                    exc_info=True,
                )
                if consecutive_failures >= _DEPENDENCY_FAILURE_LIMIT:
                    logger.error(
                        "Platform Usage: abandoning the dependency walk after %d "
                        "consecutive failures — this client has stopped being "
                        "able to do dependency lookups. Projects scanned only "
                        "through their dependencies will read “Never scanned”.",
                        consecutive_failures,
                    )
                    return trees, skipped, failures, len(resolver.truncated_versions)
                continue
            consecutive_failures = 0
            if deps:
                per_version[version_id] = [
                    (str(node.project_id), str(node.version_id)) for node in deps
                ]
        if per_version:
            trees[project_id] = per_version
    return trees, skipped, failures, len(resolver.truncated_versions)


def _dependency_scans(
    api_client: Any,
    dep_project_ids: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Fetch the scan history of dependency projects outside the report's scope.

    A ``--folder`` or ``--project`` run has its scan fetch narrowed API-side to
    the in-scope projects, so an assembly's dependency filed elsewhere
    contributes no scans and the assembly would keep reading "Never scanned" —
    the exact bug the dependency walk exists to fix, reappearing on the runs most
    likely to hit it. These projects are asked for by id, so the top-up stays
    proportional to the assemblies found rather than re-widening to the org.

    Returns ``(scans, failed_batches)``.
    """
    ordered = sorted(dep_project_ids)
    scans: list[dict[str, Any]] = []
    failed: list[str] = []
    for start in range(0, len(ordered), _DEPENDENCY_SCAN_BATCH):
        batch = ordered[start : start + _DEPENDENCY_SCAN_BATCH]
        rows = _fetch_all(
            api_client,
            "/public/v0/scans",
            filter_expr=f"project=in=({','.join(batch)})",
            label=f"dependency scans [{start // _DEPENDENCY_SCAN_BATCH}]",
        )
        if rows is None:
            failed.extend(batch)
            continue
        scans.extend(rows)
    return scans, failed


def _dependency_coverage(
    trees: dict[str, dict[str, list[tuple[str, str]]]],
    rollup: _ScanRollup,
) -> dict[str, dict[str, Any]]:
    """Roll each resolved dependency tree up into scan figures for its parent.

    Only projects that actually have dependencies appear in the mapping, so a
    caller can treat a miss as "no dependencies" rather than "not looked up".
    """
    coverage: dict[str, dict[str, Any]] = {}
    for project_id, per_version in trees.items():
        entry: dict[str, Any] = {
            "dep_project_ids": set(),
            "dep_version_ids": set(),
            "versions_with_scanned_deps": set(),
            "last_completed": None,
            "scans": 0,
            "types": set(),
            "mechanisms": set(),
        }
        for version_id, deps in per_version.items():
            version_dep_scans = 0
            for dep_project_id, dep_version_id in deps:
                version_dep_scans += rollup.version_scan_count.get(dep_version_id, 0)
                if dep_version_id in entry["dep_version_ids"]:
                    continue
                entry["dep_version_ids"].add(dep_version_id)
                entry["dep_project_ids"].add(dep_project_id)
                entry["scans"] += rollup.version_scan_count.get(dep_version_id, 0)
                entry["types"] |= rollup.version_types.get(dep_version_id, set())
                entry["mechanisms"] |= rollup.version_mechanisms.get(
                    dep_version_id, set()
                )
                finished = rollup.version_completed_at.get(dep_version_id)
                if finished is not None and (
                    entry["last_completed"] is None
                    or finished > entry["last_completed"]
                ):
                    entry["last_completed"] = finished
            if version_dep_scans:
                entry["versions_with_scanned_deps"].add(version_id)
        if entry["dep_version_ids"]:
            # A cyclic or self-referential edge would otherwise let a project be
            # its own dependency and inflate the count by one.
            entry["dep_project_ids"].discard(project_id)
            coverage[project_id] = entry
    return coverage


def _project_window_counts(
    scans: list[dict[str, Any]], floor: datetime
) -> Counter[str]:
    """project_id -> count of scans (any status) that occurred since *floor*.

    Counts scan *records*, because "Scan count (last 90 days)" in the spec is a
    record count. Rescans of the same version count, per the spec's §5 note that
    a rescan signals ongoing engagement.
    """
    counts: Counter[str] = Counter()
    for scan in scans:
        project_id = _nested(scan, "project", "id")
        if not project_id:
            continue
        occurred = _parse_ts(scan.get("completed")) or _parse_ts(scan.get("created"))
        if occurred is not None and occurred >= floor:
            counts[project_id] += 1
    return counts


# ── main transform ────────────────────────────────────────────────────────


def platform_usage_transform(
    data: list[dict[str, Any]] | pd.DataFrame,
    config: Config | None = None,
    additional_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the Platform Usage report.

    Returns the recipe's section dict. ``main`` is the per-project inventory
    (spec §C, the primary detail view and the CSV / first XLSX sheet);
    ``extra_tables`` carries the folder, version and hygiene tables as
    additional sheets and sibling CSVs; the remaining keys are promoted to
    top-level template variables by the engine.
    """
    additional_data = additional_data or {}
    params = _resolve_params(additional_data)
    api_client = additional_data.get("api_client")
    notes: list[str] = []

    if api_client is None:
        # Without the API client there is no inventory at all — only scans,
        # which cannot answer "empty project" or "never scanned". Fail loudly
        # rather than render a report whose zeros mean "not fetched".
        raise ValueError(
            "Platform Usage requires an API client. The engine injects it for "
            "this recipe; a direct transform call must pass "
            "additional_data={'api_client': <APIClient>}."
        )

    scans = _as_records(data)
    now = datetime.now(UTC)
    # Set by report_engine when the primary /scans sweep hit its hard
    # page/record ceiling (or exhausted retries mid-page) before reaching the
    # requested start date. That sweep is what "lifetime scan history" rests
    # on, so a silent ceiling would let a large or old tenant's scan counts,
    # freshness dates and "Never scanned" flag understate reality with
    # nothing in the report saying so.
    scans_truncated = bool(additional_data.get("scans_fetch_truncated"))

    raw_folders = _fetch_all(api_client, "/public/v0/folders", label="folders")
    raw_active = _fetch_all(
        api_client, "/public/v0/projects", archived=False, label="active projects"
    )
    raw_archived = _fetch_all(
        api_client, "/public/v0/projects", archived=True, label="archived projects"
    )
    # No `archived` param here, unlike the two /projects sweeps above — not an
    # oversight: /public/v0/versions has no such parameter at all (confirmed
    # against the platform's OpenAPI spec, which lists only
    # offset/limit/filter/sort/projectId for this endpoint). There is no
    # active/archived split for this endpoint to omit either side of; it
    # already returns every version regardless of the owning project's
    # archived status.
    raw_versions = _fetch_all(api_client, "/public/v0/versions", label="versions")

    # A failed sweep (None) is NOT an empty one ([]). Every zero this report
    # prints is load-bearing — "empty project", "never scanned", "0 folders" are
    # all findings — so a fetch failure must be named rather than rendered as a
    # confident zero. The failures are collected first and reported as one loud
    # note, because a run that lost its project sweep has nothing trustworthy in
    # it at all.
    fetch_failures = [
        label
        for label, rows in (
            ("folders", raw_folders),
            ("active projects", raw_active),
            ("archived projects", raw_archived),
            ("versions", raw_versions),
        )
        if rows is None
    ]
    folders = raw_folders or []
    active_projects = raw_active or []
    archived_projects = raw_archived or []
    versions = raw_versions or []
    # A failed /versions sweep leaves every project's version_count at 0 —
    # indistinguishable, downstream, from a project that genuinely has none.
    # "Empty project" must not fire on that manufactured zero: it would flag
    # every project in the org, which is a stronger and more misleading claim
    # than the general "counts are a floor" note covers.
    versions_fetch_failed = "versions" in fetch_failures

    if fetch_failures:
        message = (
            "DATA INTEGRITY: the "
            + ", ".join(fetch_failures)
            + " sweep(s) FAILED, so this report is incomplete and its zeros mean "
            "“not fetched”, not “none exist”. Counts, freshness and the hygiene "
            "list are all understated. Re-run; if it persists, check the token's "
            "permissions for those endpoints."
        )
        logger.error("Platform Usage: %s", message)
        notes.insert(0, message)
    if raw_folders == []:
        notes.append(
            "No folders were returned. Folder columns render as “(no folder)” and "
            "the folder table is empty — expected on a tenant with no folders, a "
            "permissions gap otherwise."
        )
    if raw_versions == []:
        notes.append(
            "No versions were returned from /public/v0/versions. Version counts, "
            "the version table and the “Version never scanned” flag are "
            "unavailable for this run."
        )

    projects: list[dict[str, Any]] = []
    for record in active_projects:
        merged = dict(record)
        merged["archived"] = False
        projects.append(merged)
    for record in archived_projects:
        merged = dict(record)
        merged["archived"] = True
        projects.append(merged)

    # Captured before --folder / --project narrows `projects` below: the org's
    # FULL project inventory, used later to tell "outside this run's scope but
    # a real project the token can see" (eligible to feed dependency freshness
    # via the out-of-scope top-up) apart from "not in the org's inventory at
    # all" (a genuinely invisible/orphaned scan, which must stay excluded from
    # every figure, dependency freshness included).
    org_project_ids = {str(p.get("id")) for p in projects if p.get("id")}

    # ── scope ─────────────────────────────────────────────────────────────
    # The engine already narrowed the scans query for --project / --folder.
    # Mirror that on the inventory sweeps, which are unavoidably org-wide, so
    # both halves of every ratio describe the same population.
    project_filter = getattr(config, "project_filter", None) if config else None
    folder_project_ids = additional_data.get("folder_project_ids")
    # Prefer the explicit signal: a folder holding zero projects is a
    # legitimate scope, and the truthiness fallback below cannot see it — an
    # empty `folder_project_ids` looks identical to "not scoped". The
    # fallback exists only for a caller that has no explicit flag to give
    # (e.g. project-id scoping, or an older engine); it is not a general
    # licence to pass `folder_project_ids` for anything other than folder
    # scoping, since a non-empty set there always narrows the report.
    folder_scope_active = bool(additional_data.get("folder_scope_active")) or bool(
        folder_project_ids
    )
    folder_scope_folder_ids = additional_data.get("folder_scope_folder_ids")
    scoped = False
    if project_filter:
        wanted = str(project_filter).strip().lower()
        keep = {
            str(p.get("id"))
            for p in projects
            if str(p.get("id", "")).lower() == wanted
            or str(p.get("name", "")).lower() == wanted
        }
        projects = [p for p in projects if str(p.get("id")) in keep]
        scoped = True
        if len(keep) > 1:
            # Names are not unique platform-wide, so a name that matches several
            # projects would silently widen a "single project" run.
            notes.append(
                f"--project {project_filter} matched {len(keep)} projects by name; "
                "all are included. Pass the project id to pin exactly one."
            )
        notes.append(
            f"Scoped to a single project (--project {project_filter}); the "
            "org-wide totals in the tiles describe that project only."
        )
    elif folder_scope_active:
        keep = {str(pid) for pid in (folder_project_ids or set())}
        projects = [p for p in projects if str(p.get("id")) in keep]
        scoped = True
        notes.append(
            f"Scoped to the selected folder tree (--folder): {len(projects)} "
            "project(s). Every tile and table below describes that tree only — "
            "the totals are scoped, not org-wide."
        )

    in_scope_ids = {str(p.get("id")) for p in projects if p.get("id")}

    # Folder inventory follows the same scope as the project inventory. Without
    # this, a --folder run listed every folder in the organization, reported an
    # org-wide total_folders next to a scoped project count, and flagged every
    # folder outside the selection as "Empty folder" — a hygiene finding about
    # folders that are simply out of scope.
    if scoped:
        if folder_scope_folder_ids:
            allowed_folder_ids = {str(fid) for fid in folder_scope_folder_ids}
        else:
            # No resolved tree (a --project run, or an older engine): keep only
            # the folders the in-scope projects actually sit in. Ancestors are
            # still resolvable for breadcrumbs because _folder_paths walks the
            # unfiltered set, which is captured before this narrowing.
            allowed_folder_ids = {
                _nested(p, "folder", "id") for p in projects if p.get("folder")
            } - {""}
        folder_path_source = list(folders)
        folders = [f for f in folders if str(f.get("id", "")) in allowed_folder_ids]
    else:
        folder_path_source = folders

    # Every scan whose project is not in the inventory is dropped, in EVERY scope
    # — not just when --project/--folder narrowed things. Previously the filter
    # was guarded by `if scoped:`, so on a portfolio run the per-project columns
    # and the folder chart counted only in-scope projects while scans_lifetime,
    # the windowed counts, the monthly trend and the ingestion mix counted
    # orphans too. The tiles and the tables then disagreed, which is exactly the
    # reconciliation this report claims to provide. Integrity is evaluated on the
    # RAW set first, below, so dropping them here cannot mask a broken join.
    versions = [v for v in versions if _nested(v, "project", "id") in in_scope_ids]
    raw_scan_project_ids = {_nested(scan, "project", "id") for scan in scans} - {""}
    orphan_scan_ids = raw_scan_project_ids - in_scope_ids
    join_broken = bool(
        scans and in_scope_ids and not (raw_scan_project_ids & in_scope_ids)
    )
    # Orphans are dropped even when the join is broken. Keeping them made the
    # scan-derived KPIs and charts (scans_lifetime, the windowed count, the
    # monthly trend, the ingestion mix) show hundreds of scans beside a project
    # table where every row read zero and "Never scanned" — so the tiles looked
    # like a trustworthy adoption signal next to a table contradicting them, and
    # the banner only warned about freshness. Dropping them makes the whole report
    # consistently empty, which is the honest rendering of "none of these scans
    # belong to any project we can see". The raw count is preserved in the
    # summary and the banner so the operator still knows scans WERE fetched.
    scans_fetched_total = len(scans)
    dropped_scan_count = 0
    all_scans = scans
    if orphan_scan_ids:
        scans = [s for s in scans if _nested(s, "project", "id") in in_scope_ids]
        dropped_scan_count = scans_fetched_total - len(scans)

    rollup = _ScanRollup(scans)
    if rollup.unparseable_timestamps:
        notes.append(
            f"{rollup.unparseable_timestamps} scan(s) carried no parseable "
            "timestamp and are excluded from freshness and trend figures. They "
            "are still counted in lifetime scan counts."
        )

    # Zero-intersection guard. Scans and projects are joined on project id, so if
    # both sets are non-empty and share NO id, every freshness figure below is
    # meaningless — every project reports "Never scanned" and the report renders a
    # uniform wall that looks like a finding about the tenant rather than a broken
    # join. That is exactly how a cross-tenant cache bleed presented: an 8-project
    # tenant handed a 469-scan set belonging to a different account. Evaluated on
    # the RAW scan set (before the orphan drop above), or the drop would empty the
    # set and hide the very condition this detects.
    if join_broken and not raw_scan_project_ids:
        # Every fetched scan came back with no project reference at all — a
        # payload anomaly, not a mismatch between two otherwise-valid id
        # sets. Re-running with --refresh fixes a stale cross-tenant cache;
        # it does nothing for scans the API itself returned without a
        # project, so that advice would send an operator down the wrong path.
        message = (
            f"DATA INTEGRITY: none of the {scans_fetched_total} scan(s) fetched "
            "carry a project reference at all, so none could be matched to any "
            "project in scope. Every scan-derived figure here — freshness, the "
            "scan counts, the monthly trends, the ingestion mix — is zero or "
            "“Never scanned” regardless of the real state. This is a "
            "malformed-payload gap on the /scans response, not a caching issue: "
            "`--refresh` will not fix it. Check the API token's permissions and "
            "whether the platform is degraded, and retry."
        )
        logger.error("Platform Usage: %s", message)
        notes.insert(0, message)
    elif join_broken:
        message = (
            f"DATA INTEGRITY: none of the {scans_fetched_total} scan(s) fetched "
            f"reference any of the {len(in_scope_ids)} project(s) in scope. Every "
            "scan was therefore excluded, so EVERY scan-derived figure here — "
            "freshness, the scan counts, the monthly trends, the ingestion mix — "
            "is zero or “Never scanned” regardless of the real state. This is a "
            "broken join, not a finding about the tenant. The usual cause is a "
            "cached scan set belonging to a different account: re-run with "
            "`--refresh`, or `fs-report cache clear --api`, and confirm the token "
            "and domain belong to the same tenant."
        )
        logger.error("Platform Usage: %s", message)
        notes.insert(0, message)
    elif orphan_scan_ids:
        notes.append(
            f"{dropped_scan_count} scan(s) across {len(orphan_scan_ids)} project "
            "id(s) reference projects absent from the inventory and are excluded "
            "from EVERY figure here, tiles and tables alike, so the two "
            "reconcile. Expected on a --folder or --project run, and for projects "
            "the token cannot see."
        )
    if scans_truncated:
        message = (
            "DATA INTEGRITY: the scan history fetch hit its hard page/record "
            "ceiling before reaching the requested start date, so this run's "
            "scan population is a partial history, not the full lifetime "
            "record this report claims. Scan counts, freshness dates and "
            "“Never scanned” are all a floor here — some pre-cutoff scans may "
            "be missing, and an idle-looking project may simply be one whose "
            "scans fell outside what was fetched. Narrow with --folder or "
            "--project to bring the population under the ceiling."
        )
        logger.error("Platform Usage: %s", message)
        notes.insert(0, message)

    # Breadcrumbs are built from the UNFILTERED folder set: a scoped run keeps
    # only the selected tree in the folder table, but a leaf's ancestors may sit
    # outside it, and dropping them would truncate every path to the leaf name.
    folder_path_by_id = _folder_paths(folder_path_source)
    project_by_id = {str(p.get("id")): p for p in projects if p.get("id")}

    versions_by_project: dict[str, list[dict[str, Any]]] = {}
    for version in versions:
        versions_by_project.setdefault(_nested(version, "project", "id"), []).append(
            version
        )

    # Assemblies: versions uploaded, nothing of their own ever completed. Only
    # these need the per-version dependency walk — a project with its own
    # completed scan already has a real freshness date, and paying an HTTP round
    # trip per version to confirm it would make this report unusable on a large
    # tenant.
    #
    # Skipped entirely on a broken join. Every versioned project qualifies as a
    # candidate there (nothing joined, so nothing completed), which would fire the
    # whole request budget in exactly the mismatched-token / cache-bleed case the
    # guard above exists to short-circuit — and any date it recovered would
    # contradict a banner promising every scan-derived figure reads empty.
    assembly_candidates = (
        []
        if join_broken
        else sorted(
            project_id
            for project_id, own_versions in versions_by_project.items()
            if own_versions
            and project_id in in_scope_ids
            and project_id not in rollup.project_completed_at
        )
    )
    dep_trees, dep_lookups_skipped, dep_failures, dep_lookups_capped = (
        _dependency_trees(
            api_client,
            assembly_candidates,
            versions_by_project,
            project_by_id,
            params["dependency_lookup_versions"],
        )
    )
    # A scoped run's scan fetch is narrowed API-side to the in-scope projects, so
    # a dependency filed outside the scope contributed nothing to `scans` and the
    # assembly above it would still read "Never scanned". Ask for those projects'
    # scans by id. Nothing to top up on a portfolio run — the sweep already
    # covered them — beyond the orphans dropped for the tiles' sake, which are
    # legitimate dependency sources and are already in `all_scans`.
    out_of_scope_dep_ids = {
        dep_project_id
        for per_version in dep_trees.values()
        for deps in per_version.values()
        for dep_project_id, _ in deps
    } - in_scope_ids
    dep_scan_top_up: list[dict[str, Any]] = []
    dep_scan_fetch_failed: list[str] = []
    dep_scan_topup_skipped = 0
    if out_of_scope_dep_ids:
        topup_ids = out_of_scope_dep_ids
        if len(topup_ids) > _DEPENDENCY_SCAN_TOPUP_LIMIT:
            # Deterministic: same subset every run against the same data,
            # rather than whatever order a set happens to iterate in.
            ordered_ids = sorted(topup_ids)
            topup_ids = set(ordered_ids[:_DEPENDENCY_SCAN_TOPUP_LIMIT])
            dep_scan_topup_skipped = len(ordered_ids) - _DEPENDENCY_SCAN_TOPUP_LIMIT
        dep_scan_top_up, dep_scan_fetch_failed = _dependency_scans(
            api_client, topup_ids
        )
    # Only the VERSION-level maps of this rollup are read. Every project-level and
    # org-level figure still comes from the scoped `rollup`, so topping up here
    # cannot leak an out-of-scope project's scans into a tile or a chart.
    #
    # `all_scans` still carries every orphan, not just the out-of-FOLDER-scope
    # ones this walk means to recover — a scan referencing a project the org
    # inventory sweep never returned at all (permission gap, true orphan) is
    # in there too. Restricting to `org_project_ids` keeps the legitimate case
    # (an assembly's dependency sits in another folder, still a real project)
    # while dropping the one the banner promises is dropped everywhere: a
    # scan for a project this report cannot otherwise see must not silently
    # supply a "fresh" date through the one path that bypassed the org filter.
    org_visible_scans = [
        s for s in all_scans if _nested(s, "project", "id") in org_project_ids
    ]
    dep_rollup = (
        _ScanRollup(org_visible_scans + dep_scan_top_up)
        if (dep_scan_top_up or dropped_scan_count)
        else rollup
    )
    dep_coverage = _dependency_coverage(dep_trees, dep_rollup)
    if dep_lookups_skipped:
        notes.append(
            f"{dep_lookups_skipped} version(s) were not checked for project "
            f"dependencies: the walk stops after "
            f"{params['dependency_lookup_versions']} versions "
            "(dependency_lookup_versions). Projects behind that cap may still "
            "read “Never scanned” when a dependency of theirs was in fact "
            "scanned. Raise the parameter to widen the walk."
        )
    if dep_failures:
        notes.append(
            f"{dep_failures} dependency lookup(s) failed. Any project whose "
            "scanning happens only in its dependencies may read “Never scanned” "
            "as a result; the rest of the walk is unaffected."
        )
    if dep_lookups_capped:
        notes.append(
            f"{dep_lookups_capped} version(s) — anywhere in a resolved "
            "dependency tree, not only the root — returned 100 or more direct "
            "dependencies in one page; the dependency API returns only the "
            "first 100, so a version with exactly 100 is flagged even though "
            "it may have no more, and one with more is undercounted rather "
            "than complete. Affected assemblies may still read fewer "
            "dependency projects/scans than they actually have, though not "
            "zero."
        )
    if dep_scan_fetch_failed:
        notes.append(
            f"The scan history of {len(dep_scan_fetch_failed)} out-of-scope "
            "dependency project(s) could not be fetched, so an assembly that "
            "depends on them may read “Never scanned” even though the dependency "
            "was scanned. Only affects runs narrowed by --folder or --project."
        )
    if dep_scan_topup_skipped:
        notes.append(
            f"{dep_scan_topup_skipped} out-of-scope dependency project(s) beyond "
            f"the first {_DEPENDENCY_SCAN_TOPUP_LIMIT} were not queried for scan "
            "history; an assembly depending only on one of them may still read "
            "“Never scanned” even though the dependency was scanned. Only "
            "affects runs narrowed by --folder or --project with unusually wide "
            "dependency fan-out."
        )
    versions_with_scanned_deps: set[str] = set()
    for entry in dep_coverage.values():
        versions_with_scanned_deps |= entry["versions_with_scanned_deps"]

    window_floor = now - timedelta(days=params["scan_window_days"])
    prior_floor = now - timedelta(days=params["scan_window_days"] * 2)
    version_floor = now - timedelta(days=params["no_new_version_days"])
    window_counts = _project_window_counts(scans, window_floor)
    prior_counts = _project_window_counts(scans, prior_floor)

    # ── §C projects table (primary detail view) ──────────────────────────
    project_rows: list[dict[str, Any]] = []
    for record in projects:
        project_id = str(record.get("id") or "")
        folder_id = _nested(record, "folder", "id")
        folder_path = folder_path_by_id.get(folder_id, "") or _nested(
            record, "folder", "name"
        )
        own_versions = versions_by_project.get(project_id, [])
        newest_version_at: datetime | None = None
        latest_version = ""
        for version in own_versions:
            created_at = _parse_ts(version.get("created"))
            if newest_version_at is None or (
                created_at is not None and created_at > newest_version_at
            ):
                if created_at is not None:
                    newest_version_at = created_at
                    latest_version = str(
                        version.get("version") or version.get("name") or ""
                    )
        if not latest_version and own_versions:
            # Every version lacked a parseable created date — still name one
            # rather than leaving the column blank as if there were none.
            latest_version = str(
                own_versions[0].get("version") or own_versions[0].get("name") or ""
            )

        last_completed = rollup.project_completed_at.get(project_id)
        days_since = rollup.days_since_completed(project_id, now)
        own_scan_count = int(rollup.project_scan_count.get(project_id, 0))
        mechanisms = rollup.project_mechanisms.get(project_id, set())
        artifact_types = rollup.project_types.get(project_id, set())

        # Inherit from the dependency tree ONLY where the project has nothing of
        # its own — an assembly is scanned through the projects it is built from,
        # and calling that "Never scanned" mislabels the one thing this table is
        # read for. Where the project has its own completed scan, its own figure
        # wins; the dependency columns still show what sits underneath it.
        dep = dep_coverage.get(project_id)
        dependency_projects = len(dep["dep_project_ids"]) if dep else 0
        dependency_scans = int(dep["scans"]) if dep else 0
        scan_source = "own" if own_scan_count else ""
        if last_completed is None and dep and dep["last_completed"] is not None:
            last_completed = dep["last_completed"]
            days_since = (now - last_completed).days
            scan_source = "dependencies"
        if not own_scan_count and dependency_scans:
            mechanisms = dep["mechanisms"] if dep else set()
            artifact_types = dep["types"] if dep else set()
        # UNKNOWN is claimed off whichever side supplied the values above, so a
        # dependency-fed row cannot print UNKNOWN for scans it does not have.
        effective_scan_count = own_scan_count or dependency_scans
        project_rows.append(
            {
                "project_name": str(record.get("name") or ""),
                "folder_path": folder_path,
                "created_by": str(record.get("createdBy") or ""),
                "status": "archived" if record.get("archived") else "active",
                "project_type": str(record.get("type") or ""),
                "created_date": _date_str(_parse_ts(record.get("created"))),
                "version_count": len(own_versions),
                "latest_version": latest_version,
                "latest_version_created": _date_str(newest_version_at),
                "last_scan_date": _date_str(last_completed),
                "days_since_last_scan": days_since,
                "freshness_bucket": _bucket(days_since, params),
                "scans_lifetime": own_scan_count,
                "scans_in_window": int(window_counts.get(project_id, 0)),
                # Kept OUT of scans_lifetime / scans_in_window on purpose: the
                # dependency project is itself a row in this table, so folding
                # its scans into the parent would double-count them in the
                # folder chart and every org-level total.
                "scan_source": scan_source,
                "dependency_projects": dependency_projects,
                "dependency_scans": dependency_scans,
                # UNKNOWN, not blank, when the project HAS scans but none of
                # them recorded a value: the platform returns mechanism: null on
                # some scans, and a blank cell there is indistinguishable from
                # "this project has no scans at all". Same distinction the
                # latest_scan_status column already makes with "none".
                "ingestion_methods": _joined(mechanisms)
                or ("UNKNOWN" if effective_scan_count else ""),
                "artifact_types": _joined(artifact_types)
                or ("UNKNOWN" if effective_scan_count else ""),
                "folder_id": folder_id,
                "project_id": project_id,
            }
        )

    # Folder first (folders are the platform's access boundary, so each folder
    # is a contiguous section that can be handed to its owning team), then
    # oldest-scanned first inside it — the work list reads top-down. Unfoldered
    # projects sort last; never-scanned projects sort to the top of their folder.
    project_rows.sort(
        key=lambda r: (
            # (1, "") rather than a high-codepoint sentinel string: the flag
            # sorts unfoldered projects last by construction instead of relying
            # on a noncharacter comparing greater than every real folder name.
            (0, r["folder_path"].lower()) if r["folder_path"] else (1, ""),
            -(
                r["days_since_last_scan"]
                if r["days_since_last_scan"] is not None
                else 10**7
            ),
            r["project_name"].lower(),
        )
    )
    projects_df = pd.DataFrame(project_rows)

    # ── §B folders table ─────────────────────────────────────────────────
    rows_by_folder: dict[str, list[dict[str, Any]]] = {}
    for row in project_rows:
        rows_by_folder.setdefault(str(row["folder_id"]), []).append(row)

    folder_rows: list[dict[str, Any]] = []
    for folder in folders:
        folder_id = str(folder.get("id") or "")
        members = rows_by_folder.get(folder_id, [])
        scan_dates = [r["last_scan_date"] for r in members if r["last_scan_date"]]
        parent_id = folder.get("parentFolderId")
        folder_rows.append(
            {
                "folder_path": folder_path_by_id.get(
                    folder_id, str(folder.get("name") or "")
                ),
                "folder_name": str(folder.get("name") or ""),
                "parent_folder": (
                    folder_path_by_id.get(str(parent_id), "") if parent_id else ""
                ),
                "created_by": str(folder.get("createdBy") or ""),
                # Folders return createdAt; projects and versions return created.
                # Both are read so a schema difference between endpoints
                # renders a date instead of a silent "unknown".
                "created_date": _date_str(
                    _parse_ts(folder.get("createdAt") or folder.get("created"))
                ),
                "projects": len(members),
                "active_projects": sum(1 for r in members if r["status"] == "active"),
                "archived_projects": sum(
                    1 for r in members if r["status"] == "archived"
                ),
                "versions": sum(int(r["version_count"]) for r in members),
                # ISO dates sort lexicographically, so max() is the latest.
                "last_scan_date": max(scan_dates) if scan_dates else "",
                "folder_id": folder_id,
            }
        )
    folder_rows.sort(key=lambda r: str(r["folder_path"]).lower())
    folders_df = pd.DataFrame(folder_rows)

    # ── §D versions table ────────────────────────────────────────────────
    version_rows: list[dict[str, Any]] = []
    for version in versions:
        version_id = str(version.get("id") or "")
        project_id = _nested(version, "project", "id")
        owner = project_by_id.get(project_id, {})
        owner_folder_id = _nested(owner, "folder", "id")
        version_rows.append(
            {
                "version_label": str(
                    version.get("version") or version.get("name") or ""
                ),
                "project_name": _nested(version, "project", "name")
                or str(owner.get("name") or ""),
                "folder_path": folder_path_by_id.get(
                    owner_folder_id, _nested(owner, "folder", "name")
                ),
                "branch": _nested(version, "branch", "name"),
                "created_date": _date_str(_parse_ts(version.get("created"))),
                "artifact_types": _joined(rollup.version_types.get(version_id, set()))
                or ("UNKNOWN" if rollup.version_scan_count.get(version_id) else ""),
                "ingestion_methods": _joined(
                    rollup.version_mechanisms.get(version_id, set())
                )
                or ("UNKNOWN" if rollup.version_scan_count.get(version_id) else ""),
                # "none" (not blank) so a reader can tell "no scan was ever
                # attempted" from a status the API returned as empty.
                "latest_scan_status": rollup.version_latest_status.get(version_id)
                or "none",
                "latest_scan_date": _date_str(rollup.version_latest_at.get(version_id)),
                "scan_count": int(rollup.version_scan_count.get(version_id, 0)),
                "version_id": version_id,
                "project_id": project_id,
            }
        )
    version_rows.sort(
        key=lambda r: (str(r["project_name"]).lower(), str(r["created_date"]))
    )
    versions_df = pd.DataFrame(version_rows)

    # ── §A executive summary tiles ───────────────────────────────────────
    bucket_counts = Counter(str(r["freshness_bucket"]) for r in project_rows)
    # Activity metrics exclude archived projects (spec §5: archived projects are
    # excluded from activity but still shown in inventory counts).
    activity_rows = [r for r in project_rows if r["status"] == "active"]

    # Both tiles read days_since_last_scan — the SAME whole-day figure the
    # freshness column prints — so a tile can never contradict the row beside it.
    def _within(row: dict[str, Any], window: int) -> bool:
        value = row["days_since_last_scan"]
        return value is not None and int(value) <= window

    active_recent = sum(
        1 for r in activity_rows if _within(r, params["activity_window_days"])
    )
    # "Stale" is the spec's definition — zero scans in the threshold window —
    # restricted to projects that have something to scan. Empty projects get
    # their own tile; never-scanned projects satisfy both this and the
    # never-scanned tile, which is inherent to the two definitions.
    stale_projects = sum(
        1
        for r in activity_rows
        if int(r["version_count"]) > 0 and not _within(r, params["stale_project_days"])
    )
    never_scanned = sum(
        1
        for r in project_rows
        if int(r["version_count"]) > 0 and not r["last_scan_date"]
    )
    # 0, not a count, when the /versions sweep failed: every version_count is
    # a manufactured zero then, and reporting them as "empty" would claim the
    # entire org has zero versions — the opposite of a floor, since it
    # overstates rather than understates a count we do not actually have.
    empty_projects = (
        0
        if versions_fetch_failed
        else sum(1 for r in project_rows if int(r["version_count"]) == 0)
    )

    scans_in_window = sum(int(v) for v in window_counts.values())
    scans_prior_window = max(
        sum(int(v) for v in prior_counts.values()) - scans_in_window, 0
    )

    trend_months = _month_series(now, params["trend_months"])
    trend_set = set(trend_months)

    summary: dict[str, Any] = {
        "total_folders": len(folder_rows),
        "total_projects": len(project_rows),
        "active_projects": sum(1 for r in project_rows if r["status"] == "active"),
        "archived_projects": sum(1 for r in project_rows if r["status"] == "archived"),
        "total_versions": len(version_rows),
        "scans_lifetime": len(scans),
        # Scans as FETCHED, before out-of-inventory records were dropped.
        # Keeps "0 scans counted" distinguishable from "0 scans fetched".
        "scans_fetched_total": scans_fetched_total,
        "scans_excluded_orphan": dropped_scan_count,
        "scan_window_days": params["scan_window_days"],
        "scans_in_window": scans_in_window,
        "scans_prior_window": scans_prior_window,
        "scans_window_delta": scans_in_window - scans_prior_window,
        "activity_window_days": params["activity_window_days"],
        "active_recent_projects": active_recent,
        "stale_project_days": params["stale_project_days"],
        "stale_projects": stale_projects,
        "never_scanned_projects": never_scanned,
        "empty_projects": empty_projects,
        # Projects whose freshness came from their dependency tree rather than
        # from a scan of their own. Non-zero means the Never-scanned and Stale
        # tiles above are lower than a dependency-blind reading would give them,
        # and correctly so.
        "dependency_scanned_projects": sum(
            1 for r in project_rows if r["scan_source"] == "dependencies"
        ),
        "dependency_lookups_skipped": dep_lookups_skipped,
        "dependency_lookup_failures": dep_failures,
        "dependency_lookups_capped": dep_lookups_capped,
        "dependency_scan_fetch_failures": len(dep_scan_fetch_failed),
        "dependency_scan_topup_skipped": dep_scan_topup_skipped,
        "no_new_version_days": params["no_new_version_days"],
        "freshness_thresholds": {
            "current_days": params["current_days"],
            "aging_days": params["aging_days"],
            "stale_days": params["stale_days"],
        },
        "scoped": scoped,
        # Surfaced so the template can banner it and a machine consumer can
        # reject the run rather than ingesting all-zero freshness as fact.
        "join_broken": join_broken,
        # Named sweeps that failed. Non-empty means every count below is a
        # floor, not a total — consumers should refuse to treat it as fact.
        "fetch_failures": fetch_failures,
        # True means the primary /scans sweep hit its hard page/record
        # ceiling before reaching full history — the same "floor, not a
        # total" caveat as fetch_failures, scoped to lifetime scan history.
        "scans_truncated": scans_truncated,
        "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
    }

    # ── §E activity & trend series ───────────────────────────────────────
    versions_per_month: Counter[str] = Counter()
    for version in versions:
        created_at = _parse_ts(version.get("created"))
        if created_at is not None:
            versions_per_month[_month_key(created_at)] += 1
    projects_per_month: Counter[str] = Counter()
    for record in projects:
        created_at = _parse_ts(record.get("created"))
        if created_at is not None:
            projects_per_month[_month_key(created_at)] += 1

    scans_trend: list[dict[str, Any]] = []
    for month in trend_months:
        completed_count = int(rollup.month_completed.get(month, 0))
        failed_count = int(rollup.month_failed.get(month, 0))
        finished = completed_count + failed_count
        scans_trend.append(
            {
                "month": month,
                "completed": completed_count,
                "failed": failed_count,
                "in_progress": int(rollup.month_other.get(month, 0)),
                # No denominator, no rate — an empty month prints blank, not 0%.
                "failure_rate_pct": (
                    round(failed_count / finished * 100, 1) if finished else None
                ),
            }
        )

    # Own series, so the declared chart spec resolves its own data on the
    # server-SVG (fragment / Command Center embed / PDF) path instead of the
    # chart existing only in interactive HTML. Months with no finished scan are
    # omitted rather than plotted as 0%: an idle month has no rate, and drawing
    # zero there claims a clean month.
    # EVERY trend month, with None where no scan finished. Filtering the idle
    # months out entirely made the server-SVG/PDF path draw a continuous line
    # that bridged them, while the interactive chart (connectNulls: false) drew a
    # gap — the same report telling two different stories about pipeline health
    # depending on render mode. None becomes NaN in the DataFrame the SVG
    # renderer builds, and a line plot breaks at NaN, so both paths now gap.
    failure_rate_trend: list[dict[str, Any]] = [
        {"month": row["month"], "failure_rate_pct": row["failure_rate_pct"]}
        for row in scans_trend
    ]

    growth_trend: list[dict[str, Any]] = [
        {
            "month": month,
            "new_projects": int(projects_per_month.get(month, 0)),
            "new_versions": int(versions_per_month.get(month, 0)),
        }
        for month in trend_months
    ]
    freshness_mix: list[dict[str, Any]] = [
        {"bucket": bucket, "count": int(bucket_counts.get(bucket, 0))}
        for bucket in BUCKET_ORDER
    ]

    ingestion_counter: Counter[str] = Counter()
    for scan in scans:
        occurred = _parse_ts(scan.get("completed")) or _parse_ts(scan.get("created"))
        if occurred is not None and _month_key(occurred) in trend_set:
            ingestion_counter[_enum(scan.get("mechanism")) or "UNKNOWN"] += 1
    ingestion_mix: list[dict[str, Any]] = [
        {
            "mechanism": mechanism,
            "label": INGESTION_LABELS.get(mechanism, mechanism),
            "count": int(count),
        }
        for mechanism, count in sorted(
            ingestion_counter.items(), key=lambda kv: (-kv[1], kv[0])
        )
    ]

    # Per-folder scan volume over the window, including an explicit unfoldered
    # bucket — otherwise a tenant that files nothing shows an empty chart.
    folder_scan_totals: Counter[str] = Counter()
    for row in project_rows:
        label = str(row["folder_path"]) or NO_FOLDER_LABEL
        folder_scan_totals[label] += int(row["scans_in_window"])
    scans_by_folder: list[dict[str, Any]] = [
        # folder_path is the full breadcrumb, for the interactive tooltip;
        # folder_path_short is what the declared chart actually plots (both
        # the interactive y-axis and the server-SVG/PDF path), so a deep
        # breadcrumb can't overflow one render mode and not the other.
        {
            "folder_path": label,
            "folder_path_short": _ellipsize_tail(label),
            "scans": int(count),
        }
        for label, count in sorted(
            folder_scan_totals.items(), key=lambda kv: (-kv[1], kv[0])
        )
        if count > 0
    ]

    # ── §F hygiene flags ─────────────────────────────────────────────────
    hygiene_rows: list[dict[str, Any]] = []

    def _flag(flag: str, entity_type: str, name: str, detail: str) -> None:
        hygiene_rows.append(
            {
                "flag": flag,
                "entity_type": entity_type,
                "entity": name,
                "detail": detail,
            }
        )

    for row in project_rows:
        if not row["created_by"]:
            _flag(
                "No creator recorded",
                "project",
                str(row["project_name"]),
                "The platform records createdBy, not an owner; this project has "
                "neither.",
            )
        if not row["folder_path"]:
            _flag(
                "Orphaned (no folder)",
                "project",
                str(row["project_name"]),
                "Not filed under any folder, so it inherits no folder-level "
                "access grant.",
            )
        # Both flags below read version_count as ground truth to decide
        # between "nothing to scan" and "has versions but never scanned" — a
        # distinction a failed /versions sweep cannot support, since every
        # project's count is a manufactured zero rather than a real one. Skip
        # both rather than let the manufactured zero fall through to "Empty
        # project", or its false-negative into "Never scanned" reading
        # "0 version(s) uploaded" as fact.
        if versions_fetch_failed:
            pass
        elif int(row["version_count"]) == 0:
            _flag(
                "Empty project",
                "project",
                str(row["project_name"]),
                f"Created {row['created_date'] or 'unknown'}; zero versions.",
            )
        elif not row["last_scan_date"]:
            _flag(
                "Never scanned",
                "project",
                str(row["project_name"]),
                f"{row['version_count']} version(s) uploaded, no completed scan."
                + (
                    f" Its {row['dependency_projects']} dependency project(s) "
                    "carry no completed scan either."
                    if row["dependency_projects"]
                    else ""
                ),
            )

    for row in folder_rows:
        if int(row["projects"]) == 0:
            _flag(
                "Empty folder",
                "folder",
                str(row["folder_path"]),
                f"Created {row['created_date'] or 'unknown'}; zero projects in "
                "scope.",
            )

    for row in version_rows:
        # A version whose dependency tree WAS scanned is an assembly, not a
        # neglected upload — flagging it sent teams looking for a scan that was
        # never supposed to run on it.
        if int(row["scan_count"]) == 0 and row["version_id"] not in (
            versions_with_scanned_deps
        ):
            _flag(
                "Version never scanned",
                "version",
                f"{row['project_name']} @ {row['version_label']}",
                "Artifact uploaded, no scan record of any status.",
            )

    # Active projects with no new version inside the window. Distinct from
    # "stale" (no recent scan): this catches a project nobody is shipping to,
    # which is a lifecycle question rather than a scanning one.
    for row in activity_rows:
        if int(row["version_count"]) == 0:
            continue
        newest = _parse_ts(row["latest_version_created"])
        if newest is None or newest < version_floor:
            _flag(
                f"No new version in {params['no_new_version_days']}d",
                "project",
                str(row["project_name"]),
                "Still marked active; newest version "
                f"{row['latest_version_created'] or 'unknown'}.",
            )

    # Near-duplicate project names — cheap normalisation only (case, and the
    # separators teams vary between: space / hyphen / underscore / dot). A
    # sprawl hint, not a matcher: "fms-el-web" and "fms el web" collide, but
    # "web-backend" and "webbackend-v2" do not.
    # ponytail: normalise-and-group, O(n). Swap in a similarity metric only if
    # real sprawl turns out to hide behind edits bigger than separators.
    # Deliberately spans active + archived and every folder tree: an archived
    # predecessor renamed and recreated under an active successor is exactly
    # the sprawl case a per-scope or active-only version of this hint would
    # miss, and it is a common one. Narrowing it trades a real, common finding
    # for fewer false positives on a heuristic that already tells the reader
    # it is a hint, not a defect.
    name_groups: dict[str, list[str]] = {}
    for row in project_rows:
        key = "".join(ch for ch in str(row["project_name"]).lower() if ch.isalnum())
        if key:
            name_groups.setdefault(key, []).append(str(row["project_name"]))
    for names in name_groups.values():
        if len(names) > 1:
            _flag(
                "Near-duplicate project names",
                "project",
                ", ".join(sorted(names)),
                "Names differ only by case, separators or punctuation — possible "
                "sprawl from teams not reusing an existing project.",
            )

    # HTML and Markdown banner a broken join or a failed sweep above the numbers
    # they invalidate. CSV and XLSX have nowhere to put a banner, so the warning
    # rides the hygiene table's first rows instead — it is the one table that
    # ships to every format, so a consumer loading only the tabular export still
    # sees that the figures beside it are a floor or a fiction.
    if fetch_failures:
        hygiene_rows.insert(
            0,
            {
                "flag": "Report incomplete",
                "entity_type": "report",
                "entity": ", ".join(fetch_failures) + " sweep(s) failed",
                "detail": "Every count in this run is a floor, not a total, and "
                "its zeros mean “not fetched”, not “none exist”.",
            },
        )
    if join_broken:
        hygiene_rows.insert(
            0,
            {
                "flag": "Scan figures invalid",
                "entity_type": "report",
                "entity": "All scan-derived columns",
                "detail": "No fetched scan references any project in scope, so "
                "scan counts, freshness and the trends read zero regardless of "
                "the real state. Only the inventory columns are trustworthy.",
            },
        )
    if scans_truncated:
        hygiene_rows.insert(
            0,
            {
                "flag": "Scan history truncated",
                "entity_type": "report",
                "entity": "Scan-derived columns",
                "detail": "The scan fetch hit its page/record ceiling before "
                "reaching full history; scan counts, freshness dates and "
                "“Never scanned” may be understated for older or "
                "high-volume tenants.",
            },
        )

    hygiene_df = pd.DataFrame(hygiene_rows)
    hygiene_summary: list[dict[str, Any]] = [
        {"flag": flag, "count": int(count)}
        for flag, count in sorted(
            Counter(str(r["flag"]) for r in hygiene_rows).items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
    ]

    # ── scope + gap disclosure ───────────────────────────────────────────
    notes.extend(
        [
            "Freshness is measured from the most recent COMPLETED scan on any of "
            "a project's versions, against the report run time — not against "
            "--period. This is an assessment report; --period does not filter it.",
            "Owner is not a platform field. “Created by” is the recording user "
            "(the projects/folders API's createdBy), so “No creator recorded” is "
            "a metadata gap, not an unowned asset.",
            "The projects API exposes no tags or labels. Project type "
            "(application / firmware / container / …) is shown in their place.",
            "Artifact type and ingestion method read UNKNOWN when a project or "
            "version has scans but none of them recorded a value — the platform "
            "returns a null mechanism on some scans. A blank cell means no scans "
            "at all, which is a different thing.",
            "Artifact type and ingestion method are not stored on a version; both "
            "are derived from that version's scans (scan.type and "
            "scan.mechanism). A version with no scans shows neither — that is the "
            "“Version never scanned” flag.",
            "Scan outcome classification: COMPLETED is completed; ERROR and "
            "UPLOAD_FAILED are failed; every other status counts as in progress. "
            "Scan Analysis applies a stricter rule that also fails a "
            "non-COMPLETED SBOM/source import, so the two failure rates differ "
            "by design.",
            "Archived projects are excluded from the activity tiles (Active, "
            "Inactive) and from the no-new-version flag, but are included in "
            "inventory counts and in every table.",
            "“Inactive” (the tile) and “Stale” (the freshness bucket) are "
            "deliberately different words for a reason: they use different "
            f"thresholds ({params['stale_project_days']} days vs "
            f"{params['stale_days']} days) over different populations — the "
            "tile counts active projects with at least one version, the "
            "bucket counts every project including archived and empty ones. "
            "Among ACTIVE projects, never-scanned ones also satisfy the "
            "Inactive definition, so those two tiles overlap by construction. "
            "The overlap does not extend to archived projects: Never scanned "
            "and Empty count every project, while Inactive counts active ones "
            "only, so an archived never-scanned project raises the first "
            "without the second. Empty projects are excluded from Inactive "
            "entirely — they have nothing to scan.",
            f"“Active · {params['activity_window_days']}d” measures SCANNING, not "
            "engagement: it counts active projects whose last-scan date falls "
            "inside the window — including an assembly whose date was inherited "
            "from its dependency tree, so the tile agrees with the freshness "
            "column rather than contradicting it. Check the Source column before "
            "reading a count here as scans of the projects themselves. A project "
            "that shipped a new version yesterday but has not been scanned is not "
            "counted, so read this as scan cadence rather than adoption — version "
            "growth in the trend charts is the better adoption signal.",
            "The freshness distribution buckets EVERY project, including empty "
            "ones, which land in “Never scanned” because they have no completed "
            "scan. Its “Never scanned” slice therefore exceeds the "
            "“Never scanned” tile by the number of empty projects "
            f"({empty_projects} here); the tile follows the spec's definition, "
            "which requires at least one version.",
            "Project dependencies are followed. A project holding versions but "
            "no completed scan of its own is an assembly, so its dependency tree "
            "is resolved transitively and its last-scan date, days-since and "
            "freshness bucket are taken from the newest COMPLETED scan anywhere "
            "in that tree. The “Source” column says which: “own”, "
            "“dependencies”, or blank when there is neither. Such a project is "
            "therefore no longer counted as Never scanned or Inactive — the "
            "component that is actually scanned is one edge down.",
            "Dependency scan counts are reported in their own column and are "
            "deliberately NOT added to Scans (all) / Scans (window), the folder "
            "chart or any org total: the dependency project has its own row in "
            "this report, so folding its scans into the parent would count them "
            "twice. A project fed by dependencies keeps zeros in its own scan "
            "columns, which is accurate.",
            "Single organization per run: the API token scopes a run to one org, "
            "so there is no cross-tenant level in this report.",
        ]
    )

    json_package = {
        "meta": {
            "recipe": "Platform Usage",
            "generated_at": summary["generated_at"],
            "thresholds": params,
            "notes": notes,
        },
        "summary": summary,
        "folders": folder_rows,
        "projects": project_rows,
        "versions": version_rows,
        "hygiene": hygiene_rows,
        "hygiene_summary": hygiene_summary,
        "trends": {
            "scans_by_month": scans_trend,
            "failure_rate_trend": failure_rate_trend,
            "growth_by_month": growth_trend,
            "freshness_mix": freshness_mix,
            "ingestion_mix": ingestion_mix,
            "scans_by_folder": scans_by_folder,
        },
    }

    return {
        "main": projects_df,
        "usage_summary": summary,
        "project_table": project_rows,
        "folder_table": folder_rows,
        "version_table": version_rows,
        "hygiene": hygiene_rows,
        "hygiene_summary": hygiene_summary,
        "scans_trend": scans_trend,
        "failure_rate_trend": failure_rate_trend,
        "growth_trend": growth_trend,
        "freshness_mix": freshness_mix,
        "ingestion_mix": ingestion_mix,
        # The single source of truth for the ingestion mechanism -> label
        # text the chart legend uses, so the HTML template's chip rendering
        # can read the same names instead of hand-copying them and risking
        # drift between the chart and the table beside it.
        "ingestion_labels": dict(INGESTION_LABELS),
        "scans_by_folder": scans_by_folder,
        "usage_notes": notes,
        "extra_tables": {
            "Folders": folders_df,
            "Versions": versions_df,
            "Hygiene": hygiene_df,
        },
        "json_package": json_package,
    }
