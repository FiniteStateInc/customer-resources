# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Main report engine for orchestrating the reporting process."""

import base64
import datetime as _datetime
import gc
import hashlib
import importlib
import logging
import mimetypes
import os
import platform
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import resource  # Unix only; not available on Windows
except ImportError:
    resource = None  # type: ignore[assignment]
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import Any

import httpx
import pandas as pd

from fs_report.api_client import APIClient
from fs_report.data_cache import DataCache
from fs_report.data_transformer import DataTransformer
from fs_report.dependency_resolver import DependencyNode, DependencyResolver
from fs_report.models import (
    AxisConfig,
    ComparisonRecipe,
    CompoundRecipe,
    Config,
    FailedSection,
    QueryConfig,
    QueryParams,
    Recipe,
    RenderedFragment,
    ReportData,
    SectionRef,
    SectionResult,
)
from fs_report.recipe_loader import RecipeLoader, RecipeSlugCollision
from fs_report.recipe_requirements import recipe_requirements
from fs_report.renderers import ReportRenderer
from fs_report.scope_ref import ResolvedScope, ScopeRef, ScopeRefError
from fs_report.scope_ref import parse as _parse_scope_ref
from fs_report.slug import slug as _slug
from fs_report.sqlite_cache import _trim_factors


@dataclass
class RecipeResult:
    """Per-recipe result data for headless JSON summary."""

    recipe: str
    output_dir: str
    files: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunResult:
    """Overall run result returned by ``ReportEngine.run()``."""

    success: bool
    recipes: list[RecipeResult] = field(default_factory=list)
    # Actionable failure message for the CLI to surface to the user instead of
    # the generic "Report generation failed!" banner. Populated on validation
    # failures (axis scope-flag checks, axis-compound missing-scope prechecks)
    # so the user sees e.g. "pass --left and --right" or "run via fs-report
    # compare". None when there's no single actionable message. (M1-3, M1-4.)
    error_message: str | None = None


# Raw API columns that _normalize_columns already extracts into flat
# columns (component_name, has_exploit, reachability_score, etc.).
# Safe to drop after per-batch scoring to reclaim ~1 KB/row.
_TRIAGE_DROP_AFTER_SCORE: frozenset[str] = frozenset(
    {
        # Nested dicts (biggest memory hogs — ~500 bytes each)
        "component",
        "project",
        "projectVersion",
        # List/dict fields consumed by _normalize_columns
        "exploitInfo",
        "reachability",
        "factors",
        # Flat API fields already normalized into snake_case columns
        "cwes",
        "attackVector",
        "epssPercentile",
        "epssScore",
        "reachabilityScore",
        "hasKnownExploit",
        "inKev",
        "inVcKev",
        "affectedFunctions",
        "findingId",
        "projectId",
        # Dot-notation columns from json_normalize (if pre-flattened)
        "component.name",
        "component.version",
        "component.vcId",
        "component.id",
        "project.name",
        "project.id",
        "projectVersion.id",
        "projectVersion.version",
    }
)


# Columns the Executive Summary actually uses.  Everything else is
# dropped per-batch during fetch to avoid accumulating ~50+ columns
# (nested dicts, exploit info, etc.) across 500K+ rows.
_EXEC_SUMMARY_KEEP: frozenset[str] = frozenset(
    {"id", "project.name", "severity", "status", "detected"}
)


# Per-facet row-list keys a comparison transform emits, exposed on
# ``RenderedFragment.rows`` for the compound exec Action Plan (spec §5a).
_COMPARISON_ROW_KEYS: tuple[str, ...] = (
    "port_fixes_left_to_right",
    "port_fixes_right_to_left",
    "version_skew",
    "triaged_left_untriaged_right",
    "triaged_right_untriaged_left",
    "status_divergence",
)


def _extract_comparison_rows(data: Any) -> dict[str, Any] | None:
    """Extract the comparison facet row lists from a child transform dict.

    ``data`` is the child ``report_data.data`` — the transform's output dict
    for a comparison child, or anything else for a non-comparison child.
    Returns a dict carrying only the :data:`_COMPARISON_ROW_KEYS` actually
    present (defensive, mirrors how ``summary`` is extracted), or ``None`` when
    ``data`` isn't a dict or carries none of the row keys (non-comparison
    children). The exec Action Plan tolerates missing facets, so a partial dict
    is fine.
    """
    if not isinstance(data, dict):
        return None
    rows = {k: data[k] for k in _COMPARISON_ROW_KEYS if k in data}
    return rows or None


def _prune_exec_summary(
    df: pd.DataFrame,
    extra_keep: frozenset[str] | None = None,
) -> pd.DataFrame:
    """Extract ``project.name`` and keep only the columns Executive Summary needs.

    This is called per-batch during fetch so large nested-dict columns
    (component, project, exploitInfo, …) are freed immediately, reducing
    peak memory from ~4-5 GB to ~100 MB on folders with 500K+ findings.
    """
    # Extract project.name from nested dict if not already flat
    if "project.name" not in df.columns and "project" in df.columns:
        df = df.copy()
        df["project.name"] = df["project"].apply(
            lambda p: p.get("name", "") if isinstance(p, dict) else ""
        )
    else:
        df = df.copy()

    keep = _EXEC_SUMMARY_KEEP | extra_keep if extra_keep else _EXEC_SUMMARY_KEEP
    # Derive exploit-signal scalars (inKev/inVcKev/is_real_exploit) BEFORE the
    # column drop, while the heavy exploitInfo/exploitMaturity columns are
    # still present — they are dropped just below, so the memory win is
    # preserved. Gated on the keep-set so this only runs for Exec Summary
    # (which sets _exec_extra_keep to include the scalars); other callers pay
    # nothing. See C1/C2 (2026-06-14 pre-release fixes).
    if keep & {"inKev", "inVcKev", "is_real_exploit"}:
        df = _derive_exec_exploit_scalars(df)
    drop = [c for c in df.columns if c not in keep]
    if drop:
        df = df.drop(columns=drop)
    return df


def _derive_exec_exploit_scalars(df: pd.DataFrame) -> pd.DataFrame:
    """Add the Executive Summary exploit-signal scalar columns in place.

    Computes ``inKev`` / ``inVcKev`` (coerced to clean booleans) and
    ``is_real_exploit`` from each raw finding. Folded into ``_prune_exec_summary``
    so all seven per-batch prune call sites get the scalars with one edit
    rather than per-site duplication (mirrors the Findings-by-Project
    pre-flatten intent). Idempotent: a second pass after pruning reuses the
    already-computed ``is_real_exploit`` column.
    """
    from fs_report.transforms.pandas.executive_exploit_signals_transform import (
        _bool_series,
    )
    from fs_report.transforms.pandas.executive_exploit_signals_transform import (
        is_real_exploit as _is_real_exploit,
    )

    # Coerce via the shared helper so NaN/None and falsey string renderings
    # ("false"/"0"/…) normalize to False (missing column → all-False).
    for col in ("inKev", "inVcKev"):
        df[col] = _bool_series(df, col)
    if "is_real_exploit" not in df.columns:
        if df.empty:
            df["is_real_exploit"] = pd.Series(dtype=bool)
        else:
            df["is_real_exploit"] = df.apply(
                lambda r: _is_real_exploit(r.to_dict()), axis=1
            )
    return df


# Columns the Executive Dashboard actually uses.  Everything else is
# dropped per-batch during fetch, same pattern as Executive Summary.
_EXEC_DASHBOARD_KEEP: frozenset[str] = frozenset(
    {
        "id",
        "severity",
        "status",
        "detected",
        "category",
        "type",
        "projectId",
        "inKev",
        "in_kev",
        "hasKnownExploit",
        "has_known_exploit",
    }
)


def _prune_exec_dashboard(
    df: pd.DataFrame,
    extra_keep: frozenset[str] | None = None,
) -> pd.DataFrame:
    """Extract ``projectId`` and keep only the columns Executive Dashboard needs.

    This is called per-batch during fetch so large nested-dict columns
    (component, project, exploitInfo, …) are freed immediately.
    """
    df = df.copy()
    # Extract projectId from nested dict if not already flat
    if "projectId" not in df.columns and "project" in df.columns:
        df["projectId"] = df["project"].apply(
            lambda p: p.get("id", "") if isinstance(p, dict) else ""
        )

    keep = _EXEC_DASHBOARD_KEEP | extra_keep if extra_keep else _EXEC_DASHBOARD_KEEP
    drop = [c for c in df.columns if c not in keep]
    if drop:
        df = df.drop(columns=drop)
    return df


# Columns the Component Vulnerability Analysis transform actually uses.
# Everything else is dropped per-batch after flattening.
_CVA_KEEP: frozenset[str] = frozenset(
    {
        "id",
        "severity",
        "risk",
        "component.name",
        "component.version",
        "project.name",
        "inKev",
        "inVcKev",
        "hasKnownExploit",
        "epssPercentile",
        "reachabilityScore",
        "exploitInfo",
    }
)


def _prune_cva(
    df: pd.DataFrame,
    extra_keep: frozenset[str] | None = None,
) -> pd.DataFrame:
    """Keep only the columns Component Vulnerability Analysis needs.

    This is called per-batch (after flatten) during fetch so unused
    columns are freed immediately.
    """
    df = df.copy()
    keep = _CVA_KEEP | extra_keep if extra_keep else _CVA_KEEP
    drop = [c for c in df.columns if c not in keep]
    if drop:
        df = df.drop(columns=drop)
    return df


def _log_memory(logger: logging.Logger, label: str) -> None:
    """Log current process memory usage (RSS) for diagnostics."""
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # macOS reports ru_maxrss in bytes; Linux reports in kilobytes
        if platform.system() == "Darwin":
            rss_mb = usage.ru_maxrss / (1024 * 1024)
        else:
            rss_mb = usage.ru_maxrss / 1024
        logger.info(f"[Memory] {label}: {rss_mb:.0f} MB peak RSS")
    except Exception:
        pass  # Don't let memory logging break the report


def _inject_folder_names_df(df: pd.DataFrame, pf_map: dict[str, str]) -> None:
    """Add folder_name column to DataFrame using project-to-folder mapping."""

    def _extract_pid(row: pd.Series) -> str:
        p = row.get("project") or row.get("projectId")
        if isinstance(p, dict):
            return str(p.get("id", ""))
        return str(p) if p else ""

    df["folder_name"] = df.apply(_extract_pid, axis=1).map(pf_map).fillna("")


def _inject_project_names_df(df: pd.DataFrame, project_map: dict[str, str]) -> None:
    """Add project_name column to DataFrame using project ID mapping."""

    def _extract_name(row: pd.Series) -> str:
        p = row.get("project") or row.get("projectId")
        if isinstance(p, dict):
            name = p.get("name")
            if name:
                return str(name)
            return project_map.get(str(p.get("id", "")), str(p.get("id", "")))
        return project_map.get(str(p), str(p)) if p else ""

    df["project_name"] = df.apply(_extract_name, axis=1)


# Finding type/category mapping for --finding-types flag
#
# The API has two filtering mechanisms:
#   - `?type=` URL parameter: accepts exactly cve, sast, thirdparty, all
#     (single value only; verified against the server's own enum error)
#   - `category==` RSQL filter: accepts CVE, SAST_ANALYSIS, CREDENTIALS,
#     CONFIG_ISSUES, CRYPTO_MATERIAL (uppercase)
#
# Routing strategy:
#   - "all" → no filter (returns everything)
#   - cve only → category==CVE (preserves reachabilityScore that ?type=cve drops)
#   - sast only → ?type=sast
#   - thirdparty only → ?type=thirdparty
#   - any combination of {cve, sast, credentials, config_issues, crypto_material}
#     → category=in=(...) RSQL filter
#   - thirdparty mixed with other types → no clean way to combine in one query;
#     thirdparty is dropped with a logged warning and the rest filtered via
#     category=in=(...). To include only thirdparty findings, run with
#     --finding-types thirdparty alone, or use --finding-types all.
#
# binary_sca and source_sca were historically advertised as --finding-types
# values but were never functional (the API has no equivalent filter — they're
# scan types, not finding types). They're stripped by the CLI with a
# deprecation warning before reaching this function.
CATEGORY_VALUES = {"credentials", "config_issues", "crypto_material", "sast_analysis"}
TYPE_VALUES = {"cve", "sast", "thirdparty"}
CATEGORY_MAP = {
    "credentials": "CREDENTIALS",
    "config_issues": "CONFIG_ISSUES",
    "crypto_material": "CRYPTO_MATERIAL",
    "sast_analysis": "SAST_ANALYSIS",
    "cve": "CVE",
}
# CLI type → API category values (uppercase, per Swagger). Only types that
# have a documented category mapping. `thirdparty` has no category equivalent
# and is handled separately by the URL-param route.
TYPE_TO_CATEGORY = {
    "cve": ["CVE"],
    "sast": ["SAST_ANALYSIS"],
}


def _strip_project_scope(filter_str: str | None) -> str | None:
    """Strip `project==X` and `project=in=(...)` clauses from an RSQL filter.

    Use when the filter is being combined with a more specific
    ``projectVersion==`` / ``projectVersion=in=(...)`` clause — the project
    *inclusion* scope is then redundant. Keeping it bloats the URL with
    the full project list (large folders => HTTP 414). Caller passes the
    result to a query that already scopes by version IDs.

    Only inclusion operators (``project==`` and ``project=in=``) are
    stripped. Exclusion operators (``project!=`` and ``project=out=``) are
    deliberately preserved — those carry filter semantics ("exclude this
    project") that a version-ID list does not encode, so removing them
    would change the result set.

    ``projectVersion`` clauses are also preserved (different field).

    Returns the filter with redundant clauses removed, or ``None`` if
    nothing remains. ``None`` / empty-string inputs pass through unchanged
    (both indicate "no filter").
    """
    if not filter_str:
        return filter_str
    kept: list[str] = []
    for part in filter_str.split(";"):
        stripped = part.strip()
        # Keep projectVersion clauses untouched (different field name).
        if stripped.startswith("projectVersion"):
            kept.append(part)
            continue
        if stripped.startswith("project==") or stripped.startswith("project=in="):
            continue
        kept.append(part)
    return ";".join(kept) if kept else None


def build_findings_type_params(finding_types: str) -> dict[str, Any]:
    """
    Build API parameters for finding type/category filtering.

    Returns a dict with `type` (URL param) and `category_filter` (RSQL).
    Exactly one of them is populated, or both are None for "fetch everything".

    Args:
        finding_types: Comma-separated finding types from config.
    """
    logger = logging.getLogger("fs-report.report_engine")

    values = [v.strip().lower() for v in finding_types.split(",")]

    # Drop legacy fictitious values that were never functional. The CLI
    # surfaces these as a deprecation warning, so this is a safety net for
    # callers that bypass CLI validation (programmatic use, recipe params).
    fake = [v for v in values if v in {"binary_sca", "source_sca"}]
    if fake:
        logger.warning(
            "Ignoring --finding-types value(s) %s — these are scan types, not "
            "finding-type filters; the API has no equivalent filter.",
            ",".join(sorted(set(fake))),
        )
        values = [v for v in values if v not in {"binary_sca", "source_sca"}]

    # "all" anywhere in the list wins — fetch everything, no filter.
    if "all" in values:
        return {"type": None, "category_filter": None}

    categories = [v for v in values if v in CATEGORY_VALUES]
    simple_types = [v for v in values if v in TYPE_VALUES]

    # If stripping fakes left nothing, fall back to the default cve filter.
    if not categories and not simple_types:
        return {"type": "cve", "category_filter": None}

    # CVE-only: use category==CVE RSQL (preserves reachabilityScore that
    # ?type=cve silently drops — see API quirk #2 in CLAUDE.md memory).
    if simple_types == ["cve"] and not categories:
        return {"type": None, "category_filter": "category==CVE"}

    # Single non-CVE type alone: use the URL param directly.
    if (
        len(simple_types) == 1
        and simple_types[0] in ("sast", "thirdparty")
        and not categories
    ):
        return {"type": simple_types[0], "category_filter": None}

    # Multi-type or named-category path: build a category=in=(...) RSQL filter.
    # `thirdparty` cannot be combined with category filters in a single API
    # query (no `category` enum equivalent, and the response `type` field is
    # unreliable for post-filtering — see fs-report-finding-types report).
    # Drop it with a warning and filter the rest via category.
    if "thirdparty" in simple_types and (categories or len(simple_types) > 1):
        logger.warning(
            "--finding-types includes 'thirdparty' alongside other types. "
            "There is no API filter that combines `?type=thirdparty` with "
            "`category=in=(...)`, so 'thirdparty' will be excluded from "
            "this run. Run with `--finding-types thirdparty` alone, or use "
            "`--finding-types all`, to include thirdparty findings."
        )
        simple_types = [t for t in simple_types if t != "thirdparty"]

    filter_categories: set[str] = set()
    for t in simple_types:
        filter_categories.update(TYPE_TO_CATEGORY.get(t, []))
    for c in categories:
        mapped_cat = CATEGORY_MAP.get(c)
        if mapped_cat:
            filter_categories.add(mapped_cat)

    if not filter_categories:
        # Only thirdparty was requested via a multi-type call — already
        # warned and stripped above; fall back to the default cve filter.
        return {"type": "cve", "category_filter": None}

    cats_sorted = sorted(filter_categories)
    if len(cats_sorted) == 1:
        return {"type": None, "category_filter": f"category=={cats_sorted[0]}"}
    return {"type": None, "category_filter": f"category=in=({','.join(cats_sorted)})"}


def _trim_versions_by_period(
    versions: list[dict],
    start_iso: str,
    end_iso: str,
) -> list[dict]:
    """Filter versions to a [start..end] window, including the most recent
    pre-window version as implicit baseline.

    Returns a list of version dicts: [predecessor?] + in_window (predecessor
    first when present). Caller-side sort may re-order afterward; the returned
    order reflects chronological "predecessor, then in-window oldest→newest".

    Versions with missing or unparseable `created` are dropped from
    consideration entirely — they cannot be in-window and cannot serve
    as predecessor.

    Args:
      versions: list of dicts with at least `{"id", "name", "created"}`.
        `created` is expected as ISO-8601 string (e.g. "2026-02-01T12:00:00Z").
      start_iso: "YYYY-MM-DD" window start (inclusive, 00:00:00 UTC).
      end_iso: "YYYY-MM-DD" window end (inclusive, 23:59:59 UTC).
    """
    window_start = f"{start_iso}T00:00:00Z"
    window_end = f"{end_iso}T23:59:59Z"

    dated: list[tuple[str, dict]] = []
    for v in versions:
        created = v.get("created")
        if not created or not isinstance(created, str):
            continue
        # Strict lexicographic validity check: first 10 chars must look
        # like YYYY-MM-DD. This catches obvious garbage like "not-a-date".
        if len(created) < 10 or created[4] != "-" or created[7] != "-":
            continue
        dated.append((created, v))

    in_window = [v for c, v in dated if window_start <= c <= window_end]
    pre_window = [(c, v) for c, v in dated if c < window_start]

    predecessor = None
    if pre_window:
        # Sort by created asc; last one is most recent pre-window.
        pre_window.sort(key=lambda cv: cv[0])
        predecessor = pre_window[-1][1]

    # Preserve in_window input order among its members; sort by `created` asc
    # so downstream sort still receives a deterministic list.
    in_window.sort(key=lambda v: v.get("created", ""))

    if predecessor is not None:
        return [predecessor] + in_window
    return in_window


class ReportCancelled(Exception):
    """Raised when a running report is cancelled via the web UI."""


class ReportEngine:
    """Main engine for generating reports from recipes."""

    def __init__(
        self,
        config: Config,
        data_override: dict[str, Any] | None = None,
        cancel_event: threading.Event | None = None,
        on_recipe_complete: Callable[[int, int, str], None] | None = None,
        on_recipe_start: Callable[[int, int, str], None] | None = None,
        on_section_start: Callable[[int, str], None] | None = None,
        on_section_complete: Callable[[int, str, bool], None] | None = None,
        deployment_context: Any | None = None,
        extra_recipes: list[Recipe] | None = None,
        scan_user_recipes: bool = True,
    ) -> None:
        """Initialize the report engine.

        Args:
            on_recipe_complete: Optional callback invoked after each recipe
                finishes.  Signature: ``(completed, total, recipe_name)``.
            on_recipe_start: Optional callback invoked just before each recipe
                begins processing (after its per-recipe cancel check + the
                requires-* pre-checks, so a skipped recipe fires neither hook).
                Signature: ``(index, total, recipe_name)``.  Used by the web
                run-canvas to light a plain-report node "running" (T5); the CLI
                never supplies it.
            on_section_start: Optional callback invoked just before a compound
                child section begins processing (after the per-child cancel
                check, so a cancelled child fires neither hook).  Signature:
                ``(child_index, child_name)``.  Fired only on the non-axis
                ``_process_compound`` path; the CLI never supplies it.
            on_section_complete: Optional callback invoked once per compound
                child that started, after its section result is recorded.
                Signature: ``(child_index, child_name, success)`` where
                ``success`` is True iff the child produced a rendered fragment
                (False for any failure path).  Fired only on the non-axis
                ``_process_compound`` path; the CLI never supplies it.
            deployment_context: Optional DeploymentContext for AI prompt customization.
            extra_recipes: Optional pre-constructed recipe objects merged into
                the loaded corpus (decision #10). B3.7's ``fs-report compare``
                uses this to execute an in-memory axis ``CompoundRecipe`` (plus
                its comparison children) without writing a temp YAML. An extra
                with the same slug as a loaded recipe OVERRIDES it (extra wins)
                — extras are explicit per-run injections that legitimately
                shadow disk recipes. See ``set_extra_recipes``.
            scan_user_recipes: When ``True`` (default), the loader also scans
                the user-recipes dir (``~/.fs-report/recipes/``) so saved
                compound bundles AND user-defined comparison recipes are
                discoverable. CLI entrypoints (``fs-report run`` /
                ``fs-report compare``) opt in; programmatic / test consumers
                keep the default. Ignored when ``config.recipes_dir`` is set (an
                explicit overlay dir already supersedes the user scan).
        """
        self.config = config
        self._deployment_context = deployment_context
        self.logger = logging.getLogger(__name__)
        self._cancel_event = cancel_event
        self._on_recipe_complete = on_recipe_complete
        self._on_recipe_start = on_recipe_start
        self._on_section_start = on_section_start
        self._on_section_complete = on_section_complete

        # Initialize cache
        self.cache = DataCache()

        # Initialize components
        self.api_client = APIClient(
            config,
            cache=self.cache,
            cache_ttl=getattr(config, "cache_ttl", 0),
            cache_refresh=getattr(config, "cache_refresh", False),
        )
        # Secondary API client for cross-server version comparison
        if config.compare_domain and config.compare_auth_token:
            compare_config = Config(
                auth_token=config.compare_auth_token,
                domain=config.compare_domain,
                recipes_dir=config.recipes_dir,
                use_bundled_recipes=config.use_bundled_recipes,
                output_dir=config.output_dir,
                start_date=config.start_date,
                end_date=config.end_date,
                period_explicit=config.period_explicit,
                detailed_mode=config.detailed_mode,  # NEW
                verbose=config.verbose,
                finding_types=config.finding_types,
                request_delay=config.request_delay,
                batch_size=config.batch_size,
            )
            self.compare_api_client: APIClient | None = APIClient(
                compare_config, cache=DataCache()
            )
        else:
            self.compare_api_client = None

        self.recipe_loader = RecipeLoader(
            config.recipes_dir,
            use_bundled=getattr(config, "use_bundled_recipes", True),
            # CLI entrypoints opt into user-recipe discovery (~/.fs-report/recipes/)
            # for saved compound bundles AND user-defined comparison recipes.
            # Programmatic / test consumers of RecipeLoader keep the default
            # False.
            scan_user_recipes=scan_user_recipes,
        )

        # Pre-constructed recipe objects merged into the loaded corpus
        # (decision #10 — the extra_recipes seam used by `fs-report compare`).
        # set_extra_recipes() validates the in-memory list for self-collisions
        # at registration; run() merges them with OVERRIDE semantics (an extra
        # replaces a loaded recipe of the same slug — extra wins).
        self._extra_recipes: list[Recipe] = []
        if extra_recipes:
            self.set_extra_recipes(extra_recipes)

        # Initialize transformer (only pandas is used)
        self.transformer = DataTransformer()
        # self.logger.info("Using Pandas transformer")

        self.renderer = ReportRenderer(
            config.output_dir, config, overwrite=getattr(config, "overwrite", False)
        )
        self.data_override = data_override

        # Cache for latest version IDs when current_version_only is enabled
        self._latest_version_ids: list | None = None

        # In-memory cache: folder project IDs → latest version IDs (avoids re-resolving per report)
        self._folder_version_ids_cache: dict[str, list] = {}
        # In-memory cache: same key → {project_id: latest_version_id} mapping,
        # populated as a side effect of _get_latest_version_ids_for_projects so
        # callers (folder-scope resolution) can recover per-project provenance
        # from a single batch call without a second N+1 pass.
        self._folder_version_id_map_cache: dict[str, dict[str, Any]] = {}

        # In-memory cache: findings data keyed by (endpoint, filter, finding_type, version_ids_hash)
        # Avoids redundant API fetches when multiple reports need the same data
        # Stores DataFrames (not list[dict]) to reduce peak memory.
        # Scans cache entries may still store list[dict] for internal reuse.
        self._findings_cache: dict[str, Any] = {}

        # In-memory cache: per-version findings keyed by (endpoint, version_id, finding_type)
        # Shared across Version Comparison within the same run
        self._version_findings_cache: dict[str, list[dict]] = {}

        # In-memory cache: per-project version lists from /projects/{id}/versions
        self._project_versions_cache: dict[str, list[dict]] = {}

        # Cache for _fetch_all_folders() — avoids redundant API calls per run
        self._all_folders_cache: list[dict] | None = None

        # Cache for _build_project_folder_map_from_projects() — avoids re-fetching per recipe
        self._project_map_cache: dict[str, str] | None = None

        # Files produced by the last run() call
        self.generated_files: list[str] = []

        # Resolved project name (populated by _validate_and_resolve_filters)
        self.resolved_project_name: str | None = None

        # Folder scoping state (populated by _resolve_folder_scope in run())
        self._folder_project_ids: set[str] | None = None
        self._project_folder_map: dict[str, str] = {}  # project_id -> folder_name
        self._folder_name: str | None = None
        self._folder_path: str | None = None  # e.g. "Division A / Medical Products"

        # Dependency resolver for project dependency tree traversal
        self._dependency_resolver = DependencyResolver(self.api_client)

        # Cache: dependency tree per root version ID
        self._dependency_tree_cache: dict[int, DependencyNode] = {}

        # Current dependency tree for the active recipe run
        self._current_dependency_tree: DependencyNode | None = None

    def _resolve_dependency_tree(
        self,
        project_id: int | str,
        project_name: str,
        version_id: int,
    ) -> DependencyNode:
        """Resolve the dependency tree for a project version.

        When ``self.config.standalone`` is True, returns a single-node tree
        with no children (no dependency traversal).
        """
        if self.config.standalone:
            return DependencyNode(
                project_id=project_id,
                project_name=project_name,
                version_id=version_id,
                path=[project_name],
                children=[],
            )

        if version_id in self._dependency_tree_cache:
            return self._dependency_tree_cache[version_id]

        self.logger.info(
            f"Resolving dependency tree for {project_name} (version {version_id})..."
        )
        tree = self._dependency_resolver.resolve(
            project_id=project_id,
            project_name=project_name,
            version_id=version_id,
        )

        dep_count = len(tree.all_version_ids()) - 1
        if dep_count > 0:
            self.logger.info(f"Found {dep_count} dependencies for {project_name}")
        else:
            self.logger.info(f"No dependencies found for {project_name}")

        self._dependency_tree_cache[version_id] = tree
        return tree

    def _expand_version_ids_with_dependencies(
        self,
        version_ids: list,
        project_id: int | str,
        project_name: str,
    ) -> tuple[list, DependencyNode | None]:
        """Expand version IDs to include dependency project versions.

        For single-project mode (--project), resolves the dependency tree
        and returns all version IDs in the tree.

        Returns:
            Tuple of (expanded_version_ids, dependency_tree_or_None).
            The tree is None when no expansion happened (no project scope).
        """
        if len(version_ids) != 1:
            return version_ids, None

        root_version_id = version_ids[0]
        tree = self._resolve_dependency_tree(
            project_id=project_id,
            project_name=project_name,
            version_id=root_version_id,
        )

        expanded = tree.all_version_ids()
        return expanded, tree

    def _expand_folder_version_ids_with_dependencies(
        self,
        version_ids: list,
    ) -> tuple[list, DependencyNode | None]:
        """Expand version IDs for folder mode by resolving each project's deps.

        Builds a synthetic root DependencyNode whose children are per-project
        trees, so that annotation can produce correct dependency paths.

        Uses the same /projects batch + per-project fallback as
        ``_get_latest_version_ids_for_projects`` to build a version→project
        mapping, avoiding "unknown" nodes when the batch response omits
        ``defaultBranch``.

        Returns:
            Tuple of (expanded_version_ids, synthetic_tree_or_None).
            The tree is None when standalone mode or no dependencies found.
        """
        if self.config.standalone:
            return version_ids, None

        # Build version_id -> (project_id, project_name) mapping.
        # Step 1: Try batch /projects (same data already cached by DataCache).
        from fs_report.models import QueryConfig, QueryParams

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        all_projects = self.api_client.fetch_all_with_resume(projects_query)

        version_id_set = {str(v) for v in version_ids}
        vid_to_project: dict[str, tuple[str, str]] = {}
        for proj in all_projects:
            pid = proj.get("id")
            pname = proj.get("name", "")
            db = proj.get("defaultBranch") or {}
            lv = db.get("latestVersion") or {} if isinstance(db, dict) else {}
            vid = lv.get("id") if isinstance(lv, dict) else None
            if pid and vid is not None:
                vid_str = str(vid)
                if vid_str in version_id_set:
                    vid_to_project[vid_str] = (str(pid), pname)

        # Step 2: Fallback — for any version IDs not matched from batch,
        # look up project details individually (handles API responses that
        # omit defaultBranch in list payloads).
        unmapped = [v for v in version_ids if str(v) not in vid_to_project]
        if unmapped and self._folder_project_ids:
            self.logger.info(
                f"Folder dep expansion: {len(unmapped)} version(s) not matched "
                f"from batch /projects; trying per-project detail calls"
            )
            for pid_str in sorted(self._folder_project_ids):
                try:
                    url = f"{self.api_client.base_url}/public/v0/projects/{pid_str}"
                    resp = self.api_client.client.get(url)
                    resp.raise_for_status()
                    data = resp.json()
                    db = data.get("defaultBranch") or {}
                    lv = db.get("latestVersion") or {} if isinstance(db, dict) else {}
                    vid = lv.get("id") if isinstance(lv, dict) else None
                    if vid is not None:
                        vid_str = str(vid)
                        if vid_str in version_id_set and vid_str not in vid_to_project:
                            vid_to_project[vid_str] = (
                                str(pid_str),
                                data.get("name", pid_str),
                            )
                except Exception:
                    self.logger.debug(
                        f"Failed to fetch project detail for {pid_str}",
                        exc_info=True,
                    )
                # Stop once all unmapped versions are resolved
                if all(str(v) in vid_to_project for v in unmapped):
                    break

        # Resolve dependency tree per project
        all_expanded: list = []
        has_any_deps = False
        per_project_trees: list[DependencyNode] = []

        for vid in version_ids:
            proj_info = vid_to_project.get(str(vid))
            if not proj_info:
                # Still unmapped after fallback — include version without deps
                self.logger.debug(
                    f"Could not resolve project for version {vid}; "
                    "skipping dependency expansion for this version"
                )
                all_expanded.append(vid)
                per_project_trees.append(
                    DependencyNode(
                        project_id=0,
                        project_name=str(vid),
                        version_id=vid,
                        path=[str(vid)],
                        children=[],
                    )
                )
                continue

            proj_id, proj_name = proj_info
            tree = self._resolve_dependency_tree(proj_id, proj_name, vid)
            per_project_trees.append(tree)
            expanded = tree.all_version_ids()
            all_expanded.extend(expanded)
            if tree.has_dependencies:
                has_any_deps = True

        if not has_any_deps:
            return version_ids, None

        # Deduplicate while preserving order
        seen: set = set()
        deduped: list = []
        for vid in all_expanded:
            if vid not in seen:
                seen.add(vid)
                deduped.append(vid)

        # Build synthetic root for annotation
        synthetic_root = DependencyNode(
            project_id=0,
            project_name="__folder__",
            version_id=0,
            path=[],
            children=per_project_trees,
        )

        dep_count = len(deduped) - len(version_ids)
        self.logger.info(
            f"Folder dependency expansion: {len(version_ids)} projects "
            f"expanded to {len(deduped)} versions (+{dep_count} from dependencies)"
        )

        return deduped, synthetic_root

    @staticmethod
    def _cache_key(*parts: str | None) -> str:
        """Build a normalized cache key from *parts*.

        ``None`` values are coerced to the empty string and parts are
        joined with ``\\x00`` so that values containing ``|`` can never
        collide with a different combination of parts.
        """
        return "\x00".join(p if p is not None else "" for p in parts)

    def _check_cancel(self) -> None:
        """Raise ``ReportCancelled`` if the cancel event has been set."""
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise ReportCancelled("Report cancelled by user")

    def _cancellable_sleep(self, seconds: float) -> None:
        """Sleep ``seconds``, but in short chunks so a Stop takes effect promptly.

        The engine's own delays (batch cooldown, inter-request spacing, retry
        backoff) used plain ``time.sleep`` and so swallowed a Stop until the full
        delay elapsed — the batch cooldown (~15s) dominated portfolio wall-clock,
        making the run-view Stop feel dead (#13). This mirrors the NVD client's
        ``_cancellable_sleep``: check the cancel event at each chunk boundary
        (~0.5s) and raise ``ReportCancelled`` so cancellation lands within a chunk
        rather than after the whole sleep. With no cancel event it degrades to a
        plain sleep. (An in-flight network/LLM call is still not interruptible —
        the run cancels when that call returns.)
        """
        if self._cancel_event is None:
            time.sleep(max(0, seconds))
            return
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self._check_cancel()
            time.sleep(max(0, min(0.5, end - time.monotonic())))
        self._check_cancel()

    def _validate_numeric_project_id(self, project_id: int | str) -> bool:
        """Check whether *project_id* is a valid project in the API.

        Returns ``True`` if the API returns project data for this ID,
        ``False`` otherwise (e.g. 404 or non-project entity).
        """
        try:
            url = f"{self.api_client.base_url}/public/v0/projects/{project_id}"
            resp = self.api_client.client.get(url)
            if resp.status_code == 404:
                return False
            resp.raise_for_status()
            data = resp.json()
            # Sanity-check: the response should contain an "id" key matching
            # the requested project ID.
            return isinstance(data, dict) and data.get("id") is not None
        except Exception:
            return False

    def _resolve_project_name(self, project_name: str) -> int | str | None:
        """Delegate to APIClient.resolve_project (added 2026-05-24 for
        CRA Compliance, spec §0).

        Return type broadened from int | None to int | str | None
        because some FS tenants return string/UUID project IDs that the
        original signature silently coerced. The sole engine caller
        (line 2137) does str(resolved_id) and truthiness checks, so
        this widening is safe.
        """
        return self.api_client.resolve_project(project_name)

    @staticmethod
    def _is_id_like(value: str) -> bool:
        """Return True if *value* looks like an API ID (signed integer or UUID).

        Accepts an optional leading ``-`` because some Finite State tenants
        issue negative int64 project/version IDs.
        """
        import re

        if re.fullmatch(r"-?\d+", value):
            return True
        # UUID v4/v5 pattern (with or without hyphens)
        return bool(re.match(r"^[0-9a-fA-F-]{32,36}$", value))

    @staticmethod
    def _is_glob(value: str) -> bool:
        """Return True if *value* contains glob metacharacters (``*``, ``?``, ``[``)."""
        return any(c in value for c in ("*", "?", "["))

    def _resolve_project_glob(self, pattern: str) -> list[tuple[int | str, str]]:
        """Resolve a glob pattern against all project names.

        Returns a list of ``(id, name)`` tuples for every project whose name
        matches *pattern* (case-insensitive ``fnmatch``).  Also logs a warning
        if any project names collide when lowercased.
        """
        import fnmatch
        from collections import defaultdict

        from fs_report.models import QueryConfig, QueryParams

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        projects = self.api_client.fetch_data(projects_query)

        # Case-collision check across ALL projects
        by_lower: dict[str, list[str]] = defaultdict(list)
        for p in projects:
            name = p.get("name", "")
            if name:
                by_lower[name.lower()].append(name)
        for lower, names in by_lower.items():
            distinct = sorted(set(names))
            if len(distinct) > 1:
                self.logger.warning(
                    f"Case collision: projects {distinct} map to the same "
                    f"lowercase name '{lower}'. Glob matching is case-insensitive "
                    "and will match all of them."
                )

        # Match projects against the glob pattern
        pat_lower = pattern.lower()
        matches: list[tuple[int | str, str]] = []
        for p in projects:
            name = p.get("name", "")
            pid = p.get("id")
            if name and pid is not None and fnmatch.fnmatch(name.lower(), pat_lower):
                matches.append((pid, name))

        return matches

    def _resolve_project_id_to_name(self, project_id: int | str) -> str | None:
        """Resolve a project ID to its display name.

        Returns the project name, or None if the lookup fails.
        """
        try:
            url = f"{self.api_client.base_url}/public/v0/projects/{project_id}"
            resp = self.api_client.client.get(url)
            resp.raise_for_status()
            data = resp.json()
            return data.get("name") if isinstance(data, dict) else None
        except Exception:
            return None

    def _get_project_versions(self, project_id: int | str) -> list[dict]:
        """Fetch all versions for a project, walking pages and caching the
        result on the engine instance.

        Single source of truth for ``/public/v0/projects/{pid}/versions``
        — ``_resolve_version_name`` and ``_lookup_version_display_name``
        both go through here so we only hit the API once per project per
        run, regardless of who asks first. Returns an empty list on any
        error (callers must handle the empty-or-missing case).
        """
        pid_str = str(project_id)
        if pid_str in self._project_versions_cache:
            return self._project_versions_cache[pid_str]

        base_url = f"{self.api_client.base_url}/public/v0/projects/{pid_str}/versions"
        page_size = min(1000, self.api_client.max_page_size)
        versions: list[dict] = []
        offset = 0
        try:
            while True:
                resp = self.api_client.client.get(
                    base_url, params={"limit": page_size, "offset": offset}
                )
                resp.raise_for_status()
                page = resp.json()
                if not isinstance(page, list) or not page:
                    break
                versions.extend(page)
                if len(page) < page_size:
                    break
                offset += page_size
        except Exception as e:
            self.logger.debug(f"Error fetching versions for project {pid_str}: {e}")
            # Don't cache on error — let a future call retry.
            return versions

        self._project_versions_cache[pid_str] = versions
        return versions

    def _lookup_version_display_name(
        self, project_id: int | str, version_id: int | str
    ) -> str:
        """Resolve a version ID to its human-readable name.

        Inverse of _resolve_version_name. Returns ``str(version_id)`` on any
        failure so callers can blindly substitute without raising — used to
        backfill ``projectVersion.version`` on rows fetched from the
        version-scoped endpoint, which omits that field.
        """
        for v in self._get_project_versions(project_id):
            if str(v.get("id")) == str(version_id):
                name = v.get("version") or v.get("name")
                if name:
                    return str(name)
        return str(version_id)

    def _resolve_version_name(
        self, project_id: int | str, version_name: str
    ) -> int | str | None:
        """Resolve a version name to its API ID within a project.

        Performs a case-insensitive name match against the cached version
        list (see _get_project_versions). Returns the version ID, or None
        if not found.
        """
        versions = self._get_project_versions(project_id)
        if not versions:
            return None

        for v in versions:
            name = v.get("version") or v.get("name") or ""
            if str(name).lower() == version_name.lower():
                vid: int | str | None = v.get("id")
                return vid

        # Fuzzy hint: show close matches
        available = [
            str(v.get("version") or v.get("name") or "")
            for v in versions
            if v.get("version") or v.get("name")
        ]
        close = [n for n in available if version_name.lower() in n.lower()]
        if close:
            self.logger.info(f"Did you mean one of these versions? {close[:5]}")

        return None

    def _resolve_baseline_current_versions(self) -> bool:
        """Resolve --baseline-version / --current-version name → ID.

        Runs before recipe execution. ID-like values pass through.
        Name values require config.project_filter to be a numeric ID
        (already resolved by the project-filter block upstream).

        Not re-entrant: if _resolve_version_name returns a non-numeric
        ID (e.g. a slug), a second call would re-enter the name path
        and re-query the API. Call this exactly once per run.

        Returns False on resolution failure; the caller should abort.
        """
        bv = self.config.baseline_version
        cv = self.config.current_version

        if not bv and not cv:
            return True

        def _resolve_one(label: str, value: str) -> str | None:
            if self._is_id_like(value):
                return value
            if not self.config.project_filter or not self._is_id_like(
                self.config.project_filter
            ):
                self.logger.error(
                    f"Cannot resolve {label} name '{value}' without a --project. "
                    "Pass --project <name-or-id> so the version name can be looked up, "
                    "or supply the version ID directly."
                )
                return None
            resolved = self._resolve_version_name(self.config.project_filter, value)
            if not resolved:
                self.logger.error(
                    f"Could not resolve {label} name '{value}' in project "
                    f"{self.config.project_filter}. "
                    "Use 'fs-report list-versions <project>' to see available versions."
                )
                return None
            self.logger.info(f"Resolved {label} '{value}' to ID {resolved}")
            return str(resolved)

        if bv:
            new_bv = _resolve_one("--baseline-version", bv)
            if new_bv is None:
                return False
            self.config.baseline_version = new_bv

        if cv:
            new_cv = _resolve_one("--current-version", cv)
            if new_cv is None:
                return False
            self.config.current_version = new_cv

        return True

    def _fetch_all_folders(self) -> list[dict]:
        """Fetch all folders from the API (cached per run)."""
        if self._all_folders_cache is not None:
            return self._all_folders_cache

        from fs_report.models import QueryConfig, QueryParams

        folders_query = QueryConfig(
            endpoint="/public/v0/folders",
            params=QueryParams(limit=10000),
        )
        self._all_folders_cache = self.api_client.fetch_data(folders_query)
        return self._all_folders_cache

    def _resolve_folder(self, folder_input: str) -> dict | None:
        """
        Resolve a folder name or ID to its API record.
        Returns the full folder dict, or None if not found.
        """
        folders = self._fetch_all_folders()

        # Try exact ID match first
        for f in folders:
            if str(f.get("id", "")) == folder_input:
                return f

        # Case-insensitive name match
        for f in folders:
            if f.get("name", "").lower() == folder_input.lower():
                return f

        # Fuzzy hint
        available = [f.get("name", "") for f in folders if f.get("name")]
        close = [n for n in available if folder_input.lower() in n.lower()]
        if close:
            self.logger.info(f"Did you mean one of these folders? {close[:5]}")

        return None

    def _collect_folder_tree(
        self, target_folder_id: str, all_folders: list[dict] | None = None
    ) -> tuple[set[str], dict[str, str], list[dict], dict[str, str], dict[str, str]]:
        """
        Walk the folder tree starting from *target_folder_id* and collect:
        1. All descendant folder IDs (including the target itself).
        2. project_id -> folder_name mapping for every project in those folders.
        3. The list of subfolder dicts (for logging/display).
        4. project_name(lowercased) -> project_id (for case-insensitive lookup).
        5. project_id -> project_name (ORIGINAL case, for provenance labels).

        Returns (folder_ids, project_folder_map, subfolder_list,
        project_name_to_id, project_id_to_name).
        """
        if all_folders is None:
            all_folders = self._fetch_all_folders()

        folder_by_id: dict[str, dict] = {str(f["id"]): f for f in all_folders}
        children_map: dict[str, list[str]] = {}
        for f in all_folders:
            parent = f.get("parentFolderId")
            if parent:
                children_map.setdefault(str(parent), []).append(str(f["id"]))

        # BFS to collect all descendant folder IDs
        from collections import deque

        queue: deque[str] = deque([target_folder_id])
        all_folder_ids: set[str] = set()
        subfolder_list: list[dict] = []
        while queue:
            fid = queue.popleft()
            all_folder_ids.add(fid)
            if fid != target_folder_id:
                subfolder_list.append(folder_by_id.get(fid, {}))
            for child_id in children_map.get(fid, []):
                if child_id not in all_folder_ids:
                    queue.append(child_id)

        # For each folder, fetch its projects
        from fs_report.models import QueryConfig, QueryParams

        project_folder_map: dict[str, str] = {}
        project_name_to_id: dict[str, str] = {}
        project_id_to_name: dict[str, str] = {}
        all_project_ids: set[str] = set()

        for fid in all_folder_ids:
            folder_name = folder_by_id.get(fid, {}).get("name", "Unknown")
            try:
                projects_query = QueryConfig(
                    endpoint=f"/public/v0/folders/{fid}/projects",
                    params=QueryParams(limit=10000, archived=False, excluded=False),
                )
                projects = self.api_client.fetch_data(projects_query)
                for p in projects:
                    pid = str(p.get("id", ""))
                    pname = p.get("name", "")
                    if pid:
                        all_project_ids.add(pid)
                        project_folder_map[pid] = folder_name
                        if pname:
                            project_name_to_id[pname.lower()] = pid
                            project_id_to_name[pid] = pname
            except Exception as e:
                self.logger.warning(
                    f"Error fetching projects for folder '{folder_name}' ({fid}): {e}"
                )

        self.logger.info(
            f"Folder tree: {len(all_folder_ids)} folder(s), "
            f"{len(all_project_ids)} project(s)"
        )

        return (
            all_project_ids,
            project_folder_map,
            subfolder_list,
            project_name_to_id,
            project_id_to_name,
        )

    def _build_folder_path(
        self, folder_id: str, all_folders: list[dict] | None = None
    ) -> str:
        """Build a breadcrumb-style path for a folder, e.g. 'Division A / Medical Products'."""
        if all_folders is None:
            all_folders = self._fetch_all_folders()
        folder_by_id = {str(f["id"]): f for f in all_folders}

        parts: list[str] = []
        current_id: str | None = folder_id
        seen: set[str] = set()
        while current_id and current_id not in seen:
            seen.add(current_id)
            folder = folder_by_id.get(current_id)
            if not folder:
                break
            parts.append(folder.get("name", "Unknown"))
            parent = folder.get("parentFolderId")
            current_id = str(parent) if parent else None

        parts.reverse()
        return " / ".join(parts)

    def _resolve_folder_scope(self) -> bool:
        """
        Called from run() when config.folder_filter is set.
        Resolves folder, walks tree, collects project IDs & mapping.
        Returns True on success, False on failure.
        """
        folder_input = self.config.folder_filter
        if not folder_input:
            return True

        folder = self._resolve_folder(folder_input)
        if not folder:
            self.logger.error(
                f"Could not resolve folder '{folder_input}'. "
                "Use 'fs-report list-folders' to see available folders."
            )
            return False

        folder_id = str(folder["id"])
        self._folder_name = folder.get("name", folder_input)

        # Fetch all folders once (used for tree walk and path building)
        all_folders = self._fetch_all_folders()
        self._folder_path = self._build_folder_path(folder_id, all_folders)

        project_ids, project_folder_map, subfolders, project_name_to_id, _id_to_name = (
            self._collect_folder_tree(folder_id, all_folders)
        )

        self._folder_project_ids = project_ids
        self._project_folder_map = project_folder_map

        self.logger.info(
            f"Folder scope: '{self._folder_path}' — "
            f"{len(subfolders)} subfolder(s), {len(project_ids)} project(s)"
        )

        # If --project is also specified, validate it's within the folder
        if self.config.project_filter:
            pid = str(self.config.project_filter)
            # The filter may be a numeric ID or a project name
            if pid not in project_ids:
                # Try resolving by name (case-insensitive)
                resolved = project_name_to_id.get(pid.lower())
                if resolved:
                    pid = resolved
                else:
                    self.logger.error(
                        f"Project '{self.config.project_filter}' is not in folder "
                        f"'{self._folder_name}' or its subfolders."
                    )
                    return False

        return True

    def _build_project_folder_map_from_projects(self) -> dict[str, str]:
        """
        Build a project_id -> folder_name mapping by fetching projects.
        Used when --folder is not specified, to still populate folder_name
        from the ProjectV0.folder field.  Cached per run.
        """
        if self._project_map_cache is not None:
            return self._project_map_cache

        from fs_report.models import QueryConfig, QueryParams

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        projects = self.api_client.fetch_data(projects_query)

        pf_map: dict[str, str] = {}
        for p in projects:
            pid = str(p.get("id", ""))
            folder = p.get("folder")
            if pid and folder and isinstance(folder, dict):
                pf_map[pid] = folder.get("name", "")
        self._project_map_cache = pf_map
        return pf_map

    def _get_latest_version_ids(self) -> list:
        """Fetch latest version IDs for all projects (cached)."""
        if self._latest_version_ids is not None:
            return self._latest_version_ids

        self.logger.info("Fetching latest version IDs for all projects...")

        # Fetch all projects — _get_latest_version_ids_for_projects will
        # also fetch them, but the DataCache / SQLite cache makes the
        # second call essentially free.
        from fs_report.models import QueryConfig, QueryParams

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        projects = self.api_client.fetch_all_with_resume(projects_query)
        self.logger.info(f"Found {len(projects)} projects")

        project_ids = [str(p["id"]) for p in projects if p.get("id")]

        # Try extracting version IDs from the data we already have.
        # This avoids a second fetch when the list response (or cache)
        # already includes defaultBranch.
        requested_set = set(project_ids)
        version_ids = self._extract_version_ids_from_projects(projects, requested_set)
        if not version_ids and project_ids:
            # Batch data lacked defaultBranch — delegate to the fallback
            # path which does per-project detail calls.
            version_ids = self._get_latest_version_ids_for_projects(project_ids)
        else:
            self.logger.info(f"Resolved {len(version_ids)} version IDs from batch data")

        self.logger.info(f"Found {len(version_ids)} latest version IDs")
        self._latest_version_ids = version_ids
        return version_ids

    def _get_latest_version_ids_for_projects(self, project_ids: list) -> list:
        """Fetch the current (latest) version ID for each given project.

        Uses the project's defaultBranch.latestVersion.id which is the
        authoritative current version on the platform.

        Strategy:
        1. Try a single batch call to /public/v0/projects and extract
           defaultBranch.latestVersion.id for each requested project.
           This is fast and cache-friendly.
        2. If the batch response lacks defaultBranch data (some API versions
           omit it from list responses, or the SQLite cache may have been
           populated before this field was stored), fall back to individual
           /public/v0/projects/{id} calls with throttling.

        Results are cached in-memory so subsequent reports in the same run
        skip the API call entirely.
        """
        # Build a stable cache key from sorted project IDs
        cache_key = ",".join(str(pid) for pid in sorted(project_ids))
        if cache_key in self._folder_version_ids_cache:
            cached = self._folder_version_ids_cache[cache_key]
            self.logger.info(
                f"Using cached version IDs ({len(cached)} versions "
                f"for {len(project_ids)} projects)"
            )
            return cached

        from fs_report.models import QueryConfig, QueryParams

        # ------------------------------------------------------------------
        # Step 1: Try batch fetch
        # ------------------------------------------------------------------
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        all_projects = self.api_client.fetch_all_with_resume(
            projects_query, show_progress=True
        )
        self.logger.info(
            f"Resolving latest versions for {len(project_ids)} projects "
            f"(from {len(all_projects)} total projects)"
        )

        requested_ids = {str(pid) for pid in project_ids}
        id_map = self._extract_version_id_map_from_projects(all_projects, requested_ids)
        version_ids = self._extract_version_ids_from_projects(
            all_projects, requested_ids
        )

        # ------------------------------------------------------------------
        # Step 2: Fallback — per-project detail calls when batch yields nothing
        # ------------------------------------------------------------------
        if not version_ids and project_ids:
            self.logger.info(
                "Batch project list did not include defaultBranch data; "
                "falling back to per-project API calls "
                f"({len(project_ids)} projects, "
                f"delay={self.config.request_delay}s)"
            )
            id_map = self._fetch_version_id_map_per_project(project_ids)
            version_ids = list(id_map.values())

        self._folder_version_ids_cache[cache_key] = version_ids
        # Stash the pid→vid map so folder-scope resolution can recover
        # per-project provenance without re-fetching (item 4: no second N+1).
        self._folder_version_id_map_cache[cache_key] = id_map
        return version_ids

    # ------------------------------------------------------------------
    # Helpers for _get_latest_version_ids_for_projects
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_version_id_map_from_projects(
        projects: list[dict], requested_ids: set[str]
    ) -> dict[str, Any]:
        """Build a ``project_id -> latest_version_id`` map from project dicts.

        Reads ``defaultBranch.latestVersion.id`` for each requested project.
        Projects without a latest version are omitted from the map (and
        logged). The version-id value keeps its raw API type (int or str) so
        the flat-list contract of ``_extract_version_ids_from_projects`` is
        unchanged; callers that need string version IDs coerce at the use
        site. Insertion order follows the *projects* order.
        """
        logger = logging.getLogger(__name__)
        id_map: dict[str, Any] = {}
        for project in projects:
            pid = str(project.get("id", ""))
            if pid not in requested_ids:
                continue
            default_branch = project.get("defaultBranch") or {}
            latest_version = (
                default_branch.get("latestVersion") or {}
                if isinstance(default_branch, dict)
                else {}
            )
            version_id = (
                latest_version.get("id") if isinstance(latest_version, dict) else None
            )
            if version_id:
                id_map[pid] = version_id
            else:
                pname = project.get("name", pid)
                logger.info(
                    f"Project '{pname}' (id={pid}) has no defaultBranch.latestVersion; skipping"
                )
        return id_map

    @classmethod
    def _extract_version_ids_from_projects(
        cls, projects: list[dict], requested_ids: set[str]
    ) -> list:
        """Extract defaultBranch.latestVersion.id from a list of project dicts.

        Preserves the order in which projects appear in *projects* and the
        raw API type of each version id.
        """
        id_map = cls._extract_version_id_map_from_projects(projects, requested_ids)
        return [
            id_map[str(p.get("id", ""))]
            for p in projects
            if str(p.get("id", "")) in id_map
        ]

    def _fetch_version_id_map_per_project(self, project_ids: list) -> dict[str, Any]:
        """Fetch defaultBranch.latestVersion.id one project at a time.

        Returns a ``project_id -> latest_version_id`` map (projects without a
        latest version are omitted; version-id value keeps its raw API type).
        Used as a fallback when the batch /projects list doesn't include
        branch data. Respects --request-delay for throttling.
        """
        from tqdm import tqdm

        delay = max(0.5, self.config.request_delay)
        id_map: dict[str, Any] = {}
        for pid in tqdm(
            project_ids,
            desc="Fetching latest versions",
            unit=" projects",
            leave=True,
        ):
            try:
                url = f"{self.api_client.base_url}/public/v0/projects/{pid}"
                resp = self.api_client.client.get(url)
                resp.raise_for_status()
                data = resp.json()
                default_branch = data.get("defaultBranch") or {}
                latest_version = (
                    default_branch.get("latestVersion") or {}
                    if isinstance(default_branch, dict)
                    else {}
                )
                vid = (
                    latest_version.get("id")
                    if isinstance(latest_version, dict)
                    else None
                )
                if vid:
                    id_map[str(pid)] = vid
                else:
                    self.logger.debug(
                        f"No defaultBranch.latestVersion for project {pid}"
                    )
            except Exception:
                self.logger.warning(
                    f"Failed to fetch version for project {pid}",
                    exc_info=True,
                )
            self._cancellable_sleep(delay)
        return id_map

    def _split_and_cache_by_version(
        self,
        records: list[dict],
        entity_type: str,
        finding_type: str = "",
        category_filter: str | None = None,
        batch_version_ids: list | None = None,
    ) -> None:
        """Split batch results by projectVersion.id and cache each version individually.

        Populates both the in-memory ``_version_findings_cache`` and, when a SQLite
        cache is available, creates per-version SQLite entries using the same hash
        that a ``projectVersion=={vid}`` query would produce.  This means a later
        per-version fetch from Version Comparison can hit the
        SQLite cache entry created by a batch fetch in an earlier run.

        When ``batch_version_ids`` is provided, versions that returned zero records
        are cached as empty lists.  Without this, empty versions would be re-fetched
        on every run (the cache only stored versions that had data).

        Args:
            records: Raw API records (findings or components).
            entity_type: 'findings' or 'components'.
            finding_type: API finding type (e.g. 'cve'). Only used for findings.
            category_filter: Optional RSQL category filter. Only used for findings.
            batch_version_ids: Version IDs that were queried in this batch.
                If provided, any IDs not present in the results are cached as empty.
        """
        from collections import defaultdict

        by_version: dict[str, list[dict]] = defaultdict(list)
        for rec in records:
            pv = rec.get("projectVersion") or {}
            vid = str(pv.get("id", ""))
            if vid:
                by_version[vid].append(rec)

        # If we know which version IDs were in the batch, add empty entries
        # for versions that returned no records so they are cached as "checked".
        if batch_version_ids is not None:
            for batch_vid in batch_version_ids:
                svid = str(batch_vid)
                if svid not in by_version:
                    by_version[svid] = []

        stored_versions = 0
        for vid, version_records in by_version.items():
            if entity_type == "findings":
                cache_key = self._cache_key(
                    "findings", vid, finding_type, category_filter
                )
            else:
                cache_key = self._cache_key("components", vid)
            if cache_key not in self._version_findings_cache:
                self._version_findings_cache[cache_key] = version_records
                stored_versions += 1

                # Warm SQLite cache with a per-version entry
                if self.api_client.sqlite_cache and self.api_client.cache_ttl > 0:
                    endpoint = f"/public/v0/{entity_type}"
                    # Build params that match what a per-version query would produce
                    filter_str = f"projectVersion=={vid}"
                    if category_filter:
                        filter_str = f"{filter_str};{category_filter}"
                    params: dict[str, Any] = {"filter": filter_str, "limit": 10000}
                    if entity_type == "findings" and finding_type:
                        params["finding_type"] = finding_type
                    if entity_type == "findings":
                        params["archived"] = False
                        params["excluded"] = False

                    try:
                        if not self.api_client.sqlite_cache.is_cache_valid(
                            endpoint, params, self.api_client.cache_ttl
                        ):
                            qh = self.api_client.sqlite_cache.start_fetch(
                                endpoint, params, self.api_client.cache_ttl
                            )
                            self.api_client.sqlite_cache.store_records(
                                qh, endpoint, version_records
                            )
                            self.api_client.sqlite_cache.complete_fetch(qh)
                    except Exception:
                        self.logger.warning(
                            f"Failed to warm SQLite cache for version {vid}; continuing without cache"
                        )

        if stored_versions:
            self.logger.debug(
                f"Split batch into {stored_versions} per-version {entity_type} cache entries "
                f"(skipped {len(by_version) - stored_versions} already cached)"
            )

    def _check_version_in_cache(
        self,
        vid: str,
        entity_type: str,
        finding_type: str = "",
        category_filter: str | None = None,
    ) -> list[dict] | None:
        """Check both in-memory and SQLite caches for per-version data.

        Returns cached records or None if not found.
        """
        if entity_type == "findings":
            cache_key = self._cache_key("findings", vid, finding_type, category_filter)
        else:
            cache_key = self._cache_key("components", vid)

        # 1. In-memory cache
        if cache_key in self._version_findings_cache:
            return self._version_findings_cache[cache_key]

        # 2. SQLite cache (skip when refreshing)
        if (
            self.api_client.sqlite_cache
            and self.api_client.cache_ttl > 0
            and not self.api_client.cache_refresh
        ):
            endpoint = f"/public/v0/{entity_type}"
            filter_str = f"projectVersion=={vid}"
            if category_filter:
                filter_str = f"{filter_str};{category_filter}"
            params: dict[str, Any] = {"filter": filter_str, "limit": 10000}
            if entity_type == "findings" and finding_type:
                params["finding_type"] = finding_type
            if entity_type == "findings":
                params["archived"] = False
                params["excluded"] = False

            if self.api_client.sqlite_cache.is_cache_valid(
                endpoint, params, self.api_client.cache_ttl
            ):
                cached = self.api_client.sqlite_cache.get_cached_data(
                    endpoint, params, allow_empty=True
                )
                if cached is not None:
                    # Promote to in-memory cache for fast re-reads
                    self._version_findings_cache[cache_key] = cached
                    return cached

        return None

    def _get_findings_for_versions(
        self,
        version_ids: list,
        finding_type: str,
        category_filter: str | None = None,
        entity_type: str = "findings",
        on_records: "Callable[[list[dict]], None] | None" = None,
        include_additional_details: bool | None = None,
    ) -> list[dict]:
        """Reassemble data from per-version cache, fetching any missing versions first.

        This is the main entry point for findings-based reports to get data for a
        set of versions.  It checks in-memory and SQLite caches per-version, then
        batch-fetches any missing versions from the API.

        Args:
            version_ids: Version IDs to retrieve data for.
            finding_type: API finding type (e.g. 'cve').
            category_filter: Optional RSQL category filter.
            entity_type: 'findings' or 'components'.
            on_records: Optional callback invoked with each batch of records
                as they become available (cached records first, then each
                API batch).  Used to start background work (e.g. NVD
                lookups) in parallel with the remaining fetch.

        Returns:
            Merged list of records across all requested versions.
        """
        all_records: list[dict] = []
        missing: list = []

        for vid in version_ids:
            cached = self._check_version_in_cache(
                str(vid), entity_type, finding_type, category_filter
            )
            if cached is not None:
                all_records.extend(cached)
            else:
                missing.append(vid)

        # Notify callback with cached records so background work can start
        # while API batches are still being fetched.
        if on_records and all_records:
            on_records(all_records)

        cached_count = len(version_ids) - len(missing)
        if missing:
            self.logger.info(
                f"{cached_count}/{len(version_ids)} versions from cache, "
                f"fetching {len(missing)} from API ({entity_type})"
            )
            from fs_report.models import QueryConfig, QueryParams

            # Build base query WITHOUT date filters — entity cache stores all data per version
            filters: list[str] = []
            if category_filter:
                filters.append(category_filter)
            combined_filter = ";".join(filters) if filters else None

            base_query = QueryConfig(
                endpoint=f"/public/v0/{entity_type}",
                params=QueryParams(
                    limit=10000,
                    filter=combined_filter,
                    finding_type=finding_type if entity_type == "findings" else None,
                    archived=False if entity_type == "findings" else None,
                    excluded=False if entity_type == "findings" else None,
                    include_additional_details=include_additional_details,
                ),
            )
            if entity_type == "components":
                # Components need type!=file filter
                comp_filters = ["type!=file"]
                if combined_filter:
                    comp_filters.append(combined_filter)
                base_query.params.filter = ";".join(comp_filters)

            new_records = self._fetch_with_version_batching(
                base_query,
                sorted(missing, key=str),
                finding_type=finding_type,
                category_filter=category_filter,
                entity_type=entity_type,
                on_records=on_records,
            )
            all_records.extend(new_records)
        else:
            self.logger.info(
                f"All {len(version_ids)} versions served from cache ({entity_type})"
            )

        return all_records

    def _volume_based_cooldown(self, records_in_batch: int) -> float:
        """Return a cooldown duration (seconds) scaled by data volume."""
        if records_in_batch > 50_000:
            return max(90.0, self.config.request_delay * 15)
        if records_in_batch > 20_000:
            return max(45.0, self.config.request_delay * 10)
        if records_in_batch > 5_000:
            return max(15.0, self.config.request_delay * 5)
        return max(5.0, self.config.request_delay * 2)

    def _fetch_with_version_batching(
        self,
        base_query: "QueryConfig",
        version_ids: list,
        batch_size: int | None = None,
        finding_type: str = "",
        category_filter: str | None = None,
        entity_type: str = "findings",
        on_records: "Callable[[list[dict]], None] | None" = None,
    ) -> list[dict]:
        """Fetch data in batches, filtering by version IDs.

        Before each batch, filters out versions already in per-version cache.
        After each batch, splits results and stores per-version entries.
        Uses ``skip_cache_store=True`` to avoid duplicating batch-level SQLite
        entries (per-version storage handles it).

        batch_size defaults to ``self.config.batch_size`` (CLI: ``--batch-size``,
        default 5).  Kept small to avoid overloading the server on large
        instances.  Each batch is followed by an adaptive cooldown that scales
        with the number of records fetched.
        """
        if batch_size is None:
            batch_size = self.config.batch_size
        from tqdm import tqdm

        all_results = []

        # Filter out already-cached versions first
        uncached_ids = [
            v
            for v in version_ids
            if self._check_version_in_cache(
                str(v), entity_type, finding_type, category_filter
            )
            is None
        ]

        # Collect cached results
        cached_count = len(version_ids) - len(uncached_ids)
        if cached_count > 0:
            for vid in version_ids:
                cached = self._check_version_in_cache(
                    str(vid), entity_type, finding_type, category_filter
                )
                if cached is not None:
                    all_results.extend(cached)
            self.logger.debug(
                f"Version batching: {cached_count} versions served from cache"
            )

        if not uncached_ids:
            self.logger.debug("Version batching: all versions served from cache")
            return all_results

        total_batches = (len(uncached_ids) + batch_size - 1) // batch_size

        # Log the base filter being used
        self.logger.debug(
            f"Version batching with base filter: {base_query.params.filter}"
        )

        # Split uncached version IDs into batches with progress bar
        # Track elevated cooldown state: after server errors, keep cooldowns
        # elevated for several batches so the server gets sustained recovery.
        elevated_batches_remaining = 0
        elevated_cooldown = 0.0

        with tqdm(
            range(0, len(uncached_ids), batch_size),
            desc="Fetching version batches",
            unit=" batches",
            total=total_batches,
            leave=False,
        ) as pbar:
            for i in pbar:
                batch_ids = uncached_ids[i : i + batch_size]

                from fs_report.models import QueryConfig, QueryParams

                # Batch version IDs with RSQL filter against the
                # portfolio-wide /findings endpoint.

                # Build version filter
                version_filter = (
                    f"projectVersion=in=({','.join(str(v) for v in batch_ids)})"
                )

                # Combine with existing filter (MUST preserve base filter
                # like type!=file). Strip any project== / project=in=()
                # clauses though — the per-batch projectVersion=in=(...)
                # uniquely identifies both project and version, and
                # keeping a 706-project list in every batch URL pushes
                # past nginx's 8 KB default and yields HTTP 414. See
                # CST-747.
                base_filter_stripped = _strip_project_scope(base_query.params.filter)
                if base_filter_stripped:
                    combined_filter = f"{base_filter_stripped};{version_filter}"
                else:
                    combined_filter = version_filter

                self.logger.debug(
                    f"Batch {i//batch_size + 1}/{total_batches} filter: {combined_filter[:100]}..."
                )

                # Create batch query
                batch_query = QueryConfig(
                    endpoint=base_query.endpoint,
                    params=QueryParams(
                        limit=base_query.params.limit,
                        filter=combined_filter,
                        finding_type=base_query.params.finding_type,
                        archived=False if entity_type == "findings" else None,
                        excluded=False if entity_type == "findings" else None,
                        include_additional_details=base_query.params.include_additional_details,
                    ),
                )

                # Use skip_cache_store to avoid duplicating batch-level SQLite entries
                batch_results = self.api_client.fetch_all_with_resume(
                    batch_query,
                    show_progress=False,
                    skip_cache_store=True,
                )

                # Split and cache per-version (in-memory + SQLite).
                # Pass batch_ids so versions with 0 results are cached as
                # empty — otherwise they'd be re-fetched on every run.
                self._split_and_cache_by_version(
                    batch_results,
                    entity_type,
                    finding_type,
                    category_filter,
                    batch_version_ids=batch_ids,
                )

                # Trim factors in-memory to avoid OOM on large instances.
                # The full factors are already persisted (trimmed) in SQLite;
                # here we apply the same trim so the in-memory accumulation
                # doesn't hold multi-MB factors arrays per finding.
                for record in batch_results:
                    raw_factors = record.get("factors")
                    if isinstance(raw_factors, list) and raw_factors:
                        record["factors"] = _trim_factors(raw_factors)

                all_results.extend(batch_results)
                if on_records and batch_results:
                    on_records(batch_results)
                pbar.set_postfix({"records": len(all_results)})

                # Adaptive cooldown between batches — scale with data volume
                if i + batch_size < len(uncached_ids):
                    records_in_batch = len(batch_results)
                    # Check if the API client hit any retries during this batch
                    retries_in_batch = getattr(self.api_client, "last_fetch_retries", 0)
                    if retries_in_batch > 0:
                        # Server was struggling — give it a long recovery and
                        # keep cooldowns elevated for the next several batches
                        # so the server gets sustained breathing room.
                        cooldown = max(120.0, self.config.request_delay * 20)
                        elevated_cooldown = max(60.0, self.config.request_delay * 10)
                        elevated_batches_remaining = 5
                        self.logger.warning(
                            f"Server had {retries_in_batch} retries in batch; "
                            f"extended cooldown {cooldown:.0f}s "
                            f"(next {elevated_batches_remaining} batches "
                            f"will use ≥{elevated_cooldown:.0f}s)"
                        )
                    elif elevated_batches_remaining > 0:
                        # Still in recovery window from a previous retry event
                        elevated_batches_remaining -= 1
                        volume_cooldown = self._volume_based_cooldown(records_in_batch)
                        cooldown = max(volume_cooldown, elevated_cooldown)
                        self.logger.info(
                            f"Recovery cooldown {cooldown:.0f}s "
                            f"({elevated_batches_remaining} elevated batches left)"
                        )
                    else:
                        cooldown = self._volume_based_cooldown(records_in_batch)
                    batches_remaining = total_batches - (i // batch_size + 1)
                    est_minutes = (batches_remaining * cooldown) / 60
                    self.logger.info(
                        f"Batch {i // batch_size + 1}/{total_batches}: "
                        f"{records_in_batch:,} records. "
                        f"Cooling down {cooldown:.0f}s. "
                        f"~{est_minutes:.0f} min remaining"
                    )
                    self._cancellable_sleep(cooldown)

        return all_results

    def _fire_recipe_start(self, idx: int, total: int, name: str) -> None:
        """Fire the optional on_recipe_start hook (T5 — lights the plain-report
        canvas node 'running' before the recipe runs). Defensive: a misbehaving
        observer must never break the run, but log it so a silent SSE/recorder
        failure leaves a trail (mirrors on_section_start, M1-4)."""
        if self._on_recipe_start:
            try:
                self._on_recipe_start(idx, total, name)
            except Exception:
                self.logger.exception("on_recipe_start hook raised")

    def _resolve_run_scope(self) -> bool:
        """Resolve folder / project / version scope on ``self.config`` in place.

        Folder name→IDs (``_folder_project_ids``), project name/glob→ID, and
        version name→ID resolution — the API filters require IDs.  Mutates
        ``self.config`` (and ``self.resolved_project_name`` /
        ``self._folder_project_ids``) and returns ``True`` on success, ``False``
        on any unresolvable / invalid scope (the caller maps False to a run
        failure).  Skipped entirely under ``data_override``.

        Extracted from ``run()`` so the per-section compound override path can
        re-resolve a child's overridden scope through the SAME logic
        (``_process_compound``) — a section that retargets ``project_filter`` /
        ``folder_filter`` / ``version_filter`` resolves exactly as a run-level
        scope would, with no duplicated resolution code.
        """
        # Resolve folder scope first (may narrow down project set)
        if self.config.folder_filter and not self.data_override:
            if not self._resolve_folder_scope():
                return False

        # Resolve project name to ID if needed (API filters require IDs)
        if self.config.project_filter and not self.data_override:
            if self._is_id_like(self.config.project_filter):
                pid = self.config.project_filter
                # ID-like value — validate it actually refers to a project
                if not self._validate_numeric_project_id(pid):
                    self.logger.error(
                        f"No project found with ID {pid}. "
                        "This may be a project *version* ID rather than a project ID. "
                        "If so, use --version (with --project) or "
                        "--baseline-version / --current-version instead.\n"
                        "Use 'fs-report list-projects' to see available projects."
                    )
                    return False
                # Resolve ID to project name for display
                self.resolved_project_name = self._resolve_project_id_to_name(pid)
            else:
                filter_value = self.config.project_filter
                if self._is_glob(filter_value):
                    matches = self._resolve_project_glob(filter_value)
                    if not matches:
                        self.logger.error(
                            f"No projects matched glob pattern '{filter_value}'. "
                            "Use 'fs-report list-projects' to see available projects."
                        )
                        return False
                    elif len(matches) == 1:
                        mid, mname = matches[0]
                        self.logger.info(
                            f"Glob '{filter_value}' matched 1 project: {mname} (ID {mid})"
                        )
                        self.resolved_project_name = mname
                        self.config.project_filter = str(mid)
                    else:
                        names = [m[1] for m in matches]
                        self.logger.info(
                            f"Glob '{filter_value}' matched {len(matches)} projects: "
                            + ", ".join(sorted(names))
                        )
                        self._folder_project_ids = {str(m[0]) for m in matches}
                        self.config.project_filter = None
                else:
                    original_name = filter_value
                    resolved_id = self._resolve_project_name(filter_value)
                    if resolved_id:
                        self.logger.info(
                            f"Resolved project '{filter_value}' to ID {resolved_id}"
                        )
                        self.resolved_project_name = original_name
                        self.config.project_filter = str(resolved_id)
                    else:
                        self.logger.error(
                            f"Could not resolve project name '{filter_value}'. "
                            "Use 'fs-report list-projects' to see available projects."
                        )
                        return False

        # Reject version filter with multi-project glob
        if (
            self.config.version_filter
            and not self.data_override
            and self._folder_project_ids
            and not self.config.project_filter
            and not self.config.folder_filter
        ):
            self.logger.error(
                "Version filter is not supported with project glob patterns. "
                "Use an exact project name or ID with --version."
            )
            return False

        # Resolve version name to ID if needed (API filters require IDs)
        if self.config.version_filter and not self.data_override:
            if not self.config.project_filter:
                self.logger.error(
                    "Version filter requires a project filter. "
                    "Use --project-filter to specify the project."
                )
                return False
            if self._is_id_like(self.config.version_filter):
                pass  # Already an ID — no resolution needed
            else:
                if not self._is_id_like(self.config.project_filter):
                    # project_filter should already be resolved above
                    self.logger.error(
                        f"Cannot resolve version name '{self.config.version_filter}': "
                        f"project filter '{self.config.project_filter}' is not an ID."
                    )
                    return False
                resolved_ver_id = self._resolve_version_name(
                    self.config.project_filter, self.config.version_filter
                )
                if resolved_ver_id:
                    self.logger.info(
                        f"Resolved version '{self.config.version_filter}' to ID {resolved_ver_id}"
                    )
                    self.config.version_filter = str(resolved_ver_id)
                else:
                    self.logger.error(
                        f"Could not resolve version name '{self.config.version_filter}' "
                        f"in project {self.config.project_filter}. "
                        "Use 'fs-report list-versions <project>' to see available versions."
                    )
                    return False
        return True

    def run(self) -> "RunResult":
        """Run the complete report generation process. Returns RunResult with success status."""
        _fail = RunResult(success=False)
        self.logger.info("Starting report generation...")

        # Load recipes
        recipes = self.recipe_loader.load_recipes()

        # Merge pre-constructed extra_recipes (decision #10) into the corpus.
        # `fs-report compare` (B3.7) uses this to run an in-memory axis
        # CompoundRecipe + its comparison children without a temp YAML.
        #
        # OVERRIDE semantics: an extra recipe REPLACES a loaded recipe with the
        # same slug (extra wins) rather than colliding with it. Extras are
        # explicit per-run injections that legitimately shadow disk recipes —
        # e.g. `compare --save-as NAME` writes NAME.yaml AND injects the same
        # compound as an extra; the on-disk copy and the extra share a slug, so
        # the extra simply overrides the loaded copy and the run proceeds
        # cleanly. The loaded-corpus integrity check (loaded-vs-loaded
        # collisions) still runs at load time in load_recipes(); only this
        # extra-vs-loaded merge uses override instead of collision.
        if self._extra_recipes:
            extra_slugs = {_slug(r.name) for r in self._extra_recipes}
            recipes = [r for r in recipes if _slug(r.name) not in extra_slugs] + list(
                self._extra_recipes
            )

        if not recipes:
            if self.recipe_loader.recipe_filter:
                self.logger.warning(
                    "No recipes matched the requested filter. "
                    "Check spelling with: fs-report list recipes"
                )
            else:
                self.logger.warning("No recipes found in recipes directory")
            return _fail

        # Filter recipes if specific recipe is requested
        # Check both config.recipe_filter and recipe_loader.recipe_filter
        # (CLI sets recipe_loader.recipe_filter directly, not config.recipe_filter)
        explicit_recipe_requested = self.config.recipe_filter or getattr(
            self.recipe_loader, "recipe_filter", None
        )
        if self.config.recipe_filter:
            filtered_recipes = [
                r
                for r in recipes
                if r.name.lower() == self.config.recipe_filter.lower()
            ]
            if not filtered_recipes:
                self.logger.error(
                    f"Recipe '{self.config.recipe_filter}' not found. Available recipes: {[r.name for r in recipes]}"
                )
                return _fail
            recipes = filtered_recipes
            self.logger.info(f"Filtered to {len(recipes)} recipe(s)")
        elif not explicit_recipe_requested:
            # Exclude recipes with auto_run=False only when no specific recipe
            # is requested. Comparison recipes never auto-run, but add a
            # defensive engine-side skip too: a bare `fs-report run` must
            # never execute a category=='comparison' recipe (decision #14 —
            # standalone comparisons are not a supported run path; use
            # `fs-report compare`).
            auto_run_recipes = [
                r
                for r in recipes
                if getattr(r, "auto_run", True)
                and getattr(r, "category", "") != "comparison"
            ]
            skipped = len(recipes) - len(auto_run_recipes)
            if skipped > 0:
                self.logger.info(
                    f"Skipping {skipped} recipe(s) with auto_run=false (use --recipe to run them)"
                )
            recipes = auto_run_recipes

        # Meta-compare scope-flag + standalone-comparison validation (B3.6).
        # --left/--right only apply to an axis-bearing compound; a comparison
        # recipe requested standalone errors with a pointer to `fs-report
        # compare` (decision #14).
        _axis_ok, _axis_msg = self._validate_axis_scope_flags(recipes)
        if not _axis_ok:
            self.logger.error(_axis_msg)
            # Surface the actionable message to the CLI (M1-3) rather than the
            # generic "Report generation failed!" banner.
            return RunResult(success=False, error_message=_axis_msg)

        # Sort recipes by execution_order to maximize cache reuse
        # Lower order = runs first (e.g., Scan Analysis fetches scans that other reports reuse)
        recipes = sorted(recipes, key=lambda r: r.execution_order)

        self.logger.info(f"Loaded {len(recipes)} recipes")

        # Resolve folder / project / version scope on self.config in place
        # (folder→IDs, project name/glob→ID, version name→ID). Extracted to
        # _resolve_run_scope so the compound per-section override path can
        # re-resolve a child's overridden scope through the same logic.
        if not self._resolve_run_scope():
            return _fail

        # Resolve --baseline-version / --current-version names to IDs
        # (Version Comparison's explicit-pair short-circuit needs IDs)
        if (
            self.config.baseline_version or self.config.current_version
        ) and not self.data_override:
            if not self._resolve_baseline_current_versions():
                return _fail

        # Process each recipe
        all_succeeded = True
        generated_files: list[str] = []
        recipe_results: list[RecipeResult] = []
        # Captures an actionable per-recipe failure message (e.g. an axis
        # compound's missing-scope precheck) so the CLI can surface it instead
        # of the generic banner. (M1-4.)
        run_error_message: str | None = None
        total = len(recipes)

        # Pre-build a slug-keyed index over the FULL loaded corpus so a
        # compound's children can resolve even when they have
        # auto_run=False or are excluded from the current `recipes` slice
        # by --recipe filtering. Compound-section validation in the loader
        # already enforced slug bijection (B1.3) — duplicates would have
        # raised RecipeSlugCollision at startup, so a name appearing once
        # here is the unique resolution.
        #
        # IMPORTANT: load_recipes() honors recipe_loader.recipe_filter,
        # which the CLI sets when the user passes --recipe <bundle>. A
        # naive second call would return ONLY the compound and leave
        # children unresolvable. Shadow the filter while we fetch the
        # full corpus, then restore it so the subsequent normal flow is
        # unchanged. (PR #100 round-1 multi-review C1.)
        _saved_filter = self.recipe_loader.recipe_filter
        self.recipe_loader.recipe_filter = None
        try:
            all_recipes_for_compound: dict[str, Recipe] = {
                _slug(r.name): r for r in self.recipe_loader.load_recipes()
            }
        finally:
            self.recipe_loader.recipe_filter = _saved_filter
        # Make extra_recipes (decision #10) resolvable as compound children
        # too — an in-memory axis CompoundRecipe's comparison children come
        # from the extras list, not the on-disk corpus.
        for _extra in self._extra_recipes:
            all_recipes_for_compound[_slug(_extra.name)] = _extra

        for idx, recipe in enumerate(recipes, 1):
            self._current_dependency_tree = None  # Reset per recipe
            self._check_cancel()
            try:
                self.logger.info(f"[{idx}/{total}] Generating: {recipe.name} ...")

                # Compound dispatch — BEFORE the standalone per-recipe
                # pre-checks. The compound has no data of its own, so the
                # requires_project / requires_cve / etc. checks apply to
                # its children, not the bundle. _process_compound runs
                # those pre-checks per child and either fails fast (if a
                # child is misconfigured for this run) or builds a
                # SectionResult list and dispatches to the assembler.
                if isinstance(recipe, CompoundRecipe):
                    compound_result = self._process_compound(
                        recipe, all_recipes_for_compound
                    )
                    recipe_results.append(compound_result)
                    generated_files.extend(compound_result.files)
                    if compound_result.stats.get("any_failed"):
                        all_succeeded = False
                        # Surface the compound's actionable message in
                        # stats["error"] rather than the generic banner. This
                        # covers BOTH:
                        #   * an axis-compound precheck failure (missing
                        #     --left/--right) that produces NO files (M1-4), and
                        #   * a partial-failure bundle that DID write files but
                        #     has failed sections — the summary names them so
                        #     the CLI shows specifics. (M1-12.)
                        _cm = compound_result.stats.get("error")
                        if _cm:
                            run_error_message = str(_cm)
                    continue

                # Require --project for recipes that declare requires_project
                if (
                    getattr(recipe, "requires_project", False) is True
                    and not self.config.project_filter
                ):
                    self.logger.error(
                        f"'{recipe.name}' requires a --project filter. "
                        "Use --project <name-or-id> to scope to a single project."
                    )
                    all_succeeded = False
                    continue

                # Require --cve for recipes that declare requires_cve
                if getattr(recipe, "requires_cve", False) is True and not getattr(
                    self.config, "cve_filter", None
                ):
                    self.logger.error(
                        f"'{recipe.name}' requires a --cve filter. "
                        "Use --cve <CVE-ID> to specify one or more CVEs."
                    )
                    all_succeeded = False
                    continue

                # Require --project or --folder for recipes that declare requires_project_or_folder
                if (
                    getattr(recipe, "requires_project_or_folder", False) is True
                    and not self.config.project_filter
                    and not self.config.folder_filter
                ):
                    self.logger.error(
                        f"'{recipe.name}' requires --project or --folder. "
                        "Use --project <name-or-id> or --folder <name-or-id> to scope."
                    )
                    all_succeeded = False
                    continue

                # Require --component for recipes that declare requires_component
                # (B4 #25) — e.g. Component Impact / Component Remediation Package.
                if (
                    getattr(recipe, "requires_component", False) is True
                    and not str(
                        getattr(self.config, "component_filter", None) or ""
                    ).strip()
                ):
                    self.logger.error(
                        f"'{recipe.name}' requires a --component filter. "
                        "Use --component <name> to specify the component."
                    )
                    all_succeeded = False
                    continue

                # Folder-scoped Remediation Package: iterate over projects.
                # Note: the same recipe name is encoded in
                # recipe_requirements._NAME_REQUIRES_PROJECT_OR_FOLDER; keep
                # in sync if this recipe is ever renamed.
                if (
                    recipe.name == "Remediation Package"
                    and not self.config.project_filter
                    and self._folder_project_ids
                ):
                    # T5/M3-1: this branch does real per-project work then
                    # `continue`s BEFORE the generic on_recipe_start site below,
                    # so light the node "running" here too (else a folder-scoped
                    # Remediation Package stays visually queued until completion).
                    self._fire_recipe_start(idx, total, recipe.name)
                    folder_ok = self._run_remediation_folder(
                        recipe,
                        sorted(self._folder_project_ids),
                        generated_files,
                        recipe_results,
                    )
                    if not folder_ok:
                        all_succeeded = False
                    continue

                # Remediation Package without --project or --folder.
                # Note: the same recipe name is encoded in
                # recipe_requirements._NAME_REQUIRES_PROJECT_OR_FOLDER; keep
                # in sync if this recipe is ever renamed.
                if (
                    recipe.name == "Remediation Package"
                    and not self.config.project_filter
                    and not self._folder_project_ids
                ):
                    self.logger.error(
                        "'Remediation Package' requires --project or --folder. "
                        "Use --project <name-or-id> or --folder <name-or-id>."
                    )
                    all_succeeded = False
                    continue

                # Scoped output naming: when --component or --cve is set, suffix
                # the recipe name for the output directory.
                _scoped_recipe = recipe
                scope_suffix = ""
                if getattr(self.config, "component_filter", None):
                    scope_suffix = str(self.config.component_filter)
                elif getattr(self.config, "cve_filter", None):
                    scope_suffix = str(self.config.cve_filter)
                if scope_suffix:
                    _scoped_recipe = recipe.model_copy(
                        update={"name": f"{recipe.name} - {scope_suffix}"}
                    )
                # Light the plain-report canvas node "running" before the recipe
                # does its work (T5).  Fired here (generic path) AND in the
                # folder-scoped Remediation Package branch above — both AFTER the
                # requires-* skip checks, so a skipped recipe never lights running.
                # Placed BEFORE check_output_guard so an overwrite-guard failure
                # still gets underway feedback rather than queued→done (M1-1).
                # Uses recipe.name to match the report node id (build_canvas_nodes)
                # + the on_recipe_complete signal.
                self._fire_recipe_start(idx, total, recipe.name)
                self.renderer.check_output_guard(_scoped_recipe)
                report_data = self._process_recipe(recipe)
                if report_data:
                    files = self.renderer.render(_scoped_recipe, report_data)
                    if files:
                        generated_files.extend(files)
                    # Collect extra files written by transforms (prompts, VEX JSON)
                    extra = report_data.metadata.get("additional_data", {}).get(
                        "_extra_generated_files", []
                    )
                    if extra:
                        generated_files.extend(extra)

                    # Build per-recipe result
                    recipe_output_dir = str(
                        self.renderer.output_dir
                        / self.renderer._sanitize_filename(_scoped_recipe.name)
                    )
                    row_count = 0
                    data = report_data.data
                    if hasattr(data, "__len__"):
                        row_count = len(data)
                    recipe_results.append(
                        RecipeResult(
                            recipe=_scoped_recipe.name,
                            output_dir=recipe_output_dir,
                            files=files + (extra or []),
                            stats={"finding_count": row_count},
                        )
                    )
                else:
                    self.logger.error(
                        f"No report data generated for recipe: {recipe.name}"
                    )
                    recipe_results.append(
                        RecipeResult(
                            recipe=recipe.name,
                            output_dir="",
                            files=[],
                            stats={"error": "no report data"},
                        )
                    )
                    all_succeeded = False
            except ReportCancelled:
                # A Stop mid-recipe (e.g. ReportCancelled re-raised out of a
                # compound's child loop) must PROPAGATE out of run() so the web
                # worker's `except ReportCancelled` reports status="cancelled".
                # The bare `except Exception` below would otherwise record it as
                # a failed recipe and return success=False → "error", defeating
                # cancel parity for compound (and plain-recipe) runs. The CLI
                # never sets a cancel_event, so _check_cancel never raises and
                # this path is web-only — CLI behavior is unchanged. (R3 M1-1.)
                raise
            except Exception as e:
                self.logger.error(f"Failed to process recipe {recipe.name}: {e}")
                recipe_results.append(
                    RecipeResult(
                        recipe=recipe.name,
                        output_dir="",
                        files=[],
                        stats={"error": str(e)},
                    )
                )
                all_succeeded = False
            finally:
                if self._on_recipe_complete:
                    try:
                        self._on_recipe_complete(idx, total, recipe.name)
                    except Exception:
                        pass
        self.generated_files = generated_files
        if generated_files:
            print("\nReports generated:")
            for f in generated_files:
                print(f"  - {f}")
        return RunResult(
            success=all_succeeded,
            recipes=recipe_results,
            error_message=None if all_succeeded else run_error_message,
        )

    # ------------------------------------------------------------------
    # extra_recipes seam (B3.6, decision #10)
    # ------------------------------------------------------------------

    def set_extra_recipes(self, recipes: list[Recipe]) -> None:
        """Register pre-constructed recipe objects to merge into the corpus.

        Used by ``fs-report compare`` (B3.7) to run an in-memory axis
        ``CompoundRecipe`` (and its comparison children) without writing a
        temp YAML. The extras are merged into the loaded corpus in ``run()``
        with OVERRIDE semantics: an extra whose slug matches a loaded recipe
        REPLACES that loaded recipe (extra wins). Extras are explicit per-run
        injections that legitimately shadow disk recipes — e.g.
        ``compare --save-as NAME`` writes ``NAME.yaml`` AND injects the same
        compound as an extra; the on-disk copy is overridden by the extra, so
        the run proceeds with no collision.

        This setter validates the extras for collisions *among themselves*
        up front so a programmatic caller gets a clear error at registration.
        It does NOT collision-check extras against the on-disk corpus —
        override is the intended behavior there.

        Raises:
            RecipeSlugCollision: if two extras normalize to the same slug.
        """
        by_slug: dict[str, list[str]] = {}
        for r in recipes:
            by_slug.setdefault(_slug(r.name), []).append(r.name)
        collisions = {s: names for s, names in by_slug.items() if len(names) > 1}
        if collisions:
            details = "; ".join(
                f"slug={s!r} shared by {names}" for s, names in collisions.items()
            )
            raise RecipeSlugCollision(
                f"extra_recipes contain slug collisions: {details}. "
                "Each extra recipe name must normalize to a unique slug."
            )
        self._extra_recipes = list(recipes)

    # ------------------------------------------------------------------
    # Meta-compare scope resolution (B3.6 — spec § 1)
    # ------------------------------------------------------------------

    def _resolve_scope(self, ref: "ScopeRef") -> "ResolvedScope":
        """Resolve a parsed :class:`ScopeRef` against the API.

        Runs post-auth, BEFORE any comparison-recipe fetch. Failures raise
        ``ValueError`` with a CLI-grade message that fails the whole run.

        * project scope: name/ID → project id; ``@version`` → version id
          (name match or accepted ID); no ``@version`` → latest version id.
          Label: ``"{project_name} @ {version_display}"``.
        * folder scope: folder → recursive project set → latest version per
          project. Label: ``"folder {folder_name} ({N} projects)"``.

        See docs/superpowers/specs/2026-05-11-meta-compare-design.md § 1.
        """
        if ref.kind == "folder":
            return self._resolve_folder_scope_ref(ref)
        return self._resolve_project_scope_ref(ref)

    def _resolve_project_scope_ref(self, ref: "ScopeRef") -> "ResolvedScope":
        """Resolve a ``project:`` scope reference (see ``_resolve_scope``)."""
        target = ref.target
        # ---- Resolve target → (project_id, project_name).
        if self._is_id_like(target):
            if self._validate_numeric_project_id(target):
                project_id: int | str = target
                project_name = self._resolve_project_id_to_name(target) or target
            else:
                # M3-3 (round-4 item 7): the target LOOKS id-like but no project
                # has that ID. Before erroring, fall back to a NAME lookup — a
                # project whose NAME is a numeric string (e.g. "12345") is
                # otherwise untargetable. Only error if the name lookup also
                # misses.
                resolved = self._resolve_project_name(target)
                if not resolved:
                    raise ValueError(
                        f"Project '{target}' not found. "
                        "Use 'fs-report list-projects' to see available projects."
                    )
                project_id = resolved
                project_name = target
        else:
            resolved = self._resolve_project_name(target)
            if not resolved:
                hint = self._folder_name_hint(target)
                raise ValueError(
                    f"Project '{target}' not found{hint}. "
                    "Use 'fs-report list-projects' to see available projects."
                )
            project_id = resolved
            project_name = target

        # ---- Resolve version.
        if ref.version is not None:
            if self._is_id_like(ref.version):
                version_id: str = str(ref.version)
                # Fail fast if the id isn't actually a version of this project.
                # _lookup_version_display_name can't signal "not a member" (it
                # falls back to str(version_id)), so do an explicit membership
                # check against the same version list the name path uses
                # (PR review I).
                project_versions = self._get_project_versions(project_id)
                is_member = any(
                    str(v.get("id")) == version_id for v in project_versions
                )
                if not is_member:
                    raise ValueError(
                        f"Version '{ref.version}' not found on project "
                        f"{project_name}. Use 'fs-report list-versions "
                        f"{project_name}' to see available versions."
                    )
                version_display = self._lookup_version_display_name(
                    project_id, version_id
                )
            else:
                resolved_ver = self._resolve_version_name(project_id, ref.version)
                if not resolved_ver:
                    raise ValueError(
                        f"Version '{ref.version}' not found on project "
                        f"{project_name}. Use 'fs-report list-versions "
                        f"{project_name}' to see available versions."
                    )
                version_id = str(resolved_ver)
                version_display = ref.version
        else:
            latest = self._get_latest_version_ids_for_projects([str(project_id)])
            if not latest:
                raise ValueError(
                    f"Project '{project_name}' has no versions to compare. "
                    "Upload a scan to create a version, or pass an explicit "
                    "@<version>."
                )
            version_id = str(latest[0])
            version_display = self._lookup_version_display_name(project_id, version_id)

        return ResolvedScope(
            label=f"{project_name} @ {version_display}",
            version_ids=[version_id],
            project_names={version_id: project_name},
            version_displays={version_id: version_display},
        )

    def _resolve_folder_scope_ref(self, ref: "ScopeRef") -> "ResolvedScope":
        """Resolve a ``folder:`` scope reference (see ``_resolve_scope``)."""
        folder = self._resolve_folder(ref.target)
        if folder is None:
            raise ValueError(
                f"Folder '{ref.target}' not found. "
                "Use 'fs-report list-folders' to see available folders."
            )
        folder_id = str(folder.get("id", ""))
        folder_name = folder.get("name", ref.target)

        _pids, _pf_map, _subs, _name_to_id, id_to_name = self._collect_folder_tree(
            folder_id
        )
        sorted_pids = sorted(_pids)
        total_projects = len(sorted_pids)

        # Resolve latest versions for ALL projects in ONE batch call (item 4:
        # no per-project N+1). The pid→vid map is stashed by the helper so we
        # can recover per-project provenance.
        self._get_latest_version_ids_for_projects(sorted_pids)
        cache_key = ",".join(sorted_pids)
        pid_to_vid = self._folder_version_id_map_cache.get(cache_key)

        if not pid_to_vid:
            # The batch resolver did not stash a pid→vid map (e.g. a test stub
            # overrides _get_latest_version_ids_for_projects, or an API shape
            # that the batch path couldn't map). Recover the association BY
            # PROJECT via the per-project resolver — NEVER by positionally
            # zipping a flat version list against sorted pids, which mis-
            # associates versions whenever a project is silently omitted.
            # (M1-6/M3-2.)
            try:
                pid_to_vid = self._fetch_version_id_map_per_project(sorted_pids)
            except Exception as exc:  # pragma: no cover - defensive
                # If even the per-project resolve is unavailable, drop the
                # association rather than risk mis-association: warn and treat
                # every project as unresolved.
                self.logger.warning(
                    "Folder '%s': could not resolve per-project latest versions "
                    "(%s); the folder compare cannot be scoped by project.",
                    folder_name,
                    exc,
                )
                pid_to_vid = {}

        version_ids: list[str] = []
        project_names: dict[str, str] = {}
        version_displays: dict[str, str] = {}

        # Association is ALWAYS by project id (never positional). Projects
        # without a resolvable latest version are skipped.
        ordered = [(pid, pid_to_vid[pid]) for pid in sorted_pids if pid in pid_to_vid]
        skipped_pids = [pid for pid in sorted_pids if pid not in pid_to_vid]

        for pid, raw_vid in ordered:
            vid = str(raw_vid)
            version_ids.append(vid)
            # Provenance from the folder tree's id→name map built once in
            # _collect_folder_tree (item 4: no per-project
            # _resolve_project_id_to_name N+1).
            project_names[vid] = id_to_name.get(pid) or pid
            # No version display name is resolved per-project for folder scope
            # (the folder label omits versions); the version_id is a safe,
            # correct backfill for projectVersion.version — never the project
            # name (item 1).
            version_displays[vid] = vid

        n = len(version_ids)

        # M1-5/M1-7: a folder compare must not silently run against a subset.
        # When some folder projects have no resolvable latest version, WARN
        # naming how many (and which, when cheap) were skipped.
        if skipped_pids:
            skipped_names = [id_to_name.get(p) or p for p in skipped_pids]
            self.logger.warning(
                "Folder '%s': %d of %d project%s have no resolvable latest "
                "version and were skipped from the comparison scope: %s",
                folder_name,
                len(skipped_pids),
                total_projects,
                "" if total_projects == 1 else "s",
                ", ".join(skipped_names),
            )

        # M1-2 (round-4 item 3): a scope resolving to ZERO versions must fail
        # fast. An empty folder, or a folder whose every project lacks a scanned
        # version, would otherwise return an empty scope that produces a
        # misleading empty-diff report. Raise a clear ValueError instead (which
        # becomes a clean precheck failure via _process_axis_compound).
        if n == 0:
            if total_projects == 0:
                detail = "the folder is empty"
            else:
                detail = (
                    f"none of its {total_projects} project"
                    f"{'' if total_projects == 1 else 's'} has a scanned version"
                )
            raise ValueError(
                f"Scope 'folder {folder_name}' resolved to 0 versions — "
                f"{detail}. Upload a scan to a project in this folder, or point "
                "--left/--right at a project with a version."
            )

        # A folder scope spans multiple projects. Comparison rows are grouped by
        # match_key, so a CVE/component shared by several projects is reported as
        # ONE row (counts are key-level). Per-project provenance is NOT lost —
        # the playbook redesign preserves each project's variant as owner
        # attribution (the owner chips / Project column, via the transforms'
        # ``project_names`` / side-specific owner sets). Note it at INFO so the
        # folder-mode aggregation is never silent without crying limitation.
        if n > 1:
            self.logger.info(
                "Folder '%s' spans %d projects: findings shared across projects "
                "are aggregated to one row per match_key, with each project's "
                "variant preserved as owner attribution (owner chips / Project "
                "column).",
                folder_name,
                n,
            )

        # M1-5: make the label honest — show resolved-version count AND total
        # folder-project count when they differ; keep the simple form when all
        # resolve.
        if n == total_projects:
            label = f"folder {folder_name} ({n} project{'' if n == 1 else 's'})"
        else:
            label = (
                f"folder {folder_name} ({n} of {total_projects} projects "
                "with a version)"
            )

        return ResolvedScope(
            label=label,
            version_ids=version_ids,
            project_names=project_names,
            version_displays=version_displays,
        )

    def _folder_name_hint(self, target: str) -> str:
        """Return a ``(a folder named 'X' exists — use folder:X)`` hint.

        Only consulted on the project-not-found failure path. A name match
        against the (already-cached when folder resolution ran) folder list
        keeps this cheap. Returns an empty string when no folder matches.
        """
        try:
            folders = self._fetch_all_folders()
        except Exception:
            return ""
        for f in folders:
            if str(f.get("name", "")).lower() == target.lower():
                return f" (a folder named '{target}' exists — use folder:{target})"
        return ""

    def _fetch_scope_data(
        self, query: "QueryConfig", resolved_scope: "ResolvedScope"
    ) -> pd.DataFrame:
        """Fetch one side's data for every version in *resolved_scope*.

        Routing follows the per-version precedents in this engine:

        * findings endpoint → RSQL ``projectVersion==<id>`` composed with any
          recipe filter via ``;`` (preserving ``finding_type`` / category per
          the ``_fetch_findings`` precedent); reuses the version-keyed cache.
        * components endpoint → URL rewrite to
          ``/public/v0/versions/{id}/components`` (RSQL ``projectVersion==``
          400s on /api/-prefixed deployments) + projectVersion backfill.

        Frames are concatenated across the scope's ``version_ids``. A
        ``project_name`` provenance column is backfilled from
        ``resolved_scope.project_names`` (decision #6).

        See docs/superpowers/specs/2026-05-11-meta-compare-design.md § 4.
        """
        is_findings = query.endpoint.rstrip("/").endswith("/findings")
        recipe_filter = query.params.filter if query.params else None
        limit = (query.params.limit if query.params else None) or 10000

        type_params = build_findings_type_params(self.config.finding_types)
        finding_type = type_params.get("type", "cve") or ""
        category_filter = type_params.get("category_filter")
        # The findings branch composes the recipe's own filter onto the
        # type/category clause so both narrowings survive (RSQL ';' = AND).
        # The category clause (e.g. ``category==CVE``) is meaningful ONLY on
        # the findings endpoint — folding it onto the version-scoped
        # /components endpoint filters the wrong field (or 400s on real
        # deployments), so components get the BARE recipe filter (item 2).
        findings_filter = recipe_filter
        if category_filter:
            findings_filter = (
                f"{category_filter};{recipe_filter}"
                if recipe_filter
                else category_filter
            )

        frames: list[pd.DataFrame] = []
        for version_id in resolved_scope.version_ids:
            project_name = resolved_scope.project_names.get(version_id, "")
            version_display = resolved_scope.version_displays.get(version_id, "")
            if is_findings:
                df = self._fetch_scope_findings(
                    version_id, finding_type, findings_filter, limit
                )
            else:
                df = self._fetch_scope_components(
                    version_id, recipe_filter, limit, project_name, version_display
                )
            if df is None or df.empty:
                continue
            # Provenance backfill (decision #6) — only when rows lack it.
            if "project_name" not in df.columns:
                df["project_name"] = project_name
            else:
                df["project_name"] = df["project_name"].fillna(project_name)
            frames.append(df)

        if not frames:
            return pd.DataFrame()
        return pd.concat(frames, ignore_index=True)

    def _fetch_scope_findings(
        self,
        version_id: str,
        finding_type: str,
        recipe_filter: str | None,
        limit: int,
    ) -> pd.DataFrame:
        """Fetch findings for one version (cache-aware, RSQL-composed)."""
        version_filter = f"projectVersion=={version_id}"
        combined_filter = (
            f"{version_filter};{recipe_filter}" if recipe_filter else version_filter
        )
        # The version-keyed cache key keys on the category filter portion only
        # (the precedent stores per (entity, version, finding_type, category)),
        # so it lines up with sibling Version Comparison entries when the recipe
        # adds no extra clause.
        cached = self._check_version_in_cache(
            version_id, "findings", finding_type, recipe_filter
        )
        if cached is not None:
            return pd.DataFrame(cached) if cached else pd.DataFrame()
        q = QueryConfig(
            endpoint="/public/v0/findings",
            params=QueryParams(
                limit=limit,
                filter=combined_filter,
                finding_type=finding_type,
                archived=False,
                excluded=False,
            ),
        )
        result = self.api_client.fetch_all_with_resume(q, show_progress=False)
        cache_key = self._cache_key("findings", version_id, finding_type, recipe_filter)
        self._version_findings_cache[cache_key] = result
        return pd.DataFrame(result) if result else pd.DataFrame()

    def _fetch_scope_components(
        self,
        version_id: str,
        recipe_filter: str | None,
        limit: int,
        project_name: str,
        version_display: str = "",
    ) -> pd.DataFrame:
        """Fetch components for one version via the version-scoped endpoint.

        URL-rewrite path (RSQL ``projectVersion==`` 400s on /api/-prefixed
        deployments) + projectVersion backfill, mirroring the Component-List
        precedent. Reuses the per-version components cache so a sibling
        Component Diff in the same bundle makes the inventory fetch free.

        The cache key includes the *effective filter* whenever one is present
        so a filtered fetch never poisons the unfiltered key (and vice versa)
        — sibling recipes / inventory fetches that request different filters
        must not cross-contaminate (item 3). The bare key (no filter part) is
        reserved for unfiltered fetches so the inventory / Component Diff
        sharing still works.
        """
        if recipe_filter:
            # Filtered fetch — use a filter-aware key (and skip the shared
            # unfiltered cache helper, which keys only on (entity, version)).
            cache_key = self._cache_key("components", version_id, recipe_filter)
            cached_records = self._version_findings_cache.get(cache_key)
            if cached_records is not None:
                df = pd.DataFrame(cached_records) if cached_records else pd.DataFrame()
            else:
                df = self._fetch_scope_components_fresh(
                    version_id, recipe_filter, limit, cache_key
                )
        else:
            # Unfiltered fetch — share the bare per-version components cache
            # so inventory / Component Diff in the same bundle is free.
            cached = self._check_version_in_cache(version_id, "components")
            if cached is not None:
                df = pd.DataFrame(cached) if cached else pd.DataFrame()
            else:
                df = self._fetch_scope_components_fresh(
                    version_id, None, limit, self._cache_key("components", version_id)
                )

        if df.empty:
            return df
        # Backfill projectVersion (the version-scoped endpoint omits it; the
        # version is implicit in the URL) so downstream transforms reading
        # projectVersion.version don't render "Unknown". The version slot gets
        # the VERSION display name (falling back to the version_id), never the
        # project name (item 1) — mirroring the Component-List precedent.
        if "projectVersion" not in df.columns:
            pv_obj = {
                "id": str(version_id),
                "version": version_display or str(version_id),
            }
            df["projectVersion"] = pd.Series(
                [pv_obj] * len(df), index=df.index, dtype=object
            )
        return df

    def _fetch_scope_components_fresh(
        self,
        version_id: str,
        recipe_filter: str | None,
        limit: int,
        cache_key: str,
    ) -> pd.DataFrame:
        """Fetch components from the version-scoped endpoint and cache them."""
        q = QueryConfig(
            endpoint=f"/public/v0/versions/{version_id}/components",
            params=QueryParams(
                limit=limit,
                filter=recipe_filter,
                archived=False,
                excluded=False,
            ),
        )
        result = self.api_client.fetch_all_with_resume(q, show_progress=False)
        self._version_findings_cache[cache_key] = result
        return pd.DataFrame(result) if result else pd.DataFrame()

    # ------------------------------------------------------------------
    # Meta-compare axis validation (B3.6 — spec § 3, decision #14)
    # ------------------------------------------------------------------

    def _validate_axis_scope_flags(self, recipes: list[Recipe]) -> tuple[bool, str]:
        """Validate --left/--right + standalone-comparison invariants.

        Returns ``(ok, message)``. On ``ok == False`` the caller aborts the
        run with *message*. Rules:

        * ``--left``/``--right`` set but no axis-bearing CompoundRecipe in the
          run → error (those flags only mean something for a meta-compare).
        * a bare ``ComparisonRecipe`` requested standalone (no axis parent in
          the run) → error pointing at ``fs-report compare`` (decision #14).

        Invariant for B3.7: comparison children are assumed NEVER to land in
        this post-filter ``recipes`` list — they are dispatched only as
        ``CompoundRecipe.sections`` via ``_process_compound``, never run
        directly. The ``fs-report compare`` CLI (B3.7) must therefore keep its
        ``extra_recipes`` limited to the compound itself (its children are
        looked up from the corpus by slug, not appended as runnable recipes);
        any comparison child reaching here is a standalone request and is
        rejected above. If B3.7 ever needs to register children as extras,
        the auto-run filter that drops ``category == "comparison"`` recipes
        (see ``run()``) is what keeps them out of this list — keep it.
        """
        has_axis_compound = any(
            isinstance(r, CompoundRecipe) and r.axis is not None for r in recipes
        )
        scopes_set = bool(self.config.left_scope or self.config.right_scope)

        standalone_comparisons = [
            r.name for r in recipes if isinstance(r, ComparisonRecipe)
        ]
        if standalone_comparisons:
            # M1-12 (round-4 item 6): explain comparison recipes run INSIDE an
            # axis bundle (not "positionally"), and show the exact invocation.
            example_name = standalone_comparisons[0]
            return (
                False,
                f"Comparison recipe '{example_name}' runs only inside a "
                "meta-compare. Use: fs-report compare "
                f"{example_name} --left <scope> --right <scope>.",
            )

        if scopes_set and not has_axis_compound:
            return (
                False,
                "--left / --right only apply to a meta-compare bundle (an "
                "axis-bearing compound recipe). The selected recipe(s) are "
                "not a meta-compare. Use 'fs-report compare' or select a "
                "saved meta-compare bundle.",
            )

        return (True, "")

    # ------------------------------------------------------------------
    # Per-section effective config (compound override merge)
    # ------------------------------------------------------------------

    def _compound_run_effective(self) -> dict[str, Any]:
        """The run-level effective config seen by every compound child.

        Reads the already-resolved ``self.config`` scope/AI/finding-type/date
        fields into a dict shaped like the workflow effective config (date mode
        expressed as ``period`` OR ``start``/``end``). This is the LOWER-priority
        side of the per-section merge — a section override layers on top.

        Note the date mode is carried as ``start``/``end`` (the resolved run
        window) so a section that overrides ``period`` correctly CLEARS the run
        range via the period↔range mutual-exclusion in the merge (mirrors the
        workflow ``_effective_step_config``).
        """
        eff: dict[str, Any] = {}
        for key in (
            "project_filter",
            "folder_filter",
            "version_filter",
            "finding_types",
            "current_version_only",
            "ai",
            "ai_depth",
        ):
            val = getattr(self.config, key, None)
            if val is not None and val != "":
                eff[key] = val
        # Run window as start/end (the engine resolves period→start_date/end_date
        # at config build, so the live run mode is always a range here).
        if getattr(self.config, "start_date", None):
            eff["start"] = self.config.start_date
        if getattr(self.config, "end_date", None):
            eff["end"] = self.config.end_date
        return eff

    def _section_overrides(self, section: "SectionRef") -> dict[str, Any]:
        """Whitelisted, coerced, non-empty overrides for one section (or {})."""
        from fs_report.compound_overrides import effective_child_config

        # effective_child_config(base={}, overrides) returns just the cleaned,
        # coerced override dict (no run-level keys) — reuse it so the whitelist /
        # coercion / emptiness rules live in ONE place.
        return effective_child_config({}, getattr(section, "overrides", None))

    @contextmanager
    def _apply_section_config(
        self, section: "SectionRef"
    ) -> "Generator[bool, None, None]":
        """Temporarily apply a section's effective config to ``self.config``.

        Yields ``True`` when the section's overridden scope re-resolved cleanly
        (or there were no scope overrides), ``False`` when a scope override
        failed to resolve (the caller records a FailedSection). Restores
        ``self.config`` / ``self.api_client.config`` / ``resolved_project_name``
        / ``_folder_project_ids`` on exit, so the next child sees the run-level
        config again. Not re-entrant: it assumes the section loop is sequential
        and never nested (compound nesting is rejected by validation), since a
        nested call would clobber the saved run-level snapshot.

        Precedence (highest→lowest): section override ▸ run-level effective
        config (``self.config``) ▸ recipe/engine defaults. The authored bundle
        ``global`` block is deliberately NOT re-applied here — this path only
        layers the per-SECTION overrides onto the run-level config, so the
        global can never be double-applied on top of a section override.
        """
        from fs_report.compound_overrides import effective_child_config

        overrides = self._section_overrides(section)
        if not overrides:
            # No-op fast path: child runs under the run-level config unchanged.
            yield True
            return

        run_eff = self._compound_run_effective()
        child_eff = effective_child_config(run_eff, getattr(section, "overrides", None))

        # Scope-provenance precedence — mirrors the workflow _effective_step_config
        # so an inherited run-level scope can't combine into an invalid pairing.
        step_sets_project = bool(str(overrides.get("project_filter") or "").strip())
        step_sets_folder = bool(str(overrides.get("folder_filter") or "").strip())
        step_sets_version = bool(str(overrides.get("version_filter") or "").strip())
        # A folder-only section drops the INHERITED run-level project + version
        # (folder-wins for that child).
        if step_sets_folder and not step_sets_project:
            child_eff.pop("project_filter", None)
            child_eff.pop("version_filter", None)
        # A section retargeting its OWN project drops an inherited version (that
        # version ID belongs to the run-level project, not this one) unless it
        # supplies its own version.
        if step_sets_project and not step_sets_version:
            child_eff.pop("version_filter", None)
        # Project-wins: an effective project means the folder was only a UI
        # filter and must not travel into the engine (it would force the
        # stricter project-in-folder intersection).
        if str(child_eff.get("project_filter") or "").strip():
            child_eff.pop("folder_filter", None)

        # Translate the merged effective dict back onto a Config copy. Scope keys
        # are forced (set even when they resolved to empty above) so a child that
        # dropped an inherited project/version/folder doesn't keep the run-level
        # value on the copied Config.
        update: dict[str, Any] = {}
        for k in ("project_filter", "folder_filter", "version_filter"):
            update[k] = child_eff.get(k) or None
        for k in (
            "finding_types",
            "current_version_only",
            "ai",
            "ai_depth",
        ):
            if k in child_eff:
                update[k] = child_eff[k]
        # Date mode → start_date/end_date. A section ``period`` is resolved to a
        # window via PeriodParser (same as create_config); a section start/end
        # pair is used verbatim. period↔range exclusion was already applied by
        # effective_child_config, so child_eff carries at most ONE mode.
        if child_eff.get("start") and child_eff.get("end"):
            update["start_date"] = child_eff["start"]
            update["end_date"] = child_eff["end"]
            update["period_explicit"] = True
        elif child_eff.get("period"):
            from fs_report.period_parser import PeriodParser

            try:
                _s, _e = PeriodParser.parse_period(str(child_eff["period"]))
                update["start_date"] = _s
                update["end_date"] = _e
                update["period_explicit"] = True
            except ValueError:
                self.logger.warning(
                    "Section override period %r could not be parsed; "
                    "keeping the run-level window.",
                    child_eff["period"],
                )

        # A scope override means we must re-resolve names→IDs for this child.
        scope_overridden = any(
            key in overrides
            for key in ("project_filter", "folder_filter", "version_filter")
        )

        saved_config = self.config
        saved_api_config = self.api_client.config
        saved_resolved_name = self.resolved_project_name
        saved_folder_ids = self._folder_project_ids
        child_config = self.config.model_copy(update=update)
        self.config = child_config
        self.api_client.config = child_config
        # A retargeted scope starts from a clean folder-id set so a prior
        # child's glob/folder expansion doesn't leak in.
        if scope_overridden:
            self._folder_project_ids = None
            self.resolved_project_name = None
        try:
            ok = self._resolve_run_scope() if scope_overridden else True
            yield ok
        finally:
            self.config = saved_config
            self.api_client.config = saved_api_config
            self.resolved_project_name = saved_resolved_name
            self._folder_project_ids = saved_folder_ids

    # ------------------------------------------------------------------
    # Compound-recipe dispatch
    # ------------------------------------------------------------------

    def _process_compound(
        self,
        compound: "CompoundRecipe",
        all_recipes_index: dict[str, Recipe],
    ) -> "RecipeResult":
        """Render one CompoundRecipe — see compound-reports spec § 4.

        Steps:

        1. Resolve each ``compound.sections[].recipe`` to a child Recipe
           via the slug-keyed corpus index. Loader-level validation has
           already enforced this, but a defensive check guards against
           an out-of-band ``all_recipes_index`` mismatch.
        2. Run per-child pre-checks (``requires_project``,
           ``requires_cve``, ``requires_project_or_folder``); if any
           child can't satisfy them under the current scope, fail the
           bundle fast — no partial output.
        3. Reject folder-iterating recipes (Remediation Package without
           ``--project``) at runtime, before any child runs.
        4. For each child: call ``_process_recipe`` for the data, then
           ``HTMLRenderer.render_fragment(...,
           fragment_scripts_enabled=True, suppress_section_title=True)``.
           Catch transform exceptions and ``None`` returns alike and
           record them as ``FailedSection`` entries.
        5. Run the compound assembler to build the bundled HTML.
        6. Call ``PDFRenderer.render_html()`` to produce the bundled PDF.
        7. Return a ``RecipeResult`` describing the compound output
           directory, files, and per-child stats.

        Always returns a ``RecipeResult``. Pre-check or folder-iterator
        rejections produce a result with empty ``files`` and
        ``stats["error"]`` set so programmatic consumers can distinguish
        "compound skipped at pre-check" from "compound never reached".
        PDF render failures keep the HTML in place and surface via
        logged warnings (HTML still ships; CLI exits non-zero via
        ``any_failed`` stat). (PR #100 round-1 multi-review N4.)

        When ``compound.axis is not None`` (a meta-compare bundle), dispatch
        is routed to ``_process_axis_compound`` (B3.6 — meta-compare design
        spec § 4): the two scopes are resolved ONCE for the bundle, each
        comparison child is fetched for left+right and diffed, and the
        ``requires_*`` pre-checks (which describe single-scope recipes) are
        skipped — the axis scopes replace them.
        """
        from fs_report.renderers.html_renderer import HTMLRenderer

        def _precheck_failure(message: str) -> RecipeResult:
            self.logger.error(message)
            return RecipeResult(
                recipe=compound.name,
                output_dir="",
                files=[],
                stats={"error": message, "any_failed": True},
            )

        # ---- Axis branch: a meta-compare bundle. Resolve both scopes once,
        # then fetch+diff each comparison child. The single-scope pre-checks
        # below don't apply (axis scopes replace requires_project etc.).
        # Route to the axis path ONLY when the compound itself declares an axis.
        # The config left_scope/right_scope are runtime overrides that only
        # matter for an axis compound — a non-axis compound must never take the
        # comparison path even if both scopes happen to be set (PR review A).
        if compound.axis is not None:
            return self._process_axis_compound(
                compound, all_recipes_index, _precheck_failure
            )

        # ---- 1. Resolve children + 2. pre-checks + 3. folder rejection.
        children: list[Recipe] = []
        for section in compound.sections:
            child_slug = _slug(section.recipe)
            child = all_recipes_index.get(child_slug)
            if child is None:
                return _precheck_failure(
                    f"Compound '{compound.name}' references unknown child "
                    f"recipe '{section.recipe}' (slug='{child_slug}'). "
                    "Loader validation should have caught this — failing "
                    "fast to surface the index mismatch."
                )

            # Folder-iterating recipes can't ride a single sections[] entry
            # because they fan out one render per project under the same
            # fs-section-<slug> scope — every per-project fragment would
            # collide on ids. Reject the whole bundle BEFORE any child runs
            # so we don't leak partial output.
            # Note: the same recipe name is encoded in
            # recipe_requirements._NAME_REQUIRES_PROJECT_OR_FOLDER; keep
            # in sync if this recipe is ever renamed.
            if (
                child.name == "Remediation Package"
                and not self.config.project_filter
                and self._folder_project_ids
            ):
                return _precheck_failure(
                    f"Compound '{compound.name}' includes "
                    f"'{child.name}' under --folder scope. Folder-iterating "
                    "recipes can't be bundled in v1 — pass --project explicitly "
                    "or remove the recipe from the bundle. See compound-reports "
                    "design spec § 4."
                )

            # Per-child requires_* pre-checks. Bundle fails fast — partial
            # bundles with missing sections are confusing.
            # Use the shared predicate (recipe_requirements) so this path
            # and the web prerun computation (PR2.3) can't diverge.  The
            # predicate also enforces name-based rules (e.g. "Remediation
            # Package" requires project-or-folder despite declaring no flag),
            # closing a gap where that child was previously not pre-checked.
            #
            # Scope requirements are evaluated against the section's EFFECTIVE
            # scope (run-level ▸ section override): a section that retargets
            # ``project_filter`` satisfies a ``requires_project`` child even when
            # the bundle carries no run-level project. ``cve_filter`` /
            # ``component_filter`` are NOT section-overridable (not in the
            # whitelist), so those checks read run-level config only.
            _sec_ov = self._section_overrides(section)
            _eff_project = str(
                _sec_ov.get("project_filter") or self.config.project_filter or ""
            ).strip()
            _eff_folder = str(
                _sec_ov.get("folder_filter") or self.config.folder_filter or ""
            ).strip()
            _reqs = recipe_requirements(child)
            if _reqs.requires_project and not _eff_project:
                return _precheck_failure(
                    f"Compound '{compound.name}' child '{child.name}' "
                    "requires --project. Pass --project <name-or-id>."
                )
            if _reqs.requires_cve and not getattr(self.config, "cve_filter", None):
                return _precheck_failure(
                    f"Compound '{compound.name}' child '{child.name}' "
                    "requires --cve."
                )
            if (
                _reqs.requires_project_or_folder
                and not _eff_project
                and not _eff_folder
            ):
                return _precheck_failure(
                    f"Compound '{compound.name}' child '{child.name}' "
                    "requires --project or --folder."
                )
            if (
                _reqs.requires_component
                and not str(
                    getattr(self.config, "component_filter", None) or ""
                ).strip()
            ):
                return _precheck_failure(
                    f"Compound '{compound.name}' child '{child.name}' "
                    "requires --component."
                )

            children.append(child)

        # ---- 3.5. Resolve formats + 3.6. output guard (shared helper). ----
        compound_slug = _slug(compound.name)
        output_dir = Path(self.config.output_dir) / compound_slug
        wants_html, wants_pdf = self._compound_output_guard(compound, output_dir)

        # ---- 4. Per-child data fetch + fragment render.
        html_renderer = HTMLRenderer()
        section_results: list[SectionResult] = []
        chart_libraries_union: list[str] = []
        extra_files: list[str] = []
        any_failed = False
        for i, child in enumerate(children):
            # Observe cancellation between children so long bundles
            # don't run to completion after a user cancel. Other engine
            # loops re-check between work units; the compound loop now
            # matches. (PR #100 round-1 multi-review N3.)
            #
            # The cancel check is OUTSIDE the try/finally below so a cancel
            # raises ReportCancelled BEFORE we announce the child as running
            # — a cancelled child fires NEITHER the start NOR the complete
            # hook (it never executed). (Pass 4 Run canvas.)
            self._check_cancel()
            # Additive, optional Run-canvas hook: announce this child as
            # starting. Defensive try/except mirrors _on_recipe_complete so a
            # misbehaving observer can never break the render.
            if self._on_section_start:
                try:
                    self._on_section_start(i, child.name)
                except Exception:
                    self.logger.exception(
                        f"on_section_start hook raised for compound "
                        f"'{compound.name}' child '{child.name}'"
                    )
            child_slug = _slug(child.name)
            child_title = getattr(child.output, "slide_title", None) or child.name
            # The per-child body sits in a try/finally so the completion hook
            # fires from a SINGLE place reached by EVERY path — the success
            # path AND all three failure paths (each ends in `continue`). The
            # `finally` runs before the loop continues, and `ok` is derived
            # from the section result actually appended for THIS child, so a
            # child that survives _process_recipe but then fails in
            # render_fragment (or returns None data) is correctly reported as
            # ok=False. (Pass 4 Run canvas — the completion-placement invariant.)
            section_count_before = len(section_results)
            # A Stop during an in-flight child surfaces as ReportCancelled from
            # _process_recipe / render_fragment. It must PROPAGATE (so the run
            # ends status="cancelled" via _execute_run's handler) — NOT be
            # swallowed as a FailedSection by the bare `except Exception` below,
            # which (on the LAST child) would let the compound assemble a partial
            # bundle and report "error" instead of "cancelled" (cancel-parity
            # bug, multi-review R2 M1-1). The flag suppresses the completion hook
            # for the cancelled child (it never finished).
            _child_cancelled = False
            # Per-section effective config (run-level ▸ section override). The
            # context swaps self.config (+ api_client.config) for the duration of
            # THIS child's fetch+render and restores it afterwards, so a saved
            # override actually steers the child's data fetch / transform. A
            # scope override that fails to re-resolve yields False → FailedSection.
            _section = compound.sections[i]
            try:
                _scope_ctx = self._apply_section_config(_section)
                _scope_ok = _scope_ctx.__enter__()
            except Exception as exc:  # pragma: no cover — defensive
                self.logger.error(
                    f"Compound '{compound.name}' child '{child.name}' "
                    f"raised applying section overrides: {exc}"
                )
                section_results.append(
                    FailedSection(slug=child_slug, title=child_title, error=str(exc))
                )
                any_failed = True
                if not _child_cancelled and self._on_section_complete:
                    try:
                        self._on_section_complete(i, child.name, False)
                    except Exception:
                        self.logger.exception(
                            f"on_section_complete hook raised for compound "
                            f"'{compound.name}' child '{child.name}'"
                        )
                continue
            try:
                if not _scope_ok:
                    self.logger.error(
                        f"Compound '{compound.name}' child '{child.name}' "
                        "section scope override could not be resolved."
                    )
                    section_results.append(
                        FailedSection(
                            slug=child_slug,
                            title=child_title,
                            error="section scope override could not be resolved",
                        )
                    )
                    any_failed = True
                    continue
                try:
                    report_data = self._process_recipe(child)
                except ReportCancelled:
                    _child_cancelled = True
                    raise
                except Exception as exc:
                    self.logger.error(
                        f"Compound '{compound.name}' child '{child.name}' "
                        f"raised during _process_recipe: {exc}"
                    )
                    section_results.append(
                        FailedSection(
                            slug=child_slug, title=child_title, error=str(exc)
                        )
                    )
                    any_failed = True
                    continue

                if report_data is None:
                    self.logger.error(
                        f"Compound '{compound.name}' child '{child.name}' "
                        "returned no report data."
                    )
                    section_results.append(
                        FailedSection(
                            slug=child_slug,
                            title=child_title,
                            error="no report data",
                        )
                    )
                    any_failed = True
                    continue

                try:
                    fragment_html = html_renderer.render_fragment(
                        child,
                        report_data,
                        heading_depth=2,
                        fragment_scripts_enabled=True,
                        suppress_section_title=True,
                    )
                except ReportCancelled:
                    _child_cancelled = True
                    raise
                except Exception as exc:
                    self.logger.error(
                        f"Compound '{compound.name}' child '{child.name}' "
                        f"raised during render_fragment: {exc}"
                    )
                    section_results.append(
                        FailedSection(
                            slug=child_slug, title=child_title, error=str(exc)
                        )
                    )
                    any_failed = True
                    continue

                # Expose the comparison child's facet summary dict to the
                # assembler so the compound exec overview can bind to it.
                # report_data.data is the transform dict; its ``summary`` key
                # holds the facet counts. None for non-comparison children.
                child_summary = (
                    report_data.data.get("summary")
                    if isinstance(getattr(report_data, "data", None), dict)
                    else None
                )
                child_summary = (
                    child_summary if isinstance(child_summary, dict) else None
                )
                # Expose the comparison child's per-facet row lists (§5a) so the
                # assembler's Action Plan can bind to them. Extract only the six
                # known keys when present; None for non-comparison children.
                child_rows = _extract_comparison_rows(
                    getattr(report_data, "data", None)
                )
                section_results.append(
                    RenderedFragment(
                        slug=child_slug,
                        title=child_title,
                        html=fragment_html,
                        summary=child_summary,
                        rows=child_rows,
                    )
                )
                # Only surviving children contribute libraries to the shell's
                # <head> union (spec § 5 step 4).
                chart_libraries_union.extend(child.chart_libraries)
                # Some child transforms emit side-effect files (VEX JSON,
                # AI prompts) via report_data.metadata. Standalone runs surface
                # these in generated_files; compounds should too so a saved
                # bundle's VEX export isn't invisible to automation.
                # (PR #100 round-1 multi-review N6.)
                child_extra = (
                    report_data.metadata.get("additional_data", {}).get(
                        "_extra_generated_files", []
                    )
                    if isinstance(report_data.metadata, dict)
                    else []
                )
                if child_extra:
                    extra_files.extend(child_extra)
            finally:
                # Restore the run-level config (the section-config swap is scoped
                # to THIS child). The context manager only restores in its own
                # finally — it never suppresses exceptions — so calling __exit__
                # with no exc info here is correct even when ReportCancelled is
                # propagating through this finally.
                try:
                    _scope_ctx.__exit__(None, None, None)
                except Exception:  # pragma: no cover — defensive
                    self.logger.exception(
                        f"Restoring section config raised for compound "
                        f"'{compound.name}' child '{child.name}'"
                    )
                # Fire exactly once per child that started, from the single
                # exit point every path passes through. ``ok`` reflects the
                # FINAL section result appended for this child: a
                # RenderedFragment means success; any FailedSection (from any
                # of the three failure paths above) means failure. Defensive
                # try/except so a hook exception can never break the render.
                # A child cancelled mid-flight (ReportCancelled propagating)
                # fires NEITHER hook — it never finished (R2 M1-1).
                if not _child_cancelled and self._on_section_complete:
                    ok = len(section_results) > section_count_before and isinstance(
                        section_results[-1], RenderedFragment
                    )
                    try:
                        self._on_section_complete(i, child.name, ok)
                    except Exception:
                        self.logger.exception(
                            f"on_section_complete hook raised for compound "
                            f"'{compound.name}' child '{child.name}'"
                        )

        # ---- 5. Assemble HTML + 6. render PDF + 7. RecipeResult (shared). ----
        return self._finalize_compound_render(
            compound,
            output_dir=output_dir,
            compound_slug=compound_slug,
            wants_html=wants_html,
            wants_pdf=wants_pdf,
            html_renderer=html_renderer,
            section_results=section_results,
            chart_libraries_union=chart_libraries_union,
            extra_files=extra_files,
            any_failed=any_failed,
        )

    # ------------------------------------------------------------------
    # Shared compound finalize (used by both non-axis and axis paths)
    # ------------------------------------------------------------------

    def _compound_output_guard(
        self,
        compound: "CompoundRecipe",
        output_dir: Path,
        *,
        force_overwrite: bool = False,
    ) -> tuple[bool, bool]:
        """Resolve formats + run the output-directory overwrite guard.

        Returns ``(wants_html, wants_pdf)``. Raises ``FileExistsError`` when
        a deliverable would be written into a non-empty directory without
        ``--overwrite``. Both compound paths call this before the per-child
        fetch loop so a blocked overwrite doesn't waste API + transform work.
        (PR #100 round-2 M1-1; round-3 M2-1/M3-1.)

        ``force_overwrite`` (M1-3): the meta-compare (axis) path passes True so
        a re-run regenerates its output directory unconditionally. A meta-
        compare ALWAYS executes and regenerates the report, so the output-dir
        guard must not block a second run; ``--overwrite`` governs only the
        saved YAML there, not the deliverable directory.
        """
        formats = [f.lower() for f in (compound.output.formats or [])]
        wants_html = "html" in formats
        wants_pdf = "pdf" in formats
        if not (wants_html or wants_pdf):
            self.logger.warning(
                f"Compound '{compound.name}' resolved to formats={formats!r} — "
                "no HTML or PDF deliverable will be produced. Children still "
                "run for side-effect files (VEX, prompts). Set "
                "output.formats explicitly in the bundle YAML to silence "
                "this warning."
            )
        if force_overwrite:
            # M3-3: the meta-compare path forces overwrite so a re-run isn't
            # blocked — but a forced re-run must also REMOVE pre-existing files
            # in the compound's OWN output subdirectory. Otherwise stale
            # artifacts linger (an old `.pdf` when a later run is html-only, or
            # a renamed file) alongside the fresh output. Scoped strictly to
            # ``output/<compound-slug>/`` — never a parent or user dir.
            if wants_html or wants_pdf:
                self._clean_compound_output_dir(compound, output_dir)
        elif wants_html or wants_pdf:
            if (
                output_dir.exists()
                and any(output_dir.iterdir())
                and not self.renderer.overwrite
            ):
                raise FileExistsError(
                    f"Compound output directory '{output_dir}' already contains "
                    "files. Use --overwrite to replace existing reports."
                )
        return wants_html, wants_pdf

    def _clean_compound_output_dir(
        self, compound: "CompoundRecipe", output_dir: Path
    ) -> None:
        """Remove pre-existing files in the compound's OWN output subdirectory.

        Called only on the force-overwrite (meta-compare) path before fresh
        artifacts are written, so stale files from a prior run (an old `.pdf`,
        a renamed leftover) don't linger. Deliberately conservative:

        * The target MUST be ``<config.output_dir>/<compound-slug>`` — we
          recompute the slug here and refuse to touch anything else (guards
          against an empty slug or path traversal upstream).
        * We never recurse into or delete a parent / user directory; only the
          direct contents of the compound's own subdir are removed.
        """
        compound_slug = _slug(compound.name)
        # Defensive: _slug never returns empty (falls back to "section"), but
        # re-assert before any unlink so a future regression can't widen scope.
        if not compound_slug:
            return
        base = Path(self.config.output_dir).resolve()
        expected = (base / compound_slug).resolve()
        try:
            resolved = output_dir.resolve()
        except OSError:
            return
        # The dir we're about to clean must be EXACTLY the compound's own
        # output subdir under the configured output base — not a parent, not a
        # sibling, not the base itself. Refuse anything that doesn't match.
        if resolved != expected or resolved == base or resolved.parent != base:
            self.logger.warning(
                f"Refusing to clean compound output dir '{output_dir}': "
                f"resolved path '{resolved}' is not the expected "
                f"'{expected}' under output base '{base}'."
            )
            return
        if not resolved.is_dir():
            return
        for entry in resolved.iterdir():
            try:
                if entry.is_file() or entry.is_symlink():
                    entry.unlink(missing_ok=True)
                elif entry.is_dir():
                    import shutil

                    shutil.rmtree(entry, ignore_errors=True)
            except OSError as exc:
                self.logger.warning(
                    f"Could not remove stale compound artifact '{entry}': {exc}"
                )

    def _finalize_compound_render(
        self,
        compound: "CompoundRecipe",
        *,
        output_dir: Path,
        compound_slug: str,
        wants_html: bool,
        wants_pdf: bool,
        html_renderer: Any,
        section_results: list[SectionResult],
        chart_libraries_union: list[str],
        extra_files: list[str],
        any_failed: bool,
        runtime_scope_extra: dict[str, str] | None = None,
        facet_titles: list[str] | None = None,
        left_leads: bool | None = None,
    ) -> "RecipeResult":
        """Assemble the shell, render the PDF, and build the RecipeResult.

        Shared by the non-axis and axis (meta-compare) compound paths so the
        two never drift on overwrite/PDF/return semantics.
        ``runtime_scope_extra`` lets the axis path inject ``left_scope`` /
        ``right_scope`` cover labels on top of the base substitution vars.
        ``facet_titles`` carries the ordered child section display titles for
        the comparison cover's Facets row (axis path only; ``None`` on the
        non-axis path, which renders no Facets row).
        ``left_leads`` carries the axis path's already-computed pass-1 leader
        direction into the assembler (single source of truth — M1-1 / M1-5 /
        M3-3) so the verdict band, cover, action plan, and the surviving
        fragments share ONE direction even across a render failure. ``None`` on
        the non-axis path (no leader); the assembler then falls back to
        ``compute_left_leads`` over the RenderedFragment summaries.
        """
        from fs_report.compound_assembler import assemble
        from fs_report.renderers.pdf_renderer import PDFRenderer

        html_path = output_dir / f"{compound_slug}.html"
        pdf_path = output_dir / f"{compound_slug}.pdf"
        if wants_html or wants_pdf:
            output_dir.mkdir(parents=True, exist_ok=True)

        runtime_scope = self._build_compound_runtime_scope(compound)
        if runtime_scope_extra:
            runtime_scope.update(runtime_scope_extra)
        logo_data_uri = self._resolve_compound_logo_data_uri(
            compound.cover.logo if compound.cover else None
        )
        tokens_inline_css = html_renderer._tokens_inline_css

        written_files: list[str] = []
        # Child side-effect files (e.g. VEX JSON) are part of the bundle's
        # output regardless of compound.output.formats — they're emitted
        # by the child transforms, not by the assembler.
        written_files.extend(extra_files)

        # Only write the HTML if we'll consume it (as a deliverable or
        # as the PDF source). When formats is explicitly empty, we still
        # ran the children for their side effects but produce no shell.
        if wants_html or wants_pdf:
            assembled_html = assemble(
                compound,
                runtime_scope=runtime_scope,
                section_results=section_results,
                chart_libraries=chart_libraries_union,
                tokens_inline_css=tokens_inline_css,
                logo_data_uri=logo_data_uri,
                facet_titles=facet_titles,
                left_leads=left_leads,
            )
            html_path.write_text(assembled_html, encoding="utf-8")
            if wants_html:
                written_files.append(str(html_path))

        if wants_pdf:
            try:
                pdf_renderer = PDFRenderer()
                pdf_renderer.render_html(
                    html_path,
                    pdf_path,
                    # Inherited OutputConfig overrides — when the bundle
                    # YAML declares pdf_footer_template / pdf_margin,
                    # those win over the shell's defaults. The string-
                    # template footer wins over the compound-footer
                    # template-id fallback inside render_html(). (PR #100
                    # round-1 multi-review J1, J2, M2-3.)
                    footer_template=compound.output.pdf_footer_template,
                    pdf_footer_template_id="compound-footer",
                    pdf_header_template_id=compound.output.pdf_header_template_id,
                    pdf_margin=compound.output.pdf_margin,
                    # Spec § 5: the compound assembler ALWAYS passes
                    # wait_for_chart_beacon=True. The shell template
                    # includes the readiness partials unconditionally
                    # (counter clamps to 0 / safety net flips to true
                    # if no charts construct) so chart-free bundles
                    # aren't penalized. (PR #100 round-1 multi-review J4.)
                    wait_for_chart_beacon=True,
                )
                written_files.append(str(pdf_path))
                # PDF-only deliverables don't keep the intermediate HTML.
                # On PDF failure we DO keep it AND surface it (caller can
                # re-render or triage), which is why the unlink is in the
                # success branch only.
                if not wants_html:
                    html_path.unlink(missing_ok=True)
            except Exception as exc:
                # PDF failure does NOT roll back the HTML — caller sees
                # the bundled HTML for triage. Surface it in written_files
                # even when "html" wasn't a requested format so
                # programmatic consumers can discover the artifact
                # without parsing logs. (PR #100 round-2 multi-review
                # M1-2.) CLI exits non-zero via any_failed.
                self.logger.error(
                    f"Compound '{compound.name}' PDF render failed: {exc}. "
                    f"HTML preserved at {html_path}."
                )
                any_failed = True
                if not wants_html and html_path.exists():
                    written_files.append(str(html_path))

        # Per-child stats: which slugs rendered, which failed, what the
        # union of chart libraries looked like.
        rendered_slugs = [
            r.slug for r in section_results if isinstance(r, RenderedFragment)
        ]
        failed_slugs = [r.slug for r in section_results if isinstance(r, FailedSection)]
        stats: dict[str, Any] = {
            "sections_total": len(section_results),
            "sections_rendered": len(rendered_slugs),
            "sections_failed": len(failed_slugs),
            "rendered_slugs": rendered_slugs,
            "failed_slugs": failed_slugs,
            "chart_libraries": sorted(set(chart_libraries_union)),
            "any_failed": any_failed,
        }
        # M1-12: when the bundle completes but one or more children failed,
        # carry a short summary naming the failed sections in stats["error"] so
        # both `run` and `compare` can surface specifics (which sections) rather
        # than the generic banner. (A PDF-render failure with no failed_slugs
        # still sets any_failed; describe that case too.)
        if any_failed:
            if failed_slugs:
                joined = ", ".join(failed_slugs)
                section_word = "section" if len(failed_slugs) == 1 else "sections"
                stats["error"] = (
                    f"Compound '{compound.name}': {len(failed_slugs)} of "
                    f"{len(section_results)} {section_word} failed ({joined}). "
                    "See logs for per-section details."
                )
            else:
                stats["error"] = (
                    f"Compound '{compound.name}' completed with errors "
                    "(see logs — e.g. PDF render)."
                )
        return RecipeResult(
            recipe=compound.name,
            output_dir=str(output_dir),
            files=written_files,
            stats=stats,
        )

    # ------------------------------------------------------------------
    # Axis (meta-compare) compound dispatch (B3.6 — spec § 4)
    # ------------------------------------------------------------------

    def _process_axis_compound(
        self,
        compound: "CompoundRecipe",
        all_recipes_index: dict[str, Recipe],
        precheck_failure: "Callable[[str], RecipeResult]",
    ) -> "RecipeResult":
        """Dispatch a meta-compare bundle — see meta-compare design spec § 4.

        Resolve the two scopes ONCE for the whole compound, then for each
        comparison child: fetch left+right data, optionally fetch each side's
        component inventory (``needs_component_inventory``), run the comparison
        transform, and render a fragment. Per-child failures are isolated as
        ``FailedSection`` entries (the bundle completes; ``any_failed`` drives
        the non-zero exit). The cover gains ``left_scope`` / ``right_scope``
        labels.
        """
        from fs_report.renderers.html_renderer import HTMLRenderer

        # ---- Resolve the two sides ONCE. Runtime --left/--right override
        # any pinned axis.left / axis.right.
        axis = compound.axis or AxisConfig(left=None, right=None)
        left_raw = self.config.left_scope or axis.left
        right_raw = self.config.right_scope or axis.right
        if not left_raw or not right_raw:
            return precheck_failure(
                f"Recipe '{compound.name}' requires --left and --right flags."
            )

        if self.config.period_explicit:
            self.logger.warning(
                "Meta-compare: --period is ignored — the compared scopes are "
                "explicit (--left / --right or the bundle's pinned axis)."
            )

        try:
            left_ref = _parse_scope_ref(left_raw)
            right_ref = _parse_scope_ref(right_raw)
        except ScopeRefError as exc:
            return precheck_failure(
                f"Recipe '{compound.name}' has an invalid scope reference: {exc}"
            )

        try:
            left_scope = self._resolve_scope(left_ref)
            right_scope = self._resolve_scope(right_ref)
        except Exception as exc:
            # Broadened from ValueError (M1-3/M1-4): scope resolution issues
            # API calls (project / folder / version lookups) that can raise
            # auth / network / API-status errors, not just the curated
            # ValueErrors. Convert ALL of them into a clean precheck failure
            # (RunResult.error_message set) so the run fails cleanly via the
            # same path instead of surfacing an uncaught traceback.
            return precheck_failure(
                f"Recipe '{compound.name}' scope resolution failed: {exc}"
            )

        if left_scope.label == right_scope.label or left_raw == right_raw:
            self.logger.warning(
                "Meta-compare: left and right resolve to the same scope "
                f"('{left_scope.label}'). Producing a self-comparison "
                "(useful as a sanity check)."
            )

        # ---- Resolve children (loader guarantees ComparisonRecipe; keep a
        # defensive check). The single-scope requires_* pre-checks don't
        # apply — axis scopes replace them.
        children: list[Recipe] = []
        for section in compound.sections:
            child_slug = _slug(section.recipe)
            child = all_recipes_index.get(child_slug)
            if child is None:
                return precheck_failure(
                    f"Compound '{compound.name}' references unknown child "
                    f"recipe '{section.recipe}' (slug='{child_slug}')."
                )
            children.append(child)

        # Ordered child section display titles (compound.sections source order)
        # for the cover's Facets row — resolved here at cover time from the
        # loaded child Recipe objects using the SAME rule the section
        # divider/TOC uses (spec §6 R5 M1-4). Passed to the assembler so the
        # cover Facets match the actual section headers, not the bare recipe
        # canonical names.
        facet_titles = [
            getattr(child.output, "slide_title", None) or child.name
            for child in children
        ]

        compound_slug = _slug(compound.name)
        output_dir = Path(self.config.output_dir) / compound_slug
        # M1-3: a meta-compare ALWAYS executes and regenerates the report, so a
        # re-run into an existing output dir must not be blocked by the compound
        # output guard. ``--overwrite`` governs only the saved YAML for compare,
        # not the deliverable directory — force the output regeneration here.
        wants_html, wants_pdf = self._compound_output_guard(
            compound, output_dir, force_overwrite=True
        )

        html_renderer = HTMLRenderer()
        section_results: list[SectionResult] = []
        chart_libraries_union: list[str] = []
        # Intentionally empty: no current comparison transform emits
        # side-effect files (prompts / VEX JSON). Revisit if one does — wire
        # the transform's extra files into this list before finalize.
        extra_files: list[str] = []
        any_failed = False

        # ---- TWO-PASS dispatch (spec § 5.0 / G0). The playbook needs the
        # leader/laggard direction inside the per-child fragments, but the
        # direction is only knowable after every facet's transform has produced
        # its summary. So we split the single child loop into two passes over
        # the SAME children in source order:
        #
        #   Pass 1 (transform): fire on_section_start, run the comparison
        #     transform (the API fetch happens HERE, once), and STORE each
        #     report_data. No render yet. A child that can't transform records
        #     a FailedSection, fires its on_section_complete(ok=False) right
        #     here (so every started child still gets exactly one complete),
        #     and is skipped in pass 2.
        #   Between passes: compute left_leads from whatever facet summaries
        #     survived pass 1 (shared compute_left_leads → agrees with the
        #     assembler verdict on identical summaries; see its docstring for
        #     the lone transform-ok/render-fail edge).
        #   Pass 2 (render): inject left_leads / leader_label / laggard_label
        #     into each stored report_data.data, render the fragment, and fire
        #     on_section_complete when the fragment is rendered.
        #
        # Hook timing (M2-4 — the Run canvas's sole compound progress source):
        # on_section_start in pass 1, on_section_complete in pass 2 (or in
        # pass 1 for a child that failed there). Exactly one start+complete
        # pair per child in a non-cancelled run. A child cancelled mid-flight
        # (ReportCancelled) fires NEITHER hook from that point and propagates
        # (run ends status="cancelled"); children that only finished their
        # pass-1 transform before the cancel have fired start but not yet
        # complete — the run aborts before pass 2, exactly as a cancel should.
        from fs_report.compound_assembler import compute_left_leads

        # Per-child carry from pass 1 → pass 2 for the children that transformed
        # successfully (source order preserved). Failed/non-comparison children
        # are NOT carried (they already recorded their FailedSection + complete
        # in pass 1) so pass 2 skips them.
        pending: list[tuple[int, ComparisonRecipe, str, str, ReportData]] = []
        # Collected facet summaries keyed by bare slug, for the leader
        # computation (mirrors the assembler's comparison_summaries shape).
        collected_summaries: dict[str, dict] = {}
        # Per-child SectionResult slot indexed by source position. Both passes
        # write into this so section_results stays in compound.sections order
        # (the assembler's TOC + "SECTION NN" numbering depend on it) even when
        # pass-1 failures and pass-2 renders interleave. Flushed to
        # section_results in index order after pass 2.
        per_child_result: list[SectionResult | None] = [None] * len(children)

        def _fire_complete(idx: int, name: str, ok: bool) -> None:
            # Defensive try/except so a misbehaving observer can never abort
            # the run (preserved invariant).
            if not self._on_section_complete:
                return
            try:
                self._on_section_complete(idx, name, ok)
            except Exception:
                self.logger.exception(
                    f"on_section_complete hook raised for meta-compare "
                    f"'{compound.name}' child '{name}'"
                )

        # ---- Pass 1: transform every child, store report_data.
        for i, child in enumerate(children):
            self._check_cancel()
            # Additive, optional Run-canvas hook: announce this child as
            # starting. Mirrors _process_compound's hook pattern — defensive
            # try/except so a misbehaving observer can never abort the run.
            if self._on_section_start:
                try:
                    self._on_section_start(i, child.name)
                except Exception:
                    self.logger.exception(
                        f"on_section_start hook raised for meta-compare "
                        f"'{compound.name}' child '{child.name}'"
                    )
            child_slug = _slug(child.name)
            child_title = getattr(child.output, "slide_title", None) or child.name

            if not isinstance(child, ComparisonRecipe):
                self.logger.error(
                    f"Meta-compare '{compound.name}' child '{child.name}' is "
                    "not a comparison recipe; skipping."
                )
                per_child_result[i] = FailedSection(
                    slug=child_slug,
                    title=child_title,
                    error="not a comparison recipe",
                )
                any_failed = True
                # Failed in pass 1 → fire its completion now (ok=False) so
                # every started child still gets exactly one complete; skipped
                # in pass 2.
                _fire_complete(i, child.name, False)
                continue

            try:
                report_data = self._run_comparison_child(child, left_scope, right_scope)
            except ReportCancelled:
                # A Stop mid-transform must PROPAGATE (run ends "cancelled") and
                # fire NEITHER complete — neither for this child nor for earlier
                # children still awaiting their pass-2 render.
                raise
            except Exception as exc:
                self.logger.error(
                    f"Meta-compare '{compound.name}' child '{child.name}' "
                    f"raised during fetch/transform: {exc}"
                )
                per_child_result[i] = FailedSection(
                    slug=child_slug, title=child_title, error=str(exc)
                )
                any_failed = True
                _fire_complete(i, child.name, False)
                continue

            # Collect the facet summary for the leader computation (same shape
            # as the assembler's comparison_summaries). None for non-dict data.
            child_summary = (
                report_data.data.get("summary")
                if isinstance(getattr(report_data, "data", None), dict)
                else None
            )
            if isinstance(child_summary, dict):
                collected_summaries[child_slug] = child_summary

            pending.append((i, child, child_slug, child_title, report_data))

        # ---- Between passes: compute the leader direction ONCE from the
        # surviving facet summaries (shared helper → identical to the verdict).
        left_leads = compute_left_leads(collected_summaries)
        leader_label = left_scope.label if left_leads else right_scope.label
        laggard_label = right_scope.label if left_leads else left_scope.label

        # ---- Pass 2: inject the leader direction into each stored report_data
        # and render its fragment.
        for i, child, child_slug, child_title, report_data in pending:
            self._check_cancel()
            child_summary = collected_summaries.get(child_slug)

            # Inject the leader direction into the transform dict so the
            # fragment templates can select the primary (leader→laggard)
            # worklist without re-deriving the verdict. html_renderer merges
            # report_data.data into the fragment template context, so these
            # are reachable as data.left_leads / data.leader_label /
            # data.laggard_label. Only meaningful when data is the transform
            # dict (it always is for a comparison child).
            if isinstance(getattr(report_data, "data", None), dict):
                report_data.data["left_leads"] = left_leads
                report_data.data["leader_label"] = leader_label
                report_data.data["laggard_label"] = laggard_label

            try:
                fragment_html = html_renderer.render_fragment(
                    child,
                    report_data,
                    heading_depth=2,
                    fragment_scripts_enabled=True,
                    suppress_section_title=True,
                )
            except ReportCancelled:
                # A Stop mid-render propagates and fires NEITHER complete for
                # this child (it never finished), mirroring today's guard.
                raise
            except Exception as exc:
                self.logger.error(
                    f"Meta-compare '{compound.name}' child '{child.name}' "
                    f"raised during render_fragment: {exc}"
                )
                per_child_result[i] = FailedSection(
                    slug=child_slug, title=child_title, error=str(exc)
                )
                any_failed = True
                _fire_complete(i, child.name, False)
                continue

            # Expose the per-facet row lists (§5a) for the assembler Action
            # Plan. Extracted from the stored transform dict; the leader
            # injection above does not touch these keys.
            child_rows = _extract_comparison_rows(getattr(report_data, "data", None))
            per_child_result[i] = RenderedFragment(
                slug=child_slug,
                title=child_title,
                html=fragment_html,
                summary=child_summary,
                rows=child_rows,
            )
            chart_libraries_union.extend(child.chart_libraries)
            # Fire completion when the fragment is rendered (pass 2).
            _fire_complete(i, child.name, True)

        # Flush per-child results in source order — keeps the assembler's TOC +
        # "SECTION NN" numbering aligned with compound.sections even when pass-1
        # failures and pass-2 renders interleave. Slots stay None only for a
        # child whose render was skipped by a propagating cancel (which aborts
        # the run before this flush), so every reached slot is filled.
        section_results.extend(r for r in per_child_result if r is not None)

        return self._finalize_compound_render(
            compound,
            output_dir=output_dir,
            compound_slug=compound_slug,
            wants_html=wants_html,
            wants_pdf=wants_pdf,
            html_renderer=html_renderer,
            section_results=section_results,
            chart_libraries_union=chart_libraries_union,
            extra_files=extra_files,
            any_failed=any_failed,
            runtime_scope_extra={
                "left_scope": left_scope.label,
                "right_scope": right_scope.label,
            },
            facet_titles=facet_titles,
            # Single source of truth (M1-1 / M1-5 / M3-3): thread the pass-1
            # leader direction (the SAME value injected into every surviving
            # fragment above) into the assembler so the verdict band, cover, and
            # action plan can't diverge from the fragments — even when a
            # leader-driving facet transformed but failed to render. The
            # non-axis call omits this (default None → assembler falls back to
            # compute_left_leads over the RenderedFragment summaries).
            left_leads=left_leads,
        )

    def _run_comparison_child(
        self,
        child: "ComparisonRecipe",
        left_scope: "ResolvedScope",
        right_scope: "ResolvedScope",
    ) -> "ReportData":
        """Fetch both sides, run the comparison transform, wrap as ReportData.

        Routes through a dedicated comparison resolver (decision #4 — NOT
        ``DataTransformer._apply_pandas_transform_function``): the module is
        ``child.transform_function`` minus the ``_transform`` suffix, imported
        from ``fs_report.transforms.pandas.comparison``. When
        ``child.needs_component_inventory`` is set, each side's component
        inventory is also fetched (reusing the per-version components cache)
        and passed as ``left_components`` / ``right_components``.
        """
        # ComparisonRecipe's validator guarantees both are set; assert for mypy.
        assert child.query is not None
        assert child.transform_function
        left_df = self._fetch_scope_data(child.query, left_scope)
        right_df = self._fetch_scope_data(child.query, right_scope)

        kwargs: dict[str, Any] = {
            "left_label": left_scope.label,
            "right_label": right_scope.label,
            "config": child.parameters,
        }
        if child.needs_component_inventory:
            comp_query = QueryConfig(
                endpoint="/public/v0/components",
                params=QueryParams(limit=10000),
            )
            kwargs["left_components"] = self._fetch_scope_data(comp_query, left_scope)
            kwargs["right_components"] = self._fetch_scope_data(comp_query, right_scope)

        transform_fn = self._resolve_comparison_transform(child.transform_function)
        result = transform_fn(left_df, right_df, **kwargs)

        # Intentionally empty metadata: no current comparison transform emits
        # side-effect files (prompts / VEX JSON) the way assessment transforms
        # do via metadata["additional_data"]["_extra_generated_files"].
        # Revisit if one does — surface them here and into extra_files.
        return ReportData(recipe_name=child.name, data=result, metadata={})

    @staticmethod
    def _resolve_comparison_transform(transform_function: str) -> "Callable[..., Any]":
        """Resolve a comparison ``transform_function`` name to its callable.

        Decision #4: comparison transforms are NOT routed through
        ``DataTransformer._apply_pandas_transform_function``. The module is
        the function name minus the ``_transform`` suffix, imported from
        ``fs_report.transforms.pandas.comparison``.
        """
        module_name = transform_function
        if module_name.endswith("_transform"):
            module_name = module_name[: -len("_transform")]
        module = importlib.import_module(
            f"fs_report.transforms.pandas.comparison.{module_name}"
        )
        fn: Callable[..., Any] = getattr(module, transform_function)
        return fn

    def _build_compound_runtime_scope(
        self, compound: "CompoundRecipe"
    ) -> dict[str, str]:
        """Resolve the base substitution vars for a bundle.

        Returns the four scope-independent whitelisted vars
        (``project_name``, ``period``, ``title``, ``generated_at``). The
        meta-compare (axis) path adds the two scope vars (``left_scope`` /
        ``right_scope``) via ``runtime_scope_extra`` in
        ``_finalize_compound_render``, for six whitelisted substitution
        variables in total.

        Values flow from current ``self.config`` + already-resolved
        engine state (``self.resolved_project_name``). Missing scope
        produces an empty string for that key so the assembler omits the
        corresponding metadata row instead of rendering blank values.
        """
        project_name = self.resolved_project_name or (self.config.project_filter or "")
        start = getattr(self.config, "start_date", None)
        end = getattr(self.config, "end_date", None)
        if start and end:
            period = f"{start} – {end}"
        elif start:
            period = f"from {start}"
        elif end:
            period = f"through {end}"
        else:
            period = ""
        # UTC ISO-8601 second precision — same format spreadsheet/CSV
        # consumers see elsewhere in the report.
        generated_at = _datetime.datetime.now(_datetime.UTC).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        return {
            "project_name": str(project_name),
            "period": period,
            "title": compound.title,
            "generated_at": generated_at,
        }

    @staticmethod
    def _bundled_logo_data_uri() -> str:
        """Return the bundled Finite State wordmark as a base64 data-URI.

        Uses ``fs_report/templates/assets/fs-logo.png`` — the single
        canonical bundled PNG shared by every fallback path.  This is the
        Python-side equivalent of the Jinja ``default_logo_data_uri()``
        macro in ``_console_macros.html``.
        """
        import importlib.resources

        pkg_files = importlib.resources.files("fs_report.templates")
        logo_ref = pkg_files / "assets" / "fs-logo.png"
        with importlib.resources.as_file(logo_ref) as logo_path:
            data = logo_path.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:image/png;base64,{b64}"

    def _resolve_compound_logo_data_uri(self, logo: str | None) -> str | None:
        """Resolve a cover-config logo path to a base64 data URI.

        Mirrors ``_resolve_logo_path`` (which reads from
        ``self.config.logo``) but takes the path from
        ``compound.cover.logo``. Bare filenames resolve under
        ``~/.fs-report/logos/`` per the spec. Missing or unsupported
        logos warn-and-skip rather than failing the bundle.

        E1 precedence: per-bundle ``compound.cover.logo`` →
        ``config.logo`` → bundled Finite State wordmark.

        When no cover logo is set, fall through to the user-configured
        ``config.logo`` (via ``_resolve_logo_path``), and then to the
        bundled wordmark — so the compound cover always shows branding,
        matching every other report family.

        When the per-bundle logo is set but missing/unreadable/unsupported,
        fall through to ``config.logo`` / bundled (rather than silently
        dropping all branding).
        """
        if not logo:
            return self._resolve_logo_path() or self._bundled_logo_data_uri()
        path = Path(logo)
        if not path.is_absolute():
            path = Path.home() / ".fs-report" / "logos" / logo
        if not path.is_file():
            self.logger.warning(f"Compound logo file not found: {path}")
            return self._resolve_logo_path() or self._bundled_logo_data_uri()
        suffix = path.suffix.lower()
        allowed = {".png", ".jpg", ".jpeg", ".svg", ".webp"}
        if suffix not in allowed:
            self.logger.warning(
                f"Unsupported compound logo format '{suffix}'. "
                f"Use: {', '.join(sorted(allowed))}"
            )
            return self._resolve_logo_path() or self._bundled_logo_data_uri()
        mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if suffix == ".svg":
            mime = "image/svg+xml"
        data = path.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:{mime};base64,{b64}"

    # ------------------------------------------------------------------
    # Folder-scoped Remediation Package helper
    # ------------------------------------------------------------------

    def _run_remediation_folder(
        self,
        recipe: Recipe,
        project_ids: list[str],
        generated_files: list[str],
        recipe_results: list[RecipeResult],
    ) -> bool:
        """Run Remediation Package for each project in a folder.

        Creates per-project subdirectories under ``Remediation Package/``.
        Returns ``True`` if at least one project succeeded.
        """
        total_projects = len(project_ids)
        any_succeeded = False
        self.logger.info(
            f"Remediation Package: folder scope with {total_projects} project(s)"
        )

        base_output = Path(self.config.output_dir) / "Remediation Package"
        base_output.mkdir(parents=True, exist_ok=True)

        for pi, pid in enumerate(project_ids, 1):
            project_name = self._resolve_project_id_to_name(pid)
            if not project_name:
                project_name = pid
            self.logger.info(
                f"Remediation Package: project {pi}/{total_projects} — {project_name}"
            )

            # Create a scoped config with project_filter set to this project
            scoped_config = self.config.model_copy(update={"project_filter": pid})

            # Create a sub-engine for this project
            try:
                sub_engine = ReportEngine(
                    scoped_config,
                    deployment_context=self._deployment_context,
                )
                # Share the API client to reuse connections/cache
                sub_engine.api_client = self.api_client

                # Override the renderer to write to a per-project subdirectory
                safe_name = self.renderer._sanitize_filename(project_name)
                project_output_dir = str(base_output / safe_name)
                sub_engine.renderer = ReportRenderer(
                    project_output_dir,
                    config=scoped_config,
                    overwrite=self.renderer.overwrite,
                )

                report_data = sub_engine._process_recipe(recipe)
                if report_data:
                    # Render with the original recipe name (not scoped)
                    # since the per-project dir already provides scoping
                    files = sub_engine.renderer.render(recipe, report_data)
                    if files:
                        generated_files.extend(files)
                    extra = report_data.metadata.get("additional_data", {}).get(
                        "_extra_generated_files", []
                    )
                    if extra:
                        generated_files.extend(extra)

                    row_count = 0
                    data = report_data.data
                    if hasattr(data, "__len__"):
                        row_count = len(data)
                    recipe_results.append(
                        RecipeResult(
                            recipe=f"Remediation Package/{project_name}",
                            output_dir=project_output_dir,
                            files=files + (extra or []),
                            stats={"finding_count": row_count, "project": project_name},
                        )
                    )
                    any_succeeded = True
                else:
                    self.logger.warning(
                        f"No report data for Remediation Package — {project_name}"
                    )
            except Exception as e:
                self.logger.error(f"Remediation Package failed for {project_name}: {e}")

        return any_succeeded

    # ------------------------------------------------------------------
    # Component search optimization
    # ------------------------------------------------------------------

    _MAX_COMPONENT_SEARCH_SPECS = 10

    def _search_components(
        self,
    ) -> tuple[list[dict[str, Any]], set] | None:
        """Search for components by name via /public/v0/components/search.

        Uses ``self.config.component_filter`` (comma-separated specs).
        Returns ``(components, version_ids)`` or ``None`` if the search
        should be skipped (too many specs, API error, etc.).

        When ``self.config.project_filter`` is set, *version_ids* is
        narrowed to only versions belonging to that project.

        When ``self.config.component_version`` contains range operators
        (>=, <=, >, <, !=), version filtering is done client-side after
        the search.  Simple version strings are passed to the search
        endpoint's ``version`` query param.
        """
        import re

        comp_filter = getattr(self.config, "component_filter", None)
        if not comp_filter:
            return None

        specs = [s.strip() for s in comp_filter.split(",") if s.strip()]
        if len(specs) > self._MAX_COMPONENT_SEARCH_SPECS:
            self.logger.warning(
                "Component search optimization skipped: %d specs exceeds "
                "limit of %d — falling back to full fetch",
                len(specs),
                self._MAX_COMPONENT_SEARCH_SPECS,
            )
            return None

        _RANGE_RE = re.compile(r"[><=!]")

        all_components: list[dict[str, Any]] = []
        url = f"{self.api_client.base_url}/public/v0/components/search"

        # Determine if --component-version should be passed to the
        # search endpoint (simple string) or filtered client-side (range).
        comp_version = getattr(self.config, "component_version", None)
        _version_is_range = bool(comp_version and _RANGE_RE.search(comp_version))

        for spec in specs:
            search_params: dict[str, str] = {"limit": "1000"}

            # Parse name@version syntax
            if "@" in spec:
                name, version = spec.rsplit("@", 1)
                search_params["name"] = name
                search_params["version"] = version
            else:
                search_params["name"] = spec
                # Pass simple --component-version to the search endpoint
                if comp_version and not _version_is_range:
                    search_params["version"] = comp_version

            try:
                response = self.api_client.client.get(
                    url, params=search_params, timeout=60
                )
                response.raise_for_status()
                data = response.json()
                if isinstance(data, list):
                    all_components.extend(data)
                    self.logger.info(
                        "Component search '%s': %d results", spec, len(data)
                    )
                else:
                    self.logger.warning(
                        "Component search '%s': unexpected response type %s",
                        spec,
                        type(data).__name__,
                    )
            except Exception as exc:
                self.logger.warning(
                    "Component search failed for '%s': %s — falling back to full fetch",
                    spec,
                    exc,
                )
                return None

        # Apply client-side version range filtering if --component-version
        # contains range operators
        if comp_version and _version_is_range:
            from fs_report.transforms.pandas.component_impact import (
                _parse_version_range,
                _version_matches,
            )

            try:
                constraints = _parse_version_range(comp_version)
                before = len(all_components)
                all_components = [
                    c
                    for c in all_components
                    if _version_matches(
                        str(c.get("componentVersion", c.get("version", ""))),
                        constraints,
                    )
                ]
                self.logger.info(
                    "Component version range '%s': %d → %d components",
                    comp_version,
                    before,
                    len(all_components),
                )
            except Exception as exc:
                self.logger.warning(
                    "Version range filtering failed: %s — using all components",
                    exc,
                )

        # Extract version IDs, optionally filtered by project or folder.
        # Post-filter search results by component name.  The search
        # endpoint uses partial matching (e.g. "typer" returns "media-typer").
        # We filter to exact name matches on the search results.
        _target_names = set()
        for spec in specs:
            name = spec.rsplit("@", 1)[0] if "@" in spec else spec
            _target_names.add(name.lower())

        before_filter = len(all_components)
        all_components = [
            c
            for c in all_components
            if c.get("componentName", c.get("name", "")).lower() in _target_names
        ]
        if before_filter != len(all_components):
            self.logger.info(
                "Component name filter: %d → %d (removed partial matches)",
                before_filter,
                len(all_components),
            )

        if not all_components:
            self.logger.info("Component search: no results after name filtering")
            return all_components, set()

        # The search endpoint returns a different shape than /public/v0/components:
        #   { "componentName", "componentVersion",
        #     "project": { "projectId", "projectName",
        #                  "latestMatchingProjectVersionId", "projectVersionName" } }
        project_filter = self.config.project_filter
        folder_project_ids: set | None = getattr(self, "_folder_project_ids", None)
        _folder_pid_strs = (
            {str(p) for p in folder_project_ids} if folder_project_ids else None
        )
        version_ids: set = set()
        for comp in all_components:
            # Handle both search endpoint shape and ComponentV0 shape
            proj = comp.get("project") or {}
            if isinstance(proj, dict):
                pv_id = proj.get(
                    "latestMatchingProjectVersionId",
                    (comp.get("projectVersion") or {}).get("id"),
                )
                proj_id = proj.get("projectId", proj.get("id"))
            else:
                pv_id = (comp.get("projectVersion") or {}).get("id")
                proj_id = None

            if pv_id is None:
                continue

            # Narrow to project if --project is set
            if project_filter:
                if str(proj_id) != str(project_filter):
                    continue
            # Narrow to folder's project set if --folder is set
            elif _folder_pid_strs is not None and proj_id is not None:
                if str(proj_id) not in _folder_pid_strs:
                    continue

            version_ids.add(str(pv_id))

        # Cap version IDs to avoid URL-too-long (414) on the findings RSQL
        _MAX_VERSION_IDS = 200
        if len(version_ids) > _MAX_VERSION_IDS:
            self.logger.warning(
                "Component search returned %d version IDs (cap=%d) "
                "— falling back to full fetch",
                len(version_ids),
                _MAX_VERSION_IDS,
            )
            return None

        self.logger.info(
            "Component search: %d components, %d unique version IDs",
            len(all_components),
            len(version_ids),
        )

        return all_components, version_ids

    # ------------------------------------------------------------------
    # Cross-server Version Comparison helper
    # ------------------------------------------------------------------

    def _fetch_cross_server_comparison(
        self,
        _fetch_findings_primary: Any,
        _fetch_components_primary: Any,
        finding_type: str,
        category_filter: str | None,
    ) -> list[dict]:
        """Fetch findings from two different servers and build pair comparison."""
        from tqdm import tqdm as _tqdm

        from fs_report.models import QueryConfig, QueryParams

        assert self.compare_api_client is not None

        def _fetch_findings_secondary(version_id: str) -> list[dict]:
            version_filter = f"projectVersion=={version_id}"
            combined_filter = (
                f"{version_filter};{category_filter}"
                if category_filter
                else version_filter
            )
            q = QueryConfig(
                endpoint="/public/v0/findings",
                params=QueryParams(
                    limit=10000,
                    filter=combined_filter,
                    finding_type=finding_type,
                    archived=False,
                    excluded=False,
                ),
            )
            assert self.compare_api_client is not None
            return self.compare_api_client.fetch_all_with_resume(q, show_progress=False)

        def _fetch_components_secondary(version_id: str) -> list[dict]:
            q = QueryConfig(
                endpoint="/public/v0/components",
                params=QueryParams(
                    limit=10000,
                    filter=f"projectVersion=={version_id}",
                ),
            )
            assert self.compare_api_client is not None
            return self.compare_api_client.fetch_all_with_resume(q, show_progress=False)

        def _resolve_latest_version(
            api_client: APIClient, project_filter: str
        ) -> tuple[str, str, str]:
            """Resolve project → latest version. Returns (version_id, version_name, project_name)."""
            # Fetch projects
            pq = QueryConfig(
                endpoint="/public/v0/projects",
                params=QueryParams(limit=10000, archived=False, excluded=False),
            )
            projects = api_client.fetch_all_with_resume(pq, show_progress=False)
            project = None
            for p in projects:
                pid = str(p.get("id", ""))
                pname = p.get("name", "")
                if pid == project_filter or pname.lower() == project_filter.lower():
                    project = p
                    break
            if not project:
                raise ValueError(
                    f"Project '{project_filter}' not found on " f"{api_client.base_url}"
                )
            pid = str(project["id"])
            pname = project.get("name", pid)

            # Fetch versions for project
            url = f"{api_client.base_url}/public/v0/projects/{pid}/versions"
            resp = api_client.client.get(url)
            resp.raise_for_status()
            versions = resp.json()
            if not isinstance(versions, list) or not versions:
                raise ValueError(
                    f"No versions found for project '{pname}' on "
                    f"{api_client.base_url}"
                )
            # Latest = most recently created
            versions.sort(key=lambda v: v.get("created", v.get("id", "")), reverse=True)
            latest = versions[0]
            vid = str(latest.get("id", ""))
            vname = latest.get("version", latest.get("name", vid))
            return vid, vname, pname

        # ── Resolve primary side ──────────────────────────────────────
        primary_version_id = self.config.version_filter
        primary_version_name = primary_version_id or ""
        primary_project_name = ""

        if primary_version_id:
            # Explicit version ID
            self.logger.info("Cross-server: primary version ID %s", primary_version_id)
        elif self.config.project_filter:
            # Resolve project → latest version
            self.logger.info(
                "Cross-server: resolving primary project '%s'",
                self.config.project_filter,
            )
            primary_version_id, primary_version_name, primary_project_name = (
                _resolve_latest_version(self.api_client, self.config.project_filter)
            )
            self.logger.info(
                "Cross-server: primary resolved to %s (%s) in project '%s'",
                primary_version_id,
                primary_version_name,
                primary_project_name,
            )
        else:
            raise ValueError(
                "Cross-server comparison requires --project or --version "
                "to identify the primary version."
            )

        # ── Resolve secondary side ────────────────────────────────────
        secondary_version_id = self.config.compare_version
        secondary_version_name = secondary_version_id or ""
        secondary_project_name = ""

        if secondary_version_id:
            self.logger.info(
                "Cross-server: secondary version ID %s", secondary_version_id
            )
        elif self.config.compare_project:
            self.logger.info(
                "Cross-server: resolving secondary project '%s'",
                self.config.compare_project,
            )
            secondary_version_id, secondary_version_name, secondary_project_name = (
                _resolve_latest_version(
                    self.compare_api_client, self.config.compare_project
                )
            )
            self.logger.info(
                "Cross-server: secondary resolved to %s (%s) in project '%s'",
                secondary_version_id,
                secondary_version_name,
                secondary_project_name,
            )
        else:
            raise ValueError(
                "Cross-server comparison requires --compare-project or "
                "--compare-version to identify the secondary version."
            )

        # ── Fetch data from both servers ──────────────────────────────
        pair_pbar = _tqdm(
            total=4,
            desc="Fetching cross-server pair",
            unit=" requests",
            leave=False,
        )

        pair_pbar.set_postfix({"step": "Primary findings"})
        primary_findings = _fetch_findings_primary(primary_version_id)
        pair_pbar.update(1)

        pair_pbar.set_postfix({"step": "Primary components"})
        primary_components = _fetch_components_primary(primary_version_id)
        pair_pbar.update(1)

        pair_pbar.set_postfix({"step": "Secondary findings"})
        secondary_findings = _fetch_findings_secondary(secondary_version_id)
        pair_pbar.update(1)

        pair_pbar.set_postfix({"step": "Secondary components"})
        secondary_components = _fetch_components_secondary(secondary_version_id)
        pair_pbar.update(1)
        pair_pbar.close()

        # Extract version metadata from findings if not already resolved
        def _extract_meta(
            findings: list[dict], version_id: str
        ) -> tuple[str, str, str]:
            vname, created, pname = version_id, "", ""
            for f in findings:
                pv = f.get("projectVersion")
                if isinstance(pv, dict):
                    v = pv.get("version") or pv.get("name")
                    if v:
                        vname = str(v)
                    c = pv.get("created", "")
                    if c:
                        created = c
                proj = f.get("project")
                if isinstance(proj, dict):
                    n = proj.get("name")
                    if n:
                        pname = str(n)
                if vname != version_id and pname:
                    break
            return vname, created, pname

        if not primary_project_name:
            primary_version_name, primary_created, primary_project_name = _extract_meta(
                primary_findings, primary_version_id
            )
        else:
            _, primary_created, _ = _extract_meta(primary_findings, primary_version_id)

        if not secondary_project_name:
            secondary_version_name, secondary_created, secondary_project_name = (
                _extract_meta(secondary_findings, secondary_version_id)
            )
        else:
            _, secondary_created, _ = _extract_meta(
                secondary_findings, secondary_version_id
            )

        # Build labels with domain for clarity
        primary_domain = self.config.domain
        secondary_domain = self.config.compare_domain
        primary_label = f"{primary_domain} @ {primary_version_name}"
        secondary_label = f"{secondary_domain} @ {secondary_version_name}"

        # Build project name for display
        if primary_project_name and secondary_project_name:
            if primary_project_name == secondary_project_name:
                project_name = primary_project_name
            else:
                project_name = (
                    primary_project_name + " \u2194 " + secondary_project_name
                )
        else:
            project_name = (
                primary_project_name
                or secondary_project_name
                or "Cross-Server Comparison"
            )

        projects_data: list[dict] = [
            {
                "project_name": project_name,
                "is_pair_comparison": True,
                "versions": [
                    {
                        "id": primary_version_id,
                        "name": primary_label,
                        "created": primary_created,
                        "project_name": primary_project_name,
                        "findings": primary_findings,
                        "components": primary_components,
                    },
                    {
                        "id": secondary_version_id,
                        "name": secondary_label,
                        "created": secondary_created,
                        "project_name": secondary_project_name,
                        "findings": secondary_findings,
                        "components": secondary_components,
                    },
                ],
            }
        ]

        self._version_comparison_data = {"projects": projects_data}
        return [{"_vc_placeholder": True}]

    # ------------------------------------------------------------------
    # Version Comparison: specialised data fetcher
    # ------------------------------------------------------------------

    def _fetch_version_comparison_data(self, recipe: Any) -> list[dict]:
        """
        Fetch findings for every version of every in-scope project so the
        transform can show a full version-over-version progression.

        Supports:
          * ``--folder``   → projects in that folder
          * ``--project``  → single project
          * (neither)      → entire portfolio

        Stores a list of per-project dicts in
        ``self._version_comparison_data["projects"]``.
        Each dict: ``{project_name, versions: [{id, name, created, findings, components}]}``.
        """
        from tqdm import tqdm as _tqdm

        from fs_report.models import QueryConfig, QueryParams

        type_params = build_findings_type_params(self.config.finding_types)
        finding_type = type_params.get("type", "cve") or ""
        category_filter = type_params.get("category_filter")

        def _fetch_findings(version_id: str) -> list[dict]:
            # Check both in-memory and SQLite caches
            cached = self._check_version_in_cache(
                version_id, "findings", finding_type, category_filter
            )
            if cached is not None:
                return cached
            version_filter = f"projectVersion=={version_id}"
            combined_filter = (
                f"{version_filter};{category_filter}"
                if category_filter
                else version_filter
            )
            q = QueryConfig(
                endpoint="/public/v0/findings",
                params=QueryParams(
                    limit=10000,
                    filter=combined_filter,
                    finding_type=finding_type,
                    archived=False,
                    excluded=False,
                ),
            )
            result = self.api_client.fetch_all_with_resume(q, show_progress=False)
            # Store per-version in both in-memory and SQLite caches
            cache_key = self._cache_key(
                "findings", version_id, finding_type, category_filter
            )
            self._version_findings_cache[cache_key] = result
            # SQLite is already handled by fetch_all_with_resume when cache_ttl > 0
            return result

        def _fetch_components(version_id: str) -> list[dict]:
            # Check both in-memory and SQLite caches
            cached = self._check_version_in_cache(version_id, "components")
            if cached is not None:
                return cached
            q = QueryConfig(
                endpoint="/public/v0/components",
                params=QueryParams(
                    limit=10000,
                    filter=f"projectVersion=={version_id}",
                ),
            )
            result = self.api_client.fetch_all_with_resume(q, show_progress=False)
            cache_key = self._cache_key("components", version_id)
            self._version_findings_cache[cache_key] = result
            return result

        # ── Cross-server comparison ────────────────────────────────────
        if self.compare_api_client is not None:
            return self._fetch_cross_server_comparison(
                _fetch_findings,
                _fetch_components,
                finding_type,
                category_filter,
            )

        # ── Validate --baseline-version / --current-version ─────────────
        bv = self.config.baseline_version
        cv = self.config.current_version
        if bool(bv) != bool(cv):
            raise ValueError(
                "Both --baseline-version and --current-version must be provided together. "
                "Use 'fs-report list-versions <project>' to find version IDs."
            )

        # Warn once if --period was specified alongside --baseline/--current.
        if bv and cv and self.config.period_explicit:
            self.logger.warning(
                "Version Comparison: --period ignored because --baseline-version "
                "and --current-version were provided."
            )

        # ── Short-circuit: explicit version pair ──────────────────────
        if bv and cv:
            if bv == cv:
                raise ValueError(
                    "--baseline-version and --current-version must be different version IDs."
                )

            self.logger.info(
                "Version Comparison: explicit pair (baseline=%s, current=%s)",
                bv,
                cv,
            )

            # Fetch findings + components directly (version IDs are globally unique)
            pair_pbar = _tqdm(
                total=4,
                desc="Fetching version pair",
                unit=" requests",
                leave=False,
            )
            pair_pbar.set_postfix({"step": "Baseline findings"})
            baseline_findings = _fetch_findings(bv)
            pair_pbar.update(1)

            pair_pbar.set_postfix({"step": "Baseline components"})
            baseline_components = _fetch_components(bv)
            pair_pbar.update(1)

            pair_pbar.set_postfix({"step": "Current findings"})
            current_findings = _fetch_findings(cv)
            pair_pbar.update(1)

            pair_pbar.set_postfix({"step": "Current components"})
            current_components = _fetch_components(cv)
            pair_pbar.update(1)
            pair_pbar.close()

            # Resolve version metadata from the already-fetched findings.
            # Each finding record contains projectVersion.version (name) and
            # project.name, so we can extract names without extra API calls.
            baseline_name, baseline_created = bv, ""
            current_name, current_created = cv, ""
            baseline_project_name = ""
            current_project_name = ""
            project_name = "Version Comparison"

            def _extract_version_meta(
                findings: list[dict], version_id: str
            ) -> tuple[str, str, str]:
                """Extract (version_name, created, project_name) from findings."""
                vname, created, pname = version_id, "", ""
                for f in findings:
                    pv = f.get("projectVersion")
                    if isinstance(pv, dict):
                        v = pv.get("version") or pv.get("name")
                        if v:
                            vname = str(v)
                        c = pv.get("created", "")
                        if c:
                            created = c
                    proj = f.get("project")
                    if isinstance(proj, dict):
                        n = proj.get("name")
                        if n:
                            pname = str(n)
                    if vname != version_id and pname:
                        break  # found both, stop early
                return vname, created, pname

            baseline_name, baseline_created, baseline_project_name = (
                _extract_version_meta(baseline_findings, bv)
            )
            current_name, current_created, current_project_name = _extract_version_meta(
                current_findings, cv
            )

            # Build display project name
            if baseline_project_name and current_project_name:
                if baseline_project_name == current_project_name:
                    project_name = baseline_project_name
                else:
                    project_name = (
                        baseline_project_name + " \u2194 " + current_project_name
                    )
            elif baseline_project_name:
                project_name = baseline_project_name
            elif current_project_name:
                project_name = current_project_name

            projects_data: list[dict] = [
                {
                    "project_name": project_name,
                    "is_pair_comparison": True,
                    "versions": [
                        {
                            "id": bv,
                            "name": baseline_name,
                            "created": baseline_created,
                            "project_name": baseline_project_name,
                            "findings": baseline_findings,
                            "components": baseline_components,
                        },
                        {
                            "id": cv,
                            "name": current_name,
                            "created": current_created,
                            "project_name": current_project_name,
                            "findings": current_findings,
                            "components": current_components,
                        },
                    ],
                }
            ]

            self._version_comparison_data = {"projects": projects_data}
            return [{"_vc_placeholder": True}]

        # ── Discover projects ──────────────────────────────────────────
        project_ids_and_names: list[tuple[str, str]] = []  # (pid, pname)

        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        all_projects = self.api_client.fetch_all_with_resume(
            projects_query,
            show_progress=False,
        )

        if self.config.project_filter:
            # --project (alone or with --folder) → narrow to that single project.
            # _resolve_folder_scope has already validated project ∈ folder when both set.
            if self._folder_project_ids:
                self.logger.info(
                    "Version Comparison: project '%s' within folder '%s'",
                    self.config.project_filter,
                    self._folder_name or "unknown",
                )
            else:
                self.logger.info(
                    "Version Comparison: single project '%s'",
                    self.config.project_filter,
                )
            pf = self.config.project_filter
            for p in all_projects:
                pid = str(p.get("id", ""))
                pname = p.get("name", "")
                if pid == pf or pname.lower() == pf.lower():
                    project_ids_and_names.append((pid, pname))
                    break

        elif self._folder_project_ids:
            self.logger.info(
                "Version Comparison: %d project(s) from folder '%s'",
                len(self._folder_project_ids),
                self._folder_name or "unknown",
            )
            for p in all_projects:
                pid = str(p.get("id", ""))
                if pid in self._folder_project_ids:
                    project_ids_and_names.append((pid, p.get("name", pid)))

        else:
            self.logger.info("Version Comparison: all projects in portfolio")
            for p in all_projects:
                pid = str(p.get("id", ""))
                if pid:
                    project_ids_and_names.append((pid, p.get("name", pid)))

        if not project_ids_and_names:
            self.logger.warning("No projects found for version comparison")
            self._version_comparison_data = {}
            return []

        # ── Fetch version lists per project (with caching) ─────────────
        # Each entry: (pname, sorted_versions_list)
        project_version_lists: list[tuple[str, list[dict]]] = []

        self.logger.info(
            "Discovering versions for %d project(s)…",
            len(project_ids_and_names),
        )
        delay = getattr(self.config, "request_delay", 0.5)
        cache_hits = 0
        sqlite_cache = self.api_client.sqlite_cache
        cache_ttl = self.api_client.cache_ttl

        with _tqdm(
            project_ids_and_names,
            desc="Discovering versions",
            unit=" projects",
            leave=False,
        ) as pbar:
            for pid, pname in pbar:
                pbar.set_postfix({"project": pname[:30]})
                versions = None

                # 1. Check in-memory cache
                if pid in self._project_versions_cache:
                    versions = self._project_versions_cache[pid]
                    cache_hits += 1

                # 2. Check SQLite cache
                if versions is None and sqlite_cache and cache_ttl > 0:
                    cached = sqlite_cache.get_version_list(pid, cache_ttl)
                    if cached is not None:
                        versions = cached
                        self._project_versions_cache[pid] = versions
                        cache_hits += 1

                # 3. Fetch from API (only on cache miss)
                if versions is None:
                    # Route through _get_project_versions so paginated and
                    # cache-coherent with _lookup_version_display_name /
                    # _resolve_version_name. A previous direct unpaginated
                    # GET here could poison _project_versions_cache with a
                    # truncated first page when VC ran before any
                    # version-name lookup on the same project.
                    versions = self._get_project_versions(pid)
                    if delay > 0:
                        self._cancellable_sleep(delay)
                    if not versions:
                        # API error or empty list — _get_project_versions
                        # already logged the underlying exception.
                        continue
                    # In-mem cache already populated by _get_project_versions
                    # on success. Persist to SQLite too if configured.
                    if sqlite_cache and cache_ttl > 0:
                        sqlite_cache.store_version_list(pid, versions)

                # Apply --period filter (single-project mode only; folder /
                # portfolio modes and explicit-pair mode skip this).
                trim_applied = False
                if (
                    self.config.period_explicit
                    and self.config.project_filter
                    and not (
                        self.config.baseline_version or self.config.current_version
                    )
                ):
                    before_n = len(versions)
                    versions = _trim_versions_by_period(
                        versions,
                        self.config.start_date,
                        self.config.end_date,
                    )
                    trim_applied = True
                    pre_name = (
                        versions[0].get("version", versions[0].get("name", ""))
                        if versions
                        and versions[0].get("created", "")
                        < f"{self.config.start_date}T00:00:00Z"
                        else None
                    )
                    if pre_name:
                        self.logger.info(
                            "Version Comparison: period %s..%s applied to '%s' → "
                            "%d in-window version(s), predecessor '%s' included "
                            "(trimmed from %d total)",
                            self.config.start_date,
                            self.config.end_date,
                            pname,
                            len(versions) - 1,
                            pre_name,
                            before_n,
                        )
                    else:
                        self.logger.info(
                            "Version Comparison: period %s..%s applied to '%s' → "
                            "%d in-window version(s), no predecessor available "
                            "(trimmed from %d total)",
                            self.config.start_date,
                            self.config.end_date,
                            pname,
                            len(versions),
                            before_n,
                        )

                if len(versions) < 2:
                    self.logger.debug(
                        "%s has %d version(s) — skipping",
                        pname,
                        len(versions),
                    )
                    continue

                if trim_applied:
                    # Preserve trim order: [predecessor, in_window ASC]. This
                    # keeps the predecessor at index 0 so the transform treats
                    # it as the baseline. User-configured --version-sort[-desc]
                    # is ignored on period-filtered runs to preserve the
                    # "what entered the period" semantic.
                    pass
                else:
                    # Sort versions by configured key (default: created ascending)
                    _vs = self.config.version_sort or "created"
                    versions.sort(
                        key=lambda v: v.get(_vs, v.get("id", "")),
                        reverse=self.config.version_sort_desc,
                    )
                project_version_lists.append((pname, versions))

        if cache_hits > 0:
            self.logger.info(
                "Version discovery: %d/%d projects served from cache",
                cache_hits,
                len(project_ids_and_names),
            )

        if not project_version_lists:
            self.logger.warning("No projects with ≥ 2 versions found")
            self._version_comparison_data = {}
            return []

        # ── Fetch findings & components for every version ──────────────
        total_versions = sum(len(vl) for _, vl in project_version_lists)
        self.logger.info(
            "Fetching findings for %d version(s) across %d project(s)…",
            total_versions,
            len(project_version_lists),
        )

        projects_data = []  # list[dict]
        with _tqdm(  # type: ignore[assignment]
            total=total_versions,
            desc="Fetching version data",
            unit=" versions",
            leave=False,
        ) as pbar:
            for pname, versions in project_version_lists:
                version_records: list[dict] = []
                for v in versions:
                    vid = str(v.get("id", ""))
                    vname = v.get("version", v.get("name", vid))
                    created = v.get("created", "")
                    pbar.set_postfix({"project": pname[:20], "version": vname[:20]})

                    try:
                        findings = _fetch_findings(vid)
                        if delay > 0:
                            self._cancellable_sleep(delay)
                        components = _fetch_components(vid)
                        version_records.append(
                            {
                                "id": vid,
                                "name": vname,
                                "created": created,
                                "findings": findings,
                                "components": components,
                            }
                        )
                    except Exception as e:
                        self.logger.warning(
                            "Version Comparison: failed to fetch data for "
                            "version %s (%s) after retries: %s. "
                            "Marking as unavailable and continuing.",
                            vname,
                            vid,
                            str(e)[:200],
                        )
                        version_records.append(
                            {
                                "id": vid,
                                "name": vname,
                                "created": created,
                                "fetch_failed": True,
                                "findings": [],
                                "components": [],
                            }
                        )
                    pbar.update(1)

                    # Throttle between versions to avoid overloading the server
                    if delay > 0:
                        self._cancellable_sleep(delay)

                n_failed = sum(1 for rec in version_records if rec.get("fetch_failed"))
                if n_failed:
                    self.logger.warning(
                        "Version Comparison: %d of %d version(s) had fetch failures "
                        "for project '%s'. Report is partial — see per-version "
                        "warnings above.",
                        n_failed,
                        len(version_records),
                        pname,
                    )

                projects_data.append(
                    {
                        "project_name": pname,
                        "versions": version_records,
                    }
                )

        self._version_comparison_data = {"projects": projects_data}
        return [{"_vc_placeholder": True}]

    def _process_recipe(self, recipe: Recipe) -> ReportData | None:
        """Process a single recipe and return report data."""
        try:
            # Reset per-recipe state
            self._component_search_results = None

            # Track whether entity-level caching was used (needs date post-filtering)
            needs_date_postfilter = False
            is_operational = False

            # --- NVD pipeline handles (initialised here so both branches see them) ---
            _nvd_on_records = None
            _nvd_collect = None
            _es_cache_key: str | None = None
            _ed_cache_key: str | None = None
            # CVA flatten/prune state (initialised here so post-accumulation code sees them)
            _is_cva = False
            _cva_pre_flattened = False
            _cva_extra_keep: frozenset[str] | None = None

            # Use override data if provided
            if self.data_override is not None:
                self.logger.info(
                    f"Using data from override file for recipe: {recipe.name}"
                )
                if recipe.query is None:
                    # No endpoint to match — use entire override as raw data
                    if isinstance(self.data_override, list):  # type: ignore[unreachable]
                        raw_data = self.data_override  # type: ignore[unreachable]
                    else:
                        # Dict override: use first value, or the whole dict
                        first_key = next(iter(self.data_override), None)
                        raw_data = self.data_override[first_key] if first_key else []
                else:
                    # For data override, we need to extract the main query data
                    # The main query should match one of the keys in the override data
                    endpoint = recipe.query.endpoint
                    raw_data = None
                    # Patch: if override is a list, use it directly
                    if isinstance(self.data_override, list):  # type: ignore[unreachable]
                        raw_data = self.data_override  # type: ignore[unreachable]
                    else:
                        self.logger.debug(
                            f"Override matching: endpoint={endpoint}, override keys={list(self.data_override.keys())}"
                        )
                        for key in self.data_override:
                            key_str = str(key)
                            endpoint_str = str(endpoint)
                            self.logger.debug(
                                f"Comparing key='{key_str}' to endpoint='{endpoint_str}'"
                            )
                            if key_str == endpoint_str or key_str.endswith(
                                endpoint_str.split("/")[-1]
                            ):
                                raw_data = self.data_override[key]
                                self.logger.debug(
                                    f"Override match found: key='{key_str}'"
                                )
                                break
                    if raw_data is None:
                        self.logger.error(
                            f"Could not find data for endpoint {endpoint} in override data"
                        )
                        return None
            else:
                if recipe.query is None:
                    self.logger.error(
                        f"Recipe '{recipe.name}' has no query and no data override — skipping"
                    )
                    return None
                # Use robust pagination for all major findings-based reports
                _ROBUST_ENDPOINTS = {
                    "/public/v0/findings",
                    "/public/v0/scans",
                    "/public/v0/cves",
                    "/public/v0/audit",
                    "/public/v0/components",
                }
                _endpoint = recipe.query.endpoint if recipe.query else ""
                # Short-circuit for Executive Dashboard in summary mode —
                # bypass the findings fetch entirely; all data comes from
                # _fetch_exec_dashboard_summary (called later at transform time).
                _is_ed_summary = recipe.name == "Executive Dashboard" and not getattr(
                    self.config, "detailed_mode", True
                )
                if _is_ed_summary:
                    raw_data = pd.DataFrame()
                elif _endpoint in _ROBUST_ENDPOINTS or recipe.name in (
                    "Version Comparison",
                    "User Activity",
                    "Scan Analysis",
                    "CVE Impact",
                    "Component List",
                ):
                    from fs_report.models import QueryConfig, QueryParams

                    if recipe.name in ("Version Comparison", "Security Progress"):
                        # --- Version Comparison / Security Progress: two-version parallel fetch ---
                        _fetched = self._fetch_version_comparison_data(recipe)
                        if _fetched or recipe.name == "Version Comparison":
                            raw_data = (
                                pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                            )
                            del _fetched
                        else:
                            # Security Progress: fall back to flat findings fetch
                            # when no multi-version data is available (e.g. single version)
                            del _fetched
                            self.logger.info(
                                "Security Progress: no multi-version data, "
                                "falling back to flat findings fetch"
                            )
                            _flat = self.api_client.fetch_all_with_resume(recipe.query)
                            raw_data = pd.DataFrame(_flat) if _flat else pd.DataFrame()
                            del _flat
                    elif recipe.name == "User Activity":
                        # Build filter for audit endpoint using RSQL format
                        # The audit API supports: time=ge=START;time=le=END
                        # (The date=START,date=END format has parsing issues with commas in filter param)
                        audit_filter = f"time=ge={self.config.start_date}T00:00:00Z;time=le={self.config.end_date}T23:59:59Z"

                        unified_query = QueryConfig(
                            endpoint=recipe.query.endpoint,
                            params=QueryParams(
                                limit=recipe.query.params.limit, filter=audit_filter
                            ),
                        )
                        self.logger.info(
                            f"Fetching audit events for {recipe.name} with filter: {audit_filter}"
                        )
                        _fetched = self.api_client.fetch_all_with_resume(unified_query)
                        raw_data = (
                            pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                        )
                        del _fetched
                    elif recipe.name == "Scan Analysis":
                        # Apply project and version filtering to scans
                        # Batch folder project IDs to avoid 414 URL Too Long
                        if (
                            self._folder_project_ids
                            and not self.config.project_filter
                            and len(self._folder_project_ids) > 25
                        ):
                            folder_pids = sorted(self._folder_project_ids)
                            batch_size = 15 if len(folder_pids) > 200 else 25
                            all_scans: list[dict] = []
                            saved_pids = self._folder_project_ids
                            self.logger.info(
                                f"Batching Scan Analysis fetch: "
                                f"{len(folder_pids)} projects, batch_size={batch_size}"
                            )
                            try:
                                for i in range(0, len(folder_pids), batch_size):
                                    scan_batch_pids = set(
                                        folder_pids[i : i + batch_size]
                                    )
                                    self._folder_project_ids = scan_batch_pids
                                    scan_query = self._apply_scan_filters(recipe.query)
                                    batch_data = (
                                        self._fetch_scans_with_early_termination(
                                            scan_query
                                        )
                                    )
                                    if batch_data:
                                        all_scans.extend(batch_data)
                            finally:
                                self._folder_project_ids = saved_pids
                            _fetched = all_scans
                        else:
                            scan_query = self._apply_scan_filters(recipe.query)
                            # Use early termination to avoid fetching old scans
                            _fetched = self._fetch_scans_with_early_termination(
                                scan_query
                            )
                        raw_data = (
                            pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                        )
                        del _fetched

                        # Fetch project data for new vs existing analysis
                        # Store in a variable that will be added to additional_data later
                        self._scan_analysis_project_data = None
                        if (
                            hasattr(recipe, "project_list_query")
                            and recipe.project_list_query
                        ):
                            self.logger.info("Fetching project data for Scan Analysis")
                            project_query = QueryConfig(
                                endpoint=recipe.project_list_query.endpoint,
                                params=QueryParams(
                                    limit=recipe.project_list_query.params.limit,
                                    offset=0,
                                    archived=False,
                                    excluded=False,
                                ),
                            )
                            self._scan_analysis_project_data = (
                                self.api_client.fetch_all_with_resume(project_query)
                            )
                            self.logger.info(
                                f"Fetched {len(self._scan_analysis_project_data)} projects for new/existing analysis"
                            )
                    elif recipe.name == "CVE Impact":
                        # CVE Impact uses the /public/v0/cves endpoint which
                        # returns data pre-aggregated by CVE ID. Simple pagination,
                        # no version batching needed.

                        # Scope guard: --cve is always required.
                        # A project-scoped query (--project without --cve)
                        # can return thousands of CVEs and overwhelm the
                        # report.  For a project with N CVEs the dossier
                        # enrichment alone would issue ~3*N API calls
                        # (e.g. 4 000 CVEs → ~12 000 requests).
                        # --project is still accepted as an optional
                        # narrowing filter alongside --cve.
                        if not self.config.cve_filter:
                            self.logger.error(
                                "CVE Impact requires --cve to specify which CVE(s) to analyse. "
                                "--project alone is not supported because it can return "
                                "thousands of CVEs (e.g. 4 000 CVEs → ~12 000 API calls for "
                                "dossier enrichment).  Examples:\n"
                                "  --cve CVE-2022-37434\n"
                                "  --cve CVE-2022-37434,CVE-2023-44487\n"
                                "  --cve CVE-2022-37434 --project openwrt"
                            )
                            raw_data = pd.DataFrame()
                        else:
                            cve_filters: list[str] = []

                            # Apply --cve filter at the API level
                            if self.config.cve_filter:
                                cve_ids = [
                                    c.strip()
                                    for c in self.config.cve_filter.split(",")
                                    if c.strip()
                                ]
                                if len(cve_ids) == 1:
                                    cve_filters.append(f"cveId=={cve_ids[0]}")
                                else:
                                    cve_filters.append(
                                        f"cveId=in=({','.join(cve_ids)})"
                                    )

                            # Apply --project filter (already resolved to
                            # numeric ID by run(), so int() will not fail)
                            if self.config.project_filter:
                                cve_filters.append(
                                    f"project=={self.config.project_filter}"
                                )

                            # Apply --detected-after
                            if getattr(self.config, "detected_after", None):
                                cve_filters.append(
                                    f"detectionDate>={self.config.detected_after}T00:00:00"
                                )

                            cve_query = QueryConfig(
                                endpoint="/public/v0/cves",
                                params=QueryParams(
                                    limit=10000,
                                    filter=(
                                        ";".join(cve_filters) if cve_filters else None
                                    ),
                                ),
                            )
                            self.logger.info(
                                f"Fetching CVEs for {recipe.name}"
                                + (
                                    f" with filter: {cve_query.params.filter}"
                                    if cve_query.params.filter
                                    else ""
                                )
                            )
                            _fetched = self.api_client.fetch_all_with_resume(cve_query)
                            raw_data = (
                                pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                            )
                            del _fetched

                            # In dossier mode, enrich with per-finding reachability,
                            # CVE descriptions, and exploit details
                            if self.config.cve_filter and not raw_data.empty:
                                (
                                    self._cve_impact_reachability,
                                    self._cve_impact_descriptions,
                                    self._cve_impact_exploit_details,
                                    self._cve_impact_nvd_missing,
                                ) = self._fetch_cve_reachability(raw_data)

                    elif recipe.name in (
                        "Component List",
                        "License Report",
                        "CVE Component Evidence",
                    ):
                        # Assessment report: shows current component inventory
                        # No date filtering by default (current state, not period-bound)
                        filters = []

                        # Exclude file type components (SAST placeholders without meaningful data)
                        filters.append("type!=file")

                        # Apply --detected-after if specified (opt-in period filtering)
                        if getattr(self.config, "detected_after", None):
                            filters.append(
                                f"created>={self.config.detected_after}T00:00:00"
                            )

                        # Short-circuit on empty folder: `_folder_project_ids`
                        # is an empty set when --folder resolves to a real
                        # folder that happens to contain zero projects. Without
                        # this guard the falsy `elif self._folder_project_ids:`
                        # checks below fall through to the "no folder" branch
                        # and silently process the entire portfolio (observed
                        # in testing with a --folder that resolved to 0
                        # projects: 155 processed over 10+ minutes). Skip the
                        # fetch and return an empty DataFrame — downstream
                        # transform/render handle empty input.
                        if (
                            self._folder_project_ids is not None
                            and not self._folder_project_ids
                            and not self.config.project_filter
                        ):
                            self.logger.info(
                                "%s: --folder '%s' resolved to 0 projects — "
                                "skipping component fetch",
                                recipe.name,
                                self._folder_name or "(unknown)",
                            )
                            raw_data = pd.DataFrame()
                        elif self.config.version_filter:
                            # Version-scoped endpoint path: encode the version
                            # in the URL so we don't need a projectVersion==
                            # RSQL clause (which returns HTTP 400 against
                            # /public/v0/components on /api/-prefixed
                            # deployments). Preserve every other constraint
                            # the non-version path applies — `type!=file`,
                            # optional `--detected-after`, `archived=False`,
                            # `excluded=False` — so version-filtered runs of
                            # Component List / License Report / CVE Component
                            # Evidence return the same component universe as
                            # the RSQL path. The `project==` clause is
                            # intentionally omitted since the project is
                            # implicit in the projectVersion URL.
                            pvid = str(self.config.version_filter)
                            combined_filter = ";".join(filters) if filters else None
                            unified_query = QueryConfig(
                                endpoint=f"/public/v0/versions/{pvid}/components",
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    archived=False,
                                    excluded=False,
                                ),
                            )
                            self.logger.info(
                                f"Fetching components for {recipe.name} via "
                                f"version-scoped endpoint "
                                f"/public/v0/versions/{pvid}/components"
                            )
                            _fetched = self.api_client.fetch_all_with_resume(
                                unified_query
                            )
                            raw_data = (
                                pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                            )
                            del _fetched
                            # The version-scoped endpoint omits projectVersion
                            # on each row (the version is implicit in the
                            # URL). Backfill it so downstream transforms that
                            # read projectVersion.version (Component List,
                            # License Report) don't render "Unknown".
                            if not raw_data.empty:
                                _v_name = self._lookup_version_display_name(
                                    self.config.project_filter or "", pvid
                                )
                                _pv_obj = {"id": pvid, "version": _v_name}
                                raw_data["projectVersion"] = pd.Series(
                                    [_pv_obj] * len(raw_data),
                                    index=raw_data.index,
                                    dtype=object,
                                )
                        else:
                            if self.config.project_filter:
                                try:
                                    project_id = int(self.config.project_filter)
                                    filters.append(f"project=={project_id}")
                                except ValueError:
                                    filters.append(
                                        f"project=={self.config.project_filter}"
                                    )
                            elif self._folder_project_ids:
                                # Folder scoping — add project=in=() filter (sorted for deterministic cache keys)
                                folder_pids = sorted(self._folder_project_ids)
                                filters.append(
                                    f"project=in=({','.join(str(pid) for pid in folder_pids)})"
                                )

                            combined_filter = ";".join(filters)

                            unified_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    archived=False,
                                    excluded=False,
                                ),
                            )

                            # Use batched version filtering if current_version_only is enabled
                            if self.config.current_version_only:
                                # Scope version resolution to only the projects
                                # being queried — avoids fetching version IDs (and
                                # then components) for projects that the filter will
                                # exclude anyway.
                                if self.config.project_filter:
                                    # Single project → resolve just that one version
                                    version_ids = (
                                        self._get_latest_version_ids_for_projects(
                                            [self.config.project_filter]
                                        )
                                    )
                                elif self._folder_project_ids:
                                    # Folder scope → resolve only folder projects
                                    version_ids = (
                                        self._get_latest_version_ids_for_projects(
                                            list(self._folder_project_ids)
                                        )
                                    )
                                else:
                                    # No project/folder filter → resolve all
                                    version_ids = self._get_latest_version_ids()
                                self.logger.info(
                                    f"Fetching components for {recipe.name} with --current-version-only ({len(version_ids)} versions), base filter: {combined_filter}"
                                )
                                _fetched = self._fetch_with_version_batching(
                                    unified_query,
                                    version_ids,
                                    entity_type="components",
                                )
                                raw_data = (
                                    pd.DataFrame(_fetched)
                                    if _fetched
                                    else pd.DataFrame()
                                )
                                del _fetched
                            else:
                                self.logger.info(
                                    f"Fetching components for {recipe.name} with filter: {combined_filter}"
                                )
                                _fetched = self.api_client.fetch_all_with_resume(
                                    unified_query
                                )
                                raw_data = (
                                    pd.DataFrame(_fetched)
                                    if _fetched
                                    else pd.DataFrame()
                                )
                                del _fetched
                    elif recipe.query.endpoint == "/public/v0/findings":
                        # Report category determines period behaviour:
                        #   Operational (Executive Summary): period filters findings by detected date
                        #   Assessment  (CVA, Findings by Project, Triage): shows current state, period ignored
                        is_operational = recipe.name == "Executive Summary"

                        # Recipes whose YAML filter declares ${start}/${end} have opted
                        # into period-based date filtering regardless of category.
                        _recipe_has_date_filter = bool(
                            recipe.query
                            and recipe.query.params
                            and recipe.query.params.filter
                            and (
                                "${start}" in recipe.query.params.filter
                                or "${end}" in recipe.query.params.filter
                            )
                        )

                        # Build finding type parameters based on --finding-types flag
                        # Executive Dashboard needs all finding types regardless of CLI flag
                        _uses_gates = bool(
                            recipe.parameters and recipe.parameters.get("gates")
                        )
                        if recipe.name == "Executive Dashboard":
                            type_params = build_findings_type_params("all")
                        elif _uses_gates:
                            # Check if the recipe defines its own default finding types
                            _recipe_default_ft = (
                                recipe.parameters.get("default_finding_types")
                                if recipe.parameters
                                else None
                            )
                            if _recipe_default_ft:
                                type_params = build_findings_type_params(
                                    _recipe_default_ft
                                )
                            else:
                                # Recipes with gate-based triage scoring need
                                # reachabilityScore which the API omits when the
                                # ``type=cve`` URL param is used.  Use a category
                                # RSQL filter instead so the full field set is
                                # returned.
                                type_params = {
                                    "type": None,
                                    "category_filter": "category==CVE",
                                }
                        else:
                            type_params = build_findings_type_params(
                                self.config.finding_types
                            )
                        finding_type = type_params.get("type", "cve") or ""
                        category_filter = type_params.get("category_filter")

                        # Whether we need to post-filter by date (set True when entity-
                        # level caching is used and date filters are NOT in the API query)
                        needs_date_postfilter = False
                        raw_data = None

                        # --- Per-batch scoring for Triage Prioritization ---
                        # Normalize + score each batch during fetch so raw
                        # API dicts are discarded immediately, reducing peak
                        # memory by an additional ~20-30% on top of chunked DF.
                        _is_triage = recipe.name == "Triage Prioritization"
                        _low_memory = getattr(self.config, "low_memory", False)
                        _triage_weights = None
                        _triage_gates = None
                        if _is_triage:
                            from fs_report.transforms.pandas.triage_prioritization import (
                                _load_gates,
                                _load_weights,
                                _normalize_columns,
                                apply_tiered_gates,
                                assign_risk_bands,
                                calculate_additive_score,
                            )

                            _triage_ad: dict[str, Any] = {"config": self.config}
                            if recipe.parameters:
                                _triage_ad["recipe_parameters"] = recipe.parameters
                            _triage_weights = _load_weights(self.config, _triage_ad)
                            _triage_gates = _load_gates(self.config, _triage_ad)

                        # --- Per-batch flattening for Findings by Project ---
                        # Pre-flatten nested dict columns and drop unused API
                        # fields per-chunk, reducing accumulated memory ~60%.
                        _is_findings_by_project = recipe.name == "Findings by Project"
                        _flatten_findings_data: Callable | None = None
                        if _is_findings_by_project:
                            from fs_report.transforms.pandas.findings_by_project import (
                                flatten_findings_data as _flatten_findings_data,
                            )

                        # Nested dict columns consumed by flatten_findings_data, plus
                        # API fields not used by the Findings by Project transform.
                        _FBP_DROP_AFTER_FLATTEN = {
                            "component",
                            "project",
                            "projectVersion",
                            "exploitInfo",
                            "cwes",
                            "attackVector",
                            "epssPercentile",
                            "epssScore",
                            "hasKnownExploit",
                            "inKev",
                            "affectedFunctions",
                            "risk",  # already extracted to cvss_score
                        }

                        # --- Per-batch column pruning for Executive Summary ---
                        # Keep only the 5 columns the transforms actually use,
                        # dropping ~50+ nested-dict/API columns per batch.
                        _is_exec_summary = recipe.name == "Executive Summary"
                        # Retain the exploit-signal scalars derived in the
                        # per-batch pre-flatten (C1/C2). One assignment covers
                        # all 7 _prune_exec_summary call sites — none builds its
                        # own keep-set. exploitInfo/exploitMaturity are still
                        # dropped after the scalars are computed.
                        _exec_extra_keep: frozenset[str] | None = (
                            frozenset({"inKev", "inVcKev", "is_real_exploit"})
                            if _is_exec_summary
                            else None
                        )

                        # --- Per-batch column pruning for Executive Dashboard ---
                        _is_exec_dashboard = recipe.name == "Executive Dashboard"
                        _ed_extra_keep: frozenset[str] | None = None

                        # --- Per-batch flatten + pruning for CVA ---
                        _is_cva = recipe.name == "Component Vulnerability Analysis"
                        _cva_pre_flattened = False

                        # --- Per-batch description parse-and-discard for Config Analysis Triage ---
                        _is_config_triage = (
                            recipe.name == "Configuration Analysis Triage"
                        )
                        _config_extract: Callable | None = None
                        if _is_config_triage:
                            from fs_report.transforms.pandas.configuration_analysis_triage import (
                                extract_detail_columns as _config_extract,
                            )

                        # --- NVD pipeline: start background lookups during fetch ---
                        if _is_findings_by_project and not getattr(
                            self.config, "skip_nvd", False
                        ):
                            _nvd_on_records, _nvd_collect = self._start_nvd_pipeline()

                        # --- Component search optimization ---
                        # For component-scoped recipes (RP, CRP, CI), search
                        # components by name first to get version IDs, then scope
                        # the findings query to only those versions.
                        _component_search_results: list[dict] | None = None
                        _component_version_ids: set | None = None
                        _is_component_scoped = getattr(
                            self.config, "component_filter", None
                        ) and recipe.name in (
                            "Remediation Package",
                            "Component Remediation Package",
                            "Component Impact",
                        )
                        if _is_component_scoped:
                            _cs_result = self._search_components()
                            if _cs_result is not None:
                                _component_search_results, _component_version_ids = (
                                    _cs_result
                                )
                                if _component_version_ids:
                                    self.logger.info(
                                        "Component search optimization: scoping "
                                        "findings to %d version IDs",
                                        len(_component_version_ids),
                                    )
                                else:
                                    self.logger.info(
                                        "Component search returned 0 matching "
                                        "versions — report will be empty"
                                    )

                        # Store for later injection into additional_data
                        self._component_search_results = _component_search_results

                        # Build filter list for non-entity-cached paths
                        # (entity-cached paths skip this and post-filter instead)
                        filters = []

                        # Preserve recipe-defined RSQL filter (e.g. CRA Compliance KEV filter)
                        if (
                            recipe.query
                            and recipe.query.params
                            and recipe.query.params.filter
                            and "${" not in recipe.query.params.filter
                        ):
                            _recipe_rsql = recipe.query.params.filter
                            # RSQL "or" keyword needs parentheses when combined with ";"
                            # Convert: "inKev==true or hasKnownExploit==true"
                            #      to: "(inKev==true,hasKnownExploit==true)"
                            if " or " in _recipe_rsql.lower():
                                parts = [
                                    p.strip()
                                    for p in _recipe_rsql.split(" or ")
                                    if p.strip()
                                ]
                                _recipe_rsql = f"({','.join(parts)})"
                            filters.append(_recipe_rsql)

                        if category_filter:
                            filters.append(category_filter)

                        # Period-filtered reports: add detected date range filter
                        if is_operational or _recipe_has_date_filter:
                            filters.append(
                                f"detected>={self.config.start_date}T00:00:00"
                            )
                            filters.append(f"detected<={self.config.end_date}T23:59:59")

                        # Assessment reports (without date vars): apply --detected-after if specified
                        if (
                            not is_operational
                            and not _recipe_has_date_filter
                            and getattr(self.config, "detected_after", None)
                        ):
                            filters.append(
                                f"detected>={self.config.detected_after}T00:00:00"
                            )

                        if getattr(self.config, "open_only", False):
                            filters.append(
                                "status=out=(NOT_AFFECTED,FALSE_POSITIVE,RESOLVED,RESOLVED_WITH_PEDIGREE)"
                            )

                        # Scoped Remediation Package: CVE filter is applied in the
                        # transform (not at API level) so sibling CVEs on the
                        # same component are included in the action card.

                        # Component-search scoping: add version ID filter and
                        # skip the project/folder version-resolution branches
                        # (versions are already known from the search).
                        if _component_version_ids:
                            sorted_vids = sorted(_component_version_ids)
                            filters.append(
                                f"projectVersion=in=({','.join(str(v) for v in sorted_vids)})"
                            )
                            # Still add project filter for safety (redundant but harmless)
                            if self.config.project_filter:
                                try:
                                    project_id = int(self.config.project_filter)
                                    filters.append(f"project=={project_id}")
                                except ValueError:
                                    filters.append(
                                        f"project=={self.config.project_filter}"
                                    )

                            # Build query and fetch immediately — skip the
                            # version-resolution / entity-caching branches below
                            combined_filter = ";".join(filters) if filters else ""
                            unified_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    finding_type=finding_type,
                                    archived=False,
                                    excluded=False,
                                ),
                            )
                            self.logger.info(
                                "Fetching findings for %s (component-search scoped) "
                                "with filter: %s",
                                recipe.name,
                                combined_filter,
                            )
                            _fetched = self.api_client.fetch_all_with_resume(
                                unified_query
                            )
                            # Feed NVD pipeline before converting to DataFrame
                            if _nvd_on_records is not None and _fetched:
                                _nvd_on_records(_fetched)
                            raw_data = (
                                pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                            )
                            del _fetched

                        elif (
                            _is_component_scoped
                            and _component_search_results is not None
                        ):
                            # Component search ran and returned 0 versions
                            # (e.g. --component-match exact with no exact matches).
                            # Skip all findings fetch paths below — without this
                            # short-circuit, the `else` branch fetches every
                            # project in the period and the transform's
                            # contains-mode filter re-includes substring matches.
                            self.logger.info(
                                "Skipping findings fetch: component search "
                                "returned 0 matching versions"
                            )
                            raw_data = pd.DataFrame()

                        elif self.config.project_filter:
                            # Single project filter - get findings for this project
                            try:
                                project_id = int(self.config.project_filter)
                                filters.append(f"project=={project_id}")
                            except ValueError:
                                filters.append(f"project=={self.config.project_filter}")

                            if self.config.version_filter:
                                # Resolve dependencies for pinned version
                                _vf_proj_id = self.config.project_filter
                                _vf_ver_id = self.config.version_filter
                                _vf_proj_name = self.resolved_project_name or str(
                                    _vf_proj_id
                                )
                                _dep_vids, self._current_dependency_tree = (
                                    self._expand_version_ids_with_dependencies(
                                        [_vf_ver_id],
                                        _vf_proj_id,
                                        _vf_proj_name,
                                    )
                                )
                                if len(_dep_vids) > 1:
                                    # Has dependencies — use version batching
                                    _vf = self._get_findings_for_versions(
                                        _dep_vids,
                                        finding_type,
                                        category_filter,
                                        on_records=_nvd_on_records,
                                        include_additional_details=(
                                            True if _is_config_triage else None
                                        ),
                                    )
                                    raw_data = (
                                        pd.DataFrame(_vf) if _vf else pd.DataFrame()
                                    )
                                    del _vf
                                    # Pre-flatten nested dicts for Findings by Project
                                    if (
                                        _is_findings_by_project
                                        and _flatten_findings_data is not None
                                        and not raw_data.empty
                                    ):
                                        raw_data = _flatten_findings_data(raw_data)
                                        _drop = [
                                            c
                                            for c in _FBP_DROP_AFTER_FLATTEN
                                            if c in raw_data.columns
                                        ]
                                        if _drop:
                                            raw_data = raw_data.drop(columns=_drop)
                                    if _is_exec_summary and not raw_data.empty:
                                        raw_data = _prune_exec_summary(
                                            raw_data, _exec_extra_keep
                                        )
                                    if _is_exec_dashboard and not raw_data.empty:
                                        raw_data = _prune_exec_dashboard(
                                            raw_data, _ed_extra_keep
                                        )
                                    if (
                                        _is_config_triage
                                        and _config_extract is not None
                                        and not raw_data.empty
                                    ):
                                        raw_data = _config_extract(raw_data)
                                    needs_date_postfilter = True
                                else:
                                    # No dependencies — use existing filter path
                                    filters.append(
                                        f"projectVersion=={self.config.version_filter}"
                                    )
                            elif self.config.current_version_only:
                                # Use entity-level caching (consistent with folder/scan paths)
                                _proj_id = self.config.project_filter
                                if _proj_id is not None:
                                    latest_vids = (
                                        self._get_latest_version_ids_for_projects(
                                            [_proj_id]
                                        )
                                    )
                                    if latest_vids:
                                        # Expand with dependency versions
                                        _proj_name = self.resolved_project_name or str(
                                            _proj_id
                                        )
                                        latest_vids, self._current_dependency_tree = (
                                            self._expand_version_ids_with_dependencies(
                                                latest_vids,
                                                _proj_id,
                                                _proj_name,
                                            )
                                        )
                                        self.logger.info(
                                            f"--current-version-only: scoping to latest version {latest_vids[0]}"
                                        )
                                        _vf = self._get_findings_for_versions(
                                            latest_vids,
                                            finding_type,
                                            category_filter,
                                            on_records=_nvd_on_records,
                                            include_additional_details=(
                                                True if _is_config_triage else None
                                            ),
                                        )
                                        raw_data = (
                                            pd.DataFrame(_vf) if _vf else pd.DataFrame()
                                        )
                                        del _vf
                                        # Pre-flatten nested dicts for Findings by Project
                                        if (
                                            _is_findings_by_project
                                            and _flatten_findings_data is not None
                                            and not raw_data.empty
                                        ):
                                            raw_data = _flatten_findings_data(raw_data)
                                            _drop = [
                                                c
                                                for c in _FBP_DROP_AFTER_FLATTEN
                                                if c in raw_data.columns
                                            ]
                                            if _drop:
                                                raw_data = raw_data.drop(columns=_drop)
                                        # Per-batch column pruning for Executive Summary
                                        if _is_exec_summary and not raw_data.empty:
                                            raw_data = _prune_exec_summary(
                                                raw_data, _exec_extra_keep
                                            )
                                        # Per-batch column pruning for Executive Dashboard
                                        if _is_exec_dashboard and not raw_data.empty:
                                            raw_data = _prune_exec_dashboard(
                                                raw_data, _ed_extra_keep
                                            )
                                        # Per-batch parse-and-discard for Config Analysis Triage
                                        if (
                                            _is_config_triage
                                            and _config_extract is not None
                                            and not raw_data.empty
                                        ):
                                            raw_data = _config_extract(raw_data)
                                        needs_date_postfilter = True
                                    else:
                                        self.logger.warning(
                                            f"Could not resolve latest version for project {self.config.project_filter}; "
                                            "falling back to all versions"
                                        )

                            if raw_data is None:
                                combined_filter = ";".join(filters) if filters else ""
                                unified_query = QueryConfig(
                                    endpoint=recipe.query.endpoint,
                                    params=QueryParams(
                                        limit=recipe.query.params.limit,
                                        filter=combined_filter,
                                        finding_type=finding_type,
                                        archived=False,
                                        excluded=False,
                                        include_additional_details=(
                                            True if _is_config_triage else None
                                        ),
                                    ),
                                )

                                self.logger.info(
                                    f"Fetching findings for {recipe.name} with type={finding_type}, filter: {combined_filter}"
                                )
                                _fetched = self.api_client.fetch_all_with_resume(
                                    unified_query
                                )
                                # Feed NVD pipeline before converting to DataFrame
                                if _nvd_on_records is not None and _fetched:
                                    _nvd_on_records(_fetched)
                                raw_data = (
                                    pd.DataFrame(_fetched)
                                    if _fetched
                                    else pd.DataFrame()
                                )
                                del _fetched
                                # Per-batch column pruning for Executive Summary
                                if _is_exec_summary and not raw_data.empty:
                                    raw_data = _prune_exec_summary(
                                        raw_data, _exec_extra_keep
                                    )
                                # Per-batch column pruning for Executive Dashboard
                                if _is_exec_dashboard and not raw_data.empty:
                                    raw_data = _prune_exec_dashboard(
                                        raw_data, _ed_extra_keep
                                    )
                                # Per-batch parse-and-discard for Config Analysis Triage
                                if (
                                    _is_config_triage
                                    and _config_extract is not None
                                    and not raw_data.empty
                                ):
                                    raw_data = _config_extract(raw_data)
                        elif self._folder_project_ids:
                            # Folder scoping active — use folder's project set directly
                            # Sort for deterministic batching (ensures SQLite cache hits across runs)
                            folder_pids = sorted(self._folder_project_ids)
                            self.logger.info(
                                f"Fetching findings for {recipe.name} scoped to folder '{self._folder_name}' ({len(folder_pids)} projects)"
                            )

                            combined_filter = ";".join(filters) if filters else ""
                            unified_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=combined_filter,
                                    finding_type=finding_type,
                                    archived=False,
                                    excluded=False,
                                ),
                            )

                            if self.config.current_version_only:
                                # Entity-level caching: fetch per-version (shared across reports)
                                version_ids = sorted(
                                    self._get_latest_version_ids_for_projects(
                                        folder_pids
                                    )
                                )
                                # Expand with dependency versions per project
                                version_ids, self._current_dependency_tree = (
                                    self._expand_folder_version_ids_with_dependencies(
                                        version_ids
                                    )
                                )
                                self.logger.info(
                                    f"Fetching findings for {recipe.name} with --current-version-only "
                                    f"({len(version_ids)} latest versions)"
                                )
                                _vf = self._get_findings_for_versions(
                                    version_ids,
                                    finding_type,
                                    category_filter,
                                    on_records=_nvd_on_records,
                                    include_additional_details=(
                                        True if _is_config_triage else None
                                    ),
                                )
                                raw_data = pd.DataFrame(_vf) if _vf else pd.DataFrame()
                                del _vf
                                # Pre-flatten nested dicts for Findings by Project
                                if (
                                    _is_findings_by_project
                                    and _flatten_findings_data is not None
                                    and not raw_data.empty
                                ):
                                    if self._project_folder_map:
                                        _inject_folder_names_df(
                                            raw_data, self._project_folder_map
                                        )
                                    raw_data = _flatten_findings_data(raw_data)
                                    _drop = [
                                        c
                                        for c in _FBP_DROP_AFTER_FLATTEN
                                        if c in raw_data.columns
                                    ]
                                    if _drop:
                                        raw_data = raw_data.drop(columns=_drop)
                                    self.logger.info(
                                        f"Pre-flattened {len(raw_data)} findings ({len(raw_data.columns)} columns after pruning)"
                                    )
                                # Per-batch column pruning for Executive Summary
                                if _is_exec_summary and not raw_data.empty:
                                    raw_data = _prune_exec_summary(
                                        raw_data, _exec_extra_keep
                                    )
                                # Per-batch column pruning for Executive Dashboard
                                if _is_exec_dashboard and not raw_data.empty:
                                    raw_data = _prune_exec_dashboard(
                                        raw_data, _ed_extra_keep
                                    )
                                # Per-batch parse-and-discard for Config Analysis Triage
                                if (
                                    _is_config_triage
                                    and _config_extract is not None
                                    and not raw_data.empty
                                ):
                                    raw_data = _config_extract(raw_data)
                                needs_date_postfilter = True
                            else:
                                # Batch by project IDs — all versions
                                # Build a cache key from the query signature
                                _pid_str = ",".join(str(p) for p in sorted(folder_pids))
                                _cache_parts = f"{recipe.query.endpoint}|{combined_filter or ''}|{finding_type}|pids:{_pid_str}"
                                _cache_key = hashlib.sha256(
                                    _cache_parts.encode()
                                ).hexdigest()[:16]

                                if _cache_key in self._findings_cache:
                                    raw_data = self._findings_cache[_cache_key]
                                    self.logger.info(
                                        f"Using in-memory cached findings for {recipe.name} "
                                        f"({len(raw_data)} records, same query as a previous report)"
                                    )
                                else:
                                    # Chunked DF construction — convert each batch
                                    # to a DataFrame immediately so raw list[dict] is
                                    # freed, reducing peak memory by ~40-50%.
                                    chunks: list[pd.DataFrame] = []
                                    # Adaptive batch sizing: reduce batch size for large project counts
                                    batch_size = (
                                        15 if len(folder_pids) > 200 else 25
                                    )  # Keep URLs under server limits
                                    from tqdm import tqdm as _tqdm

                                    total_records = 0
                                    with _tqdm(
                                        range(0, len(folder_pids), batch_size),
                                        desc="Fetching folder findings",
                                        unit=" batches",
                                        leave=False,
                                    ) as pbar:
                                        for i in pbar:
                                            batch_ids = folder_pids[i : i + batch_size]
                                            project_filter_str = f"project=in=({','.join(str(pid) for pid in batch_ids)})"
                                            batch_filters = [
                                                project_filter_str
                                            ] + filters
                                            batch_combined = ";".join(batch_filters)

                                            batch_query = QueryConfig(
                                                endpoint=recipe.query.endpoint,
                                                params=QueryParams(
                                                    limit=recipe.query.params.limit,
                                                    filter=batch_combined,
                                                    finding_type=finding_type,
                                                    archived=False,
                                                    excluded=False,
                                                ),
                                            )
                                            batch_data = (
                                                self.api_client.fetch_all_with_resume(
                                                    batch_query, show_progress=False
                                                )
                                            )
                                            if batch_data:
                                                # Feed CVE IDs to NVD pipeline
                                                if _nvd_on_records is not None:
                                                    _nvd_on_records(batch_data)
                                                # Per-batch flatten for CVA
                                                if _is_cva:
                                                    from fs_report.data_transformer import (
                                                        flatten_records,
                                                    )

                                                    batch_data = flatten_records(
                                                        batch_data,
                                                        fields_to_flatten=[
                                                            "component",
                                                            "project",
                                                            "finding",
                                                        ],
                                                    )
                                                    _cva_pre_flattened = True
                                                chunk_df = pd.DataFrame(batch_data)
                                                total_records += len(batch_data)
                                                del batch_data  # Free batch memory immediately
                                                # Per-batch triage scoring
                                                if (
                                                    _is_triage
                                                    and _triage_weights is not None
                                                ):
                                                    if self._project_folder_map:
                                                        _inject_folder_names_df(
                                                            chunk_df,
                                                            self._project_folder_map,
                                                        )
                                                    chunk_df = _normalize_columns(
                                                        chunk_df
                                                    )
                                                    chunk_df = apply_tiered_gates(
                                                        chunk_df, gates=_triage_gates
                                                    )
                                                    chunk_df = calculate_additive_score(
                                                        chunk_df,
                                                        weights=_triage_weights,
                                                        gates=_triage_gates,
                                                    )
                                                    chunk_df = assign_risk_bands(
                                                        chunk_df,
                                                        weights=_triage_weights,
                                                        gates=_triage_gates,
                                                    )
                                                    _drop = [
                                                        c
                                                        for c in _TRIAGE_DROP_AFTER_SCORE
                                                        if c in chunk_df.columns
                                                    ]
                                                    if _drop:
                                                        chunk_df = chunk_df.drop(
                                                            columns=_drop
                                                        )
                                                # Per-batch flattening for Findings by Project
                                                if (
                                                    _is_findings_by_project
                                                    and _flatten_findings_data
                                                    is not None
                                                ):
                                                    if self._project_folder_map:
                                                        _inject_folder_names_df(
                                                            chunk_df,
                                                            self._project_folder_map,
                                                        )
                                                    chunk_df = _flatten_findings_data(
                                                        chunk_df
                                                    )
                                                    _drop = [
                                                        c
                                                        for c in _FBP_DROP_AFTER_FLATTEN
                                                        if c in chunk_df.columns
                                                    ]
                                                    if _drop:
                                                        chunk_df = chunk_df.drop(
                                                            columns=_drop
                                                        )
                                                # Per-batch column pruning for Executive Summary
                                                if _is_exec_summary:
                                                    chunk_df = _prune_exec_summary(
                                                        chunk_df, _exec_extra_keep
                                                    )
                                                # Per-batch column pruning for Executive Dashboard
                                                if _is_exec_dashboard:
                                                    chunk_df = _prune_exec_dashboard(
                                                        chunk_df, _ed_extra_keep
                                                    )
                                                # Per-batch column pruning for CVA
                                                if _is_cva:
                                                    chunk_df = _prune_cva(
                                                        chunk_df, _cva_extra_keep
                                                    )
                                                chunks.append(chunk_df)
                                                del chunk_df
                                            else:
                                                del batch_data
                                            pbar.set_postfix({"records": total_records})

                                            # Inter-batch delay to reduce server load
                                            # Scales with --request-delay (minimum 1s between batches)
                                            if i + batch_size < len(folder_pids):
                                                self._cancellable_sleep(
                                                    max(1.0, self.config.request_delay)
                                                )
                                    raw_data = (
                                        pd.concat(chunks, ignore_index=True)
                                        if chunks
                                        else pd.DataFrame()
                                    )
                                    del chunks
                                    self._findings_cache[_cache_key] = raw_data
                                    if _is_exec_summary:
                                        _es_cache_key = _cache_key
                                    if _is_exec_dashboard:
                                        _ed_cache_key = _cache_key

                            self.logger.info(
                                f"Fetched {len(raw_data)} findings for folder scope"
                            )
                        else:
                            # No project filter - get projects scanned in the period, then their findings
                            self.logger.info(
                                f"Finding projects scanned between {self.config.start_date} and {self.config.end_date}..."
                            )

                            # Fetch scans in the period to get project IDs
                            # Use the same early termination logic as Scan Analysis
                            # Apply folder/project filters for cache reuse with Scan Analysis
                            # Note: /scans endpoint has max limit of 100
                            scan_query = QueryConfig(
                                endpoint="/public/v0/scans",
                                params=QueryParams(limit=100, sort="created:desc"),
                            )
                            scan_query = self._apply_scan_filters(scan_query)
                            scans_in_period = self._fetch_scans_with_early_termination(
                                scan_query
                            )

                            # Extract unique project IDs and track latest version per project
                            scanned_project_ids = set()
                            # Track latest version per project: {project_id: (version_id, scan_created)}
                            project_latest_version: dict[str, tuple[str, str]] = {}

                            for scan in scans_in_period:
                                # Scan structure has 'project' and 'projectVersion' at top level
                                project = scan.get("project", {})
                                project_version = scan.get("projectVersion", {})
                                scan_created = scan.get("created", "")

                                # Extract project ID
                                if isinstance(project, dict) and project.get("id"):
                                    project_id = project["id"]
                                    scanned_project_ids.add(project_id)

                                    # Extract version ID
                                    version_id = None
                                    if isinstance(project_version, dict):
                                        version_id = project_version.get("id")

                                    if version_id:
                                        # Keep track of the most recently scanned version per project
                                        if project_id not in project_latest_version:
                                            project_latest_version[project_id] = (
                                                version_id,
                                                scan_created,
                                            )
                                        else:
                                            existing_created = project_latest_version[
                                                project_id
                                            ][1]
                                            if scan_created > existing_created:
                                                project_latest_version[project_id] = (
                                                    version_id,
                                                    scan_created,
                                                )

                            self.logger.info(
                                f"Found {len(scanned_project_ids)} unique projects scanned in the period"
                            )

                            if not scanned_project_ids:
                                self.logger.warning(
                                    "No projects found with scans in the specified period"
                                )
                                raw_data = pd.DataFrame()
                            elif self.config.current_version_only:
                                # Entity-level caching: fetch per-version (shared across reports)
                                version_ids = self._get_latest_version_ids_for_projects(
                                    list(scanned_project_ids)
                                )
                                self.logger.info(
                                    f"Fetching findings for {len(version_ids)} projects (true latest version each)"
                                )
                                _vf = self._get_findings_for_versions(
                                    sorted(version_ids),
                                    finding_type,
                                    category_filter,
                                    on_records=_nvd_on_records,
                                    include_additional_details=(
                                        True if _is_config_triage else None
                                    ),
                                )
                                raw_data = pd.DataFrame(_vf) if _vf else pd.DataFrame()
                                del _vf
                                # Pre-flatten nested dicts for Findings by Project
                                if (
                                    _is_findings_by_project
                                    and _flatten_findings_data is not None
                                    and not raw_data.empty
                                ):
                                    raw_data = _flatten_findings_data(raw_data)
                                    _drop = [
                                        c
                                        for c in _FBP_DROP_AFTER_FLATTEN
                                        if c in raw_data.columns
                                    ]
                                    if _drop:
                                        raw_data = raw_data.drop(columns=_drop)
                                # Per-batch column pruning for Executive Summary
                                if _is_exec_summary and not raw_data.empty:
                                    raw_data = _prune_exec_summary(
                                        raw_data, _exec_extra_keep
                                    )
                                # Per-batch column pruning for Executive Dashboard
                                if _is_exec_dashboard and not raw_data.empty:
                                    raw_data = _prune_exec_dashboard(
                                        raw_data, _ed_extra_keep
                                    )
                                # Per-batch parse-and-discard for Config Analysis Triage
                                if (
                                    _is_config_triage
                                    and _config_extract is not None
                                    and not raw_data.empty
                                ):
                                    raw_data = _config_extract(raw_data)
                                needs_date_postfilter = True
                            else:
                                # Get findings for all scanned projects (all versions)
                                project_ids = list(scanned_project_ids)
                                self.logger.info(
                                    f"Fetching findings for {len(project_ids)} scanned projects (all versions)"
                                )

                                # Batch by project IDs to avoid URL length limits
                                # Chunked DF construction — convert each batch to
                                # a DataFrame immediately so raw list[dict] is freed.
                                pv_chunks: list[pd.DataFrame] = []
                                batch_size = (
                                    10 if len(project_ids) > 200 else 25
                                )  # Projects per batch (kept small — IDs are 20-digit longs)
                                from tqdm import tqdm

                                total_records = 0
                                _log_memory(
                                    self.logger,
                                    f"Before batch fetch ({len(project_ids)} projects, batch_size={batch_size})",
                                )
                                with tqdm(
                                    range(0, len(project_ids), batch_size),
                                    desc="Fetching project findings",
                                    unit=" batches",
                                    leave=False,
                                ) as pbar:
                                    for i in pbar:
                                        batch_ids = project_ids[i : i + batch_size]
                                        project_filter = f"project=in=({','.join(str(pid) for pid in batch_ids)})"

                                        batch_filters = [project_filter] + filters
                                        combined_filter = ";".join(batch_filters)

                                        batch_query = QueryConfig(
                                            endpoint=recipe.query.endpoint,
                                            params=QueryParams(
                                                limit=recipe.query.params.limit,
                                                filter=combined_filter,
                                                finding_type=finding_type,
                                                archived=False,
                                                excluded=False,
                                            ),
                                        )
                                        batch_data = (
                                            self.api_client.fetch_all_with_resume(
                                                batch_query, show_progress=False
                                            )
                                        )
                                        if batch_data:
                                            # Feed CVE IDs to NVD pipeline
                                            if _nvd_on_records is not None:
                                                _nvd_on_records(batch_data)
                                            # Per-batch flatten for CVA
                                            if _is_cva:
                                                from fs_report.data_transformer import (
                                                    flatten_records,
                                                )

                                                batch_data = flatten_records(
                                                    batch_data,
                                                    fields_to_flatten=[
                                                        "component",
                                                        "project",
                                                        "finding",
                                                    ],
                                                )
                                                _cva_pre_flattened = True
                                            chunk_df = pd.DataFrame(batch_data)
                                            total_records += len(batch_data)
                                            del batch_data  # Free batch memory immediately
                                            # Per-batch triage scoring
                                            if (
                                                _is_triage
                                                and _triage_weights is not None
                                            ):
                                                chunk_df = _normalize_columns(chunk_df)
                                                chunk_df = apply_tiered_gates(
                                                    chunk_df, gates=_triage_gates
                                                )
                                                chunk_df = calculate_additive_score(
                                                    chunk_df,
                                                    weights=_triage_weights,
                                                    gates=_triage_gates,
                                                )
                                                chunk_df = assign_risk_bands(
                                                    chunk_df,
                                                    weights=_triage_weights,
                                                    gates=_triage_gates,
                                                )
                                                _drop = [
                                                    c
                                                    for c in _TRIAGE_DROP_AFTER_SCORE
                                                    if c in chunk_df.columns
                                                ]
                                                if _drop:
                                                    chunk_df = chunk_df.drop(
                                                        columns=_drop
                                                    )
                                            # Per-batch flattening for Findings by Project
                                            if (
                                                _is_findings_by_project
                                                and _flatten_findings_data is not None
                                            ):
                                                chunk_df = _flatten_findings_data(
                                                    chunk_df
                                                )
                                                _drop = [
                                                    c
                                                    for c in _FBP_DROP_AFTER_FLATTEN
                                                    if c in chunk_df.columns
                                                ]
                                                if _drop:
                                                    chunk_df = chunk_df.drop(
                                                        columns=_drop
                                                    )
                                            # Per-batch column pruning for Executive Summary
                                            if _is_exec_summary:
                                                chunk_df = _prune_exec_summary(
                                                    chunk_df, _exec_extra_keep
                                                )
                                            # Per-batch column pruning for Executive Dashboard
                                            if _is_exec_dashboard:
                                                chunk_df = _prune_exec_dashboard(
                                                    chunk_df, _ed_extra_keep
                                                )
                                            # Per-batch column pruning for CVA
                                            if _is_cva:
                                                chunk_df = _prune_cva(
                                                    chunk_df, _cva_extra_keep
                                                )
                                            pv_chunks.append(chunk_df)
                                            del chunk_df
                                        else:
                                            del batch_data
                                        pbar.set_postfix({"records": total_records})

                                        # Inter-batch delay to reduce server load
                                        # Scales with --request-delay (minimum 1s between batches)
                                        if i + batch_size < len(project_ids):
                                            self._cancellable_sleep(
                                                max(1.0, self.config.request_delay)
                                            )
                                raw_data = (
                                    pd.concat(pv_chunks, ignore_index=True)
                                    if pv_chunks
                                    else pd.DataFrame()
                                )
                                del pv_chunks

                                _log_memory(
                                    self.logger,
                                    f"After batch fetch ({total_records} findings)",
                                )
                                if _low_memory and not raw_data.empty:
                                    self.logger.info(
                                        f"[low-memory] Concat'd {total_records:,} findings "
                                        f"({len(raw_data.columns)} columns)"
                                    )
                                self.logger.info(
                                    f"Fetched {total_records} total findings for scanned projects"
                                )
                    else:
                        # Generic handler for robust endpoints not matched above
                        # (e.g. Scan Quality on /public/v0/scans).
                        if _endpoint == "/public/v0/scans":
                            # Use the same scan-specific fetch path as Scan Analysis:
                            # _apply_scan_filters for project/folder scoping, then
                            # _fetch_scans_with_early_termination for robust retry +
                            # date-based early termination + SQLite cache.
                            # Assessment recipes (e.g. Scan Quality) need ALL scans,
                            # not just those in the --period window.
                            _saved_start = self.config.start_date
                            if recipe.category == "assessment":
                                self.config.start_date = "2020-01-01"
                            try:
                                # Batch folder project IDs to avoid 414 URL Too Long
                                if (
                                    self._folder_project_ids
                                    and not self.config.project_filter
                                    and len(self._folder_project_ids) > 25
                                ):
                                    _folder_pids = sorted(self._folder_project_ids)
                                    _batch_sz = 15 if len(_folder_pids) > 200 else 25
                                    _all_scans: list[dict] = []
                                    _saved_pids = self._folder_project_ids
                                    self.logger.info(
                                        f"Batching {recipe.name} scan fetch: "
                                        f"{len(_folder_pids)} projects, "
                                        f"batch_size={_batch_sz}"
                                    )
                                    try:
                                        for _bi in range(
                                            0, len(_folder_pids), _batch_sz
                                        ):
                                            self._folder_project_ids = set(
                                                _folder_pids[_bi : _bi + _batch_sz]
                                            )
                                            _scan_query = self._apply_scan_filters(
                                                recipe.query
                                            )
                                            _batch_data = self._fetch_scans_with_early_termination(
                                                _scan_query
                                            )
                                            if _batch_data:
                                                _all_scans.extend(_batch_data)
                                    finally:
                                        self._folder_project_ids = _saved_pids
                                    _fetched = _all_scans
                                else:
                                    _scan_query = self._apply_scan_filters(recipe.query)
                                    self.logger.info(
                                        f"Fetching {recipe.name} via scan filters"
                                        + (
                                            f", filter: {_scan_query.params.filter}"
                                            if _scan_query.params.filter
                                            else ""
                                        )
                                    )
                                    _fetched = self._fetch_scans_with_early_termination(
                                        _scan_query
                                    )
                            finally:
                                if recipe.category == "assessment":
                                    self.config.start_date = _saved_start
                        else:
                            _generic_filters: list[str] = []
                            if self.config.project_filter:
                                try:
                                    _gp_id = int(self.config.project_filter)
                                    _generic_filters.append(f"project=={_gp_id}")
                                except ValueError:
                                    _generic_filters.append(
                                        f"project=={self.config.project_filter}"
                                    )
                            elif self._folder_project_ids:
                                folder_pids = sorted(self._folder_project_ids)
                                _generic_filters.append(
                                    f"project=in=({','.join(str(pid) for pid in folder_pids)})"
                                )
                            _generic_combined = (
                                ";".join(_generic_filters) if _generic_filters else ""
                            )
                            _generic_query = QueryConfig(
                                endpoint=recipe.query.endpoint,
                                params=QueryParams(
                                    limit=recipe.query.params.limit,
                                    filter=_generic_combined or None,
                                    sort=getattr(recipe.query.params, "sort", None),
                                ),
                            )
                            self.logger.info(
                                f"Fetching {recipe.name} with paginated fetch"
                                + (
                                    f", filter: {_generic_combined}"
                                    if _generic_combined
                                    else ""
                                )
                            )
                            _fetched = self.api_client.fetch_all_with_resume(
                                _generic_query
                            )
                        raw_data = (
                            pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                        )
                        del _fetched
                else:
                    _fetched = self.api_client.fetch_data(recipe.query)
                    raw_data = pd.DataFrame(_fetched) if _fetched else pd.DataFrame()
                    del _fetched

            # --- Date post-filtering for entity-cached paths ---
            # When _get_findings_for_versions was used, data is NOT date-filtered
            # at the API level (entity cache stores ALL findings per version).
            # Apply the date filter in-memory now.
            if (
                needs_date_postfilter
                and isinstance(raw_data, pd.DataFrame)
                and not raw_data.empty
            ):
                if is_operational or _recipe_has_date_filter:
                    start = f"{self.config.start_date}T00:00:00"
                    end = f"{self.config.end_date}T23:59:59"
                    before_count = len(raw_data)
                    detected = raw_data.get(
                        "detected", pd.Series("", index=raw_data.index)
                    ).fillna("")
                    raw_data = raw_data[(detected >= start) & (detected <= end)]
                    self.logger.debug(
                        f"Date post-filter ({self.config.start_date} to {self.config.end_date}): "
                        f"{before_count} -> {len(raw_data)} findings"
                    )
                elif (
                    not is_operational
                    and not _recipe_has_date_filter
                    and getattr(self.config, "detected_after", None)
                ):
                    before_count = len(raw_data)
                    detected = raw_data.get(
                        "detected", pd.Series("", index=raw_data.index)
                    ).fillna("")
                    raw_data = raw_data[
                        detected >= f"{self.config.detected_after}T00:00:00"
                    ]
                    self.logger.debug(
                        f"Detected-after post-filter ({self.config.detected_after}): "
                        f"{before_count} -> {len(raw_data)} findings"
                    )

            # --- Status post-filtering for entity-cached paths ---
            # Entity cache stores ALL findings per version (no status filter).
            # When --open-only is set, exclude resolved/suppressed statuses here.
            if (
                needs_date_postfilter
                and getattr(self.config, "open_only", False)
                and isinstance(raw_data, pd.DataFrame)
                and not raw_data.empty
            ):
                _RESOLVED_STATUSES = {
                    "NOT_AFFECTED",
                    "FALSE_POSITIVE",
                    "RESOLVED",
                    "RESOLVED_WITH_PEDIGREE",
                }
                before_count = len(raw_data)
                status_col = (
                    raw_data.get("status", pd.Series("", index=raw_data.index))
                    .fillna("")
                    .str.upper()
                )
                raw_data = raw_data[~status_col.isin(_RESOLVED_STATUSES)]
                self.logger.debug(
                    f"Open-only post-filter: {before_count} -> {len(raw_data)} findings"
                )

            # Multi-type filtering used to be implemented as a post-fetch
            # filter on the response `category` and `type` fields, but the
            # `category` field is always null in /findings responses and the
            # `type` field uses dashed values (`binary-sast`) that did not
            # match the underscored CLI values, so the filter dropped every
            # row. The fix is upstream in build_findings_type_params, which
            # now resolves multi-type requests to a single `category=in=(...)`
            # RSQL query at the API layer (no post-filter needed).

            # Ensure raw_data is a DataFrame at this point
            if not isinstance(raw_data, pd.DataFrame):
                raw_data = pd.DataFrame(raw_data) if raw_data else pd.DataFrame()

            if raw_data.empty:
                self.logger.warning(f"No data returned for recipe: {recipe.name}")
                _operational_recipes = {
                    "Executive Summary",
                    "Scan Analysis",
                    "User Activity",
                }
                if self.config.project_filter and recipe.name in _operational_recipes:
                    self.logger.warning(
                        f"'{recipe.name}' is an operational report that only "
                        f"shows activity within the reporting period "
                        f"({self.config.start_date} to {self.config.end_date}). "
                        f"The project '{self.config.project_filter}' may have "
                        f"no activity in this window. Try a longer --period or "
                        f"use an assessment recipe (e.g. Triage Prioritization, "
                        f"CVE Impact) for point-in-time analysis."
                    )

            # --- Enrich with CVE details for Findings by Project ---
            # If NVD pipeline was started during fetch, collect results now.
            # Otherwise fall back to synchronous fetch for non-batched paths
            # (e.g. single project without --current-version-only).
            if recipe.name == "Findings by Project":
                if _nvd_collect is not None:
                    # Always call collect() to send termination sentinel and
                    # avoid leaking the background consumer thread.
                    self._findings_by_project_cve_details = _nvd_collect()
                elif not raw_data.empty and not getattr(self.config, "skip_nvd", False):
                    self._findings_by_project_cve_details = (
                        self._fetch_findings_cve_details(raw_data)
                    )

            # --- Apply flattening if needed ---
            if (
                recipe.name == "Component Vulnerability Analysis"
                and not _cva_pre_flattened
            ):
                # Flatten nested structures if needed (skipped when already
                # flattened per-batch during chunked fetch)
                fields_to_flatten = ["component", "project", "finding"]
                if not raw_data.empty:
                    from fs_report.data_transformer import flatten_records

                    # flatten_records expects list[dict] — convert, flatten, convert back
                    _records: list[dict[str, Any]] = raw_data.to_dict(orient="records")  # type: ignore[assignment]
                    _records = flatten_records(
                        _records, fields_to_flatten=fields_to_flatten
                    )
                    raw_data = pd.DataFrame(_records) if _records else pd.DataFrame()
                    del _records
            # Prune CVA columns for non-batch paths (after post-accumulation flatten)
            if _is_cva and not _cva_pre_flattened and not raw_data.empty:
                raw_data = _prune_cva(raw_data, _cva_extra_keep)
            # --- Inject project_name if needed ---
            # Only do this if the recipe uses project-level grouping
            # (via transform group_by or transform_function that needs it)
            uses_project = any(
                (t.group_by and "project_name" in t.group_by)
                or (t.calc and t.calc.name == "project_name")
                for t in recipe.transform or []
            ) or recipe.name in ("Executive Dashboard",)
            if uses_project:
                # Fetch all projects and build mapping
                from fs_report.models import QueryConfig, QueryParams

                project_query = QueryConfig(
                    endpoint="/public/v0/projects",
                    params=QueryParams(
                        limit=10000, offset=0, archived=False, excluded=False
                    ),
                )
                projects = self.api_client.fetch_all_with_resume(project_query)

                # Build project mapping, handling different ID formats
                project_map = {}
                for p in projects:
                    pid_val = p.get("id") or p.get("projectId")
                    project_name = p.get("name")
                    if pid_val and project_name:
                        # Convert project_id to string to ensure it's hashable
                        project_map[str(pid_val)] = project_name

                # Inject project_name using vectorized DataFrame helper
                if not raw_data.empty:
                    # Copy to avoid mutating cached DataFrame
                    raw_data = raw_data.copy()
                    _inject_project_names_df(raw_data, project_map)

            # --- Inject folder_name into raw records ---
            # Build the project-to-folder mapping (either from folder scope or from projects endpoint)
            if self._project_folder_map:
                # Folder scoping active — use the pre-built mapping
                pf_map = self._project_folder_map
            elif not raw_data.empty:
                # No folder scoping — try to extract folder from projects data
                pf_map = self._build_project_folder_map_from_projects()
            else:
                pf_map = {}

            if pf_map and not raw_data.empty and "folder_name" not in raw_data.columns:
                # Copy to avoid mutating cached DataFrame (if not already copied above)
                if "project_name" not in raw_data.columns:
                    raw_data = raw_data.copy()
                _inject_folder_names_df(raw_data, pf_map)

            # --- Inject dependency path if tree has dependencies ---
            if (
                self._current_dependency_tree is not None
                and self._current_dependency_tree.has_dependencies
                and not raw_data.empty
            ):
                raw_data = self._annotate_dependency_paths(
                    raw_data, self._current_dependency_tree
                )

            # --- SBOM-based group enrichment for Component List ---
            if (
                recipe.name in ("Component List", "License Report")
                and not raw_data.empty
            ):
                raw_data = raw_data.copy()
                # Extract version IDs from nested projectVersion dict before enrichment
                if (
                    "projectVersion" in raw_data.columns
                    and "projectVersion.id" not in raw_data.columns
                ):
                    raw_data["projectVersion.id"] = raw_data["projectVersion"].apply(
                        lambda pv: pv.get("id", "") if isinstance(pv, dict) else ""
                    )
                raw_data = self._enrich_group_from_sbom(
                    raw_data,
                    version_id_col="projectVersion.id",
                    name_col="name",
                    version_col="version",
                    group_col="group",
                )

            # --- SBOM-based group enrichment for Findings by Project ---
            if recipe.name == "Findings by Project" and not raw_data.empty:
                raw_data = raw_data.copy()
                # Extract version ID from nested dict if not already flattened
                if (
                    "projectVersion.id" not in raw_data.columns
                    and "projectVersion" in raw_data.columns
                ):
                    raw_data["projectVersion.id"] = raw_data["projectVersion"].apply(
                        lambda pv: pv.get("id", "") if isinstance(pv, dict) else ""
                    )
                # Extract component name/version from nested dict if not already flattened
                if (
                    "component.name" not in raw_data.columns
                    and "component" in raw_data.columns
                ):
                    raw_data["component.name"] = raw_data["component"].apply(
                        lambda c: c.get("name", "") if isinstance(c, dict) else ""
                    )
                if (
                    "component.version" not in raw_data.columns
                    and "component" in raw_data.columns
                ):
                    raw_data["component.version"] = raw_data["component"].apply(
                        lambda c: c.get("version", "") if isinstance(c, dict) else ""
                    )
                if "projectVersion.id" in raw_data.columns:
                    raw_data = self._enrich_group_from_sbom(
                        raw_data,
                        version_id_col="projectVersion.id",
                        name_col="component.name",
                        version_col="component.version",
                        group_col="component.group",
                    )

            # Handle additional data for multiple charts
            additional_data: dict[str, Any] = {}
            # Add config for pandas transform functions
            additional_data["config"] = self.config
            # Human-readable project name. config.project_filter holds the
            # resolved numeric ID by transform time, so transforms that
            # build display strings (scope labels, subtitles) must prefer
            # this (2026-06-06 visual QA: IDs leaked into five topbars).
            if self.resolved_project_name:
                additional_data["project_name"] = self.resolved_project_name
            if self._deployment_context is not None:
                additional_data["deployment_context"] = self._deployment_context
            # Pass recipe parameters so transforms can access them
            if recipe.parameters:
                additional_data["recipe_parameters"] = recipe.parameters

            # --- Executive Dashboard summary-mode: fetch all per-project data ---
            # When detailed_mode is False, raw_data is empty (findings skipped).
            # We fetch the summary bundle here and merge it into additional_data
            # so _invoke_exec_dashboard_transform can pass it to the summary transform.
            if recipe.name == "Executive Dashboard" and not getattr(
                self.config, "detailed_mode", True
            ):
                # Default serial (1 worker): most platforms rate-limit hard
                # enough that parallelism provides no speedup — the retry/backoff
                # dominates wall time anyway. Customers with generous quotas
                # can raise this via FS_REPORT_EXEC_DASHBOARD_WORKERS.
                _ed_max_workers = int(
                    os.environ.get("FS_REPORT_EXEC_DASHBOARD_WORKERS", "1")
                )
                self.logger.info(
                    "Executive Dashboard summary mode: fetching per-project data "
                    f"(max_workers={_ed_max_workers})"
                )
                _summary_bundle = self._fetch_exec_dashboard_summary(
                    max_workers=_ed_max_workers
                )
                additional_data.update(_summary_bundle)

            # Add project data for Scan Analysis (for new vs existing analysis)
            if (
                recipe.name == "Scan Analysis"
                and hasattr(self, "_scan_analysis_project_data")
                and self._scan_analysis_project_data
            ):
                additional_data["projects"] = self._scan_analysis_project_data

            # Inject NVD client for False Positive Analysis
            if recipe.name == "False Positive Analysis":
                try:
                    from fs_report.nvd_client import NVDClient

                    _fpa_nvd = NVDClient(
                        api_key=getattr(self.config, "nvd_api_key", None),
                        cache_dir=getattr(self.config, "cache_dir", None),
                        cache_ttl=max(getattr(self.config, "cache_ttl", 0), 86400),
                        domain=getattr(self.config, "domain", None),
                    )
                    additional_data["nvd_client"] = _fpa_nvd
                except Exception as e:
                    self.logger.info(
                        f"NVD client unavailable for FPA (version-range checks disabled): {e}"
                    )

            # Inject CVE Impact reachability data, descriptions, and exploits
            if recipe.name == "CVE Impact":
                if (
                    hasattr(self, "_cve_impact_reachability")
                    and self._cve_impact_reachability
                ):
                    additional_data["reachability"] = self._cve_impact_reachability
                # Always inject cve_descriptions when set (even if empty dict)
                # so transforms can distinguish "not called" from "called, all failed"
                if hasattr(self, "_cve_impact_descriptions"):
                    additional_data["cve_descriptions"] = self._cve_impact_descriptions
                if (
                    hasattr(self, "_cve_impact_exploit_details")
                    and self._cve_impact_exploit_details
                ):
                    additional_data["exploit_details"] = (
                        self._cve_impact_exploit_details
                    )
                if (
                    hasattr(self, "_cve_impact_nvd_missing")
                    and self._cve_impact_nvd_missing
                ):
                    additional_data["nvd_missing_cves"] = self._cve_impact_nvd_missing

            # Inject CVE details for Findings by Project
            if recipe.name == "Findings by Project":
                if (
                    hasattr(self, "_findings_by_project_cve_details")
                    and self._findings_by_project_cve_details
                ):
                    additional_data["cve_details"] = (
                        self._findings_by_project_cve_details
                    )
                # Pass domain for FS platform link construction
                additional_data["domain"] = self.config.domain

            # Inject Version Comparison data into additional_data
            if recipe.name in ("Version Comparison", "Security Progress") and hasattr(
                self, "_version_comparison_data"
            ):
                additional_data.update(self._version_comparison_data)

            # Inject API client and domain for recipes that need live API access
            if recipe.name in (
                "Security Progress",
                "Component Impact",
                "Assessment Overview",
                "Customer Brief",
                "Customer Brief Detailed",
                "CRA Compliance",  # added 2026-05-24 per CRA compliance spec step 2
                "CVE Component Evidence",
            ):
                additional_data["api_client"] = self.api_client
                if "domain" not in additional_data:
                    additional_data["domain"] = self.config.domain
                if recipe.name == "CRA Compliance" and self._folder_project_ids:
                    additional_data["folder_project_ids"] = self._folder_project_ids

            # Inject API client and domain for Remediation Package / CRP (SBOM fetching)
            if recipe.name in ("Remediation Package", "Component Remediation Package"):
                additional_data["api_client"] = self.api_client
                additional_data["domain"] = self.config.domain

                # AI master switch: --ai off → disable all AI regardless of recipe YAML
                rp = additional_data.get("recipe_parameters", {})
                if not getattr(self.config, "ai", False):
                    rp["ai_live"] = False
                    rp["ai_prompts"] = False
                    rp["ai_analysis"] = False
                else:
                    # AI enabled — respect recipe defaults, apply depth
                    if getattr(self.config, "ai_prompts", False):
                        rp["ai_prompts"] = True
                    if getattr(self.config, "ai_depth", "summary") == "full":
                        rp["ai_analysis"] = True

                # Fetch component details for enriching agent prompts (RP only)
                if recipe.name == "Remediation Package" and not raw_data.empty:
                    self._fetch_remediation_component_details(raw_data, additional_data)

            # Inject API client and domain for Scan Quality
            if recipe.name == "Scan Quality":
                additional_data["api_client"] = self.api_client
                if "domain" not in additional_data:
                    additional_data["domain"] = self.config.domain
                # Fetch active project list for filtering stale/deleted projects
                if hasattr(recipe, "project_list_query") and recipe.project_list_query:
                    from fs_report.models import QueryParams

                    project_query = QueryConfig(
                        endpoint=recipe.project_list_query.endpoint,
                        params=QueryParams(
                            limit=recipe.project_list_query.params.limit,
                            offset=0,
                            archived=False,
                            excluded=False,
                        ),
                    )
                    try:
                        projects_data = self.api_client.fetch_all_with_resume(
                            project_query
                        )
                        additional_data["projects"] = projects_data
                        self.logger.info(
                            f"Fetched {len(projects_data)} active projects for Scan Quality"
                        )
                    except Exception as exc:
                        self.logger.warning(
                            f"Failed to fetch project list for Scan Quality: {exc}"
                        )

            # Inject component search results (from _search_components optimization)
            if getattr(self, "_component_search_results", None) is not None:
                additional_data["component_search_results"] = (
                    self._component_search_results
                )

            # Fetch scoped components for Executive Dashboard
            if recipe.name == "Executive Dashboard" and not raw_data.empty:
                comp_filters = ["type!=file"]
                if self.config.project_filter:
                    comp_filters.append(f"project=={self.config.project_filter}")
                elif self._folder_project_ids:
                    folder_pids = sorted(self._folder_project_ids)
                    # Batch folder project IDs to avoid 414 URL Too Long
                    batch_size = 15 if len(folder_pids) > 200 else 25
                    all_components: list[dict] = []
                    base_filter = ";".join(comp_filters)
                    self.logger.info(
                        f"Fetching scoped components for Executive Dashboard "
                        f"in {len(range(0, len(folder_pids), batch_size))} batches "
                        f"({len(folder_pids)} projects, batch_size={batch_size})"
                    )
                    try:
                        for i in range(0, len(folder_pids), batch_size):
                            batch_ids = folder_pids[i : i + batch_size]
                            pid_filter = (
                                f"project=in=({','.join(str(p) for p in batch_ids)})"
                            )
                            batch_filter = (
                                f"{base_filter};{pid_filter}"
                                if base_filter
                                else pid_filter
                            )
                            batch_query = QueryConfig(
                                endpoint="/public/v0/components",
                                params=QueryParams(
                                    limit=10000,
                                    filter=batch_filter,
                                ),
                            )
                            batch_data = self.api_client.fetch_all_with_resume(
                                batch_query, show_progress=True
                            )
                            if batch_data:
                                all_components.extend(batch_data)
                        additional_data["components"] = all_components
                        self.logger.info(f"Fetched {len(all_components)} components")
                    except Exception as e:
                        self.logger.warning(
                            f"Could not fetch components for Executive Dashboard: {e}"
                        )
                        additional_data["components"] = []
                    # Skip the single-query path below
                    comp_filters = None  # type: ignore[assignment]

                if comp_filters is not None:
                    # For portfolio-wide (no project, no folder), extract
                    # project IDs from already-fetched findings to batch.
                    _portfolio_pids: list = []
                    if (
                        not self.config.project_filter
                        and not self._folder_project_ids
                        and isinstance(raw_data, pd.DataFrame)
                        and not raw_data.empty
                    ):
                        for col in ("projectId", "project_id"):
                            if col in raw_data.columns:
                                _portfolio_pids = sorted(
                                    str(p)
                                    for p in raw_data[col].dropna().unique()
                                    if p is not None and str(p).strip()
                                )
                                break

                    if _portfolio_pids:
                        # Batch like folder-scoped path
                        batch_size = 15 if len(_portfolio_pids) > 200 else 25
                        all_comps: list[dict] = []
                        base_filter = ";".join(comp_filters)
                        self.logger.info(
                            f"Fetching portfolio components for Executive Dashboard "
                            f"in {len(range(0, len(_portfolio_pids), batch_size))} batches "
                            f"({len(_portfolio_pids)} projects)"
                        )
                        try:
                            for i in range(0, len(_portfolio_pids), batch_size):
                                p_batch = _portfolio_pids[i : i + batch_size]
                                pid_filter = (
                                    f"project=in=({','.join(str(p) for p in p_batch)})"
                                )
                                batch_filter = (
                                    f"{base_filter};{pid_filter}"
                                    if base_filter
                                    else pid_filter
                                )
                                batch_query = QueryConfig(
                                    endpoint="/public/v0/components",
                                    params=QueryParams(
                                        limit=10000,
                                        filter=batch_filter,
                                    ),
                                )
                                batch_data = self.api_client.fetch_all_with_resume(
                                    batch_query, show_progress=True
                                )
                                if batch_data:
                                    all_comps.extend(batch_data)
                            additional_data["components"] = all_comps
                            self.logger.info(f"Fetched {len(all_comps)} components")
                        except Exception as e:
                            self.logger.warning(
                                f"Could not fetch components for Executive Dashboard: {e}"
                            )
                            additional_data["components"] = []
                    else:
                        comp_query = QueryConfig(
                            endpoint="/public/v0/components",
                            params=QueryParams(
                                limit=10000,
                                filter=";".join(comp_filters),
                            ),
                        )
                        self.logger.info(
                            f"Fetching scoped components for Executive Dashboard "
                            f"(filter: {comp_query.params.filter})"
                        )
                        try:
                            additional_data["components"] = (
                                self.api_client.fetch_all_with_resume(
                                    comp_query, show_progress=True
                                )
                            )
                            self.logger.info(
                                f"Fetched {len(additional_data['components'])} components"
                            )
                        except Exception as e:
                            self.logger.warning(
                                f"Could not fetch components for Executive Dashboard: {e}"
                            )
                            additional_data["components"] = []

            if recipe.additional_queries:
                for query_name, query_config in recipe.additional_queries.items():
                    self.logger.debug(f"Fetching additional data for {query_name}")
                    self.logger.debug(f"Query config: {query_config}")

                    # Apply project/version scoping to additional queries
                    # (generic additional_queries lack scope by default)
                    _aq = query_config
                    _aq_scoped = False
                    if (
                        self.config.project_filter
                        and hasattr(_aq, "params")
                        and hasattr(_aq, "endpoint")
                        and "/components" in str(_aq.endpoint)
                    ):
                        from fs_report.models import QueryConfig as _QC
                        from fs_report.models import QueryParams as _QP

                        _aq_filters: list[str] = []
                        if _aq.params and _aq.params.filter:
                            _aq_filters.append(_aq.params.filter)
                        try:
                            _pf_id = int(self.config.project_filter)
                            _aq_filters.append(f"project=={_pf_id}")
                        except ValueError:
                            _aq_filters.append(f"project=={self.config.project_filter}")
                        _aq = _QC(
                            endpoint=_aq.endpoint,
                            params=_QP(
                                limit=_aq.params.limit if _aq.params else 10000,
                                filter=";".join(_aq_filters),
                            ),
                        )
                        _aq_scoped = True
                        self.logger.info(
                            f"Scoped additional query '{query_name}' with project filter: {_aq.params.filter}"
                        )

                    # Use paginated fetch for scoped queries (may exceed single page)
                    if _aq_scoped:
                        additional_raw_data = self.api_client.fetch_all_with_resume(_aq)
                    else:
                        additional_raw_data = self.api_client.fetch_data(_aq)

                    self.logger.debug(
                        f"Additional data for {query_name}: {len(additional_raw_data) if additional_raw_data else 0} records"
                    )

                    # Apply flattening to additional data if needed
                    if (
                        recipe.name == "Component Vulnerability Analysis"
                        and additional_raw_data
                    ):
                        from fs_report.data_transformer import flatten_records

                        self.logger.info(f"Applying flattening to {query_name} data")
                        additional_raw_data = flatten_records(
                            additional_raw_data,
                            fields_to_flatten=["component", "project", "finding"],
                        )

                    # Inject project names if needed
                    if additional_raw_data and uses_project:
                        for finding in additional_raw_data:
                            project_field = finding.get("project") or finding.get(
                                "projectId"
                            )
                            if project_field:
                                if isinstance(project_field, dict):
                                    project_name = project_field.get("name")
                                    if project_name:
                                        finding["project_name"] = project_name
                                    else:
                                        pid_str = str(
                                            project_field.get("id", project_field)
                                        )
                                        finding["project_name"] = project_map.get(
                                            pid_str, pid_str
                                        )
                                else:
                                    pid_str = str(project_field)
                                    finding["project_name"] = project_map.get(
                                        pid_str, pid_str
                                    )

                    # Apply specific transforms if available
                    if query_name == "open_issues" and recipe.open_issues_transform:
                        additional_data[query_name] = self.transformer.transform(
                            additional_raw_data,
                            recipe.open_issues_transform,
                            additional_data={"config": self.config},
                        )
                    elif (
                        query_name == "scan_frequency"
                        and recipe.scan_frequency_transform
                    ):
                        additional_data[query_name] = self.transformer.transform(
                            additional_raw_data,
                            recipe.scan_frequency_transform,
                            additional_data={"config": self.config},
                        )
                    else:
                        additional_data[query_name] = additional_raw_data

            # Add scan frequency data from main findings if transform is defined
            if recipe.scan_frequency_transform:
                self.logger.debug("Applying scan frequency transform to main data")
                additional_data["scan_frequency"] = self.transformer.transform(
                    raw_data,
                    recipe.scan_frequency_transform,
                    additional_data={"config": self.config},
                )

            # Add open issues data from main findings if transform is defined
            if recipe.open_issues_transform:
                self.logger.debug(
                    f"Applying open issues transform to {len(raw_data)} findings"
                )
                additional_data["open_issues"] = self.transformer.transform(
                    raw_data,
                    recipe.open_issues_transform,
                    additional_data={"config": self.config},
                )

            # Exploit Signals gauge (C1) — open-snapshot KEV/real-exploit counts.
            if recipe.exploit_signals_transform:
                self.logger.debug("Applying exploit signals transform to main data")
                additional_data["exploit_signals"] = self.transformer.transform(
                    raw_data,
                    recipe.exploit_signals_transform,
                    additional_data={"config": self.config},
                )

            # Exploits Over Time line (C2) — real-exploit detection volume.
            if recipe.exploits_over_time_transform:
                self.logger.debug("Applying exploits over time transform to main data")
                additional_data["exploits_over_time"] = self.transformer.transform(
                    raw_data,
                    recipe.exploits_over_time_transform,
                    additional_data={"config": self.config},
                )

            # Apply transformations (pass additional_data for join support)
            self.logger.debug(f"Applying transformations for recipe: {recipe.name}")
            self.logger.debug(f"Raw data count: {len(raw_data)}")
            if isinstance(raw_data, dict):  # type: ignore[unreachable]
                self.logger.debug(f"Raw data keys: {list(raw_data.keys())}")  # type: ignore[unreachable]
            else:
                self.logger.debug(
                    f"Raw data is a {type(raw_data).__name__}, not logging keys."
                )
            self.logger.debug(f"Additional data keys: {list(additional_data.keys())}")

            # Handle transform_function if present
            transforms_to_apply = recipe.transform
            if hasattr(recipe, "transform_function") and recipe.transform_function:
                from fs_report.models import Transform

                # Create a Transform object with the transform_function
                custom_transform = Transform(
                    transform_function=recipe.transform_function
                )
                transforms_to_apply = [custom_transform]
                self.logger.debug(
                    f"Using custom transform function: {recipe.transform_function}"
                )

            self.logger.debug(
                f"Transform count: {len(transforms_to_apply) if transforms_to_apply else 0}"
            )
            _log_memory(self.logger, f"Before transform ({recipe.name})")
            raw_data_count = len(raw_data) if hasattr(raw_data, "__len__") else 0

            # --- Executive Dashboard dispatch ---
            # In summary mode use _invoke_exec_dashboard_transform (bypasses
            # the data_transformer entirely — result dict goes straight into
            # additional_data so the template receives all panel keys).
            transformed_data: Any  # declared here; assigned in both branches below
            if recipe.name == "Executive Dashboard" and not getattr(
                self.config, "detailed_mode", True
            ):
                _ed_result = self._invoke_exec_dashboard_transform(
                    raw_data, additional_data=additional_data
                )
                additional_data.update(_ed_result)
                additional_data["transform_result"] = _ed_result
                transformed_data = pd.DataFrame()
            else:
                transformed_data = self.transformer.transform(
                    raw_data, transforms_to_apply, additional_data=additional_data
                )

            # Handle custom transform functions that return dictionaries with additional data
            if hasattr(recipe, "transform_function") and recipe.transform_function:
                # Check if transform returned a dictionary result in additional_data
                transform_result = additional_data.get("transform_result")
                if transform_result and isinstance(transform_result, dict):
                    self.logger.debug(
                        f"Processing transform result dictionary with keys: {list(transform_result.keys())}"
                    )
                    # Store all keys in additional_data
                    for key, value in transform_result.items():
                        additional_data[key] = value
                    self.logger.debug(
                        "Transform function returned dict with keys, merged into additional_data"
                    )

                    # Write VEX recommendations JSON
                    if recipe.name in (
                        "Triage Prioritization",
                        "Configuration Analysis Triage",
                        "False Positive Analysis",
                    ):
                        vex_recs = transform_result.get("vex_recommendations", [])
                        if not vex_recs:
                            self.logger.info(
                                "No VEX recommendations generated (no eligible findings)"
                            )
                        if vex_recs:
                            import json

                            # Use the same sanitized directory name as the report renderer
                            sanitized_name = (
                                recipe.name.replace("/", "_")
                                .replace("\\", "_")
                                .replace(":", "_")
                                .replace("*", "_")
                                .replace("?", "_")
                                .replace('"', "_")
                                .replace("<", "_")
                                .replace(">", "_")
                                .replace("|", "_")
                                .strip(" .")
                            )
                            vex_dir = Path(self.config.output_dir) / sanitized_name
                            vex_dir.mkdir(parents=True, exist_ok=True)
                            vex_path = vex_dir / "vex_recommendations.json"
                            with open(vex_path, "w") as f:
                                json.dump(vex_recs, f, indent=2, default=str)
                            self.logger.info(
                                f"Wrote {len(vex_recs)} VEX recommendations to {vex_path}"
                            )
                            # Track for output listing
                            additional_data.setdefault(
                                "_extra_generated_files", []
                            ).append(str(vex_path))

            # When a transform returns a dict with a "main" key, extract the
            # main DataFrame as the primary report data.  The full dict is
            # already available via additional_data["transform_result"].
            if isinstance(transformed_data, dict) and "main" in transformed_data:
                self.logger.debug(
                    "Extracting 'main' DataFrame from transform result dict"
                )
                transformed_data = transformed_data["main"]

            # Promote transform results into additional_data for recipes
            # with custom HTML templates so they receive charts, summary,
            # dossiers, etc. as top-level template variables.
            if recipe.template:
                tr = additional_data.get("transform_result", {})
                if isinstance(tr, dict):
                    for k, v in tr.items():
                        if k != "main":
                            additional_data[k] = v

            # Apply portfolio transforms if available (for Component Vulnerability Analysis)
            portfolio_data = None
            if hasattr(recipe, "portfolio_transform") and recipe.portfolio_transform:
                self.logger.debug("Applying portfolio transforms")
                portfolio_data = self.transformer.transform(
                    raw_data,
                    recipe.portfolio_transform,
                    additional_data=additional_data,
                )
            # For CVA with transform_function, the result IS the portfolio data
            elif recipe.name == "Component Vulnerability Analysis" and hasattr(
                recipe, "transform_function"
            ):
                self.logger.debug("Setting CVA transform result as portfolio data")
                portfolio_data = transformed_data
                transformed_data = (
                    pd.DataFrame()
                )  # Empty for main data since we only need portfolio data

            # Release the Executive Summary/Dashboard _findings_cache entries
            # early — pruned DataFrames are small enough that cross-report reuse
            # is not worthwhile and we want to free memory before rendering.
            if _es_cache_key is not None:
                self._findings_cache.pop(_es_cache_key, None)
            if _ed_cache_key is not None:
                self._findings_cache.pop(_ed_cache_key, None)

            # Free raw_data now that all transforms have consumed it.
            # (For folder-scoped paths, _findings_cache may still hold a reference
            # for cross-report reuse — that's fine; del here just drops this local ref.)
            del raw_data
            gc.collect()
            _log_memory(self.logger, f"After transforms + gc ({recipe.name})")

            # Create report data
            report_data = ReportData(
                recipe_name=recipe.name,
                data=transformed_data,
                metadata={
                    "raw_count": raw_data_count,
                    "transformed_count": (
                        len(transformed_data)
                        if hasattr(transformed_data, "__len__")
                        else 1
                    ),
                    "portfolio_data": portfolio_data,
                    "recipe": recipe.model_dump(),
                    "cache_stats": self.cache.get_stats(),
                    "additional_data": additional_data,
                    "start_date": self.config.start_date,
                    "end_date": self.config.end_date,
                    "project_filter": self.config.project_filter,
                    "project_name": self.resolved_project_name,
                    "folder_name": self._folder_name,
                    "folder_path": self._folder_path,
                    "folder_filter": self.config.folder_filter,
                    "domain": self.config.domain,
                    "logo_path": self._resolve_logo_path(),
                },
            )

            return report_data

        except Exception as e:
            self.logger.error(f"Error processing recipe {recipe.name}: {e}")
            raise

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()

    def _resolve_logo_path(self) -> str | None:
        """Resolve the configured logo to a base64 data URI.

        Returns a ``data:image/...;base64,...`` string or *None* if no logo
        is configured or the file cannot be found.
        """
        import base64
        import mimetypes

        logo = getattr(self.config, "logo", None)
        if not logo:
            return None

        path = Path(logo)
        if not path.is_absolute():
            path = Path.home() / ".fs-report" / "logos" / logo

        if not path.is_file():
            self.logger.warning(f"Logo file not found: {path}")
            return None

        suffix = path.suffix.lower()
        allowed = {".png", ".jpg", ".jpeg", ".svg", ".webp"}
        if suffix not in allowed:
            self.logger.warning(
                f"Unsupported logo format '{suffix}'. Use: {', '.join(sorted(allowed))}"
            )
            return None

        size = path.stat().st_size
        if size > 500_000:
            self.logger.warning(
                f"Logo file is {size / 1024:.0f}KB (>500KB recommended maximum)"
            )

        mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if suffix == ".svg":
            mime = "image/svg+xml"

        data = path.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:{mime};base64,{b64}"

    @staticmethod
    def _filter_findings_by_version_ids(
        findings: list[dict],
        version_ids: set,
    ) -> list[dict]:
        """Keep only findings whose projectVersion.id is in *version_ids*.

        Handles both nested dict keys (live API) and flat dotted keys
        (SQLite cache).  Findings with no extractable version ID are kept
        as a safety net.
        """
        # Normalize IDs to strings so int/UUID comparisons work uniformly
        str_version_ids = {str(v) for v in version_ids}
        result: list[dict] = []
        for f in findings:
            pv_obj = f.get("projectVersion")
            if isinstance(pv_obj, dict):
                ver_id = pv_obj.get("id")
            else:
                ver_id = f.get("projectVersion.id") or f.get("project_version_id")
            ver_str = str(ver_id) if ver_id is not None else None
            if ver_str is None or ver_str in str_version_ids:
                result.append(f)
        return result

    def _fetch_remediation_component_details(
        self,
        raw_data: "pd.DataFrame",
        additional_data: dict[str, Any],
    ) -> None:
        """Fetch component details from /public/v0/components for Remediation Package.

        Enriches agent prompts with component metadata (type, license, supplier, etc.).
        Results are stored in ``additional_data["component_details"]``.
        """
        from fs_report.models import QueryConfig, QueryParams

        # Determine project scope
        comp_filters = ["type!=file"]
        if self.config.project_filter:
            try:
                _proj_id = int(self.config.project_filter)
                comp_filters.append(f"project=={_proj_id}")
            except ValueError:
                comp_filters.append(f"project=={self.config.project_filter}")
        elif self._folder_project_ids:
            folder_pids = sorted(self._folder_project_ids)
            # Batch folder project IDs to avoid 414 URL Too Long
            batch_size = 15 if len(folder_pids) > 200 else 25
            all_components: list[dict] = []
            base_filter = ";".join(comp_filters)
            self.logger.info(
                f"Fetching component details for Remediation Package "
                f"in {len(range(0, len(folder_pids), batch_size))} batches "
                f"({len(folder_pids)} projects, batch_size={batch_size})"
            )
            try:
                for i in range(0, len(folder_pids), batch_size):
                    batch_ids = folder_pids[i : i + batch_size]
                    pid_filter = f"project=in=({','.join(str(p) for p in batch_ids)})"
                    batch_filter = (
                        f"{base_filter};{pid_filter}" if base_filter else pid_filter
                    )
                    batch_query = QueryConfig(
                        endpoint="/public/v0/components",
                        params=QueryParams(
                            limit=10000,
                            filter=batch_filter,
                        ),
                    )
                    batch_data = self.api_client.fetch_all_with_resume(
                        batch_query, show_progress=True
                    )
                    if batch_data:
                        all_components.extend(batch_data)
                additional_data["component_details"] = all_components
                self.logger.info(f"Fetched {len(all_components)} component details")
            except Exception as e:
                self.logger.warning(
                    f"Could not fetch component details for Remediation Package: {e}"
                )
                additional_data["component_details"] = []
            return

        comp_query = QueryConfig(
            endpoint="/public/v0/components",
            params=QueryParams(
                limit=10000,
                filter=";".join(comp_filters),
            ),
        )
        self.logger.info(
            f"Fetching component details for Remediation Package "
            f"(filter: {comp_query.params.filter})"
        )
        try:
            additional_data["component_details"] = (
                self.api_client.fetch_all_with_resume(comp_query, show_progress=True)
            )
            self.logger.info(
                f"Fetched {len(additional_data['component_details'])} component details"
            )
        except Exception as e:
            self.logger.warning(
                f"Could not fetch component details for Remediation Package: {e}"
            )
            additional_data["component_details"] = []

    def _fetch_cve_reachability(
        self, cve_records: "list[dict] | pd.DataFrame"
    ) -> tuple[dict[str, list[dict]], dict[str, str], dict[str, list[dict]], list[str]]:
        """Fetch per-finding reachability from /findings for dossier mode.

        For each CVE in the records, queries the findings endpoint with
        ``findingId==<cveId>`` to retrieve reachability scores per finding.

        Also fetches CVE descriptions via NVDClient batch lookup and
        exploit details from ``/findings/{findingId}/exploits`` for
        each CVE (using any finding's numeric ``id``).

        Returns:
            Tuple of:
            - reachability_map: cveId -> list of finding dicts
            - descriptions_map: cveId -> NVD description string
            - exploit_details_map: cveId -> list of exploit detail dicts
            - nvd_missing_cves: list of CVE IDs that NVD could not resolve
        """
        from fs_report.models import QueryConfig, QueryParams
        from fs_report.nvd_client import NVD_ATTRIBUTION, NVDClient

        reachability_map: dict[str, list[dict]] = {}
        descriptions_map: dict[str, str] = {}
        exploit_details_map: dict[str, list[dict]] = {}

        # Collect unique CVE IDs from the data
        cve_ids_ordered: list[str] = []
        if isinstance(cve_records, pd.DataFrame):
            # Try cveId first, then cve_id
            if "cveId" in cve_records.columns:
                cve_ids_ordered = cve_records["cveId"].dropna().unique().tolist()
            elif "cve_id" in cve_records.columns:
                cve_ids_ordered = cve_records["cve_id"].dropna().unique().tolist()
        else:
            cve_ids_seen: set[str] = set()
            for rec in cve_records:
                cve_id = rec.get("cveId") or rec.get("cve_id")
                if cve_id and cve_id not in cve_ids_seen:
                    cve_ids_seen.add(cve_id)
                    cve_ids_ordered.append(cve_id)

        if not cve_ids_ordered:
            return reachability_map, descriptions_map, exploit_details_map, []

        self.logger.info(
            f"Enriching {len(cve_ids_ordered)} CVEs with reachability data from /findings"
        )

        # Batch-fetch NVD descriptions upfront (unless --no-nvd)
        nvd_missing_cves: list[str] = []
        if not getattr(self.config, "skip_nvd", False):
            self._check_cancel()
            nvd = NVDClient(
                api_key=getattr(self.config, "nvd_api_key", None),
                cache_dir=getattr(self.config, "cache_dir", None),
                cache_ttl=max(getattr(self.config, "cache_ttl", 0) or 0, 86400),
                cancel_event=self._cancel_event,
                domain=getattr(self.config, "domain", None),
            )
            self.logger.info(NVD_ATTRIBUTION)
            nvd_results = nvd.get_batch(cve_ids_ordered, progress=True)
            nvd_missing_cves = list(nvd.last_batch_missing)
            if nvd_missing_cves:
                self.logger.info(
                    f"NVD: {len(nvd_results)}/{len(cve_ids_ordered)} CVEs resolved"
                )
            for nvd_cve_id, nvd_rec in nvd_results.items():
                if nvd_rec.description:
                    descriptions_map[nvd_cve_id] = nvd_rec.description
        else:
            self.logger.info("Skipping NVD enrichment for CVE Impact (--no-nvd)")
            nvd_missing_cves = list(cve_ids_ordered)

        # Pre-fetch authoritative latest version IDs (from
        # defaultBranch.latestVersion.id) so we can filter per-CVE
        # findings to only the current version of each project.
        latest_version_ids: set | None = None
        if self.config.current_version_only:
            try:
                auth_ids = self._get_latest_version_ids()
                latest_version_ids = {str(v) for v in auth_ids if v is not None}
            except Exception:
                self.logger.warning(
                    "Failed to resolve authoritative version IDs",
                    exc_info=True,
                )
            if latest_version_ids:
                self.logger.info(
                    f"Version filter: {len(latest_version_ids)} authoritative "
                    f"latest version IDs"
                )
            else:
                self.logger.warning(
                    "No authoritative version IDs resolved; "
                    "version filter will be skipped"
                )
                latest_version_ids = None

        # Fetch reachability and exploit details per CVE
        for cve_id in sorted(cve_ids_ordered):
            self._check_cancel()
            finding_query = QueryConfig(
                endpoint="/public/v0/findings",
                params=QueryParams(
                    limit=10000,
                    filter=f"findingId=={cve_id}",
                ),
            )
            try:
                findings = self.api_client.fetch_all_with_resume(finding_query)
                if latest_version_ids is not None and findings:
                    before = len(findings)
                    filtered = self._filter_findings_by_version_ids(
                        findings, latest_version_ids
                    )
                    if filtered:
                        findings = filtered
                        self.logger.debug(
                            f"  Version post-filter: {before} -> "
                            f"{len(findings)} findings for {cve_id}"
                        )
                    else:
                        # Don't discard all findings — keep unfiltered so
                        # the report shows reachability data rather than
                        # UNKNOWN for every CVE.
                        self.logger.debug(
                            f"  Version filter would remove all {before} "
                            f"findings for {cve_id}; keeping unfiltered"
                        )
                reachability_map[cve_id] = findings
                self.logger.debug(
                    f"  {cve_id}: {len(findings)} findings with reachability"
                )

                # Fetch exploit details using the finding's numeric id
                if findings:
                    f0 = findings[0]
                    finding_numeric_id = f0.get("id")
                    pv_obj = f0.get("projectVersion")
                    pv_id = (
                        pv_obj.get("id")
                        if isinstance(pv_obj, dict)
                        else f0.get("project_version_id")
                    )
                    if finding_numeric_id and pv_id:
                        fid = str(finding_numeric_id)
                        pvid = str(pv_id)
                        exploits = self._fetch_cve_exploits(pvid, fid, cve_id)
                        if exploits:
                            exploit_details_map[cve_id] = exploits
            except Exception as exc:
                self.logger.warning(f"Failed to fetch reachability for {cve_id}: {exc}")
                reachability_map[cve_id] = []

        return reachability_map, descriptions_map, exploit_details_map, nvd_missing_cves

    def _start_nvd_pipeline(
        self,
    ) -> "tuple[Callable[[list[dict]], None], Callable[[], dict[str, dict[str, str]]]]":
        """Start a background NVD lookup pipeline.

        Returns ``(on_records, collect)`` where:

        * ``on_records(records)`` — callback to invoke with each batch of raw
          finding dicts as they become available.  Extracts ``findingId``
          values and queues them for the background NVD thread.
        * ``collect()`` — blocks until the pipeline is finished and returns
          the CVE details dict (same shape as ``_fetch_findings_cve_details``).

        The background thread processes CVE IDs incrementally: as soon as
        ``on_records`` is called (e.g. with cached findings), the thread
        starts NVD/OSV lookups.  Subsequent calls add new CVE IDs.  This
        overlaps NVD I/O with the remaining FS API fetch and its cooldowns.
        """
        import queue as _queue
        from concurrent.futures import ThreadPoolExecutor

        from fs_report.nvd_client import NVD_ATTRIBUTION, NVDClient

        cve_queue: _queue.Queue[set[str] | None] = _queue.Queue()

        def _consumer() -> dict[str, dict[str, str]]:
            nvd = NVDClient(
                api_key=getattr(self.config, "nvd_api_key", None),
                cache_dir=getattr(self.config, "cache_dir", None),
                cache_ttl=max(getattr(self.config, "cache_ttl", 0) or 0, 86400),
                cancel_event=self._cancel_event,
                domain=getattr(self.config, "domain", None),
            )
            self.logger.info(NVD_ATTRIBUTION)

            seen: set[str] = set()
            results: dict[str, dict[str, str]] = {}
            batch_num = 0

            while True:
                try:
                    batch = cve_queue.get(timeout=1.0)
                except _queue.Empty:
                    continue
                if batch is None:  # sentinel
                    break
                new_ids = batch - seen
                seen.update(batch)
                if new_ids:
                    batch_num += 1
                    self.logger.info(
                        f"NVD background: looking up {len(new_ids)} new CVEs "
                        f"({len(seen)} total so far)"
                    )
                    nvd_results = nvd.get_batch(list(new_ids), progress=True)
                    results.update(
                        {
                            cve_id: {
                                "description": rec.description,
                                "cvss_v2_vector": rec.cvss_v2_vector,
                                "cvss_v3_vector": rec.cvss_v3_vector,
                            }
                            for cve_id, rec in nvd_results.items()
                        }
                    )
                    self.logger.info(
                        f"NVD background: batch {batch_num} done, "
                        f"{len(results)}/{len(seen)} CVEs resolved so far"
                    )

            self.logger.info(
                f"NVD background: completed — {len(results)}/{len(seen)} CVEs"
            )
            return results

        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="nvd")
        future = executor.submit(_consumer)
        executor.shutdown(wait=False)
        self.logger.info("NVD/OSV pipeline started in background thread")

        def on_records(records: list[dict]) -> None:
            ids: set[str] = {r["findingId"] for r in records if r.get("findingId")}
            if ids:
                cve_queue.put(ids)

        def collect() -> dict[str, dict[str, str]]:
            cve_queue.put(None)  # sentinel
            return future.result()

        return on_records, collect

    def _fetch_findings_cve_details(
        self, raw_data: "list[dict] | pd.DataFrame"
    ) -> dict[str, dict[str, str]]:
        """Fetch CVE details (description, CVSS vectors) for Findings by Project.

        Uses NVDClient with SQLite caching, tqdm progress, and NVD API rate
        limiting instead of per-finding FS API calls.

        Returns a mapping of CVE ID -> {"description": str, "cvss_v2_vector": str, "cvss_v3_vector": str}.
        """
        from fs_report.nvd_client import NVD_ATTRIBUTION, NVDClient

        # Collect unique CVE IDs from findings
        cve_ids: list[str] = []
        if isinstance(raw_data, pd.DataFrame):
            cve_ids = (
                raw_data["findingId"].dropna().unique().tolist()
                if "findingId" in raw_data.columns
                else []
            )
        else:
            seen: set[str] = set()
            for finding in raw_data:
                cve_id = finding.get("findingId")
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    cve_ids.append(cve_id)

        if not cve_ids:
            return {}

        self.logger.info(
            f"Fetching CVE details for {len(cve_ids)} unique CVEs (Findings by Project)"
        )

        self._check_cancel()

        nvd = NVDClient(
            api_key=getattr(self.config, "nvd_api_key", None),
            cache_dir=getattr(self.config, "cache_dir", None),
            cache_ttl=max(getattr(self.config, "cache_ttl", 0) or 0, 86400),
            cancel_event=self._cancel_event,
            domain=getattr(self.config, "domain", None),
        )
        self.logger.info(NVD_ATTRIBUTION)

        nvd_results = nvd.get_batch(cve_ids, progress=True)

        results: dict[str, dict[str, str]] = {
            cve_id: {
                "description": rec.description,
                "cvss_v2_vector": rec.cvss_v2_vector,
                "cvss_v3_vector": rec.cvss_v3_vector,
            }
            for cve_id, rec in nvd_results.items()
        }

        self.logger.info(f"Fetched CVE details for {len(results)}/{len(cve_ids)} CVEs")
        return results

    def _fetch_cve_exploits(
        self, project_version_id: str, finding_numeric_id: str, cve_id: str
    ) -> list[dict]:
        """Fetch exploit details from /findings/{pvId}/{findingId}/exploits.

        The response is a nested dict keyed by CVE ID::

            {
              "CVE-XXXX": {
                "request": {
                  "exploits": [
                    {
                      "url": "https://...",
                      "name": "exploit description",
                      "refsource": "github-exploits",
                      "exploit_maturity": "poc",
                      "exploit_type": "denial-of-service",
                      ...
                    }
                  ],
                  "counts": {"exploits": 5, ...},
                  "epss": {...}
                }
              }
            }

        Returns a list of exploit detail dicts, or empty list on failure.
        """
        url = (
            f"{self.api_client.base_url}/public/v0/findings"
            f"/{project_version_id}/{finding_numeric_id}/exploits"
        )
        result: list[dict] = []
        try:
            resp = self.api_client.client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict):
                # Navigate: data[cveId].request.exploits
                cve_entry = data.get(cve_id, {})
                if isinstance(cve_entry, dict):
                    request_obj = cve_entry.get("request", {})
                    if isinstance(request_obj, dict):
                        exploits_list = request_obj.get("exploits", [])
                        if isinstance(exploits_list, list):
                            result = exploits_list
            elif isinstance(data, list):
                result = data
            if result:
                self.logger.debug(f"  {cve_id}: fetched {len(result)} exploit details")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                self.logger.debug(f"No exploit details for {cve_id} (404)")
            else:
                self.logger.warning(
                    f"Could not fetch exploit details for {cve_id} "
                    f"(pv={project_version_id}, finding={finding_numeric_id}): {exc}"
                )
        except Exception as exc:
            self.logger.warning(
                f"Could not fetch exploit details for {cve_id} "
                f"(pv={project_version_id}, finding={finding_numeric_id}): {exc}"
            )
        # Polite delay between API calls
        self._cancellable_sleep(0.3)
        return result

    def _fetch_scans_with_early_termination(
        self, query_config: "QueryConfig"
    ) -> list[dict]:
        """
        Fetch scans sorted by -created with early termination.
        Stops fetching when we've passed the start date (no more relevant scans).

        The scans endpoint does NOT support RSQL date filtering, so we must
        paginate manually and stop when scans are older than our window.

        Results are cached in-memory (same run) and SQLite (cross-run).

        Note: We extend the cutoff by 7 days to capture scans that were CREATED
        before the period but COMPLETED within it (e.g., long-running scans).
        The transform will do final filtering to include scans completed in range.
        """
        from datetime import datetime, timedelta

        from tqdm import tqdm

        # --- In-memory cache (shared across reports in the same run) ---
        _cache_parts = f"scans|{query_config.params.filter or ''}|{self.config.start_date}|{self.config.end_date}"
        _cache_key = hashlib.sha256(_cache_parts.encode()).hexdigest()[:16]
        if _cache_key in self._findings_cache:
            cached: list[dict[Any, Any]] = self._findings_cache[_cache_key]
            self.logger.info(f"Using in-memory cached scans ({len(cached)} records)")
            return cached

        # --- SQLite cache (cross-run) ---
        sqlite_params = {
            "filter": query_config.params.filter or "",
            "sort": "created:desc",
            "start_date": self.config.start_date,
            "end_date": self.config.end_date,
        }
        if (
            self.api_client.sqlite_cache
            and self.api_client.cache_ttl > 0
            and not self.api_client.cache_refresh
            and self.api_client.sqlite_cache.is_cache_valid(
                "/public/v0/scans", sqlite_params, self.api_client.cache_ttl
            )
        ):
            sqlite_cached = self.api_client.sqlite_cache.get_cached_data(
                "/public/v0/scans", sqlite_params
            )
            if sqlite_cached is not None:
                self.logger.info(
                    f"Using SQLite cached scans ({len(sqlite_cached)} records)"
                )
                self._findings_cache[_cache_key] = sqlite_cached
                return sqlite_cached

        # --- Fetch from API with early termination ---
        # Parse start date for comparison
        # Extend by 7 days to capture scans that completed in range but started earlier
        actual_start = datetime.fromisoformat(f"{self.config.start_date}T00:00:00")
        start_date = actual_start - timedelta(days=7)

        # Ensure we're sorting by created:desc (newest first)
        from fs_report.models import QueryConfig, QueryParams

        sorted_query = QueryConfig(
            endpoint=query_config.endpoint,
            params=QueryParams(
                filter=query_config.params.filter,
                sort="created:desc",  # Force sort by newest first
                limit=min(
                    query_config.params.limit or 100, 100
                ),  # scans API max is 100
                offset=0,
            ),
        )

        all_scans: list[dict[str, Any]] = []
        offset = 0
        limit = sorted_query.params.limit or 100
        done = False
        consecutive_old_pages = 0
        old_page_threshold = (
            3  # Stop after N consecutive pages where majority of scans are old
        )

        self.logger.info(
            f"Fetching scans with early termination (extended to {start_date.date()} to capture completions in {self.config.start_date} - {self.config.end_date})"
        )

        import random

        max_retries = 8
        max_pages = 500  # Hard upper bound to prevent infinite loops
        pages_fetched = 0

        with tqdm(desc="Fetching scans", unit=" records", leave=False) as pbar:
            while not done and pages_fetched < max_pages:
                # Update query with current offset
                page_query = QueryConfig(
                    endpoint=sorted_query.endpoint,
                    params=QueryParams(
                        filter=sorted_query.params.filter,
                        sort=sorted_query.params.sort,
                        limit=limit,
                        offset=offset,
                    ),
                )

                # Fetch this page with retry logic
                page_data = None
                for retry_count in range(max_retries):
                    try:
                        page_data = self.api_client.fetch_data(page_query)
                        break
                    except Exception as e:
                        wait = (2 ** min(retry_count, 6)) + random.uniform(0, 1)
                        self.logger.debug(
                            f"Transient error at offset {offset}: {e}. Retrying in {wait:.1f}s..."
                        )
                        self._cancellable_sleep(wait)
                        if retry_count >= max_retries - 1:
                            if all_scans:
                                self.logger.warning(
                                    f"Max retries exceeded at offset {offset}. "
                                    f"Returning {len(all_scans)} partial results."
                                )
                                done = True
                                break
                            self.logger.error(
                                f"Max retries exceeded at offset {offset}. Aborting."
                            )
                            raise

                pages_fetched += 1
                if not page_data:
                    break

                # Check each scan and count old vs new
                old_scans_in_page = 0
                new_scans_in_page = 0

                for scan in page_data:
                    scan_created = scan.get("created")
                    scan_in_range = True  # Assume in range unless proven otherwise

                    if scan_created:
                        try:
                            # Parse the scan created timestamp
                            if isinstance(scan_created, str):
                                # Handle various timestamp formats
                                scan_dt = datetime.fromisoformat(
                                    scan_created.replace("Z", "+00:00").split("+")[0]
                                )
                            else:
                                scan_dt = scan_created

                            # Check if scan is before our start date
                            if scan_dt < start_date:
                                scan_in_range = False
                                old_scans_in_page += 1
                            else:
                                new_scans_in_page += 1
                        except (ValueError, TypeError):
                            new_scans_in_page += (
                                1  # Include scans with unparseable dates
                            )
                    else:
                        new_scans_in_page += 1  # Include scans without dates

                    # Only include scans that are in our date range
                    if scan_in_range:
                        all_scans.append(scan)

                pbar.update(len(page_data))
                pbar.set_postfix({"total": len(all_scans), "old": old_scans_in_page})

                # Check if majority of this page is old scans
                total_in_page = old_scans_in_page + new_scans_in_page
                if total_in_page > 0 and old_scans_in_page > (total_in_page / 2):
                    consecutive_old_pages += 1
                    self.logger.debug(
                        f"Page at offset {offset}: {old_scans_in_page}/{total_in_page} old, consecutive_old={consecutive_old_pages}"
                    )
                    if consecutive_old_pages >= old_page_threshold:
                        self.logger.debug(
                            f"Stopping: {old_page_threshold} consecutive majority-old pages reached"
                        )
                        done = True
                else:
                    # Reset counter if we get a page with mostly new scans
                    if consecutive_old_pages > 0:
                        self.logger.debug(
                            f"Page at offset {offset}: {new_scans_in_page}/{total_in_page} new, resetting consecutive counter"
                        )
                    consecutive_old_pages = 0

                # Only stop on truly empty pages - some APIs return partial pages mid-stream
                if len(page_data) == 0:
                    self.logger.debug(f"Stopping: Empty page at offset {offset}")
                    break
                elif len(page_data) < limit:
                    self.logger.debug(
                        f"Partial page at offset {offset}: {len(page_data)} records (continuing)"
                    )

                offset += limit

        if pages_fetched >= max_pages:
            self.logger.warning(
                f"Scan fetch hit max_pages limit ({max_pages}). "
                f"Results may be incomplete."
            )
        self.logger.info(
            f"Fetched {len(all_scans)} scans (early termination saved fetching older scans)"
        )

        # --- Store in caches ---
        self._findings_cache[_cache_key] = all_scans

        # Store in SQLite for cross-run reuse
        if self.api_client.sqlite_cache and self.api_client.cache_ttl > 0:
            qh = self.api_client.sqlite_cache.start_fetch(
                "/public/v0/scans", sqlite_params, self.api_client.cache_ttl
            )
            self.api_client.sqlite_cache.store_records(
                qh, "/public/v0/scans", all_scans
            )
            self.api_client.sqlite_cache.complete_fetch(qh)

        return all_scans

    def _apply_scan_filters(self, query_config: Any) -> Any:
        """Apply project, version, and folder filtering to scan queries."""
        from fs_report.models import QueryConfig, QueryParams

        # Start with the original filter
        original_filter = query_config.params.filter or ""

        # Build additional filters for project and version
        additional_filters = []

        if self.config.project_filter:
            try:
                project_id = int(self.config.project_filter)
                additional_filters.append(f"project=={project_id}")
                self.logger.debug(
                    f"Added project ID filter to scans: project=={project_id}"
                )
            except ValueError:
                # Not an integer, treat as project name
                additional_filters.append(f"project=={self.config.project_filter}")
                self.logger.debug(
                    f"Added project name filter to scans: project=={self.config.project_filter}"
                )
        elif self._folder_project_ids:
            # Folder scoping — add project=in=() filter for scans
            folder_pids = sorted(self._folder_project_ids)
            additional_filters.append(
                f"project=in=({','.join(str(pid) for pid in folder_pids)})"
            )
            self.logger.debug(
                f"Added folder project filter to scans: {len(folder_pids)} projects"
            )

        if self.config.version_filter:
            additional_filters.append(f"projectVersion=={self.config.version_filter}")
            self.logger.debug(
                f"Added version filter to scans: projectVersion=={self.config.version_filter}"
            )

        if getattr(self.config, "scan_types", None):
            types_list = [
                t.strip().upper() for t in str(self.config.scan_types).split(",")
            ]
            if len(types_list) == 1:
                additional_filters.append(f"type=={types_list[0]}")
            else:
                additional_filters.append(f"type=in=({','.join(types_list)})")

        if getattr(self.config, "scan_statuses", None):
            statuses_list = [
                s.strip().upper() for s in str(self.config.scan_statuses).split(",")
            ]
            if len(statuses_list) == 1:
                additional_filters.append(f"status=={statuses_list[0]}")
            else:
                additional_filters.append(f"status=in=({','.join(statuses_list)})")

        # Combine filters
        if additional_filters:
            combined_filter = ";".join(additional_filters)
            if original_filter:
                final_filter = f"{original_filter};{combined_filter}"
            else:
                final_filter = combined_filter

            # Create new query config with filters
            return QueryConfig(
                endpoint=query_config.endpoint,
                params=QueryParams(
                    filter=final_filter,
                    sort=query_config.params.sort,
                    limit=query_config.params.limit,
                    offset=query_config.params.offset,
                ),
            )

        # No additional filters, return original query
        return query_config

    # ------------------------------------------------------------------
    # SBOM-based group enrichment
    # ------------------------------------------------------------------

    def _enrich_group_from_sbom(
        self,
        raw_data: pd.DataFrame,
        *,
        version_id_col: str,
        name_col: str,
        version_col: str,
        group_col: str,
    ) -> pd.DataFrame:
        """Enrich a DataFrame with component group/namespace from SBOMs.

        Downloads CycloneDX SBOMs for each unique version ID in *raw_data*,
        parses them, and builds a ``(name, version) → group`` lookup.  The
        *group_col* in *raw_data* is then filled where it was previously
        empty.

        Args:
            raw_data: DataFrame to enrich (returned as-is if empty).
            version_id_col: Column containing numeric project-version IDs.
            name_col: Column containing component names.
            version_col: Column containing component versions.
            group_col: Column to populate with group values.

        Returns:
            The enriched DataFrame (modified in-place when possible).
        """
        if raw_data.empty or version_id_col not in raw_data.columns:
            return raw_data

        from fs_report.sbom_parser import parse_cyclonedx

        # Collect unique version IDs (drop unknowns / empty strings)
        vid_series = raw_data[version_id_col].dropna().astype(str)
        version_ids = sorted({v for v in vid_series if v.strip() and v != "nan"})

        if not version_ids:
            return raw_data

        self.logger.info(
            f"Fetching SBOMs for group enrichment ({len(version_ids)} versions)"
        )

        # Build lookup: (lower_name, lower_version) → group
        group_lookup: dict[tuple[str, str], str] = {}
        for vid in version_ids:
            try:
                sbom_raw = self.api_client.fetch_sbom(
                    vid, sbom_format="cyclonedx", include_vex=False
                )
                sbom = parse_cyclonedx(sbom_raw)
                for comp in sbom.components.values():
                    if comp.group:
                        key = (comp.name.lower(), comp.version.lower())
                        group_lookup[key] = comp.group
            except Exception:
                self.logger.debug(
                    f"SBOM fetch failed for version {vid}, skipping group enrichment"
                )

        if not group_lookup:
            return raw_data

        self.logger.info(
            f"SBOM group lookup built: {len(group_lookup)} components with group info"
        )

        # Ensure group column exists
        if group_col not in raw_data.columns:
            raw_data[group_col] = ""

        # Vectorised fill: only overwrite where current group is empty
        needs_fill = raw_data[group_col].fillna("").eq("")
        if not needs_fill.any():
            return raw_data

        # Build lookup keys for rows needing a fill
        if name_col in raw_data.columns and version_col in raw_data.columns:
            keys = list(
                zip(
                    raw_data.loc[needs_fill, name_col].fillna("").str.lower(),
                    raw_data.loc[needs_fill, version_col].fillna("").str.lower(),
                    strict=True,
                )
            )
            filled = [group_lookup.get(k, "") for k in keys]
            raw_data.loc[needs_fill, group_col] = filled

        filled_count = (raw_data[group_col].fillna("") != "").sum()
        self.logger.info(
            f"Group enrichment complete: {filled_count} components have group info"
        )

        return raw_data

    @staticmethod
    def _annotate_dependency_paths(
        df: pd.DataFrame,
        tree: DependencyNode,
    ) -> pd.DataFrame:
        """Add dependency_path and component_dependency_path columns.

        Only adds columns when the tree has dependencies (children).
        Uses the version ID from each finding's projectVersion to look up
        the dependency path in the tree.
        """
        if not tree.has_dependencies:
            return df

        path_map = tree.version_id_to_path_map()

        def _get_version_id(row: pd.Series) -> int | None:
            pv = row.get("projectVersion")
            if isinstance(pv, dict):
                return pv.get("id")
            for col in ("projectVersion.id", "project_version_id"):
                val = row.get(col)
                if val is not None:
                    try:
                        return int(val)
                    except (ValueError, TypeError):
                        pass
            return None

        def _get_component_str(row: pd.Series) -> str:
            comp = row.get("component")
            if isinstance(comp, dict):
                name = comp.get("name", "")
                version = comp.get("version", "")
                if name and version:
                    return f"{name} {version}"
                return name or ""
            name = row.get("component_name", row.get("component.name", ""))
            version = row.get("component_version", row.get("component.version", ""))
            if name and version:
                return f"{name} {version}"
            return str(name) if name else ""

        df = df.copy()
        dep_paths = []
        comp_dep_paths = []

        for _, row in df.iterrows():
            vid = _get_version_id(row)
            dep_path = path_map.get(vid, "") if vid else ""
            comp_str = _get_component_str(row)
            comp_path = (
                f"{dep_path} -> {comp_str}" if (dep_path and comp_str) else dep_path
            )
            dep_paths.append(dep_path)
            comp_dep_paths.append(comp_path)

        df["dependency_path"] = dep_paths
        df["component_dependency_path"] = comp_dep_paths
        return df

    def _invoke_exec_dashboard_transform(
        self,
        data: Any,
        additional_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Dispatch Exec Dashboard transform by mode."""
        if self.config.detailed_mode:
            from fs_report.transforms.pandas.executive_dashboard import (
                executive_dashboard_transform,
            )

            return executive_dashboard_transform(
                data,
                additional_data=additional_data,
            )
        from fs_report.transforms.pandas.executive_dashboard_summary import (
            executive_dashboard_summary_transform,
        )

        return executive_dashboard_summary_transform(
            data,
            additional_data=additional_data,
            start_date=self.config.start_date,
            end_date=self.config.end_date,
        )

    def _batched_fetch_components_by_pv(
        self,
        pv_ids: list[str],
        failed_out: list[str] | None = None,
    ) -> dict[str, list[dict]]:
        """Fetch /components for many projectVersions in RSQL `=in=(...)` batches.

        Returns ``{pv_id: [components...]}`` with an entry for every requested
        id (empty list if no components). Batch size follows the existing
        convention (15 if >200 ids, else 25) to stay under URI length limits.

        ``failed_out`` (when provided) collects projectVersion ids whose
        fetch degraded to an empty list because the platform 400s even a
        single-id query (poisoned row, ALLOY-3274 family). Those ids get
        an empty entry in the result but are NOT cache-warmed, and callers
        should surface them to report consumers.

        Per-PV cache read first: any projectVersion whose per-PV SQLite entry
        (written by ``_split_and_cache_by_version``) is still valid bypasses
        the API entirely. Only the cold remainder is batched.

        Batched results feed ``_split_and_cache_by_version`` so later
        ``projectVersion=={pv}`` fetches hit the same SQLite entries.
        """
        if not pv_ids:
            return {}

        sorted_ids = sorted(str(pv) for pv in pv_ids)
        cache = getattr(self.api_client, "sqlite_cache", None)
        ttl = getattr(self.api_client, "cache_ttl", 0) or 0

        # Phase 1: consult per-PV SQLite cache, partition into hit/miss.
        by_pv: dict[str, list[dict]] = {}
        uncached: list[str] = []
        if cache is not None and ttl > 0:
            endpoint = "/public/v0/components"
            for pv_id in sorted_ids:
                params = {"filter": f"projectVersion=={pv_id}", "limit": 10000}
                if cache.is_cache_valid(endpoint, params, ttl):
                    data = cache.get_cached_data(endpoint, params, allow_empty=True)
                    # Per-PV cache entries are stored under a filterless
                    # key and may predate the type!=file batch filter (or
                    # come from a path that cached file rows). Filter on
                    # read so warm caches can't reintroduce file-typed
                    # SAST placeholders into the SCA KPIs (round-2
                    # review, 2/3 finding).
                    by_pv[pv_id] = [
                        c for c in (data or []) if (c or {}).get("type") != "file"
                    ]
                else:
                    uncached.append(pv_id)
        else:
            uncached = list(sorted_ids)

        if not uncached:
            self.logger.info(
                "Batched /components fetch: all %d projectVersion(s) cached, "
                "skipping API",
                len(by_pv),
            )
            return by_pv

        all_failed: list[str] = []
        batch_size = 15 if len(uncached) > 200 else 25
        total_batches = (len(uncached) + batch_size - 1) // batch_size
        self.logger.info(
            "Batched /components fetch: %d uncached projectVersion(s) "
            "(%d cached), batch_size=%d, %d batches",
            len(uncached),
            len(by_pv),
            batch_size,
            total_batches,
        )

        for i in range(0, len(uncached), batch_size):
            batch_ids = uncached[i : i + batch_size]
            t0 = time.monotonic()
            batch_failed: list[str] = []
            batch_records = self._fetch_components_batch_with_bisect(
                batch_ids, batch_failed
            )
            elapsed = time.monotonic() - t0
            self.logger.info(
                "/components batch %d/%d: %d PVs, %d records, %.1fs",
                i // batch_size + 1,
                total_batches,
                len(batch_ids),
                len(batch_records),
                elapsed,
            )

            # Warm per-version SQLite cache so later projectVersion=={pv}
            # fetches (e.g. detailed mode, Version Comparison) hit the cache.
            # Degraded (poisoned) versions are EXCLUDED: caching their empty
            # result would make the degradation sticky for the cache TTL and
            # indistinguishable from a legitimately component-free version —
            # leaving them uncached retries the platform on every run until
            # the corrupt row is repaired.
            cacheable_ids = [v for v in batch_ids if v not in batch_failed]
            # _split_and_cache_by_version partitions records by their OWN
            # projectVersion.id, so salvaged partial rows for a poisoned
            # version must be filtered out too — caching them would make
            # the incomplete list sticky for the TTL and indistinguishable
            # from a complete fetch (round-4 review M2-2).
            _failed_set = set(map(str, batch_failed))
            cacheable_records = [
                r
                for r in batch_records
                if str(((r or {}).get("projectVersion") or {}).get("id"))
                not in _failed_set
            ]
            self._split_and_cache_by_version(
                cacheable_records,
                entity_type="components",
                batch_version_ids=cacheable_ids,
            )

            for comp in batch_records:
                pv = (comp.get("projectVersion") or {}).get("id")
                if pv:
                    by_pv.setdefault(str(pv), []).append(comp)
            for pv_id in batch_ids:
                by_pv.setdefault(pv_id, [])
            if failed_out is not None:
                failed_out.extend(batch_failed)
            all_failed.extend(batch_failed)

        # Systemic-failure guard: poison rows are a PER-VERSION data
        # defect. If EVERY REQUESTED version degraded (and there was
        # more than one), the 400s are far more likely a request/
        # contract regression on our side — degrading would mask an
        # outage behind rollup fallbacks (round-5 review M3-1).
        # Compared against the full requested scope, not just the
        # uncached subset: cache-served versions prove the platform is
        # not systemically failing, so a warm-cache run must not
        # hard-fail where a cold run would degrade (round-6 M3-3).
        # A single-version scope keeps degradation so one poisoned
        # project can still report.
        if len(sorted_ids) > 1 and len(all_failed) == len(sorted_ids):
            raise ValueError(
                f"/components batched fetch degraded for ALL "
                f"{len(sorted_ids)} projectVersions — treating as a "
                f"systemic API failure rather than per-row corruption."
            )

        return by_pv

    @staticmethod
    def _is_components_page_error(exc: BaseException) -> bool:
        """True for the HTTP-400 page-failure family that bisection can
        actually help with (platform window / poisoned-row 400s,
        ALLOY-3274 family). ``fetch_all_with_resume`` formats permanent
        errors as ``API request failed at offset N: <status> - <body>``;
        auth/permission/contract failures (401/403/404/422...) affect
        every batch equally, so bisecting them would only spam the API
        and mis-label the failure as a corrupt row (round-2 review,
        3/3 finding). Both observed corrupt-row variants (ALLOY-3274
        "Illegal character in path", ALLOY-3275 "URLDecoder: Incomplete
        trailing escape") carry the platform's "Invalid parameter value"
        envelope — generic 400s (e.g. contract violations) propagate."""
        msg = str(exc)
        return ": 400 -" in msg and "Invalid parameter value" in msg

    def _fetch_single_pv_components_partial(self, pv_id: str) -> list[dict]:
        """Salvage pages of a single projectVersion's /components up to the
        first failing window.

        Used when even the single-id batched query 400s (poisoned row).
        Pages at limit=1000 give finer salvage granularity than the
        batched 10k pages; the loop stops at the first page-level
        failure or after a sane cap. Errors are swallowed by design —
        this path only ever runs inside degradation handling.
        """
        from fs_report.models import QueryConfig as _QC
        from fs_report.models import QueryParams as _QP

        salvaged: list[dict] = []
        page_limit = 1000
        max_pages = 50  # 50k rows — generous cap for a single version
        for page_no in range(max_pages):
            page_query = _QC(
                endpoint="/public/v0/components",
                params=_QP(
                    limit=page_limit,
                    offset=page_no * page_limit,
                    filter=f"type!=file;projectVersion=in=({pv_id})",
                ),
            )
            try:
                page = self.api_client._fetch_page_direct(page_query)
            except Exception:
                break
            if not page:
                break
            salvaged.extend(page)
            if len(page) < page_limit:
                break
        else:
            self.logger.warning(
                "Component salvage for projectVersion %s hit the %d-page "
                "cap (%d rows) — the salvaged list may be truncated "
                "beyond the cap, in addition to the poison-row gap.",
                pv_id,
                max_pages,
                len(salvaged),
            )
        return salvaged

    def _fetch_components_batch_with_bisect(
        self,
        batch_ids: list[str],
        failed_ids: list[str] | None = None,
    ) -> list[dict]:
        """Fetch one /components RSQL batch; bisect on permanent 4xx.

        The filter always carries ``type!=file``, matching every other
        /components path (generic version batching, License Report, ED
        detailed mode). Without it, file-typed SAST placeholders inflate
        the summary-mode SCA KPIs (vs. both the platform UI and the
        latestVersion-rollup fallback in executive_dashboard_summary).

        Bisection: the platform 400s (bogus "URLDecoder: Incomplete
        trailing escape (%)" message) on /components queries that must
        reach past its first ~10k-row window — deep ``offset``, or a
        ``!=`` post-filter at limit=10000 — observed in the 2026-06-06
        qabot run (step_05b). ``fetch_all_with_resume`` surfaces that as
        ``ValueError``. Halving the id list keeps each query's matched
        rows under the window, so the fetch recovers without waiting on
        a platform-side fix.

        A projectVersion that fails even as a single-id query (a
        platform-side corrupt row, ALLOY-3274 family) DEGRADES: it is
        logged, appended to ``failed_ids`` (when provided), and
        contributes whatever pages could be SALVAGED before the failing
        window (possibly empty) — the whole portfolio report must not
        die for one poisoned row. Callers use ``failed_ids`` to skip
        cache-warming for those versions (so a repaired platform
        dataset is retried on the next run) and to surface the
        degradation to report consumers; salvaged partial lists must be
        treated as incomplete (KPI sums prefer rollups for degraded
        projects).
        """
        batch_filter = f"type!=file;projectVersion=in=({','.join(batch_ids)})"
        batch_query = QueryConfig(
            endpoint="/public/v0/components",
            params=QueryParams(limit=10000, filter=batch_filter),
        )
        try:
            return (
                self.api_client.fetch_all_with_resume(
                    batch_query, show_progress=False, skip_cache_store=True
                )
                or []
            )
        except ValueError as e:
            if not self._is_components_page_error(e):
                # Auth / permission / contract errors are not row-window
                # failures — bisection can't help and degradation would
                # hide a real outage. Propagate.
                raise
            if len(batch_ids) <= 1:
                # One projectVersion still fails after bisection: a
                # platform-side corrupt row (ALLOY-3274 family — e.g. a
                # component field with a bare '%') 400s every page whose
                # window touches it. Salvage the pages BEFORE the poison
                # (a >10k-component version failing in a late window
                # would otherwise lose everything — round-3 review,
                # 3/3 finding), then degrade: the summary transform
                # falls back to latestVersion rollups when the salvage
                # comes back empty.
                pv = batch_ids[0] if batch_ids else "?"
                partial = self._fetch_single_pv_components_partial(str(pv))
                self.logger.warning(
                    "/components fetch for projectVersion %s failed even as "
                    "a single-id query (%s); salvaged %d component row(s) "
                    "from pages before the failure. Its project is marked "
                    "degraded%s. Likely platform-side corrupt row (see "
                    "ALLOY-3274).",
                    pv,
                    str(e)[:160],
                    len(partial),
                    "" if partial else " and falls back to latestVersion rollups",
                )
                if failed_ids is not None and batch_ids:
                    failed_ids.append(batch_ids[0])
                return partial
            mid = len(batch_ids) // 2
            self.logger.warning(
                "/components batch of %d projectVersions failed (%s); "
                "bisecting into %d + %d",
                len(batch_ids),
                str(e)[:120],
                mid,
                len(batch_ids) - mid,
            )
            return self._fetch_components_batch_with_bisect(
                batch_ids[:mid], failed_ids
            ) + self._fetch_components_batch_with_bisect(batch_ids[mid:], failed_ids)

    def _batched_fetch_versions_histories(
        self, project_ids: list[str]
    ) -> dict[str, list[dict]]:
        """Fetch /versions for many projects in RSQL `project=in=(...)` batches.

        Returns ``{project_id: [versions asc by created...]}`` with an entry for
        every requested id. Batch size matches the portfolio batching convention
        (15 if >200 ids, else 25).

        Writes each per-project partition to ``raw_cache`` under
        ``versions_history:{project_id}`` so single-project callers of
        ``fetch_versions_history`` (e.g. per-project reruns) hit warm cache.
        """
        if not project_ids:
            return {}

        sorted_ids = sorted(str(p) for p in project_ids)
        cache = getattr(self.api_client, "sqlite_cache", None)
        ttl = getattr(self.api_client, "cache_ttl", 0) or 0

        # Phase 1: consult per-project raw_cache, partition into hit/miss.
        by_project: dict[str, list[dict]] = {}
        uncached: list[str] = []
        if cache is not None and ttl > 0:
            for pid in sorted_ids:
                cached = cache.get_raw(f"versions_history:{pid}", ttl)
                if isinstance(cached, list):
                    by_project[pid] = cached
                else:
                    uncached.append(pid)
        else:
            uncached = list(sorted_ids)

        if not uncached:
            self.logger.info(
                "Batched /versions fetch: all %d project(s) cached, skipping API",
                len(by_project),
            )
            return by_project

        batch_size = 15 if len(uncached) > 200 else 25
        total_batches = (len(uncached) + batch_size - 1) // batch_size
        self.logger.info(
            "Batched /versions fetch: %d uncached project(s) (%d cached), "
            "batch_size=%d, %d batches",
            len(uncached),
            len(by_project),
            batch_size,
            total_batches,
        )

        for i in range(0, len(uncached), batch_size):
            batch_ids = uncached[i : i + batch_size]
            batch_filter = f"project=in=({','.join(batch_ids)})"
            batch_query = QueryConfig(
                endpoint="/public/v0/versions",
                params=QueryParams(
                    limit=10000,
                    filter=batch_filter,
                    sort="created:asc",
                ),
            )
            t0 = time.monotonic()
            batch_records = (
                self.api_client.fetch_all_with_resume(
                    batch_query, show_progress=False, skip_cache_store=True
                )
                or []
            )
            elapsed = time.monotonic() - t0
            self.logger.info(
                "/versions batch %d/%d: %d projects, %d records, %.1fs",
                i // batch_size + 1,
                total_batches,
                len(batch_ids),
                len(batch_records),
                elapsed,
            )

            partition: dict[str, list[dict]] = {}
            for ver in batch_records:
                proj_id = (ver.get("project") or {}).get("id")
                if proj_id:
                    partition.setdefault(str(proj_id), []).append(ver)
            # API sort=created:asc applies across the batch; re-sort per project
            # to be defensive against intermixed/bag-ordered responses.
            for plist in partition.values():
                plist.sort(key=lambda v: v.get("created", ""))

            for pid in batch_ids:
                plist = partition.get(pid, [])
                by_project[pid] = plist
                if cache is not None and ttl > 0:
                    cache.put_raw(f"versions_history:{pid}", plist)

        return by_project

    def _filter_projects_to_period(self, projects: list[dict]) -> list[dict]:
        """Keep only projects whose current version was scanned in the window.

        Window is [start_date 00:00:00 UTC, end_date+1 day 00:00:00 UTC), so
        both endpoint days are inclusive. Projects without a parseable
        ``defaultBranch.latestVersion.created`` are excluded — for the
        purposes of "what happened in this period", a project with no
        recent scan didn't happen.
        """
        from datetime import UTC, datetime, timedelta

        try:
            start = datetime.fromisoformat(self.config.start_date).replace(tzinfo=UTC)
            end = datetime.fromisoformat(self.config.end_date).replace(
                tzinfo=UTC
            ) + timedelta(days=1)
        except (ValueError, TypeError):
            self.logger.warning(
                "Could not parse period dates (%s, %s) — skipping period filter",
                self.config.start_date,
                self.config.end_date,
            )
            return projects

        filtered: list[dict] = []
        for proj in projects:
            db = proj.get("defaultBranch") or {}
            lv = db.get("latestVersion") or {} if isinstance(db, dict) else {}
            created_str = lv.get("created")
            if not created_str:
                continue
            try:
                created = datetime.fromisoformat(
                    str(created_str).replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                continue
            if start <= created < end:
                filtered.append(proj)
        return filtered

    def _fetch_exec_dashboard_summary(self, max_workers: int = 10) -> dict[str, Any]:
        """Fetch Executive Dashboard summary-mode data.

        Pipeline:
          1. GET /public/v0/projects (paginated) — once, up front
          2. Optional period filter — projects whose current version was
             scanned outside [start_date, end_date] are dropped when the
             user explicitly requested a period (--period, --start, --end).
          3. Batched fetch of /components (RSQL projectVersion=in=(...))
          4. Batched fetch of /versions (RSQL project=in=(...))
          5. per_project_parallel — 4 calls per project (summary counts only);
             components and versions are served from the batched pre-fetch
        Returns a dict consumable by executive_dashboard_summary_transform.
        """
        from fs_report.api.per_project_parallel import per_project_parallel
        from fs_report.api.summary_counts import fetch_all_summary_counts

        # 1. Paginated /projects fetch
        projects_query = QueryConfig(
            endpoint="/public/v0/projects",
            params=QueryParams(limit=10000, archived=False, excluded=False),
        )
        all_projects = self.api_client.fetch_all_with_resume(
            projects_query, show_progress=True
        )

        # Apply folder/project filters (existing engine state)
        if self._folder_project_ids:
            in_scope = [
                p for p in all_projects if str(p.get("id")) in self._folder_project_ids
            ]
        elif self.config.project_filter:
            pf = self.config.project_filter
            in_scope = [
                p
                for p in all_projects
                if str(p.get("id")) == pf or p.get("name", "").lower() == pf.lower()
            ]
        else:
            in_scope = list(all_projects)

        # Period scoping: when the user explicitly requested a period, restrict
        # the KPI/chart totals to projects whose current version was scanned in
        # that window. Without this, summary mode reports the full all-time
        # portfolio regardless of --period. When period is the default, skip
        # the filter — that path means "no time constraint was requested".
        if getattr(self.config, "period_explicit", False):
            before = len(in_scope)
            in_scope = self._filter_projects_to_period(in_scope)
            self.logger.info(
                "Period scope [%s to %s]: %d/%d project(s) with current "
                "version in window",
                self.config.start_date,
                self.config.end_date,
                len(in_scope),
                before,
            )

        self.logger.info(
            "Executive Dashboard (summary): %d project(s) in scope",
            len(in_scope),
        )

        # Collect pv_ids + project_ids for batched pre-fetch.
        pv_ids: list[str] = []
        project_ids: list[str] = []
        pv_to_project_name: dict[str, str] = {}
        for proj in in_scope:
            db = proj.get("defaultBranch") or {}
            lv = db.get("latestVersion") or {} if isinstance(db, dict) else {}
            pv_id = lv.get("id")
            pid = proj.get("id")
            if pv_id and pid is not None:
                pv_ids.append(str(pv_id))
                project_ids.append(str(pid))
                pv_to_project_name[str(pv_id)] = proj.get("name") or str(pid)

        # 2. Batched /components fetch
        degraded_pv_ids: list[str] = []
        components_by_pv = self._batched_fetch_components_by_pv(
            pv_ids, failed_out=degraded_pv_ids
        )

        # 3. Batched /versions fetch
        versions_by_project = self._batched_fetch_versions_histories(project_ids)

        # 4. Per-project summary-counts fan-out (path-parameterized endpoints
        # can't be RSQL-batched, so this remains per-version).
        def work(proj: dict) -> dict:
            pid = proj.get("id")
            db = proj.get("defaultBranch") or {}
            lv = db.get("latestVersion") or {} if isinstance(db, dict) else {}
            pv_id = lv.get("id")
            if not pv_id:
                return {"id": pid, "name": proj.get("name"), "skipped": True}

            counts = fetch_all_summary_counts(self.api_client, pv_id)

            return {
                "id": str(pid),
                "name": proj.get("name"),
                "folder": proj.get("folder") or {"id": "", "name": ""},
                "latestVersion": lv,
                "components": components_by_pv.get(str(pv_id), []),
                "versions_history": versions_by_project.get(str(pid), []),
                "summary_counts": counts,
            }

        parallel_results = per_project_parallel(in_scope, work, max_workers=max_workers)

        successes: list[dict] = []
        failed_names: list[str] = []
        for proj, outcome in parallel_results:
            if isinstance(outcome, Exception):
                self.logger.warning(
                    "Summary fetch failed for project %s: %s",
                    proj.get("name"),
                    str(outcome)[:200],
                )
                failed_names.append(proj.get("name", str(proj.get("id"))))
                continue
            if outcome.get("skipped"):
                self.logger.debug(
                    "Project %s has no latest version; skipping", proj.get("name")
                )
                continue
            successes.append(outcome)

        # Map degraded (poisoned-row) projectVersions back to project names
        # so the template can surface the gap: their SCA KPIs fall back to
        # latestVersion rollups and they are absent from component-derived
        # charts (License Bar / License KPIs / Policy Health).
        degraded_names: list[str] = []
        if degraded_pv_ids:
            degraded_names = [
                pv_to_project_name.get(str(pv), str(pv)) for pv in degraded_pv_ids
            ]
            self.logger.warning(
                "Executive Dashboard summary: component lists degraded for "
                "%d project(s): %s (platform-side corrupt rows — see "
                "ALLOY-3274; SCA KPIs use rollups, license/policy charts "
                "include only the salvaged subset)",
                len(degraded_names),
                ", ".join(degraded_names),
            )

        return {
            "projects": successes,
            "mode": "summary",
            # Umbrella machine-readable flag: True when ANY project's data
            # is incomplete — fully-failed fetches OR component-degraded
            # projects (round-3 review M-3: automation gating on
            # partial_report alone must detect degraded runs).
            "partial_report": bool(failed_names or degraded_names),
            "failed_projects": failed_names,
            "degraded_components_projects": degraded_names,
        }

    def clear_cache(self) -> None:
        """Clear the data cache."""
        self.cache.clear()
        self.logger.info("Cache cleared")
