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

"""
LLM client for AI-powered remediation guidance.

Provides LLM-generated remediation summaries at three scopes:
- Portfolio: Strategic remediation opportunities across all projects
- Project: Recommended remediation order per project
- Finding: Fix version, workaround, code search hints (full depth only)

Supports multiple LLM providers:
- Anthropic Claude (default): Opus for summaries, Sonnet for bulk guidance
- OpenAI: GPT-4o for summaries, GPT-4o-mini for bulk guidance
- GitHub Copilot: Uses OpenAI SDK with Copilot endpoint (OAuth device flow supported)
- Google Gemini: Uses OpenAI-compatible endpoint

Provider is auto-detected from environment variables or set explicitly
via the ``provider`` parameter.

Results are cached in SQLite to avoid redundant API calls.
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fs_report.deployment_context import DeploymentContext

logger = logging.getLogger(__name__)

# Token limits
MAX_PORTFOLIO_TOKENS = 2000
MAX_PROJECT_TOKENS = 1500
MAX_COMPONENT_TOKENS = 800
MAX_ANALYSIS_TOKENS = 4000
TOKENS_PER_CVE = 500  # extra budget per CVE for combined analysis
MAX_ANALYSIS_TOKENS_CAP = 16000  # hard ceiling for a single call

# Provider -> (summary_model, component_model)
# Use alias IDs (e.g. "claude-opus-4-6") rather than date-pinned IDs
# (e.g. "claude-opus-4-6-20260205") so the API routes to the latest
# snapshot automatically and we never 404 on a retired model.
MODEL_MAP: dict[str, tuple[str, str]] = {
    "anthropic": ("claude-opus-4-6", "claude-sonnet-4-6"),
    "openai": ("gpt-4o", "gpt-4o-mini"),
    "copilot": ("gpt-4o", "gpt-4o-mini"),
    "gemini": ("gemini-2.5-pro", "gemini-2.5-flash"),
}

# Env var detection order
_PROVIDER_ENV_VARS: list[tuple[str, str]] = [
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("openai", "OPENAI_API_KEY"),
    ("gemini", "GEMINI_API_KEY"),
    ("copilot", "GITHUB_TOKEN"),
]

# Legacy env var kept for backwards compatibility
_ANTHROPIC_LEGACY_VAR = "ANTHROPIC_AUTH_TOKEN"

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"

# Canonical list of env vars that indicate AI provider credentials are available.
# Import this instead of duplicating the list.
AI_ENV_VARS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",  # deprecated, kept for detection
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GITHUB_TOKEN",
)


# Cache schema version. Bump this to force clean regeneration of the AI
# narrative caches (cve_remediations + ai_summary_cache narrative rows) on the
# next run — used to purge entries written under an older, unscoped key layout
# that could contain another project's/customer's text.
_LLM_CACHE_SCHEMA_VERSION = "2"

# ai_summary_cache "scope" values that hold project-blind LIBRARY FACTS (the
# scanned component's true identity / per-CVE applicability). These are safe to
# share across projects and tenants and are preserved across a schema-version
# purge; every other scope holds project-specific narrative.
_FACT_SUMMARY_SCOPES = ("identity", "applicability")

# Tokens that a null/absent identifier can arrive as once a value has passed
# through pandas (float64 coercion of an int column with any null -> NaN, which
# str()-es to "nan") or JSON. Treated as "no stable identity".
_NULL_REF_TOKENS = frozenset({"", "nan", "none", "null", "<na>", "na"})

# Application salt for cache-scope tokens. Scope digests are HMAC-keyed (with a
# fixed, non-secret application salt) rather than a bare hash, so scope values
# are namespaced to this app and not a plain SHA-256 an attacker could match
# against generic rainbow tables. NOTE: because the salt is public, the digest
# is NOT a defense against an attacker who can brute-force the API token —
# confidentiality of the token rests on its own entropy (a real Finite State API
# token is high-entropy and not enumerable); true offline-oracle resistance would
# require a per-install secret key, which we do not have here. Digests are
# 128-bit (32 hex) to keep accidental cross-account collisions far out of reach,
# since the scope IS the confidentiality boundary.
_SCOPE_HMAC_SALT = b"fs-report/ai-cache-scope/v1"
_SCOPE_DIGEST_HEX = 32

# Placeholder API tokens that do NOT identify a real account. Offline/data-file
# runs use "dummy_token" (see cli/run.py); such runs have no account boundary,
# so build_tenant_scope must not mint a (constant) tenant token from them.
_PLACEHOLDER_AUTH_TOKENS = frozenset({"", "dummy_token"})


def _scope_digest(data: str) -> str:
    """Keyed, non-reversible digest of a cache-scope string."""
    return hmac.new(_SCOPE_HMAC_SALT, data.encode(), hashlib.sha256).hexdigest()[
        :_SCOPE_DIGEST_HEX
    ]


def normalize_project_ref(value: Any) -> str:
    """Canonicalize a project-version identifier for use in a cache scope.

    Returns ``""`` for any null-like value (``None``, ``NaN``, ``"nan"``,
    ``"None"``, empty). A stable id is required to scope narrative safely; an
    empty return means "no stable identity" and callers must NOT cache narrative
    under it (they bypass the cache instead of risking a cross-project match).

    Floats produced by pandas coercing an int id column (e.g. ``"12345.0"``) are
    canonicalized back to the integer form so the same version always hashes to
    the same scope regardless of whether it arrived via the dict or flattened
    dataframe branch.
    """
    if value is None:
        return ""
    # float NaN is truthy, so an explicit check is required.
    if isinstance(value, float):
        if value != value:  # NaN
            return ""
        # 12345.0 -> "12345"; keep genuine fractional ids intact (unexpected).
        value = int(value) if value.is_integer() else value
    text = str(value).strip()
    if text.lower() in _NULL_REF_TOKENS:
        return ""
    # "12345.0" (string form of a pandas-coerced int id) -> "12345".
    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]
    return text


def build_tenant_scope(domain: str | None, auth_token: str | None) -> str:
    """Build a stable tenant-boundary token from the platform host + API token.

    The confidentiality boundary is the *account*, identified by the API token —
    NOT the host: a single host (e.g. ``platform.finitestate.io``) serves many
    accounts. A real token is therefore REQUIRED; without one this returns ``""``
    (no tenant boundary). That covers domain-only callers and offline/data-file
    runs, whose token is the shared placeholder ``dummy_token`` — treating it as
    a real tenant would give every offline user the same constant token and
    defeat callers that rely on the tenant boundary (e.g. the name-scoped CRP
    path, which bypasses its cache when there is no tenant).

    An empty tenant token is safe: cross-project isolation still comes from the
    per-item ``project_version_id`` scope, which bypasses the cache when absent.
    The domain is folded in (so the same token across staging/prod differs), but
    only once a real token is present.
    """
    token = (auth_token or "").strip()
    if token in _PLACEHOLDER_AUTH_TOKENS:
        return ""
    domain = (domain or "").strip().lower()
    return _scope_digest(f"{domain}\x1f{token}")


def _is_auth_error(exc: Exception) -> bool:
    """Return True if *exc* looks like a 401/403 authentication error."""
    # openai.AuthenticationError (status_code 401)
    if type(exc).__name__ in ("AuthenticationError", "PermissionDeniedError"):
        return True
    status = getattr(exc, "status_code", None)
    return status in (401, 403)


def _usage_int(value: Any) -> int:
    """Coerce an SDK usage field to int; None/absent/non-numeric → 0.

    Usage accounting must never raise — some providers omit ``usage`` and
    mocked responses carry auto-attribute objects in its place.
    """
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def merge_ai_usage(target: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Accumulate one ``ai_usage`` payload into another, in place.

    Shared shape: ``{"input_tokens": int, "output_tokens": int, "models":
    {model: {"input_tokens": int, "output_tokens": int}}}``. Used by
    :meth:`LLMClient.record_usage_metadata` (a transform running more than
    one client) and by the compound assembler aggregating per-child usage
    into the bundle's ``RecipeResult.stats``. Coerces every count through
    :func:`_usage_int` and skips non-mapping model entries — usage
    accounting must never raise, even on a malformed payload.
    """
    target["input_tokens"] = _usage_int(target.get("input_tokens")) + _usage_int(
        incoming.get("input_tokens")
    )
    target["output_tokens"] = _usage_int(target.get("output_tokens")) + _usage_int(
        incoming.get("output_tokens")
    )
    models = target.setdefault("models", {})
    incoming_models = incoming.get("models")
    if isinstance(incoming_models, dict):
        for model, counts in incoming_models.items():
            if not isinstance(counts, dict):
                continue
            bucket = models.setdefault(
                str(model), {"input_tokens": 0, "output_tokens": 0}
            )
            bucket["input_tokens"] = _usage_int(
                bucket.get("input_tokens")
            ) + _usage_int(counts.get("input_tokens"))
            bucket["output_tokens"] = _usage_int(
                bucket.get("output_tokens")
            ) + _usage_int(counts.get("output_tokens"))
    return target


def resolve_active_api_key(provider_override: str | None = None) -> str:
    """Raw API key of the AI provider active for this process, or ``""``.

    The same resolution ``LLMClient`` itself performs (explicit provider
    override, else env-var auto-detection) — public entry point for log
    redaction, so the key ``llm_client`` would actually send never lands
    unscrubbed in a run log or a bridge event. Best-effort by contract: any
    resolution failure returns ``""`` (logged at DEBUG) because redaction
    must never break a run.

    For Copilot this is the ``GITHUB_TOKEN``; the short-lived bearer minted
    later by ``copilot_auth.get_copilot_token`` (and any GitHub-side token it
    spends) is covered separately — it registers itself as a runtime
    redaction secret via ``logging_utils.register_runtime_secret``.
    """
    try:
        _provider, api_key = LLMClient._detect_provider(provider_override)
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "No AI credential resolved for log redaction: %s", exc
        )
        return ""
    return api_key


# ── Shared prompt blocks ────────────────────────────────────────────
# These replace text that was previously duplicated across 5+ prompt
# locations.  Each function returns a stable string fragment.


def _verdict_block() -> str:
    """Library-identity check preamble for VERDICT / APPLICABILITY fields."""
    return (
        "IMPORTANT: Check library identity FIRST, before considering "
        "reachability or exploit data. (1) Does the NVD Target name a "
        "DIFFERENT library than the scanned component? e.g., CVE targets "
        '"gnu/glibc" but component is openwrt/libc (musl), or CVE targets '
        '"openssl" but component is BoringSSL. If YES → answer "not_affected" '
        "and STOP. Reachability of standard functions (getaddrinfo, realpath, "
        "glob, strcoll, nan, nanf, etc.) does NOT mean the same bug exists — "
        "different implementations (glibc vs musl, OpenSSL vs BoringSSL) have "
        "completely different source code and different bugs. A function name "
        "match is NOT a vulnerability match. (2) Is this the wrong platform? "
        'e.g., Windows-only CVE on Linux. If YES → "not_affected". '
        "(3) Is the installed version outside the affected range? If YES → "
        '"not_affected". Only answer "affected" when the component is '
        "genuinely the SAME library the CVE targets."
    )


def _fix_version_block(component_version: str = "") -> str:
    """Fix-version guidance for FIX_VERSION fields."""
    ver_ref = ""
    if component_version:
        ver_ref = (
            f" Cross-reference the installed version ({component_version}) "
            "against the NVD affected ranges."
        )
    return (
        'specific version number. If NVD data says "FIXED in >= X", recommend X. '
        'If NVD data says a version is "STILL VULNERABLE", the fix must be '
        "AFTER that version — do NOT recommend the vulnerable version."
        f"{ver_ref} "
        "For well-known libraries (OpenSSL, curl, busybox, zlib, etc.), recall "
        "the specific patch version from security advisories. "
        'Only state "verify latest stable release" if no version data is available.'
    )


def _workaround_block(ctx: "DeploymentContext | None" = None) -> str:
    """Workaround template parameterized by product type."""
    from fs_report.deployment_context import get_workaround_template

    mitigations = get_workaround_template(ctx)
    return (
        f"1-3 sentences: if no straightforward upgrade is available, suggest "
        f"mitigations such as {mitigations}. "
        f'If a direct upgrade is available, state "Upgrade recommended."'
    )


def _applicability_warning() -> str:
    """False-positive NVD warning block for portfolio/project prompts."""
    return (
        "## Applicability Warning\n"
        "Some NVD matches may be false positives (e.g., openwrt/libc matched "
        "to glibc CVEs, or BoringSSL matched to OpenSSL CVEs).\n"
        "When the NVD product name differs from the scanned component, flag "
        "it as a potential false positive."
    )


# ── System message & combined wrapper builders ──────────────────────


def build_system_message(ctx: "DeploymentContext | None" = None) -> str:
    """Build the LLM system message, parameterized by deployment context."""
    from fs_report.deployment_context import get_persona

    persona = get_persona(ctx)
    return (
        f"You are a {persona}. "
        "Always ground your advice in the provided data — do not speculate beyond what the "
        "evidence supports. "
        "When NVD fix version data is provided, USE IT: cross-reference the installed "
        "component version against the NVD affected ranges and state the exact minimum "
        "fixed version. CRITICAL RULE: when the data says a version is 'FIXED in >= X', "
        "then X is safe to recommend. But when it says a version is 'STILL VULNERABLE' "
        "or 'affects up to and including X', then X is NOT a fix — the fix must be a "
        "version AFTER X. Never recommend a version that is marked as vulnerable. "
        "When NVD data is absent, draw on your knowledge of well-known open-source "
        "libraries (e.g. OpenSSL, busybox, curl, zlib, Linux kernel) to recall specific "
        "patch versions from security advisories. "
        "Only fall back to 'verify latest stable release' if you have no version data at all. "
        "Cite the source of your version recommendation (NVD, vendor advisory, or general "
        "knowledge) to help the reader calibrate trust. "
        "Format responses exactly as instructed."
    )


def build_combined_analysis_wrapper(ctx: "DeploymentContext | None" = None) -> str:
    """Build the combined analysis wrapper, parameterized by deployment context."""
    from fs_report.deployment_context import build_context_section, get_persona

    persona = get_persona(ctx)
    context_section = build_context_section(ctx)
    context_block = f"\n{context_section}\n" if context_section else ""
    workaround_examples = _workaround_block(ctx)

    return (
        f"You are a {persona}. Below is all available data for a "
        f"remediation action.{context_block} Produce TWO sections:\n\n"
        "**Section 1 — Structured Assessment** (one field per line, exact format):\n"
        f"VERDICT: <affected | not_affected | uncertain — {_verdict_block()}>\n"
        "FIX_VERSION: <correct fix version for the INSTALLED branch/series, or "
        '"none" if not affected. CRITICAL: if NVD lists a fix for a different '
        "branch (e.g. 4.19.x) but the installed version is on a different series "
        "(e.g. 6.6.x), find the correct fix for the installed series. "
        "Do NOT recommend cross-branch downgrades.>\n"
        "CONFIDENCE: <high | medium | low>\n"
        "RATIONALE: <1 sentence explaining the verdict>\n"
        "GUIDANCE: <1-2 sentence actionable upgrade/verification guidance>\n\n"
        f"WORKAROUNDS: <{workaround_examples} Numbered list. Say 'none' if not possible.>\n"
        "BREAKING_CHANGES: <key breaking changes between current and fix version. "
        "API changes, removed features, config format changes. Say 'none expected' "
        "for patch-level.>\n\n"
        "**Section 2 — Detailed Analysis** (after a `---` separator, in markdown):\n"
        "1. **Key Finding** — Is this component actually affected? Check library "
        "identity first: does the NVD product match the scanned component, or is "
        "this a false-positive CPE match (e.g., glibc CVE matched to musl)?\n"
        "2. **Verification Steps** — Exact shell commands to confirm\n"
        "3. **Remediation Plan** — If affected: upgrade path, breaking-change risks, "
        "regression tests. If not affected: how to document and close.\n"
        "4. **Risk if Deferred** — What happens if this is not addressed?\n"
        "5. **References** — Relevant links and advisories\n"
        "6. **Environmental Controls & Workarounds** — WAF rules, config changes, "
        "network segmentation that mitigate the vulnerability without upgrading.\n"
        "7. **Upgrade Impact** — Breaking changes, migration steps, and regression "
        "risks for the recommended upgrade path.\n\n"
        "Be specific — cite exact versions, function names, and commands.\n\n---\n\n"
    )


# System message for all LLM calls — establishes persona, constraints, and
# the fix-version guardrail to reduce hallucinated version numbers.
_ANALYSIS_WRAPPER = (
    "Below is a structured remediation prompt for a security vulnerability. "
    "Produce a detailed analysis in markdown covering:\n\n"
    "1. **Key Finding** — Is this component actually affected? Why or why not?\n"
    "2. **Verification Steps** — Exact shell commands to confirm the assessment\n"
    "3. **Remediation Plan** — If affected: upgrade path, breaking-change risks, "
    "regression tests. If not affected: how to document and close.\n"
    "4. **Risk if Deferred** — What happens if this is not fixed?\n"
    "5. **References** — Relevant links and advisories\n\n"
    "Be specific and actionable — cite exact versions, function names, and commands. "
    "Synthesize the data; do not repeat it verbatim.\n\n---\n\n"
)

# Backward-compatible aliases — module-level constants built with default context
SYSTEM_MESSAGE = build_system_message()
_COMBINED_ANALYSIS_WRAPPER = build_combined_analysis_wrapper()

# Scoring methodology block — appended to portfolio/project prompts so the
# LLM can reason about (and validate) the pre-computed priority bands.
# Built dynamically from the active scoring configuration.
_SCORING_METHODOLOGY_CACHE: str | None = None


def get_scoring_methodology(scoring_config: dict | None = None) -> str:
    """Return a scoring methodology text block for LLM prompts.

    Uses the dynamic builder from triage_prioritization when available,
    falling back to a sensible default when the transform module is not loaded.

    Args:
        scoring_config: Active scoring configuration dict (from ``_build_scoring_config``).
            Pass this when the actual gates/weights are known to ensure prompts
            match the configuration in use.
    """
    global _SCORING_METHODOLOGY_CACHE  # noqa: PLW0603
    try:
        from fs_report.transforms.pandas.triage_prioritization import (
            _build_scoring_methodology,
        )

        result = _build_scoring_methodology(scoring_config)
        _SCORING_METHODOLOGY_CACHE = result
        return result
    except ImportError:
        pass

    # Fallback: return cached or default static text
    if _SCORING_METHODOLOGY_CACHE is not None:
        return _SCORING_METHODOLOGY_CACHE
    return (
        "## Scoring Methodology\n"
        "Findings are prioritized using a tiered-gates model.\n"
        "See report configuration for gate definitions and additive scoring weights."
    )


# Backward-compatible alias for any external callers that reference the constant
SCORING_METHODOLOGY = get_scoring_methodology()


class LLMClient:
    """
    LLM client for generating remediation guidance.

    Supports Anthropic, OpenAI, GitHub Copilot, and Google Gemini providers
    with SQLite-backed result caching. Model tiering: a rich model for
    summaries and a fast model for bulk component guidance.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        cache_ttl: int = 0,
        provider: str | None = None,
        model_high: str | None = None,
        model_low: str | None = None,
        deployment_context: Any | None = None,
        cache_scope: str | None = None,
    ) -> None:
        """
        Initialize the LLM client.

        Args:
            cache_dir: Directory for SQLite cache. Defaults to ~/.fs-report/
            cache_ttl: Cache TTL in seconds. 0 = no caching (always regenerate).
            provider: LLM provider override ("anthropic", "openai", "copilot", "gemini").
                      Auto-detected from env vars if not set.
            model_high: Override for the summary model (high-capability tier).
            model_low: Override for the component model (fast/cheap tier).
            deployment_context: Optional DeploymentContext for prompt customization.
            cache_scope: Tenant-boundary token (see ``build_tenant_scope``) mixed
                into every project-scoped narrative cache key so one account's
                AI text is never served to another account sharing the local
                ``cache.db``. Optional; per-item project identity provides the
                primary isolation, this adds the account boundary on top.
        """
        self._deployment_ctx = deployment_context
        self._cache_scope = (cache_scope or "").strip()

        # Resolve provider and API key
        self._provider, self.api_key = self._detect_provider(provider)
        default_high, default_low = MODEL_MAP[self._provider]
        self._summary_model = model_high or default_high
        self._component_model = model_low or default_low

        logger.info(
            f"LLM provider: {self._provider} (models: {self._summary_model}, {self._component_model})"
        )

        # Create the appropriate client
        self.client: Any = self._create_client()

        # Set up cache
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".fs-report"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "cache.db"
        self.cache_ttl = cache_ttl
        self._init_cache_tables()

        self._call_count = 0
        self._cached_count = 0
        # Per-model token usage accumulated from provider `usage` objects —
        # a single client can call both the summary and component tiers in
        # one run, so totals are kept per model, not flat.
        self._usage_by_model: dict[str, dict[str, int]] = {}
        # Snapshot of what record_usage_metadata has already reported, so
        # repeat calls contribute only the delta (never double-count).
        self._usage_reported: dict[str, dict[str, int]] = {}

        if self.cache_ttl > 0:
            logger.info(
                f"AI cache enabled (TTL: {self.cache_ttl}s, DB: {self.db_path})"
            )
        else:
            logger.info("AI cache disabled (TTL=0, will regenerate every run)")

    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the cache database with a 30s busy timeout."""
        return sqlite3.connect(str(self.db_path), timeout=30.0)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        # `with conn:` alone commits/rolls back but leaks the FD until cyclic
        # GC runs. On macOS (default ulimit -n = 256) a batch of ~100 AI
        # calls exhausts FDs before GC triggers, then the first lazy import
        # after the batch (e.g. pandas.core.methods.to_dict) fails with
        # "OSError: [Errno 24] Too many open files".
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_cache_tables(self) -> None:
        """Ensure remediation cache tables exist and are at the current schema.

        Owns the AI narrative tables (``cve_remediations`` and
        ``ai_summary_cache``) outright: they are intentionally NOT declared in
        ``sqlite_cache.SCHEMA_SQL`` so a concurrent ``SQLiteCache`` init cannot
        recreate them under an older, unscoped layout. The generic project-blind
        fact tables (``cve_detail_cache`` / ``exploit_detail_cache``) are shared
        and left untouched by the version purge.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            # Create the stable tables first (including the unchanged
            # ai_summary_cache and the LLM-owned schema-version marker) so the
            # version purge below can DELETE from ai_summary_cache even on a
            # brand-new DB. A dedicated meta row is used rather than PRAGMA
            # user_version because cache.db is shared with SQLiteCache when no
            # domain is configured, and user_version is a single file-global int
            # the two subsystems would clobber.
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS llm_cache_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                CREATE TABLE IF NOT EXISTS cve_detail_cache (
                    finding_id TEXT PRIMARY KEY,
                    cve_metadata TEXT,
                    fetched_at TEXT
                );
                CREATE TABLE IF NOT EXISTS exploit_detail_cache (
                    finding_id TEXT PRIMARY KEY,
                    exploit_metadata TEXT,
                    fetched_at TEXT
                );
                CREATE TABLE IF NOT EXISTS ai_summary_cache (
                    cache_key TEXT PRIMARY KEY,
                    scope TEXT,
                    summary_text TEXT,
                    generated_by TEXT,
                    generated_at TEXT
                );
            """)
            row = conn.execute(
                "SELECT value FROM llm_cache_meta WHERE key = 'schema_version'"
            ).fetchone()
            stored_version = row[0] if row else None
            if stored_version != _LLM_CACHE_SCHEMA_VERSION:
                # Older entries were keyed without project/tenant scope and may
                # hold another project's/customer's AI narrative. Discard them:
                # drop cve_remediations outright (its PRIMARY KEY changes, which
                # SQLite cannot ALTER in place) and delete the narrative rows
                # from ai_summary_cache while preserving the project-blind
                # library-fact rows (identity / applicability).
                conn.execute("DROP TABLE IF EXISTS cve_remediations")
                placeholders = ",".join(["?"] * len(_FACT_SUMMARY_SCOPES))
                conn.execute(
                    f"DELETE FROM ai_summary_cache "  # noqa: S608 - fixed placeholders
                    f"WHERE scope IS NULL OR scope NOT IN ({placeholders})",
                    _FACT_SUMMARY_SCOPES,
                )
                conn.execute(
                    "INSERT OR REPLACE INTO llm_cache_meta (key, value) "
                    "VALUES ('schema_version', ?)",
                    (_LLM_CACHE_SCHEMA_VERSION,),
                )
            # (Re)create cve_remediations at the current schema. After a version
            # purge it was just dropped, so this makes the new composite
            # (cve_id, scope) primary key; on an up-to-date DB it is a no-op.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_remediations (
                    cve_id TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT '',
                    component_name TEXT,
                    fix_version TEXT,
                    guidance TEXT,
                    workaround TEXT,
                    code_search_hints TEXT,
                    generated_by TEXT,
                    generated_at TEXT,
                    confidence TEXT,
                    project_notes TEXT,
                    verdict TEXT DEFAULT 'affected',
                    rationale TEXT DEFAULT '',
                    PRIMARY KEY (cve_id, scope)
                )
            """)

    # =========================================================================
    # Provider helpers
    # =========================================================================

    @staticmethod
    def _detect_provider(override: str | None) -> tuple[str, str]:
        """Return (provider_name, api_key) based on override or env vars."""
        if override:
            override = override.lower()
            if override not in MODEL_MAP:
                raise ValueError(
                    f"Unknown AI provider '{override}'. "
                    f"Choose from: {', '.join(MODEL_MAP)}"
                )
            # Copilot handles auth via device flow — no env var required
            if override == "copilot":
                return "copilot", os.getenv("GITHUB_TOKEN", "")
            # Gemini supports GOOGLE_API_KEY as fallback
            if override == "gemini":
                api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
                if not api_key:
                    raise ValueError(
                        "AI provider 'gemini' requires GEMINI_API_KEY or "
                        "GOOGLE_API_KEY environment variable to be set."
                    )
                return "gemini", api_key
            env_map = dict(_PROVIDER_ENV_VARS)
            env_var = env_map[override]
            api_key = os.getenv(env_var, "")
            # Anthropic: fall back to deprecated ANTHROPIC_AUTH_TOKEN
            if not api_key and override == "anthropic":
                api_key = os.getenv(_ANTHROPIC_LEGACY_VAR, "")
                if api_key:
                    import warnings

                    warnings.warn(
                        "ANTHROPIC_AUTH_TOKEN is deprecated. "
                        "Use ANTHROPIC_API_KEY instead.",
                        DeprecationWarning,
                        stacklevel=2,
                    )
            if not api_key:
                raise ValueError(
                    f"AI provider '{override}' requires the {env_var} "
                    "environment variable to be set."
                )
            return override, api_key

        # Auto-detect: first env var found wins
        for provider, env_var in _PROVIDER_ENV_VARS:
            api_key = os.getenv(env_var, "")
            if api_key:
                return provider, api_key
        # Anthropic: fall back to deprecated ANTHROPIC_AUTH_TOKEN
        api_key = os.getenv(_ANTHROPIC_LEGACY_VAR, "")
        if api_key:
            import warnings

            warnings.warn(
                "ANTHROPIC_AUTH_TOKEN is deprecated. " "Use ANTHROPIC_API_KEY instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            return "anthropic", api_key
        # Also check GOOGLE_API_KEY as Gemini fallback
        google_key = os.getenv("GOOGLE_API_KEY", "")
        if google_key:
            return "gemini", google_key

        raise ValueError(
            "No AI provider credentials found. Set one of: "
            + ", ".join(ev for _, ev in _PROVIDER_ENV_VARS)
        )

    def _create_client(self) -> Any:
        """Create the appropriate SDK client for the resolved provider."""
        if self._provider == "anthropic":
            try:
                import anthropic

                return anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "The 'anthropic' package is required for Anthropic AI features. "
                    "Install it with: pip install anthropic"
                )
        elif self._provider == "copilot":
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "The 'openai' package is required for Copilot AI features. "
                    "Install it with: pip install openai"
                )
            from fs_report.copilot_auth import get_copilot_token

            # Preserve the original GitHub token for re-exchange on refresh
            self._github_token = self.api_key or None
            copilot_token, base_url = get_copilot_token(self._github_token)
            self.api_key = copilot_token
            self._copilot_base_url = base_url
            return openai.OpenAI(api_key=copilot_token, base_url=base_url)
        elif self._provider in ("openai", "gemini"):
            try:
                import openai

                kwargs: dict[str, Any] = {"api_key": self.api_key}
                if self._provider == "gemini":
                    kwargs["base_url"] = GEMINI_BASE_URL
                return openai.OpenAI(**kwargs)
            except ImportError:
                raise ImportError(
                    "The 'openai' package is required for OpenAI/Gemini AI features. "
                    "Install it with: pip install openai"
                )
        raise ValueError(f"Unsupported provider: {self._provider}")

    def _call_llm(self, prompt: str, model_tier: str, max_tokens: int) -> str:
        """
        Send a prompt to the configured LLM and return the response text.

        Args:
            prompt: The user message content.
            model_tier: ``"summary"`` (rich model) or ``"component"`` (fast model).
            max_tokens: Maximum tokens in the response.

        Returns:
            The assistant's response text.
        """
        model = (
            self._summary_model if model_tier == "summary" else self._component_model
        )

        system_msg = build_system_message(self._deployment_ctx)

        if self._provider == "anthropic":
            response = self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system_msg,
                messages=[{"role": "user", "content": prompt}],
            )
            self._call_count += 1
            usage = getattr(response, "usage", None)
            self._record_usage(
                model,
                getattr(usage, "input_tokens", 0),
                getattr(usage, "output_tokens", 0),
            )
            return response.content[0].text  # type: ignore[no-any-return]
        else:
            # OpenAI / Copilot / Gemini
            oai_kwargs = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": prompt},
                ],
            }
            try:
                response = self.client.chat.completions.create(**oai_kwargs)
            except Exception as exc:
                # Copilot tokens expire — retry once with a fresh token
                if self._provider == "copilot" and _is_auth_error(exc):
                    logger.info("Copilot token expired, refreshing…")
                    self._refresh_copilot_client()
                    response = self.client.chat.completions.create(**oai_kwargs)
                else:
                    raise
            self._call_count += 1
            usage = getattr(response, "usage", None)
            self._record_usage(
                model,
                getattr(usage, "prompt_tokens", 0),
                getattr(usage, "completion_tokens", 0),
            )
            return response.choices[0].message.content or ""

    def _record_usage(self, model: str, input_tokens: Any, output_tokens: Any) -> None:
        """Accumulate token usage for ``model``.

        Provider/mocked responses may omit ``usage`` or carry non-numeric
        fields — those count as 0, never raise (usage reporting must not
        break a run).
        """
        in_tokens = _usage_int(input_tokens)
        out_tokens = _usage_int(output_tokens)
        if not in_tokens and not out_tokens:
            # No usage reported (provider omitted it / mocked response) —
            # don't create a misleading 0/0 model bucket.
            return
        bucket = self._usage_by_model.setdefault(
            model, {"input_tokens": 0, "output_tokens": 0}
        )
        bucket["input_tokens"] += in_tokens
        bucket["output_tokens"] += out_tokens

    def record_usage_metadata(self, additional_data: dict[str, Any] | None) -> None:
        """Merge this client's UN-REPORTED token usage into
        ``additional_data["_ai_usage"]``.

        Transforms call this after their LLM work; the engine copies the
        accumulated value into ``RecipeResult.stats["ai_usage"]`` so raw
        token counts reach CLI/headless output (an external integration
        computes dollar cost from them server-side). Merging — not
        overwriting — supports transforms that use more than one client
        (e.g. remediation guidance + combined-analysis passes). Only the
        delta since the previous call is contributed, so a repeat invocation
        (retry paths, future refactors) can never double-count this client's
        lifetime totals; ``get_stats()`` stays lifetime-cumulative.
        """
        if additional_data is None or not self._usage_by_model:
            return
        delta_models: dict[str, dict[str, int]] = {}
        for model, counts in self._usage_by_model.items():
            reported = self._usage_reported.get(
                model, {"input_tokens": 0, "output_tokens": 0}
            )
            d_in = counts["input_tokens"] - reported["input_tokens"]
            d_out = counts["output_tokens"] - reported["output_tokens"]
            if d_in or d_out:
                delta_models[model] = {"input_tokens": d_in, "output_tokens": d_out}
        if not delta_models:
            return
        merge_ai_usage(
            additional_data.setdefault(
                "_ai_usage", {"input_tokens": 0, "output_tokens": 0, "models": {}}
            ),
            {
                "input_tokens": sum(m["input_tokens"] for m in delta_models.values()),
                "output_tokens": sum(m["output_tokens"] for m in delta_models.values()),
                "models": delta_models,
            },
        )
        self._usage_reported = {
            model: dict(counts) for model, counts in self._usage_by_model.items()
        }

    def _refresh_copilot_client(self) -> None:
        """Re-exchange credentials and rebuild the OpenAI client for Copilot."""
        import openai

        from fs_report.copilot_auth import get_copilot_token

        copilot_token, base_url = get_copilot_token(self._github_token)
        self.api_key = copilot_token
        self._copilot_base_url = base_url
        self.client = openai.OpenAI(api_key=copilot_token, base_url=base_url)

    def _context_section(self) -> str:
        """Return deployment context section for prompts, or empty string."""
        from fs_report.deployment_context import build_context_section

        return build_context_section(self._deployment_ctx)

    def _is_fresh(self, generated_at: str | None) -> bool:
        """Check if a cached entry is still within the TTL window."""
        if self.cache_ttl <= 0 or not generated_at:
            return False
        try:
            cached_time = datetime.fromisoformat(generated_at)
            if cached_time.tzinfo is None:
                cached_time = cached_time.replace(tzinfo=UTC)
            age_seconds = (datetime.now(UTC) - cached_time).total_seconds()
            return age_seconds < self.cache_ttl
        except (ValueError, TypeError):
            return False

    # =========================================================================
    # Cache Operations
    # =========================================================================

    def _narrative_scope(self, project_ref: str | None) -> str | None:
        """Return the effective cache scope for a project-specific narrative
        entry, or ``None`` when the entry must NOT be cached (bypass).

        ``project_ref`` must be a STABLE project identity (a project-version id,
        or a joined set of them for portfolio/multi-project deliverables) — never
        a human-chosen name like ``project_name``, which is caller-controlled and
        collides across customers. When no stable identity is present the method
        returns ``None`` so the caller regenerates instead of risking a
        cross-project cache hit. The tenant token (``self._cache_scope``) is
        folded in so the same project id under two accounts never collides.
        """
        ref = normalize_project_ref(project_ref)
        if not ref:
            return None
        return _scope_digest(f"{self._cache_scope}\x1f{ref}")

    def _component_scope(
        self, project_ref: str | None, component_name: str, component_version: str
    ) -> str | None:
        """Scope for a ``cve_remediations`` row: project+tenant identity plus the
        specific component.

        Including the component means two *different* components that happen to
        share a CVE never satisfy each other's lookup (the guidance is written
        under every CVE in the component's group, so a bare-CVE key would let
        component A's firmware-shaped guidance be returned for component B).
        Returns ``None`` (bypass) when there is no stable project identity.
        """
        base = self._narrative_scope(project_ref)
        if base is None:
            return None
        return _scope_digest(
            f"{base}\x1fcomp\x1f{component_name}\x1f{component_version}"
        )

    def get_cached_remediation(
        self, cve_id: str, *, scope: str | None = None
    ) -> dict[str, Any] | None:
        """Look up cached remediation guidance for a CVE (respects TTL).

        ``scope`` is the project+tenant identity the guidance was generated for
        (see ``_component_scope`` / ``_narrative_scope``). It is REQUIRED: this
        guidance is project-specific narrative, so without a scope there is no
        safe way to know it belongs to the requesting project. A falsy scope
        therefore skips the lookup entirely (cache bypass) rather than risk
        serving another project's text.

        Only returns an entry generated by the currently-configured component
        model, so swapping ``--ai-model-low`` forces a fresh API call.
        """
        if not scope:
            return None
        try:
            with self._connection() as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM cve_remediations WHERE cve_id = ? AND scope = ?",
                    (cve_id, scope),
                ).fetchone()
                if row:
                    row_dict = dict(row)
                    cached_model = row_dict.get("generated_by") or ""
                    if cached_model and cached_model != self._component_model:
                        logger.debug(
                            f"Remediation cache model mismatch for {cve_id}: "
                            f"cached={cached_model}, requested={self._component_model}"
                        )
                    elif self._is_fresh(row_dict.get("generated_at")):
                        # Backwards compat: old cache entries may lack verdict/rationale
                        row_dict.setdefault("verdict", "affected")
                        row_dict.setdefault("rationale", "")
                        logger.debug(f"Remediation cache hit: {cve_id}")
                        return row_dict
                    else:
                        logger.debug(
                            f"Remediation cache expired for {cve_id} "
                            f"(generated_at={row_dict.get('generated_at')}, "
                            f"ttl={self.cache_ttl})"
                        )
                else:
                    logger.debug(
                        f"Remediation cache miss: {cve_id} "
                        f"(not in DB: {self.db_path})"
                    )
        except sqlite3.OperationalError:
            # Table may not exist yet (e.g. shared DB without LLM tables)
            try:
                self._init_cache_tables()
            except sqlite3.OperationalError as exc:
                logger.warning(f"Remediation cache unavailable: {exc}")
        return None

    def cache_remediation(
        self, cve_id: str, remediation: dict[str, Any], *, scope: str | None = None
    ) -> None:
        """Store remediation guidance in the cache under ``scope``.

        ``scope`` (project+tenant identity) is REQUIRED — this text is
        project-specific narrative and must never be written to the shared,
        cross-project keyspace. A falsy scope skips the write (the guidance is
        still returned to the current caller; it just isn't persisted).

        ``generated_by`` always reflects the active component model so that
        ``get_cached_remediation`` can reject entries written by a different
        model after a model swap. Callers may pass a ``generated_by`` override
        (e.g. tests) and it is honored as-is.
        """
        if not scope:
            return
        try:
            with self._connection() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO cve_remediations
                       (cve_id, scope, component_name, fix_version, guidance,
                        workaround, code_search_hints, generated_by, generated_at,
                        confidence, project_notes, verdict, rationale)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        cve_id,
                        scope,
                        remediation.get("component_name", ""),
                        remediation.get("fix_version", ""),
                        remediation.get("guidance", ""),
                        remediation.get("workaround", ""),
                        remediation.get("code_search_hints", ""),
                        remediation.get("generated_by") or self._component_model,
                        datetime.now(UTC).isoformat(),
                        remediation.get("confidence", "medium"),
                        remediation.get("project_notes", ""),
                        remediation.get("verdict", "affected"),
                        remediation.get("rationale", ""),
                    ),
                )
        except sqlite3.OperationalError:
            try:
                self._init_cache_tables()
                # Retry once after creating tables
                self.cache_remediation(cve_id, remediation, scope=scope)
            except sqlite3.OperationalError as exc:
                logger.warning(f"Remediation cache write failed: {exc}")

    def get_cached_summary(self, cache_key: str) -> str | None:
        """Look up cached AI summary (portfolio or project level, respects TTL)."""
        try:
            with self._connection() as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM ai_summary_cache WHERE cache_key = ?", (cache_key,)
                ).fetchone()
                if row:
                    row_dict = dict(row)
                    if self._is_fresh(row_dict.get("generated_at")):
                        logger.debug(f"AI summary cache hit: {cache_key}")
                        return row_dict.get("summary_text")
                    logger.debug(f"AI summary cache expired: {cache_key}")
        except sqlite3.OperationalError:
            try:
                self._init_cache_tables()
            except sqlite3.OperationalError as exc:
                logger.warning(f"AI summary cache unavailable: {exc}")
        return None

    def cache_summary(
        self, cache_key: str, scope: str, summary_text: str, model: str
    ) -> None:
        """Store an AI summary in the cache."""
        try:
            with self._connection() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO ai_summary_cache
                       (cache_key, scope, summary_text, generated_by, generated_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        cache_key,
                        scope,
                        summary_text,
                        model,
                        datetime.now(UTC).isoformat(),
                    ),
                )
        except sqlite3.OperationalError:
            try:
                self._init_cache_tables()
                self.cache_summary(cache_key, scope, summary_text, model)
            except sqlite3.OperationalError as exc:
                logger.warning(f"AI summary cache write failed: {exc}")

    def get_cached_cve_detail(self, finding_id: str) -> dict[str, Any] | None:
        """Look up cached CVE detail metadata."""
        try:
            with self._connection() as conn:
                row = conn.execute(
                    "SELECT cve_metadata FROM cve_detail_cache WHERE finding_id = ?",
                    (finding_id,),
                ).fetchone()
                if row and row[0]:
                    result: dict[str, Any] = json.loads(row[0])
                    return result
        except sqlite3.OperationalError:
            try:
                self._init_cache_tables()
            except sqlite3.OperationalError as exc:
                logger.warning(f"CVE detail cache unavailable: {exc}")
        return None

    def cache_cve_detail(self, finding_id: str, metadata: Any) -> None:
        """Store CVE detail metadata in the cache."""
        try:
            with self._connection() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO cve_detail_cache
                       (finding_id, cve_metadata, fetched_at)
                       VALUES (?, ?, ?)""",
                    (
                        finding_id,
                        json.dumps(metadata, default=str),
                        datetime.now(UTC).isoformat(),
                    ),
                )
        except sqlite3.OperationalError:
            try:
                self._init_cache_tables()
                self.cache_cve_detail(finding_id, metadata)
            except sqlite3.OperationalError as exc:
                logger.warning(f"CVE detail cache write failed: {exc}")

    def get_cached_exploit_detail(self, finding_id: str) -> dict[str, Any] | None:
        """Look up cached exploit detail metadata."""
        try:
            with self._connection() as conn:
                row = conn.execute(
                    "SELECT exploit_metadata FROM exploit_detail_cache WHERE finding_id = ?",
                    (finding_id,),
                ).fetchone()
                if row and row[0]:
                    result: dict[str, Any] = json.loads(row[0])
                    return result
        except sqlite3.OperationalError:
            try:
                self._init_cache_tables()
            except sqlite3.OperationalError as exc:
                logger.warning(f"Exploit detail cache unavailable: {exc}")
        return None

    def cache_exploit_detail(self, finding_id: str, metadata: Any) -> None:
        """Store exploit detail metadata in the cache."""
        try:
            with self._connection() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO exploit_detail_cache
                       (finding_id, exploit_metadata, fetched_at)
                       VALUES (?, ?, ?)""",
                    (
                        finding_id,
                        json.dumps(metadata, default=str),
                        datetime.now(UTC).isoformat(),
                    ),
                )
        except sqlite3.OperationalError:
            try:
                self._init_cache_tables()
                self.cache_exploit_detail(finding_id, metadata)
            except sqlite3.OperationalError as exc:
                logger.warning(f"Exploit detail cache write failed: {exc}")

    # =========================================================================
    # Bullet-point formatters (replace verbose JSON dumps in prompts)
    # =========================================================================

    @staticmethod
    def _format_projects_bullet(projects: list[dict[str, Any]]) -> str:
        """Format project summaries as compact bullet points."""
        lines = []
        for p in projects:
            name = p.get("project_name", "Unknown")
            total = p.get("total_findings", 0)
            bands = []
            for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = p.get(band, 0)
                if count:
                    bands.append(f"{count} {band}")
            band_str = ", ".join(bands) if bands else "no findings"
            avg = p.get("avg_score", 0)
            lines.append(
                f"- **{name}** -- {total} findings ({band_str}), avg score: {avg}"
            )
        return "\n".join(lines) if lines else "No project data available."

    @staticmethod
    def _format_components_bullet(components: list[dict[str, Any]]) -> str:
        """Format component summaries as compact bullet points."""
        lines = []
        for c in components:
            name = c.get("component_name", c.get("component", "Unknown"))
            version = c.get("component_version", "")
            label = (
                f"{name}:{version}" if version and ":" not in str(name) else str(name)
            )
            total = c.get("total_findings", c.get("findings_count", 0))
            bands = []
            for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = c.get(band, 0)
                if count:
                    bands.append(f"{count} {band}")
            band_str = ", ".join(bands) if bands else "no findings"
            avg = c.get("avg_score", "")
            line = f"- **{label}** -- {total} findings ({band_str})"
            if avg:
                line += f", avg score: {avg}"
            # Exploitability signals
            signals: list[str] = []
            g1 = c.get("gate_1_count", 0)
            g2 = c.get("gate_2_count", 0)
            if g1:
                signals.append(f"{g1} GATE_1")
            if g2:
                signals.append(f"{g2} GATE_2")
            exploit = c.get("exploit_count", 0)
            if exploit:
                signals.append(f"{int(exploit)} exploited")
            kev = c.get("kev_count", 0)
            if kev:
                signals.append(f"{int(kev)} KEV")
            reachable = c.get("reachable_count", 0)
            if reachable:
                signals.append(f"{int(reachable)} reachable")
            max_epss = c.get("max_epss", 0)
            if max_epss and float(max_epss) > 0.5:
                signals.append(f"EPSS max: {float(max_epss) * 100:.0f}th pctl")
            if signals:
                line += f" | {', '.join(signals)}"
            lines.append(line)
        return "\n".join(lines) if lines else "No component data available."

    @staticmethod
    def _format_project_components_bullet(
        components: list[dict[str, Any]],
    ) -> str:
        """Format project-level component summaries as compact bullet points."""
        lines = []
        for c in components:
            comp = c.get("component", "Unknown")
            count = c.get("findings_count", 0)
            bands_list = c.get("bands", [])
            band_counts: dict[str, int] = {}
            for b in bands_list:
                band_counts[b] = band_counts.get(b, 0) + 1
            band_parts = []
            for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if band_counts.get(band, 0):
                    band_parts.append(f"{band_counts[band]} {band}")
            band_str = ", ".join(band_parts) if band_parts else "no findings"
            reach_cves = c.get("reachable_cves", [])
            vuln_fns = c.get("vuln_functions", [])
            line = f"- **{comp}** -- {count} findings ({band_str})"
            if reach_cves:
                line += f", {len(reach_cves)} reachable"
            if vuln_fns:
                line += f", vuln functions: {', '.join(str(f) for f in vuln_fns)}"
            # Exploitability signals
            signals: list[str] = []
            gate_cts = c.get("gate_counts", {})
            g1 = gate_cts.get("GATE_1", 0) if isinstance(gate_cts, dict) else 0
            g2 = gate_cts.get("GATE_2", 0) if isinstance(gate_cts, dict) else 0
            if g1:
                signals.append(f"{g1} GATE_1")
            if g2:
                signals.append(f"{g2} GATE_2")
            exploit = c.get("exploit_count", 0)
            if exploit:
                signals.append(f"{int(exploit)} exploited")
            kev = c.get("kev_count", 0)
            if kev:
                signals.append(f"{int(kev)} KEV")
            max_epss = c.get("max_epss", 0)
            if max_epss and float(max_epss) > 0.5:
                signals.append(f"EPSS max: {float(max_epss) * 100:.0f}th pctl")
            if signals:
                line += f" | {', '.join(signals)}"
            lines.append(line)
        return "\n".join(lines) if lines else "No component data available."

    # =========================================================================
    # Portfolio Summary (Sonnet)
    # =========================================================================

    def generate_portfolio_summary(
        self,
        portfolio_summary: dict[str, Any],
        project_summaries: list[dict[str, Any]],
        top_components: list[dict[str, Any]],
        reachability_summary: dict[str, Any] | None = None,
        nvd_snippets_map: dict[str, str] | None = None,
        project_ai_summaries: dict[str, str] | None = None,
        project_scope: str | None = None,
    ) -> str:
        """
        Generate a strategic portfolio-level remediation summary.

        Uses Sonnet for rich analysis. Cached by a hash of the input data.

        Args:
            nvd_snippets_map: Optional map of "component:version" -> NVD fix snippet.
            project_ai_summaries: Optional map of project_name -> AI summary text
                (from project-level LLM calls, for bottom-up cascade).
            project_scope: Stable identity of the project SET in this portfolio
                (e.g. the joined project_version_ids). Folded into the cache key
                so two different portfolios with coincidentally-equal aggregate
                counts never collide and swap strategic narrative. The summary
                names specific projects, so this is the tenant/project boundary.
        """
        # Build a stable cache key from the input data. The summary names
        # specific projects, so it is only cached under a project scope; without
        # one (scope is None) the cache is bypassed and the summary regenerated.
        scope = self._narrative_scope(project_scope)
        ctx_hash = self._deployment_ctx.context_hash() if self._deployment_ctx else ""
        key_data = json.dumps(
            {
                "portfolio": portfolio_summary,
                "reach": reachability_summary,
                "has_nvd": bool(nvd_snippets_map),
                "has_proj_ai": bool(project_ai_summaries),
                "ctx": ctx_hash,
                "scope": scope,
                "provider": self._provider,
                "model": self._summary_model,
            },
            sort_keys=True,
            default=str,
        )
        cache_key = f"portfolio:{hashlib.sha256(key_data.encode()).hexdigest()[:16]}"

        # Check cache
        if scope is not None:
            cached = self.get_cached_summary(cache_key)
            if cached is not None:
                self._cached_count += 1
                logger.info("Portfolio summary loaded from cache")
                return cached

        prompt = self._build_portfolio_prompt(
            portfolio_summary,
            project_summaries,
            top_components,
            reachability_summary,
            nvd_snippets_map=nvd_snippets_map,
            project_ai_summaries=project_ai_summaries,
        )

        try:
            result_text = self._call_llm(prompt, "summary", MAX_PORTFOLIO_TOKENS)
            if scope is not None:
                self.cache_summary(
                    cache_key, "portfolio", result_text, self._summary_model
                )
            return result_text
        except Exception as e:
            logger.error(f"Portfolio summary generation failed: {e}")
            return f"AI summary unavailable: {e}"

    def _build_portfolio_prompt(
        self,
        portfolio_summary: dict[str, Any],
        project_summaries: list[dict[str, Any]],
        top_components: list[dict[str, Any]],
        reachability_summary: dict[str, Any] | None = None,
        nvd_snippets_map: dict[str, str] | None = None,
        project_ai_summaries: dict[str, str] | None = None,
    ) -> str:
        """Build the prompt for portfolio-level summary."""
        # Truncate data to keep prompt reasonable
        top_projects = project_summaries[:10]
        top_comps = top_components[:10]

        reach_section = ""
        if reachability_summary:
            reach_section = f"""
## Reachability Analysis
- Reachable (confirmed exploitable code paths): {reachability_summary.get('reachable', 0)}
- Unreachable (code not reachable in deployed binaries): {reachability_summary.get('unreachable', 0)}
- Inconclusive (reachability unknown): {reachability_summary.get('unknown', 0)}
- Key vulnerable functions found: {', '.join(reachability_summary.get('top_vuln_functions', [])[:10]) or 'None identified'}

Note: "Reachable" means static/binary analysis confirmed the vulnerable function exists in and is callable from the deployed firmware. This is the strongest signal for real-world exploitability.
"""

        # VEX status summary
        vex_section = ""
        vex_counts = portfolio_summary.get("vex_status_counts", {})
        vex_not_triaged = portfolio_summary.get("vex_not_triaged", 0)
        if vex_counts or vex_not_triaged:
            vex_lines = ["\n## VEX / Triage Status"]
            if vex_not_triaged:
                vex_lines.append(f"- Not yet triaged: {vex_not_triaged}")
            for status, count in sorted(vex_counts.items(), key=lambda x: -x[1]):
                vex_lines.append(f"- {status}: {count}")
            vex_section = "\n".join(vex_lines) + "\n"

        # Gate counts for highest-priority section
        g1 = portfolio_summary.get("gate_1_count", 0)
        g2 = portfolio_summary.get("gate_2_count", 0)

        gate_section = ""
        if g1 or g2:
            gate_section = f"""
## Highest Priority: GATE_1 + GATE_2 Findings
- GATE_1 (CRITICAL): {g1} findings — reachable + exploited/KEV vulnerabilities
- GATE_2 (HIGH): {g2} findings — network-accessible + high EPSS or exploit available

These are the most urgent findings. Focus remediation here first.
"""

        return f"""Analyze this vulnerability triage data and provide strategic remediation guidance.

## Portfolio Overview
- Total findings: {portfolio_summary.get('total', 0)}
- CRITICAL: {portfolio_summary.get('CRITICAL', 0)}, HIGH: {portfolio_summary.get('HIGH', 0)}, MEDIUM: {portfolio_summary.get('MEDIUM', 0)}, LOW: {portfolio_summary.get('LOW', 0)}, INFO: {portfolio_summary.get('INFO', 0)}
- GATE_1 (must fix): {g1}, GATE_2 (should fix): {g2}
{vex_section}
{get_scoring_methodology()}
{gate_section}{reach_section}
## Components by Exploitability (ranked)
{self._format_components_bullet(top_comps)}

## Top Projects by Risk
{self._format_projects_bullet(top_projects)}
{self._build_nvd_section_for_portfolio(top_comps, nvd_snippets_map)}
{self._build_project_ai_section(top_projects, project_ai_summaries)}
{_applicability_warning()}
{self._context_section()}

Provide a concise strategic summary (3-5 paragraphs):
1. Focus on GATE_1 and GATE_2 findings as the most urgent
2. Top 3 components to remediate, ranked by exploitability (exploits, KEV, EPSS, reachability)
3. Quick wins — single upgrades resolving multiple GATE_1/GATE_2 findings
4. Recommended remediation order across projects
5. Flag any likely false-positive NVD matches (where the CVE targets a different library than the scanned component)

Be specific with component names and versions. Focus on actionable guidance."""

    # =========================================================================
    # Project Summary (Sonnet)
    # =========================================================================

    def generate_project_summary(
        self,
        project_name: str,
        findings: list[dict[str, Any]],
        band_counts: dict[str, int],
        nvd_snippets_map: dict[str, str] | None = None,
        component_guidance: dict[str, dict[str, Any]] | None = None,
        project_ref: str | None = None,
    ) -> str:
        """
        Generate a project-level remediation summary.

        Uses Sonnet for rich analysis. Cached by project name + band distribution.

        Args:
            nvd_snippets_map: Optional map of "component:version" -> NVD fix snippet.
            component_guidance: Optional map of "component:version" -> AI guidance dict
                (from component-level LLM calls, containing fix_version, confidence, etc.).
            project_ref: Stable project-version identity. Folded into the cache
                key so this summary is not shared across project versions, or
                across same-named projects in different tenants (project_name
                alone is caller-controlled and collides).
        """
        # Only cached under a project scope; without one (None) the summary,
        # which names the project, is regenerated rather than shared.
        scope = self._narrative_scope(project_ref)
        ctx_hash = self._deployment_ctx.context_hash() if self._deployment_ctx else ""
        key_data = json.dumps(
            {
                "project": project_name,
                "bands": band_counts,
                "has_nvd": bool(nvd_snippets_map),
                "has_comp_ai": bool(component_guidance),
                "ctx": ctx_hash,
                "scope": scope,
                "provider": self._provider,
                "model": self._summary_model,
            },
            sort_keys=True,
            default=str,
        )
        cache_key = f"project:{hashlib.sha256(key_data.encode()).hexdigest()[:16]}"

        if scope is not None:
            cached = self.get_cached_summary(cache_key)
            if cached is not None:
                self._cached_count += 1
                logger.info(f"Project summary for '{project_name}' loaded from cache")
                return cached

        prompt = self._build_project_prompt(
            project_name,
            findings,
            band_counts,
            nvd_snippets_map=nvd_snippets_map,
            component_guidance=component_guidance,
        )

        try:
            result_text = self._call_llm(prompt, "summary", MAX_PROJECT_TOKENS)
            if scope is not None:
                self.cache_summary(
                    cache_key, "project", result_text, self._summary_model
                )
            return result_text
        except Exception as e:
            logger.error(f"Project summary generation failed for {project_name}: {e}")
            return f"AI summary unavailable: {e}"

    def _build_project_prompt(
        self,
        project_name: str,
        findings: list[dict[str, Any]],
        band_counts: dict[str, int],
        nvd_snippets_map: dict[str, str] | None = None,
        component_guidance: dict[str, dict[str, Any]] | None = None,
    ) -> str:
        """Build the prompt for project-level summary."""
        # Group findings by component for conciseness
        component_groups: dict[str, list[dict]] = {}
        for f in findings[:50]:  # Limit to top 50 findings
            comp_key = f"{f.get('component_name', 'Unknown')}:{f.get('component_version', '?')}"
            component_groups.setdefault(comp_key, []).append(f)

        component_summary = []
        for comp_key, comp_findings in sorted(
            component_groups.items(),
            key=lambda x: (
                sum(
                    1
                    for f in x[1]
                    if f.get("priority_band", "") in ("CRITICAL", "HIGH")
                ),
                sum(f.get("triage_score", 0) for f in x[1]),
            ),
            reverse=True,
        )[:10]:
            # Collect reachability info for this component
            reachable_cves = [
                f.get("finding_id", "")
                for f in comp_findings
                if f.get("reachability_score", 0) > 0
            ]
            unreachable_count = sum(
                1 for f in comp_findings if f.get("reachability_score", 0) < 0
            )
            vuln_funcs: set[str] = set()
            for f in comp_findings:
                vf = f.get("vuln_functions", "")
                if vf:
                    vuln_funcs.update(fn.strip() for fn in vf.split(",") if fn.strip())

            # Exploitability signals for this component
            comp_exploit_count = sum(1 for f in comp_findings if f.get("has_exploit"))
            comp_kev_count = sum(1 for f in comp_findings if f.get("in_kev"))
            epss_vals = [f.get("epss_percentile", 0) for f in comp_findings]
            comp_max_epss = max(epss_vals) if epss_vals else 0
            comp_gate_counts: dict[str, int] = {}
            for f in comp_findings:
                g = f.get("gate_assignment", "NONE")
                comp_gate_counts[g] = comp_gate_counts.get(g, 0) + 1

            component_summary.append(
                {
                    "component": comp_key,
                    "findings_count": len(comp_findings),
                    "bands": [f.get("priority_band", "INFO") for f in comp_findings],
                    "cves": [f.get("finding_id", "") for f in comp_findings[:5]],
                    "reachable_cves": reachable_cves[:5],
                    "unreachable_count": unreachable_count,
                    "vuln_functions": list(vuln_funcs)[:5],
                    "exploit_count": comp_exploit_count,
                    "kev_count": comp_kev_count,
                    "max_epss": comp_max_epss,
                    "gate_counts": comp_gate_counts,
                }
            )

        # Aggregate reachability stats for the project
        reachable_total = sum(1 for f in findings if f.get("reachability_score", 0) > 0)
        unreachable_total = sum(
            1 for f in findings if f.get("reachability_score", 0) < 0
        )
        unknown_total = sum(1 for f in findings if f.get("reachability_score", 0) == 0)

        # VEX status distribution for this project's findings
        vex_dist: dict[str, int] = {}
        vex_not_triaged = 0
        for f in findings:
            raw = f.get("status")
            if raw and str(raw) not in ("", "nan", "None"):
                vex_dist[str(raw)] = vex_dist.get(str(raw), 0) + 1
            else:
                vex_not_triaged += 1
        vex_lines: list[str] = []
        if vex_not_triaged:
            vex_lines.append(f"- Not yet triaged: {vex_not_triaged}")
        for st, cnt in sorted(vex_dist.items(), key=lambda x: -x[1]):
            vex_lines.append(f"- {st}: {cnt}")
        vex_section = (
            "\n## VEX / Triage Status\n" + "\n".join(vex_lines) + "\n"
            if vex_lines
            else ""
        )

        # Gate counts for this project
        proj_gate_1 = sum(1 for f in findings if f.get("gate_assignment") == "GATE_1")
        proj_gate_2 = sum(1 for f in findings if f.get("gate_assignment") == "GATE_2")

        gate_section = ""
        if proj_gate_1 or proj_gate_2:
            gate_section = f"""
## Highest Priority: GATE_1 + GATE_2 Findings
- GATE_1 (CRITICAL): {proj_gate_1} findings — reachable + exploited/KEV vulnerabilities
- GATE_2 (HIGH): {proj_gate_2} findings — network-accessible + high EPSS or exploit available

These are the most urgent findings. Focus remediation here first.
"""

        return f"""Provide remediation guidance for project "{project_name}".

## Risk Band Distribution
{json.dumps(band_counts, indent=2)}
- GATE_1 (must fix): {proj_gate_1}, GATE_2 (should fix): {proj_gate_2}
{vex_section}
{get_scoring_methodology()}
{gate_section}
## Reachability Summary
- Reachable: {reachable_total} (vulnerable code confirmed present and callable in firmware)
- Unreachable: {unreachable_total} (vulnerable code not reachable — lower risk)
- Inconclusive: {unknown_total} (reachability not determined)

## Top Components by Exploitability
{self._format_project_components_bullet(component_summary)}
{self._build_nvd_section_for_project(component_summary, nvd_snippets_map)}
{self._build_component_ai_section(component_summary, component_guidance)}
{_applicability_warning()}

Note: "reachable" indicates CVEs where binary analysis confirmed the vulnerable code path is callable.
{self._context_section()}

Provide a concise project remediation plan (2-3 paragraphs):
1. Focus on GATE_1 and GATE_2 findings as the most urgent — which components to upgrade first
2. Recommended upgrade order ranked by exploitability (exploits, KEV, EPSS, reachability)
3. Quick wins — single upgrades resolving multiple GATE_1/GATE_2 findings
4. Flag any likely false-positive NVD matches (where the CVE targets a different library than the scanned component)

Be specific with component names and versions."""

    # =========================================================================
    # Cascade helpers (NVD + component AI → project/portfolio prompts)
    # =========================================================================

    @staticmethod
    def _build_nvd_section_for_portfolio(
        top_components: list[dict[str, Any]],
        nvd_snippets_map: dict[str, str] | None,
    ) -> str:
        """Build Known Fix Versions section for a portfolio prompt."""
        if not nvd_snippets_map:
            return ""
        lines = ["\n## Known Fix Versions (from NVD)"]
        count = 0
        for comp in top_components[:10]:
            name = comp.get("component_name", comp.get("component", "Unknown"))
            version = comp.get("component_version", "")
            comp_key = (
                f"{name}:{version}" if version and ":" not in str(name) else str(name)
            )
            snippet = nvd_snippets_map.get(comp_key, "")
            if snippet:
                first_line = snippet.strip().split("\n")[0]
                lines.append(f"- **{comp_key}**: {first_line}")
                count += 1
        if count == 0:
            return ""
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _build_project_ai_section(
        top_projects: list[dict[str, Any]],
        project_ai_summaries: dict[str, str] | None,
    ) -> str:
        """Build Project AI Summaries section for a portfolio prompt."""
        if not project_ai_summaries:
            return ""
        lines = ["\n## Project AI Summaries"]
        count = 0
        for proj in top_projects[:5]:
            proj_name = proj.get("project_name", "")
            summary = project_ai_summaries.get(proj_name, "")
            if summary:
                truncated = summary[:200] + ("..." if len(summary) > 200 else "")
                lines.append(f"- **{proj_name}**: {truncated}")
                count += 1
        if count == 0:
            return ""
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _build_nvd_section_for_project(
        component_summary: list[dict[str, Any]],
        nvd_snippets_map: dict[str, str] | None,
    ) -> str:
        """Build NVD Fix Intelligence section for a project prompt."""
        if not nvd_snippets_map:
            return ""
        lines = ["\n## NVD Fix Intelligence"]
        count = 0
        for comp in component_summary[:5]:
            comp_key = comp.get("component", "")
            snippet = nvd_snippets_map.get(comp_key, "")
            if snippet:
                # Extract first line (compact summary) for each component
                first_line = snippet.strip().split("\n")[0]
                lines.append(f"- **{comp_key}**: {first_line}")
                count += 1
        if count == 0:
            return ""
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _build_component_ai_section(
        component_summary: list[dict[str, Any]],
        component_guidance: dict[str, dict[str, Any]] | None,
    ) -> str:
        """Build Component Fix Recommendations section for a project prompt."""
        if not component_guidance:
            return ""
        lines = ["\n## Component Fix Recommendations (AI-generated)"]
        count = 0
        for comp in component_summary:
            comp_key = comp.get("component", "")
            guidance = component_guidance.get(comp_key)
            if guidance:
                fix_ver = guidance.get("fix_version", "Unknown")
                confidence = guidance.get("confidence", "medium")
                rationale = guidance.get("rationale", guidance.get("guidance", ""))
                if rationale:
                    rationale = rationale[:150]
                lines.append(
                    f"- **{comp_key}**: upgrade to {fix_ver} "
                    f"(confidence: {confidence}) — {rationale}"
                )
                count += 1
        if count == 0:
            return ""
        lines.append("")
        return "\n".join(lines)

    # =========================================================================
    # Component-Level Guidance (Haiku — full depth only)
    # =========================================================================

    def generate_component_guidance(
        self,
        component_name: str,
        component_version: str,
        cve_ids: list[str],
        cve_details: list[dict[str, Any]] | None = None,
        exploit_details: list[dict[str, Any]] | None = None,
        reachability_info: list[dict[str, Any]] | None = None,
        nvd_fix_snippet: str = "",
        project_ref: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate component-level remediation guidance.

        Uses Haiku for fast, cost-effective bulk generation.
        Checks cache first to avoid redundant calls.

        Args:
            reachability_info: List of dicts with reachability_score,
                reachability_label, vuln_functions, factors for each CVE.
            nvd_fix_snippet: Pre-formatted NVD fix version data to inject
                into the prompt (from NVDClient.format_batch_for_prompt).
            project_ref: Stable project-version identity this guidance belongs
                to. Required to cache — the guidance is shaped by this project's
                firmware reachability, so without a project id it is regenerated
                every call rather than shared across projects.

        Returns:
            Dict with fix_version, guidance, workaround, code_search_hints
        """
        scope = self._component_scope(project_ref, component_name, component_version)

        # Check cache for each CVE (scoped to this project+component).
        for cve_id in cve_ids:
            cached = self.get_cached_remediation(cve_id, scope=scope)
            if cached:
                self._cached_count += 1
                return cached

        # Build prompt with enriched data
        prompt = self._build_component_prompt(
            component_name,
            component_version,
            cve_ids,
            cve_details,
            exploit_details,
            reachability_info,
            nvd_fix_snippet,
        )

        try:
            result_text = self._call_llm(prompt, "component", MAX_COMPONENT_TOKENS)

            # Parse structured response
            remediation = self._parse_component_response(
                result_text, component_name, component_version
            )

            # Cache for each CVE (skipped when scope is None — see cache_remediation)
            for cve_id in cve_ids:
                self.cache_remediation(cve_id, remediation, scope=scope)

            return remediation

        except Exception as e:
            logger.error(
                f"Component guidance generation failed for {component_name}: {e}"
            )
            return {
                "component_name": component_name,
                "fix_version": "Unknown",
                "guidance": f"AI guidance unavailable: {e}",
                "workaround": "",
                "code_search_hints": "",
                "generated_by": "error",
                "confidence": "none",
            }

    def generate_component_identity_verdict(
        self,
        component_name: str,
        component_version: str,
        cve_ids: list[str],
        nvd_fix_snippet: str = "",
    ) -> dict[str, str]:
        """Determine whether a scanned component is the product NVD associates
        with its CVEs, or a different product that happens to share a name.

        Returns dict with keys: identity, likely_product, nvd_product,
        evidence, confidence. All values are strings; missing fields are "".
        """
        cve_section = "\n".join(f"- {cve}" for cve in cve_ids[:15])
        nvd_section = f"\n{nvd_fix_snippet}\n" if nvd_fix_snippet else ""
        prompt = f"""You are a security analyst determining whether a scanned software component is actually the product that NVD associates with its CVEs, or a *different* product that happens to share a name or path.

Scanned component: {component_name} version {component_version}

CVEs attributed to it (sample):
{cve_section}
{nvd_section}
Answer in this exact format:
IDENTITY: <confirmed | mismatched | ambiguous>
LIKELY_PRODUCT: <name of what the scanned component actually is — e.g., "musl libc">
NVD_PRODUCT: <what NVD thinks it is, based on CPEs in the CVEs — e.g., "GNU glibc">
EVIDENCE: <1–3 sentences citing CPE vendor/product, characteristic symbols, upstream repo, or other identifying signals>
CONFIDENCE: <high | medium | low>
"""
        # Cache key scoped by provider/model/deployment-context so switching
        # providers or contexts doesn't silently reuse stale verdicts.
        # Mirrors the finding-guidance cache-key pattern at llm_client.py:1898.
        ctx_hash = self._deployment_ctx.context_hash() if self._deployment_ctx else ""
        model_tag = f"{self._provider}:{self._component_model}"
        cache_key = (
            f"identity:{component_name}:{component_version}:{model_tag}:"
            f"{ctx_hash}:{','.join(sorted(cve_ids)[:15])}"
        )
        cached = self.get_cached_summary(cache_key)
        if cached is not None:
            self._cached_count += 1
            try:
                return dict(json.loads(cached))
            except Exception:
                pass  # fall through to live call on malformed cache

        response = self._call_llm(prompt, model_tier="component", max_tokens=500)
        parsed = self._parse_structured_response(
            response,
            {
                "IDENTITY": "identity",
                "LIKELY_PRODUCT": "likely_product",
                "NVD_PRODUCT": "nvd_product",
                "EVIDENCE": "evidence",
                "CONFIDENCE": "confidence",
            },
        )
        # _parse_structured_response already defaults missing fields to "" via
        # dict.fromkeys, so no further normalization needed for string fields.
        ident = parsed.get("identity", "").lower()
        parsed["identity"] = (
            ident if ident in ("confirmed", "mismatched", "ambiguous") else "ambiguous"
        )
        parsed["confidence"] = parsed.get("confidence", "").lower()

        self.cache_summary(
            cache_key,
            scope="identity",
            summary_text=json.dumps(parsed),
            model=self._component_model or "",
        )
        return parsed

    def generate_per_cve_applicability(
        self,
        component_name: str,
        component_version: str,
        likely_product: str,
        nvd_product: str,
        cve_ids: list[str],
        nvd_fix_snippet: str = "",
    ) -> dict[str, dict[str, str]]:
        """Given that the scanned component's identity differs from NVD's,
        classify each CVE as does_not_apply (CVE targets nvd_product only) or
        might_still_apply (CVE may affect likely_product too).

        Returns dict mapping cve_id -> {"verdict": ..., "rationale": ...}.
        Missing CVEs default to might_still_apply (conservative).
        """
        cve_lines = "\n".join(f"- {cve}" for cve in cve_ids)
        nvd_section = f"\n{nvd_fix_snippet}\n" if nvd_fix_snippet else ""
        prompt = f"""Scanned component: {component_name} {component_version}
This component is actually: {likely_product}
NVD CVEs were authored against: {nvd_product}

For each CVE below, determine whether it applies to {likely_product}
(the real component), not {nvd_product}. Some CVEs described as affecting
{nvd_product} may also have analogous bugs in {likely_product}; flag those
as might_still_apply. CVEs that are specific to {nvd_product}'s code paths
(unique symbols, implementation details, CPEs naming only {nvd_product})
are does_not_apply.

CVEs:
{cve_lines}
{nvd_section}
Answer with ONE LINE PER CVE in this exact format:
<CVE-ID>: <does_not_apply | might_still_apply> | <one-sentence rationale citing code path, symbol, or CPE evidence>
"""
        ctx_hash = self._deployment_ctx.context_hash() if self._deployment_ctx else ""
        model_tag = f"{self._provider}:{self._component_model}"
        cache_key = (
            f"applic:{component_name}:{component_version}:{model_tag}:"
            f"{ctx_hash}:{likely_product}:{nvd_product}:"
            f"{','.join(sorted(cve_ids))}"
        )
        cached = self.get_cached_summary(cache_key)
        if cached is not None:
            self._cached_count += 1
            try:
                return dict(json.loads(cached))
            except Exception:
                pass

        # Scale max_tokens with CVE count (~80 tokens per line).
        max_tokens = min(4000, 200 + 80 * len(cve_ids))
        response = self._call_llm(prompt, model_tier="component", max_tokens=max_tokens)
        results: dict[str, dict[str, str]] = {}
        valid_verdicts = {"does_not_apply", "might_still_apply"}
        for line in response.strip().split("\n"):
            line = line.strip()
            if not line or ":" not in line:
                continue
            cve_part, _, rest = line.partition(":")
            cve_id = cve_part.strip()
            if not cve_id.upper().startswith("CVE-"):
                continue
            # rest = "<verdict> | <rationale>"
            verdict_part, _, rationale = rest.partition("|")
            verdict = verdict_part.strip().lower()
            if verdict not in valid_verdicts:
                verdict = "might_still_apply"
            results[cve_id] = {
                "verdict": verdict,
                "rationale": rationale.strip(),
            }
        # Fill in any requested CVEs the model didn't answer for
        for cve in cve_ids:
            if cve not in results:
                results[cve] = {
                    "verdict": "might_still_apply",
                    "rationale": "LLM did not classify; defaulting to conservative verdict.",
                }

        self.cache_summary(
            cache_key,
            scope="applicability",
            summary_text=json.dumps(results),
            model=self._component_model or "",
        )
        return results

    def _build_component_prompt(
        self,
        component_name: str,
        component_version: str,
        cve_ids: list[str],
        cve_details: list[dict[str, Any]] | None = None,
        exploit_details: list[dict[str, Any]] | None = None,
        reachability_info: list[dict[str, Any]] | None = None,
        nvd_fix_snippet: str = "",
    ) -> str:
        """Build the prompt for component-level guidance."""
        cve_section = "\n".join(f"- {cve}" for cve in cve_ids[:10])

        cve_detail_section = ""
        if cve_details:
            for detail in cve_details[:5]:
                desc = detail.get("description", "No description available")
                affected = detail.get("affectedFunctions", [])
                cve_detail_section += f"\n### {detail.get('cveId', 'Unknown')}\n"
                cve_detail_section += f"Description: {desc[:500]}\n"
                if affected:
                    cve_detail_section += f"Affected functions: {', '.join(str(f) for f in affected[:10])}\n"

        exploit_section = ""
        if exploit_details:
            for exploit in exploit_details[:5]:
                exploit_section += f"\n- Source: {exploit.get('source', 'Unknown')}"
                exploit_section += f"\n  URL: {exploit.get('url', 'N/A')}"
                exploit_section += (
                    f"\n  Description: {str(exploit.get('description', ''))[:200]}"
                )

        # Build reachability section from binary analysis evidence
        reach_section = ""
        if reachability_info:
            reach_items = []
            all_vuln_funcs: set[str] = set()
            for ri in reachability_info:
                score = ri.get("reachability_score", 0)
                label = (
                    "REACHABLE"
                    if score > 0
                    else ("UNREACHABLE" if score < 0 else "INCONCLUSIVE")
                )
                cve_id = ri.get("finding_id", "Unknown")
                vuln_funcs = ri.get("vuln_functions", "")
                factors = ri.get("factors", [])

                reach_items.append(
                    f"- {cve_id}: {label} (score={score})"
                    + (f", vulnerable functions: {vuln_funcs}" if vuln_funcs else "")
                )

                # Collect all vulnerable functions from factors
                if vuln_funcs:
                    all_vuln_funcs.update(
                        fn.strip() for fn in vuln_funcs.split(",") if fn.strip()
                    )
                if isinstance(factors, list):
                    for factor in factors:
                        if isinstance(factor, dict):
                            entity_name = factor.get("entity_name", "")
                            if factor.get("entity_type") == "vuln_func" and entity_name:
                                all_vuln_funcs.add(entity_name)

            reach_section = "\n## Reachability Analysis (from binary analysis)\n"
            reach_section += "\n".join(reach_items[:10])
            if all_vuln_funcs:
                reach_section += (
                    f"\n\nVulnerable functions confirmed in firmware binaries: "
                    f"{', '.join(sorted(all_vuln_funcs)[:10])}"
                )
            reach_section += (
                "\n\nNote: REACHABLE means binary analysis confirmed these "
                "functions exist in deployed firmware and can be reached. "
                "Include these function names in CODE_SEARCH guidance."
            )

        nvd_section = ""
        if nvd_fix_snippet:
            nvd_section = f"\n{nvd_fix_snippet}\n"

        ctx_section = self._context_section()
        return f"""Provide specific fix guidance for:

Component: {component_name} version {component_version}

CVEs:
{cve_section}

{f"## CVE Details{cve_detail_section}" if cve_detail_section else ""}

{f"## Exploit Information{exploit_section}" if exploit_section else ""}

{reach_section}
{nvd_section}
{ctx_section}
IMPORTANT — Output contract:
- Produce exactly ONE response block for this component, covering all CVEs together. Do NOT emit per-CVE sections, per-CVE headers, or repeated field labels.
- Do NOT wrap field labels in markdown emphasis (no ``**FIX_VERSION:**`` — use bare ``FIX_VERSION:``).
- Each field appears exactly once. Use plain text; reserve markdown formatting for prose *inside* GUIDANCE / WORKAROUND values only.
- FIX_VERSION should be a single recommended upgrade target for the component as a whole (the highest fix that clears the largest number of listed CVEs). If CVEs require different fix versions, state the consolidated upgrade target and mention the per-CVE spread inside RATIONALE.

Respond in this exact format:
VERDICT: <affected | not_affected | uncertain — {_verdict_block()}>
FIX_VERSION: <{_fix_version_block(component_version)}>
RATIONALE: <1-2 sentences explaining why this fix or version is recommended, citing NVD data or advisories; if CVEs span multiple fix branches, summarize the spread here>
GUIDANCE: <1-2 sentence upgrade guidance for the component as a whole>
WORKAROUND: <{_workaround_block(self._deployment_ctx)}>
CODE_SEARCH: <grep/search patterns to find affected code — use specific vulnerable function names if known from reachability analysis, e.g., "grep -r 'vulnerableFunction' src/">
CONFIDENCE: <high (exact fix version confirmed via NVD data or advisory), medium (version estimated from known patterns), low (uncertain — verify independently)>"""

    @staticmethod
    def _parse_structured_response(
        response_text: str,
        field_map: dict[str, str],
    ) -> dict[str, str]:
        """Parse a structured LLM response with multi-line field support.

        Lines starting with a known ``PREFIX:`` are captured into the
        corresponding result key.  Continuation lines (that don't start
        with any known prefix) are appended to the most-recently-matched
        field so that multi-line WORKAROUND / GUIDANCE values aren't
        silently truncated.

        Args:
            response_text: Raw LLM response.
            field_map: Mapping of ``"PREFIX"`` (without colon) to result
                dict key, e.g. ``{"FIX_VERSION": "fix_version", ...}``.

        Returns:
            Dict with one entry per *field_map* value (all strings).
        """
        result: dict[str, str] = dict.fromkeys(field_map.values(), "")
        current_key: str | None = None

        for line in response_text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Tolerate markdown emphasis around the prefix (e.g.
            # ``**FIX_VERSION:** 5.16.18`` or ``*FIX_VERSION:* ...``) — the
            # LLM sometimes bolds its own field labels when asked to emit
            # per-CVE structured blocks. Strip leading/trailing ``*``/``_``
            # runs from the candidate token before prefix-matching.
            probe = line.lstrip("*_").strip()
            matched = False
            for prefix, key in field_map.items():
                if probe.startswith(f"{prefix}:"):
                    # Strip leading ``**`` the LLM may have left attached to
                    # the value itself (e.g. ``FIX_VERSION:** 5.16.18``).
                    value = probe.split(":", 1)[1].lstrip("*").strip()
                    result[key] = value
                    current_key = key
                    matched = True
                    break
            if not matched and current_key is not None:
                # Continuation line — append to the current field
                result[current_key] += " " + line

        # Trim all values
        for k in result:
            result[k] = result[k].strip()

        return result

    @staticmethod
    def _parse_combined_response(text: str) -> tuple[dict[str, str], str]:
        """Parse a combined structured + analysis response.

        The LLM produces structured fields (VERDICT, FIX_VERSION, etc.)
        followed by a ``---`` separator and a markdown analysis section.

        Returns:
            Tuple of (structured_dict, markdown_str).
        """
        field_map = {
            "VERDICT": "verdict",
            "FIX_VERSION": "fix_version",
            "CONFIDENCE": "confidence",
            "RATIONALE": "rationale",
            "GUIDANCE": "guidance",
            "WORKAROUNDS": "workarounds",
            "BREAKING_CHANGES": "breaking_changes",
        }
        # Split on first --- separator after the structured fields
        parts = text.split("\n---\n", 1)
        structured_text = parts[0] if parts else text
        markdown = parts[1].strip() if len(parts) > 1 else ""

        # If no explicit separator, look for markdown headers as boundary
        if not markdown:
            lines = text.strip().split("\n")
            struct_lines: list[str] = []
            md_lines: list[str] = []
            in_markdown = False
            for line in lines:
                if not in_markdown and (
                    line.startswith("# ") or line.startswith("## ")
                ):
                    in_markdown = True
                if in_markdown:
                    md_lines.append(line)
                else:
                    struct_lines.append(line)
            structured_text = "\n".join(struct_lines)
            markdown = "\n".join(md_lines).strip()

        parsed = LLMClient._parse_structured_response(structured_text, field_map)

        # Normalize verdict
        raw_v = parsed.get("verdict", "affected").lower().strip()
        parsed["verdict"] = (
            "not_affected"
            if raw_v
            in (
                "not_affected",
                "not affected",
                "already_fixed",
                "already fixed",
            )
            else "uncertain" if raw_v == "uncertain" else "affected"
        )
        # Normalize confidence
        raw_c = parsed.get("confidence", "medium").lower().strip()
        conf_word = raw_c.split()[0].rstrip("—-:,") if raw_c else "medium"
        parsed["confidence"] = (
            conf_word if conf_word in ("high", "medium", "low") else "medium"
        )

        return parsed, markdown

    def _parse_component_response(
        self,
        response_text: str,
        component_name: str,
        component_version: str,
    ) -> dict[str, Any]:
        """Parse structured response from component guidance prompt."""
        field_map = {
            "VERDICT": "verdict",
            "FIX_VERSION": "fix_version",
            "RATIONALE": "rationale",
            "GUIDANCE": "guidance",
            "WORKAROUND": "workaround",
            "CODE_SEARCH": "code_search_hints",
            "CONFIDENCE": "confidence",
        }
        parsed = self._parse_structured_response(response_text, field_map)

        result: dict[str, Any] = {
            "component_name": component_name,
            "generated_by": self._component_model,
            **parsed,
        }
        # Normalize confidence to just the level (high/medium/low), stripping
        # any trailing rationale the LLM may have appended after a dash.
        raw_conf = result.get("confidence", "medium").lower().strip()
        conf_word = raw_conf.split()[0].rstrip("—-:,") if raw_conf else "medium"
        result["confidence"] = (
            conf_word if conf_word in ("high", "medium", "low", "none") else "medium"
        )

        # Normalize verdict to one of: affected, not_affected, uncertain
        raw_verdict = result.get("verdict", "affected").lower().strip()
        result["verdict"] = (
            "not_affected"
            if raw_verdict in ("not_affected", "not affected")
            else "uncertain" if raw_verdict == "uncertain" else "affected"
        )

        # Post-hoc consistency check: if the rationale clearly says "wrong
        # library" / "different library" / "completely different" but the
        # verdict came back as "affected", the LLM contradicted itself.
        # Override to not_affected — the rationale is the deeper reasoning.
        if result["verdict"] == "affected":
            rationale_lower = result.get("rationale", "").lower()
            guidance_lower = result.get("guidance", "").lower()
            _combined = rationale_lower + " " + guidance_lower
            _wrong_library_signals = (
                "different library" in _combined
                or "wrong library" in _combined
                or "completely different" in _combined
                or "not the same library" in _combined
                or "does not affect" in _combined
                or "no action needed" in _combined
            )
            if _wrong_library_signals:
                logger.info(
                    f"Verdict override for {component_name}: "
                    f"rationale says wrong library but verdict was 'affected'"
                )
                result["verdict"] = "not_affected"

        # If parsing didn't work well, use the raw text as guidance
        if not result.get("guidance"):
            result["guidance"] = response_text.strip()

        return result

    # =========================================================================
    # Batch Processing for Full Depth
    # =========================================================================

    def generate_batch_component_guidance(
        self,
        components: list[dict[str, Any]],
        cve_details_map: dict[str, list[dict]] | None = None,
        exploit_details_map: dict[str, list[dict]] | None = None,
        reachability_map: dict[str, dict[str, Any]] | None = None,
        nvd_snippets_map: dict[str, str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """
        Generate guidance for multiple components (grouped by component+version).

        Args:
            components: List of dicts with component_name, component_version, cve_ids
            cve_details_map: Optional map of finding_id -> CVE detail list
            exploit_details_map: Optional map of finding_id -> exploit detail list
            reachability_map: Optional map of finding_id -> reachability info dict
                (reachability_score, reachability_label, vuln_functions, factors)
            nvd_snippets_map: Optional map of "component:version" -> formatted
                NVD fix snippet (from NVDClient.format_batch_for_prompt).

        Returns:
            Dict mapping "component:version" to remediation guidance
        """
        results: dict[str, dict[str, Any]] = {}

        from tqdm import tqdm

        cached_before = self._cached_count
        with tqdm(
            components, desc="Generating AI guidance", unit=" components"
        ) as pbar:
            for comp in pbar:
                comp_key = f"{comp['component_name']}:{comp['component_version']}"

                # Collect CVE/exploit/reachability details for this component
                cve_details = []
                exploit_details_list = []
                reach_info_list = []
                if cve_details_map:
                    for cve_id in comp.get("cve_ids", []):
                        details = cve_details_map.get(cve_id, [])
                        cve_details.extend(details)
                if exploit_details_map:
                    for cve_id in comp.get("cve_ids", []):
                        details = exploit_details_map.get(cve_id, [])
                        exploit_details_list.extend(details)
                if reachability_map:
                    for cve_id in comp.get("cve_ids", []):
                        ri = reachability_map.get(cve_id)
                        if ri:
                            reach_info_list.append(ri)

                # NVD fix data for this component
                nvd_snippet = ""
                if nvd_snippets_map:
                    nvd_snippet = nvd_snippets_map.get(comp_key, "")

                prev_cached = self._cached_count
                guidance = self.generate_component_guidance(
                    component_name=comp["component_name"],
                    component_version=comp["component_version"],
                    cve_ids=comp.get("cve_ids", []),
                    cve_details=cve_details if cve_details else None,
                    exploit_details=(
                        exploit_details_list if exploit_details_list else None
                    ),
                    reachability_info=reach_info_list if reach_info_list else None,
                    nvd_fix_snippet=nvd_snippet,
                    project_ref=comp.get("project_ref"),
                )
                results[comp_key] = guidance

                was_cached = self._cached_count > prev_cached
                cached_this_batch = self._cached_count - cached_before
                total_done = len(results)
                pbar.set_postfix_str(
                    f"{'cached' if was_cached else 'api'} "
                    f"({cached_this_batch}/{total_done} cached) "
                    f"{comp_key[:30]}"
                )
                # Only rate-limit when we actually hit the API
                if not was_cached:
                    time.sleep(0.5)

        logger.info(
            f"AI guidance complete: {self._call_count} API calls, "
            f"{self._cached_count} cache hits"
        )
        return results

    # =========================================================================
    # Finding-Level Triage Guidance (Haiku — full depth only)
    # =========================================================================

    def generate_finding_guidance(
        self,
        finding_id: str,
        prompt: str,
        project_ref: str | None = None,
    ) -> dict[str, str]:
        """
        Generate finding-level triage guidance from a pre-built prompt.

        Uses the fast (component) model. Caches per project+finding.

        Args:
            finding_id: The CVE/finding identifier (a bare CVE id, shared across
                projects — hence the mandatory project scope below).
            prompt: The complete triage prompt text (built by _build_triage_prompt).
            project_ref: Stable project-version identity. The triage prompt
                embeds this project's context (reachability, VEX status, and
                historically the project name), so the guidance is project
                narrative: it is cached per project and, without a project id,
                regenerated every call rather than shared.

        Returns:
            Dict with priority, action, rationale, fix_version, workaround,
            code_search_hints, confidence.
        """
        # ai_summary_cache "finding:" scope, keyed by project (scope) so one
        # project's triage narrative is never served to another. Model name is
        # part of the key so swapping models forces fresh LLM calls. When there
        # is no stable project id, scope is None and the cache is bypassed.
        scope = self._narrative_scope(project_ref)
        ctx_hash = self._deployment_ctx.context_hash() if self._deployment_ctx else ""
        model_tag = f"{self._provider}:{self._component_model}"
        cache_key = f"finding:{scope}:{finding_id}:{model_tag}:{ctx_hash}"
        if scope is not None:
            cached_json = self.get_cached_summary(cache_key)
            if cached_json is not None:
                self._cached_count += 1
                try:
                    result: dict[str, str] = json.loads(cached_json)
                    return result
                except (json.JSONDecodeError, TypeError):
                    pass  # stale/corrupt entry — regenerate

        try:
            result_text = self._call_llm(prompt, "component", MAX_COMPONENT_TOKENS)
            guidance = self._parse_finding_response(result_text, finding_id)
            if scope is not None:
                self.cache_summary(
                    cache_key,
                    "finding",
                    json.dumps(guidance, default=str),
                    self._component_model,
                )
            return guidance
        except Exception as e:
            logger.error(f"Finding guidance failed for {finding_id}: {e}")
            return {
                "finding_id": finding_id,
                "component_name": "",
                "priority": "",
                "applicability": "",
                "action": "",
                "rationale": "",
                "fix_version": "Unknown",
                "guidance": f"AI guidance unavailable: {e}",
                "workaround": "",
                "code_search_hints": "",
                "generated_by": "error",
                "confidence": "none",
            }

    def _parse_finding_response(
        self, response_text: str, finding_id: str
    ) -> dict[str, str]:
        """Parse structured response from finding triage prompt."""
        field_map = {
            "PRIORITY": "priority",
            "APPLICABILITY": "applicability",
            "ACTION": "action",
            "RATIONALE": "rationale",
            "FIX_VERSION": "fix_version",
            "WORKAROUND": "workaround",
            "CODE_SEARCH": "code_search_hints",
            "CONFIDENCE": "confidence",
        }
        parsed = self._parse_structured_response(response_text, field_map)

        result: dict[str, str] = {
            "finding_id": finding_id,
            "component_name": "",
            "guidance": "",
            "generated_by": "llm",
            **parsed,
        }
        result["confidence"] = result.get("confidence", "medium").lower()

        # Normalize applicability verdict (check not_affected before affected)
        raw_app = result.get("applicability", "").lower().strip()
        if "not_affected" in raw_app or "not affected" in raw_app:
            result["applicability"] = "not_affected"
        elif "uncertain" in raw_app:
            result["applicability"] = "uncertain"
        elif "affected" in raw_app:
            result["applicability"] = "affected"
        elif raw_app:
            result["applicability"] = "uncertain"

        # If parsing didn't work well, use the raw text as action
        if not result.get("action") and not result.get("priority"):
            result["action"] = response_text.strip()[:500]

        return result

    def generate_batch_finding_guidance(
        self,
        findings: Sequence[tuple[Any, ...]],
    ) -> dict[str, dict[str, str]]:
        """
        Generate triage guidance for multiple findings.

        Args:
            findings: List of ``(finding_id, prompt_text)`` or
                ``(finding_id, prompt_text, project_ref)`` tuples. The optional
                third element is the stable project-version identity used to
                scope the per-finding cache; when omitted (2-tuple) the entry is
                not cached (regenerated each call) so narrative is never shared
                across projects.

        Returns:
            Dict mapping finding_id to guidance dict.
        """
        results: dict[str, dict[str, str]] = {}

        from tqdm import tqdm

        cached_before = self._cached_count
        with tqdm(
            findings, desc="Generating AI finding guidance", unit=" findings"
        ) as pbar:
            for entry in pbar:
                finding_id, prompt = entry[0], entry[1]
                project_ref = entry[2] if len(entry) > 2 else None
                pbar.set_postfix_str(finding_id[:40])
                prev_cached = self._cached_count
                guidance = self.generate_finding_guidance(
                    finding_id, prompt, project_ref=project_ref
                )
                results[finding_id] = guidance
                was_cached = self._cached_count > prev_cached
                # Only rate-limit when we actually hit the API
                if not was_cached:
                    time.sleep(0.5)

        cached_this_batch = self._cached_count - cached_before
        if cached_this_batch > 0:
            logger.info(
                f"Finding guidance: {cached_this_batch}/{len(findings)} from cache, "
                f"{len(findings) - cached_this_batch} from API"
            )

        return results

    # =========================================================================
    # Action-Level Deep Analysis (Summary model — expensive)
    # =========================================================================

    def _action_cache_key(self, action_key: str, scope: str | None) -> str | None:
        """Compose the ai_summary_cache key for an action/combined analysis, or
        ``None`` when the analysis must NOT be cached (bypass).

        The deep analysis names its affected projects, so it is project-specific
        narrative. It is cached only under a project scope (prepended so one
        project's analysis is never served to another sharing a
        ``component:version`` action key); without a stable scope the method
        returns ``None`` and the caller regenerates rather than sharing an
        unscoped entry.
        """
        eff = self._narrative_scope(scope)
        if eff is None:
            return None
        return f"{eff}:{action_key}:{self._provider}:{self._summary_model}"

    def generate_action_analysis(
        self, action_key: str, agent_prompt: str, *, scope: str | None = None
    ) -> str:
        """Send an action's agent prompt to the summary model for deep analysis."""
        keyed = self._action_cache_key(action_key, scope)
        if keyed is not None:
            cached = self.get_cached_summary(keyed)
            if cached is not None:
                self._cached_count += 1
                return cached

        wrapped = _ANALYSIS_WRAPPER + agent_prompt
        try:
            text = self._call_llm(wrapped, "summary", MAX_ANALYSIS_TOKENS)
            if keyed is not None:
                self.cache_summary(keyed, "action", text, self._summary_model)
            return text
        except Exception as e:
            logger.error(f"Action analysis failed for {action_key}: {e}")
            return ""

    def generate_batch_action_analysis(
        self,
        actions: Sequence[tuple[Any, ...]],
    ) -> dict[str, str]:
        """Generate deep analysis for multiple actions with rate limiting.

        Each action is ``(action_key, agent_prompt)`` or
        ``(action_key, agent_prompt, project_scope)``.
        """
        results: dict[str, str] = {}
        from tqdm import tqdm

        with tqdm(actions, desc="Generating AI analysis", unit=" actions") as pbar:
            for entry in pbar:
                action_key, agent_prompt = entry[0], entry[1]
                scope = entry[2] if len(entry) > 2 else None
                pbar.set_postfix_str(action_key[:40])
                prev = self._cached_count
                results[action_key] = self.generate_action_analysis(
                    action_key, agent_prompt, scope=scope
                )
                if self._cached_count == prev:  # was not a cache hit → rate limit
                    time.sleep(0.5)
        return results

    # =========================================================================
    # Combined Analysis (single high-model pass: structured + deep analysis)
    # =========================================================================

    def generate_combined_action_analysis(
        self,
        action_key: str,
        context_prompt: str,
        cve_count: int = 1,
        *,
        scope: str | None = None,
    ) -> tuple[dict[str, str], str]:
        """Single high-model call: structured verdict + deep analysis."""
        keyed = self._action_cache_key(action_key, scope)
        if keyed is not None:
            cached = self.get_cached_summary(keyed)
            if cached is not None:
                self._cached_count += 1
                return self._parse_combined_response(cached)

        wrapped = build_combined_analysis_wrapper(self._deployment_ctx) + context_prompt
        max_tokens = min(
            MAX_ANALYSIS_TOKENS + max(cve_count - 1, 0) * TOKENS_PER_CVE,
            MAX_ANALYSIS_TOKENS_CAP,
        )
        try:
            text = self._call_llm(wrapped, "summary", max_tokens)
            if keyed is not None:
                self.cache_summary(keyed, "action_combined", text, self._summary_model)
            return self._parse_combined_response(text)
        except Exception as e:
            logger.error(f"Combined analysis failed for {action_key}: {e}")
            return {}, ""

    def generate_batch_combined_analysis(
        self,
        actions: Sequence[tuple[Any, ...]],
    ) -> dict[str, tuple[dict[str, str], str]]:
        """Batch combined analysis with rate limiting.

        Each action is ``(action_key, context_prompt, cve_count)`` or
        ``(action_key, context_prompt, cve_count, project_scope)``.
        """
        results: dict[str, tuple[dict[str, str], str]] = {}
        from tqdm import tqdm

        with tqdm(actions, desc="Generating AI analysis", unit=" actions") as pbar:
            for entry in pbar:
                action_key, context_prompt, cve_count = entry[0], entry[1], entry[2]
                scope = entry[3] if len(entry) > 3 else None
                pbar.set_postfix_str(action_key[:40])
                prev = self._cached_count
                results[action_key] = self.generate_combined_action_analysis(
                    action_key, context_prompt, cve_count=cve_count, scope=scope
                )
                if self._cached_count == prev:
                    time.sleep(0.5)
        return results

    # =========================================================================
    # Stats
    # =========================================================================

    def get_stats(self) -> dict[str, Any]:
        """Return API call, cache, and token-usage statistics.

        ``input_tokens`` / ``output_tokens`` are totals across models;
        ``models`` carries the per-model breakdown (a single client can call
        both the summary and component tiers in one run, so a flat "model"
        field would be ambiguous). Token counts are raw provider-reported
        usage — no pricing math here; cost is computed downstream.
        """
        return {
            "api_calls": self._call_count,
            "cache_hits": self._cached_count,
            "input_tokens": sum(
                m["input_tokens"] for m in self._usage_by_model.values()
            ),
            "output_tokens": sum(
                m["output_tokens"] for m in self._usage_by_model.values()
            ),
            "models": {
                model: dict(counts) for model, counts in self._usage_by_model.items()
            },
        }
