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
- Anthropic Claude (default): Sonnet for summaries, Haiku for bulk guidance
- OpenAI: GPT-4o for summaries, GPT-4o-mini for bulk guidance
- GitHub Copilot: Uses OpenAI SDK with Copilot endpoint

Provider is auto-detected from environment variables or set explicitly
via the ``provider`` parameter.

Results are cached in SQLite to avoid redundant API calls.
"""

import json
import logging
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Token limits
MAX_PORTFOLIO_TOKENS = 2000
MAX_PROJECT_TOKENS = 1500
MAX_COMPONENT_TOKENS = 800

# Provider -> (summary_model, component_model)
# Use alias IDs (e.g. "claude-opus-4-6") rather than date-pinned IDs
# (e.g. "claude-opus-4-6-20260205") so the API routes to the latest
# snapshot automatically and we never 404 on a retired model.
MODEL_MAP: dict[str, tuple[str, str]] = {
    "anthropic": ("claude-opus-4-6", "claude-haiku-4-5"),
    "openai": ("gpt-4o", "gpt-4o-mini"),
    "copilot": ("gpt-4o", "gpt-4o-mini"),
}

# Env var detection order
_PROVIDER_ENV_VARS: list[tuple[str, str]] = [
    ("anthropic", "ANTHROPIC_AUTH_TOKEN"),
    ("openai", "OPENAI_API_KEY"),
    ("copilot", "GITHUB_TOKEN"),
]

COPILOT_BASE_URL = "https://api.githubcopilot.com"

# System message for all LLM calls — establishes persona, constraints, and
# the fix-version guardrail to reduce hallucinated version numbers.
SYSTEM_MESSAGE = (
    "You are a firmware security analyst specializing in embedded device remediation. "
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

        return _build_scoring_methodology(scoring_config)
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

    Supports Anthropic, OpenAI, and GitHub Copilot providers with
    SQLite-backed result caching. Model tiering: a rich model for
    summaries and a fast model for bulk component guidance.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        cache_ttl: int = 0,
        provider: str | None = None,
        model_high: str | None = None,
        model_low: str | None = None,
    ) -> None:
        """
        Initialize the LLM client.

        Args:
            cache_dir: Directory for SQLite cache. Defaults to ~/.fs-report/
            cache_ttl: Cache TTL in seconds. 0 = no caching (always regenerate).
            provider: LLM provider override ("anthropic", "openai", "copilot").
                      Auto-detected from env vars if not set.
            model_high: Override for the summary model (high-capability tier).
            model_low: Override for the component model (fast/cheap tier).
        """
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

        if self.cache_ttl > 0:
            logger.info(
                f"AI cache enabled (TTL: {self.cache_ttl}s, DB: {self.db_path})"
            )
        else:
            logger.info("AI cache disabled (TTL=0, will regenerate every run)")

    def _init_cache_tables(self) -> None:
        """Ensure remediation cache tables exist."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cve_remediations (
                    cve_id TEXT PRIMARY KEY,
                    component_name TEXT,
                    fix_version TEXT,
                    guidance TEXT,
                    workaround TEXT,
                    code_search_hints TEXT,
                    generated_by TEXT,
                    generated_at TEXT,
                    confidence TEXT
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
            # Migrate: add project_notes column if missing
            try:
                conn.execute("SELECT project_notes FROM cve_remediations LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute(
                    "ALTER TABLE cve_remediations ADD COLUMN project_notes TEXT"
                )

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
            env_map = dict(_PROVIDER_ENV_VARS)
            env_var = env_map[override]
            api_key = os.getenv(env_var, "")
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
        elif self._provider in ("openai", "copilot"):
            try:
                import openai

                kwargs: dict[str, Any] = {"api_key": self.api_key}
                if self._provider == "copilot":
                    kwargs["base_url"] = COPILOT_BASE_URL
                return openai.OpenAI(**kwargs)
            except ImportError:
                raise ImportError(
                    "The 'openai' package is required for OpenAI/Copilot AI features. "
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

        if self._provider == "anthropic":
            response = self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=SYSTEM_MESSAGE,
                messages=[{"role": "user", "content": prompt}],
            )
            self._call_count += 1
            return response.content[0].text  # type: ignore[no-any-return]
        else:
            # OpenAI / Copilot
            response = self.client.chat.completions.create(
                model=model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": prompt},
                ],
            )
            self._call_count += 1
            return response.choices[0].message.content or ""

    def _is_fresh(self, generated_at: str | None) -> bool:
        """Check if a cached entry is still within the TTL window."""
        if self.cache_ttl <= 0 or not generated_at:
            return False
        try:
            cached_time = datetime.fromisoformat(generated_at)
            age_seconds = (datetime.utcnow() - cached_time).total_seconds()
            return age_seconds < self.cache_ttl
        except (ValueError, TypeError):
            return False

    # =========================================================================
    # Cache Operations
    # =========================================================================

    def get_cached_remediation(self, cve_id: str) -> dict[str, Any] | None:
        """Look up cached remediation guidance for a CVE (respects TTL)."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM cve_remediations WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            if row:
                row_dict = dict(row)
                if self._is_fresh(row_dict.get("generated_at")):
                    return row_dict
                logger.debug(f"Cache expired for {cve_id}")
        return None

    def cache_remediation(self, cve_id: str, remediation: dict[str, Any]) -> None:
        """Store remediation guidance in the cache."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cve_remediations
                   (cve_id, component_name, fix_version, guidance, workaround,
                    code_search_hints, generated_by, generated_at, confidence,
                    project_notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id,
                    remediation.get("component_name", ""),
                    remediation.get("fix_version", ""),
                    remediation.get("guidance", ""),
                    remediation.get("workaround", ""),
                    remediation.get("code_search_hints", ""),
                    remediation.get("generated_by", self._component_model),
                    datetime.utcnow().isoformat(),
                    remediation.get("confidence", "medium"),
                    remediation.get("project_notes", ""),
                ),
            )

    def get_cached_summary(self, cache_key: str) -> str | None:
        """Look up cached AI summary (portfolio or project level, respects TTL)."""
        with sqlite3.connect(str(self.db_path)) as conn:
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
        return None

    def cache_summary(
        self, cache_key: str, scope: str, summary_text: str, model: str
    ) -> None:
        """Store an AI summary in the cache."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO ai_summary_cache
                   (cache_key, scope, summary_text, generated_by, generated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (cache_key, scope, summary_text, model, datetime.utcnow().isoformat()),
            )

    def get_cached_cve_detail(self, finding_id: str) -> dict[str, Any] | None:
        """Look up cached CVE detail metadata."""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT cve_metadata FROM cve_detail_cache WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if row and row[0]:
                result: dict[str, Any] = json.loads(row[0])
                return result
        return None

    def cache_cve_detail(self, finding_id: str, metadata: Any) -> None:
        """Store CVE detail metadata in the cache."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cve_detail_cache
                   (finding_id, cve_metadata, fetched_at)
                   VALUES (?, ?, ?)""",
                (
                    finding_id,
                    json.dumps(metadata, default=str),
                    datetime.utcnow().isoformat(),
                ),
            )

    def get_cached_exploit_detail(self, finding_id: str) -> dict[str, Any] | None:
        """Look up cached exploit detail metadata."""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT exploit_metadata FROM exploit_detail_cache WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if row and row[0]:
                result: dict[str, Any] = json.loads(row[0])
                return result
        return None

    def cache_exploit_detail(self, finding_id: str, metadata: Any) -> None:
        """Store exploit detail metadata in the cache."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO exploit_detail_cache
                   (finding_id, exploit_metadata, fetched_at)
                   VALUES (?, ?, ?)""",
                (
                    finding_id,
                    json.dumps(metadata, default=str),
                    datetime.utcnow().isoformat(),
                ),
            )

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
    ) -> str:
        """
        Generate a strategic portfolio-level remediation summary.

        Uses Sonnet for rich analysis. Cached by a hash of the input data.

        Args:
            nvd_snippets_map: Optional map of "component:version" -> NVD fix snippet.
            project_ai_summaries: Optional map of project_name -> AI summary text
                (from project-level LLM calls, for bottom-up cascade).
        """
        # Build a stable cache key from the input data
        import hashlib

        key_data = json.dumps(
            {
                "portfolio": portfolio_summary,
                "reach": reachability_summary,
                "has_nvd": bool(nvd_snippets_map),
                "has_proj_ai": bool(project_ai_summaries),
            },
            sort_keys=True,
            default=str,
        )
        cache_key = f"portfolio:{hashlib.sha256(key_data.encode()).hexdigest()[:16]}"

        # Check cache
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
            self.cache_summary(cache_key, "portfolio", result_text, self._summary_model)
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

        return f"""Analyze this vulnerability triage data and provide strategic remediation guidance.

## Portfolio Overview
- Total findings: {portfolio_summary.get('total', 0)}
- CRITICAL: {portfolio_summary.get('CRITICAL', 0)}
- HIGH: {portfolio_summary.get('HIGH', 0)}
- MEDIUM: {portfolio_summary.get('MEDIUM', 0)}
- LOW: {portfolio_summary.get('LOW', 0)}
- INFO: {portfolio_summary.get('INFO', 0)}
{vex_section}
{get_scoring_methodology()}
{reach_section}
## Top Projects by Risk
{self._format_projects_bullet(top_projects)}

## Top Risky Components
{self._format_components_bullet(top_comps)}
{self._build_nvd_section_for_portfolio(top_comps, nvd_snippets_map)}
{self._build_project_ai_section(top_projects, project_ai_summaries)}
Provide a concise strategic summary (3-5 paragraphs):
1. Overall risk posture assessment — highlight the reachability findings as the most urgent
2. Top 3 remediation priorities (specific components/projects), prioritizing reachable+exploitable findings
3. Quick wins (high-impact, low-effort fixes), especially where specific vulnerable functions are identified
4. Recommended remediation order

Be specific with component names and versions. When vulnerable functions are identified, mention them as they guide developers to the exact code that needs attention. Focus on actionable guidance."""

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
    ) -> str:
        """
        Generate a project-level remediation summary.

        Uses Sonnet for rich analysis. Cached by project name + band distribution.

        Args:
            nvd_snippets_map: Optional map of "component:version" -> NVD fix snippet.
            component_guidance: Optional map of "component:version" -> AI guidance dict
                (from component-level LLM calls, containing fix_version, confidence, etc.).
        """
        import hashlib

        key_data = json.dumps(
            {
                "project": project_name,
                "bands": band_counts,
                "has_nvd": bool(nvd_snippets_map),
                "has_comp_ai": bool(component_guidance),
            },
            sort_keys=True,
            default=str,
        )
        cache_key = f"project:{hashlib.sha256(key_data.encode()).hexdigest()[:16]}"

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
            self.cache_summary(cache_key, "project", result_text, self._summary_model)
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

            component_summary.append(
                {
                    "component": comp_key,
                    "findings_count": len(comp_findings),
                    "bands": [f.get("priority_band", "INFO") for f in comp_findings],
                    "cves": [f.get("finding_id", "") for f in comp_findings[:5]],
                    "reachable_cves": reachable_cves[:5],
                    "unreachable_count": unreachable_count,
                    "vuln_functions": list(vuln_funcs)[:5],
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

        return f"""Provide remediation guidance for project "{project_name}".

## Risk Band Distribution
{json.dumps(band_counts, indent=2)}
{vex_section}
{get_scoring_methodology()}

## Reachability Summary
- Reachable: {reachable_total} (vulnerable code confirmed present and callable in firmware)
- Unreachable: {unreachable_total} (vulnerable code not reachable — lower risk)
- Inconclusive: {unknown_total} (reachability not determined)

## Top Components by Risk
{self._format_project_components_bullet(component_summary)}
{self._build_nvd_section_for_project(component_summary, nvd_snippets_map)}
{self._build_component_ai_section(component_summary, component_guidance)}
Note: "reachable" indicates CVEs where binary analysis confirmed the vulnerable code path is callable. Vulnerable functions listed are specific functions identified in the deployed binaries — developers should search for and audit these.

Provide a concise project remediation plan (2-3 paragraphs):
1. Which components to upgrade first — prioritize those with reachable vulnerabilities and known exploits
2. Recommended upgrade order considering dependencies. Mention specific vulnerable functions when known.
3. Any quick wins or workarounds, especially for reachable findings where specific functions are identified

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

        Returns:
            Dict with fix_version, guidance, workaround, code_search_hints
        """
        # Check cache for each CVE
        for cve_id in cve_ids:
            cached = self.get_cached_remediation(cve_id)
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

            # Cache for each CVE
            for cve_id in cve_ids:
                self.cache_remediation(cve_id, remediation)

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

        return f"""Provide specific fix guidance for:

Component: {component_name} version {component_version}

CVEs:
{cve_section}

{f"## CVE Details{cve_detail_section}" if cve_detail_section else ""}

{f"## Exploit Information{exploit_section}" if exploit_section else ""}

{reach_section}
{nvd_section}
Respond in this exact format:
FIX_VERSION: <specific version number. If NVD data says "FIXED in >= X", recommend X. If NVD data says a version is "STILL VULNERABLE", the fix must be AFTER that version — do NOT recommend the vulnerable version. Cross-reference the component version ({component_version}) against the NVD affected ranges. Only state "verify latest stable release" if no version data is available.>
RATIONALE: <1 sentence explaining why this fix or version is recommended, citing the NVD data or advisory if available>
GUIDANCE: <1-2 sentence upgrade guidance>
WORKAROUND: <1-3 sentences: if no straightforward upgrade is available, suggest firmware-specific mitigations such as disabling affected services, network segmentation, restricting exposed interfaces, or configuration hardening. If a direct upgrade is available, state "Upgrade recommended.">
CODE_SEARCH: <grep/search patterns to find affected code in firmware — use specific vulnerable function names if known from reachability analysis, e.g., "grep -r 'vulnerableFunction' src/">
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
            matched = False
            for prefix, key in field_map.items():
                if line.startswith(f"{prefix}:"):
                    value = line.split(":", 1)[1].strip()
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

    def _parse_component_response(
        self,
        response_text: str,
        component_name: str,
        component_version: str,
    ) -> dict[str, Any]:
        """Parse structured response from component guidance prompt."""
        field_map = {
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
            "generated_by": "llm",
            **parsed,
        }
        result["confidence"] = result.get("confidence", "medium").lower()

        # If parsing didn't work well, use the raw text as guidance
        if not result.get("guidance"):
            result["guidance"] = response_text.strip()[:500]

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

        with tqdm(
            components, desc="Generating AI guidance", unit=" components"
        ) as pbar:
            for comp in pbar:
                comp_key = f"{comp['component_name']}:{comp['component_version']}"
                pbar.set_postfix_str(comp_key[:40])

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
                )
                results[comp_key] = guidance

                # Only rate-limit when we actually hit the API
                if self._cached_count == prev_cached:
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
    ) -> dict[str, str]:
        """
        Generate finding-level triage guidance from a pre-built prompt.

        Uses the fast (component) model. Caches by finding_id.

        Args:
            finding_id: The CVE/finding identifier.
            prompt: The complete triage prompt text (built by _build_triage_prompt).

        Returns:
            Dict with priority, action, rationale, fix_version, workaround,
            code_search_hints, confidence.
        """
        # Check cache — use ai_summary_cache with "finding:" prefix to avoid
        # collision with component-level cve_remediations cache.
        cache_key = f"finding:{finding_id}"
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

        # If parsing didn't work well, use the raw text as action
        if not result.get("action") and not result.get("priority"):
            result["action"] = response_text.strip()[:500]

        return result

    def generate_batch_finding_guidance(
        self,
        findings: list[tuple[str, str]],
    ) -> dict[str, dict[str, str]]:
        """
        Generate triage guidance for multiple findings.

        Args:
            findings: List of (finding_id, prompt_text) tuples.

        Returns:
            Dict mapping finding_id to guidance dict.
        """
        results: dict[str, dict[str, str]] = {}

        from tqdm import tqdm

        cached_before = self._cached_count
        with tqdm(
            findings, desc="Generating AI finding guidance", unit=" findings"
        ) as pbar:
            for finding_id, prompt in pbar:
                pbar.set_postfix_str(finding_id[:40])
                prev_cached = self._cached_count
                guidance = self.generate_finding_guidance(finding_id, prompt)
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
    # Stats
    # =========================================================================

    def get_stats(self) -> dict[str, int]:
        """Return API call and cache statistics."""
        return {
            "api_calls": self._call_count,
            "cache_hits": self._cached_count,
        }
