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

Uses Anthropic Claude with model tiering:
- Sonnet: Portfolio/project summaries (rich analysis)
- Haiku: Bulk component-level guidance (fast, cheap)

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

# Model configuration
SONNET_MODEL = "claude-sonnet-4-20250514"
HAIKU_MODEL = "claude-3-5-haiku-20241022"

# Token limits
MAX_PORTFOLIO_TOKENS = 2000
MAX_PROJECT_TOKENS = 1500
MAX_COMPONENT_TOKENS = 800


class LLMClient:
    """
    LLM client for generating remediation guidance.

    Uses Anthropic Claude API with SQLite-backed result caching.
    Model tiering: Sonnet for summaries, Haiku for bulk component guidance.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        cache_ttl: int = 0,
    ) -> None:
        """
        Initialize the LLM client.

        Args:
            cache_dir: Directory for SQLite cache. Defaults to ~/.fs-report/
            cache_ttl: Cache TTL in seconds. 0 = no caching (always regenerate).
        """
        self.api_key = os.getenv("ANTHROPIC_AUTH_TOKEN", "")
        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_AUTH_TOKEN environment variable is required for AI features"
            )

        # Lazy import to avoid requiring anthropic when --ai is not used
        try:
            import anthropic

            self.client = anthropic.Anthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "The 'anthropic' package is required for AI features. "
                "Install it with: pip install anthropic"
            )

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
            conn.executescript(
                """
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
            """
            )

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
                    code_search_hints, generated_by, generated_at, confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id,
                    remediation.get("component_name", ""),
                    remediation.get("fix_version", ""),
                    remediation.get("guidance", ""),
                    remediation.get("workaround", ""),
                    remediation.get("code_search_hints", ""),
                    remediation.get("generated_by", HAIKU_MODEL),
                    datetime.utcnow().isoformat(),
                    remediation.get("confidence", "medium"),
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
    # Portfolio Summary (Sonnet)
    # =========================================================================

    def generate_portfolio_summary(
        self,
        portfolio_summary: dict[str, Any],
        project_summaries: list[dict[str, Any]],
        top_components: list[dict[str, Any]],
        reachability_summary: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate a strategic portfolio-level remediation summary.

        Uses Sonnet for rich analysis. Cached by a hash of the input data.
        """
        # Build a stable cache key from the input data
        import hashlib

        key_data = json.dumps(
            {"portfolio": portfolio_summary, "reach": reachability_summary},
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
        )

        try:
            response = self.client.messages.create(
                model=SONNET_MODEL,
                max_tokens=MAX_PORTFOLIO_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )
            self._call_count += 1
            result_text = response.content[0].text  # type: ignore[union-attr]
            self.cache_summary(cache_key, "portfolio", result_text, SONNET_MODEL)
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

        return f"""You are a firmware security analyst. Analyze this vulnerability triage data and provide strategic remediation guidance.

## Portfolio Overview
- Total findings: {portfolio_summary.get('total', 0)}
- CRITICAL: {portfolio_summary.get('CRITICAL', 0)}
- HIGH: {portfolio_summary.get('HIGH', 0)}
- MEDIUM: {portfolio_summary.get('MEDIUM', 0)}
- LOW: {portfolio_summary.get('LOW', 0)}
- INFO: {portfolio_summary.get('INFO', 0)}
{reach_section}
## Top Projects by Risk
{json.dumps(top_projects, indent=2, default=str)}

## Top Risky Components
{json.dumps(top_comps, indent=2, default=str)}

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
    ) -> str:
        """
        Generate a project-level remediation summary.

        Uses Sonnet for rich analysis. Cached by project name + band distribution.
        """
        import hashlib

        key_data = json.dumps(
            {"project": project_name, "bands": band_counts},
            sort_keys=True,
            default=str,
        )
        cache_key = f"project:{hashlib.sha256(key_data.encode()).hexdigest()[:16]}"

        cached = self.get_cached_summary(cache_key)
        if cached is not None:
            self._cached_count += 1
            logger.info(f"Project summary for '{project_name}' loaded from cache")
            return cached

        prompt = self._build_project_prompt(project_name, findings, band_counts)

        try:
            response = self.client.messages.create(
                model=SONNET_MODEL,
                max_tokens=MAX_PROJECT_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )
            self._call_count += 1
            result_text = response.content[0].text  # type: ignore[union-attr]
            self.cache_summary(cache_key, "project", result_text, SONNET_MODEL)
            return result_text
        except Exception as e:
            logger.error(f"Project summary generation failed for {project_name}: {e}")
            return f"AI summary unavailable: {e}"

    def _build_project_prompt(
        self,
        project_name: str,
        findings: list[dict[str, Any]],
        band_counts: dict[str, int],
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
            key=lambda x: max(f.get("triage_score", 0) for f in x[1]),
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

        return f"""You are a firmware security analyst. Provide remediation guidance for project "{project_name}".

## Risk Band Distribution
{json.dumps(band_counts, indent=2)}

## Reachability Summary
- Reachable: {reachable_total} (vulnerable code confirmed present and callable in firmware)
- Unreachable: {unreachable_total} (vulnerable code not reachable — lower risk)
- Inconclusive: {unknown_total} (reachability not determined)

## Top Components by Risk
{json.dumps(component_summary, indent=2, default=str)}

Note: "reachable_cves" lists CVEs where binary analysis confirmed the vulnerable code path is callable. "vuln_functions" are the specific functions identified as vulnerable in the deployed binaries — developers should search for and audit these.

Provide a concise project remediation plan (2-3 paragraphs):
1. Which components to upgrade first — prioritize those with reachable vulnerabilities and known exploits
2. Recommended upgrade order considering dependencies. Mention specific vulnerable functions when known.
3. Any quick wins or workarounds, especially for reachable findings where specific functions are identified

Be specific with component names and versions."""

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
    ) -> dict[str, Any]:
        """
        Generate component-level remediation guidance.

        Uses Haiku for fast, cost-effective bulk generation.
        Checks cache first to avoid redundant calls.

        Args:
            reachability_info: List of dicts with reachability_score,
                reachability_label, vuln_functions, factors for each CVE.

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
        )

        try:
            response = self.client.messages.create(
                model=HAIKU_MODEL,
                max_tokens=MAX_COMPONENT_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )
            self._call_count += 1
            result_text = response.content[0].text  # type: ignore[union-attr]

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
            all_binary_paths = set()
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

                # Collect all vulnerable functions and binary paths from factors
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
                            # Extract binary paths for context
                            details = factor.get("details", {})
                            if isinstance(details, dict):
                                for path in details.get("comp_files", [])[:3]:
                                    all_binary_paths.add(path)

            reach_section = "\n## Reachability Analysis (from binary analysis)\n"
            reach_section += "\n".join(reach_items[:10])
            if all_vuln_funcs:
                reach_section += (
                    f"\n\nVulnerable functions confirmed in firmware binaries: "
                    f"{', '.join(sorted(all_vuln_funcs)[:10])}"
                )
            if all_binary_paths:
                reach_section += (
                    f"\nBinary locations: " f"{', '.join(sorted(all_binary_paths)[:5])}"
                )
            reach_section += (
                "\n\nNote: REACHABLE means binary analysis confirmed these "
                "functions exist in deployed firmware and can be reached. "
                "Include these function names in CODE_SEARCH guidance."
            )

        return f"""You are a security remediation advisor. Provide specific fix guidance for:

Component: {component_name} version {component_version}

CVEs:
{cve_section}

{f"## CVE Details{cve_detail_section}" if cve_detail_section else ""}

{f"## Exploit Information{exploit_section}" if exploit_section else ""}

{reach_section}

Respond in this exact format:
FIX_VERSION: <recommended version to upgrade to>
GUIDANCE: <1-2 sentence upgrade guidance>
WORKAROUND: <workaround if upgrade isn't immediately possible, or "None">
CODE_SEARCH: <grep/search patterns to find affected code in firmware — use specific vulnerable function names if known from reachability analysis, e.g., "grep -r 'vulnerableFunction' src/">
CONFIDENCE: <high|medium|low>"""

    def _parse_component_response(
        self,
        response_text: str,
        component_name: str,
        component_version: str,
    ) -> dict[str, Any]:
        """Parse structured response from component guidance prompt."""
        result = {
            "component_name": component_name,
            "fix_version": "",
            "guidance": "",
            "workaround": "",
            "code_search_hints": "",
            "generated_by": HAIKU_MODEL,
            "confidence": "medium",
        }

        for line in response_text.strip().split("\n"):
            line = line.strip()
            if line.startswith("FIX_VERSION:"):
                result["fix_version"] = line.split(":", 1)[1].strip()
            elif line.startswith("GUIDANCE:"):
                result["guidance"] = line.split(":", 1)[1].strip()
            elif line.startswith("WORKAROUND:"):
                result["workaround"] = line.split(":", 1)[1].strip()
            elif line.startswith("CODE_SEARCH:"):
                result["code_search_hints"] = line.split(":", 1)[1].strip()
            elif line.startswith("CONFIDENCE:"):
                result["confidence"] = line.split(":", 1)[1].strip().lower()

        # If parsing didn't work well, use the raw text as guidance
        if not result["guidance"]:
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
    ) -> dict[str, dict[str, Any]]:
        """
        Generate guidance for multiple components (grouped by component+version).

        Args:
            components: List of dicts with component_name, component_version, cve_ids
            cve_details_map: Optional map of finding_id -> CVE detail list
            exploit_details_map: Optional map of finding_id -> exploit detail list
            reachability_map: Optional map of finding_id -> reachability info dict
                (reachability_score, reachability_label, vuln_functions, factors)

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

                guidance = self.generate_component_guidance(
                    component_name=comp["component_name"],
                    component_version=comp["component_version"],
                    cve_ids=comp.get("cve_ids", []),
                    cve_details=cve_details if cve_details else None,
                    exploit_details=exploit_details_list
                    if exploit_details_list
                    else None,
                    reachability_info=reach_info_list if reach_info_list else None,
                )
                results[comp_key] = guidance

                # Rate limiting — 0.5s between calls to avoid hitting limits
                time.sleep(0.5)

        logger.info(
            f"AI guidance complete: {self._call_count} API calls, "
            f"{self._cached_count} cache hits"
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
