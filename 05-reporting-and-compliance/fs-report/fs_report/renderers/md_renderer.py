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

"""Agent-optimized Markdown renderer for structured, token-efficient report output."""

import logging
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from fs_report.models import Recipe, ReportData

logger = logging.getLogger(__name__)


def _safe_str(val: Any) -> str:
    """Convert a value to string, handling NaN/None gracefully."""
    if val is None:
        return ""
    if isinstance(val, float) and math.isnan(val):
        return ""
    return str(val)


def _safe_int(val: Any, default: int = 0) -> int:
    """Convert to int safely."""
    try:
        if val is None or (isinstance(val, float) and math.isnan(val)):
            return default
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, decimals: int = 1, default: str = "") -> str:
    """Format a float safely with given decimal places."""
    try:
        if val is None or (isinstance(val, float) and math.isnan(val)):
            return default
        return f"{float(val):.{decimals}f}"
    except (ValueError, TypeError):
        return default


def _escape_pipe(val: str) -> str:
    """Escape pipe characters in markdown table cells."""
    return val.replace("|", "\\|").replace("\n", " ")


class MarkdownRenderer:
    """Renders agent-optimized Markdown reports with curated columns and summary sections."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def render(
        self,
        recipe: Recipe,
        report_data: ReportData,
        output_path: Path,
    ) -> None:
        """Render a Markdown report for the given recipe. Dispatches to per-recipe methods."""
        dispatch = {
            "Remediation Package": self._render_remediation_package,
            "CVE Impact": self._render_cve_impact,
            "Triage Prioritization": self._render_triage_prioritization,
            "False Positive Analysis": self._render_false_positive_analysis,
            "Findings by Project": self._render_findings_by_project,
            "Component Vulnerability Analysis": self._render_component_vulnerability_analysis,
            "Version Comparison": self._render_version_comparison,
            "Customer Brief": self._render_customer_brief,
            "Assessment Overview": self._render_assessment_overview,
            "Workflow Summary": self._render_workflow_summary,
            "Component Remediation Package": self._render_component_remediation_package,
            "Component Impact": self._render_component_impact,
            "Scan Quality": self._render_scan_quality,
        }

        # Try exact match first, then prefix match (handles scoped names
        # like "Remediation Package - CVE-2024-27397")
        renderer = dispatch.get(recipe.name)
        if renderer is None:
            for key, func in dispatch.items():
                if recipe.name.startswith(key):
                    renderer = func
                    break

        if renderer is None:
            self.logger.debug(
                f"No Markdown renderer for recipe '{recipe.name}'; "
                f"falling back to generic table export."
            )
            content = self._render_generic(recipe, report_data)
        else:
            content = renderer(recipe, report_data)

        output_path.write_text(content, encoding="utf-8")
        self.logger.debug(f"Generated Markdown: {output_path}")

    # ── Shared helpers ──────────────────────────────────────────────────

    def _get_additional_data(self, report_data: ReportData) -> dict[str, Any]:
        """Extract additional_data from report metadata."""
        result = report_data.metadata.get("additional_data", {})
        return result if isinstance(result, dict) else {}

    def _get_transform_result(self, report_data: ReportData) -> dict[str, Any]:
        """Extract transform_result from additional_data."""
        ad = self._get_additional_data(report_data)
        tr = ad.get("transform_result", {})
        return tr if isinstance(tr, dict) else {}

    def _metadata_block(self, report_data: ReportData, recipe: Recipe) -> str:
        """Render the ## Metadata section with domain, project, date range, etc."""
        meta = report_data.metadata
        rows = []

        domain = meta.get("domain", "")
        if domain:
            rows.append(("Domain", domain))

        project = meta.get("project_filter", "")
        if project:
            rows.append(("Project", project))

        folder = meta.get("folder_name", "") or meta.get("folder_filter", "")
        if folder:
            rows.append(("Folder", folder))

        start = meta.get("start_date", "")
        end = meta.get("end_date", "")
        if start and end:
            rows.append(("Date Range", f"{start} to {end}"))
        elif start:
            rows.append(("Date Range", f"From {start}"))

        rows.append(("Generated", datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")))

        if not rows:
            return ""

        lines = ["## Metadata", "| Field | Value |", "|-------|-------|"]
        for field, value in rows:
            lines.append(f"| {_escape_pipe(str(field))} | {_escape_pipe(str(value))} |")
        return "\n".join(lines)

    def _summary_table(self, metrics: list[tuple[str, Any]]) -> str:
        """Render a summary section as a key-value table."""
        lines = ["## Summary", "| Metric | Value |", "|--------|-------|"]
        for key, val in metrics:
            lines.append(
                f"| {_escape_pipe(str(key))} | {_escape_pipe(_safe_str(val))} |"
            )
        return "\n".join(lines)

    def _df_to_table(
        self,
        df: pd.DataFrame,
        columns: list[str] | None = None,
        headers: dict[str, str] | None = None,
        max_rows: int = 0,
    ) -> str:
        """Convert a DataFrame to a Markdown pipe table.

        Args:
            df: Source DataFrame.
            columns: Subset of columns to include (in order). If None, uses all.
            headers: Optional column→display name mapping.
            max_rows: Max rows to include; 0 means unlimited.
        """
        if df is None or df.empty:
            return "*No data available.*"

        if columns:
            cols = [c for c in columns if c in df.columns]
        else:
            cols = list(df.columns)

        if not cols:
            return "*No data available.*"

        hdrs = headers or {}
        header_row = [_escape_pipe(hdrs.get(c, c)) for c in cols]

        lines = [
            "| " + " | ".join(header_row) + " |",
            "| " + " | ".join(["---"] * len(cols)) + " |",
        ]

        data = df.head(max_rows) if max_rows > 0 else df
        for _, row in data.iterrows():
            cells = [_escape_pipe(_safe_str(row.get(c, ""))) for c in cols]
            lines.append("| " + " | ".join(cells) + " |")

        if max_rows > 0 and len(df) > max_rows:
            lines.append(f"\n*({len(df) - max_rows} more rows omitted)*")

        return "\n".join(lines)

    def _footer(self) -> str:
        """Return the standard copyright footer for Markdown reports."""
        return "\n---\n*Generated by fs-report | Copyright \u00a9 2026 Finite State, Inc.*\n"

    def _render_generic(self, recipe: Recipe, report_data: ReportData) -> str:
        """Fallback: dump the main DataFrame as a pipe table."""
        parts = [
            f"# {recipe.name}",
            "",
            self._metadata_block(report_data, recipe),
            "",
        ]
        if isinstance(report_data.data, pd.DataFrame):
            parts.append("## Data")
            parts.append(self._df_to_table(report_data.data, max_rows=500))
        else:
            parts.append("*No tabular data available.*")
        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Tier 1: Remediation Package ─────────────────────────────────────

    def _render_remediation_package(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        tr = self._get_transform_result(report_data)
        ad = self._get_additional_data(report_data)

        actions_df = tr.get("actions_df", pd.DataFrame())
        if not isinstance(actions_df, pd.DataFrame):
            actions_df = pd.DataFrame()
        suppressed_df = tr.get("suppressed_df", pd.DataFrame())
        if not isinstance(suppressed_df, pd.DataFrame):
            suppressed_df = pd.DataFrame()
        unresolvable_df = tr.get("unresolvable_df", pd.DataFrame())
        if not isinstance(unresolvable_df, pd.DataFrame):
            unresolvable_df = pd.DataFrame()
        summary = tr.get("remediation_summary", {})
        if not isinstance(summary, dict):
            summary = {}

        parts = ["# Remediation Package", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Summary
        by_priority = summary.get("by_priority", {})
        metrics = [
            ("Total Components", summary.get("total_components", len(actions_df))),
            ("CVEs Resolved", summary.get("total_cves", 0)),
            ("Suppressed (VEX)", summary.get("suppressed_count", len(suppressed_df))),
            ("Unresolvable", summary.get("unresolvable_count", len(unresolvable_df))),
        ]
        for p in ["P0", "P1", "P2", "P3"]:
            cnt = by_priority.get(p, 0)
            if cnt:
                metrics.append((f"Priority {p}", cnt))
        fix_pct = summary.get("fix_coverage_pct")
        if fix_pct is not None:
            metrics.append(("Fix Coverage", f"{fix_pct}%"))
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Component-centric remediation sections
        if not actions_df.empty:
            parts.append("## Remediation Actions")
            parts.append("")
            for _, action in actions_df.iterrows():
                comp = _safe_str(action.get("component_name", ""))
                ver = _safe_str(action.get("component_version", ""))
                prio = _safe_str(action.get("priority", ""))
                cve_count = _safe_int(action.get("cve_count", 0))
                parts.append(f"### {comp} {ver} ({prio} — {cve_count} CVEs)")
                parts.append("")

                # Remediation options
                options = action.get("remediation_options_parsed")
                if isinstance(options, list) and options:
                    parts.append("**Remediation Options:**")
                    parts.append("")
                    for opt in options:
                        if not isinstance(opt, dict):
                            continue
                        num = opt.get("option_number", "")
                        title = opt.get("title", "")
                        opt_type = opt.get("type", "")

                        if opt_type == "upgrade":
                            validated = opt.get("fix_validated", True)
                            val_label = (
                                "Validated clean" if validated else "Unvalidated"
                            )
                            cmd = opt.get("upgrade_command", "")
                            utype = opt.get("upgrade_type", "")
                            risk = opt.get("breaking_change_risk", "")
                            parts.append(f"{num}. **{title}** ({val_label})")
                            if cmd:
                                parts.append(f"   - `{cmd}`")
                            if utype or risk:
                                parts.append(f"   - Type: {utype} | Risk: {risk}")
                            breaking = opt.get("breaking_change_notes", "")
                            if breaking and breaking.lower() not in (
                                "",
                                "none expected",
                            ):
                                parts.append(f"   - Breaking changes: {breaking}")
                        elif opt_type == "workaround":
                            parts.append(f"{num}. **{title}**")
                            workarounds = opt.get("workarounds", [])
                            for wa in workarounds:
                                parts.append(f"   - {wa}")
                            wa_urls = opt.get("workaround_urls", [])
                            for url in wa_urls[:3]:
                                parts.append(f"   - Reference: {url}")
                        elif opt_type == "code_mitigation":
                            parts.append(f"{num}. **{title}**")
                            aff_funcs = opt.get("affected_functions", "")
                            if aff_funcs:
                                parts.append(f"   - Affected functions: `{aff_funcs}`")
                            patch_urls = opt.get("patch_urls", [])
                            for url in patch_urls[:3]:
                                parts.append(f"   - Patch: {url}")
                            sp = opt.get("search_pattern", "")
                            if sp:
                                parts.append(f"   - Search: `{sp}`")

                    parts.append("")
                else:
                    # Fallback: show upgrade instruction if no structured options
                    upgrade_inst = _safe_str(action.get("upgrade_instruction", ""))
                    if upgrade_inst:
                        parts.append(f"**Upgrade:** `{upgrade_inst}`")
                        parts.append("")

                # Resolved CVEs
                resolves = action.get("resolves_parsed")
                if isinstance(resolves, list) and resolves:
                    parts.append("**Resolved CVEs:**")
                    shown = resolves[:6]
                    for r in shown:
                        if isinstance(r, dict):
                            cve_id = r.get("cve_id", r.get("cve", ""))
                            severity = r.get("severity", "")
                            cvss = _safe_float(r.get("cvss"))
                            parts.append(f"- {cve_id} {severity} (CVSS {cvss})")
                        else:
                            parts.append(f"- {r}")
                    remaining = len(resolves) - len(shown)
                    if remaining > 0:
                        parts.append(f"- ...{remaining} more")
                    parts.append("")

                # AI guidance
                guidance = _safe_str(action.get("llm_guidance", ""))
                if guidance:
                    parts.append(f"**AI Guidance:** {guidance}")
                    parts.append("")

                parts.append("---")
                parts.append("")

        # Suppressed
        if not suppressed_df.empty:
            parts.append("## Suppressed (VEX)")
            supp_cols = [
                "component_name",
                "component_version",
                "vex_status",
                "vex_justification",
                "vex_detail",
            ]
            # Fall back to columns that might exist
            alt_cols = ["name", "version", "status", "justification", "detail"]
            use_cols = (
                supp_cols
                if any(c in suppressed_df.columns for c in supp_cols)
                else alt_cols
            )
            supp_headers = {
                "component_name": "Component",
                "name": "Component",
                "component_version": "Version",
                "version": "Version",
                "vex_status": "VEX State",
                "status": "VEX State",
                "vex_justification": "Justification",
                "justification": "Justification",
                "vex_detail": "Detail",
                "detail": "Detail",
            }
            parts.append(
                self._df_to_table(
                    suppressed_df,
                    columns=use_cols,
                    headers=supp_headers,
                    max_rows=10,
                )
            )
            remaining = len(suppressed_df) - 10
            if remaining > 0:
                parts.append(f"\n*(\u2026and {remaining} more suppressed)*")
            parts.append("")

        # Unresolvable
        if not unresolvable_df.empty:
            parts.append("## Unresolvable")
            unres_cols = [
                "component_name",
                "component_version",
                "cve_count",
                "worst_band",
            ]
            alt_cols2 = ["name", "version", "cve_count", "severity"]
            use_cols2 = (
                unres_cols
                if any(c in unresolvable_df.columns for c in unres_cols)
                else alt_cols2
            )
            unres_headers = {
                "component_name": "Component",
                "name": "Component",
                "component_version": "Version",
                "version": "Version",
                "cve_count": "CVEs",
                "worst_band": "Severity",
                "severity": "Severity",
            }
            parts.append(
                self._df_to_table(
                    unresolvable_df,
                    columns=use_cols2,
                    headers=unres_headers,
                    max_rows=10,
                )
            )
            remaining = len(unresolvable_df) - 10
            if remaining > 0:
                parts.append(f"\n*(\u2026and {remaining} more unresolvable)*")
            parts.append("")

        # Agent Prompts (consolidate old separate files into this single .md)
        project_prompt = ad.get("project_agent_prompt", "")
        if not project_prompt:
            project_prompt = tr.get("project_agent_prompt", "")
        if project_prompt:
            parts.append("## Agent Prompt")
            parts.append(project_prompt)
            parts.append("")

        # Per-action prompts
        if not actions_df.empty and "agent_prompt" in actions_df.columns:
            prompts = actions_df[actions_df["agent_prompt"].fillna("").astype(bool)]
            if not prompts.empty:
                parts.append("## Per-Action Agent Prompts")
                for _, row in prompts.iterrows():
                    prompt = row.get("agent_prompt", "")
                    if prompt:
                        parts.append("---")
                        parts.append("")
                        parts.append(str(prompt))
                        parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Tier 1: CVE Impact ──────────────────────────────────────────────

    def _render_cve_impact(self, recipe: Recipe, report_data: ReportData) -> str:
        tr = self._get_transform_result(report_data)

        mode = tr.get("mode", "summary")
        summary = tr.get("summary", {})
        if not isinstance(summary, dict):
            summary = {}
        main_df = report_data.data
        if not isinstance(main_df, pd.DataFrame):
            main_df = pd.DataFrame()
        dossiers = tr.get("dossiers", [])

        parts = ["# CVE Impact", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Summary metrics
        sev_counts = summary.get("severity_counts", {})
        metrics = [
            ("Total CVEs", summary.get("total_cves", len(main_df))),
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            cnt = sev_counts.get(sev, 0)
            if cnt:
                metrics.append((sev.title(), cnt))
        worst_cvss = summary.get("worst_cvss")
        if worst_cvss is not None:
            metrics.append(("Worst CVSS", _safe_float(worst_cvss)))
        reachable = _safe_int(summary.get("total_reachable", 0))
        if reachable:
            metrics.append(("Reachable CVEs", reachable))
        parts.append(self._summary_table(metrics))
        parts.append("")

        if mode == "dossier" and dossiers:
            # Dossier mode: per-CVE detailed sections
            parts.append("## CVE Dossiers")
            parts.append("")
            for dossier in dossiers:
                if not isinstance(dossier, dict):
                    continue
                cve_id = dossier.get("cve_id", "Unknown")
                parts.append(f"### {cve_id}")

                # Key facts
                facts = []
                for key, label in [
                    ("severity", "Severity"),
                    ("cvss", "CVSS"),
                    ("epss", "EPSS"),
                    ("attack_vector", "Attack Vector"),
                    ("cwe", "CWE"),
                ]:
                    val = dossier.get(key)
                    if val is not None and _safe_str(val):
                        display = (
                            _safe_float(val)
                            if key in ("cvss", "epss")
                            else _safe_str(val)
                        )
                        facts.append(f"- **{label}:** {display}")
                if facts:
                    parts.extend(facts)
                    parts.append("")

                # Description
                desc = dossier.get("description", "")
                if desc:
                    parts.append(f"**Description:** {desc}")
                    parts.append("")

                # Exploit details
                exploits = dossier.get("exploit_details", [])
                if exploits:
                    parts.append("**Exploits:**")
                    for ex in exploits:
                        if isinstance(ex, dict):
                            src = ex.get("source", "")
                            url = ex.get("url", "")
                            maturity = ex.get("maturity", "")
                            line = f"- {src}"
                            if maturity:
                                line += f" ({maturity})"
                            if url:
                                line += f": {url}"
                            parts.append(line)
                    parts.append("")

                # Project impact
                projects = dossier.get("project_details", [])
                if projects:
                    parts.append("**Affected Projects:**")
                    parts.append("| Project | Reachability | Component |")
                    parts.append("| --- | --- | --- |")
                    for proj in projects:
                        if isinstance(proj, dict):
                            pname = _escape_pipe(
                                _safe_str(proj.get("project_name", ""))
                            )
                            reach = _escape_pipe(
                                _safe_str(proj.get("reachability_label", ""))
                            )
                            comp = _escape_pipe(_safe_str(proj.get("component", "")))
                            parts.append(f"| {pname} | {reach} | {comp} |")
                    parts.append("")

                # Vulnerable functions
                vf = dossier.get("vuln_functions", "")
                if vf:
                    parts.append(f"**Vulnerable Functions:** {vf}")
                    parts.append("")

                # AI guidance
                ai = dossier.get("ai_guidance")
                if isinstance(ai, dict) and ai:
                    guidance = ai.get("guidance", ai.get("summary", ""))
                    if guidance:
                        parts.append(f"**AI Guidance:** {guidance}")
                        parts.append("")
        else:
            # Summary mode: CVE table
            if not main_df.empty:
                parts.append("## CVE Table")
                cve_cols = [
                    "cve_id",
                    "severity",
                    "cvss",
                    "epss",
                    "in_kev",
                    "exploit_count",
                    "affected_project_count",
                    "reachable_in",
                    "components",
                ]
                cve_headers = {
                    "cve_id": "CVE ID",
                    "severity": "Severity",
                    "cvss": "CVSS",
                    "epss": "EPSS",
                    "in_kev": "KEV",
                    "exploit_count": "Exploits",
                    "affected_project_count": "Affected Projects",
                    "reachable_in": "Reachable In",
                    "components": "Components",
                }
                parts.append(
                    self._df_to_table(main_df, columns=cve_cols, headers=cve_headers)
                )
                parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Tier 1: Triage Prioritization ───────────────────────────────────

    def _render_triage_prioritization(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        tr = self._get_transform_result(report_data)

        findings_df = tr.get("findings_df", pd.DataFrame())
        if not isinstance(findings_df, pd.DataFrame):
            findings_df = pd.DataFrame()
        portfolio_summary = tr.get("portfolio_summary", {})
        if not isinstance(portfolio_summary, dict):
            portfolio_summary = {}
        gate_funnel = tr.get("gate_funnel", {})
        top_components = tr.get("top_components", pd.DataFrame())
        if not isinstance(top_components, pd.DataFrame):
            top_components = pd.DataFrame()
        vex_recs = tr.get("vex_recommendations", [])

        parts = ["# Triage Prioritization", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Summary
        total = (
            portfolio_summary.get("total", 0) if portfolio_summary else len(findings_df)
        )
        metrics = [("Total Findings", total)]
        for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = portfolio_summary.get(band, 0)
            if cnt:
                metrics.append((band.title(), cnt))
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Gate Funnel
        if gate_funnel and isinstance(gate_funnel, dict):
            parts.append("## Gate Funnel")
            # gate_funnel may be a dict of gate_name → count or a chart-ready structure
            if "labels" in gate_funnel and "values" in gate_funnel:
                parts.append("| Gate | Count |")
                parts.append("| --- | --- |")
                labels = gate_funnel["labels"]
                values = gate_funnel["values"]
                for label, val in zip(labels, values, strict=False):
                    parts.append(f"| {_escape_pipe(str(label))} | {val} |")
            elif isinstance(gate_funnel, dict):
                # Try as simple dict
                parts.append("| Gate | Count |")
                parts.append("| --- | --- |")
                for gate, count in gate_funnel.items():
                    if gate in ("labels", "values"):
                        continue
                    parts.append(f"| {_escape_pipe(str(gate))} | {count} |")
            parts.append("")

        # Top Components
        if not top_components.empty:
            parts.append("## Top Components")
            comp_cols = [
                "component_name",
                "component_version",
                "finding_count",
                "worst_band",
                "project_names",
            ]
            # Fallback column names
            if (
                "component_name" not in top_components.columns
                and "name" in top_components.columns
            ):
                comp_cols = [
                    "name",
                    "version",
                    "finding_count",
                    "worst_band",
                    "project_names",
                ]
            comp_headers = {
                "component_name": "Component",
                "name": "Component",
                "component_version": "Version",
                "version": "Version",
                "finding_count": "Findings",
                "worst_band": "Worst Band",
                "project_names": "Projects",
            }
            parts.append(
                self._df_to_table(
                    top_components, columns=comp_cols, headers=comp_headers
                )
            )
            parts.append("")

        # Findings table
        if not findings_df.empty:
            parts.append("## Findings")
            find_cols = [
                "finding_id",
                "severity",
                "risk",
                "priority_band",
                "triage_score",
                "gate_assignment",
                "component_name",
                "component_version",
                "project_name",
                "reachability_label",
                "epss_percentile",
                "ai_fix_version",
                "ai_guidance",
                "ai_workaround",
                "ai_confidence",
            ]
            find_headers = {
                "finding_id": "Finding ID",
                "severity": "Severity",
                "risk": "CVSS",
                "priority_band": "Band",
                "triage_score": "Score",
                "gate_assignment": "Gate",
                "component_name": "Component",
                "component_version": "Version",
                "project_name": "Project",
                "reachability_label": "Reachability",
                "epss_percentile": "EPSS",
                "ai_fix_version": "Fix Version",
                "ai_guidance": "Guidance",
                "ai_workaround": "Workaround",
                "ai_confidence": "Confidence",
            }
            parts.append(
                self._df_to_table(
                    findings_df,
                    columns=find_cols,
                    headers=find_headers,
                    max_rows=500,
                )
            )
            parts.append("")

        # VEX Recommendations
        if vex_recs and isinstance(vex_recs, list):
            parts.append("## VEX Recommendations")
            parts.append(
                "| Finding ID | CVE | Component | Recommended Status | Justification | Reason |"
            )
            parts.append("| --- | --- | --- | --- | --- | --- |")
            for rec in vex_recs:
                if not isinstance(rec, dict):
                    continue
                fid = _escape_pipe(_safe_str(rec.get("finding_id", "")))
                cve = _escape_pipe(_safe_str(rec.get("cve_id", "")))
                comp = _escape_pipe(_safe_str(rec.get("component_name", "")))
                status = _escape_pipe(_safe_str(rec.get("recommended_vex_status", "")))
                just = _escape_pipe(_safe_str(rec.get("justification", "")))
                reason = _escape_pipe(_safe_str(rec.get("reason", "")))
                parts.append(
                    f"| {fid} | {cve} | {comp} | {status} | {just} | {reason} |"
                )
            parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── False Positive Analysis ────────────────────────────────────────

    def _render_false_positive_analysis(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        """Render False Positive Analysis with identity assertions first."""
        tr = self._get_transform_result(report_data)
        lines: list[str] = [f"# {recipe.name}\n"]

        # Metadata section — reuse the existing helper used by other renderers
        meta_block = self._metadata_block(report_data, recipe)
        if meta_block:
            lines.append(meta_block)

        # Identity assertions (lead section)
        assertions = tr.get("identity_assertions", []) or []
        if assertions:
            lines.append("## Component Identity Assertions\n")
            lines.append(
                f"{len(assertions)} component(s) detected as misidentified "
                "relative to NVD.\n"
            )
            for a in assertions:
                lines.append(
                    f"### {a.get('component_name', '?')} "
                    f"{a.get('component_version', '?')} — "
                    f"scanned as `{a.get('likely_product') or '?'}`, "
                    f"NVD expected `{a.get('nvd_product') or '?'}` "
                    f"(confidence: {a.get('confidence') or 'medium'})\n"
                )
                if a.get("evidence"):
                    lines.append(f"**Evidence:** {a['evidence']}\n")
                lines.append("| CVE | Verdict | Rationale |")
                lines.append("| --- | --- | --- |")
                for cv in a.get("cve_verdicts", []) or []:
                    rationale = (cv.get("rationale") or "").replace("|", "\\|")
                    lines.append(
                        f"| {cv.get('cve_id', '?')} | "
                        f"{cv.get('verdict', '?')} | {rationale} |"
                    )
                lines.append("")

        # Residual candidates (finding-level fallback)
        candidates = tr.get("candidates")
        if (
            candidates is not None
            and hasattr(candidates, "empty")
            and not candidates.empty
        ):
            lines.append("## Residual FP Candidates\n")
            lines.append(
                "Findings on components whose identity was confirmed or "
                "ambiguous, flagged by finding-level applicability.\n"
            )
            lines.append(
                "| CVE | Component | Severity | Confidence | Signals | Reason |"
            )
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for _, row in candidates.iterrows():
                sigs = row.get("fp_signals", "")
                if not isinstance(sigs, str):
                    sigs = ", ".join(sigs) if sigs else ""
                reason = str(row.get("primary_reason", "") or "").replace("|", "\\|")
                lines.append(
                    f"| {row.get('cve_id', '') or row.get('finding_id', '')} | "
                    f"{row.get('component_name', '')} "
                    f"{row.get('component_version', '')} | "
                    f"{row.get('severity', '')} | "
                    f"{row.get('fp_confidence', '')} | "
                    f"{sigs} | {reason} |"
                )
            lines.append("")
        else:
            lines.append("## Residual FP Candidates\n")
            lines.append("No residual finding-level FP candidates.\n")

        lines.append(self._footer())
        return "\n".join(lines) + "\n"

    # ── Tier 2: Findings by Project ─────────────────────────────────────

    def _render_findings_by_project(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        df = report_data.data
        if not isinstance(df, pd.DataFrame):
            df = pd.DataFrame()

        parts = ["# Findings by Project", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Summary
        if not df.empty:
            sev_col = "Severity" if "Severity" in df.columns else "severity"
            sev_counts = (
                df[sev_col].value_counts().to_dict() if sev_col in df.columns else {}
            )
            proj_col = (
                "Project Name" if "Project Name" in df.columns else "project_name"
            )
            unique_projects = df[proj_col].nunique() if proj_col in df.columns else 0
            comp_col = "Component" if "Component" in df.columns else "component_name"
            unique_components = df[comp_col].nunique() if comp_col in df.columns else 0

            metrics = [
                ("Total Findings", len(df)),
                ("Unique Projects", unique_projects),
                ("Unique Components", unique_components),
            ]
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                cnt = sev_counts.get(sev, 0)
                if cnt:
                    metrics.append((sev.title(), cnt))
            parts.append(self._summary_table(metrics))
        else:
            parts.append(self._summary_table([("Total Findings", 0)]))
        parts.append("")

        # Findings table
        if not df.empty:
            parts.append("## Findings")
            find_cols = [
                "CVE ID",
                "Severity",
                "CVSS",
                "Project Name",
                "Project Version",
                "Component",
                "Component Version",
                "Status",
                "Detected",
                "# of known exploits",
                "CWE",
            ]
            parts.append(self._df_to_table(df, columns=find_cols, max_rows=500))
            parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Tier 2: Component Vulnerability Analysis ────────────────────────

    def _render_component_vulnerability_analysis(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        # CVA uses portfolio_data for table rendering
        portfolio_data = report_data.metadata.get("portfolio_data")
        df = (
            portfolio_data
            if isinstance(portfolio_data, pd.DataFrame) and not portfolio_data.empty
            else report_data.data
        )
        if not isinstance(df, pd.DataFrame):
            df = pd.DataFrame()

        parts = ["# Component Vulnerability Analysis", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Summary
        if not df.empty:
            top_comp = ""
            if "portfolio_composite_risk" in df.columns:
                top_idx = df["portfolio_composite_risk"].idxmax()
                top_comp = (
                    _safe_str(df.loc[top_idx, "name"]) if "name" in df.columns else ""
                )
            metrics = [
                ("Total Components", len(df)),
                ("Top Risk Component", top_comp),
            ]
            if "findings_count" in df.columns:
                metrics.append(
                    ("Total Findings", _safe_int(df["findings_count"].sum()))
                )
        else:
            metrics = [("Total Components", 0)]
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Components table
        if not df.empty:
            parts.append("## Components")
            comp_cols = [
                "name",
                "version",
                "portfolio_composite_risk",
                "normalized_risk_score",
                "findings_count",
                "project_count",
                "has_kev",
                "has_exploits",
                "project_names",
            ]
            comp_headers = {
                "name": "Component",
                "version": "Version",
                "portfolio_composite_risk": "Risk Score",
                "normalized_risk_score": "Normalized Score",
                "findings_count": "Findings",
                "project_count": "Projects",
                "has_kev": "KEV",
                "has_exploits": "Exploits",
                "project_names": "Project Names",
            }
            parts.append(self._df_to_table(df, columns=comp_cols, headers=comp_headers))
            parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Tier 2: Version Comparison ──────────────────────────────────────

    def _render_version_comparison(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        tr = self._get_transform_result(report_data)
        ad = self._get_additional_data(report_data)

        projects = tr.get("projects", [])
        kpi = tr.get("kpi", {})
        if not isinstance(kpi, dict):
            kpi = {}
        partial_report = bool(tr.get("partial_report", False))
        failed_version_names: list[str] = tr.get("failed_version_names", []) or []
        detail_findings = ad.get("detail_findings")
        if not isinstance(detail_findings, pd.DataFrame):
            detail_findings = tr.get("detail_findings")
        if not isinstance(detail_findings, pd.DataFrame):
            detail_findings = pd.DataFrame()
        detail_churn = ad.get("detail_findings_churn", tr.get("detail_churn"))
        if not isinstance(detail_churn, pd.DataFrame):
            detail_churn = pd.DataFrame()
        component_churn = ad.get("detail_component_churn", tr.get("component_churn"))
        if not isinstance(component_churn, pd.DataFrame):
            component_churn = pd.DataFrame()

        parts = ["# Version Comparison", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Partial-report banner — shown right after metadata when some versions
        # could not be fetched.
        if partial_report:
            failed_str = (
                ", ".join(str(v) for v in failed_version_names)
                if failed_version_names
                else "unknown"
            )
            parts.append(
                f"> ⚠ **Partial report:** could not fetch versions: {failed_str}"
            )
            parts.append("")

        # KPI Summary
        metrics: list[tuple[str, Any]] = []
        total_f = kpi.get("total_findings", {})
        if isinstance(total_f, dict):
            metrics.append(("Baseline Total", _safe_int(total_f.get("baseline", 0))))
            metrics.append(("Current Total", _safe_int(total_f.get("current", 0))))
            delta = total_f.get("delta", 0)
            pct = total_f.get("pct", 0.0)
            metrics.append(
                ("Net Change", f"{_safe_int(delta):+d} ({_safe_float(pct, 1, '0.0')}%)")
            )
        crit_f = kpi.get("critical_findings", {})
        if isinstance(crit_f, dict) and crit_f.get("delta", 0):
            metrics.append(
                ("Critical Delta", f"{_safe_int(crit_f.get('delta', 0)):+d}")
            )
        fixed = kpi.get("fixed_count", 0)
        new = kpi.get("new_count", 0)
        if fixed:
            metrics.append(("Fixed Findings", _safe_int(fixed)))
        if new:
            metrics.append(("New Findings", _safe_int(new)))
        if metrics:
            parts.append(self._summary_table(metrics))
        else:
            parts.append(self._summary_table([("Projects Compared", len(projects))]))
        parts.append("")

        # Per-Project Progression
        if projects and isinstance(projects, list):
            parts.append("## Per-Project Progression")
            for proj in projects:
                if not isinstance(proj, dict):
                    continue
                pname = proj.get("project_name", "Unknown")
                parts.append(f"### {pname}")

                # Support both ``progression`` (transform output with fetch_failed
                # support) and legacy ``versions`` (old-style / test data).
                progression = proj.get("progression", [])
                versions = proj.get("versions", []) if not progression else []

                if progression:
                    parts.append(
                        "| Version | Total | Critical | High | Medium | Low | New | Fixed |"
                    )
                    parts.append("| --- | --- | --- | --- | --- | --- | --- | --- |")

                    def _fmt_cell(val: Any) -> str:
                        return "—" if val is None else str(_safe_int(val))

                    for step in progression:
                        if not isinstance(step, dict):
                            continue
                        is_failed = bool(step.get("fetch_failed"))
                        raw_label = _safe_str(step.get("version", step.get("name", "")))
                        if is_failed:
                            vname = _escape_pipe(f"⚠ {raw_label} (fetch failed)")
                        else:
                            vname = _escape_pipe(raw_label)

                        total = _fmt_cell(step.get("total"))
                        crit = _fmt_cell(step.get("critical", step.get("CRITICAL")))
                        high = _fmt_cell(step.get("high", step.get("HIGH")))
                        med = _fmt_cell(step.get("medium", step.get("MEDIUM")))
                        low = _fmt_cell(step.get("low", step.get("LOW")))
                        new_v = _fmt_cell(step.get("new", step.get("new_findings")))
                        fixed_v = _fmt_cell(
                            step.get("fixed", step.get("fixed_findings"))
                        )
                        parts.append(
                            f"| {vname} | {total} | {crit} | {high} | {med} | {low} | {new_v} | {fixed_v} |"
                        )
                elif versions:
                    parts.append(
                        "| Version | Total | Critical | High | Medium | Low | New | Fixed |"
                    )
                    parts.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
                    for ver in versions:
                        if not isinstance(ver, dict):
                            continue
                        vname = _escape_pipe(
                            _safe_str(ver.get("name", ver.get("version", "")))
                        )
                        v_total = _safe_int(ver.get("total", 0))
                        v_crit = _safe_int(ver.get("critical", ver.get("CRITICAL", 0)))
                        v_high = _safe_int(ver.get("high", ver.get("HIGH", 0)))
                        v_med = _safe_int(ver.get("medium", ver.get("MEDIUM", 0)))
                        v_low = _safe_int(ver.get("low", ver.get("LOW", 0)))
                        v_new = _safe_int(ver.get("new", ver.get("new_findings", 0)))
                        v_fixed = _safe_int(
                            ver.get("fixed", ver.get("fixed_findings", 0))
                        )
                        parts.append(
                            f"| {vname} | {v_total} | {v_crit} | {v_high} | {v_med} | {v_low} | {v_new} | {v_fixed} |"
                        )
                parts.append("")

        # Detail: New/Fixed Findings
        if not detail_findings.empty:
            # Try to split into new vs fixed
            status_col = None
            for candidate in ["status", "change_type", "delta_type"]:
                if candidate in detail_findings.columns:
                    status_col = candidate
                    break

            if status_col:
                new_df = detail_findings[
                    detail_findings[status_col]
                    .fillna("")
                    .str.upper()
                    .isin(["NEW", "ADDED"])
                ]
                fixed_df = detail_findings[
                    detail_findings[status_col]
                    .fillna("")
                    .str.upper()
                    .isin(["FIXED", "RESOLVED", "REMOVED"])
                ]
            else:
                new_df = detail_findings
                fixed_df = pd.DataFrame()

            if not new_df.empty:
                parts.append("## New Findings")
                parts.append(self._df_to_table(new_df, max_rows=200))
                parts.append("")

            if not fixed_df.empty:
                parts.append("## Fixed Findings")
                parts.append(self._df_to_table(fixed_df, max_rows=200))
                parts.append("")
        elif not detail_churn.empty:
            parts.append("## Findings Churn")
            parts.append(self._df_to_table(detail_churn, max_rows=200))
            parts.append("")

        # Component Churn
        if not component_churn.empty:
            parts.append("## Component Churn")
            churn_cols = [
                "component",
                "name",
                "old_version",
                "new_version",
                "finding_delta",
                "version_old",
                "version_new",
                "delta",
            ]
            # Use whichever columns exist
            available: list[str] | None = [
                c for c in churn_cols if c in component_churn.columns
            ]
            if not available:
                available = None  # show all
            parts.append(
                self._df_to_table(component_churn, columns=available, max_rows=200)
            )
            parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Customer Brief ──────────────────────────────────────────────────

    def _render_customer_brief(self, recipe: Recipe, report_data: ReportData) -> str:
        tr = self._get_transform_result(report_data)

        summary = tr.get("summary", {})
        if not isinstance(summary, dict):
            summary = {}
        triage = tr.get("triage_summary", {})
        if not isinstance(triage, dict):
            triage = {}
        top_findings = tr.get("top_findings", [])
        remed = tr.get("remediation_highlights", {})
        if not isinstance(remed, dict):
            remed = {}
        sbom = tr.get("sbom_stats", {})
        if not isinstance(sbom, dict):
            sbom = {}
        scan_meta = tr.get("scan_metadata", {})
        if not isinstance(scan_meta, dict):
            scan_meta = {}

        parts = ["# Customer Brief", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Scan metadata
        meta_items = []
        if scan_meta.get("project_name"):
            meta_items.append(f"**Project:** {scan_meta['project_name']}")
        if scan_meta.get("version_name"):
            meta_items.append(f"**Version:** {scan_meta['version_name']}")
        if scan_meta.get("scan_date_range"):
            meta_items.append(f"**Detection Range:** {scan_meta['scan_date_range']}")
        if meta_items:
            parts.append(" | ".join(meta_items))
            parts.append("")

        # KPI Summary
        metrics: list[tuple[str, Any]] = [
            ("Total Findings", _safe_int(summary.get("total_findings", 0))),
            (
                "Open (Untriaged + In Triage)",
                _safe_int(summary.get("open_count", 0)),
            ),
            ("Critical", _safe_int(summary.get("critical_count", 0))),
            ("High", _safe_int(summary.get("high_count", 0))),
            ("Medium", _safe_int(summary.get("medium_count", 0))),
            ("Low", _safe_int(summary.get("low_count", 0))),
            ("% Triaged", f"{summary.get('pct_triaged', 0)}%"),
            ("KEV Listed", _safe_int(summary.get("kev_count", 0))),
            ("Exploits", _safe_int(summary.get("exploit_count", 0))),
            ("Components", _safe_int(summary.get("total_components", 0))),
        ]
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Triage breakdown
        parts.append("## Triage Status")
        parts.append("| Status | Count |")
        parts.append("| --- | --- |")
        parts.append(f"| Untriaged | {_safe_int(triage.get('untriaged', 0))} |")
        parts.append(f"| In Triage | {_safe_int(triage.get('in_triage', 0))} |")
        parts.append(f"| Not Affected | {_safe_int(triage.get('not_affected', 0))} |")
        parts.append(
            f"| False Positive | {_safe_int(triage.get('false_positive', 0))} |"
        )
        parts.append(f"| Affected | {_safe_int(triage.get('affected', 0))} |")
        parts.append(f"| Resolved | {_safe_int(triage.get('resolved', 0))} |")
        parts.append("")

        # Severity Distribution
        sev_dist = tr.get("severity_distribution", {})
        if isinstance(sev_dist, dict) and sev_dist:
            parts.append("## Severity Distribution")
            parts.append("| Severity | Count |")
            parts.append("| --- | --- |")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                parts.append(f"| {sev} | {_safe_int(sev_dist.get(sev, 0))} |")
            parts.append("")

        # Top Security Risks
        top_risks = tr.get("top_security_risks", [])
        if top_risks:
            parts.append("## Top Security Risks")
            parts.append(
                "| CVE | Severity | Component | Version "
                "| CVSS | EPSS %ile | KEV | Exploit |"
            )
            parts.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
            for r in top_risks:
                if not isinstance(r, dict):
                    continue
                kev = "KEV" if r.get("in_kev") else ""
                exploit = "Yes" if r.get("has_exploit") else ""
                cvss = _safe_float(r.get("cvss_score"), 1)
                epss = _safe_float(r.get("epss_percentile"), 1)
                parts.append(
                    f"| {_escape_pipe(_safe_str(r.get('cve_id')))} "
                    f"| {_safe_str(r.get('severity'))} "
                    f"| {_escape_pipe(_safe_str(r.get('component')))} "
                    f"| {_escape_pipe(_safe_str(r.get('component_version')))} "
                    f"| {cvss} "
                    f"| {epss} "
                    f"| {kev} "
                    f"| {exploit} |"
                )
            parts.append("")

        # Exploit Maturity
        exploit_mat = tr.get("exploit_maturity_summary", {})
        if isinstance(exploit_mat, dict) and exploit_mat:
            _exploit_labels = {
                "kev": "In KEV",
                "vckev": "VulnCheck KEV",
                "weaponized": "Weaponized",
                "poc": "PoC",
                "threatactors": "Threat Actors",
                "ransomware": "Ransomware",
                "botnets": "Botnets",
                "commercial": "Commercial",
                "reported": "Reported",
            }
            parts.append("## Exploit Maturity")
            parts.append("| Category | Count |")
            parts.append("| --- | --- |")
            for key, label in _exploit_labels.items():
                parts.append(f"| {label} | {_safe_int(exploit_mat.get(key, 0))} |")
            total_exploits = exploit_mat.get("total_with_exploits", 0)
            parts.append(
                f"| **Total with Exploits** " f"| **{_safe_int(total_exploits)}** |"
            )
            parts.append("")

        # Reachability Analysis
        reach = tr.get("reachability_summary", {})
        if isinstance(reach, dict) and reach.get("has_data"):
            parts.append("## Reachability Analysis")
            parts.append(f"- **Reachable:** {_safe_int(reach.get('reachable', 0))}")
            parts.append(f"- **Unreachable:** {_safe_int(reach.get('unreachable', 0))}")
            parts.append(
                f"- **Inconclusive:** " f"{_safe_int(reach.get('inconclusive', 0))}"
            )
            parts.append("")

        # Component Risk Analysis
        comp_risk = tr.get("component_risk_ranking", [])
        if comp_risk:
            parts.append("## Component Risk Analysis")
            parts.append(
                "| Component | Version | Critical | High "
                "| Medium | Low | Total | Score |"
            )
            parts.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
            for c in comp_risk:
                if not isinstance(c, dict):
                    continue
                parts.append(
                    f"| {_escape_pipe(_safe_str(c.get('component')))} "
                    f"| {_escape_pipe(_safe_str(c.get('component_version')))} "
                    f"| {_safe_int(c.get('critical', 0))} "
                    f"| {_safe_int(c.get('high', 0))} "
                    f"| {_safe_int(c.get('medium', 0))} "
                    f"| {_safe_int(c.get('low', 0))} "
                    f"| {_safe_int(c.get('total', 0))} "
                    f"| {_safe_float(c.get('risk_score'), 1)} |"
                )
            parts.append("")

        # License Distribution
        lic_dist = tr.get("component_license_distribution", [])
        if lic_dist:
            parts.append("## License Distribution")
            parts.append("| License | Count |")
            parts.append("| --- | --- |")
            for entry in lic_dist:
                if not isinstance(entry, dict):
                    continue
                parts.append(
                    f"| {_escape_pipe(_safe_str(entry.get('license')))} "
                    f"| {_safe_int(entry.get('count', 0))} |"
                )
            parts.append("")

        # Top findings
        if top_findings:
            parts.append("## Top Findings (Critical & High, Open)")
            parts.append(
                "| CVE | Severity | Component | Version | CVSS | KEV | Exploit |"
            )
            parts.append("| --- | --- | --- | --- | --- | --- | --- |")
            for f in top_findings:
                if not isinstance(f, dict):
                    continue
                kev = "KEV" if f.get("in_kev") else ""
                exploit = "Yes" if f.get("has_exploit") else ""
                cvss = _safe_float(f.get("cvss_score"), 1)
                parts.append(
                    f"| {_escape_pipe(_safe_str(f.get('cve_id')))} "
                    f"| {_safe_str(f.get('severity'))} "
                    f"| {_escape_pipe(_safe_str(f.get('component')))} "
                    f"| {_escape_pipe(_safe_str(f.get('component_version')))} "
                    f"| {cvss} "
                    f"| {kev} "
                    f"| {exploit} |"
                )
            parts.append("")

        # Remediation highlights (gate-based)
        g1 = remed.get("gate_1", [])
        g2 = remed.get("gate_2", [])
        if g1 or g2:
            parts.append("## Remediation Highlights")
            for label, cards in [
                ("Gate 1 — Reachable + Exploitable/KEV", g1),
                ("Gate 2 — Network Vector + High EPSS", g2),
            ]:
                if cards:
                    parts.append(f"### {label}")
                    for card in cards:
                        if not isinstance(card, dict):
                            continue
                        parts.append(
                            f"- **{_escape_pipe(_safe_str(card.get('component')))}** "
                            f"— {_safe_int(card.get('finding_count'))} finding(s), "
                            f"top CVE: {_safe_str(card.get('top_cve'))}, "
                            f"CVSS {_safe_float(card.get('worst_cvss'), 1)}"
                        )
            parts.append("")

        # SBOM
        total_comp = _safe_int(sbom.get("total_components", 0))
        if total_comp:
            parts.append(f"## SBOM Summary\n\n**Total Components:** {total_comp}")
            parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Assessment Overview ────────────────────────────────────────────────

    def _render_assessment_overview(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        tr = self._get_transform_result(report_data)

        summary = tr.get("summary", {})
        if not isinstance(summary, dict):
            summary = {}
        severity_distribution = tr.get("severity_distribution", {})
        if not isinstance(severity_distribution, dict):
            severity_distribution = {}
        top_security_risks = tr.get("top_security_risks", [])
        exploit_maturity = tr.get("exploit_maturity_summary", {})
        if not isinstance(exploit_maturity, dict):
            exploit_maturity = {}
        reachability = tr.get("reachability_summary", {})
        if not isinstance(reachability, dict):
            reachability = {}
        exploit_intel = tr.get("exploit_intel", {})
        if not isinstance(exploit_intel, dict):
            exploit_intel = {}
        triage_pipeline = tr.get("triage_pipeline", {})
        if not isinstance(triage_pipeline, dict):
            triage_pipeline = {}
        remediation_progress = tr.get("remediation_progress", {})
        if not isinstance(remediation_progress, dict):
            remediation_progress = {}
        findings_by_tier = tr.get("findings_by_tier", {})
        if not isinstance(findings_by_tier, dict):
            findings_by_tier = {}
        component_risk_ranking = tr.get("component_risk_ranking", [])
        component_license_distribution = tr.get("component_license_distribution", [])
        sbom_stats = tr.get("sbom_stats", {})
        if not isinstance(sbom_stats, dict):
            sbom_stats = {}
        project_cards = tr.get("project_cards", [])
        scan_meta = tr.get("scan_metadata", {})
        if not isinstance(scan_meta, dict):
            scan_meta = {}

        parts = ["# Assessment Overview", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Scan metadata
        meta_items = []
        if scan_meta.get("project_name"):
            meta_items.append(f"**Project:** {scan_meta['project_name']}")
        if scan_meta.get("version_name"):
            meta_items.append(f"**Version:** {scan_meta['version_name']}")
        if scan_meta.get("scan_date"):
            meta_items.append(f"**Scan Date:** {scan_meta['scan_date']}")
        if meta_items:
            parts.append(" | ".join(meta_items))
            parts.append("")

        # KPI Summary
        metrics: list[tuple[str, Any]] = [
            ("Total Findings", _safe_int(summary.get("total_findings", 0))),
            ("Critical", _safe_int(summary.get("critical_count", 0))),
            ("High", _safe_int(summary.get("high_count", 0))),
            ("Medium", _safe_int(summary.get("medium_count", 0))),
            ("Low", _safe_int(summary.get("low_count", 0))),
            ("Open", _safe_int(summary.get("open_count", 0))),
            ("Triaged", _safe_int(summary.get("triaged_count", 0))),
            ("Exploited", _safe_int(exploit_intel.get("has_exploit_count", 0))),
            (
                "EPSS \u2265 0.5",
                _safe_int(exploit_intel.get("epss_high_count", 0)),
            ),
            ("KEV Listed", _safe_int(exploit_intel.get("kev_count", 0))),
            ("Components", _safe_int(summary.get("total_components", 0))),
        ]
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Severity Distribution
        if severity_distribution:
            parts.append("## Severity Distribution")
            parts.append("| Severity | Count |")
            parts.append("| --- | --- |")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                parts.append(
                    f"| {sev} | {_safe_int(severity_distribution.get(sev, 0))} |"
                )
            parts.append("")

        # Top Security Risks
        if top_security_risks:
            parts.append("## Top Security Risks")
            parts.append(
                "| CVE | Severity | Component | Version "
                "| CVSS | EPSS %ile | KEV | Exploit |"
            )
            parts.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
            for r in top_security_risks[:10]:
                if not isinstance(r, dict):
                    continue
                kev = "KEV" if r.get("in_kev") else ""
                exploit = "Yes" if r.get("has_exploit") else ""
                cvss = _safe_float(r.get("cvss_score"), 1)
                epss = _safe_float(r.get("epss_percentile"), 1)
                parts.append(
                    f"| {_escape_pipe(_safe_str(r.get('cve_id')))} "
                    f"| {_safe_str(r.get('severity'))} "
                    f"| {_escape_pipe(_safe_str(r.get('component')))} "
                    f"| {_escape_pipe(_safe_str(r.get('component_version')))} "
                    f"| {cvss} "
                    f"| {epss} "
                    f"| {kev} "
                    f"| {exploit} |"
                )
            parts.append("")

        # Exploit Maturity
        if exploit_maturity:
            _exploit_labels = {
                "kev": "In KEV",
                "vckev": "VulnCheck KEV",
                "weaponized": "Weaponized",
                "poc": "PoC",
                "threatactors": "Threat Actors",
                "ransomware": "Ransomware",
                "botnets": "Botnets",
                "commercial": "Commercial",
                "reported": "Reported",
            }
            parts.append("## Exploit Maturity")
            parts.append("| Category | Count |")
            parts.append("| --- | --- |")
            for key, label in _exploit_labels.items():
                parts.append(f"| {label} | {_safe_int(exploit_maturity.get(key, 0))} |")
            total_exploits = exploit_maturity.get("total_with_exploits", 0)
            parts.append(
                f"| **Total with Exploits** " f"| **{_safe_int(total_exploits)}** |"
            )
            parts.append("")

        # Reachability Analysis
        if isinstance(reachability, dict) and reachability.get("has_data"):
            parts.append("## Reachability Analysis")
            parts.append(
                f"- **Reachable:** {_safe_int(reachability.get('reachable', 0))}"
            )
            parts.append(
                f"- **Unreachable:** {_safe_int(reachability.get('unreachable', 0))}"
            )
            parts.append(
                f"- **Inconclusive:** "
                f"{_safe_int(reachability.get('inconclusive', 0))}"
            )
            parts.append("")

        # Triage Pipeline
        parts.append("## Triage Pipeline")
        parts.append("| Status | Count |")
        parts.append("| --- | --- |")
        parts.append(
            f"| In Triage | {_safe_int(triage_pipeline.get('in_triage', 0))} |"
        )
        parts.append(f"| Affected | {_safe_int(triage_pipeline.get('affected', 0))} |")
        parts.append(
            f"| Open + Exploit "
            f"| {_safe_int(triage_pipeline.get('exploitable', 0))} |"
        )
        parts.append("")

        # Remediation Progress
        p0 = remediation_progress.get("p0_components", [])
        p1 = remediation_progress.get("p1_components", [])
        if p0 or p1:
            parts.append("## Remediation Progress")
            if p0:
                parts.append("### P0 — Critical + Exploitable/KEV")
                for card in p0:
                    if not isinstance(card, dict):
                        continue
                    parts.append(
                        f"- **{_escape_pipe(_safe_str(card.get('component')))}** "
                        f"— {_safe_int(card.get('finding_count'))} finding(s), "
                        f"top CVE: {_safe_str(card.get('top_cve'))}, "
                        f"CVSS {_safe_float(card.get('worst_cvss'), 1)}"
                    )
            if p1:
                parts.append("### P1 — High + Network Vector")
                for card in p1:
                    if not isinstance(card, dict):
                        continue
                    parts.append(
                        f"- **{_escape_pipe(_safe_str(card.get('component')))}** "
                        f"— {_safe_int(card.get('finding_count'))} finding(s), "
                        f"top CVE: {_safe_str(card.get('top_cve'))}, "
                        f"CVSS {_safe_float(card.get('worst_cvss'), 1)}"
                    )
            parts.append("")

        # All Findings
        tier_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        has_any_findings = any(findings_by_tier.get(sev) for sev in tier_order)
        if has_any_findings:
            parts.append("## All Findings")
            parts.append(
                "| CVE | Severity | Component | Version "
                "| CVSS | EPSS %ile | KEV | Exploit | Status |"
            )
            parts.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
            rendered = 0
            for sev in tier_order:
                tier_findings = findings_by_tier.get(sev, [])
                for f in tier_findings:
                    if rendered >= 2000:
                        break
                    if not isinstance(f, dict):
                        continue
                    kev = "KEV" if f.get("in_kev") else ""
                    exploit = "Yes" if f.get("has_exploit") else ""
                    cvss = _safe_float(f.get("cvss_score"), 1)
                    epss = _safe_float(f.get("epss_percentile"), 1)
                    parts.append(
                        f"| {_escape_pipe(_safe_str(f.get('cve_id')))} "
                        f"| {_safe_str(f.get('severity'))} "
                        f"| {_escape_pipe(_safe_str(f.get('component')))} "
                        f"| {_escape_pipe(_safe_str(f.get('component_version')))} "
                        f"| {cvss} "
                        f"| {epss} "
                        f"| {kev} "
                        f"| {exploit} "
                        f"| {_safe_str(f.get('status'))} |"
                    )
                    rendered += 1
                if rendered >= 2000:
                    break
            parts.append("")

        # Component Risk Ranking
        if component_risk_ranking:
            parts.append("## Component Risk Ranking")
            parts.append(
                "| Component | Version | Critical | High "
                "| Medium | Low | Total | Score |"
            )
            parts.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
            for c in component_risk_ranking:
                if not isinstance(c, dict):
                    continue
                parts.append(
                    f"| {_escape_pipe(_safe_str(c.get('component')))} "
                    f"| {_escape_pipe(_safe_str(c.get('component_version')))} "
                    f"| {_safe_int(c.get('critical', 0))} "
                    f"| {_safe_int(c.get('high', 0))} "
                    f"| {_safe_int(c.get('medium', 0))} "
                    f"| {_safe_int(c.get('low', 0))} "
                    f"| {_safe_int(c.get('total', 0))} "
                    f"| {_safe_float(c.get('risk_score'), 1)} |"
                )
            parts.append("")

        # License Distribution
        if component_license_distribution:
            parts.append("## License Distribution")
            parts.append("| License | Count |")
            parts.append("| --- | --- |")
            for entry in component_license_distribution:
                if not isinstance(entry, dict):
                    continue
                parts.append(
                    f"| {_escape_pipe(_safe_str(entry.get('license')))} "
                    f"| {_safe_int(entry.get('count', 0))} |"
                )
            parts.append("")

        # SBOM Stats
        total_comp = _safe_int(sbom_stats.get("total_components", 0))
        if total_comp:
            parts.append(f"## SBOM Summary\n\n**Total Components:** {total_comp}")
            parts.append("")

        # Per-Project Breakdown
        if project_cards:
            parts.append("## Per-Project Breakdown")
            parts.append("")
            for card in project_cards:
                if not isinstance(card, dict):
                    continue
                proj_name = _safe_str(card.get("project_name"))
                parts.append(f"### {_escape_pipe(proj_name)}")
                parts.append(
                    f"Critical: {_safe_int(card.get('critical', 0))} | "
                    f"High: {_safe_int(card.get('high', 0))} | "
                    f"Medium: {_safe_int(card.get('medium', 0))} | "
                    f"Low: {_safe_int(card.get('low', 0))} | "
                    f"Total: {_safe_int(card.get('total', 0))}"
                )
                top5 = card.get("top_findings", [])
                if top5:
                    parts.append("")
                    parts.append("| CVE | Severity | Component | Version | CVSS |")
                    parts.append("| --- | --- | --- | --- | --- |")
                    for f in top5[:5]:
                        if not isinstance(f, dict):
                            continue
                        cvss = _safe_float(f.get("cvss_score"), 1)
                        parts.append(
                            f"| {_escape_pipe(_safe_str(f.get('cve_id')))} "
                            f"| {_safe_str(f.get('severity'))} "
                            f"| {_escape_pipe(_safe_str(f.get('component')))} "
                            f"| {_escape_pipe(_safe_str(f.get('component_version')))} "
                            f"| {cvss} |"
                        )
                parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Workflow Summary ─────────────────────────────────────────────────

    def _render_workflow_summary(self, recipe: Recipe, report_data: ReportData) -> str:
        import json as _json

        tr = self._get_transform_result(report_data)

        kpis = tr.get("kpis", {})
        if not isinstance(kpis, dict):
            kpis = {}
        timeline = tr.get("timeline", [])
        if not isinstance(timeline, list):
            timeline = []
        steps = tr.get("steps", [])
        if not isinstance(steps, list):
            steps = []
        workflow_meta = tr.get("workflow_meta", {})
        if not isinstance(workflow_meta, dict):
            workflow_meta = {}

        parts = ["# Workflow Summary", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        if workflow_meta.get("start_time"):
            parts.append(f"**Started:** {workflow_meta['start_time']}")
            parts.append("")

        # KPI table
        dur = kpis.get("total_duration_sec", 0)
        if dur >= 60:
            dur_str = f"{dur / 60:.1f}m"
        else:
            dur_str = f"{int(dur)}s"
        metrics: list[tuple[str, Any]] = [
            ("Findings Triaged", _safe_int(kpis.get("total_findings_triaged", 0))),
            ("VEX Applied", _safe_int(kpis.get("vex_applied", 0))),
            ("Tickets Created", _safe_int(kpis.get("tickets_created", 0))),
            ("Notifications Sent", _safe_int(kpis.get("notifications_sent", 0))),
            ("Total Steps", _safe_int(kpis.get("total_steps", 0))),
            ("Duration", dur_str),
        ]
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Timeline
        if timeline:
            parts.append("## Timeline")
            for i, tl in enumerate(timeline):
                if not isinstance(tl, dict):
                    continue
                display_name = tl.get("label") or tl.get("step", "")
                ts = tl.get("timestamp", "")
                dur_prev = tl.get("duration_from_prev_sec", 0)
                dur_note = f" (+{dur_prev:.0f}s)" if dur_prev else ""
                ts_note = f" — {ts}" if ts else ""
                parts.append(
                    f"{i + 1}. **{_escape_pipe(display_name)}**{dur_note}{ts_note}"
                )
            parts.append("")

        # Per-step details
        if steps:
            parts.append("## Step Details")
            parts.append("")
            for step in steps:
                if not isinstance(step, dict):
                    continue
                display_name = step.get("label") or step.get("step", "")
                step_type = step.get("step_type", "unknown")
                detail = step.get("detail", {})
                raw_data = step.get("raw_data", {})

                tag = f" [{step.get('step', '')}]"
                parts.append(f"### {_escape_pipe(display_name)}{tag}")
                parts.append("")

                if step_type == "triage" and isinstance(detail, dict):
                    ts_d = detail.get("triage_summary", {})
                    cr = detail.get("change_report", {})
                    vx = detail.get("vex_applied", {})
                    if isinstance(ts_d, dict) and ts_d.get("total_recommendations"):
                        parts.append(
                            f"- **{ts_d['total_recommendations']}** findings triaged"
                        )
                    if isinstance(cr, dict) and cr.get("new_recommendations"):
                        parts.append(
                            f"- **{cr['new_recommendations']}** new recommendations"
                        )
                    if isinstance(vx, dict) and vx.get("applied_count"):
                        parts.append(
                            f"- **{vx['applied_count']}** VEX statements applied"
                        )

                elif step_type == "tickets" and isinstance(detail, dict):
                    tickets = detail.get("tickets_created", [])
                    count = detail.get("tickets_count", 0)
                    if isinstance(tickets, list) and tickets:
                        parts.append("| Component | Ticket |")
                        parts.append("| --- | --- |")
                        for t in tickets:
                            if not isinstance(t, dict):
                                continue
                            comp = _escape_pipe(str(t.get("component", "—")))
                            key = _escape_pipe(
                                str(t.get("ticket_key", t.get("key", "—")))
                            )
                            parts.append(f"| {comp} | {key} |")
                    elif count:
                        parts.append(
                            f"- **{count}** ticket{'s' if count != 1 else ''} created"
                        )

                elif step_type == "notification" and isinstance(detail, dict):
                    status = "Sent" if detail.get("success") else "Failed"
                    channel = detail.get("channel", "")
                    line = f"- **{status}**"
                    if channel:
                        line += f" — {_escape_pipe(channel)}"
                    parts.append(line)

                elif step_type == "recipe_run" and isinstance(detail, dict):
                    recipe_name = detail.get("recipe", "")
                    if recipe_name:
                        parts.append(f"- Recipe: **{_escape_pipe(recipe_name)}**")
                    output_files = detail.get("output_files", [])
                    if isinstance(output_files, list) and output_files:
                        parts.append(
                            f"- {len(output_files)} output file{'s' if len(output_files) != 1 else ''}"
                        )

                else:
                    # Unknown step — fenced JSON
                    parts.append("```json")
                    parts.append(_json.dumps(raw_data, indent=2, default=str))
                    parts.append("```")

                parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Component Remediation Package ────────────────────────────────

    def _render_component_remediation_package(
        self, recipe: Recipe, report_data: ReportData
    ) -> str:
        tr = self._get_transform_result(report_data)

        actions: list[dict[str, Any]] = tr.get("actions", [])
        suppressed: list[dict[str, Any]] = tr.get("suppressed", [])
        summary: dict[str, Any] = tr.get("summary", {})

        parts = ["# Component Remediation Package", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Summary
        comp_name = summary.get("component_name", "")
        ver_range = summary.get("version_range", "")
        label = comp_name
        if ver_range:
            label += f" ({ver_range})"
        if label:
            parts.append(f"**Component:** {label}")
            parts.append("")

        metrics = [
            ("Action Cards", summary.get("total_actions", len(actions))),
            ("Affected Projects", summary.get("affected_project_count", 0)),
            ("Zero-Day Actions", summary.get("zero_day_actions", 0)),
            ("CVE Actions", summary.get("cve_actions", 0)),
            ("Critical", summary.get("critical_actions", 0)),
            ("High", summary.get("high_actions", 0)),
        ]
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Action cards
        if actions:
            parts.append("## Remediation Actions")
            parts.append("")
            for action in actions:
                comp = action.get("component_name", "")
                ver = action.get("component_version_name", "")
                severity = action.get("max_severity", "UNKNOWN")
                is_zd = action.get("is_zero_day", False)
                tag = "ZERO-DAY" if is_zd else severity
                cve_count = len(action.get("cve_ids", []))
                project_count = len(action.get("affected_projects", []))

                parts.append(
                    f"### {comp} {ver} [{tag}] — {cve_count} CVEs, "
                    f"{project_count} project(s)"
                )
                parts.append("")

                # Affected projects
                projects = action.get("affected_projects", [])
                if projects:
                    parts.append(f"**Projects:** {', '.join(projects)}")
                    parts.append("")

                # CVEs
                cve_ids = action.get("cve_ids", [])
                if cve_ids:
                    parts.append(f"**Known CVEs:** {', '.join(cve_ids[:20])}")
                    if len(cve_ids) > 20:
                        parts.append(f"  *(+{len(cve_ids) - 20} more)*")
                    parts.append("")
                elif is_zd:
                    parts.append("**Known CVEs:** None — zero-day scenario")
                    parts.append("")

                # Upgrade recommendation
                upgrade = action.get("upgrade_recommendation", "")
                if upgrade:
                    parts.append(f"**Upgrade:** {upgrade}")
                    parts.append("")

                # Interim mitigations
                mitigations = action.get("interim_mitigations", [])
                if mitigations:
                    parts.append("**Interim Mitigations:**")
                    for m in mitigations:
                        parts.append(f"- {m}")
                    parts.append("")

                # AI guidance (live LLM response)
                ai_guidance = action.get("ai_guidance", "")
                if ai_guidance:
                    parts.append("**AI Remediation Guidance:**")
                    parts.append("")
                    parts.append(ai_guidance)
                    parts.append("")

                # AI prompt (for copy-paste when no live call)
                prompt_data = action.get("ai_prompt")
                if prompt_data and not ai_guidance:
                    parts.append("**AI Prompt (copy-paste):**")
                    parts.append("")
                    parts.append("```")
                    parts.append(prompt_data.get("user", ""))
                    parts.append("```")
                    parts.append("")

        # Suppressed findings
        if suppressed:
            parts.append("## Suppressed Findings")
            parts.append("")
            parts.append("| Component | Version | CVE | Severity | Status | Project |")
            parts.append("|-----------|---------|-----|----------|--------|---------|")
            for s in suppressed[:50]:
                parts.append(
                    f"| {_safe_str(s.get('component_name', ''))} "
                    f"| {_safe_str(s.get('component_version_name', ''))} "
                    f"| {_safe_str(s.get('cve_id', ''))} "
                    f"| {_safe_str(s.get('severity', ''))} "
                    f"| {_safe_str(s.get('status', ''))} "
                    f"| {_safe_str(s.get('project_name', ''))} |"
                )
            if len(suppressed) > 50:
                parts.append(f"\n*({len(suppressed) - 50} more suppressed findings)*")
            parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Component Impact ─────────────────────────────────────────────

    def _render_component_impact(self, recipe: Recipe, report_data: ReportData) -> str:
        tr = self._get_transform_result(report_data)

        locations: list[dict[str, Any]] = tr.get("locations", [])
        summary: dict[str, Any] = tr.get("summary", {})

        comp_name = summary.get("component_name", "")
        ver_range = summary.get("version_range", "")
        label = comp_name
        if ver_range:
            label += f" ({ver_range})"

        parts = [f"# Component Impact — {label}", ""]
        parts.append(self._metadata_block(report_data, recipe))
        parts.append("")

        # Summary
        metrics = [
            (
                "Projects with Component",
                summary.get("projects_with_component", len(locations)),
            ),
            ("Projects with CVE Findings", summary.get("projects_with_findings", 0)),
            ("Total CVEs", summary.get("total_cve_count", 0)),
            ("Critical", summary.get("critical_count", 0)),
            ("High", summary.get("high_count", 0)),
        ]
        parts.append(self._summary_table(metrics))
        parts.append("")

        # Locations table
        if locations:
            parts.append("## Affected Projects")
            parts.append("")
            parts.append("| Project | Version(s) | CVEs | Critical | High | Medium |")
            parts.append("|---------|------------|------|----------|------|--------|")
            for loc in locations:
                proj = _safe_str(loc.get("project_name", ""))
                versions = ", ".join(loc.get("detected_versions", [])) or "—"
                cve_count = loc.get("cve_count", 0)
                critical = loc.get("critical_count", 0)
                high = loc.get("high_count", 0)
                medium = loc.get("medium_count", 0)
                parts.append(
                    f"| {proj} | {versions} | {cve_count} | {critical} | {high} | {medium} |"
                )
            parts.append("")

            # Top CVEs across all projects
            all_top_cves: list[dict[str, Any]] = []
            for loc in locations:
                for cve in loc.get("top_cves", []):
                    if isinstance(cve, dict) and cve not in all_top_cves:
                        all_top_cves.append(cve)
            if all_top_cves:
                all_top_cves.sort(
                    key=lambda c: float(c.get("cvss_score", 0)), reverse=True
                )
                parts.append("## Top CVEs")
                parts.append("")
                parts.append("| CVE ID | Severity | CVSS |")
                parts.append("|--------|----------|------|")
                for cve in all_top_cves[:10]:
                    cve_id = _safe_str(cve.get("cve_id", ""))
                    severity = _safe_str(cve.get("severity", ""))
                    cvss = cve.get("cvss_score", "")
                    parts.append(f"| {cve_id} | {severity} | {cvss} |")
                parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"

    # ── Scan Quality ──────────────────────────────────────────────────

    def _render_scan_quality(self, recipe: Recipe, report_data: ReportData) -> str:
        tr = self._get_transform_result(report_data)
        meta = report_data.metadata

        summary_df = tr.get("summary_table", pd.DataFrame())
        if not isinstance(summary_df, pd.DataFrame):
            summary_df = pd.DataFrame()
        summary = tr.get("summary", {})
        if not isinstance(summary, dict):
            summary = {}

        # Derive scope label from metadata
        scope_parts = []
        folder = meta.get("folder_name", "") or meta.get("folder_filter", "")
        project = meta.get("project_filter", "")
        if folder:
            scope_parts.append(f"Folder: {folder}")
        if project:
            scope_parts.append(f"Project: {project}")
        scope = ", ".join(scope_parts) if scope_parts else "All Projects"

        date_str = datetime.now(UTC).strftime("%Y-%m-%d")

        parts = [
            "# Scan Quality Report",
            f"**Generated:** {date_str} | **Scope:** {scope}",
            "",
        ]

        # Summary stats
        total_projects = _safe_int(summary.get("total_projects", len(summary_df)))
        avg_coverage = summary.get("avg_coverage_score", 0.0)
        reach_cov = summary.get("reachability_coverage", {})
        if not isinstance(reach_cov, dict):
            reach_cov = {}
        with_reachability = _safe_int(reach_cov.get("with_reachability", 0))
        binary_projects = _safe_int(reach_cov.get("binary_projects", 0))
        # binary projects eligible for reachability = those with binary SCA
        # (with_reachability already has it; binary_projects = binary without reach)
        total_binary = with_reachability + binary_projects
        stale_count = _safe_int(summary.get("stale_project_count", 0))

        parts.append("## Summary")
        parts.append(f"- **Projects Scanned:** {total_projects}")
        parts.append(f"- **Avg Coverage Score:** {_safe_float(avg_coverage)} / 4")
        parts.append(
            f"- **Reachability Coverage:** {with_reachability} of {total_binary}"
            " binary-scanned projects"
        )
        parts.append(f"- **Stale/Dormant Projects:** {stale_count}")
        parts.append("")

        # Summary table — curated columns
        if not summary_df.empty:
            parts.append("## Projects")
            table_cols = [
                "project_name",
                "staleness",
                "coverage_score",
                "has_reachability",
                "critical_findings",
                "unpack_rating",
            ]
            table_headers = {
                "project_name": "Project",
                "staleness": "Staleness",
                "coverage_score": "Coverage Score",
                "has_reachability": "Reachability",
                "critical_findings": "Critical Findings",
                "unpack_rating": "Unpack Rating",
            }
            parts.append(
                self._df_to_table(summary_df, columns=table_cols, headers=table_headers)
            )
            parts.append("")

        # Projects Needing Attention
        if not summary_df.empty:
            attention_rows: list[tuple[str, str]] = []
            for _, row in summary_df.iterrows():
                issues: list[str] = []
                staleness_val = _safe_str(row.get("staleness", ""))
                if staleness_val in ("STALE", "DORMANT"):
                    issues.append(staleness_val)
                if _safe_str(row.get("has_reachability", "")) == "No":
                    issues.append("No reachability")
                unpack_val = _safe_str(row.get("unpack_rating", ""))
                if unpack_val in ("Fair", "Poor"):
                    issues.append(f"{unpack_val} unpack quality")
                if issues:
                    proj = _escape_pipe(_safe_str(row.get("project_name", "")))
                    attention_rows.append((proj, ", ".join(issues)))

            if attention_rows:
                parts.append("## Projects Needing Attention")
                parts.append("")
                parts.append("| Project | Issue |")
                parts.append("|---------|-------|")
                for proj, issue in attention_rows:
                    parts.append(f"| {proj} | {issue} |")
                parts.append("")

        parts.append(self._footer())
        return "\n".join(parts) + "\n"
