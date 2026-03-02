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
            "Findings by Project": self._render_findings_by_project,
            "Component Vulnerability Analysis": self._render_component_vulnerability_analysis,
            "Version Comparison": self._render_version_comparison,
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
            self.logger.warning(
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

                versions = proj.get("versions", [])
                if versions:
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
                        total = _safe_int(ver.get("total", 0))
                        crit = _safe_int(ver.get("critical", ver.get("CRITICAL", 0)))
                        high = _safe_int(ver.get("high", ver.get("HIGH", 0)))
                        med = _safe_int(ver.get("medium", ver.get("MEDIUM", 0)))
                        low = _safe_int(ver.get("low", ver.get("LOW", 0)))
                        new = _safe_int(ver.get("new", ver.get("new_findings", 0)))
                        fixed = _safe_int(
                            ver.get("fixed", ver.get("fixed_findings", 0))
                        )
                        parts.append(
                            f"| {vname} | {total} | {crit} | {high} | {med} | {low} | {new} | {fixed} |"
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
