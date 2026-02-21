# Column Reference Guide

This document lists all CSV/XLSX column names produced by each report, in the order they appear. Use these names for template access.

## Findings by Project

### Main DataFrame

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `CVE ID` | string | CVE identifier |
| 2 | `Severity` | string | Finding severity (CRITICAL, HIGH, MEDIUM, LOW) |
| 3 | `CVSS` | float | CVSS score (0-10) |
| 4 | `Project Name` | string | Project name |
| 5 | `Project Version` | string | Project version |
| 6 | `Folder` | string | Folder path (when folder filtering active) |
| 7 | `Component` | string | Affected component name |
| 8 | `Component Version` | string | Component version |
| 9 | `Status` | string | Finding status |
| 10 | `Detected` | string | Detection date |
| 11 | `# of known exploits` | int | Exploit count |
| 12 | `# of known weaponization` | int | Weaponization count |
| 13 | `CWE` | string | CWE identifier |
| 14 | `Description` | string | CVE description from NVD (English) |
| 15 | `CVSS v2 Vector` | string | CVSS v2 vector string |
| 16 | `CVSS v3 Vector` | string | CVSS v3.1 vector string (fallback v3.0) |
| 17 | `NVD URL` | string | Link to NVD detail page |
| 18 | `FS Link` | string | Direct link to finding in Finite State platform |

---

## Triage Prioritization

### findings_df DataFrame (CSV/XLSX output)

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `finding_id` | string | CVE identifier (e.g., CVE-2024-0001) |
| 2 | `severity` | string | CVSS severity (CRITICAL, HIGH, MEDIUM, LOW) |
| 3 | `risk` | float | CVSS score (0-10) |
| 4 | `priority_band` | string | Triage band: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| 5 | `triage_score` | float | Composite triage score (0-100) |
| 6 | `gate_assignment` | string | GATE_1, GATE_2, ADDITIVE, or NONE |
| 7 | `component_name` | string | Component name |
| 8 | `component_version` | string | Component version |
| 9 | `project_name` | string | Project name |
| 10 | `version_name` | string | Version name |
| 11 | `reachability_label` | string | REACHABLE, INCONCLUSIVE, UNREACHABLE |
| 12 | `reachability_score` | float | Raw reachability score (positive/zero/negative) |
| 13 | `vuln_functions` | string | Vulnerable function names (comma-separated) |
| 14 | `has_exploit` | bool | Whether known exploits exist |
| 15 | `in_kev` | bool | Whether in CISA KEV |
| 16 | `attack_vector` | string | NETWORK, ADJACENT, LOCAL, PHYSICAL |
| 17 | `epss_percentile` | float | EPSS percentile (0-1) |
| 18 | `ai_fix_version` | string | AI-recommended fix version (when `--ai` enabled) |
| 19 | `ai_guidance` | string | AI remediation guidance (when `--ai` enabled) |
| 20 | `ai_workaround` | string | AI workaround suggestion (when `--ai` enabled) |
| 21 | `ai_confidence` | string | AI confidence: high, medium, low (when `--ai` enabled) |
| 22 | `internal_id` | string | Internal finding identifier |
| 23 | `component_id` | string | Component identifier |
| 24 | `project_id` | string | Project identifier |
| 25 | `project_version_id` | string | Project version identifier |

### portfolio_summary Dict

| Key | Type | Description |
|-----|------|-------------|
| `CRITICAL` | int | Count of CRITICAL findings |
| `HIGH` | int | Count of HIGH findings |
| `MEDIUM` | int | Count of MEDIUM findings |
| `LOW` | int | Count of LOW findings |
| `INFO` | int | Count of INFO findings |
| `total` | int | Total finding count |

### project_summary_df List[Dict]

| Key | Type | Description |
|-----|------|-------------|
| `project_name` | string | Project name |
| `CRITICAL` | int | CRITICAL count for project |
| `HIGH` | int | HIGH count for project |
| `MEDIUM` | int | MEDIUM count for project |
| `LOW` | int | LOW count for project |
| `INFO` | int | INFO count for project |
| `total_findings` | int | Total findings in project |
| `avg_score` | float | Average triage score |

### top_components List[Dict]

| Key | Type | Description |
|-----|------|-------------|
| `component_name` | string | Component name |
| `component_version` | string | Component version |
| `CRITICAL` | int | CRITICAL findings count |
| `HIGH` | int | HIGH findings count |
| `MEDIUM` | int | MEDIUM findings count |
| `LOW` | int | LOW findings count |
| `total_findings` | int | Total findings |
| `avg_score` | float | Average triage score |
| `max_score` | float | Max triage score |

### gate_funnel Dict

| Key | Type | Description |
|-----|------|-------------|
| `gate_1_critical` | int | Findings entering Gate 1 (Reachable+Exploit) |
| `gate_2_high` | int | Findings entering Gate 2 (Strong Signal) |
| `additive_high` | int | Additive scoring -> HIGH |
| `additive_medium` | int | Additive scoring -> MEDIUM |
| `additive_low` | int | Additive scoring -> LOW |
| `additive_info` | int | Additive scoring -> INFO |

### cvss_band_matrix Dict

| Key | Type | Description |
|-----|------|-------------|
| `rows` | list | CVSS severity labels |
| `cols` | list | Priority band labels |
| `data` | list | Objects with `x`, `y`, `v`, `severity`, `band` |

### factor_radar Dict

| Key | Type | Description |
|-----|------|-------------|
| `labels` | list | Factor names (Reachability, Exploit, Vector, EPSS, CVSS) |
| `datasets` | list | Per-project datasets with `label` and `data` arrays |

### vex_recommendations DataFrame (JSON output)

| Column | Type | Description |
|--------|------|-------------|
| `finding_id` | string | CVE identifier |
| `project_version_id` | string | Project version ID |
| `priority_band` | string | Triage band |
| `triage_score` | float | Composite score |
| `vex_status` | string | EXPLOITABLE, IN_TRIAGE, NOT_AFFECTED |
| `vex_justification` | string | Justification text |
| `vex_reason` | string | AI-generated or template reason |
| `component_name` | string | Component name |
| `severity` | string | CVSS severity |

### AI Guidance Fields (when `--ai` enabled)

| Key | Type | Description |
|-----|------|-------------|
| `ai_portfolio_summary` | string | Portfolio-level remediation narrative |
| `ai_project_summaries` | dict | Per-project remediation narratives |
| `ai_component_guidance` | dict | Per-component fix guidance (full depth) |
| `ai_remediation_guidance` | dict | Per-finding guidance object |
| `ai_remediation_guidance.guidance` | string | Remediation steps |
| `ai_remediation_guidance.fix_version` | string | Recommended fix version |
| `ai_remediation_guidance.workaround` | string | Temporary mitigation |
| `ai_remediation_guidance.code_search_hints` | string | Code patterns to search for |
| `ai_remediation_guidance.confidence` | string | high, medium, low |

---

## CVE Impact

### Main DataFrame (CSV/XLSX output)

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `CVE ID` | string | CVE identifier |
| 2 | `Severity` | string | CRITICAL, HIGH, MEDIUM, LOW |
| 3 | `CVSS` | float | CVSS score (0-10) |
| 4 | `Title` | string | Finding title |
| 5 | `CWE` | string | CWE identifier |
| 6 | `EPSS Percentile` | float | EPSS percentile (0-1) |
| 7 | `EPSS Score` | float | Raw EPSS score (0-1) |
| 8 | `KEV` | bool | In CISA KEV |
| 9 | `Has Exploit` | bool | Known exploits exist |
| 10 | `Exploits` | string | Exploit details |
| 11 | `Affected Projects` | int | Number of affected projects |
| 12 | `Reachable In` | int | Projects where reachable |
| 13 | `Unreachable In` | int | Projects where unreachable |
| 14 | `Inconclusive In` | int | Projects with inconclusive reachability |
| 15 | `Project Names` | string | Comma-separated project names |
| 16 | `Reachable Projects` | string | Comma-separated reachable project names |
| 17 | `Components` | string | Affected component names |
| 18 | `First Detected` | string | Earliest detection date |
| 19 | `Last Detected` | string | Most recent detection date |

---

## Component Vulnerability Analysis

### portfolio_data DataFrame

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `name` | string | Component name |
| 2 | `version` | string | Component version |
| 3 | `portfolio_composite_risk` | int | Aggregate risk score |
| 4 | `normalized_risk_score` | int | Risk per project |
| 5 | `cumulative_percentage` | float | Cumulative risk contribution (%) |
| 6 | `findings_count` | int | Total findings |
| 7 | `project_count` | int | Projects using this component |
| 8 | `has_kev` | bool | In CISA KEV |
| 9 | `has_exploits` | bool | Known exploits exist |
| 10 | `project_names` | string | Comma-separated project names |

---

## Component List

### Main DataFrame

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `Component` | string | Component name |
| 2 | `Version` | string | Component version |
| 3 | `Type` | string | library, application, firmware |
| 4 | `Source` | string | How discovered: Source SCA, Binary SCA, SBOM Import, etc. |
| 5 | `Project Name` | string | Project name |
| 6 | `Project Version` | string | Project version |
| 7 | `Folder` | string | Folder path |
| 8 | `Declared License` | string | Automatically detected license (SPDX) |
| 9 | `Concluded License` | string | Human-reviewed/confirmed license (SPDX) |
| 10 | `Copyleft Status` | string | Permissive, Weak Copyleft, Strong Copyleft |
| 11 | `Policy Status` | string | PERMITTED, WARNING, VIOLATION |
| 12 | `Findings` | int | Finding count |
| 13 | `Warnings` | int | Warning count |
| 14 | `Violations` | int | Violation count |
| 15 | `Supplier` | string | Component supplier |
| 16 | `Component Status` | string | CONFIRMED, NEEDS_REVIEW, IN_REVIEW, FALSE_POSITIVE |
| 17 | `BOM Reference` | string | PURL or CPE identifier |
| 18 | `Release Date` | string | Component release date |
| 19 | `Created` | string | Discovery timestamp |
| 20 | `Branch` | string | Branch name |
| 21 | `License URL` | string | Link to license text |

---

## Scan Analysis

### daily_metrics DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `period` | string | Date in YYYY-MM-DD format |
| `date` | string | Same as period |
| `total_scans_started` | int | Scans initiated on this date |
| `unique_projects` | int | Distinct projects with scans |
| `new_projects` | int | Projects with first-ever scan |
| `existing_projects` | int | Projects with prior scans |
| `unique_versions` | int | Distinct versions scanned |
| `server_completed_scans` | int | Completed (non-external) |
| `external_completed_scans` | int | External tool scans |
| `total_completed_scans` | int | All completed scans |
| `failed_scans` | int | Scans with ERROR status |
| `stuck_scans` | int | Scans stuck in progress |
| `recently_queued` | int | Scans in INITIAL state |
| `still_active_scans` | int | Scans currently running |
| `success_rate` | float | Completion percentage |
| `completion_rate` | float | Same as success_rate |
| `avg_duration_minutes` | int | Mean completion time |
| `median_duration_minutes` | int | Median completion time |
| `min_duration_minutes` | int | Fastest scan |
| `max_duration_minutes` | int | Slowest scan |
| `sca_scans` | int | SCA type count |
| `sast_scans` | int | SAST type count |
| `config_scans` | int | CONFIG type count |
| `source_sca_scans` | int | SOURCE_SCA type count |
| `vulnerability_analysis_scans` | int | VULNERABILITY_ANALYSIS count |
| `sbom_import_scans` | int | SBOM_IMPORT type count |

### raw_data DataFrame

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `id` | string | Scan identifier |
| 2 | `type` | string | SCA, SAST, CONFIG, etc. |
| 3 | `status` | string | COMPLETED, ERROR, INITIAL, STARTED |
| 4 | `folder_name` | string | Folder name |
| 5 | `project_name` | string | Project name |
| 6 | `version_name` | string | Version name |
| 7 | `scan_date` | string | Start timestamp |
| 8 | `completion_date` | string | End timestamp or '-' |
| 9 | `duration_minutes` | float | Time to complete |
| 10 | `current_status_time_minutes` | float | Time in current status |
| 11 | `errorMessage` | string | Error details or '-' |

### failure_types List

| Key | Type | Description |
|-----|------|-------------|
| `type` | string | Scan type (SCA, SAST, etc.) |
| `count` | int | Failed scan count |

---

## Version Comparison

The Version Comparison report produces four DataFrames for CSV/XLSX export.

### Summary (one row per version)

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `Project` | string | Project name |
| 2 | `Version` | string | Version name |
| 3 | `Date` | string | Version created date (YYYY-MM-DD) |
| 4 | `Total Findings` | int | Total findings in this version |
| 5 | `Critical` | int | Critical severity count |
| 6 | `High` | int | High severity count |
| 7 | `Medium` | int | Medium severity count |
| 8 | `Low` | int | Low severity count |
| 9 | `Fixed (vs prev)` | int | Findings fixed since previous version |
| 10 | `New (vs prev)` | int | New findings since previous version |
| 11 | `Components` | int | Unique component count |

### Findings Detail (one row per finding per version)

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `Project` | string | Project name |
| 2 | `Version` | string | Version name |
| 3 | `Date` | string | Version created date |
| 4 | `ID` | string | CVE ID or finding ID |
| 5 | `Severity` | string | CRITICAL, HIGH, MEDIUM, LOW, INFO, UNSPECIFIED |
| 6 | `Component Name` | string | Affected component |
| 7 | `Component Version` | string | Component version |
| 8 | `Risk` | float | CVSS risk score (0-10) |
| 9 | `Title` | string | Finding title/description |

### Findings Churn (one row per fixed or new finding per version pair)

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `Project` | string | Project name |
| 2 | `From Version` | string | Baseline version name |
| 3 | `To Version` | string | Current version name |
| 4 | `Change Type` | string | `Fixed` or `New` |
| 5 | `ID` | string | CVE ID or finding ID |
| 6 | `Severity` | string | CRITICAL, HIGH, MEDIUM, LOW, INFO, UNSPECIFIED |
| 7 | `Component Name` | string | Affected component |
| 8 | `Component Version` | string | Component version |
| 9 | `Risk` | float | CVSS risk score (0-10) |
| 10 | `Title` | string | Finding title/description |

### Component Churn (one row per component change per version pair)

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | `Project` | string | Project name |
| 2 | `From Version` | string | Baseline version name |
| 3 | `To Version` | string | Current version name |
| 4 | `Change Type` | string | `added`, `removed`, or `updated` |
| 5 | `Component Name` | string | Component name |
| 6 | `Version Baseline` | string | Component version in baseline (empty if added) |
| 7 | `Version Current` | string | Component version in current (empty if removed) |
| 8 | `Findings Impact` | int | Number of findings attributed to this component change |

---

## User Activity

### summary Dict

| Key | Type | Description |
|-----|------|-------------|
| `total_events` | int | Total audit events |
| `unique_users` | int | Distinct users |
| `active_days` | int | Days with activity |
| `avg_daily_users` | float | Average daily active users |

### daily_logins DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `Date` | string | Date in YYYY-MM-DD |
| `Unique Users` | int | Distinct users active |
| `Total Logins` | int | Total events count |

### activity_by_type DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `Event Type` | string | Event category |
| `Count` | int | Event count |
| `Percentage` | float | Percentage of total |

### top_users DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `User` | string | User email |
| `Total Actions` | int | Action count |
| `Logins` | int | Login count |
| `Event Types` | int | Distinct event types |
| `Last Active` | string | Most recent activity |

### data (recent activity) DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `Time` | string | Event timestamp |
| `User` | string | User email |
| `Event Type` | string | Event category |
| `Project` | string | Related project or null |

---

## Executive Summary

### findings DataFrame (input)

| Column | Type | Description |
|--------|------|-------------|
| `project` | string | Project name |
| `severity` | string | Finding severity |
| `status` | string | Finding status |
| `detected` | string | Detection timestamp |

### open_issues DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `severity` | string | Severity level |
| `count` | int | Open finding count |

### scan_frequency DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `month` | string | Month period |
| `scan_count` | int | Scans in period |

---

## Executive Dashboard

HTML-only output. No CSV/XLSX columns.

---

## Template Access Patterns

### Direct Access (Jinja2)

```jinja2
{{ row.column_name }}
{{ row['Column Name'] }}
```

### With Default Value

```jinja2
{{ row.get('column_name', 'default') }}
{{ row.column_name|default('-') }}
```

### Conditional Formatting

```jinja2
{% if row.value >= 90 %}high{% elif row.value >= 70 %}medium{% else %}low{% endif %}
```

### Numeric Formatting

```jinja2
{{ "%.1f"|format(row.percentage) }}%
{{ "%.0f"|format(row.duration) }}
```

### Boolean Check

```jinja2
{% if row.has_kev %}yes{% else %}-{% endif %}
```
