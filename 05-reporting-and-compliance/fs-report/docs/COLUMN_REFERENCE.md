# Column Reference Guide

This document lists all column names produced by each transform function. Use these names for template access.

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

| Column | Type | Description |
|--------|------|-------------|
| `id` | string | Scan identifier |
| `scan_date` | string | Start timestamp |
| `completion_date` | string | End timestamp or '-' |
| `status` | string | COMPLETED, ERROR, INITIAL, STARTED |
| `type` | string | SCA, SAST, CONFIG, etc. |
| `project_name` | string | Project name |
| `version_name` | string | Version name |
| `duration_minutes` | float | Time to complete |
| `current_status_time_minutes` | float | Time in current status |
| `errorMessage` | string | Error details or '-' |

### failure_types List

| Key | Type | Description |
|-----|------|-------------|
| `type` | string | Scan type (SCA, SAST, etc.) |
| `count` | int | Failed scan count |

---

## Component Vulnerability Analysis

### portfolio_data DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `name` | string | Component name |
| `version` | string | Component version |
| `project_count` | int | Projects using this component |
| `portfolio_composite_risk` | int | Aggregate risk score |
| `normalized_risk_score` | int | Risk per project |
| `findings_count` | int | Total findings |
| `has_kev` | bool | In CISA KEV |
| `has_exploits` | bool | Known exploits exist |

---

## Findings by Project

### Main DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `Project Name` | string | Project name |
| `CVE ID` | string | CVE identifier |
| `Component` | string | Affected component |
| `Component Version` | string | Component version |
| `Project Version` | string | Project version |
| `CVSS` | float | CVSS score |
| `# of known exploits` | int | Exploit count |
| `# of known weaponization` | int | Weaponization count |
| `CWE` | string | CWE identifier |

---

## Component List

### Main DataFrame

| Column | Type | Description |
|--------|------|-------------|
| `Component` | string | Component name |
| `Version` | string | Component version |
| `Type` | string | library, application, firmware |
| `Supplier` | string | Component supplier |
| `Licenses` | string | License information |
| `Project Name` | string | Project name |
| `Project Version` | string | Project version |
| `Findings` | int | Finding count |
| `Warnings` | int | Warning count |
| `Violations` | int | Violation count |
| `Status` | string | CONFIRMED, NEEDS_REVIEW, etc. |

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

## Triage Prioritization

### findings_df DataFrame (main data)

| Column | Type | Description |
|--------|------|-------------|
| `finding_id` | string | CVE identifier (e.g., CVE-2024-0001) |
| `severity` | string | CVSS severity (CRITICAL, HIGH, MEDIUM, LOW) |
| `risk` | float | CVSS score (0-10) |
| `priority_band` | string | Triage band: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `triage_score` | float | Composite triage score (0-100) |
| `gate_assignment` | string | GATE_1, GATE_2, ADDITIVE, or NONE |
| `reachability_label` | string | REACHABLE, INCONCLUSIVE, UNREACHABLE |
| `reachability_score` | float | Raw reachability score (positive/zero/negative) |
| `has_exploit` | bool | Whether known exploits exist |
| `in_kev` | bool | Whether in CISA KEV |
| `attack_vector` | string | NETWORK, ADJACENT, LOCAL, PHYSICAL |
| `epss_percentile` | float | EPSS percentile (0-1) |
| `epss_score` | float | Raw EPSS score (0-1) |
| `component_name` | string | Component name |
| `component_version` | string | Component version |
| `project_name` | string | Project name |
| `project_version_id` | string | Project version identifier |
| `score_reachability` | float | Reachability contribution to score |
| `score_exploit` | float | Exploit/KEV contribution to score |
| `score_vector` | float | Attack vector contribution to score |
| `score_epss` | float | EPSS contribution to score |
| `score_cvss` | float | CVSS contribution to score |
| `vex_status` | string | Recommended VEX status |
| `vex_justification` | string | Justification for VEX status |
| `vex_reason` | string | Human-readable reason for VEX decision |

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
| `additive_high` | int | Additive scoring → HIGH |
| `additive_medium` | int | Additive scoring → MEDIUM |
| `additive_low` | int | Additive scoring → LOW |
| `additive_info` | int | Additive scoring → INFO |

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

## Version Comparison

The Version Comparison report produces four DataFrames for CSV/XLSX export.

### Summary (one row per version)

| Column | Type | Description |
|--------|------|-------------|
| `Project` | string | Project name |
| `Version` | string | Version name |
| `Date` | string | Version created date (YYYY-MM-DD) |
| `Total Findings` | int | Total findings in this version |
| `Critical` | int | Critical severity count |
| `High` | int | High severity count |
| `Medium` | int | Medium severity count |
| `Low` | int | Low severity count |
| `Fixed (vs prev)` | int | Findings fixed since previous version |
| `New (vs prev)` | int | New findings since previous version |
| `Components` | int | Unique component count |

### Findings Detail (one row per finding per version)

| Column | Type | Description |
|--------|------|-------------|
| `Project` | string | Project name |
| `Version` | string | Version name |
| `Date` | string | Version created date |
| `ID` | string | CVE ID or finding ID |
| `Severity` | string | CRITICAL, HIGH, MEDIUM, LOW, INFO, UNSPECIFIED |
| `Component Name` | string | Affected component |
| `Component Version` | string | Component version |
| `Risk` | float | CVSS risk score (0-10) |
| `Title` | string | Finding title/description |

### Findings Churn (one row per fixed or new finding per version pair)

| Column | Type | Description |
|--------|------|-------------|
| `Project` | string | Project name |
| `From Version` | string | Baseline version name |
| `To Version` | string | Current version name |
| `Change Type` | string | `Fixed` or `New` |
| `ID` | string | CVE ID or finding ID |
| `Severity` | string | CRITICAL, HIGH, MEDIUM, LOW, INFO, UNSPECIFIED |
| `Component Name` | string | Affected component |
| `Component Version` | string | Component version |
| `Risk` | float | CVSS risk score (0-10) |
| `Title` | string | Finding title/description |

### Component Churn (one row per component change per version pair)

| Column | Type | Description |
|--------|------|-------------|
| `Project` | string | Project name |
| `From Version` | string | Baseline version name |
| `To Version` | string | Current version name |
| `Change Type` | string | `added`, `removed`, or `updated` |
| `Component Name` | string | Component name |
| `Version Baseline` | string | Component version in baseline (empty if added) |
| `Version Current` | string | Component version in current (empty if removed) |
| `Findings Impact` | int | Number of findings attributed to this component change |

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
{% if row.has_kev %}🔒{% else %}-{% endif %}
```
