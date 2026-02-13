# Finite State Reporting Kit — Report Guide

This guide explains each report available in the Finite State Reporting Kit, what insights they provide, and how to use them effectively.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Report Categories](#report-categories)
3. [Available Reports](#available-reports)
   - [Executive Summary](#executive-summary) *(Operational)*
   - [Scan Analysis](#scan-analysis) *(Operational)*
   - [User Activity](#user-activity) *(Operational)*
   - [Component Vulnerability Analysis](#component-vulnerability-analysis) *(Assessment)*
   - [Findings by Project](#findings-by-project) *(Assessment)*
   - [Component List](#component-list) *(Assessment)*
   - [Triage Prioritization](#triage-prioritization) *(Assessment)*
   - [Version Comparison](#version-comparison) *(Assessment, on-demand: full version & component changelog)*
4. [Output Formats](#output-formats)
5. [Filtering Options](#filtering-options)
6. [Using Reports Together](#using-reports-together)
7. [Recommended Cadence](#recommended-cadence)

---

## Quick Start

```bash
# Generate all reports for the last 30 days
poetry run fs-report --period 30d

# Generate a specific report
poetry run fs-report --recipe "Executive Summary" --period 30d

# List available reports
poetry run fs-report list-recipes

# Filter to a specific project
poetry run fs-report --project "MyProject" --period 30d
```

Reports are saved to the `output/` directory in HTML, CSV, and XLSX formats.

---

## Report Categories

Reports are classified into two categories that determine how the `--period` (or `--start`/`--end`) time window is applied:

### Operational Reports

**"What happened during this period?"**

Operational reports show activity and trends within the specified time window. The `--period` flag filters the data to only include events that occurred during that window.

| Report | What it measures over the period |
|--------|----------------------------------|
| **Executive Summary** | Findings detected during the window |
| **Scan Analysis** | Scans run during the window |
| **User Activity** | User actions during the window |

### Assessment Reports

**"What does the target look like today?"**

Assessment reports show the current security state of the target — the latest version of each project, as it exists right now. The `--period` flag is used only to identify which projects were active (scanned) during the window; the actual findings and components shown are from the current (latest) version, not filtered by date.

| Report | What it shows |
|--------|---------------|
| **Component Vulnerability Analysis** | Current vulnerability posture by component |
| **Findings by Project** | Current findings inventory per project |
| **Component List** | Current software component inventory |
| **Triage Prioritization** | Current triage priorities based on today's data |
| **Version Comparison** | Full version and component changelog across all version pairs (on-demand) |

> **Tip:** If you need to date-filter an Assessment report (e.g., "only show findings detected after January 1"), use the `--detected-after YYYY-MM-DD` flag. This injects a date floor without changing the report's current-state nature.

---

## Available Reports

### Executive Summary

**Category:** Operational — data is filtered to the specified time period.

**Purpose:** High-level security dashboard for leadership and stakeholders.

**Who should use it:** Executives, security leadership, program managers

**What it shows:**
- Overall security posture across all projects
- Distribution of findings by severity
- Security trends over time
- Project-level risk breakdown

**Key visualizations:**
- **Project Breakdown Chart** — How findings are distributed across projects
- **Open Issues Distribution** — Unresolved findings by severity level
- **Security Findings Over Time** — Monthly discovery trends

**What to look for:**
| Healthy | Needs Attention |
|---------|-----------------|
| Majority low/medium severity | High concentration of critical findings |
| Open issues decreasing | Growing backlog of unresolved issues |
| Consistent discovery trends | Sudden spikes in findings |
| Risk spread across projects | One project dominates risk |

**Example command:**
```bash
poetry run fs-report --recipe "Executive Summary" --period 90d
```

---

### Component Vulnerability Analysis

**Category:** Assessment — shows current vulnerability posture regardless of time period.

**Purpose:** Identify which software components create the most risk across your portfolio.

**Who should use it:** Security teams, architects, remediation planners

**What it shows:**
- Highest-risk components across all projects
- Which components affect the most projects
- Composite risk scores combining severity and impact
- Strategic remediation priorities

**Key visualizations:**
- **Pareto Chart** — Component risk ranking with cumulative percentage (focus on the left side)
- **Bubble Chart** — Risk score vs project impact (look for items in upper right)

**How to prioritize:**

| Priority | Criteria | Action |
|----------|----------|--------|
| **Immediate** | High risk + many projects | Fix first for maximum impact |
| **Quick wins** | Very high risk + few projects | Easy to remediate |
| **Strategic** | Medium risk + many projects | Plan coordinated updates |
| **Monitor** | Low risk + few projects | Track but don't prioritize |

**Example command:**
```bash
poetry run fs-report --recipe "Component Vulnerability Analysis" --period 30d
```

---

### Findings by Project

**Category:** Assessment — shows current findings inventory regardless of time period.

**Purpose:** Detailed security findings inventory organized by project.

**Who should use it:** Development teams, project managers, security analysts

**What it shows:**
- Complete list of security findings per project
- CVSS scores and severity levels
- Affected components and versions
- CVE identifiers and exploit information

**Key data columns:**
- **CVSS Score** — Vulnerability severity (0-10 scale)
- **Component & Version** — Specific vulnerable software
- **Project Name** — Which project contains the finding
- **Exploit/Weaponization Count** — Known active threats

**Project health indicators:**
| Status | Indicators |
|--------|------------|
| **Healthy** | Low CVSS scores (<7.0), minimal exploits, manageable count |
| **Needs Attention** | Multiple high CVSS findings, some exploit activity |
| **Critical** | CVSS >8.0, active exploits, large volumes |

**Example commands:**
```bash
# All projects
poetry run fs-report --recipe "Findings by Project" --period 30d

# Specific project
poetry run fs-report --recipe "Findings by Project" --project "MyProject"
```

---

### Scan Analysis

**Category:** Operational — data is filtered to the specified time period.

**Purpose:** Monitor scanning infrastructure performance and understand team scanning patterns.

**Who should use it:** DevSecOps, operations teams, platform administrators

**What it shows:**
- Scan throughput and completion rates
- Success vs failure rates by day
- Average scan durations
- Queue status and backlogs
- **New:** Version tracking to identify duplicate submissions
- **New:** New vs existing project breakdown
- **New:** Failure type distribution

**Key metrics:**
| Metric | What it tells you |
|--------|-------------------|
| **Total Scans** | Volume of scanning activity |
| **Projects (new/existing)** | Are teams creating new projects or reusing existing ones? |
| **Versions** | Unique artifacts processed |
| **Success Rate** | Reliability of scanning infrastructure |
| **Avg Duration** | Performance health |
| **Failed Scans** | Issues requiring investigation |

**Key visualizations:**
- **Throughput Chart** — Daily scans started vs completed with trend lines
- **Success Rate** — Daily reliability percentages
- **Scan Type Distribution** — Workload balance across SCA, SAST, CONFIG, etc.
- **Failure Type Distribution** — Which scan types fail most often

**Understanding new vs existing projects:**
- **High "new" ratio** — Rapid onboarding of new products
- **High "existing" ratio** — Mature, ongoing security processes
- **All new projects** — May indicate workflow issues (teams not reusing projects)

**Operational health:**
| Status | Indicators |
|--------|------------|
| **Healthy** | >95% success rate, stable durations, minimal queue |
| **Needs Attention** | Declining success, growing durations, queue building |
| **Critical** | <90% success, high variability, large backlogs |

**Example command:**
```bash
poetry run fs-report --recipe "Scan Analysis" --period 14d
```

---

### Component List

**Category:** Assessment — shows the current component inventory regardless of time period.

**Purpose:** Complete software inventory (SBOM) across your portfolio.

**Who should use it:** Compliance teams, legal, engineering leadership

**What it shows:**
- All software components in the current (latest) version of each project
- Component versions, types, and suppliers
- License information
- Associated projects, versions, and branches
- Risk metrics per component (findings, warnings, violations)

**Date Filtering:**
By default, no date filtering is applied — the report shows the full current inventory. To restrict to components discovered after a specific date, use `--detected-after YYYY-MM-DD`.

**Key data columns:**
| Column | Description |
|--------|-------------|
| **Component** | Software component name |
| **Version** | Specific version in use |
| **Type** | Library, framework, etc. |
| **Supplier** | Vendor or maintainer |
| **Licenses** | License information for compliance |
| **Project/Version/Branch** | Where the component is used |
| **Findings/Warnings/Violations** | Risk indicators |

**Use cases:**
- **SBOM Compliance** — Export for regulatory requirements
- **License Reviews** — Filter by license type for legal review
- **Standardization** — Identify version fragmentation
- **Risk Assessment** — Focus on high-finding components
- **New Components Report** — Track what new software entered the portfolio this period

**Example commands:**
```bash
# Full current component inventory
poetry run fs-report --recipe "Component List"

# Specific project
poetry run fs-report --recipe "Component List" --project "MyProject"

# Only components discovered since a date
poetry run fs-report --recipe "Component List" --detected-after 2026-01-01

# Specific version
poetry run fs-report --recipe "Component List" --version "1234567890"
```

---

### User Activity

**Category:** Operational — data is filtered to the specified time period.

**Purpose:** Track platform adoption and user engagement.

**Who should use it:** Platform administrators, management, security operations

**What it shows:**
- Daily active user counts
- Average daily users over the period
- Activity breakdown by event type
- Most active users (power users)
- Activity trends over time

**Key metrics:**
| Metric | What it tells you |
|--------|-------------------|
| **Unique Users** | Total distinct users with activity |
| **Days with Activity** | Platform usage consistency |
| **Avg Daily Users** | Typical daily engagement level |

**Key visualizations:**
- **Daily Activity Chart** — Users and events over time (dual-axis)
- **Activity by Type** — What actions users perform most
- **Top Users** — Power users and champions

**What to look for:**
| Healthy | Concerning |
|---------|------------|
| Consistent daily active users | Sharp drops in activity |
| Growing or stable engagement | Declining user counts |
| Diverse activity types | Activity concentrated in 1-2 users |
| Multiple active users | Long periods with no activity |

**Example command:**
```bash
poetry run fs-report --recipe "User Activity" --period 30d
```

---

### Triage Prioritization

**Category:** Assessment — shows current triage priorities regardless of time period.

**Purpose:** Risk-based vulnerability triage that goes beyond CVSS to prioritize findings using reachability, exploit intelligence, attack vectors, and EPSS.

**Who should use it:** Security teams, vulnerability managers, remediation planners

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
poetry run fs-report --recipe "Triage Prioritization" --period 30d
```

**What it shows:**
- Priority bands (CRITICAL, HIGH, MEDIUM, LOW, INFO) based on real-world exploitability
- Gate classification: findings that short-circuit to CRITICAL/HIGH via exploit+reachability
- CVSS vs Priority Band heatmap showing where traditional scoring diverges from context-aware triage
- Per-project risk breakdown with band distribution
- Top 15 riskiest components with remediation priority
- Risk factor radar profiles per project

**Scoring Model:**

| Gate | Criteria | Result |
|------|----------|--------|
| **Gate 1** | Reachable + (Exploit OR KEV) | → CRITICAL |
| **Gate 2** | (Reachable OR Exploit/KEV) + (NETWORK OR EPSS≥90th OR CVSS≥9) | → HIGH |
| **Additive** | Points-based: Reachability (±30), Exploit/KEV (+25/+20), Vector (+15→0), EPSS (0-20), CVSS (0-10) | → Score-based band |

| Band | Score Range | Action |
|------|-------------|--------|
| CRITICAL | Gate 1 | Fix immediately |
| HIGH | Gate 2 or ≥70 | Fix this week |
| MEDIUM | 40-69 | Fix this month |
| LOW | 25-39 | Plan remediation |
| INFO | <25 | Track only |

**AI Remediation Guidance (optional):**

Enable AI-powered remediation guidance with the `--ai` flag:

```bash
# Summary mode (portfolio + project summaries)
poetry run fs-report --recipe "Triage Prioritization" --ai --period 30d

# Full mode (+ component-level fix guidance for Critical/High)
poetry run fs-report --recipe "Triage Prioritization" --ai --ai-depth full --period 30d
```

Requires `ANTHROPIC_AUTH_TOKEN` environment variable. Uses Claude with model tiering (Sonnet for summaries, Haiku for bulk guidance). Results are cached in `~/.fs-report/cache.db`.

**VEX Integration:**

The report generates a `vex_recommendations.json` file that can be used to update finding statuses in the platform:

```bash
python scripts/apply_vex_triage.py output/triage_prioritization/vex_recommendations.json --dry-run
```

**Example commands:**
```bash
# Basic triage report
poetry run fs-report --recipe "Triage Prioritization" --period 30d

# Single project
poetry run fs-report --recipe "Triage Prioritization" --project "MyProject"

# With AI guidance
poetry run fs-report --recipe "Triage Prioritization" --ai --period 30d

# Full AI depth (includes component-level fix guidance)
poetry run fs-report --recipe "Triage Prioritization" --ai --ai-depth full --period 30d
```

---

### Version Comparison

**Category:** Assessment (on-demand) — full version and component changelog for every active project.

**Purpose:** Show the complete progression of each project across *all* its versions: for every version pair (v1→v2, v2→v3, …), what was fixed, what was new, and which component changes drove the difference. It’s a full changelog, not just a single two-version snapshot.

**Who should use it:** Development teams, security engineers, release managers

**How it works:** The report discovers every project that had scan activity in the period and loads *all* scanned versions for each project. It then builds a version-by-version progression: for each step (e.g. 3.14 → 3.15), it shows fixed findings, new findings, and component churn. You can scope to `--project` or `--folder`, or use `--baseline-version` and `--current-version` to limit to a single version pair.

**What it shows:**
- Project summary table (multi-project mode): per-project deltas at a glance
- KPI delta cards: total findings, critical, high, and component counts (before → after)
- Severity comparison: grouped bar chart showing each severity level side by side
- **Changes (latest pair):** Fixed findings table (resolved issues) and New findings table (regressions), side by side with severity summaries
- **Component Changes (latest pair):** Added, removed, and updated components with finding impact
- **Version changelog:** One collapsible entry per version pair (e.g. 3.14 → 3.15) with Fixed | New findings tables and **Component changes** for that pair. The first entry is expanded by default; click a row to expand others.

**Key visualizations:**
- **Project Summary** (multi-project) — One row per project with version names and deltas
- **KPI Delta Cards** — At-a-glance before/after for total, critical, high, and components
- **Severity Comparison** — Grouped bar chart (baseline vs current)
- **Fixed / New Findings** — Side-by-side tables with severity summary line
- **Component Churn** — Added, removed, updated components with finding impact
- **Version changelog** — Per-version-pair fixed/new findings and component changes (expand to see)

**"Fixed" Definition:** A finding is fixed if it is present in the baseline version but **absent from the current version**. Matching is by CVE ID (preferred) or finding ID.

**CSV and XLSX (detail exports):**  
In addition to the **Summary** (one row per version), the report produces detail exports:

| Export | Content |
|--------|---------|
| **Summary** | One row per version: Project, Version, Date, Total/Critical/High/Medium/Low, Fixed (vs prev), New (vs prev), Components |
| **Findings Detail** | One row per finding per version: Project, Version, Date, ID, Severity, Component Name/Version, Risk, Title |
| **Findings Churn** | One row per finding that was fixed or new in some version pair: Project, From Version, To Version, Change Type (Fixed/New), ID, Severity, Component, Risk, Title |
| **Component Churn** | One row per component change (added/removed/updated) across version pairs: Project, From Version, To Version, Change Type, Component Name, Version Baseline/Current, Findings Impact |

- **CSV:** Main file `Version Comparison.csv` (summary) plus `Version Comparison_Detail_Findings.csv`, `Version Comparison_Detail_Findings_Churn.csv`, and `Version Comparison_Detail_Component_Churn.csv` when data exists.
- **XLSX:** Single workbook with sheets **Summary**, **Findings Detail**, **Findings Churn**, and **Component Churn** (sheets omitted if empty).

**What to look for:**
| Healthy | Needs Attention |
|---------|-----------------|
| More fixed than new | More new than fixed |
| Critical count decreasing | New critical findings |
| Component updates reducing findings | Component additions bringing new findings |

**Example commands:**
```bash
# Portfolio-wide: full version changelog for every active project
poetry run fs-report --recipe "Version Comparison" --period 90d

# Scope to a single project
poetry run fs-report --recipe "Version Comparison" --project "Router Firmware"

# Scope to a folder (product group)
poetry run fs-report --recipe "Version Comparison" --folder "Toy Cars"

# Explicit version pair (advanced)
poetry run fs-report --recipe "Version Comparison" \
  --baseline-version 12345 --current-version 67890
```

---

## Output Formats

All reports generate three output formats:

| Format | Best for | Location |
|--------|----------|----------|
| **HTML** | Interactive viewing, sharing, presentations | `output/{Report Name}/{Report Name}.html` |
| **CSV** | Data analysis, spreadsheet import, scripting | `output/{Report Name}/{Report Name}.csv` |
| **XLSX** | Excel users, formatted reports, filtering | `output/{Report Name}/{Report Name}.xlsx` |

**Version Comparison** (full version and component changelog) produces additional detail in CSV and XLSX: alongside the summary file/sheet, it writes **Findings Detail**, **Findings Churn** (fixed/new per version pair), and **Component Churn** as separate CSV files or as additional sheets in the same XLSX workbook. See [Version Comparison](#version-comparison) for the full export table.

---

## Filtering Options

| Option | Description | Applies to | Example |
|--------|-------------|------------|---------|
| `--period` | Relative time period | Operational reports (used to scope Assessment reports to active projects) | `--period 30d` |
| `--start` / `--end` | Specific date range | Same as `--period` | `--start 2026-01-01 --end 2026-01-31` |
| `--detected-after` | Date floor for findings/components | Assessment reports only | `--detected-after 2026-01-01` |
| `--project` | Filter by project name or ID | All reports | `--project "MyProject"` |
| `--version` | Filter by version ID | All reports | `--version "1234567890"` |
| `--recipe` | Run specific report only | N/A | `--recipe "Scan Analysis"` |
| `--finding-types` | Finding types to include | Findings reports | `--finding-types cve,credentials` |
| `--baseline-version` | Baseline version ID | Version Comparison | `--baseline-version 12345` |
| `--current-version` | Current version ID | Version Comparison | `--current-version 67890` |

**How `--period` interacts with report categories:**

- **Operational reports** (Executive Summary, Scan Analysis, User Activity): `--period` directly filters the data to events within the time window.
- **Assessment reports** (CVA, Findings by Project, Component List, Triage): `--period` identifies which projects were active (scanned) during the window, then fetches the **current (latest) version** of those projects. The findings/components shown are not date-filtered.

**`--detected-after` (Assessment reports only):**

Use `--detected-after YYYY-MM-DD` to add a date floor to Assessment reports. For example, to see only findings detected since Q1:

```bash
poetry run fs-report --recipe "Findings by Project" --detected-after 2026-01-01
```

**Period shortcuts:**
- `7d` — last 7 days
- `2w` — last 2 weeks
- `1m` — last month
- `90d` — last 90 days
- `1q` — last quarter

**Finding types (default: `cve`):**

| Value | Description |
|-------|-------------|
| `cve` | CVE/vulnerability findings (default) |
| `sast` | Binary SAST / non-CVE findings (requests both legacy SAST_ANALYSIS and BINARY_SCA so either API naming works) |
| `binary_sca` | Binary SCA findings only (API category BINARY_SCA) |
| `source_sca` | Source SCA findings only (API category SOURCE_SCA) |
| `thirdparty` | Third-party findings |
| `credentials` | Exposed credentials |
| `config_issues` | Configuration issues |
| `crypto_material` | Cryptographic material |
| `all` | All finding types |

**Examples:**
```bash
# Default: CVE findings only (recommended for most reports)
poetry run fs-report --period 30d

# Include credentials along with CVEs
poetry run fs-report --period 30d --finding-types cve,credentials

# Only credentials findings
poetry run fs-report --period 30d --finding-types credentials

# All findings (includes SAST/FILE components)
poetry run fs-report --period 30d --finding-types all
```

**Why default to CVE only?**
- SAST findings are associated with FILE-type components (placeholders for static analysis results)
- FILE components have no license or supplier information
- CVE findings are the most actionable for remediation priorities

---

## Using Reports Together

### Strategic Workflow

1. **Start with Executive Summary** → Understand overall portfolio health
2. **Run Triage Prioritization** → Identify what to fix first using context-aware scoring
3. **Dive into Component Vulnerability Analysis** → Identify organization-wide priorities
4. **Use Findings by Project** → Plan specific remediation within projects
5. **Run Version Comparison** → Validate that remediation work produced results
6. **Monitor with Scan Analysis** → Ensure scanning infrastructure supports the work
7. **Track with Component List** → Maintain software inventory for compliance
8. **Review User Activity** → Ensure platform adoption and engagement

### By Audience

| Audience | Primary Reports |
|----------|-----------------|
| **Executives** | Executive Summary |
| **Security Leadership** | Executive Summary, Component Vulnerability Analysis, Triage Prioritization |
| **Development Teams** | Findings by Project, Version Comparison, Triage Prioritization |
| **Release Managers** | Version Comparison |
| **Vulnerability Management** | Triage Prioritization (with `--ai`) |
| **DevSecOps / Operations** | Scan Analysis |
| **Compliance / Legal** | Component List |
| **Platform Administrators** | User Activity, Scan Analysis |

---

## Recommended Cadence

### Operational Reports (period-bound)

| Report | Frequency | Purpose |
|--------|-----------|---------|
| **Executive Summary** | Monthly (leadership), Weekly (security) | Track trends and overall progress |
| **Scan Analysis** | Daily (operations), Weekly (reviews) | Monitor scanning infrastructure |
| **User Activity** | Weekly (adoption), Monthly (stakeholder reviews) | Engagement tracking |

### Assessment Reports (current state)

| Report | Frequency | Purpose |
|--------|-----------|---------|
| **Triage Prioritization** | Weekly (active remediation), On-demand | Prioritize what to fix next |
| **Component Vulnerability Analysis** | Quarterly (strategic), Monthly (active remediation) | Prioritize risky components |
| **Findings by Project** | Weekly (dev teams), Daily (during sprints) | Plan project-level remediation |
| **Component List** | Monthly (audits), On-demand (SBOM requests) | Compliance and inventory tracking |
| **Version Comparison** | On-demand (after remediation or releases) | Validate specific version improvements |

---

## Getting Help

For questions or issues:
- Review the `README.md` for installation and CLI reference
- Check `CUSTOMER_SETUP.md` for environment configuration
- Contact your Finite State representative for support
