# Finite State Reporting Kit — Report Guide

This guide explains each report available in the Finite State Reporting Kit, what insights they provide, and how to use them effectively.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Available Reports](#available-reports)
   - [Executive Summary](#executive-summary)
   - [Component Vulnerability Analysis](#component-vulnerability-analysis)
   - [Findings by Project](#findings-by-project)
   - [Scan Analysis](#scan-analysis)
   - [Component List](#component-list)
   - [User Activity](#user-activity)
3. [Output Formats](#output-formats)
4. [Filtering Options](#filtering-options)
5. [Using Reports Together](#using-reports-together)
6. [Recommended Cadence](#recommended-cadence)

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

## Available Reports

### Executive Summary

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

**Purpose:** Complete software inventory (SBOM) across your portfolio.

**Who should use it:** Compliance teams, legal, engineering leadership

**What it shows:**
- Software components discovered during the specified time period
- Component versions, types, and suppliers
- License information
- Associated projects, versions, and branches
- Risk metrics per component (findings, warnings, violations)

**Date Filtering:**
When you specify `--start`/`--end` or `--period`, the report shows components **created** (first discovered) during that period. This answers: "What new components were found during this reporting period?"

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
# Components discovered in the last 30 days
poetry run fs-report --recipe "Component List" --period 30d

# Components discovered in a specific quarter
poetry run fs-report --recipe "Component List" --start 2026-01-01 --end 2026-03-31

# Specific project (still uses date filtering)
poetry run fs-report --recipe "Component List" --project "MyProject" --period 30d

# Specific version
poetry run fs-report --recipe "Component List" --version "1234567890" --period 30d
```

---

### User Activity

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

## Output Formats

All reports generate three output formats:

| Format | Best for | Location |
|--------|----------|----------|
| **HTML** | Interactive viewing, sharing, presentations | `output/{Report Name}/{Report Name}.html` |
| **CSV** | Data analysis, spreadsheet import, scripting | `output/{Report Name}/{Report Name}.csv` |
| **XLSX** | Excel users, formatted reports, filtering | `output/{Report Name}/{Report Name}.xlsx` |

---

## Filtering Options

| Option | Description | Example |
|--------|-------------|---------|
| `--period` | Relative time period | `--period 30d`, `--period 1w`, `--period 3m` |
| `--start` / `--end` | Specific date range | `--start 2026-01-01 --end 2026-01-31` |
| `--project` | Filter by project name or ID | `--project "MyProject"` |
| `--version` | Filter by version ID | `--version "1234567890"` |
| `--recipe` | Run specific report only | `--recipe "Scan Analysis"` |
| `--finding-types` | Finding types to include | `--finding-types cve,credentials` |

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
| `sast` | SAST/binary analysis findings |
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
2. **Dive into Component Vulnerability Analysis** → Identify organization-wide priorities
3. **Use Findings by Project** → Plan specific remediation within projects
4. **Monitor with Scan Analysis** → Ensure scanning infrastructure supports the work
5. **Track with Component List** → Maintain software inventory for compliance
6. **Review User Activity** → Ensure platform adoption and engagement

### By Audience

| Audience | Primary Reports |
|----------|-----------------|
| **Executives** | Executive Summary |
| **Security Leadership** | Executive Summary, Component Vulnerability Analysis |
| **Development Teams** | Findings by Project |
| **DevSecOps / Operations** | Scan Analysis |
| **Compliance / Legal** | Component List |
| **Platform Administrators** | User Activity, Scan Analysis |

---

## Recommended Cadence

| Report | Frequency | Purpose |
|--------|-----------|---------|
| **Executive Summary** | Monthly (leadership), Weekly (security) | Track overall progress |
| **Component Vulnerability Analysis** | Quarterly (strategic), Monthly (active remediation) | Prioritize components |
| **Findings by Project** | Weekly (dev teams), Daily (during sprints) | Track remediation |
| **Scan Analysis** | Daily (operations), Weekly (reviews) | Monitor infrastructure |
| **Component List** | Monthly (audits), On-demand (SBOM requests) | Compliance tracking |
| **User Activity** | Weekly (adoption), Monthly (stakeholder reviews) | Engagement tracking |

---

## Getting Help

For questions or issues:
- Review the `README.md` for installation and CLI reference
- Check `CUSTOMER_SETUP.md` for environment configuration
- Contact your Finite State representative for support
