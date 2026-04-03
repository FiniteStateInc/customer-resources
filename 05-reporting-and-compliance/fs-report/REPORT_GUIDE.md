# Finite State Reporting Kit — Report Guide

This guide explains each report available in the Finite State Reporting Kit, what insights they provide, and how to use them effectively.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Report Categories](#report-categories)
3. [Available Reports](#available-reports)
   - [Executive Summary](#executive-summary) *(Operational)*
   - [Security Progress](#security-progress) *(Operational, on-demand: posture improvement tracking)*
   - [Scan Analysis](#scan-analysis) *(Operational)*
   - [User Activity](#user-activity) *(Operational)*
   - [Component Vulnerability Analysis](#component-vulnerability-analysis) *(Assessment)*
   - [Findings by Project](#findings-by-project) *(Assessment)*
   - [Component List](#component-list) *(Assessment)*
   - [License Report](#license-report) *(Assessment, on-demand: license risk by category)*
   - [Triage Prioritization](#triage-prioritization) *(Assessment)*
   - [Configuration Analysis Triage](#configuration-analysis-triage) *(Assessment, on-demand: config/secrets/crypto triage)*
   - [False Positive Analysis](#false-positive-analysis) *(Assessment, on-demand: FP candidate identification)*
   - [Scan Quality](#scan-quality) *(Assessment, on-demand: per-asset coverage and quality signals)*
   - [CRA Compliance](#cra-compliance) *(Assessment, on-demand: EU Cyber Resilience Act notification scope)*
   - [Component Impact](#component-impact) *(Assessment, on-demand: portfolio blast radius for a named component)*
   - [CVE Impact](#cve-impact) *(Assessment, on-demand: CVE dossier with affected projects)*
   - [Version Comparison](#version-comparison) *(Assessment, on-demand: full version & component changelog)*
   - [Executive Dashboard](#executive-dashboard) *(Assessment, on-demand: executive-level security overview)*
   - [Component Remediation Package](#component-remediation-package) *(Assessment, on-demand: zero-day component remediation)*
   - [Remediation Package](#remediation-package) *(Assessment, on-demand: actionable remediation plan)*
4. [Output Formats](#output-formats)
5. [Filtering Options](#filtering-options)
6. [Using Reports Together](#using-reports-together)
7. [Recommended Cadence](#recommended-cadence)

---

## Quick Start

```bash
# Launch the web UI (default)
fs-report

# Generate all reports for the last 30 days
fs-report run --period 30d

# Generate a specific report
fs-report run --recipe "Executive Summary" --period 30d

# List available reports
fs-report list recipes

# Filter to a specific project
fs-report run --project "MyProject" --period 30d
```

Reports are saved to the `output/` directory in HTML, CSV, XLSX, and Markdown formats.

---

## Report Categories

Reports are classified into two categories that determine how the `--period` (or `--start`/`--end`) time window is applied:

### Operational Reports

**"What happened during this period?"**

Operational reports show activity and trends within the specified time window. The `--period` flag filters the data to only include events that occurred during that window.

| Report | What it measures over the period |
|--------|----------------------------------|
| **Executive Summary** | Findings detected during the window |
| **Security Progress** | Version-over-version progression — CVEs resolved, new, net change per project (on-demand) |
| **Scan Analysis** | Scans run during the window |
| **User Activity** | User actions during the window |

### Assessment Reports

**"What does the target look like today?"**

Assessment reports show the current security state of the target — the latest version of each project, as it exists right now. The `--period` flag is used only to identify which projects were active (scanned) during the window; the actual findings and components shown are from the current (latest) version, not filtered by date.

| Report | What it shows |
|--------|---------------|
| **Component Vulnerability Analysis** | Current vulnerability posture by component |
| **Findings by Project** | Current findings inventory per project |
| **Component List** | Current software component inventory with license analysis |
| **License Report** | License risk distribution by category (on-demand) |
| **Triage Prioritization** | Current triage priorities based on today's data |
| **Configuration Analysis Triage** | Config/secrets/crypto triage with tiered gates (on-demand) |
| **False Positive Analysis** | FP candidates identified by mechanical signals and AI (on-demand) |
| **Scan Quality** | Per-asset scan type coverage and unpack quality scores (on-demand) |
| **CRA Compliance** | KEV and known-exploit findings requiring EU CRA notification (on-demand) |
| **Component Impact** | Portfolio blast radius for a named component (on-demand) |
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
fs-report run --recipe "Executive Summary" --period 90d
```

---

### Security Progress

**Category:** Operational (on-demand) — data is filtered to the specified time period.

**Purpose:** Communicate security progress to management and product teams. Walks each project's version timeline within the period, tracking CVE lifecycle — which vulnerabilities were resolved (by triage or component removal), which are new, and the net change. Shows what teams accomplished.

**Who should use it:** Security leads, programme managers, product team leads, management briefings

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "Security Progress" --period 2m --project openwrt
```

**What it shows:**
- **Portfolio KPI cards** — Total Resolved, Total New, Net Change, Projects Improved
- **Per-project progress table** — Baseline (open at period start), Current (open now), Resolved, New, Net Change — sorted by most improved
- **Portfolio trend chart** — line chart of open CVE count over time across all projects
- **CVE change tracking** — new CVEs, retracted CVEs, severity escalations/downgrades, exploit maturity changes (from `/public/v0/cves/updates`)
- **Per-project detail** (collapsible) — version-by-version progression with severity breakdown
- **CSV export** — Project, Version, Date, Open, Resolved, New, Net per version step

**Key visualizations:**
- **Open CVEs Over Time** — line chart showing portfolio-wide open CVE count across version releases
- **CVE Changes This Period** — bar chart of CVE-level changes (added, retracted, severity ↑/↓, exploit gained)

**CVE resolution tracking:** A CVE is counted as "resolved" when it either (a) receives a VEX triage status (NOT_AFFECTED, RESOLVED, FALSE_POSITIVE, etc.) or (b) disappears from detection (component upgraded or removed). Both count as progress.

**Single-version fallback:** If a project has only one version in the period, the report falls back to a flat snapshot view.

**CVE change categories:**

| Category | Meaning |
|----------|---------|
| **Added** | New CVEs introduced to the NVD database during the period |
| **Retracted** | CVEs removed or retracted |
| **Severity Escalated** | CVSS severity increased (e.g. HIGH → CRITICAL) |
| **Severity Downgraded** | CVSS severity decreased |
| **Exploit Gained** | Exploit maturity increased (e.g. POC → WEAPONIZED) |

**Formats:** HTML, CSV, XLSX, Markdown

**Example commands:**
```bash
# Portfolio-wide progress for the last 30 days
fs-report run --recipe "Security Progress" --period 30d

# Scoped to a specific project
fs-report run --recipe "Security Progress" --project "MyProject" --period 30d

# Scoped to a folder
fs-report run --recipe "Security Progress" --folder "Product Line A" --period 90d
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
fs-report run --recipe "Component Vulnerability Analysis" --period 30d
```

---

### Findings by Project

**Category:** Assessment — shows current findings inventory regardless of time period.

**Purpose:** Detailed security findings inventory organized by project.

**Who should use it:** Development teams, project managers, security analysts

**What it shows:**
- Complete list of security findings per project
- CVSS scores and severity levels (color-coded badges)
- CVE descriptions sourced from the NVD
- CVSS v2 and v3 vector strings for detailed analysis
- Direct links to NVD detail pages and the Finite State platform
- Affected components, versions, and folder paths
- CVE identifiers and exploit information

**Key data columns:**
- **CVSS Score** — Vulnerability severity (0-10 scale)
- **Severity** — Color-coded badge (Critical/High/Medium/Low)
- **Description** — CVE description from NVD (truncated in table, hover for full text)
- **Component & Version** — Specific vulnerable software
- **Project Name** — Which project contains the finding
- **Exploit/Weaponization Count** — Known active threats
- **CVSS v2/v3 Vectors** — Raw vector strings for detailed vulnerability analysis
- **NVD URL** — Direct link to NVD detail page (CVE ID is also clickable in HTML)
- **FS Link** — Direct link to the finding in the Finite State platform
- **Folder** — Folder path (when folder filtering is active)

**Project health indicators:**
| Status | Indicators |
|--------|------------|
| **Healthy** | Low CVSS scores (<7.0), minimal exploits, manageable count |
| **Needs Attention** | Multiple high CVSS findings, some exploit activity |
| **Critical** | CVSS >8.0, active exploits, large volumes |

**Example commands:**
```bash
# All projects
fs-report run --recipe "Findings by Project" --period 30d

# Specific project
fs-report run --recipe "Findings by Project" --project "MyProject"
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
fs-report run --recipe "Scan Analysis" --period 14d
```

---

### Component List

**Category:** Assessment — shows the current component inventory regardless of time period.

**Purpose:** Complete software inventory (SBOM) with license analysis across your portfolio.

**Who should use it:** Compliance teams, legal, engineering leadership, security auditors

**What it shows:**
- All software components in the current (latest) version of each project
- Component versions, types, and suppliers
- **Declared and concluded license information** with copyleft classification
- **License policy compliance** (Permitted, Warning, Violation)
- **Source type** — how each component was discovered (Source SCA, Binary SCA, SBOM Import, etc.)
- Associated projects, versions, and branches
- Risk metrics per component (findings, warnings, violations)
- BOM references (PURLs, CPEs)
- Release dates (when available)

**HTML report features:**
- **KPI cards** — Total components, unique licenses, unlicensed count, policy violations, copyleft count
- **License distribution chart** — Top 15 licenses by component count (horizontal bar)
- **Policy status chart** — Permitted/Warning/Violation breakdown (doughnut)
- **Copyleft classification chart** — Permissive/Weak/Strong/Unknown (doughnut)
- **Source type chart** — Discovery method breakdown (bar)
- **Interactive table** — Grouped by project, with show-more pagination for large datasets

**Date Filtering:**
By default, no date filtering is applied — the report shows the full current inventory. To restrict to components discovered after a specific date, use `--detected-after YYYY-MM-DD`.

**Key data columns:**
| Column | Description |
|--------|-------------|
| **Component** | Software component name |
| **Version** | Specific version in use |
| **Type** | Library, framework, application, etc. |
| **Source** | How discovered: Source SCA, Binary SCA, SBOM Import, etc. |
| **Declared License** | Automatically detected license (SPDX) |
| **Concluded License** | Human-reviewed/confirmed license (SPDX) |
| **Copyleft Status** | Permissive, Weak Copyleft, or Strong Copyleft |
| **Policy Status** | PERMITTED, WARNING, or VIOLATION per license policy |
| **License URL** | Link to license text (when available) |
| **Release Date** | Component release date (when available) |
| **Project/Version/Branch** | Where the component is used |
| **BOM Reference** | PURL or CPE identifier |
| **Findings** | Number of associated vulnerability findings |
| **Component Status** | Triage status: Confirmed, Needs Review, In Review, False Positive |

**XLSX output:**
When exported as XLSX, the report contains multiple sheets:
- **Summary** — KPI metrics and aggregated distributions
- **Detail** — Full component inventory with all columns
- **License Distribution** — License-by-count breakdown
- **Policy Distribution** — Policy status counts
- **Copyleft Distribution** — Copyleft classification counts

**Use cases:**
- **SBOM Compliance** — Export for regulatory requirements (CSV/XLSX)
- **License Reviews** — Filter by license type and copyleft classification for legal review
- **License Policy Enforcement** — Identify components violating license policy
- **Copyleft Risk Assessment** — Find strong copyleft licenses requiring source disclosure
- **Standardization** — Identify version fragmentation across projects
- **Risk Assessment** — Focus on high-finding components
- **New Components Report** — Track what new software entered the portfolio this period
- **Audit Preparation** — Comprehensive report with all license obligations

**Example commands:**
```bash
# Full current component inventory
fs-report run --recipe "Component List"

# Specific project
fs-report run --recipe "Component List" --project "MyProject"

# Only components discovered since a date
fs-report run --recipe "Component List" --detected-after 2026-01-01

# Specific version
fs-report run --recipe "Component List" --version "1234567890"
```

---

### License Report

**Category:** Assessment (on-demand) — shows the current license risk posture regardless of time period.

**Purpose:** Focused license risk analysis that groups all components by license risk category. Complements the Component List report's per-component view with an aggregated, risk-first perspective suitable for legal and compliance reviews.

**Who should use it:** Legal teams, compliance officers, open-source programme offices, security auditors

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "License Report"
```

**What it shows:**
- All components grouped by declared license and risk category
- Risk categories: Strong Copyleft, Weak Copyleft, Proprietary/Restricted, Unknown, Permissive
- Component count per license with associated projects
- License risk distribution pie chart

**Risk categories:**

| Category | Examples | Risk |
|----------|---------|------|
| **Strong Copyleft** | GPL-2.0, GPL-3.0, AGPL-3.0 | Source-disclosure obligations apply |
| **Weak Copyleft** | LGPL-2.1, MPL-2.0 | Limited disclosure obligations |
| **Proprietary/Restricted** | Commercial, EULA | Usage restrictions may apply |
| **Unknown** | Unlicensed, non-SPDX names | Cannot assess risk |
| **Permissive** | MIT, Apache-2.0, BSD-2-Clause | No disclosure obligations |

**Key output columns:**
- **License** — SPDX identifier or raw license name
- **Risk Category** — classification as above
- **Component Count** — number of components with this license
- **Projects** — projects where this license appears

**Formats:** HTML, CSV, XLSX

**Example commands:**
```bash
# Full portfolio license risk summary
fs-report run --recipe "License Report"

# Scoped to a specific project
fs-report run --recipe "License Report" --project "MyProject"

# Scoped to a folder
fs-report run --recipe "License Report" --folder "Product Line A"
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
fs-report run --recipe "User Activity" --period 30d
```

---

### Triage Prioritization

**Category:** Assessment — shows current triage priorities regardless of time period.

**Purpose:** Risk-based vulnerability triage that goes beyond CVSS to prioritize findings using reachability, exploit intelligence, attack vectors, and EPSS.

**Who should use it:** Security teams, vulnerability managers, remediation planners

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "Triage Prioritization" --period 30d
```

**What it shows:**
- Priority bands (CRITICAL, HIGH, MEDIUM, LOW, INFO) based on real-world exploitability
- Gate classification: findings that short-circuit to CRITICAL/HIGH via exploit+reachability
- CVSS vs Priority Band heatmap showing where traditional scoring diverges from context-aware triage
- Per-project risk breakdown with band distribution
- Top 15 riskiest components with remediation priority
- Risk factor radar profiles per project

**Scoring Model:**

The triage prioritization engine uses a two-tier system: fast-track gates for the highest-risk findings, then additive scoring for everything else.

**Tiered Gates (short-circuit classification):**

Gates are evaluated in order. Once a finding matches a gate it is excluded from subsequent gates. The default gates are:

| Gate | Criteria | Result |
|------|----------|--------|
| **GATE_1** | reachability_score > 0 AND (has_exploit OR in_kev) | → CRITICAL (score=100) |
| **GATE_2** | reachability_score >= 0 AND attack_vector in [NETWORK] AND epss_percentile > 0.9 | → HIGH (score=85) |

Gate definitions use a **DSL (domain-specific language)** with `all` (AND) and `any` (OR) combinators, plus leaf conditions with `field`, `op`, and `value`. See **Customizing Gates** below.

**Additive Scoring (findings that don't hit a gate):**

Each finding accumulates points from five factors:

| Factor | Condition | Points |
|--------|-----------|--------|
| **Reachability** | Reachable (score > 0) | +30 |
| | Inconclusive (score = 0) | 0 |
| | Unreachable (score < 0) | -15 |
| **Exploit/KEV** | Has known exploit | +25 |
| | In CISA KEV (no exploit info) | +20 |
| **Attack Vector** | NETWORK | +15 |
| | ADJACENT | +10 |
| | LOCAL | +5 |
| | PHYSICAL | 0 |
| **EPSS** | Scaled by percentile (0-1) | 0-20 |
| **CVSS** | Scaled by score/10 | 0-10 |
| **VEX Status** | NOT_AFFECTED, RESOLVED, or RESOLVED_WITH_PEDIGREE | -50 |

**VEX Status Penalty:**

Findings with a resolved VEX status (`NOT_AFFECTED`, `RESOLVED`, or `RESOLVED_WITH_PEDIGREE`) receive a **-50 point penalty** applied after gate scoring. This demotes previously triaged findings out of the critical gates (e.g. GATE_1 score 100 → 50 = MEDIUM) without removing them from the report entirely.

**Band Thresholds:**

| Band | Score Range | Action |
|------|-------------|--------|
| CRITICAL | Gate-assigned (default 100) | Fix immediately |
| HIGH | Gate-assigned (default 85) or additive >= 70 | Fix this week |
| MEDIUM | 40-69 | Fix this month |
| LOW | 25-39 | Plan remediation |
| INFO | < 25 | Track only |

**VEX Recommendation Mapping:**

| Condition | Recommended Status |
|-----------|--------------------|
| Unreachable (any band) | NOT_AFFECTED |
| CRITICAL (not unreachable) | IN_TRIAGE |
| All other bands (not unreachable) | No recommendation (skipped) |

Findings that already have a VEX status are skipped by default. Use `--vex-override` to include them.

**Customizing Gates:**

Gate definitions live in `recipes/triage_prioritization.yaml` under `parameters.gates`. Each gate has a `name`, `band`, `score`, and a `conditions` tree using `all`/`any` combinators:

```yaml
parameters:
  gates:
    - name: GATE_1
      band: CRITICAL
      score: 100
      conditions:
        all:
          - field: reachability_score
            op: ">"
            value: 0
          - any:
              - field: has_exploit
                op: "=="
                value: true
              - field: in_kev
                op: "=="
                value: true

    - name: GATE_2
      band: HIGH
      score: 85
      conditions:
        all:
          - field: reachability_score
            op: ">="
            value: 0
          - field: attack_vector
            op: in
            value: ["NETWORK"]
          - field: epss_percentile
            op: ">"
            value: 0.9
```

Supported operators: `>`, `>=`, `<`, `<=`, `==`, `!=`, `in` (value is a list).

Available fields for gate conditions include: `reachability_score`, `has_exploit`, `in_kev`, `attack_vector`, `epss_percentile`, `risk`, `severity`, and any other column present after normalization.

Examples of customization:
- **Include ADJACENT vector in Gate 2**: change `value: ["NETWORK"]` to `value: ["NETWORK", "ADJACENT"]`
- **Lower EPSS threshold**: change `value: 0.9` to `value: 0.5`
- **Add a third gate**: append another gate definition to the list
- **Disable all gates**: set `gates: []` (all findings go through additive scoring)

**Customizing Scoring Weights:**

Additive scoring weights are defined under `parameters.scoring_weights`:

```yaml
parameters:
  scoring_weights:
    reachable: 30
    unreachable: -15
    exploit: 25
    kev_only: 20
    vector_network: 15
    epss_max: 20
    cvss_max: 10
    band_high_threshold: 70
    band_medium_threshold: 40
    band_low_threshold: 25
    vex_resolved: -50
```

To override at runtime without editing the recipe, create a YAML file and pass it via `--scoring-file`:

```bash
fs-report run --recipe "Triage Prioritization" --scoring-file my_scoring.yaml --period 30d
```

The scoring file can contain just the weights and/or gates you want to change:

```yaml
# Override additive weights only
scoring_weights:
  reachable: 40
  band_high_threshold: 60

# Override gate definitions (replaces all gates)
gates:
  - name: GATE_1
    band: CRITICAL
    score: 100
    conditions:
      all:
        - field: reachability_score
          op: ">"
          value: 0
        - field: has_exploit
          op: "=="
          value: true
```

**AI Prompts (offline, no API key required):**

Export structured LLM prompts for triage guidance with `--ai-prompts`:

```bash
fs-report run --recipe "Triage Prioritization" --ai-prompts --period 30d
```

This generates a `Triage Prioritization_prompts.md` file and adds inline AI Prompt columns to the HTML report tables. Prompts are generated at four scopes:

- **Portfolio** — strategic remediation prompt (multi-project only), shown after Scoring Methodology
- **Project** — per-project remediation prompt, shown in the Project Risk Summary table
- **Component** — per-component fix guidance prompt for every listed component, shown in the Top Riskiest Components table
- **Finding** — per-finding triage prompt for the top 100 findings by priority, shown in the Findings Detail table

Each prompt includes a Copy button for pasting into any LLM. No API key required.

**AI Remediation Guidance (optional, requires API key):**

Enable AI-powered remediation guidance with the `--ai` flag:

```bash
# Summary mode (portfolio + project summaries)
fs-report run --recipe "Triage Prioritization" --ai --period 30d

# Full mode (+ component-level fix guidance for Critical/High)
fs-report run --recipe "Triage Prioritization" --ai --ai-depth full --period 30d

# Explicit provider override (default: auto-detect from env vars)
fs-report run --recipe "Triage Prioritization" --ai --ai-provider openai --period 30d
```

Supports multiple LLM providers (auto-detected from environment variables):

| Provider | Env Variable | Summary Model | Fast Model |
|----------|-------------|---------------|------------|
| **Anthropic** (default) | `ANTHROPIC_API_KEY` | Claude Opus | Claude Haiku |
| **OpenAI** | `OPENAI_API_KEY` | GPT-4o | GPT-4o-mini |
| **GitHub Copilot** | `GITHUB_TOKEN` | GPT-4o | GPT-4o-mini |

Set one of the environment variables above, or use `--ai-provider` to choose explicitly. Results are cached in `~/.fs-report/cache.db`.

**NVD Fix Version Enrichment:**

When AI remediation is enabled (`--ai`), the tool automatically queries the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) to fetch known fix versions for each CVE. This data is injected into LLM prompts so the AI can recommend specific, verified upgrade targets instead of generic "upgrade to latest" advice.

NVD lookups work without any configuration, but the public rate limit (5 requests per 30 seconds) can be slow for large reports. Register for a **free NVD API key** to get 10x throughput:

1. Go to <https://nvd.nist.gov/developers/request-an-api-key>
2. Enter your organisation name, email address, and organisation type
3. Accept the Terms of Use and submit
4. Click the activation link in the confirmation email (must activate within 7 days)
5. Save the API key — provide it via environment variable or CLI flag:

```bash
# Option A: Environment variable (recommended)
export NVD_API_KEY="your-key-here"
fs-report run --recipe "Triage Prioritization" --ai --ai-depth full --period 30d

# Option B: CLI flag
fs-report run --recipe "Triage Prioritization" --ai --ai-depth full --nvd-api-key "your-key-here" --period 30d
```

| | Without API Key | With API Key |
|---|---|---|
| **Rate limit** | 5 requests / 30 seconds | 50 requests / 30 seconds |
| **50 CVEs** | ~5 minutes | ~30 seconds |
| **Cost** | Free | Free |
| **Setup** | None | 2-minute registration |

NVD results are cached locally (24-hour TTL) so subsequent runs are fast regardless of rate limits.

> **Note:** Per NVD Terms of Use, API keys are per-requestor and must not be shared with other individuals or organisations. This product uses the NVD API but is not endorsed or certified by the NVD.

**Deployment Context (product-aware AI guidance):**

Tailor AI remediation guidance to your product's deployment environment with `--product-type` and `--network-exposure`. This selects a product-specific AI persona and shapes workaround recommendations:

```bash
# Firmware deployed on air-gapped network
fs-report run --recipe "Triage Prioritization" --ai \
  --product-type firmware --network-exposure air_gapped --period 30d

# From a YAML file (includes regulatory and free-text notes)
fs-report run --recipe "Triage Prioritization" --ai \
  --context-file deployment.yaml --period 30d
```

Example `deployment.yaml`:

```yaml
product_type: firmware
network_exposure: internal_only
regulatory: "IEC-62443, FDA"
deployment_notes: "Edge gateway deployed in hospital network"
```

| Product Type | AI Persona |
|---|---|
| `firmware` | Firmware security analyst specializing in embedded device remediation |
| `web_app` | Application security analyst specializing in web application remediation |
| `mobile_app` | Mobile security analyst specializing in mobile application remediation |
| `container` | Cloud security analyst specializing in container and microservice remediation |
| `library` | Software security analyst specializing in library and dependency remediation |
| `device_driver` | Systems security analyst specializing in driver and kernel-level remediation |
| `desktop_app` | Application security analyst specializing in desktop application remediation |
| `generic` (default) | Security analyst specializing in vulnerability remediation |

Network exposure levels: `air_gapped`, `internal_only`, `internet_facing`, `mixed`, `unknown` (default).

Deployment context is included in the AI cache key, so different contexts produce distinct cached results. When no context is specified, prompts use the generic persona (existing behaviour).

**VEX Integration:**

The report generates a `vex_recommendations.json` file that can be used to update finding statuses in the platform:

```bash
# Preview changes (dry run)
fs-report run --apply-vex-triage output/Triage_Prioritization/vex_recommendations.json --dry-run

# Apply all recommendations
fs-report run --apply-vex-triage output/Triage_Prioritization/vex_recommendations.json

# Or generate and apply in one step
fs-report run --recipe "Triage Prioritization" --autotriage --period 30d
```

**Example commands:**

```bash
# Basic triage report
fs-report run --recipe "Triage Prioritization" --period 30d

# Single project
fs-report run --recipe "Triage Prioritization" --project "MyProject"

# With AI guidance
fs-report run --recipe "Triage Prioritization" --ai --period 30d

# Full AI depth (includes component-level fix guidance)
fs-report run --recipe "Triage Prioritization" --ai --ai-depth full --period 30d

# Full AI depth with NVD fix version enrichment (faster with API key)
fs-report run --recipe "Triage Prioritization" --ai --ai-depth full --nvd-api-key "$NVD_API_KEY" --period 30d

# Export AI prompts (no API key needed)
fs-report run --recipe "Triage Prioritization" --ai-prompts --period 30d

# With deployment context (firmware on air-gapped network)
fs-report run --recipe "Triage Prioritization" --ai --product-type firmware --network-exposure air_gapped --period 30d

# Custom scoring weights
fs-report run --recipe "Triage Prioritization" --scoring-file custom.yaml --period 30d

# Override existing VEX statuses
fs-report run --recipe "Triage Prioritization" --vex-override --period 30d

# Generate reports and serve via local HTTP server (enables interactive buttons)
fs-report run --recipe "Triage Prioritization" --ai --ai-depth full --serve
```

**Interactive Action Buttons:**

The Triage Prioritization HTML report includes interactive buttons that let you take action directly from the report:

- **Create Jira Ticket** — Available on both findings and components. Pre-fills the ticket with severity, component, fix version, and AI guidance (when available). Uses your Jira integration configured in the Finite State platform.
- **Set IN_TRIAGE** — Available on individual findings. Sets the finding status to `IN_TRIAGE` with `WILL_FIX` response in the platform, so your team knows it's being worked.

**How to connect:**

1. Open the HTML report in your browser.
2. Click any action button (or the "Connect to Finite State" button in the header).
3. Enter your Finite State domain (e.g., `platform.finitestate.io`) and API token.
4. Click **Connect** — the report verifies connectivity and fetches your Jira projects.
5. A green "Connected" badge appears in the header. You're ready to create tickets and update statuses.

**Security model:**

- Credentials are stored in `sessionStorage` — they are **never written to disk** and are cleared when you close the browser tab.
- API calls happen directly from your browser to the Finite State API. No data passes through any intermediary.
- The report HTML file does not contain any credentials or secrets.

**CORS note:**

When opening the report as a local file (`file://` protocol), some browsers may block API requests due to CORS restrictions. If you encounter this:

```bash
# Use --serve to start a local HTTP server after report generation
fs-report run --recipe "Triage Prioritization" --serve

# Custom port
fs-report run --recipe "Triage Prioritization" --serve --serve-port 9090
```

The `--serve` flag starts a lightweight local server on `http://localhost:8080` (or custom port), which provides a proper HTTP origin and avoids CORS issues. Press `Ctrl+C` to stop the server.

---

### Configuration Analysis Triage

**Category:** Assessment (on-demand) — triages current config/secrets/crypto findings regardless of time period.

**Purpose:** Separates signal from noise in CREDENTIALS, CONFIG_ISSUES, and CRYPTO_MATERIAL findings. Parses structured fields from the API's `additionalDetails` to distinguish private keys (critical) from public keys/certs (noise), and ranks all findings using a tiered-gates scoring model.

**Who should use it:** Security teams, firmware analysts, compliance auditors reviewing configuration and secrets hygiene.

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "Configuration Analysis Triage" --project mydevice
```

The recipe automatically sets `--finding-types credentials,config_issues,crypto_material` — you don't need to pass it manually.

**What it shows:**
- Priority bands (CRITICAL, HIGH, MEDIUM, LOW, INFO) based on finding category and severity
- Gate classification: private keys short-circuit to CRITICAL, high-severity credentials to HIGH
- Category breakdown showing CRYPTO_MATERIAL vs CREDENTIALS vs CONFIG_ISSUES distribution
- Per-project risk summary with band distribution
- VEX recommendations (public keys/certs → NOT_AFFECTED, gate matches → IN_TRIAGE)

**Scoring Model:**

| Gate | Criteria | Result |
|------|----------|--------|
| **GATE_1** | CRYPTO_MATERIAL AND private_key=True | → CRITICAL (score=100) |
| **GATE_2** | CREDENTIALS AND severity in (critical, high) | → HIGH (score=85) |
| **GATE_3** | CONFIG_ISSUES AND severity in (critical, high) | → MEDIUM (score=70) |

**Additive Scoring (findings that don't hit a gate):**

| Factor | Points |
|--------|--------|
| Severity critical | +30 |
| Severity high | +20 |
| Severity medium | +10 |
| Severity low | +5 |
| Risk score (scaled) | 0–10 |
| VEX resolved status | -50 |

Bands: HIGH ≥ 70, MEDIUM ≥ 40, LOW ≥ 25, INFO < 25.

Gates and weights are customizable via `--scoring-file` (same YAML format as Triage Prioritization).

**VEX Recommendations:**

```bash
# Generate report with VEX recommendations:
fs-report run --recipe "Configuration Analysis Triage" --project mydevice --output ./reports

# Auto-apply NOT_AFFECTED for public keys:
fs-report run --recipe "Configuration Analysis Triage" --project mydevice \
  --autotriage --autotriage-status NOT_AFFECTED --output ./reports

# Filter to critical gate only (private keys):
fs-report run --recipe "Configuration Analysis Triage" --project mydevice \
  --tp-gate GATE_1 --output ./reports
```

**Output formats:** HTML, CSV, XLSX, JSON, Markdown

---

### False Positive Analysis

**Category:** Assessment (on-demand) — evaluates current findings regardless of time period.

**Purpose:** Identify likely false positives in your open findings inventory using mechanical signal checks and optional AI applicability analysis. Produces VEX recommendations for confirmed candidates so teams can suppress noise quickly and focus on real risk.

**Who should use it:** Security analysts, triage leads, vulnerability management teams

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "False Positive Analysis" --period 30d
```

**Tier 1 — mechanical checks (no API key needed):**

| Signal | Confidence | Description |
|--------|-----------|-------------|
| **Cross-project propagation** | HIGH | Same CVE + component already triaged FP in another project |
| **Historical component pattern** | MEDIUM | Component version has a high FP ratio in triage history |
| **NVD version-range mismatch** | MEDIUM | Component version falls outside the NVD-specified affected range |
| **Rejected/Disputed CVE** | HIGH / MEDIUM | NVD vulnerability status is Rejected or Disputed |
| **Unreachable code** | HIGH | Negative reachability score — code path cannot be reached |

**Tier 2 — AI applicability analysis (requires `--ai`):**

| Signal | Description |
|--------|-------------|
| **AI component not affected** | LLM determines the component is not affected by the CVE(s) |
| **AI finding not affected** | LLM determines the individual finding is not applicable |

Component-level prompts are evaluated first; if the AI marks a component `not_affected`, all findings on that component are flagged without running individual finding prompts.

**Key outputs:**
- **FP Review Queue** — open findings that triggered one or more signals, grouped by component, with rolled-up confidence (HIGH / MEDIUM / LOW) and inline AI prompts
- **Component Applicability Analysis** — per-component table showing AI verdict, confidence, rationale, guidance, fix version, and workaround
- **VEX Recommendations** — `NOT_AFFECTED` recommendations with justification codes for batch triage
- **Signal detail** — per-signal breakdown for analyst review
- **Charts** — FP candidates by detection method, by severity, and by component

**Formats:** HTML, CSV, XLSX, Markdown

**Example commands:**
```bash
# Mechanical checks only (no API key needed)
fs-report run --recipe "False Positive Analysis" --project "MyProject"

# With AI applicability analysis
fs-report run --recipe "False Positive Analysis" --project "MyProject" --ai

# AI analysis + auto-apply VEX recommendations
fs-report run --recipe "False Positive Analysis" --project "MyProject" --ai --autotriage

# Preview VEX changes without applying
fs-report run --recipe "False Positive Analysis" --project "MyProject" --ai --autotriage --dry-run

# Export AI prompts for manual review (no API key needed)
fs-report run --recipe "False Positive Analysis" --project "MyProject" --ai-prompts
```

---

### Scan Quality

**Category:** Assessment (on-demand) — evaluates scan coverage for assets active in the period.

**Purpose:** Surface customer-facing scan quality signals — which scan types cover each asset (SCA, SAST, CONFIG), where coverage gaps exist, and what the binary unpack quality score is for binary SCA scans. Distinct from Scan Analysis (which tracks throughput and failure rates): this report asks "how good is the scanning we do have?"

**Who should use it:** DevSecOps teams, platform administrators, security engineers

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "Scan Quality" --period 30d
```

**What it shows:**
- Per-asset scan type coverage matrix (SCA, SAST, CONFIG, Binary SCA, Vulnerability Analysis)
- Coverage score per asset (0–5, one point per scan type present)
- Aggregate coverage breakdown across the portfolio
- Binary SCA unpack evaluation scores (1–100) with short summaries and potential issues, for the 10 most-recent binary SCA scans
- Scan type distribution bar chart

**Key metrics:**

| Metric | What it tells you |
|--------|-------------------|
| **Coverage Score** | How many distinct scan types cover an asset (0 = none, 5 = all types) |
| **Avg Coverage Score** | Portfolio-wide average — lower values indicate coverage gaps |
| **Unpack Score** | Binary firmware unpack quality (1–100); low scores mean poor extraction and missed components |
| **Scan Type Breakdown** | Which scan types dominate the portfolio |

**Formats:** HTML, CSV, XLSX, Markdown

**Example commands:**
```bash
# Portfolio-wide scan quality
fs-report run --recipe "Scan Quality" --period 30d

# Scoped to a specific folder
fs-report run --recipe "Scan Quality" --folder "Product Line A" --period 30d
```

---

### CRA Compliance

**Category:** Assessment (on-demand) — shows current findings regardless of time period.

**Purpose:** Identify exploited vulnerabilities that may trigger an EU Cyber Resilience Act notification obligation. Under the CRA, manufacturers must notify ENISA within 24 hours of becoming aware of an actively exploited vulnerability in a product with digital elements. This report surfaces all findings where the CVE appears in the CISA KEV catalogue or has a known exploit — the primary signals for CRA notification scope.

**Who should use it:** Compliance teams, legal counsel, CISOs, product security officers

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "CRA Compliance" --period 30d
```

**What it shows:**
- All findings with a KEV hit or known exploit (excluding findings marked FALSE_POSITIVE or NOT_AFFECTED)
- CRA trigger label for each finding: "KEV" or "Known Exploit"
- CVSS score, EPSS score, severity, component, project, and triage status
- Per-project dossiers with top CVEs by CVSS score
- Summary counts: total in-scope findings, KEV hits, known exploit hits, Critical/High counts

**Key data columns:**

| Column | Description |
|--------|-------------|
| **CRA Trigger** | KEV or Known Exploit |
| **CVE ID** | CVE identifier |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **CVSS Score** | 0–10 scale |
| **Component** | Affected component and version |
| **Project** | Project containing the finding |
| **EPSS Score / Percentile** | Exploit Prediction Scoring System |
| **Status** | Current triage status |

**Formats:** HTML, CSV, XLSX, Markdown

**Example commands:**
```bash
# Portfolio-wide CRA scope assessment
fs-report run --recipe "CRA Compliance" --period 30d

# Scoped to a specific project
fs-report run --recipe "CRA Compliance" --project "MyProduct"

# Scoped to a folder
fs-report run --recipe "CRA Compliance" --folder "Product Line A"
```

---

### Component Impact

**Category:** Assessment (on-demand) — shows current portfolio exposure for a named component.

**Purpose:** Answer "where in our portfolio do we have component X, and what CVEs affect it?" Useful for zero-day response when a component is reported compromised before a CVE is published, or for supply-chain impact analysis.

**Requires `--component`** to specify the component name to analyse.

**Who should use it:** Security incident responders, security engineers, supply-chain risk teams

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "Component Impact" --component "openssl"
```

**How it works:** The report uses the component search API (`/public/v0/components/search`) for fast portfolio-wide lookup, then enriches each location with CVE findings context (count, severity breakdown, top 3 CVEs). Projects with active CVE findings are listed first, sorted by severity.

**What it shows:**
- Every project in the portfolio that contains the named component, with detected version(s)
- CVE count, Critical/High/Medium counts, and top 3 CVEs per project
- Portfolio-level blast radius summary: projects with component, projects with findings, total CVEs
- Optional version range filtering to scope to affected versions only

**Key outputs:**

| Section | Details |
|---------|---------|
| **Summary header** | Component name, version range, projects affected, total CVEs |
| **Location table** | One row per project: detected versions, CVE count, severity breakdown, top CVEs |
| **CSV export** | One row per project with component, version(s), project, CVE count, Critical/High/Medium |

**Formats:** HTML, CSV, XLSX, Markdown

**Example commands:**
```bash
# All projects containing openssl
fs-report run --recipe "Component Impact" --component "openssl"

# Scope to a specific version range (affected versions only)
fs-report run --recipe "Component Impact" --component "openssl" --component-version ">=3.0,<3.0.7"

# Scope to a specific exact version
fs-report run --recipe "Component Impact" --component "log4j-core" --component-version "2.14.1"

# Scope to a folder
fs-report run --recipe "Component Impact" --component "busybox" --folder "IoT Products"
```

---

### CVE Impact

**Category:** Assessment (on-demand) — CVE-centric dossier showing affected projects, reachability, and exploit details.

**Purpose:** Answer "which projects does this CVE affect and where is it reachable?" Useful for incident response and vulnerability triage across a portfolio.

**Requires `--cve`** to specify which CVE(s) to analyse. Running against an entire project is not supported because a single project can contain thousands of CVEs (e.g. 4 000 CVEs → ~12 000 API calls for dossier enrichment).

Produces a detailed dossier for each specified CVE — description, CWE, known exploits, EPSS, KEV status, and a per-project table with reachability status. Enriches with per-finding reachability data from `/findings`. Optionally combine with `--project` to narrow results to a single project.

**Key outputs:**

| Section | Details |
|---------|---------|
| **CVE header** | CVE ID (NVD link), severity badge, CVSS score |
| **Description** | Finding title (dossier mode only, from findings enrichment) |
| **Vulnerability details** | CWE (MITRE link), EPSS percentile, KEV status |
| **Known exploits** | Source, URL, description from exploit data |
| **Reachability summary** | "Reachable in N of M projects" (dossier mode only) |
| **Affected projects** | Per-project reachability (REACHABLE/UNREACHABLE/INCONCLUSIVE), component, detected date |

**Formats:** HTML, CSV, XLSX

**Examples:**

```bash
# Dossier for a specific CVE (across all projects)
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234

# Dossiers for multiple CVEs
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234,CVE-2024-5678

# Narrow to a specific project
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234 --project "MyFirmware"

# With AI remediation guidance and deployment context
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234 --ai \
  --product-type firmware --network-exposure air_gapped
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

**Note on "new" findings:** A finding may appear as "new" in a version even when the component was not updated, because the CVE itself was published or had its severity changed externally (NVD update). Use the [Security Progress](#security-progress) report to track CVE-level changes from the NVD during the same period.

**What to look for:**
| Healthy | Needs Attention |
|---------|-----------------|
| More fixed than new | More new than fixed |
| Critical count decreasing | New critical findings |
| Component updates reducing findings | Component additions bringing new findings |

**Example commands:**
```bash
# Portfolio-wide: full version changelog for every active project
fs-report run --recipe "Version Comparison" --period 90d

# Scope to a single project
fs-report run --recipe "Version Comparison" --project "Router Firmware"

# Scope to a folder (product group)
fs-report run --recipe "Version Comparison" --folder "Toy Cars"

# Explicit version pair (advanced)
fs-report run --recipe "Version Comparison" \
  --baseline-version 12345 --current-version 67890
```

---

### Executive Dashboard

**Category:** Assessment (on-demand) — executive-level security overview of the current portfolio state.

**Purpose:** Provide a single-page, visual executive briefing that summarises the security posture of an entire portfolio or a specific folder. Designed for leadership reviews, board decks, and stakeholder updates.

**Who should use it:** Executives, CISOs, program managers, customer-facing solutions engineers

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "Executive Dashboard" --period 90d
```

**What it shows (11 sections):**

| Section | Description |
|---------|-------------|
| **KPI Cards** | Projects, policy violations, warnings, components, total findings — each with a delta indicator |
| **Findings by Folder** | Stacked bar chart of severity distribution across folders (portfolio view) |
| **Findings by Project** | Stacked bar chart of severity distribution across projects (`--folder` view) |
| **Severity Trends** | Line chart tracking Critical & High findings over the last 12 months |
| **Highest-Risk Products** | Doughnut chart + table with a composite risk score (Critical×10 + High×5 + Medium×2 + Low×0.5) |
| **Open Issues by Severity** | Pie chart of unresolved findings by severity level |
| **License Distribution** | Horizontal bar chart of the top 10 licenses by component count |
| **Exploit Intelligence** | Horizontal bar chart showing CISA KEV and known exploit counts |
| **Findings by Type** | Horizontal bar chart of CVE, Crypto, Credentials, Config Issues, etc. |
| **Finding Age Distribution** | Horizontal bar chart bucketed by 0–30, 30–90, 90–180, and 180+ days |
| **Project Findings Summary** | Full-width table listing every project with per-severity counts |

**Portfolio vs folder scope:**

- Without `--folder`: the report groups findings by **folder** (portfolio-level view).
- With `--folder "Product Line A"`: the report groups findings by **project** within that folder.

**Finding types:** The report automatically overrides `--finding-types` to `all` so that every finding category (CVE, SAST, credentials, etc.) is represented in the executive view.

**Output format:** HTML only (standalone, self-contained).

**Example commands:**

```bash
# Portfolio-wide executive dashboard
fs-report run --recipe "Executive Dashboard" --period 90d

# Scoped to a specific folder
fs-report run --recipe "Executive Dashboard" --folder "Product Line A" --period 90d

# With AI remediation guidance
fs-report run --recipe "Executive Dashboard" --ai --period 90d
```

---

### Component Remediation Package

**Category:** Assessment (on-demand) — component-centric zero-day remediation guidance.

**Purpose:** Produce actionable remediation guidance for a vulnerable component across your portfolio, without requiring a CVE. Designed for zero-day scenarios where a component is known to be compromised before any CVE is published. Groups findings by (component, version) and provides upgrade paths, ecosystem health context, and interim mitigations.

**Who should use it:** Security teams, incident responders, remediation planners

**Important:** This report does **not** run by default. You must explicitly request it with `--component`:

```bash
fs-report run --recipe "Component Remediation Package" --component "openssl"
```

**What it shows:**

| Section | Details |
|---------|---------|
| **Summary** | Component name/version, affected project count, severity breakdown, suppressed count |
| **Remediation actions** | Per-component-version: blast radius, severity counts, affected projects, AI guidance |
| **Suppressed findings** | Findings excluded by VEX status (FALSE_POSITIVE / NOT_AFFECTED) |

**Key differences from Remediation Package:**
- No CVE-centric scoring or OSV fix-version lookup — works with zero CVEs
- Component-scoped view: one action per (component, version) pair across the portfolio
- Priority based on severity × blast-radius (not CVSS + OSV validation)
- AI prompts framed as zero-day guidance

**AI enrichment (optional):**

```bash
# Live AI guidance (requires API key)
fs-report run --recipe "Component Remediation Package" --component "openssl" --ai

# Deep analysis with high-capability model
fs-report run --recipe "Component Remediation Package" --component "openssl" --ai --ai-analysis

# Export AI prompts for manual review (no API key needed)
fs-report run --recipe "Component Remediation Package" --component "openssl" --ai-prompts

# With deployment context
fs-report run --recipe "Component Remediation Package" --component "openssl" --ai \
  --product-type firmware --network-exposure air_gapped

# From a context file
fs-report run --recipe "Component Remediation Package" --component "openssl" --ai \
  --context-file deployment.yaml
```

**Formats:** HTML, CSV, XLSX, Markdown

**Example commands:**
```bash
# All versions of a component across the portfolio
fs-report run --recipe "Component Remediation Package" --component "openssl"

# Scope to a specific version range
fs-report run --recipe "Component Remediation Package" --component "openssl" \
  --component-version ">=3.0,<3.0.7"

# Scope to a folder
fs-report run --recipe "Component Remediation Package" --component "busybox" \
  --folder "IoT Products"
```

---

### Remediation Package

**Category:** Assessment (on-demand) — actionable remediation plan with validated fix versions and structured options.

**Purpose:** Produce a ready-to-execute remediation plan for a project or folder. Each vulnerable component gets validated upgrade targets (checked against OSV to ensure the fix version isn't itself vulnerable), plus optional workaround and code-mitigation alternatives.

**Who should use it:** Security teams, remediation planners, development leads

**Important:** This report does **not** run by default. You must explicitly request it:

```bash
fs-report run --recipe "Remediation Package" --project "MyProject"
```

**What it shows:**

| Section | Details |
|---------|---------|
| **Summary** | Component count, severity breakdown, suppressed/unresolvable counts |
| **Remediation actions** | Per-component: upgrade target (validated), workaround URLs, code mitigation options |
| **Fix-version validation** | OSV check ensures proposed fix versions aren't themselves vulnerable; walks alternatives when needed |
| **Suppressed findings** | Findings excluded by VEX status or triage |
| **Unresolvable findings** | Findings with no known fix or workaround |

**Structured remediation options:**

Each action includes typed options:
- **upgrade** — Target version with validation status
- **workaround** — NVD-sourced workaround URLs and descriptions
- **code_mitigation** — Code-level mitigation guidance (AI-enriched when `--ai` is enabled)

**AI enrichment (optional):**

```bash
# With AI workaround and breaking-change analysis
fs-report run --recipe "Remediation Package" --project "MyProject" --ai

# Deep analysis using high-capability model (more detailed guidance)
fs-report run --recipe "Remediation Package" --project "MyProject" --ai --ai-analysis

# With deployment context from a file
fs-report run --recipe "Remediation Package" --project "MyProject" --ai \
  --context-file deployment.yaml
```

When `--ai` is enabled, each action is enriched with LLM-generated workaround guidance and breaking-change risk assessment. Add `--ai-analysis` to use the high-capability model for deeper analysis. Use `--ai off` to disable AI even if the recipe YAML enables it by default.

Add `--product-type` and `--network-exposure` (or `--context-file`) to get product-specific workaround recommendations tailored to your deployment environment. See the [Deployment Context](#deployment-context-product-aware-ai-guidance) section under Triage Prioritization for full details.

**Formats:** HTML, CSV, XLSX, JSON, Markdown

**Example commands:**

```bash
# Single project
fs-report run --recipe "Remediation Package" --project "MyProject"

# Scope to a folder
fs-report run --recipe "Remediation Package" --folder "Product Line A"

# With AI enrichment
fs-report run --recipe "Remediation Package" --project "MyProject" --ai

# With deployment context (container on internal network)
fs-report run --recipe "Remediation Package" --project "MyProject" --ai \
  --product-type container --network-exposure internal_only

# Export as Markdown (agent-optimised)
fs-report run --recipe "Remediation Package" --project "MyProject" --format md
```

---

## Output Formats

Most reports generate output in multiple formats:

| Format | Best for | Location |
|--------|----------|----------|
| **HTML** | Interactive viewing, sharing, presentations | `output/{Report Name}/{Report Name}.html` |
| **CSV** | Data analysis, spreadsheet import, scripting | `output/{Report Name}/{Report Name}.csv` |
| **XLSX** | Excel users, formatted reports, filtering | `output/{Report Name}/{Report Name}.xlsx` |
| **Markdown** | LLM/agent consumption, token-efficient structured output | `output/{Report Name}/{Report Name}.md` |

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
| `--cve` | CVE(s) to analyse (required for CVE Impact), comma-separated | CVE Impact | `--cve CVE-2024-1234` |
| `--component` | Component name to analyse (required for Component Impact, Component Remediation Package) | Component Impact, Component Remediation Package | `--component "openssl"` |
| `--component-version` | Version range for component filtering | Component Impact, Component Remediation Package | `--component-version ">=3.0,<3.0.7"` |
| `--baseline-version` | Baseline version ID | Version Comparison | `--baseline-version 12345` |
| `--current-version` | Current version ID | Version Comparison | `--current-version 67890` |
| `--ai-model-high` | Override the "high" (summary) LLM model | AI-enabled reports | `--ai-model-high claude-sonnet-4-20250514` |
| `--ai-model-low` | Override the "low" (fast) LLM model | AI-enabled reports | `--ai-model-low claude-haiku-4-5-20251001` |
| `--product-type` | Product type for AI persona selection | AI-enabled reports | `--product-type firmware` |
| `--network-exposure` | Network exposure level | AI-enabled reports | `--network-exposure air_gapped` |
| `--context-file` | Deployment context YAML file | AI-enabled reports | `--context-file deployment.yaml` |

**How `--period` interacts with report categories:**

- **Operational reports** (Executive Summary, Scan Analysis, User Activity): `--period` directly filters the data to events within the time window.
- **Assessment reports** (CVA, Findings by Project, Component List, Triage): `--period` identifies which projects were active (scanned) during the window, then fetches the **current (latest) version** of those projects. The findings/components shown are not date-filtered.

**`--detected-after` (Assessment reports only):**

Use `--detected-after YYYY-MM-DD` to add a date floor to Assessment reports. For example, to see only findings detected since Q1:

```bash
fs-report run --recipe "Findings by Project" --detected-after 2026-01-01
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
fs-report run --period 30d

# Include credentials along with CVEs
fs-report run --period 30d --finding-types cve,credentials

# Only credentials findings
fs-report run --period 30d --finding-types credentials

# All findings (includes SAST/FILE components)
fs-report run --period 30d --finding-types all
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
7. **Track Security Progress** → Measure posture improvement and catch external CVE changes
8. **Track with Component List** → Maintain software inventory for compliance
9. **Review User Activity** → Ensure platform adoption and engagement

### Incident Response Workflow (zero-day / breaking component)

1. **Component Impact** → Find every project in the portfolio containing the affected component
2. **Component Remediation Package** → Generate upgrade paths and AI-guided mitigations
3. **False Positive Analysis** → Suppress noise so the team can focus on confirmed findings

### Compliance Workflow

1. **Component List** → Full software inventory with declared/concluded licenses and policy status
2. **License Report** → Risk-first summary grouping licenses by Permissive / Copyleft / Unknown
3. **CRA Compliance** → Scope KEV and known-exploit findings for EU CRA notification

### By Audience

| Audience | Primary Reports |
|----------|-----------------|
| **Executives** | Executive Summary, Executive Dashboard |
| **Security Leadership** | Executive Summary, Security Progress, Component Vulnerability Analysis, Triage Prioritization |
| **Development Teams** | Findings by Project, Version Comparison, Triage Prioritization |
| **Release Managers** | Version Comparison |
| **Vulnerability Management** | Triage Prioritization (with `--ai`), False Positive Analysis |
| **Incident Response** | Component Impact, Component Remediation Package, CRA Compliance |
| **DevSecOps / Operations** | Scan Analysis, Scan Quality |
| **Compliance / Legal** | Component List, License Report, CRA Compliance |
| **Platform Administrators** | User Activity, Scan Analysis, Scan Quality |

---

## Recommended Cadence

### Operational Reports (period-bound)

| Report | Frequency | Purpose |
|--------|-----------|---------|
| **Executive Summary** | Monthly (leadership), Weekly (security) | Track trends and overall progress |
| **Security Progress** | Monthly (programme reviews), On-demand | Measure posture delta and catch external CVE changes |
| **Scan Analysis** | Daily (operations), Weekly (reviews) | Monitor scanning infrastructure |
| **User Activity** | Weekly (adoption), Monthly (stakeholder reviews) | Engagement tracking |

### Assessment Reports (current state)

| Report | Frequency | Purpose |
|--------|-----------|---------|
| **Triage Prioritization** | Weekly (active remediation), On-demand | Prioritize what to fix next |
| **False Positive Analysis** | Monthly (triage hygiene), On-demand | Suppress noise and focus on confirmed findings |
| **Component Vulnerability Analysis** | Quarterly (strategic), Monthly (active remediation) | Prioritize risky components |
| **Findings by Project** | Weekly (dev teams), Daily (during sprints) | Plan project-level remediation |
| **Component List** | Monthly (audits), On-demand (SBOM requests) | Compliance, license review, and inventory tracking |
| **License Report** | Quarterly (legal reviews), On-demand | License risk summary for legal and compliance |
| **CRA Compliance** | Monthly (regulatory), On-demand (incident) | EU CRA notification scope assessment |
| **Scan Quality** | Quarterly (platform health), On-demand | Identify coverage gaps and unpack quality issues |
| **Component Impact** | On-demand (zero-day / supply-chain incident) | Blast radius for a specific component |
| **Component Remediation Package** | On-demand (zero-day / supply-chain incident) | Rapid remediation guidance for a compromised component |
| **Version Comparison** | On-demand (after remediation or releases) | Validate specific version improvements |

---

## Getting Help

For questions or issues:
- Review the `README.md` for installation and CLI reference
- Check `CUSTOMER_SETUP.md` for environment configuration
- Contact your Finite State representative for support
