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
   - [CVE Impact](#cve-impact) *(Assessment, on-demand: CVE dossier with affected projects)*
   - [Version Comparison](#version-comparison) *(Assessment, on-demand: full version & component changelog)*
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
| **Component List** | Current software component inventory with license analysis |
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
fs-report run --recipe "Executive Summary" --period 90d
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
| **Anthropic** (default) | `ANTHROPIC_AUTH_TOKEN` | Claude Opus | Claude Haiku |
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

**VEX Integration:**

The report generates a `vex_recommendations.json` file that can be used to update finding statuses in the platform:

```bash
python scripts/apply_vex_triage.py output/triage_prioritization/vex_recommendations.json --dry-run
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
| `--cve` | CVE(s) to analyse (required for CVE Impact), comma-separated | CVE Impact | `--cve CVE-2024-1234` |
| `--baseline-version` | Baseline version ID | Version Comparison | `--baseline-version 12345` |
| `--current-version` | Current version ID | Version Comparison | `--current-version 67890` |

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
| **Compliance / Legal** | Component List (license analysis, copyleft, policy) |
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
| **Component List** | Monthly (audits), On-demand (SBOM requests) | Compliance, license review, and inventory tracking |
| **Version Comparison** | On-demand (after remediation or releases) | Validate specific version improvements |

---

## Getting Help

For questions or issues:
- Review the `README.md` for installation and CLI reference
- Check `CUSTOMER_SETUP.md` for environment configuration
- Contact your Finite State representative for support
