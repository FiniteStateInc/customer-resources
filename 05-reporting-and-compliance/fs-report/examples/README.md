# Example Reports

Sample output reports demonstrating the Finite State Reporting Kit capabilities. These reports represent a fictional **Acme Corp Security Lab** instance.

## Sample Data Overview

| Metric | Value |
|--------|-------|
| **Period** | January 2026 |
| **Projects** | 8 projects |
| **Components** | ~380 software components |
| **Findings** | ~830 CVE findings |

## Available Reports

### 1. Executive Summary
- **Files:** `Executive Summary.csv`, `.html`, `.xlsx`
- **Description:** High-level security posture overview with KPIs, project-level breakdowns, and trends. Includes:
  - Security findings by project and severity
  - Open issues distribution
  - Scan frequency over time

### 2. Findings by Project
- **Files:** `Findings by Project.csv`, `.html`, `.xlsx`
- **Description:** Detailed CVE inventory for each project with:
  - CVSS scores and exploitability indicators
  - Affected components and CWE classifications
  - Project and version attribution

### 3. Component Vulnerability Analysis
- **Files:** `Component Vulnerability Analysis.csv`, `.html`, `.xlsx`
- **Description:** Portfolio-wide component risk analysis featuring:
  - Composite risk scoring across all projects
  - KEV (Known Exploited Vulnerabilities) indicators
  - Cross-project impact assessment

### 4. Scan Analysis
- **Files:** `Scan Analysis.csv`, `.html`, `.xlsx` (plus daily metrics)
- **Description:** Operational scanning metrics including:
  - Scan throughput and duration analysis
  - Success/failure rates by scan type
  - New vs. existing project analysis
  - Daily metrics over time

### 5. Component List
- **Files:** `Component List.csv`, `.html`, `.xlsx`
- **Description:** Complete SBOM inventory across all projects:
  - Component name, version, type, and supplier
  - License information
  - Risk metrics (findings, warnings, violations)
  - Project and version attribution

### 6. User Activity
- **Files:** `User Activity.csv`, `.html`, `.xlsx`
- **Description:** Platform usage analytics from audit trail:
  - Unique active users over time
  - Activity breakdown by event type
  - Top users by engagement

### 7. Triage Prioritization *(on-demand)*
- **Description:** Context-aware vulnerability triage with exploit and reachability intelligence. Includes priority bands, CVSS vs Priority heatmap, per-project risk breakdown, and optional AI remediation guidance.
- **Note:** This report must be run explicitly with `--recipe "Triage Prioritization"`. Sample output is not pre-generated.

### 8. Version Comparison *(on-demand)*
- **Description:** Full version and component changelog showing fixed/new findings and component churn for every version pair. Produces summary + detail CSV/XLSX exports.
- **Note:** This report must be run explicitly with `--recipe "Version Comparison"`. Sample output is not pre-generated.

## Generating Your Own Reports

These examples demonstrate the output formats available. To generate reports from your own Finite State instance, see the [main README](../README.md) for setup and usage instructions.
