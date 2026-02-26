# Report Recipes

This directory contains YAML recipe files that define the available reports in the Finite State Reporting Kit.

## Available Recipes

| Recipe File | Report Name | Description |
|-------------|-------------|-------------|
| `executive_summary.yaml` | Executive Summary | High-level security dashboard with KPIs and trends |
| `component_vulnerability_analysis.yaml` | Component Vulnerability Analysis | Portfolio-wide component risk analysis with Pareto charts |
| `findings_by_project.yaml` | Findings by Project | Comprehensive inventory of security findings by project with CVE details and direct links |
| `scan_analysis.yaml` | Scan Analysis | Scanning infrastructure performance with throughput, failure analysis, and new vs existing project tracking |
| `component_list.yaml` | Component List | Complete inventory of software components across projects |
| `user_activity.yaml` | User Activity | Platform usage tracking with user engagement metrics |
| `version_comparison.yaml` | Version Comparison | Full version and component changelog (every version pair); fixed/new findings and component churn per step; CSV/XLSX include summary + detail *(on-demand)* |
| `triage_prioritization.yaml` | Triage Prioritization | Context-aware vulnerability triage with optional AI guidance *(on-demand)* |
| `remediation_package.yaml` | Remediation Package | Actionable remediation plan with fix-version validation and structured options *(on-demand)* |
| `executive_dashboard.yaml` | Executive Dashboard | 11-section executive-level security report with KPI cards, severity trends, and exploit intelligence *(on-demand)* |
| `cve_impact.yaml` | CVE Impact | CVE-centric dossier with affected projects, reachability, and exploit intelligence *(on-demand)* |

## Usage

To generate a report, use the CLI and specify the recipe name. For example:

```bash
# Run a specific report
poetry run fs-report run --recipe "Component Vulnerability Analysis"

# Run all available reports
poetry run fs-report run

# List all available recipes
poetry run fs-report list recipes
```

Replace the recipe name with any of the available options above. The output will be saved in the `output/` directory by default.

For more details, see the main project README or documentation. 