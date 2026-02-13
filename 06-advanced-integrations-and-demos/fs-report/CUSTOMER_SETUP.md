# Finite State Reporting Kit - Customer Setup Guide

## Prerequisites

- Python 3.11 or newer
- [Poetry](https://python-poetry.org/docs/#installation) (for dependency management)
- Finite State API access credentials

## Quick Start

### 1. Set Up Environment Variables

```bash
# Set your Finite State credentials (required)
export FINITE_STATE_AUTH_TOKEN="your-api-token"
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"

# Optional: For AI-powered triage remediation guidance
export ANTHROPIC_AUTH_TOKEN="your-anthropic-api-key"
```

**Note**: Add these to your shell profile (`.bashrc`, `.zshrc`, etc.) to make them persistent.

### 2. Create Output Directory

```bash
mkdir -p fs-reports
cd fs-reports
```

### 3. Install the Reporting Kit

Clone the repository and install dependencies using Poetry:

```bash
git clone <repository-url>
cd fs-report
poetry install
```

### 4. Run Reports

Activate the Poetry environment and run the CLI:

```bash
# Run all default reports
poetry run fs-report

# Specify a custom date range
poetry run fs-report --start 2025-01-01 --end 2025-01-31

# Use a relative time period (e.g., last 7 days, last month)
poetry run fs-report --period 7d
poetry run fs-report --period 1m

# Filter by project name or ID
poetry run fs-report --project "MyProject"

# Filter by project version (version ID or name)
poetry run fs-report --version "1234567890"  # Version ID (no project needed)
poetry run fs-report --project "MyProject" --version "v1.2.3"  # Version name (project required)

# List available recipes
poetry run fs-report list-recipes

# List available projects
poetry run fs-report list-projects

# List available versions for a project
poetry run fs-report list-versions "MyProject"

# List all versions across the portfolio
poetry run fs-report list-versions

# List top 10 projects by version count
poetry run fs-report list-versions -n 10

# List available folders (for --folder scoping)
poetry run fs-report list-folders

# Scope reports to a specific folder (product group)
poetry run fs-report --folder "Product Line A" --period 30d

# Control which finding types are included (default: cve)
poetry run fs-report --finding-types cve              # CVE only (default)
poetry run fs-report --finding-types cve,credentials  # CVE + credentials
poetry run fs-report --finding-types all              # All findings

# Include all historical versions (default: latest only for performance)
poetry run fs-report --period 1w --all-versions

# Specify custom recipes and output directories
poetry run fs-report --recipes ./my-recipes --output ./my-reports

# Enable verbose logging
poetry run fs-report --verbose
```

**Report categories:** Reports are classified as either **Operational** (period-bound: Executive Summary, Scan Analysis, User Activity) or **Assessment** (current state: CVA, Findings by Project, Component List, Triage Prioritization). The `--period` flag filters data directly for Operational reports. For Assessment reports, it identifies active projects but always shows the latest version. Use `--detected-after YYYY-MM-DD` to add a date floor to Assessment reports. See `REPORT_GUIDE.md` for details.

### 5. Run Triage Prioritization (On-Demand)

The Triage Prioritization report does **not** run with the default reports. You must explicitly request it:

```bash
# Basic triage report
poetry run fs-report --recipe "Triage Prioritization" --period 30d

# Single project
poetry run fs-report --recipe "Triage Prioritization" --project "MyProject"

# With AI-powered remediation guidance (requires Anthropic API key)
export ANTHROPIC_AUTH_TOKEN="your-anthropic-api-key"
poetry run fs-report --recipe "Triage Prioritization" --ai --period 30d

# Full AI depth (adds component-level fix guidance for Critical/High)
poetry run fs-report --recipe "Triage Prioritization" --ai --ai-depth full --period 30d
```

### 6. Run Version Comparison (On-Demand)

The Version Comparison report does **not** run with the default reports. It produces a full version and component changelog:

```bash
# Portfolio-wide: full version changelog for every active project
poetry run fs-report --recipe "Version Comparison" --period 90d

# Scope to a single project
poetry run fs-report --recipe "Version Comparison" --project "Router Firmware"

# Scope to a folder (product group)
poetry run fs-report --recipe "Version Comparison" --folder "Toy Cars"

# Explicit version pair (compare two specific versions by ID)
poetry run fs-report --recipe "Version Comparison" \
  --baseline-version 12345 --current-version 67890
```

### 7. Apply VEX Triage Updates (Optional)

After generating a Triage Prioritization report, you can apply the recommended VEX statuses to the platform:

```bash
# Preview changes (dry run)
python scripts/apply_vex_triage.py output/Triage_Prioritization/vex_recommendations.json --dry-run

# Apply only CRITICAL band findings
python scripts/apply_vex_triage.py output/Triage_Prioritization/vex_recommendations.json --filter-band CRITICAL

# Apply all recommendations
python scripts/apply_vex_triage.py output/Triage_Prioritization/vex_recommendations.json
```

## Output Files

Reports are generated in multiple formats:
- **HTML**: Interactive reports with charts
- **CSV**: Data for spreadsheet analysis
- **XLSX**: Excel-compatible files

Example output structure:
```
fs-reports/
├── Executive_Summary/
│   ├── Executive_Summary.html
│   ├── Executive_Summary.csv
│   └── Executive_Summary.xlsx
├── Component_Vulnerability_Analysis/
│   ├── Component_Vulnerability_Analysis.html
│   ├── Component_Vulnerability_Analysis.csv
│   └── Component_Vulnerability_Analysis.xlsx
├── Findings_by_Project/
│   ├── Findings_by_Project.html
│   ├── Findings_by_Project.csv
│   └── Findings_by_Project.xlsx
├── Scan_Analysis/
│   ├── Scan_Analysis.html
│   ├── Scan_Analysis.csv
│   └── Scan_Analysis.xlsx
├── Component_List/
│   ├── Component_List.html
│   ├── Component_List.csv
│   └── Component_List.xlsx
├── User_Activity/
│   ├── User_Activity.html
│   ├── User_Activity.csv
│   └── User_Activity.xlsx
├── Triage_Prioritization/          # Only when explicitly requested
│   ├── Triage_Prioritization.html
│   ├── Triage_Prioritization.csv
│   ├── Triage_Prioritization.xlsx
│   └── vex_recommendations.json    # VEX status recommendations
└── Version_Comparison/             # Only when explicitly requested
    ├── Version_Comparison.html
    ├── Version_Comparison.csv       # Summary
    ├── Version_Comparison.xlsx      # Summary + detail sheets
    ├── Version_Comparison_Detail_Findings.csv
    ├── Version_Comparison_Detail_Findings_Churn.csv
    └── Version_Comparison_Detail_Component_Churn.csv
```

## Performance Features

The reporting kit includes several performance optimizations:

- **Intelligent Caching**: Data is automatically cached and shared between reports within a session
- **Persistent SQLite Cache**: Enable with `--cache-ttl` for crash recovery and faster reruns across sessions
- **Efficient API Usage**: Project and version filtering reduces data transfer
- **Latest Version Only (Default)**: Only fetches findings from the latest version of each project, reducing data volume by 60-70%. Use `--all-versions` for historical data.
- **Clear Progress Indicators**: Shows when data comes from cache vs API calls

For detailed performance information, see [Performance Guide](docs/PERFORMANCE_GUIDE.md).

### Persistent Cache (SQLite)

```bash
# Cache data for 1 hour — enables crash recovery and faster reruns
poetry run fs-report --cache-ttl 1h

# Cache for 30 minutes
poetry run fs-report --cache-ttl 30m

# Force fresh data (ignore cache)
poetry run fs-report --no-cache

# Clear all cached API data
poetry run fs-report --clear-cache

# Clear AI remediation cache separately
poetry run fs-report --clear-ai-cache
```

Cache location: `~/.fs-report/cache.db`

## Crash Recovery

If a report is interrupted (e.g., due to network issues or API rate limiting), the reporting kit automatically resumes from where it left off. When using `--cache-ttl`, progress is tracked in the SQLite cache and reruns skip already-fetched data within the TTL window.

## Troubleshooting

### Verify Environment Variables
```bash
echo $FINITE_STATE_AUTH_TOKEN
echo $FINITE_STATE_DOMAIN
```

### Test API Connection
Try listing your projects to verify connectivity:
```bash
poetry run fs-report list-projects
```

### Cache Recovery
If a report is interrupted, rerun the same command to resume. When using `--cache-ttl`, data is stored in `~/.fs-report/cache.db`. To force a fresh run, use `--no-cache` or run `--clear-cache`.

## Support

For technical support or questions about the Finite State Reporting Kit:
- Documentation: https://documentation.finitestate.io/docs/
- Support: support@finitestate.io

## Version Information

Report Engine: fs-report
Supported Formats: HTML, CSV, XLSX 