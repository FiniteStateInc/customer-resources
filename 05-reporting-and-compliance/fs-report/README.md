# Finite State Reporting Kit

A powerful, stand-alone reporting utility for Finite State customers that generates HTML, CSV, and XLSX reports from API data using YAML recipes.

## Features

- **YAML Recipe System**: Define reports using simple YAML configuration files
- **Multiple Output Formats**: Generate HTML, CSV, and XLSX reports
- **Interactive Charts**: Beautiful, responsive charts using Chart.js
- **Custom Data Processing**: Advanced data manipulation and analysis
- **Standalone Operation**: Runs entirely outside the Finite State SaaS platform
- **CLI Interface**: Command-line tool for easy automation and integration
- **Data Comparison Tools**: Utilities for comparing XLSX files and analyzing differences

## Available Reports

Reports fall into two categories. See **`REPORT_GUIDE.md`** for full details, including Version Comparison’s full version and component changelog and CSV/XLSX detail exports (findings detail, findings churn, component churn).

**Operational** — period-bound, showing trends and activity within a time window:

| Report | Description |
|--------|-------------|
| Executive Summary | High-level security dashboard for leadership |
| Scan Analysis | Scan throughput, success rates, and infrastructure health |
| User Activity | Platform adoption and engagement metrics |

**Assessment** — current state, showing the latest security posture regardless of time period:

| Report | Description |
|--------|-------------|
| Component Vulnerability Analysis | Riskiest components across the portfolio |
| Findings by Project | Complete findings inventory per project |
| Component List | Software inventory (SBOM) for compliance |
| Triage Prioritization | Context-aware vulnerability triage with exploit + reachability intelligence |
| CVE Impact | CVE-centric dossier with affected projects, reachability, and exploit intelligence *(on-demand)* |
| Version Comparison | Full version and component changelog (every version pair); fixed/new findings and component churn per step; CSV/XLSX include summary plus detail *(on-demand)* |

## Quick Start

### Prerequisites

- Python 3.11+
- Poetry (for dependency management)
- Finite State API access

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/FiniteStateInc/customer-resources.git
   cd customer-resources/05-reporting-and-compliance/fs-report
   ```

2. **Install dependencies**:
   ```bash
   poetry install
   ```

3. **Set up API credentials** (Poetry handles the Python environment automatically):
   ```bash
   export FINITE_STATE_AUTH_TOKEN="your-api-token"
   export FINITE_STATE_DOMAIN="customer.finitestate.io"
   ```

4. **Verify installation**:
   ```bash
   poetry run fs-report --help
   ```

### CLI Usage Examples

```bash
# Run all reports with default settings
poetry run fs-report

# Run only the Executive Summary report
poetry run fs-report --recipe "Executive Summary"

# Specify a custom date range
poetry run fs-report --start 2025-01-01 --end 2025-01-31

# Use a relative time period (e.g., last 7 days, last month)
poetry run fs-report --period 7d
poetry run fs-report --period 1m

# Filter by project name or ID
poetry run fs-report --project "MyProject"

# Filter by project version (version ID or name)
poetry run fs-report --version "1234567890"  # Version ID (no project needed)

# Control which finding types are included (default: cve)
poetry run fs-report --finding-types cve              # CVE only (default)
poetry run fs-report --finding-types cve,credentials  # CVE + credentials
poetry run fs-report --finding-types all              # All findings
poetry run fs-report --project "MyProject" --version "v1.2.3"  # Version name (project required)

# Version filtering (default: latest version only for performance)
poetry run fs-report --period 1w                      # Default: latest version per project (fast)
poetry run fs-report --period 1w --all-versions       # Include all historical versions (slower)

# CVE Impact report — investigate specific CVEs across your portfolio
poetry run fs-report --recipe "CVE Impact" --cve CVE-2024-1234
poetry run fs-report --recipe "CVE Impact" --cve CVE-2024-1234,CVE-2024-5678
poetry run fs-report --recipe "CVE Impact" --cve CVE-2024-1234 --project myproject
poetry run fs-report --recipe "CVE Impact" --cve CVE-2024-1234 --ai-prompts  # Export LLM prompts
poetry run fs-report --recipe "CVE Impact" --cve CVE-2024-1234 --ai          # Live AI guidance

# [BETA] Persistent cache with TTL for crash recovery and faster reruns
poetry run fs-report --cache-ttl 1h                   # Cache data for 1 hour
poetry run fs-report --cache-ttl 30m                  # Cache data for 30 minutes
poetry run fs-report --no-cache                       # Force fresh data fetch
poetry run fs-report --clear-cache                    # Delete all cached data and exit

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

# Only projects in a folder (fewer API calls)
poetry run fs-report list-versions --folder "Product Line A"
poetry run fs-report list-versions --top 20 --folder "Product Line A"

# Specify custom recipes and output directories
poetry run fs-report --recipes ./my-recipes --output ./my-reports

# Enable verbose logging
poetry run fs-report --verbose

# Performance tuning for large instances
poetry run fs-report --batch-size 3                  # Reduce API batch size (default 5, range 1-25)
poetry run fs-report --request-delay 1.0             # Increase delay between API requests (default 0.5s)

# Show help for period format specifications
poetry run fs-report show-periods
```

## Performance and Caching

The reporting kit includes intelligent caching to improve performance and reduce API calls:

- **Latest Version Only (Default)**: By default, reports only include findings from the latest version of each project, reducing data volume by 60-70%. Use `--all-versions` if you need historical data.
- **Automatic Cache Sharing**: When running multiple reports, data is automatically cached and shared between reports
- **Progress Indicators**: The CLI shows "Fetching" for API calls and "Using cache" for cached data
- **Crash Recovery**: Progress is tracked in SQLite, so interrupted fetches resume automatically
- **Efficient Filtering**: Project and version filtering is applied at the API level for optimal performance

Example output showing cache usage:
```
Fetching /public/v0/findings | 38879 records
Using cache for /public/v0/findings | 38879 records
```

### [BETA] Persistent SQLite Cache

For long-running reports or iterative development, enable the persistent cache:

```bash
# Cache data for 1 hour - enables crash recovery and faster reruns
poetry run fs-report --cache-ttl 1h

# Force fresh data (ignore cache)
poetry run fs-report --no-cache

# Clear all cached data
poetry run fs-report --clear-cache
```

Benefits:
- **80% smaller storage** than JSON progress files
- **Crash recovery** - resume interrupted fetches automatically
- **Faster reruns** - skip API calls for cached data within TTL

Cache location: `~/.fs-report/cache.db`

## Docker Usage

If you prefer Docker over a local Python install, you can run reports in a container. All default recipes and templates are baked into the image.

1. **Build the image** (from the `fs-report` directory):
   ```bash
   docker build -t fs-report .
   ```

2. **Set your API credentials**:
   ```bash
   export FINITE_STATE_AUTH_TOKEN="your-api-token"
   export FINITE_STATE_DOMAIN="customer.finitestate.io"
   ```

3. **Run a report** (output is written to the mounted `./output` directory):
   ```bash
   docker run --rm \
     -v $(pwd)/output:/app/output \
     -e FINITE_STATE_AUTH_TOKEN \
     -e FINITE_STATE_DOMAIN \
     fs-report --period 1m --recipe "Executive Summary"
   ```

The same CLI flags documented above work inside Docker. Just replace `poetry run fs-report` with the `docker run ...` prefix. A few more examples:

```bash
# Run all reports for January 2026
docker run --rm -v $(pwd)/output:/app/output \
  -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report --start 2026-01-01 --end 2026-01-31

# Scope to a folder
docker run --rm -v $(pwd)/output:/app/output \
  -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report --folder "Product Line A" --period 1m

# List projects (no output volume needed)
docker run --rm -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report list-projects

# Use custom recipes by mounting your own recipes directory
docker run --rm \
  -v $(pwd)/my-recipes:/app/recipes \
  -v $(pwd)/output:/app/output \
  -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report
```

## Data Comparison Tools

### XLSX File Comparison

Compare two XLSX files by CVE ID for a specific project:

```bash
# Basic comparison
python scripts/compare_xlsx_files.py customer_file.xlsx generated_file.xlsx I421GLGD

# With custom output file
python scripts/compare_xlsx_files.py customer_file.xlsx generated_file.xlsx I421GLGD --output comparison_report.xlsx

# If column names are different
python scripts/compare_xlsx_files.py customer_file.xlsx generated_file.xlsx I421GLGD --cve-column "CVE_ID" --project-column "Project_ID"
```

The comparison tool generates:
- **Summary statistics** in console output
- **Detailed Excel report** with multiple sheets:
  - Summary of differences
  - CVEs only in customer file
  - CVEs only in generated file
  - Side-by-side comparison of matching CVEs

## Exit Codes
- `0`: Success
- `1`: Usage/validation error
- `2`: API authentication failure
- `3`: API rate-limit/connectivity failure

## Security

**Recipes are code.** Custom recipes can execute arbitrary pandas expressions, so treat them with the same security practices as executable scripts:

- Review custom recipes before running them
- In CI/CD pipelines, only use recipes from version-controlled sources
- Never download and execute recipes from untrusted sources

For detailed security guidance, see [Security Considerations](docs/recipes/CUSTOM_REPORT_GUIDE.md#security-considerations) in the Custom Report Guide.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass and coverage is maintained
6. Submit a pull request

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

For support and questions, please contact Finite State support or create an issue in the repository.