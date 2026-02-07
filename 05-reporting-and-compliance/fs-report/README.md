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

Reports fall into two categories. See `REPORT_GUIDE.md` for full details.

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

## Quick Start

### Prerequisites

- Python 3.11+
- Poetry (for dependency management)
- Finite State API access

### Installation

#### Option 1: Install from Package (Recommended for Customers)

1. **Download and extract the package**:
   ```bash
   # Download fs_report-0.1.1.tar.gz
   tar -xzf fs_report-0.1.1.tar.gz
   cd fs_report-0.1.1
   ```

2. **Install with Poetry**:
   ```bash
   poetry install
   ```

3. **Set up API credentials**:
   ```bash
   export FINITE_STATE_AUTH_TOKEN="your-api-token"
   export FINITE_STATE_DOMAIN="customer.finitestate.io"
   ```

4. **Verify installation**:
   ```bash
   poetry run fs-report --help
   ```

#### Option 2: Development Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd fs-report
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

# Specify custom recipes and output directories
poetry run fs-report --recipes ./my-recipes --output ./my-reports

# Enable verbose logging
poetry run fs-report --verbose
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

### Build the Image
```bash
docker build -t fs-report .
```

### Basic Usage (Built-in Recipes)
The container includes all default recipes. First, set your environment variables:

```bash
export FINITE_STATE_AUTH_TOKEN="your-token"
export FINITE_STATE_DOMAIN="customer.finitestate.io"
```

Then run with your existing environment variables:

```bash
docker run -v $(pwd)/output:/app/output \
           -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report
```

### Advanced Usage (Custom Recipes)
To use your own recipes, mount the recipes directory:

```bash
docker run -v $(pwd)/recipes:/app/recipes \
           -v $(pwd)/output:/app/output \
           -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report
```

### Available Commands
```bash
# View help
docker run --rm fs-report --help

# Generate reports with custom date range
docker run -v $(pwd)/output:/app/output \
           -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report --start 2025-01-01 --end 2025-01-31

# Filter by project and version
docker run -v $(pwd)/output:/app/output \
           -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report --project "MyProject" --version "v1.2.3"

# Filter by version ID only (no project needed)
docker run -v $(pwd)/output:/app/output \
           -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report --version "1234567890"

# Use period shortcuts
docker run -v $(pwd)/output:/app/output \
           -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report --period 1w

# List available projects
docker run --rm -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report list-projects

# List available versions for a project
docker run --rm -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report list-versions "MyProject"

# List all versions across the portfolio
docker run --rm -e FINITE_STATE_AUTH_TOKEN \
           -e FINITE_STATE_DOMAIN \
           fs-report list-versions
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