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

# Specify custom recipes and output directories
poetry run fs-report --recipes ./my-recipes --output ./my-reports

# Enable verbose logging
poetry run fs-report --verbose
```

## Performance and Caching

The reporting kit includes intelligent caching to improve performance and reduce API calls:

- **Automatic Cache Sharing**: When running multiple reports, data is automatically cached and shared between reports
- **Progress Indicators**: The CLI shows "Fetching" for API calls and "Using cache" for cached data
- **Resume Support**: Large reports can be resumed from interruption points using progress files
- **Efficient Filtering**: Project and version filtering is applied at the API level for optimal performance

Example output showing cache usage:
```
Fetching /public/v0/findings | 38879 records
Using cache for /public/v0/findings | 38879 records
```

For detailed performance information, see [Performance Guide](docs/PERFORMANCE_GUIDE.md).

## Progress Files and Recovery

When generating large reports, the tool automatically saves progress files in the output directory. If a report is interrupted (e.g., due to network issues or API rate limiting), you can simply rerun the same command. The tool will resume from the last saved progress, minimizing redundant API calls and saving time.

- **Progress files** are named according to the report and query being executed.
- If you encounter issues or interruptions, rerun the same command to continue from where it left off.
- If you want to start over, delete the relevant progress files from the output directory.

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