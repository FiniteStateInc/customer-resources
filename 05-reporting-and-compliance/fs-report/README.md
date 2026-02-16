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
| Findings by Project | Complete findings inventory per project with CVE details, severity, and platform links |
| Component List | Software inventory (SBOM) for compliance |
| Triage Prioritization | Context-aware vulnerability triage with exploit + reachability intelligence |
| CVE Impact | CVE-centric dossier with affected projects, reachability, and exploit intelligence *(on-demand)* |
| Version Comparison | Full version and component changelog (every version pair); fixed/new findings and component churn per step; CSV/XLSX include summary plus detail *(on-demand)* |

## Quick Start

### Prerequisites

- Python 3.11+
- Poetry (for dependency management)
- Finite State API access
- FastAPI and uvicorn are included by default (powers the web UI)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/FiniteStateInc/customer-resources.git
   cd customer-resources/05-reporting-and-compliance/fs-report
   ```

2. **Install dependencies and activate the environment**:
   ```bash
   poetry install
   poetry shell
   ```

3. **Set up API credentials**:
   ```bash
   export FINITE_STATE_AUTH_TOKEN="your-api-token"
   export FINITE_STATE_DOMAIN="customer.finitestate.io"
   ```

4. **Verify installation**:
   ```bash
   fs-report --help
   ```

> All examples below assume the Poetry environment is active (`poetry shell`). If you prefer not to activate the shell, prefix each command with `poetry run`.

### CLI Command Structure

The CLI is organized into subcommands for better discoverability:

| Command | Description |
|---------|-------------|
| `fs-report` | Launch the web UI (default, no arguments) |
| `fs-report run` | Generate reports (all existing flags preserved) |
| `fs-report list {recipes,projects,folders,versions}` | Explore available resources |
| `fs-report cache {clear,status}` | Manage cached data |
| `fs-report config {init,show}` | Manage configuration |
| `fs-report help periods` | Show period format help |
| `fs-report serve [directory]` | Serve reports via local HTTP server |

> **Backwards compatibility:** Old command names (`list-recipes`, `list-projects`, `show-periods`, bare `fs-report --recipe ...`) still work but emit deprecation warnings.

### Config File

Set defaults in `.fs-report.yaml` (searched in CWD first, then `~/.fs-report/config.yaml`):

```yaml
# .fs-report.yaml
recipe: "Executive Summary"
period: 30d
output: ./reports
verbose: true
```

Priority: CLI flags > environment variables > config file > defaults.

Create one interactively: `fs-report config init`

### CLI Usage Examples

**Generate reports** with `fs-report run`:

```bash
fs-report run                                          # All reports, default settings
fs-report run --recipe "Executive Summary"             # Single report
fs-report run --recipe "Executive Summary" --period 1m # Last month
fs-report run --start 2025-01-01 --end 2025-01-31     # Exact date range
fs-report run --period 7d                              # Last 7 days
```

**Filter** by project, version, or finding type:

```bash
fs-report run --project "MyProject"                    # By project name or ID
fs-report run --version "1234567890"                   # By version ID (no project needed)
fs-report run --project "MyProject" --version "v1.2.3" # Version name (needs project)
fs-report run --finding-types cve                      # CVE only (default)
fs-report run --finding-types cve,credentials          # CVE + credentials
fs-report run --finding-types all                      # All finding types
```

**Version scope** — by default only the latest version of each project is analysed:

```bash
fs-report run --period 1w                              # Latest version per project (fast)
fs-report run --period 1w --all-versions               # All historical versions (slower)
```

**CVE Impact** — investigate specific CVEs across your portfolio:

```bash
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234,CVE-2024-5678
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234 --project myproject
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234 --ai-prompts
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234 --ai
```

**Persistent cache** (beta) — crash recovery and faster reruns:

```bash
fs-report run --cache-ttl 1h                           # Cache data for 1 hour
fs-report run --cache-ttl 30m                          # 30 minutes
fs-report run --no-cache                               # Force fresh data
fs-report cache status                                 # Show cache stats
fs-report cache clear                                  # Delete all cached data
```

**List resources**:

```bash
fs-report list recipes
fs-report list projects
fs-report list versions                                # All versions across portfolio
fs-report list versions "MyProject"                    # Versions for one project
fs-report list versions -n 10                          # Top 10 by version count
fs-report list versions --folder "Product Line A"
```

**Configuration**:

```bash
fs-report config init                                  # Interactive config wizard
fs-report config show                                  # Show resolved config
```

**Serve reports** and **web UI**:

```bash
fs-report                                              # Launch web UI on localhost:8321
fs-report serve ./output                               # Serve existing reports
```

**Performance tuning** and other options:

```bash
fs-report run --verbose                                # Verbose logging
fs-report run --batch-size 3                           # Reduce API batch size (default 5)
fs-report run --request-delay 1.0                      # Increase delay between requests
fs-report run --recipes ./my-recipes --output ./reports # Custom directories
fs-report help periods                                 # Period format help
```

> **Backwards compatibility:** Old-style commands still work with deprecation warnings:
> `fs-report --recipe "..." --period 1m` → `fs-report run --recipe "..." --period 1m`,
> `fs-report list-recipes` → `fs-report list recipes`,
> `fs-report list-projects` → `fs-report list projects`,
> `fs-report show-periods` → `fs-report help periods`.

### Web UI

Running bare `fs-report` (no arguments) launches an interactive web UI at `http://localhost:8321`:

- **Dashboard** with workflow cards for common report scenarios
- **Real-time progress** streaming via Server-Sent Events (SSE) during report generation
- **Settings management** with persistence to `~/.fs-report/config.yaml`
- **Reports browser** with preview for previously generated reports
- **CSRF protection** and localhost-only access for security

To serve existing reports without the full UI:

```bash
fs-report serve ./output
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
fs-report run --cache-ttl 1h

# Force fresh data (ignore cache)
fs-report run --no-cache

# Clear all cached data
fs-report cache clear
```

Benefits:
- **80% smaller storage** than JSON progress files
- **Crash recovery** - resume interrupted fetches automatically
- **Faster reruns** - skip API calls for cached data within TTL

Cache location: `~/.fs-report/cache.db`

## AI Features

The reporting kit supports AI-powered remediation guidance via the `--ai` flag. Three LLM providers are supported — the provider is auto-detected from environment variables, or you can choose explicitly with `--ai-provider`:

| Provider | Env Variable | Models |
|----------|-------------|--------|
| **Anthropic** (default) | `ANTHROPIC_AUTH_TOKEN` | Claude Sonnet / Haiku |
| **OpenAI** | `OPENAI_API_KEY` | GPT-4o / GPT-4o-mini |
| **GitHub Copilot** | `GITHUB_TOKEN` | GPT-4o / GPT-4o-mini |

```bash
# Auto-detect provider from env vars
fs-report run --recipe "Triage Prioritization" --ai --period 30d

# Explicit provider
fs-report run --recipe "Triage Prioritization" --ai --ai-provider openai --period 30d

# Export prompts for manual use (no API key required)
fs-report run --recipe "Triage Prioritization" --ai-prompts --period 30d
```

See `REPORT_GUIDE.md` for full AI feature details.

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
     fs-report run --period 1m --recipe "Executive Summary"
   ```

The same CLI flags documented above work inside Docker. Just replace `fs-report` with the `docker run ...` prefix. A few more examples:

```bash
# Run all reports for January 2026
docker run --rm -v $(pwd)/output:/app/output \
  -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report run --start 2026-01-01 --end 2026-01-31

# Scope to a folder
docker run --rm -v $(pwd)/output:/app/output \
  -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report run --folder "Product Line A" --period 1m

# List projects (no output volume needed)
docker run --rm -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report list projects

# Use custom recipes by mounting your own recipes directory
docker run --rm \
  -v $(pwd)/my-recipes:/app/recipes \
  -v $(pwd)/output:/app/output \
  -e FINITE_STATE_AUTH_TOKEN -e FINITE_STATE_DOMAIN \
  fs-report run
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