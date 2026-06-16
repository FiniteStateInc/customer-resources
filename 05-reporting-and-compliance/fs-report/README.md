# Finite State Reporting Kit

A powerful, stand-alone reporting utility for Finite State customers that generates HTML, CSV, XLSX, and Markdown reports from API data using YAML recipes.

## Features

- **YAML Recipe System**: Define reports using simple YAML configuration files
- **Multiple Output Formats**: Generate HTML, CSV, XLSX, and Markdown reports
- **Interactive Charts**: Beautiful, responsive charts using Chart.js
- **Custom Data Processing**: Advanced data manipulation and analysis
- **Standalone Operation**: Runs entirely outside the Finite State SaaS platform
- **CLI Interface**: Command-line tool for easy automation and integration
- **Comparison Reports**: Diff components, findings, licenses, and triage status between two versions, projects, or folders

## Available Reports

Reports fall into two categories. See **`REPORT_GUIDE.md`** for full details, including Version Comparison’s full version and component changelog and CSV/XLSX detail exports (findings detail, findings churn, component churn).

**Operational** — period-bound, showing trends and activity within a time window:

| Report | Description |
|--------|-------------|
| Executive Summary | High-level security dashboard for leadership |
| Scan Analysis | Scan throughput, success rates, and infrastructure health |
| User Activity | Platform adoption and engagement metrics |
| Security Progress | Version-over-version security progression — CVEs resolved, new CVEs, per-project progress, portfolio trend |

**Assessment** — current state, showing the latest security posture regardless of time period:

| Report | Description |
|--------|-------------|
| Component Vulnerability Analysis | Riskiest components across the portfolio |
| Findings by Project | Complete findings inventory per project with CVE details, severity, and platform links |
| Component List | Software inventory (SBOM) for compliance |
| CVE Component Evidence | For a project version, lists CVE-bearing components with their associated CVE IDs and the firmware file paths where each was detected; intended for per-version triage *(on-demand, requires `--project`; `--version` optional — defaults to the current version)* |
| Triage Prioritization | Context-aware vulnerability triage with exploit + reachability intelligence |
| Configuration Analysis Triage | Config/secrets/crypto triage — private keys, hardcoded credentials, insecure configs *(on-demand)* |
| License Report | Component license risk classification (Permissive, Copyleft, Proprietary) with policy analysis |
| Executive Dashboard | Portfolio-level security overview with KPI cards, risk donut, severity trends, policy health, and more. Runs in fast **summary mode** by default; use `--detailed` for the legacy per-finding pipeline *(on-demand)* |
| CVE Impact | CVE-centric dossier with affected projects, reachability, and exploit intelligence *(on-demand)* |
| Remediation Package | Actionable remediation plan with fix-version validation, structured options (upgrade/workaround/mitigation), and optional AI enrichment *(on-demand)* |
| Component Remediation Package | Zero-day remediation guidance for a component — upgrade paths, breaking changes, mitigations, and AI-powered recommendations *(on-demand)* |
| Component Impact | Portfolio blast radius for a named component — affected projects, versions, and severity breakdown *(on-demand)* |
| Version Comparison | Full version and component changelog (every version pair); fixed/new findings and component churn per step; CSV/XLSX include summary plus detail *(on-demand)* |
| CRA Compliance | EU Cyber Resilience Act Article 14 — 5-section morning-queue (🔥 SLA-Breach, 🆕 Newly Above Threshold, 🔁 Re-emerged, ⏰ Still-in-Triage, 📋 Snapshot) with CISA KEV notification clock, action-driven KPIs (OVERDUE / DUE_SOON / Unknown Clock / Reachable / In Triage), VulnCheck threat-actor evidence on queue rows, and `--since` delta detection for daily automation runs *(on-demand)* |
| False Positive Analysis | Surface likely false positives using mechanical checks and AI applicability analysis; auto-apply VEX with `--autotriage` *(on-demand)* |
| Scan Quality | Per-asset scan coverage and quality signals — scan type gaps and reachability unknowns *(on-demand)* |

## Quick Start

### Prerequisites

- Python 3.11+
- Finite State API access

### Installation

The quickest way to install is with a single command:

**macOS / Linux (bash):**

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/05-reporting-and-compliance/fs-report/setup.sh)"
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/05-reporting-and-compliance/fs-report/setup.ps1 | iex
```

> If PowerShell blocks the script with an execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` first, then re-run the install.

These handle Python verification, pipx installation, credential setup, and PATH configuration automatically. You can also run them from a local clone:

```bash
# macOS / Linux
./setup.sh                    # Interactive setup
./setup.sh --from-source      # Install from current directory
./setup.sh --from-source --yes # Non-interactive (uses env vars)
```

```powershell
# Windows (PowerShell)
.\setup.ps1                   # Interactive setup
.\setup.ps1 -FromSource       # Install from current directory
```

You can also install manually with pipx:

```bash
pipx install fs-report
```

> **PDF output** requires the Chromium rendering engine — install it once with `fs-report install-engine` (the setup scripts print a reminder to run this).

Once installed, set up API credentials (the setup script will prompt for these, or you can set them yourself):

```bash
# macOS / Linux
export FINITE_STATE_AUTH_TOKEN="your-api-token"
export FINITE_STATE_DOMAIN="customer.finitestate.io"
```

```powershell
# Windows (PowerShell) — current session
$env:FINITE_STATE_AUTH_TOKEN = "your-api-token"
$env:FINITE_STATE_DOMAIN     = "customer.finitestate.io"

# Windows (PowerShell) — persist for future sessions
[Environment]::SetEnvironmentVariable("FINITE_STATE_AUTH_TOKEN", "your-api-token", "User")
[Environment]::SetEnvironmentVariable("FINITE_STATE_DOMAIN", "customer.finitestate.io", "User")
```

Verify installation:

```bash
fs-report --help
```

> **Developer workflow:** If you are contributing to fs-report, use `poetry install && poetry shell` to work inside the dev environment. All examples below assume `fs-report` is on your PATH (via pipx or an active Poetry shell).

### CLI Command Structure

The CLI is organized into subcommands for better discoverability:

| Command | Description |
|---------|-------------|
| `fs-report` | Launch the web UI (default, no arguments) |
| `fs-report run` | Generate reports (all existing flags preserved) |
| `fs-report bundle` | Build a compound report bundle (multiple recipes in one document) and save it for `run` |
| `fs-report compare` | Run a comparison report between two scopes (`--left` / `--right`) |
| `fs-report list {recipes,projects,folders,versions}` | Explore available resources |
| `fs-report cache {clear,status}` | Manage cached data |
| `fs-report config {init,show}` | Manage configuration |
| `fs-report changelog` | Show per-report changelog |
| `fs-report help periods` | Show period format help |
| `fs-report serve [directory]` | Serve reports via local HTTP server |

> **Backwards compatibility:** Old hyphenated command names (`list-recipes`, `list-projects`, `show-periods`) still work but emit deprecation warnings. The bare `fs-report --recipe ...` invocation is **no longer supported** — use `fs-report run --recipe ...`.

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
fs-report run --project "Router*"                      # Glob pattern (matches all Router… projects)
fs-report run --project "Sensor_[AB]"                  # Glob with character class
fs-report run --version "1234567890"                   # By version ID (no project needed)
fs-report run --project "MyProject" --version "v1.2.3" # Version name (needs project)
fs-report run --finding-types cve                      # CVE only (default)
fs-report run --finding-types cve,credentials          # CVE + credentials
fs-report run --finding-types all                      # All finding types
```

> **Project glob patterns:** `--project` accepts `*`, `?`, and `[…]` wildcards (case-insensitive). A single match scopes to that project; multiple matches scope to all matched projects (like `--folder`). Glob cannot be combined with `--version`.

**Project dependencies** — when a project has dependencies, findings from dependent projects are automatically included:

```bash
fs-report run --project "MyProduct"                    # Includes findings from all dependencies
fs-report run --project "MyProduct" --standalone       # Only direct findings (no dependencies)
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

**Remediation Package** — actionable remediation plan with fix validation:

```bash
fs-report run --recipe "Remediation Package" --project "MyProject"
fs-report run --recipe "Remediation Package" --project "MyProject" --ai
fs-report run --recipe "Remediation Package" --folder "Product Line A"
```

**CVE Component Evidence** — per-version triage: every CVE-bearing component with its CVE IDs and the firmware file paths where it was detected. Scoped to a single project version; uses the same `affected==<componentId>` findings join the platform UI uses. The `Evidence File Paths` column is fetched from the platform using your existing API credentials. Per-component lookups are parallelized and cached; if you hit rate limits or errors, lower `FS_REPORT_EVIDENCE_WORKERS` (default 5) to tune concurrency.

```bash
fs-report run --recipe "CVE Component Evidence" \
    --project "MyProject" --version 1234567890 --cache-ttl 4h
fs-report run --recipe "CVE Component Evidence" \
    --project "MyProject" --version "v1.2.3" --cache-ttl 4h     # version name also works
FS_REPORT_EVIDENCE_WORKERS=1 fs-report run \
    --recipe "CVE Component Evidence" --project "MyProject" --version 1234567890
```

**Persistent cache** — crash recovery and faster reruns:

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

- **Dashboard** with 16 workflow cards covering all recipes — each card opens a pre-run panel with recipe-specific configuration (AI settings, component filter, CVE input, version pickers, etc.)
- **Real-time progress** streaming via Server-Sent Events (SSE) during report generation
- **Direct report linking** — "View Report" opens the generated HTML immediately after a run
- **Cancellation** — cancel button works at any point, including during NVD lookups
- **Settings management** with persistence to `~/.fs-report/config.yaml`
- **Reports browser** with preview for previously generated reports
- **Scan Queue** panel — live scan monitoring with queued/processing counts, per-version grouping, stuck scan detection, and auto-refresh
- **Zip bundle download** — download current output plus history runs as a zip file
- **Log file viewer** — view log files from history runs in the browser
- **New Folder creation** — create directories in the directory browser
- **Per-recipe progress** — real-time progress bar updates during multi-recipe runs
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

### Persistent SQLite Cache

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
- **Crash recovery** — resume interrupted fetches automatically
- **Faster reruns** — skip API calls for cached data within TTL

Cache location: `~/.fs-report/cache.db`

## AI Features

The reporting kit supports AI-powered remediation guidance via the `--ai` flag. Three LLM providers are supported — the provider is auto-detected from environment variables, or you can choose explicitly with `--ai-provider`:

| Provider | Env Variable | Models |
|----------|-------------|--------|
| **Anthropic** (default) | `ANTHROPIC_API_KEY` | Claude Opus / Haiku |
| **OpenAI** | `OPENAI_API_KEY` | GPT-4o / GPT-4o-mini |
| **GitHub Copilot** | `GITHUB_TOKEN` | GPT-4o / GPT-4o-mini |

Override the default models with `--ai-model-high` / `--ai-model-low` CLI flags or the `ai_model_high` / `ai_model_low` config keys.

```bash
# Auto-detect provider from env vars
fs-report run --recipe "Triage Prioritization" --ai --period 30d

# Explicit provider
fs-report run --recipe "Triage Prioritization" --ai --ai-provider openai --period 30d

# Custom model overrides
fs-report run --recipe "Triage Prioritization" --ai --ai-model-high claude-sonnet-4-20250514 --period 30d

# Export prompts for manual use (no API key required)
fs-report run --recipe "Triage Prioritization" --ai-prompts --period 30d
```

### Deployment Context

Tailor AI prompts to your product's deployment environment with `--product-type` and `--network-exposure`. This selects a product-specific AI persona and shapes workaround recommendations:

```bash
# Inline deployment context
fs-report run --recipe "Remediation Package" --project "MyRouter" --ai \
  --product-type firmware --network-exposure air_gapped

# From a YAML file (can include regulatory and deployment_notes)
fs-report run --recipe "CVE Impact" --cve CVE-2024-1234 --ai \
  --context-file deployment.yaml
```

Example `deployment.yaml`:

```yaml
product_type: firmware
network_exposure: internal_only
regulatory: "IEC-62443, FDA"
deployment_notes: "Edge gateway deployed in hospital network"
```

Product types: `firmware`, `web_app`, `mobile_app`, `library`, `device_driver`, `container`, `desktop_app`, `generic`. Network exposure: `air_gapped`, `internal_only`, `internet_facing`, `mixed`, `unknown`.

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

## Comparison Reports

`fs-report compare` runs a comparison ("diff") report between two scopes — two
project versions, two projects, or two folders. Each `--left` / `--right` scope
is a reference like `project:My Device@v3.2.1`, `project:My Device` (latest
version), or `folder:EU-Routers`.

```bash
# Diff the components between two versions of a project
fs-report compare component_diff --left "project:My Device@v3.2.1" --right "project:My Device@v3.3.0"

# Diff findings between two projects
fs-report compare "Finding Diff" --left "project:Router A" --right "project:Router B"

# Add a cover title/logo for a customer-ready deliverable
fs-report compare "License Diff" --left "folder:EU-Routers" --right "folder:US-Routers" --title "License Drift"
```

Available comparison recipes (run `fs-report list recipes` to see the Comparison group):

| Recipe | Description |
|--------|-------------|
| Component Diff | Components added, removed, and version-changed between the two scopes |
| Finding Diff | Findings (CVEs) introduced, resolved, and carried over |
| License Diff | License classification changes across the two scopes |
| Triage Status Diff | VEX/triage status changes per finding |

Comparison reports render to HTML. For version-over-version trends within a
single project, see the **Version Comparison** report under `fs-report run` instead.

## Exit Codes
- `0`: Success
- `1`: Runtime error — report generation failed, or an API/data/file/validation error during the run
- `2`: Usage error — missing or invalid arguments (e.g. no token/domain, an invalid `--left`/`--right` scope, or an unsupported bare-flag invocation)

## Security

**Recipes are code.** Custom recipes can execute arbitrary pandas expressions, so treat them with the same security practices as executable scripts:

- Review custom recipes before running them
- In CI/CD pipelines, only use recipes from version-controlled sources
- Never download and execute recipes from untrusted sources

**Authoring your own recipe:** start from the bundled template at `fs_report/recipes/_TEMPLATE.yaml` (and the shipped recipe YAML files as worked examples), then run it with `fs-report run --recipes <your-dir> --recipe "<Name>"`.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass and coverage is maintained
6. Submit a pull request

## License

This project is licensed under the Functional Source License, Version 1.1, with MIT Future License (FSL-1.1-MIT). Each release converts to the MIT License two years after its publication. See the LICENSE file for details.

## Support

For support and questions, please contact Finite State support or create an issue in the repository.