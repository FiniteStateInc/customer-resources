# Finite State Risk Report Builder

This tool generates comprehensive PDF risk summary reports for Finite State project versions, similar to the legacy artifact version risk summary reports but updated for the new project/version terminology.

## Features

- **Comprehensive Risk Analysis**: Generates detailed security assessments with risk scores and severity breakdowns
- **Reachability Analysis Info**: Top 100 CVEs with reachability info, by severity, when the data is available
- **Visual Charts**: Includes pie charts, bar charts, and other visualizations for better data presentation
- **CVE Intelligence**: Incorporates CVE data, EPSS scores, and exploit availability information
- **Component Analysis**: Detailed breakdown of components by type, license, and risk level
- **Flexible Output**: Configurable report sections and detail levels
- **API Integration**: Seamlessly integrates with Finite State's REST API
- **Professional PDF Format**: Clean, professional report layout suitable for stakeholders

## Project Structure

```
finite-state-reporter/
├── main.py                          # Main entry point
├── pyproject.toml                    # Poetry configuration & dependencies
├── README.md                         # This file
├── requirements.txt                  # Backup pip requirements
├── src/                             # Source code (src layout)
│   └── finite_state_reporter/        # Main package
│       ├── __init__.py
│       ├── cli.py                    # Command-line interface
│       ├── core/
│       │   └── reporter.py           # Core reporting logic
│       ├── pdf/                     # PDF generation modules
│       │   ├── colors.py            # Color scheme
│       │   ├── styles.py            # Typography & styles
│       │   ├── page_templates.py    # Page layouts
│       │   └── flowables.py         # Custom PDF elements
│       └── static/                  # Static assets
│           ├── images/              # Logo and images
│           └── fonts/               # Custom fonts
├── examples/                        # Usage examples
│   ├── example_usage.py
│   └── sample_reports/              # Sample PDF outputs
├── tests/                          # Test suite
├── schemas/                        # API schemas
└── docs/                          # Documentation
```

## Installation

### Prerequisites

- Python 3.8 or higher
- Poetry (recommended) or pip

### Option 1: Using Poetry (Recommended)

1. **Install Poetry** (if not already installed):
   ```bash
   pip3 install poetry
   ```

2. **Make sure that your SSH key has been created and added to Github
    [Github Instructions](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent?platform=mac)

3. **Clone the repository**:
   ```bash
   git clone git@github.com:FiniteStateInc/customer-resources.git
   cd 05-reporting-and-compliance/fs-reporter
   ```

4. **Install dependencies**:
   ```bash
   poetry install
   ```

### Option 2: Using pip

1. **Clone the repository**:
   ```bash
   git clone git@github.com:FiniteStateInc/finite-state-reporter.git
   cd finite-state-reporter
   ```

2. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

## Quick Start

### Basic Usage with Poetry

```bash
# Using project version ID (recommended for Poetry environments)
poetry run python main.py \
  --token your-api-token-here \ # FINITE_STATE_AUTH_TOKEN environment variable can be used instead
  --subdomain "acme" \ # FINITE_STATE_DOMAIN environment variable can be used instead
  --project-version-id 987654321 \
  --output "~/Documents/Reports/Acme_summary_report.pdf"

# Using project name and version name (alternative to project version ID)
poetry run python main.py \
  --token your-api-token-here \
  --subdomain "acme" \
  --project "My IoT Device" \
  --project-version "v2.1.0" \
  --output "~/Documents/Reports/Acme_summary_report.pdf"

# Using short options (more concise)
poetry run python main.py \
  -t your-api-token-here \
  -s acme \
  -pvi 987654321 \
  -o "~/Documents/Reports/Acme_summary_report.pdf"

# With custom organization name
poetry run python main.py \
  -t your-api-token-here \
  -s acme \
  -p "My IoT Device" \
  -pv "v2.1.0" \
  -n "Acme Corporation" \
  -o "~/Documents/Reports/Acme_summary_report.pdf"
```

### Advanced Usage with Options

*VPN required to get descriptions for detailed findings

```bash
poetry run python main.py \
  --token your-api-token-here \
  --subdomain acme \
  --project-version-id 987654321 \
  --output "my_custom_report.pdf" \
  --detailed-findings \
  --all-severities \
  --max-detailed-findings 500
```

## Command Line Options

| Option | Short | Required | Default | Description |
|--------|-------|----------|---------|-------------|
| `--token` | `-t` | Yes | - | Your Finite State API token |
| `--subdomain` | `-s` | Yes | - | Your Finite State subdomain (e.g., "acme" for acme.finitestate.io) |
| `--project-version-id` | `-pvi` | One required* | - | The project version ID to analyze (mutually exclusive with project/project-version) |
| `--project` | `-p` | One required* | - | The project name (must be used with --project-version, mutually exclusive with --project-version-id) |
| `--project-version` | `-pv` | If using -p | - | The version name (must be used with --project) |
| `--output` | `-o` | No | `risk_summary_report.pdf` | Output file path for the generated PDF |
| `--detailed-findings` | `-d` | No | `false` | Include detailed findings section in the report (shows Critical/High severity and Medium severity with exploit info by default *VPN required) |
| `--all-severities` | `-a` | No | `false` | Include all severity levels in detailed findings (overrides default Critical/High filter). Use with -m to set maximum findings. |
| `--max-detailed-findings` | `-m` | No | `100` | Maximum number of detailed findings to include when using --all-severities (default: 100) |
| `--name` | `-n` | No | subdomain | Organization name to display on the report cover and header (defaults to subdomain if not provided) |

\* **Either** `--project-version-id` **OR** (`--project` + `--project-version`) is required

## Getting Required IDs

### Finding Your Subdomain
Your subdomain is the first part of your Finite State URL. For example:
- URL: `https://acme.finitestate.io` - Subdomain: `acme`

### Getting Your API Key
1. Log into your Finite State account
2. Go to **Settings** > **API Keys**
3. Create a new API key or copy an existing one

### Finding Version IDs

You have two options for specifying which project version to analyze:

#### Option 1: Use Project Name and Version Name (Easiest)
If you know your project name and version name, you can use them directly:
```bash
poetry run python main.py -t YOUR_TOKEN -s YOUR_SUBDOMAIN \
  --project "My Project" --project-version "v1.0.0"
```
The tool will automatically lookup the version ID for you.

#### Option 2: Use Version ID Directly

**Method 1: From the UI**
1. Navigate to your project in the Finite State web interface
2. Select the version you want to analyze
3. The version ID will be in the URL: `/versions/{version-id}`

**Method 2: Using the API**
```bash
# List all projects to find the one you want
curl -X 'GET' \
  'https://your-subdomain.finitestate.io/api/public/v0/projects' \
  -H 'accept: application/json' \
  -H 'X-Authorization: your-api-key'

# Get project details to find the defaultBranch.id
curl -X 'GET' \
  'https://your-subdomain.finitestate.io/api/public/v0/projects/{project-id}' \
  -H 'accept: application/json' \
  -H 'X-Authorization: your-api-key'

# List versions for the project
curl -X 'GET' \
  'https://your-subdomain.finitestate.io/api/public/v0/projects/{project-id}/versions' \
  -H 'accept: application/json' \
  -H 'X-Authorization: your-api-key'
```

## API Endpoints

This application integrates with several APIs to gather comprehensive security data:

### Finite State Customer API Endpoints

The application uses the Finite State API with endpoints that follow this pattern:
- **Base URL**: `https://{subdomain}.finitestate.io/api`
- **API Version**: `v0`

#### Core Endpoints Used:

1. **Projects** (for name lookup)
   - `GET /public/v0/projects`
   - Used to list all projects when looking up by project name

2. **Project Versions** (for name lookup)
   - `GET /public/v0/projects/{project_id}/versions`
   - Used to list all versions for a project when looking up by version name

3. **Version Details**
   - `GET /public/v0/versions/{version_id}`
   - Used to get basic version information

4. **Components**
   - `GET /public/v0/versions/{version_id}/components`
   - Used to fetch all components for a specific version

5. **Findings**
   - `GET /public/v0/versions/{version_id}/findings`
   - Used to fetch all security findings for a specific version

6. **Finding CVEs** (Unused in current implementation)
   - `GET /public/v0/findings/{finding_id}/cves`
   - This endpoint exists but isn't currently used in the code

### External API Endpoints

#### FS SIP API (Finite State Internal - VPN required)
- **URL**: `https://sip.prod-sca.fstate.ninja/cves/v2/metadata`
- **Purpose**: Batch fetching of CVE descriptions
- **Method**: POST with CVE IDs in request body
- **Authentication**: None required (VPN access only)

#### GitHub Advisories API
- **URL**: `https://github.com/advisories/{ghsa_id}`
- **Purpose**: Fetching GHSA (GitHub Security Advisory) descriptions
- **Method**: GET
- **Authentication**: None required (public endpoint)
- **Note**: This is actually HTML parsing, not a true API call

### Summary

The application primarily uses **6 main endpoints**:
1. **5 Finite State API endpoints** for project/version lookup, version details, components, and findings
2. **1 SIP API endpoint** for batch CVE description fetching
3. **1 GitHub advisories endpoint** for GHSA description fetching (HTML parsing)

All Finite State API calls require authentication via API token, while the external endpoints (SIP and GitHub) are either VPN-restricted or public.
