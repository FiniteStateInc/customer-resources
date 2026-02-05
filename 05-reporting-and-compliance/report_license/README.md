# Finite State License Report Generator

A CLI tool that pulls license data from the Finite State REST API and generates CSV reports with component license information, copyleft status, and more.

## Features

- Generate CSV reports with component license data
- Support for project name, project ID, or version ID lookups
- Automatic latest version resolution
- License copyleft family detection
- Summary statistics (optional)
- Debug mode for troubleshooting

## Prerequisites

- Python 3.8+
- [uv](https://docs.astral.sh/uv/) - install with:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- Environment variables set:
  - `FINITE_STATE_DOMAIN`: Your Finite State domain (e.g., `yourcompany.finitestate.io`)
  - `FINITE_STATE_AUTH_TOKEN`: Your API token

## Usage

Using [uv](https://docs.astral.sh/uv/):

```bash
# By project name (uses latest version)
uv run report_license.py --project "MyProject"

# By project ID (uses latest version)
uv run report_license.py --project-id 3161401371292730239

# By specific version ID
uv run report_license.py --version-id 3045724872466332389

# Output to file instead of stdout
uv run report_license.py --project "MyProject" --out licenses.csv

# Include summary statistics
uv run report_license.py --project "MyProject" --summary

# Debug mode (test API endpoints)
uv run report_license.py --project "MyProject" --debug
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--project NAME` | Project name to look up (uses latest version) |
| `--project-id ID` | Project ID to look up (uses latest version) |
| `--version-id ID` | Specific version ID to process |
| `--out FILE` | Write CSV to file (default: stdout) |
| `--delimiter STR` | Delimiter for multiple licenses (default: ` \| `) |
| `--summary` | Print summary stats to stderr |
| `--debug` | Enable debug mode |

**Note**: One of `--project`, `--project-id`, or `--version-id` is required.

## Output Format

The CSV report includes the following columns:

| Column | Description |
|--------|-------------|
| `component` | Component name |
| `version` | Component version |
| `findings_count` | Number of security findings |
| `type` | Component type (library, firmware, etc.) |
| `supplier` | Component supplier/vendor |
| `declared_licenses` | License(s) declared for the component |
| `release_date` | Component release/creation date |
| `source` | Source of the component (purl, etc.) |
| `copyleft_status` | Copyleft family status |

## Example Output

```csv
component,version,findings_count,type,supplier,declared_licenses,release_date,source,copyleft_status
express,4.18.2,3,library,express,MIT,2023-01-15,npm,PERMISSIVE
lodash,4.17.21,0,library,lodash,MIT,2021-02-20,npm,PERMISSIVE
```

## Troubleshooting

### "FINITE_STATE_DOMAIN environment variable is required"

Set your environment variables:

```bash
export FINITE_STATE_DOMAIN="yourcompany.finitestate.io"
export FINITE_STATE_AUTH_TOKEN="your-api-token"
```

### "Project not found"

- Verify the project name is spelled correctly (case-sensitive)
- Check that you have access to the project
- Use `--debug` to see available endpoints

### No components returned

- Ensure the project version has been scanned
- Check that SBOM data is available for the version

## License

MIT License - see LICENSE file for details.
