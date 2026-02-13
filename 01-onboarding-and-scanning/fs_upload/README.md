# Finite State Artifact Upload Script

A simple, functional Python script for uploading artifacts to the Finite State API with automatic project/version creation and intuitive file detection.

## Installation

This project uses [Poetry](https://python-poetry.org/) for dependency management.

```bash
# Install dependencies
poetry install

# The script can be run via Poetry
poetry run fs-upload --help

# Or directly (after installation)
fs-upload --help
```

## Authentication

The script requires authentication via API token and domain. These can be provided via:

- Command-line arguments: `--auth-token` and `--domain`
- Environment variables: `FINITE_STATE_AUTH_TOKEN` and `FINITE_STATE_DOMAIN`

```bash
export FINITE_STATE_AUTH_TOKEN="your-token-here"
export FINITE_STATE_DOMAIN="https://your-domain.finitestate.io"
```

## Usage

### Basic Usage

Upload files from the current directory to a project:

```bash
poetry run fs-upload --project "My Project" --version "1.0.0" file1.bin file2.bin
```

Upload all files from current directory (default behavior):

```bash
poetry run fs-upload --project "My Project" --version "1.0.0"
```

Upload files from a directory:

```bash
poetry run fs-upload --project "My Project" --version "1.0.0" /path/to/artifacts/
```

### Scan Types

#### Binary Scans (Default)

Binary scans run all analysis types (SCA, SAST, Config, Vulnerability Analysis):

```bash
poetry run fs-upload --project "My Project" --version "1.0.0" --scan-type binary firmware.bin
```

#### Third-Party Scans

Requires specifying the third-party scan type:

```bash
poetry run fs-upload --project "My Project" --version "1.0.0" \
  --scan-type third-party \
  --third-party-type burp_scan \
  scan-results.xml
```

#### SBOM Uploads

SBOM format (CDX or SPDX) is auto-detected, but can be overridden:

```bash
# Auto-detect format
poetry run fs-upload --project "My Project" --version "1.0.0" --scan-type sbom sbom.json

# Explicitly specify format
poetry run fs-upload --project "My Project" --version "1.0.0" \
  --scan-type sbom \
  --sbom-type cdx \
  sbom.json
```

### Project and Version Management

Projects and versions are automatically created if they don't exist:

```bash
# Creates project "New Project" and version "v1.0" if they don't exist
poetry run fs-upload --project "New Project" --version "v1.0" artifact.bin
```

#### Project Type

Default project type is `firmware`, but can be changed:

```bash
poetry run fs-upload --project "My App" --version "1.0" \
  --project-type application \
  app.bin
```

Available project types: `application`, `framework`, `library`, `container`, `platform`, `operating-system`, `device`, `device-driver`, `firmware`, `file`, `machine-learning-model`, `data`

#### Release Type

Default release type is `RELEASE`:

```bash
poetry run fs-upload --project "My Project" --version "1.0" \
  --release-type RELEASE \
  artifact.bin
```

### Folder Organization

Projects can be organized into folders by ID or name:

```bash
# By folder ID
poetry run fs-upload --project "My Project" --version "1.0" \
  --folder "1234567890123456789" \
  artifact.bin

# By folder name (auto-detected)
poetry run fs-upload --project "My Project" --version "1.0" \
  --folder "Medical Products" \
  artifact.bin
```

### CSV Input

For batch uploads with different projects/versions per file, use CSV:

```csv
artifact_name,project_name,version,destination_folder,scan_type
/path/to/file1.bin,Project A,1.0.0,Medical Products,binary
/path/to/file2.xml,Project B,2.0.0,,third-party
/path/to/sbom.json,Project C,1.5.0,,sbom
```

```bash
poetry run fs-upload --csv uploads.csv --third-party-type burp_scan
```

**CSV Column Rules:**

- `artifact_name` (required): Path to file to upload
- `project_name` (required if not in CLI): Project name
- `version` (required if not in CLI): Version name
- `destination_folder` (optional): Folder ID or name
- `scan_type` (optional): `binary`, `third-party`, or `sbom` (defaults to CLI `--scan-type`)

**Precedence:**

- CLI arguments override CSV values (e.g., `--project` overrides CSV `project_name`)
- Per-row CSV `scan_type` takes precedence over global `--scan-type` for that row

### Recursive Directory Processing

Process directories recursively:

```bash
poetry run fs-upload --project "My Project" --version "1.0" \
  --recursive \
  /path/to/artifacts/
```

### Wildcard Patterns

Use glob patterns to match files:

```bash
poetry run fs-upload --project "My Project" --version "1.0" "*.bin" "firmware/*.elf"
```

### Dry Run

Preview what would be uploaded without actually uploading:

```bash
poetry run fs-upload --project "My Project" --version "1.0" \
  --dry-run \
  artifact.bin
```

### Auto-Accept

Skip confirmation prompt (useful for automation):

```bash
poetry run fs-upload --project "My Project" --version "1.0" \
  --yes \
  artifact.bin
```

## Features

- **Automatic Project/Version Creation**: Projects and versions are created automatically if they don't exist
- **Intuitive File Detection**: Automatically detects files, directories, and patterns
- **Multiple Scan Types**: Supports binary, third-party, and SBOM uploads
- **SBOM Auto-Detection**: Automatically detects CDX vs SPDX format
- **Folder Organization**: Support for folder IDs and names with auto-lookup
- **CSV Batch Processing**: Upload multiple files with different configurations
- **Error Handling**: Continues processing on errors and reports summary
- **Progress Indication**: Shows progress for batch uploads
- **Filename Sanitization**: Automatically sanitizes filenames to match API requirements
- **Dry Run Mode**: Preview uploads without actually uploading

## Examples

### Example 1: Simple Binary Upload

```bash
poetry run fs-upload \
  --project "Firmware Release" \
  --version "2.1.0" \
  firmware.bin
```

### Example 2: Multiple Files with Folder

```bash
poetry run fs-upload \
  --project "Product Line A" \
  --version "1.0" \
  --folder "Medical Devices" \
  --release-type RELEASE \
  file1.bin file2.bin file3.bin
```

### Example 3: CSV Batch Upload

```bash
# uploads.csv
artifact_name,project_name,version,scan_type
./build/firmware_v1.bin,Firmware Project,1.0.0,binary
./scans/security_scan.xml,Security Project,2.0.0,third-party
./sboms/components.json,Components Project,1.5.0,sbom

# Command
poetry run fs-upload --csv uploads.csv --third-party-type burp_scan
```

### Example 4: Recursive Directory Upload

```bash
poetry run fs-upload \
  --project "Build Artifacts" \
  --version "nightly" \
  --recursive \
  ./build/
```

## Error Handling

The script continues processing even if individual uploads fail. At the end, a summary is displayed showing:

- Number of successful uploads
- Number of failed uploads
- Detailed error messages for failures

## Filename Requirements

Filenames are automatically sanitized to match API requirements:

- Pattern: `^[a-zA-Z0-9. -_()]{1,60}$`
- Invalid characters are replaced with underscores
- Filenames longer than 60 characters are truncated
- Warnings are displayed when filenames are modified

## Notes

- The SBOM endpoint uses `projectVersionId` as integer (int64), while binary/third-party use string. This is handled automatically.
- CSV and positional file arguments are mutually exclusive - use one or the other.
- When using CSV, per-row `scan_type` takes precedence over global `--scan-type`.
- CLI arguments always override corresponding CSV column values.
