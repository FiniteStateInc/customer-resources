# ComponentPlus

SBOM-based component injection script for Finite State project versions.

## Overview

This script enables bulk component injection into Finite State project versions by generating CycloneDX 1.6 SBOMs and uploading them via the Finite State CLI.

## Installation

```bash
poetry install
```

## Usage

```bash
poetry run componentplus \
  --components-csv components.csv \
  --targets-csv targets.csv \
  [--fs-cli-jar ./finitestate.jar] \
  [--dry-run] \
  [--java-path java] \
  [--output-dir ./sboms] \
  [--component-type library] \
  [--log-level INFO] \
  [--log-file log.txt]
```

## Environment Variables

- `FINITE_STATE_AUTH_TOKEN` - Required authentication token
- `FINITE_STATE_DOMAIN` - Required Finite State domain URL

## CSV Formats

### Components CSV

Required columns:
- `component_name`
- `component_version`
- `supplier_name`
- `swid_tag_id`

Example: See `sample_components.csv` in the root directory.

### Targets CSV

Either provide IDs or names:
- IDs: `project_id`, `project_version_id`
- Names: `project_name`, `project_version_name`

If both are present, IDs take precedence.

Example: See `sample_targets.csv` in the root directory.

## Testing

Run the test suite:

```bash
poetry install
poetry run pytest
```

Run with coverage:

```bash
poetry run pytest --cov=. --cov-report=html
```

See `tests/README.md` for more details on the test suite.

