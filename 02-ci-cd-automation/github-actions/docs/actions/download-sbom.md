# download-sbom

Exports the Finite State-generated SBOM back into the workflow as a file and/or workflow artifact.

## Usage

```yaml
- uses: finite-state/download-sbom@v1
  with:
    format: cyclonedx
    include-vex: true
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `version-id` | no | from setup/upload-scan | Falls back to setup context or upload-scan output |
| `format` | no | `cyclonedx` | SBOM format: `cyclonedx` or `spdx` |
| `include-vex` | no | `true` | Include VEX triage data in the SBOM |
| `output-file` | no | `sbom.json` | File path for the downloaded SBOM |
| `upload-artifact` | no | `true` | Upload as a workflow artifact |
| `artifact-name` | no | `finite-state-sbom` | Workflow artifact name |

## Outputs

| Output | Description |
|--------|-------------|
| `file` | Path to the downloaded SBOM file |
| `artifact-name` | Uploaded workflow artifact name |
| `component-count` | Number of components in the SBOM |

## Behavior

1. Calls the SBOM export API (`GET /sboms/cyclonedx/{pvId}` or `GET /sboms/spdx/{pvId}`)
2. Writes the SBOM to `output-file`
3. Optionally uploads as a workflow artifact (downloadable from the Actions run)

## Examples

### CycloneDX with VEX data (default)

```yaml
- uses: finite-state/download-sbom@v1
```

### SPDX format without VEX

```yaml
- uses: finite-state/download-sbom@v1
  with:
    format: spdx
    include-vex: false
    output-file: sbom-spdx.json
```

### Custom artifact name for release builds

```yaml
- uses: finite-state/download-sbom@v1
  with:
    version-id: ${{ steps.upload.outputs.version-id }}
    artifact-name: "sbom-${{ github.ref_name }}"
```

### Use SBOM in a downstream step

```yaml
- uses: finite-state/download-sbom@v1
  id: sbom
  with:
    upload-artifact: false  # Just write the file, don't upload

- name: Process SBOM
  run: |
    echo "SBOM has ${{ steps.sbom.outputs.component-count }} components"
    jq '.components | length' ${{ steps.sbom.outputs.file }}
```
