# upload-scan

Uploads binaries, SBOMs, or third-party scan results to the Finite State platform for analysis. Handles all upload types through a single action with a `type` input.

## Usage

```yaml
- uses: finite-state/upload-scan@v1
  with:
    type: sca
    file: build/firmware.bin
    version: "pr-${{ github.event.number }}"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `type` | **yes** | — | Upload type: `sca`, `sast`, `config`, `vulnerability-analysis`, `sbom`, `third-party` |
| `file` | **yes** | — | Path to the file to upload |
| `project-id` | no | from setup | Override project ID (falls back to setup context) |
| `version` | no | — | Version name. Creates a new version if provided. |
| `version-id` | no | — | Existing version ID. Mutually exclusive with `version`. |
| `scanner-type` | no | — | Required for `third-party` type: `grype`, `trivy`, `snyk`, etc. |
| `sbom-format` | no | — | Required for `sbom` type: `cdx` or `spdx` |
| `wait-for-completion` | no | `true` | Poll scan status until done |
| `timeout` | no | `600` | Max wait time in seconds |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-id` | The created scan ID |
| `version-id` | The version ID (created or existing) |
| `scan-status` | Final scan status (`COMPLETED`, `FAILED`, etc.) |

## Upload Types

| Type | Endpoint | Description |
|------|----------|-------------|
| `sca` | `POST /scans` | Binary Software Composition Analysis |
| `sast` | `POST /scans` | Static Analysis Security Testing |
| `config` | `POST /scans` | Configuration audit |
| `vulnerability-analysis` | `POST /scans` | Reachability analysis |
| `sbom` | `POST /scans/sbom` | CycloneDX or SPDX import |
| `third-party` | `POST /scans/third-party` | External scanner results (Grype, Trivy, Snyk, etc.) |

## Behavior

1. Resolves project/version from inputs or setup context
2. If `version` name is provided, creates a new version via `POST /projects/{id}/versions`
3. Routes to the correct upload endpoint based on `type`
4. If `wait-for-completion` is true, polls scan status until `COMPLETED` or `FAILED`
5. Fails the step if the scan fails or times out

## Examples

### Binary SCA scan

```yaml
- uses: finite-state/upload-scan@v1
  with:
    type: sca
    file: build/firmware.bin
    version: "v${{ github.sha }}"
```

### Reachability analysis

```yaml
- uses: finite-state/upload-scan@v1
  with:
    type: vulnerability-analysis
    file: build/firmware.bin
```

### Third-party scan results (Grype)

```yaml
- uses: finite-state/upload-scan@v1
  with:
    type: third-party
    scanner-type: grype
    file: grype-results.json
```

### SBOM import

```yaml
- uses: finite-state/upload-scan@v1
  with:
    type: sbom
    sbom-format: cdx
    file: sbom.json
```

### Long-running scan with increased timeout

```yaml
- uses: finite-state/upload-scan@v1
  with:
    type: sca
    file: build/large-firmware.bin
    timeout: 1800  # 30 minutes
```
