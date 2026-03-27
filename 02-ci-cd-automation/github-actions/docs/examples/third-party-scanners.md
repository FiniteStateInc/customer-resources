# Example: Third-Party Scanner Integration

Upload results from external vulnerability scanners (Grype, Trivy, Snyk) to Finite State for unified triage and reporting.

## When to use this

- You already run Grype, Trivy, Snyk, or other scanners in your pipeline
- You want to consolidate findings from multiple scanners in one place
- You want to use Finite State's triage prioritization on third-party results
- You want a single quality gate that covers all scanner outputs

## Grype Integration

```yaml
name: Security Scan (Grype + Finite State)

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    name: Grype Scan & Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Run Grype scan and output JSON results
      - name: Run Grype
        uses: anchore/scan-action@v4
        with:
          path: "."
          output-format: json
          output-file: grype-results.json
          fail-build: false  # Let Finite State handle gating

      # Authenticate with Finite State
      - uses: finite-state/setup@v1
        with:
          api-token: ${{ secrets.FS_API_TOKEN }}
          domain: ${{ vars.FS_DOMAIN }}
          project-id: ${{ vars.FS_PROJECT_ID }}

      # Upload Grype results to Finite State
      - uses: finite-state/upload-scan@v1
        with:
          type: third-party
          scanner-type: grype
          file: grype-results.json
          version: "pr-${{ github.event.number }}"

      # Run triage prioritization on combined findings
      - uses: finite-state/run-report@v1
        id: report
        with:
          recipe: "Triage Prioritization"
          period: 30d

      # Gate on prioritized findings
      - uses: finite-state/quality-gate@v1
        id: gate
        with:
          mode: triage-priority
          fail-on-p0: true

      # Post findings to PR
      - uses: finite-state/pr-comment@v1
        if: always()
        with:
          template: triage
          gate-result: ${{ steps.gate.outputs.result }}
```

## Trivy Integration

```yaml
# Run Trivy scan
- name: Run Trivy
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: "fs"
    format: "json"
    output: "trivy-results.json"
    exit-code: "0"  # Don't fail here

# Upload Trivy results
- uses: finite-state/upload-scan@v1
  with:
    type: third-party
    scanner-type: trivy
    file: trivy-results.json
    version: "pr-${{ github.event.number }}"
```

## Snyk Integration

```yaml
# Run Snyk test
- name: Run Snyk
  uses: snyk/actions/node@master
  continue-on-error: true
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: --json-file-output=snyk-results.json

# Upload Snyk results
- uses: finite-state/upload-scan@v1
  with:
    type: third-party
    scanner-type: snyk
    file: snyk-results.json
    version: "pr-${{ github.event.number }}"
```

## Multi-Scanner Pipeline

Combine multiple scanners in a single workflow, then gate on the unified results:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: finite-state/setup@v1
        with:
          api-token: ${{ secrets.FS_API_TOKEN }}
          domain: ${{ vars.FS_DOMAIN }}
          project-id: ${{ vars.FS_PROJECT_ID }}

      # Run Grype
      - name: Grype scan
        uses: anchore/scan-action@v4
        with:
          path: "."
          output-format: json
          output-file: grype-results.json
          fail-build: false

      # Run Trivy
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: "fs"
          format: "json"
          output: "trivy-results.json"
          exit-code: "0"

      # Upload all results to the same version
      - uses: finite-state/upload-scan@v1
        id: grype-upload
        with:
          type: third-party
          scanner-type: grype
          file: grype-results.json
          version: "pr-${{ github.event.number }}"

      - uses: finite-state/upload-scan@v1
        with:
          type: third-party
          scanner-type: trivy
          file: trivy-results.json
          version-id: ${{ steps.grype-upload.outputs.version-id }}

      # Unified reporting and gating across all scanners
      - uses: finite-state/run-report@v1
        id: report
        with:
          recipe: "Triage Prioritization,Version Comparison"
          period: 30d

      - uses: finite-state/quality-gate@v1
        id: gate
        with:
          mode: triage-priority,delta
          fail-on-p0: true
          max-new-critical: 0

      - uses: finite-state/pr-comment@v1
        if: always()
        with:
          template: triage
          gate-result: ${{ steps.gate.outputs.result }}
```

## Key Points

1. **Disable scanner gating:** Set `fail-build: false` / `exit-code: "0"` / `continue-on-error: true` on the scanner step. Let Finite State's quality gate make the pass/fail decision based on triage prioritization.

2. **Same version for all scanners:** Upload all scan results to the same version using `version-id` from the first upload. This consolidates findings for unified triage.

3. **Scanner type matters:** The `scanner-type` input tells Finite State how to parse the results. Use the correct value: `grype`, `trivy`, `snyk`, etc.

4. **JSON output format:** All scanners must output JSON. Finite State parses the native scanner JSON format.
