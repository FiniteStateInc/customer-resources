# Example: Firmware CI Pipeline

A complete firmware build-and-scan pipeline that runs SCA analysis, performs reachability analysis, generates triage-prioritized reports, and gates the PR on exploitable findings.

## When to use this

- You have a firmware build step that produces a binary artifact
- You want both SCA (component identification + CVE matching) and reachability analysis (is the vulnerable code actually called?)
- You want to gate PRs on truly exploitable vulnerabilities, not just severity

## Workflow

```yaml
name: Firmware Security Pipeline

on:
  pull_request:
    branches: [main, release/*]
  push:
    branches: [main]
    tags: ["v*"]

permissions:
  contents: read
  pull-requests: write

jobs:
  build:
    name: Build Firmware
    runs-on: ubuntu-latest
    outputs:
      artifact-name: ${{ steps.build.outputs.artifact-name }}
    steps:
      - uses: actions/checkout@v4

      # Your actual build steps here. This example uses a Makefile.
      - name: Build firmware
        id: build
        run: |
          make firmware
          echo "artifact-name=firmware-${{ github.sha }}" >> "$GITHUB_OUTPUT"

      - uses: actions/upload-artifact@v4
        with:
          name: firmware-${{ github.sha }}
          path: build/firmware.bin

  security:
    name: Security Analysis
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Download the firmware build artifact
      - uses: actions/download-artifact@v4
        with:
          name: ${{ needs.build.outputs.artifact-name }}
          path: build/

      # Authenticate with Finite State
      - uses: finite-state/setup@v1
        with:
          api-token: ${{ secrets.FS_API_TOKEN }}
          domain: ${{ vars.FS_DOMAIN }}
          project-id: ${{ vars.FS_PROJECT_ID }}

      # Upload for SCA analysis (component identification + CVE matching)
      - uses: finite-state/upload-scan@v1
        id: sca
        with:
          type: sca
          file: build/firmware.bin
          version: "pr-${{ github.event.number || github.ref_name }}"

      # Upload for reachability analysis (is the vulnerable code called?)
      # This runs as a second scan on the same version.
      - uses: finite-state/upload-scan@v1
        id: reachability
        with:
          type: vulnerability-analysis
          file: build/firmware.bin
          version-id: ${{ steps.sca.outputs.version-id }}

      # Run triage prioritization — reachability data enriches the scoring
      - uses: finite-state/run-report@v1
        id: report
        with:
          recipe: "Triage Prioritization,Version Comparison,Remediation Package"
          period: 30d

      # Gate on exploitable findings only
      - uses: finite-state/quality-gate@v1
        id: gate
        with:
          mode: triage-priority,delta
          fail-on-p0: true
          fail-on-p1: false  # Allow P1 findings (high but not immediately exploitable)
          max-new-critical: 0
          report-dir: ${{ steps.report.outputs.report-dir }}

      # Post triage summary as PR comment
      - uses: finite-state/pr-comment@v1
        if: github.event_name == 'pull_request' && always()
        with:
          template: triage
          gate-result: ${{ steps.gate.outputs.result }}
          gate-summary: ${{ steps.gate.outputs.summary }}

      # Export SBOM on main/tag pushes (not PRs)
      - uses: finite-state/download-sbom@v1
        if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/')
        with:
          version-id: ${{ steps.sca.outputs.version-id }}
          format: cyclonedx
          include-vex: true
          artifact-name: "sbom-${{ github.ref_name }}"
```

## Key Points

1. **Two scan types on one version:** SCA identifies components and CVEs. Reachability analysis determines which vulnerabilities are actually callable. Both upload to the same version using `version-id` from the first scan.

2. **Triage priority gating:** Instead of failing on any critical CVE, the gate uses the triage scoring model. A critical CVE in an unreachable code path is scored as P2/P3 and won't block the PR.

3. **Separate build and security jobs:** The build job produces the artifact, the security job consumes it. This keeps build logic clean and lets security analysis run in parallel with other CI checks.

4. **Conditional SBOM export:** SBOMs are only exported on main branch pushes and tag pushes, not on every PR.

5. **Version naming:** PRs use `pr-{number}` for easy identification. Main/tag pushes use the ref name (e.g., `main`, `v1.2.3`).
