# Finite State GitHub Actions

Integrate Finite State's firmware and software security analysis into your GitHub CI/CD pipelines.

## Prerequisites

- A **Finite State account** with API access
- An **API token** generated from the Finite State platform (Settings > API Tokens)
- A **GitHub repository** with Actions enabled
- Your **project ID** from the Finite State platform

## Quick Start

### 1. Add secrets and variables

In your GitHub repository, go to **Settings > Secrets and variables > Actions**:

| Name | Type | Description |
|------|------|-------------|
| `FS_API_TOKEN` | Secret | Your Finite State API token |
| `FS_DOMAIN` | Variable | Your platform domain (e.g., `app.finitestate.io`) |
| `FS_PROJECT_ID` | Variable | Your Finite State project ID |

### 2. Choose a workflow template

Copy one of the starter templates into `.github/workflows/` in your repository:

| Template | Description | Use when... |
|----------|-------------|-------------|
| [upload-and-gate.yml](templates/upload-and-gate.yml) | Upload + report + quality gate + PR comment | You want PR gating on security findings |
| [upload-and-comment.yml](templates/upload-and-comment.yml) | Upload + report + PR comment (no gate) | You want visibility without blocking PRs |
| [full-pipeline.yml](templates/full-pipeline.yml) | Upload + report + gate + comment + SBOM export | You want the complete pipeline |
| [sbom-export.yml](templates/sbom-export.yml) | Upload + SBOM download | You just need the generated SBOM |
| [nightly-report.yml](templates/nightly-report.yml) | Scheduled full portfolio report | You want regular security reports |

### 3. Or use the CLI wizard

```bash
npx finite-state-actions init
```

The wizard asks a few questions and generates a tailored workflow file for your repo.

## Action Reference

Each action has detailed documentation with full inputs/outputs tables:

- [setup](docs/actions/setup.md) — Authenticate and configure context
- [upload-scan](docs/actions/upload-scan.md) — Upload binaries, SBOMs, or third-party scan results
- [run-report](docs/actions/run-report.md) — Run fs-report recipes for findings analysis
- [quality-gate](docs/actions/quality-gate.md) — Pass/fail checks on findings
- [pr-comment](docs/actions/pr-comment.md) — Post findings summaries to pull requests
- [download-sbom](docs/actions/download-sbom.md) — Export FS-generated SBOMs

## Examples

Real-world pipeline examples with detailed annotations:

- [Firmware CI Pipeline](docs/examples/firmware-ci.md) — Binary SCA + reachability analysis in a firmware build
- [SBOM Import](docs/examples/sbom-import.md) — Importing SBOMs from external build systems
- [Third-Party Scanners](docs/examples/third-party-scanners.md) — Integrating Grype, Trivy, and Snyk results
- [Triage Priority Gating](docs/examples/triage-gating.md) — Custom scoring models for risk-based gating

## Custom Scoring

See [scoring/example-scoring.yaml](scoring/example-scoring.yaml) for an annotated example of a triage scoring configuration file.

## Support

- [Finite State Documentation](https://docs.finitestate.io)
- [GitHub Actions Marketplace](https://github.com/marketplace?query=finite-state)
- Contact: support@finitestate.io
