# run-report

Runs [fs-report](https://github.com/FiniteStateInc/fs-report) recipes as a GitHub Action. Installs fs-report, runs the specified recipes, parses outputs, and uploads reports as workflow artifacts.

## Usage

```yaml
- uses: finite-state/run-report@v1
  id: report
  with:
    recipe: "Triage Prioritization,Version Comparison"
    period: 30d
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `recipe` | **yes** | — | Recipe name(s), comma-separated |
| `project-id` | no | from setup | Falls back to setup context |
| `version-id` | no | — | Pin to a specific version |
| `baseline-version` | no | — | Baseline version for Version Comparison |
| `current-version` | no | — | Current version for Version Comparison |
| `period` | no | — | Time period: `7d`, `30d`, `1m`, `3m`, etc. |
| `cve` | no | — | CVE ID(s) for CVE Impact recipe |
| `finding-types` | no | — | Filter: `cve`, `sast`, etc. |
| `open-only` | no | `true` | Only include open (untriaged) findings |
| `scoring-file` | no | — | Path to custom scoring YAML for Triage Prioritization |
| `ai` | no | `false` | Enable AI analysis (requires AI provider key as secret) |
| `ai-prompts` | no | `false` | Generate AI prompts without API key |
| `output-dir` | no | `./fs-reports` | Output directory |
| `fs-report-version` | no | latest | Pin fs-report version |
| `cache-ttl` | no | `1` | API cache TTL in hours (1 hour default for CI) |
| `extra-args` | no | — | Passthrough for additional fs-report flags |

## Outputs

| Output | Description |
|--------|-------------|
| `report-dir` | Path to generated reports directory |
| `artifact-name` | Uploaded workflow artifact name |
| `summary-json` | JSON string with key metrics extracted from reports |
| `critical-count` | Findings in CRITICAL/P0 band (from Triage Prioritization) |
| `high-count` | Findings in HIGH/P1 band |
| `new-findings` | New findings count (from Version Comparison) |
| `fixed-findings` | Fixed findings count (from Version Comparison) |

## Available Recipes

| Recipe | Scope | Key Outputs |
|--------|-------|-------------|
| Executive Summary | Portfolio | HTML overview with severity charts |
| Scan Analysis | Portfolio | Scan throughput, completion rates |
| Triage Prioritization | Project/Folder | Priority-banded findings + `vex_recommendations.json` |
| Version Comparison | Project | Delta findings, component churn |
| Remediation Package | Project | Component-centric action cards with upgrade paths |
| CVE Impact | Portfolio (CVE-scoped) | Per-CVE dossier across all projects |
| Findings by Project | Project/Folder | Full findings inventory |
| Component List | Project/Folder | SBOM component inventory |
| Component Vulnerability Analysis | Project/Folder | Components ranked by composite risk |

## Behavior

1. Installs `fs-report` via `pipx` (cached across workflow runs)
2. Sets `FINITE_STATE_AUTH_TOKEN` and `FINITE_STATE_DOMAIN` from setup context
3. Runs `fs-report run --headless` with the specified recipes and flags
4. Parses output CSV/JSON/MD files to extract key metrics
5. Uploads the full report directory as a workflow artifact
6. For Triage Prioritization: extracts priority band counts (P0/P1/P2/P3)
7. For Version Comparison: extracts delta counts (new/fixed findings)

## Examples

### Triage Prioritization with custom scoring

```yaml
- uses: finite-state/run-report@v1
  id: triage
  with:
    recipe: "Triage Prioritization"
    period: 30d
    scoring-file: .github/fs-scoring.yaml
```

### Version Comparison

```yaml
- uses: finite-state/run-report@v1
  id: comparison
  with:
    recipe: "Version Comparison"
    period: 30d
```

### CVE Impact dossier with AI analysis

```yaml
- uses: finite-state/run-report@v1
  with:
    recipe: "CVE Impact"
    cve: "CVE-2024-3094"
    ai: true
```

### Multiple recipes in one run

```yaml
- uses: finite-state/run-report@v1
  with:
    recipe: "Triage Prioritization,Version Comparison,Remediation Package"
    period: 30d
    ai: true
```
