# quality-gate

Evaluates findings from `run-report` and passes or fails the workflow. Supports three gating modes that can be combined (AND'd together).

## Usage

```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: delta,triage-priority
    max-new-critical: 0
    max-new-high: 0
    fail-on-p0: true
    report-dir: ${{ steps.report.outputs.report-dir }}
```

## Inputs

### Core inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `mode` | **yes** | — | Gating mode(s): `delta`, `threshold`, `triage-priority`, or comma-separated combo |
| `report-dir` | no | from run-report | Path to fs-report output directory |
| `summary-json` | no | from run-report | Direct JSON from run-report outputs |

### Delta mode inputs

Compares findings between previous and current version. Requires Version Comparison recipe output.

| Input | Default | Description |
|-------|---------|-------------|
| `max-new-critical` | `0` | Max allowed new critical findings |
| `max-new-high` | `0` | Max allowed new high findings |
| `max-new-medium` | `-1` (unlimited) | Max allowed new medium findings |

### Threshold mode inputs

Absolute counts against the current version's total findings.

| Input | Default | Description |
|-------|---------|-------------|
| `max-critical` | — | Max total critical findings |
| `max-high` | — | Max total high findings |
| `max-total` | — | Max total findings across all severities |

### Triage priority mode inputs

Uses the triage prioritization scoring model to evaluate findings by actual risk.

| Input | Default | Description |
|-------|---------|-------------|
| `fail-on-p0` | `true` | Fail if any P0 (CRITICAL band) findings |
| `fail-on-p1` | `false` | Fail if any P1 (HIGH band) findings |
| `max-p0` | `0` | Max allowed P0 findings |
| `max-p1` | `-1` (unlimited) | Max allowed P1 findings |
| `ai` | `false` | Enable AI-powered triage analysis |
| `ai-provider` | auto-detected | `anthropic`, `openai`, or `copilot` |

## Outputs

| Output | Description |
|--------|-------------|
| `result` | `pass` or `fail` |
| `summary` | Human-readable summary of gate evaluation |
| `details-json` | Full evaluation details as JSON |

## Behavior

1. Reads structured data from `run-report` outputs
2. Evaluates each active mode independently
3. All modes are AND'd — **all must pass** for the gate to pass
4. Produces a detailed summary of what passed/failed and why
5. Sets exit code: 0 = pass, 1 = fail

## Gating Modes Explained

### Delta mode

Compares the current version's findings against the previous version. Best for catching regressions — "did this PR introduce new vulnerabilities?"

- Requires the `Version Comparison` recipe in the upstream `run-report` step
- Counts new findings by severity and checks against thresholds
- Set `max-new-critical: 0` for zero tolerance on new critical CVEs

### Threshold mode

Absolute limits on total finding counts. Best for establishing a security baseline — "we will not ship with more than N critical findings."

- Works with any recipe that produces severity counts
- Check total counts regardless of when findings were introduced
- Useful for nightly/scheduled workflows to track overall posture

### Triage priority mode

Uses the two-gate DSL + additive scoring model from Triage Prioritization. Evaluates findings by **actual exploitability risk**, not just CVSS severity.

**Default scoring model:**
- **P0 (CRITICAL):** Reachable AND (has known exploit OR in CISA KEV)
- **P1 (HIGH):** Reachable AND network attack vector AND EPSS > 90th percentile
- **P2/P3:** Remaining findings scored additively and banded

Custom scoring weights can be provided via a `scoring-file` in the upstream `run-report` step.

## Examples

### Delta only — block new critical/high findings

```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: delta
    max-new-critical: 0
    max-new-high: 0
    max-new-medium: 5
```

### Combined delta + triage priority

```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: delta,triage-priority
    max-new-critical: 0
    fail-on-p0: true
    fail-on-p1: true
    max-p1: 3
```

### Threshold — absolute limits for nightly gate

```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: threshold
    max-critical: 0
    max-high: 10
    max-total: 200
```

### All three modes combined

```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: delta,threshold,triage-priority
    max-new-critical: 0
    max-new-high: 0
    max-critical: 5
    max-high: 20
    fail-on-p0: true
```
