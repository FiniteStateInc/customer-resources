# Example: Triage Priority Gating with Custom Scoring

Use the triage prioritization scoring model to gate PRs on actual exploitability risk, not just CVSS severity. Optionally customize the scoring weights to match your threat model.

## When to use this

- You want to reduce false-positive gate failures from unexploitable CVEs
- You care about reachability, exploit availability, and EPSS more than raw severity
- You have a custom risk model or threat profile to enforce
- You want to gradually tighten your security gate over time

## Basic Triage Priority Gate

The simplest form: fail on any P0 (immediately exploitable) findings.

```yaml
name: Triage Priority Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: finite-state/setup@v1
        with:
          api-token: ${{ secrets.FS_API_TOKEN }}
          domain: ${{ vars.FS_DOMAIN }}
          project-id: ${{ vars.FS_PROJECT_ID }}

      - uses: finite-state/upload-scan@v1
        with:
          type: sca
          file: build/firmware.bin
          version: "pr-${{ github.event.number }}"

      # Run triage prioritization with default scoring
      - uses: finite-state/run-report@v1
        id: report
        with:
          recipe: "Triage Prioritization"
          period: 30d

      # Gate on P0 findings only
      - uses: finite-state/quality-gate@v1
        id: gate
        with:
          mode: triage-priority
          fail-on-p0: true
          fail-on-p1: false  # Allow P1 for now

      - uses: finite-state/pr-comment@v1
        if: always()
        with:
          template: triage
          gate-result: ${{ steps.gate.outputs.result }}
```

## Default Scoring Model

The default two-gate model classifies findings into priority bands:

| Band | Classification | Criteria |
|------|---------------|----------|
| **P0** (CRITICAL) | Immediately exploitable | Reachable AND (known exploit OR in CISA KEV) |
| **P1** (HIGH) | Likely exploitable | Reachable AND network attack vector AND EPSS > 90th percentile |
| **P2** (MEDIUM) | Moderate risk | Additive score above medium threshold |
| **P3** (LOW/INFO) | Low risk | Remaining findings |

## Custom Scoring Configuration

Create a scoring YAML file to customize the model. Store it in your repo (e.g., `.github/fs-scoring.yaml`).

```yaml
# .github/fs-scoring.yaml
#
# Custom triage scoring configuration for Finite State.
# See scoring/example-scoring.yaml for a fully annotated example.

# Gate 1: P0 (CRITICAL) — must match ALL conditions
gate_1:
  label: "P0 - Immediately Exploitable"
  conditions:
    - field: reachability_score
      operator: ">"
      value: 0
    - field: has_exploit
      operator: "=="
      value: true

# Gate 2: P1 (HIGH) — must match ALL conditions
gate_2:
  label: "P1 - Likely Exploitable"
  conditions:
    - field: reachability_score
      operator: ">="
      value: 0
    - field: attack_vector
      operator: "in"
      value: ["NETWORK"]
    - field: epss_percentile
      operator: ">"
      value: 0.85  # More aggressive than default 0.9

# Additive scoring for P2/P3 banding
additive_weights:
  cvss_base_score:
    weight: 0.3
    normalize: 10
  epss_percentile:
    weight: 0.25
  reachability_score:
    weight: 0.25
    normalize: 100
  exploit_maturity:
    weight: 0.2
    mapping:
      HIGH: 1.0
      FUNCTIONAL: 0.8
      POC: 0.5
      UNPROVEN: 0.1
      NONE: 0.0

# Band thresholds (0.0 - 1.0 composite score)
bands:
  P2_threshold: 0.5   # Score >= 0.5 after gates = P2
  P3_threshold: 0.0   # Everything else = P3
```

Reference it in your workflow:

```yaml
- uses: finite-state/run-report@v1
  id: report
  with:
    recipe: "Triage Prioritization"
    period: 30d
    scoring-file: .github/fs-scoring.yaml

- uses: finite-state/quality-gate@v1
  with:
    mode: triage-priority
    fail-on-p0: true
    fail-on-p1: true
    max-p1: 3  # Allow up to 3 P1 findings
```

## Gradual Tightening Strategy

Start permissive and tighten over time as you remediate:

**Phase 1: Visibility only (no gate)**
```yaml
# Just report, no gate
- uses: finite-state/run-report@v1
  with:
    recipe: "Triage Prioritization"
- uses: finite-state/pr-comment@v1
  with:
    template: triage
```

**Phase 2: Gate on P0 only**
```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: triage-priority
    fail-on-p0: true
    fail-on-p1: false
```

**Phase 3: Gate on P0 + P1**
```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: triage-priority
    fail-on-p0: true
    fail-on-p1: true
    max-p1: 5  # Allow some P1 during transition
```

**Phase 4: Strict gating**
```yaml
- uses: finite-state/quality-gate@v1
  with:
    mode: triage-priority,delta
    fail-on-p0: true
    fail-on-p1: true
    max-p1: 0
    max-new-critical: 0
    max-new-high: 0
```

## AI-Enhanced Triage

When an AI provider key is configured, triage analysis can use AI for more nuanced priority assignments:

```yaml
- uses: finite-state/run-report@v1
  with:
    recipe: "Triage Prioritization"
    ai: true

- uses: finite-state/quality-gate@v1
  with:
    mode: triage-priority
    ai: true
    fail-on-p0: true
```

## Key Points

1. **Scoring is deterministic:** The two-gate DSL + additive scoring produces consistent results. Same inputs always produce the same bands.

2. **Reachability is key:** P0 and P1 both require reachability. Without reachability data (i.e., only SCA scan, no vulnerability-analysis scan), findings cannot reach P0/P1 through the default gates.

3. **Custom scoring is optional:** The default model works well for most firmware/embedded use cases. Customize only if you have specific threat model requirements.

4. **Scoring works with Forge too:** The same `scoring.yaml` file is used by Forge's `run_triage_pipeline`. Tune interactively in Forge, commit the file, and CI enforces it.
