# Configuration Examples

Annotated configuration templates for fs-report — copy and adapt them for your own runs.

> Sample **output reports** are not bundled in this release. Generate your own from
> your Finite State instance using the commands in the [main README](../README.md)
> and [REPORT_GUIDE](../REPORT_GUIDE.md).

## Deployment Context (`deployment-context.yaml`)

An annotated YAML file showing all available deployment-context fields. Use it to
tailor AI-powered remediation guidance to your product's environment:

```bash
fs-report run --recipe "Triage Prioritization" --ai \
  --context-file examples/deployment-context.yaml --period 30d
```

Fields: `product_type`, `network_exposure`, `regulatory`, `deployment_notes` — all
optional, with sensible defaults.

## Scoring File (`scoring-file.yaml`)

An annotated YAML file showing custom scoring weights, gate definitions, and
staleness thresholds for the triage and scan-quality recipes. Use it to tune how
findings are prioritized:

```bash
fs-report run --recipe "Triage Prioritization" \
  --scoring-file examples/scoring-file.yaml --period 30d
```

This file is optional — default weights and thresholds are used when no scoring
file is provided.
