# pr-comment

Posts a findings summary as a PR comment. Updates in place on each push (no comment spam).

## Usage

```yaml
- uses: finite-state/pr-comment@v1
  if: always()
  with:
    template: triage
    gate-result: ${{ steps.gate.outputs.result }}
    gate-summary: ${{ steps.gate.outputs.summary }}
    report-dir: ${{ steps.report.outputs.report-dir }}
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `report-dir` | no | from run-report | Path to fs-report output directory |
| `summary-json` | no | from run-report | Direct JSON from run-report outputs |
| `template` | no | `summary` | Comment template: `summary`, `detailed`, `triage`, `comparison`, `custom` |
| `custom-template` | no | — | Path to a custom Handlebars template file |
| `gate-result` | no | — | Pass/fail result from quality-gate to include |
| `gate-summary` | no | — | Gate evaluation summary text |
| `comment-tag` | no | `finite-state` | Unique tag for edit-in-place behavior |
| `collapse-details` | no | `true` | Wrap detailed findings in `<details>` |

## Outputs

| Output | Description |
|--------|-------------|
| `comment-id` | The PR comment ID |
| `comment-url` | Direct link to the comment |

## Built-in Templates

### `summary`

Compact severity overview with gate status badge and links to full report artifacts. Best for teams that want a quick overview without scrolling.

### `triage`

Triage priority focused. Shows P0/P1/P2/P3 band counts, gate status per band, and lists the top P0/P1 findings. Best when using triage-priority gating.

### `comparison`

Version delta table showing baseline vs current severity counts, lists of new and fixed findings, and component churn summary. Best when using delta gating.

### `detailed`

Full findings table, collapsed in a `<details>` block by default. Shows every finding with severity, component, and status. Best for thorough review workflows.

### `custom`

User-provided Handlebars template with access to all report data. See the [custom template guide](#custom-templates) below.

## Behavior

1. Reads report data from `run-report` outputs (report-dir or summary-json)
2. Renders the selected template with report data + gate results
3. Searches for an existing comment with the `comment-tag` marker
4. Creates or updates the comment (edit-in-place — never creates duplicates)
5. Links to uploaded report artifacts for full details

All templates include a **Reports** section linking to the uploaded workflow artifacts (HTML reports, CSVs, etc.).

## Custom Templates

Create a Handlebars template file and pass it via `custom-template`:

```yaml
- uses: finite-state/pr-comment@v1
  with:
    template: custom
    custom-template: .github/fs-comment-template.hbs
```

Available template variables:

| Variable | Type | Description |
|----------|------|-------------|
| `severityCounts` | object | `{ CRITICAL, HIGH, MEDIUM, LOW, NONE }` |
| `triageBands` | object | `{ P0, P1, P2, P3, topFindings }` |
| `versionDelta` | object | `{ newFindings, fixedFindings, newBySeverity, fixedBySeverity }` |
| `gateResult` | string | `pass` or `fail` |
| `gateSummary` | string | Human-readable gate summary |
| `artifactLinks` | array | `[{ name, url }]` report artifact links |
| `totalFindings` | number | Total finding count |

## Tips

- Always use `if: always()` so the comment is posted even when the gate fails
- Use `comment-tag` to maintain separate comments for different scan types in the same PR
- The comment includes a timestamp showing when it was last updated
