# CSV Export with Unique IDs

Exports a Finite State project version's **findings** or **components** to CSV, reproducing the platform's own export column-for-column and adding the row's **unique ID** as the first column.

The platform's built-in CSV exports identify each row only by human-readable values — a CVE ID, a component name. Neither carries the row's unique internal ID, so exported rows can't be joined back to the API for triage automation, ticket linking, or diffing between versions. This script adds it.

For findings that ID is the **finding** ID, which is distinct from `findingId` (the CVE identifier, which repeats across components). For components it is the version-component ID.

## Features

- **Matching columns** — reproduces the platform export layout exactly, with `id` prepended; verified against real platform exports. Note the *row set* is filtered by `--severity` (default high + critical); pass `-s all` for full parity
- **CVSS vector** — adds the `cvssVector` string, which the platform CSV omits
- **Both backends** — handles new (UUID) and legacy (numeric) ID formats, `null` vs object `tracker`, absent `cvssScore`, and empty or differently-cased `severityCounts`
- **Severity filtering** — defaults to high + critical, on either raw CVSS severity or the EPSS-weighted band
- **Resilient** — retries HTTP 429/500/502/503/504 with exponential backoff, honoring `Retry-After` in both its seconds and HTTP-date forms; 300s socket timeout so a stalled connection fails instead of hanging CI; adapts the page size down if a tenant rejects it
- **Excel-clean output** — files are UTF-8 with BOM and CRLF line endings, so they open identically to a platform-downloaded export (`-o -` omits the BOM, since it breaks most parsers when piping)
- **No dependencies** — Python 3 standard library only; a single self-contained file

## Requirements

Python 3.8 or newer. No packages to install.

## Setup

```bash
export FS_TOKEN=<your api token>
export FINITE_STATE_DOMAIN=<tenant>.finitestate.io
```

`FINITE_STATE_AUTH_TOKEN` is also accepted (legacy name). If both are set, `FS_TOKEN` wins.

Both are also accepted as `--token` / `--domain`, which override the env vars — useful for CI systems that inject secrets as arguments. **Prefer the environment variable where you have the choice:** a command-line argument is visible to other users on the host via `ps` and is written to your shell history.

The token is sent as the `X-Authorization` header.

## Usage

```bash
# findings for one version (defaults to high + critical CVEs)
python3 fs_csv_export_with_ids.py findings --project-version-id <id>

# components for one version
python3 fs_csv_export_with_ids.py components --project-version-id <id>

# resolve the version by name instead of ID
python3 fs_csv_export_with_ids.py findings --project "BG Poclain Test" --version older_no_all

# everything, not just high/critical, to stdout
python3 fs_csv_export_with_ids.py findings -i <id> -s all -o -
```

`--project-version-id` and `--project`/`--version` are mutually exclusive. Project and version names match case-insensitively. Every option has a short form.

**Row-count parity:** the default `--severity high,critical` means the CSV contains *fewer rows* than an unfiltered platform download. Columns match; the row set is filtered by design. Pass `-s all` for every finding.

### Common options

| Option | Default | Notes |
|---|---|---|
| `-t`, `--token` | `$FINITE_STATE_AUTH_TOKEN` | Sent as the `X-Authorization` header |
| `-d`, `--domain` | `$FINITE_STATE_DOMAIN` | e.g. `acme.finitestate.io` |
| `-i`, `--project-version-id` | — | Mutually exclusive with `-p`/`-V` |
| `-p`, `--project` | — | Project name, use with `-V` |
| `-V`, `--version` | — | Version name, use with `-p` |
| `-n`, `--page-size` | `5000` | Items per API page (1–10000, the API maximum). Halves automatically if a tenant rejects the size |
| `-r`, `--max-retries` | `6` | Retries per request on 429/500/502/503/504 (0 disables) |
| `-o`, `--output` | `<kind>_<projectVersionId>.csv` | `-` writes to stdout |

### Findings options

| Option | Default | Notes |
|---|---|---|
| `-T`, `--type` | `cve` | Also `sast`, `thirdparty`, `all` |
| `-s`, `--severity` | `high,critical` | Comma-separated; `all` disables filtering |
| `-F`, `--severity-field` | `severity` | `severity` = raw CVSS severity; `weighted` = the EPSS-weighted band shown in the "Severity (Weighted)" column |
| `-N`, `--no-comments` | off | Skips requesting comments (faster) |

The two severity fields differ: a finding can be raw `critical` but weighted `HIGH`. Filter on whichever field your report is judged against.

### Components options

| Option | Default | Notes |
|---|---|---|
| `-x`, `--excluded` | off | Export excluded components instead of included |
| `-e`, `--edit-status` | `any` | `edited` or `unedited` to restrict |
| `-S`, `--sort` | `name:asc` | |

## Output columns

Findings — `id` first, then the platform's own columns:

```
id, CVE ID, Severity (Weighted), policy - violations, policy - warnings,
EPSS-Weighted Score, CVSS Score, CVSS Vector, Component, reachabilityScore,
Detection Date, Issue Tracking, Status, columns.epssWeightedRisk,
columns.epssWeightedSeverity, columns.exploitMaturity, columns.reason,
columns.cveReferences, columns.comments
```

Components:

```
id, Name, Version, policy - violations, policy - warnings, Findings - critical,
Findings - high, Findings - medium, Findings - low, CDX Type, Supplier,
Licenses - names, Licenses - types, releaseDate, Source, Issue Tracking, Status,
Edited, Last Modified At, Last Modified By
```

### Column notes

- **`CVSS Vector`** (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) is an addition — the platform CSV export does not include it. Backends that don't return `cvssVector` leave the column blank.
- **`CVSS Score`** uses the API's own `cvssScore` when present. Older backends omit it; there it falls back to `risk × 0.1`, which reproduces the platform's value exactly (`risk: 98` → `9.8`).
- **`Licenses - types`** is derived from `declaredLicenseDetails[].copyleftFamily` (`COPYLEFT_STRONG` → `Copyleft-Strong`), multiple values joined with `; `.
- **`Issue Tracking`** is blank unless a ticket is actually linked. Legacy backends send a `tracker` object with null ticket fields; that is still blank, matching the platform export.

## Implementation notes

- **CVE selection uses `filter=category==CVE`, not `?type=cve`.** The `type=cve` URL param makes the API silently omit `reachabilityScore` — a column this export reproduces. `fs-report` avoids it for the same reason.
- **Severity filtering is pushed server-side when possible.** With `--severity-field severity` the script probes a `severity=in=(...)` filter and uses it, so a high/critical export doesn't pull the full dataset. If the backend rejects the operator it says so and filters locally, same result.
- **Version names are resolved client-side** over `/projects/{id}/versions`, paged. The version-name filter on the flat `/versions` endpoint is not dependable across backends.
- **Not verified against platform output:** the separator for a multi-valued `Source`, and the rendering for a component with a real linked ticket — neither case appeared in the reference exports available at the time. Both are single-line changes in `join_list` / `render_tracker` if your tenant shows a difference.

## Self-check

Built-in assertions cover CVSS score/vector handling, both backend shapes, and the column mapping:

```bash
python3 fs_csv_export_with_ids.py self-check
```
