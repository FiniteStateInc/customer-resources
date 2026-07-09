# fs-cli User Guide

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Configuration](#configuration)
- [Commands](#commands)
  - [scan](#scan)
  - [upload](#upload)
  - [import](#import)
  - [third-party](#third-party)
  - [deliver](#deliver)
  - [query](#query)
  - [update](#update)
  - [version](#version)
- [Global Flags](#global-flags)
- [Supported Ecosystems](#supported-ecosystems)
- [Output Adapters](#output-adapters)
- [CI/CD Integration](#cicd-integration)
- [Migrating from the Java CLI](#migrating-from-the-java-cli)
- [Troubleshooting](#troubleshooting)

---

## Overview

fs-cli is a software composition analysis tool that scans project dependencies and uploads SBOM-grade package inventories to the Finite State platform. It ships as a single binary with no runtime dependencies and supports 19 package ecosystems with transitive dependency resolution.

---

## Installation

### Automated install

**macOS / Linux:**

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
```

Custom install directory:

```sh
curl -fsSL .../install.sh | INSTALL_DIR=/opt/tools sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.ps1 | iex
```

Custom install directory:

```powershell
$env:INSTALL_DIR = "C:\tools"; irm .../install.ps1 | iex
```

The installer:
- Detects your OS (Linux, macOS, Windows) and architecture (x86_64, ARM64)
- Downloads the correct binary
- Verifies its SHA-256 checksum
- Installs to `/usr/local/bin` (or `~/.local/bin`) on Unix, `%LOCALAPPDATA%\fs-cli` on Windows

### Manual install

Download the binary for your platform, verify the checksum, and place it on your PATH:

```sh
# Example for Linux x86_64
curl -fsSL -o fs-cli https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/latest/fs-cli-linux-amd64
chmod +x fs-cli
sudo mv fs-cli /usr/local/bin/
```

### Self-update

fs-cli keeps itself up to date automatically. Before a work command runs (`scan`, `upload`, `import`, `third-party`, `deliver`), it asks the Finite State platform whether a newer release is available for your OS and architecture. If so, it downloads the release, verifies its SHA-256 checksum and Ed25519 signature, replaces itself in place, and restarts to run your command on the new version.

This is also how fs-cli upgrades itself to the next-generation Finite State CLI (v2.3.x): once your platform is upgraded, the first run updates the binary in place — same `fs-cli` name, compatible commands and flags. If your platform has not been upgraded yet, the update check logs an informational "auto-update service is temporarily unavailable" message and the command continues normally.

The update check uses your configured endpoint and token, so it only runs when credentials are available. To check for an update manually:

```sh
fs-cli update
```

To disable automatic updates, set `FS_SKIP_UPDATE=1` (or `FS_NO_UPDATE_CHECK=1`) or pass `--no-update-check`.

---

## Configuration

Configuration is resolved in this order (highest precedence first):

1. **CLI flags** (`--token`, `--endpoint`, etc.)
2. **Environment variables** (`FS_TOKEN`, `FS_ENDPOINT`, etc.)
3. **Credential file** (`~/.finitestate/credential`)
4. **Built-in defaults**

### Environment Variables

| Variable | Alias | Description |
|---|---|---|
| `FS_TOKEN` | `FINITE_STATE_AUTH_TOKEN` | API authentication token |
| `FS_ENDPOINT` | `FINITE_STATE_DOMAIN` | API endpoint domain |
| `FS_PROJECT_NAME` | | Default project name |
| `FS_BRANCH` | | Git branch override |
| `FS_FOLDER` | | Folder name for project scoping (resolved to UUID) |
| `FS_FOLDER_ID` | | Folder UUID for project scoping |
| `FS_CREATE_FOLDER` | | Set to `true` to find-or-create `FS_FOLDER` if it doesn't exist |
| `FS_PARENT_FOLDER` | | Parent folder name when creating (defaults to root) |
| `FS_PARENT_FOLDER_ID` | | Parent folder UUID when creating (defaults to root) |
| `FS_PROJECT_ID` | | Project UUID (skips project find/create) |
| `FS_VERSION_ID` | | Version UUID (skips version creation) |
| `FS_RELEASE` | | Enable release mode (equivalent to `--release`) |
| `FS_RELEASE_SYNCHRONOUS` | | Enable synchronous release mode (equivalent to `--release-synchronous`; implies release mode) |
| `FS_DEBUG` | | Enable debug logging |
| `FS_NO_UPDATE_CHECK` | | Set to `1` to disable the automatic update check |
| `FS_SKIP_UPDATE` | | Set to `1` to disable the automatic update check (alias) |
| `FS_ALLOW_INSECURE_HTTP` | | Set to `1` to permit a plain-HTTP endpoint for the update check (not recommended) |

When both a primary variable and its alias are set, the primary (`FS_*`) takes precedence.

### Credential File

Create `~/.finitestate/credential`:

```
endpoint=app.finitestate.io
token=your-api-token
```

- One key=value pair per line
- Lines starting with `#` are comments
- Blank lines are ignored
- The keys `finite_state_domain` and `finite_state_auth_token` are also accepted for backward compatibility with the Java CLI

### Endpoint Normalization

Bare domain names are automatically prefixed with `https://` and trailing slashes are stripped. All of these are equivalent:

```
app.finitestate.io
https://app.finitestate.io
https://app.finitestate.io/
```

---

## Commands

### scan

Scan a directory for package dependencies.

```
fs-cli scan [directory] [flags]
```

If no directory is given, scans the current directory. You can also point at a specific manifest file (e.g., `fs-cli scan path/to/pom.xml --name myproject`).

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--name` / `--project` | (required) | Project name |
| `--branch` | (auto-detect) | Git branch |
| `--version` | | Version string |
| `--all`, `--deep` | | Recursive monorepo scan — find all ecosystems in subdirectories |
| `--scope` | `runtime` | Dependency scope: `runtime` excludes dev/test deps, `all` includes everything |
| `--output` | `platform` | Output adapter: `platform`, `legacy`, `helix`, `file` |
| `--output-file` | | Output file path (required when `--output=file`) |
| `--sign-key` | | PEM-encoded Ed25519 private key for signing file output |
| `--strict` | | Fail immediately on any scanner error instead of continuing |
| `--tool-options` | | Pass-through options for build tools (Maven, Gradle, etc.) |
| `--include-only` | | Gradle subproject include filter |
| `--exclude` | | Gradle subproject exclusion filter |
| `--configuration` | | Gradle configuration name |
| `--pip-file` | | Custom path to requirements.txt |
| `--timeout` | `30` | Overall timeout in minutes |
| `--scan-timeout` | `5` | Per-ecosystem scan timeout in minutes |
| `--test` | | Dry run: print JSON to stdout, do not upload |
| `--release` | | Release mode (fast, default): renames happen before upload; CLI exits as soon as upload completes (requires `--version`, mutually exclusive with `--test` and `--version-id`) |
| `--release-synchronous` | | Release mode variant that waits for scan completion and auto-rolls back on scan failure (implies `--release`) |
| `--concurrency` | CPU count | Maximum number of parallel ecosystem scans |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |
| `--folder` | | Folder name — scope project find/create to this folder (supports globs) |
| `--folder-id` | | Folder UUID — scope project find/create to this folder |
| `--create-folder` | | Find-or-create `--folder` if it doesn't exist |
| `--parent-folder` | | Parent folder name when creating (defaults to root) |
| `--parent-folder-id` | | Parent folder UUID when creating (defaults to root) |
| `--project-id` | | Project UUID — skip project find/create, use this ID directly |
| `--version-id` | | Version UUID — skip version creation, upload to this version directly |

#### Git Auto-Detection

When run inside a Git repository, fs-cli automatically detects:
- Branch name (from `HEAD`)
- Commit hash
- Remote URL

These can be overridden with `--branch` and `--version`.

#### Examples

```sh
# Basic scan
fs-cli scan --name myproject .

# Dry run (no upload)
fs-cli scan --name myproject --test .

# Recursive monorepo scan
fs-cli scan --name myproject --all .

# Include all dependency scopes
fs-cli scan --name myproject --scope all .

# Write results to a file instead of uploading
fs-cli scan --name myproject --output file --output-file results.json .

# Scan a specific manifest file
fs-cli scan --name myproject path/to/pom.xml

# Gradle-specific options
fs-cli scan --name myproject --configuration runtimeClasspath --exclude ":docs" .

# Pass options through to the build tool
fs-cli scan --name myproject --tool-options="-s settings.xml" .

# Release scan — clean snapshot, previous state archived as checkpoint
fs-cli scan --name myproject --version v2.1.0 --release .
```

#### Release Mode

`--release` creates a clean version snapshot at release time, preventing component accumulation from repeated scans to the same version name.

Two modes are available. Both perform the same rename-before-upload swap; they differ only in whether the CLI waits for the backend scan afterwards.

- **Fast (default, `--release`)** — CLI exits as soon as the upload finishes. Best for CI/CD because the job is not held up by backend scan queue time.
- **Synchronous (`--release-synchronous`)** — CLI additionally polls until the scan reaches a terminal state and automatically rolls back on scan failure. `--release-synchronous` implies `--release`; passing only the synchronous flag is sufficient.

**Shared flow — when the version already exists (both modes):**

1. Finds the existing version by name.
2. Renames it to a checkpoint: `{version}-checkpoint-{YYYY-MM-DD}` (auto-increments on conflict, e.g. `-checkpoint-2026-03-12.1`).
3. Creates a fresh version with the target name and uploads to it.

If the new version creation or upload fails, both modes automatically roll back: delete the new (empty) version and rename the checkpoint back to the original name.

**Fast mode ends here** — the CLI exits. The scan runs asynchronously on the platform. See "Recovering from a failed scan under fast mode" below.

**Synchronous mode adds:**

4. Polls until the platform scan completes (up to 30 minutes or `--timeout`, whichever is smaller).
5. If the scan fails or the poll times out, rolls back automatically: deletes the new version and renames the checkpoint back to the original name.

Because the rename happens before the upload, the version named `{version}` temporarily points at the new, still-scanning build during steps 3–4 of synchronous mode. If scan succeeds the state is final; if it fails the rollback restores the previous known-good version under its original name. Callers who need the previous-known-good name to remain stable for the duration of the scan should not use release mode at all — create a separate version instead.

**When the version does not exist** (including brand-new projects): in both modes the version is created normally and the upload proceeds directly, so release mode is safe for first runs. Synchronous mode still polls the scan on first-time releases and surfaces scan failure as a non-zero exit so CI can fail the job. Because there is no prior version to restore to, a failed first-time scan leaves the failed/partial version on the platform — the operator can delete it manually (or let the next successful run replace it, which will then create a checkpoint from the failed one).

**Constraints:** `--release` requires `--version` and is mutually exclusive with `--test` and `--version-id`. `--release-synchronous` has the same constraints and auto-enables `--release`. Set via `FS_RELEASE` / `FS_RELEASE_SYNCHRONOUS` env vars as an alternative to the flags.

##### Recovering from a failed scan under fast mode

Under fast mode, if the scan fails **after** the CLI has already swapped names, the platform ends up with:

- an empty/failed version as the current `{version}`
- the previous known-good content as `{version}-checkpoint-{YYYY-MM-DD}`

Recovery is a manual operation in the platform UI: rename the current (failed) version to a different name (or delete it), then rename the checkpoint back to the original version name.

Re-running with `--release-synchronous` does **not** fix this — it would just layer another checkpoint on top of the already-swapped state. If you cannot tolerate this recovery path, use `--release-synchronous` from the start.

#### Auto-creating a folder

If the destination folder may not exist yet, pass `--create-folder` to have fs-cli create it in the same invocation. The new folder is placed under `--parent-folder` (name) or `--parent-folder-id` (UUID); when neither is set, it is created under the root folder. `--parent-folder` uses the same lookup as `--folder` and supports the same glob patterns (`*`, `?`, `[...]`); use `--parent-folder-id` instead if the parent name contains glob metacharacters.

```sh
fs-cli scan --name my-app \
            --folder "Edge Gateway Team" \
            --create-folder \
            --parent-folder "Embedded Platforms" \
            .
```

The operation is idempotent: if a folder with that name already exists under the given parent, it is reused silently. These flags are available on all five subcommands that accept `--folder` (`scan`, `upload`, `import`, `third-party`, `deliver`). The environment variables `FS_CREATE_FOLDER`, `FS_PARENT_FOLDER`, and `FS_PARENT_FOLDER_ID` set the same values.

`--create-folder` is silently skipped (with a warning logged) when there is nothing to create — when no `--folder` is given, or when `--folder-id` already names a folder. `--parent-folder` / `--parent-folder-id` are likewise skipped (with a warning) when `--create-folder` is not set. The warnings make these misconfigurations visible in CI logs without aborting the run.

---

### upload

Upload a binary artifact for analysis.

```
fs-cli upload <file> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--name` / `--project` | (required) | Project name |
| `--version` | today's date | Version string |
| `--release` | | Release mode (fast, default): renames happen before upload; CLI exits as soon as upload completes (requires `--version`, mutually exclusive with `--version-id`) |
| `--release-synchronous` | | Release mode variant that waits for scan completion and auto-rolls back on scan failure (implies `--release`) |
| `--type` | `sca` | Scan types, comma-separated: `sca`, `sast`, `config`, `vulnerability_analysis`, `python` |
| `--timeout` | `30` | Overall timeout in minutes |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |
| `--folder` | | Folder name — scope project find/create to this folder (supports globs) |
| `--folder-id` | | Folder UUID — scope project find/create to this folder |
| `--create-folder` | | Find-or-create `--folder` if it doesn't exist |
| `--parent-folder` | | Parent folder name when creating (defaults to root) |
| `--parent-folder-id` | | Parent folder UUID when creating (defaults to root) |
| `--project-id` | | Project UUID — skip project find/create, use this ID directly |
| `--version-id` | | Version UUID — skip version creation, upload to this version directly |

#### Examples

```sh
# Upload a firmware image
fs-cli upload firmware.bin --name my-device

# Upload with multiple scan types
fs-cli upload app.bin --name myapp --type sca,sast

# Upload Python source for Bandit security scanning
fs-cli upload myapp.tar.gz --name myapp --type python

# Upload with explicit version
fs-cli upload release.bin --name myapp --version 2.1.0
```

> **Scan type notes:** The `python` type runs a [Bandit](https://bandit.readthedocs.io/en/latest/) security scan on the uploaded Python source code.

---

### import

Import an existing SBOM file (CycloneDX or SPDX) to the platform.

```
fs-cli import <sbom-file> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--name` / `--project` | (required) | Project name |
| `--version` | (auto-generated) | Version string |
| `--release` | | Release mode (fast, default): renames happen before upload; CLI exits as soon as upload completes (requires `--version`, mutually exclusive with `--version-id`) |
| `--release-synchronous` | | Release mode variant that waits for scan completion and auto-rolls back on scan failure (implies `--release`) |
| `--format` | (auto-detect) | SBOM format: `cyclonedx`, `cdx`, or `spdx` |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |
| `--folder` | | Folder name — scope project find/create to this folder (supports globs) |
| `--folder-id` | | Folder UUID — scope project find/create to this folder |
| `--create-folder` | | Find-or-create `--folder` if it doesn't exist |
| `--parent-folder` | | Parent folder name when creating (defaults to root) |
| `--parent-folder-id` | | Parent folder UUID when creating (defaults to root) |
| `--project-id` | | Project UUID — skip project find/create, use this ID directly |
| `--version-id` | | Version UUID — skip version creation, upload to this version directly |

The format is auto-detected from file contents if not specified. CycloneDX files are identified by the presence of `"bomFormat"` and SPDX files by `"spdxVersion"`.

#### Examples

```sh
# Import a CycloneDX SBOM (auto-detected)
fs-cli import sbom.cdx.json --name myproject

# Import an SPDX SBOM with explicit format
fs-cli import sbom.spdx.json --name myproject --format spdx
```

---

### third-party

Upload results from a third-party analysis tool.

```
fs-cli third-party <file> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--name` / `--project` | (required) | Project name |
| `--type` | (required) | Third-party tool type (e.g., `snyk`, `coverity`, `checkmarx`) |
| `--version` | (auto-generated) | Version string |
| `--timeout` | `30` | Overall timeout in minutes |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |
| `--folder` | | Folder name — scope project find/create to this folder (supports globs) |
| `--folder-id` | | Folder UUID — scope project find/create to this folder |
| `--create-folder` | | Find-or-create `--folder` if it doesn't exist |
| `--parent-folder` | | Parent folder name when creating (defaults to root) |
| `--parent-folder-id` | | Parent folder UUID when creating (defaults to root) |
| `--project-id` | | Project UUID — skip project find/create, use this ID directly |
| `--version-id` | | Version UUID — skip version creation, upload to this version directly |

#### Examples

```sh
# Upload Snyk results
fs-cli third-party snyk-results.json --name myproject --type snyk

# Upload Coverity results
fs-cli third-party coverity-report.json --name myproject --type coverity
```

---

### deliver

Deliver a previously saved scan output file to the Finite State platform. This is the final step in the airgap workflow — scan on a disconnected system, shuttle the file, then deliver from a connected system.

```
fs-cli deliver <file> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |
| `--verify-key` | | PEM-encoded Ed25519 public key for signature verification |
| `--folder` | | Folder name — scope project find/create to this folder (supports globs) |
| `--folder-id` | | Folder UUID — scope project find/create to this folder |
| `--create-folder` | | Find-or-create `--folder` if it doesn't exist |
| `--parent-folder` | | Parent folder name when creating (defaults to root) |
| `--parent-folder-id` | | Parent folder UUID when creating (defaults to root) |
| `--project-id` | | Project UUID — skip project find/create, use this ID directly |
| `--version-id` | | Version UUID — skip version creation, upload to this version directly |
| `--timeout` | `5` | Timeout in minutes |

If the file is a signed envelope (created with `--sign-key` during scan), the signature is automatically verified before delivery. Use `--verify-key` to require that the envelope was signed with a specific key.

#### Examples

```sh
# Deliver an unsigned scan file
fs-cli deliver scan.json --endpoint app.finitestate.io --token $FS_TOKEN

# Deliver a signed scan file (signature verified automatically)
fs-cli deliver scan-signed.json --endpoint app.finitestate.io --token $FS_TOKEN

# Deliver with explicit key verification
fs-cli deliver scan-signed.json --verify-key public.pem --endpoint app.finitestate.io --token $FS_TOKEN
```

#### Airgap Workflow

For environments without network access, use the file adapter with optional signing to produce a portable scan file, then deliver it from a connected system:

```sh
# 1. On the airgapped system: scan and write to file
fs-cli scan --name myproject --output file --output-file scan.json .

# 2. (Optional) Sign the output for tamper detection
fs-cli scan --name myproject --output file --output-file scan.json --sign-key private.pem .

# 3. Shuttle scan.json to a connected system (USB drive, approved transfer, etc.)

# 4. On the connected system: deliver to the platform
fs-cli deliver scan.json --endpoint app.finitestate.io --token $FS_TOKEN

# 4b. (Optional) Verify the signature matches a known public key
fs-cli deliver scan.json --verify-key public.pem --endpoint app.finitestate.io --token $FS_TOKEN
```

---

### query

Read-only query of the platform, built for CI/build-pipeline gating: run a scan, then query the result and let the **process exit code fail the build**. There are two modes, selected by `--type`:

- `--type scan` — report scan completion across all scan types for a project version.
- `--type project` — fail if any finding matches all of a set of AND-combined conditions (severity + exploitability).

The project version is resolved from `--name` + `--version`. `--version` is matched against the platform's `name` **or** `version` field — a version's display string can live in either — so `query` resolves the same versions that `scan` / `upload` do. Pass `--project-id` and/or `--version-id` to skip the name lookups, and `--folder` / `--folder-id` to disambiguate a project name that repeats across folders.

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--type` | (required) | `scan` or `project`. |
| `--name` / `--project` | | Project name (resolved to an ID). |
| `--version` | | Version string (matches the platform's `name` *or* `version` field). Required unless `--version-id` is given. |
| `--project-id` | | Project UUID (skips `--name` lookup). |
| `--version-id` | | Project-version UUID (skips all lookups). |
| `--folder` / `--folder-id` | | Scope the project-name lookup. |
| `--format` | `table` | `table` or `json`. |
| `--timeout` | `10` | Timeout (minutes) for version resolution and the status/findings read. The `--wait` poll is bounded separately by `--poll-timeout`, not this. |
| `--wait` *(scan)* | `false` | Poll until every scan for the version has settled (all scan types completed or failed). |
| `--poll-timeout` *(scan)* | `30` | Max minutes to wait when `--wait` is set. |
| `--fail-on-scan-incomplete` *(scan)* | `false` | Exit non-zero if any scan for the version is still running (or no scans found). |
| `--finding-scope` *(project)* | `cve` | Categories to fetch & evaluate (limits API calls): comma-separated `cve` \| `bsast` \| `config` \| `all`. |
| `--fail-on-severity` *(project)* | | Gate condition: finding severity is **at this level or higher** (`critical` \| `high` \| `medium` \| `low`). E.g. `medium` gates on medium, high, and critical; `critical` gates on critical only. |
| `--vulns-in-kev` *(project)* | `false` | Gate condition: finding is in the **CISA KEV** catalog. |
| `--vulns-in-vc-kev` *(project)* | `false` | Gate condition: finding is in **VulnCheck KEV**. |
| `--reachable` *(project)* | `false` | Gate condition: finding's vulnerable code is reachable. |
| `--exploit-maturity` *(project)* | | Gate condition: finding's CVSS exploit maturity is **≥** this level: `attacked` \| `proof-of-concept` \| `unreported` \| `not-defined`. Aliases: `none` = `not-defined`, `poc` = `proof-of-concept`. |
| `--max-epss` *(project)* | | Gate condition: finding's EPSS score (0–100 integer) **exceeds** this threshold. |

#### The gate: per-finding AND

The project gate conditions are **AND-combined per finding**: the run fails (exit non-zero) if **at least one finding satisfies every configured condition**. With no conditions set, it just prints the findings-by-severity counts and exits zero.

This is a per-finding match, not independent checks. `--fail-on-severity critical --reachable` fails only on a finding that is **both** critical **and** reachable — *not* on all criticals plus all reachables. If the criticals and the reachable findings are different findings, the gate **passes**.

`--fail-on-severity` names the **lowest severity that gates** and expands to that level plus every level more severe. So `--fail-on-severity critical` gates on critical only, `--fail-on-severity high` gates on high and critical, `--fail-on-severity medium` gates on medium, high, and critical, and `--fail-on-severity low` gates on everything. The gated severities form a **set**; a finding matches if its severity is any of them, and that set is then AND-ed with the other conditions. Example: `--fail-on-severity high --vulns-in-kev --reachable` = "a high-or-critical finding that is in CISA KEV **and** reachable."

Condition details:

- `--exploit-maturity` uses the official CVSS (FIRST) Exploit Code Maturity levels, ranked highest-threat first `attacked > proof-of-concept > unreported > not-defined`; a finding matches when its derived level is **at or above** the chosen level. Each finding's level is derived from the platform's exploit data:

  | Derived level | When the finding has… |
  |---|---|
  | **attacked** | is in CISA KEV, or is weaponized / used by botnets, commercial kits, threat actors, or ransomware |
  | **proof-of-concept** | has public proof-of-concept exploit code |
  | **not-defined** | no exploit signal |

  The platform emits no distinct "unreported" signal, so `unreported` and `proof-of-concept` behave the same (both catch PoC-or-worse), and `not-defined` matches any CVE finding. The two practically useful values are **`proof-of-concept`** and **`attacked`**.

- `--max-epss` gates on the **EPSS** (Exploit Prediction Scoring System) score — the estimated probability a CVE will be exploited in the wild. Pass a whole-number threshold from 0 to 100; a finding matches when its score **exceeds** it (a score equal to the threshold does not match). So `--max-epss 90` matches CVEs scoring above 90%, and `--max-epss 0` matches any CVE with a nonzero score.

- `--reachable` matches a finding whose vulnerable code is **reachable** — i.e. the platform's reachability analysis produced a positive reachability score. Findings not analyzed or determined not reachable do not match.

The severity conditions apply to **all** findings (CVE and non-CVE). The exploitability conditions (`--vulns-in-*`, `--exploit-maturity`, `--max-epss`, `--reachable`) key off fields (KEV membership, exploit maturity, EPSS, reachability) that the platform populates from its CVE/SCA pipeline, so in practice they match only CVE findings — AND-ing one of them effectively restricts the gate to CVEs even under a wider `--finding-scope`. (The match is field-based, not category-enforced: a non-CVE finding that somehow carried one of these fields would match it.)

**Scope (`--finding-scope`).** This limits which finding categories are fetched from the API and evaluated, primarily as a performance knob. It defaults to `cve` and is comma-combinable:

| Scope | Categories |
|---|---|
| `cve` | CVE / SCA vulnerabilities (includes third-party / SBOM-imported CVEs) |
| `bsast` | Binary SAST findings |
| `config` | configuration issues, credentials, and crypto-material findings |
| `all` | every category |

The gate (and the severity breakdown) only consider findings within the chosen scope. So with the default `cve`, `--fail-on-severity critical` matches critical **CVE** findings only; to also gate on Binary SAST or config-type findings, widen the scope, e.g. `--finding-scope cve,bsast` or `--finding-scope all`. (Third-party findings are SBOM/tool-imported CVEs and are already included in `cve` — they are distinguished by source, not category, so there is no separate scope for them.)

When a gate is active, the "Findings by severity" breakdown is computed from the same per-finding list the gate evaluates, so the counts agree with the gate's match counts. This counts finding *instances* (the same CVE on multiple components counts once per component) and can therefore differ from the platform's deduplicated severity totals. A plain `--type project` with no conditions uses the platform's aggregate counts endpoint instead.

**No-scans check (always on).** Before fetching any findings, a `--type project` query verifies the version has at least one terminally-successful (`COMPLETED`/`NOT_APPLICABLE`) scan and **fails fast if not** — unconditionally, with no flag. A version that was never successfully scanned has an empty/stale findings list, so a gate against it would pass vacuously (a silent false-green); failing instead makes that impossible. This check runs ahead of, and independently of, the per-finding gate.

#### Exit codes

- `--type scan`: rolls up every scan type the version ran (SCA, CONFIG, binary SAST, vulnerability/reachability analysis, …). Exits non-zero when any scan failed, and — with `--fail-on-scan-incomplete` — when any scan is still running (or no scans exist). A version is "complete" only when every scan type has settled, so a finished SCA scan can't mask a still-running reachability or binary-SAST scan. Under `--wait`, a version with no scans at all returns promptly (after a brief grace to absorb the lag right after a scan is kicked off) rather than polling to `--poll-timeout`.
- `--type project`: exits non-zero when the version has no terminally-successful scan (checked first, always), or when at least one finding matches **all** configured gate conditions. With no conditions set — and a successfully-scanned version — it prints the counts and exits zero.

#### Examples

```sh
# Snapshot the version's scan completion (all scan types)
fs-cli query --type scan --name myapp --version v1.2.3

# Block until every scan finishes (fails the build if any scan errored)
fs-cli query --type scan --name myapp --version v1.2.3 --wait

# Fail on any critical finding
fs-cli query --type project --name myapp --version v1.2.3 --fail-on-severity critical

# Fail only on a critical that is reachable AND in CISA KEV
fs-cli query --type project --name myapp --version v1.2.3 --fail-on-severity critical --reachable --vulns-in-kev

# Fail on a high-or-critical CVE that is actively exploited (attacked maturity)
fs-cli query --type project --name myapp --version v1.2.3 --fail-on-severity high --exploit-maturity attacked

# Fail on any critical CVE with a high likelihood of exploitation (EPSS above 90)
fs-cli query --type project --name myapp --version v1.2.3 --fail-on-severity critical --max-epss 90

# Widen the scope to gate on critical Binary SAST and config findings too
fs-cli query --type project --name myapp --version v1.2.3 --finding-scope cve,bsast,config --fail-on-severity critical

# Machine-readable output for a dashboard
fs-cli query --type project --name myapp --version v1.2.3 --format json | jq .

# Full pipeline gate
fs-cli scan  --name myapp --version "$CI_COMMIT" --release .
fs-cli query --type scan    --name myapp --version "$CI_COMMIT" --wait
fs-cli query --type project --name myapp --version "$CI_COMMIT" --fail-on-severity critical --reachable
```

---

### update

Update fs-cli to the latest version.

```
fs-cli update
```

Asks the Finite State platform for the latest release, downloads it, verifies its SHA-256 checksum and Ed25519 signature, and replaces the running binary. Requires a configured endpoint and token (flags, environment variables, or the credential file).

On **Windows**, the running executable cannot be deleted, so fs-cli renames the old binary to `fs-cli.exe.old` and writes the new one in its place. The `.old` file is automatically cleaned up on the next invocation.

---

### version

Print the tool version.

```
fs-cli version
```

---

## Global Flags

These flags apply to all commands:

| Flag | Description |
|---|---|
| `--debug` | Enable debug logging (structured key-value output) |
| `--quiet` | Minimal output |
| `--no-update-check` | Disable the automatic update check |

---

## Supported Ecosystems

### Build tool execution

These ecosystems require their build tool to be installed. fs-cli invokes the tool as a subprocess to resolve the full dependency tree:

| Ecosystem | Build tool command | What it provides |
|---|---|---|
| Maven | `mvn dependency:tree` | Full transitive tree with scopes (compile/runtime/test/provided) |
| Gradle | `gradle dependencies` | Configuration-aware resolution, multi-module, conflict resolution |
| sbt | `sbt dependencyTree` | Full Scala dependency tree |
| Go | `go list -m -json all` | Module-resolved transitive deps with indirect flag |

### Lock file parsing

These ecosystems are parsed statically from lock/manifest files — no build tool required:

| Ecosystem | Files | Scope | DependsOn |
|---|---|---|---|
| Cargo | Cargo.lock + Cargo.toml | Yes | Yes |
| Poetry | poetry.lock + pyproject.toml | Yes | Yes |
| uv | uv.lock + pyproject.toml | Yes | Yes |
| npm | package-lock.json (v2/v3) | Yes | Yes |
| Yarn | yarn.lock + package.json | Yes | No |
| pnpm | pnpm-lock.yaml + package.json | Yes | No |
| pip | Pipfile.lock or requirements.txt | Partial | No |
| Composer | composer.lock | Yes | No |
| Bundler | Gemfile.lock | Yes | No |
| .NET | packages.lock.json, .csproj, .sln | Yes | No |
| CocoaPods | Podfile.lock | Yes | No |
| SPM | Package.resolved | No | No |
| Conan | conan.lock | Yes | No |
| Conda | environment.yml | No | No |
| Docker | Dockerfile | No | No |

**Scope**: whether the scanner distinguishes runtime vs. dev/test dependencies.
**DependsOn**: whether the output includes a dependency graph (which packages depend on which).

---

## Output Adapters

Select an output adapter with `--output`:

| Adapter | Description |
|---|---|
| `platform` | **(default)** Generates a CycloneDX SBOM and uploads to the Finite State platform API. Creates the project and version automatically if they don't exist. |
| `legacy` | Transforms results into the legacy wire format (JSON, gzipped, base64-encoded) and POSTs to `/api/m/profileVulns`. For older Finite State deployments. |
| `file` | Writes scan results as indented JSON to a local file. Requires `--output-file`. Does not need API credentials. Supports optional Ed25519 signing via `--sign-key`. |
| `helix` | Reserved for the Helix format. Not yet implemented. |

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install fs-cli
  run: curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh

- name: Scan dependencies
  env:
    FS_TOKEN: ${{ secrets.FS_TOKEN }}
    FS_ENDPOINT: app.finitestate.io
  run: fs-cli scan --name "${{ github.event.repository.name }}" .
```

### GitLab CI

```yaml
scan:
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y curl
    - curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
  script:
    - fs-cli scan --name "$CI_PROJECT_NAME" .
  variables:
    FS_TOKEN: $FS_TOKEN
    FS_ENDPOINT: app.finitestate.io
```

### Jenkins

```groovy
pipeline {
    agent any
    environment {
        FS_TOKEN = credentials('fs-token')
        FS_ENDPOINT = 'app.finitestate.io'
    }
    stages {
        stage('Install fs-cli') {
            steps {
                sh 'curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh'
            }
        }
        stage('Scan') {
            steps {
                sh "fs-cli scan --name ${env.JOB_NAME} ."
            }
        }
    }
}
```

### Tips

- Store `FS_TOKEN` as a secret / masked variable — never commit it to source control.
- Use `--test` in pull request checks to validate scanning without uploading.
- Use `--strict` if you want the CI step to fail when a scanner encounters an error.
- Set `FS_SKIP_UPDATE=1` in CI if you need fully pinned tooling — note this also skips the automatic upgrade to the next-generation CLI.

---

## Migrating from the Java CLI

fs-cli is a drop-in replacement for `finitestate.jar`. Existing CI scripts work without changes because:

### Flag compatibility

camelCase flags are automatically normalized to kebab-case:

| Java CLT flag | fs-cli equivalent |
|---|---|
| `--pipFile` | `--pip-file` |
| `--toolOptions` | `--tool-options` |
| `--includeOnly` | `--include-only` |
| `--outputFile` | `--output-file` |
| `--scanTimeout` | `--scan-timeout` |
| `--thirdParty` | `--third-party` |

### Legacy mode flags

The old `--scan`, `--binary`, `--upload`, `--import`, and `--thirdParty` flags are accepted and delegated to the appropriate subcommand with a deprecation warning:

| Legacy invocation | Modern equivalent |
|---|---|
| `fs-cli --scan --name=foo .` | `fs-cli scan --name=foo .` |
| `fs-cli --binary myfile.bin --name=foo` | `fs-cli upload myfile.bin --name=foo` |
| `fs-cli --upload myfile.bin --name=foo` | `fs-cli upload myfile.bin --name=foo` |
| `fs-cli --upload=sca,sast myfile.bin --name=foo` | `fs-cli upload myfile.bin --name=foo --type=sca,sast` |
| `fs-cli --import sbom.json --name=foo` | `fs-cli import sbom.json --name=foo` |
| `fs-cli --thirdParty=snyk results.json --name=foo` | `fs-cli third-party results.json --name=foo --type=snyk` |

### Credential file

The credential file at `~/.finitestate/credential` is fully compatible. Both the old keys (`finite_state_domain`, `finite_state_auth_token`) and the new keys (`endpoint`, `token`) are accepted.

### What changed

- **No Java required.** fs-cli is a single static binary.
- **Faster.** Scans run concurrently and the binary starts instantly.
- **Self-updating.** fs-cli keeps itself up to date automatically from the Finite State platform.
- **Subcommand syntax.** `fs-cli scan`, `fs-cli upload`, etc. The old flag syntax still works but prints a deprecation warning.

---

## Troubleshooting

### "no ecosystems detected"

fs-cli could not find any recognized lock files or manifest files in the target directory. Check that you are scanning the correct directory and that your project's dependency files exist (e.g., `package-lock.json`, `go.mod`, `pom.xml`).

For monorepos where dependencies live in subdirectories, use `--all` to scan recursively.

### "token is required" / "endpoint is required"

API credentials are needed for uploading results. Set them via:
- CLI flags: `--token` and `--endpoint`
- Environment variables: `FS_TOKEN` and `FS_ENDPOINT`
- Credential file: `~/.finitestate/credential`

If you just want to test scanning locally, use `--test` (dry run) or `--output file --output-file results.json`.

### Build tool not found (Maven, Gradle, sbt, Go)

For ecosystems that use build tool execution, the corresponding tool must be installed and on your PATH. Install the build tool or ensure it is available in your CI environment.

### Scan timeout

Individual ecosystem scans time out after 5 minutes by default. The overall scan times out after 30 minutes. Adjust with `--scan-timeout` and `--timeout` respectively.

For large Gradle or Maven projects, you may need to increase the per-scan timeout:

```sh
fs-cli scan --name myproject --scan-timeout 15 .
```

### Permission denied on update

Self-updating (automatic or via `fs-cli update`) needs write access to the directory containing the binary. If installed to `/usr/local/bin`, you may need to run the update with appropriate permissions, or install to a user-writable location.

### Debug logging

Use `--debug` to see detailed structured logs, including which ecosystems were detected, which scanners ran, and what was sent to the API:

```sh
fs-cli scan --name myproject --debug .
```
