---
name: fs-cli
description: Use fs-cli to scan project dependencies, upload binaries, import SBOMs, and upload third-party results to the Finite State platform.
---

# fs-cli skill

You are helping a user work with **fs-cli**, the Finite State CLI tool for software composition analysis.

## What fs-cli does

fs-cli scans project directories for package dependencies across 19 ecosystems, produces SBOM-grade package inventories, and uploads them to the Finite State platform. It also supports uploading binary artifacts, importing existing SBOMs, and uploading third-party tool results.

## Commands

### Scan dependencies

```sh
fs-cli scan --name <project-name> [directory]
```

Key flags:
- `--name` / `--project` (required): project name
- `--all` or `--deep`: recursive monorepo scan
- `--scope runtime|all`: filter dev/test deps (default: runtime)
- `--test`: dry run — print JSON, don't upload
- `--release`: release mode (fast, default) — renames happen before upload and the CLI exits as soon as the upload completes; requires `--version`, mutually exclusive with `--test` and `--version-id`; env: `FS_RELEASE`
- `--release-synchronous`: release mode variant — waits for scan completion and auto-rolls back on scan failure; implies `--release`; env: `FS_RELEASE_SYNCHRONOUS`
- `--output platform|legacy|file`: output adapter (default: platform)
- `--output-file <path>`: required when `--output=file`
- `--strict`: fail immediately on any scanner error instead of continuing to the next ecosystem
- `--sign-key <path>`: PEM-encoded Ed25519 private key for signing file output (airgap workflow)
- `--timeout <minutes>`: overall timeout (default: 30)
- `--scan-timeout <minutes>`: per-ecosystem timeout (default: 5)
- `--concurrency <n>`: parallel scans (default: CPU count)
- `--tool-options <string>`: pass-through options to build tools
- `--include-only`, `--exclude`, `--configuration`: Gradle-specific filters
- `--pip-file <path>`: custom requirements.txt path
- `--folder <name>`: scope project find/create to a folder by name (supports globs)
- `--folder-id <uuid>`: scope project find/create to a folder by UUID
- `--create-folder`: find-or-create `--folder` if it doesn't exist
- `--parent-folder <name>`: parent folder name when creating (defaults to root)
- `--parent-folder-id <uuid>`: parent folder UUID when creating (defaults to root)
- `--project-id <uuid>`: skip project find/create, use this project ID directly
- `--version-id <uuid>`: skip version creation, upload to this version ID directly

### Upload a binary

```sh
fs-cli upload <file> --name <project-name>
```

Key flags:
- `--name` / `--project` (required): project name
- `--type sca,sast,config,vulnerability_analysis,python`: scan types (default: sca). The `python` type runs a [Bandit](https://bandit.readthedocs.io/en/latest/) security scan on Python source code.
- `--version <string>`: version (default: today's date)
- `--release`: release mode (fast, default) — renames happen before upload and the CLI exits as soon as the upload completes; requires `--version`, mutually exclusive with `--version-id`; env: `FS_RELEASE`
- `--release-synchronous`: release mode variant — waits for scan completion and auto-rolls back on scan failure; implies `--release`; env: `FS_RELEASE_SYNCHRONOUS`
- `--folder <name>`: scope project find/create to a folder by name (supports globs)
- `--folder-id <uuid>`: scope project find/create to a folder by UUID
- `--create-folder`: find-or-create `--folder` if it doesn't exist
- `--parent-folder <name>`: parent folder name when creating (defaults to root)
- `--parent-folder-id <uuid>`: parent folder UUID when creating (defaults to root)
- `--project-id <uuid>`: skip project find/create
- `--version-id <uuid>`: skip version creation, upload to this version ID directly

### Import an SBOM

```sh
fs-cli import <sbom-file> --name <project-name>
```

Key flags:
- `--name` / `--project` (required): project name
- `--format cyclonedx|spdx`: auto-detected if omitted
- `--release`: release mode (fast, default) — renames happen before upload and the CLI exits as soon as the upload completes; requires `--version`, mutually exclusive with `--version-id`; env: `FS_RELEASE`
- `--release-synchronous`: release mode variant — waits for scan completion and auto-rolls back on scan failure; implies `--release`; env: `FS_RELEASE_SYNCHRONOUS`
- `--folder <name>`: scope project find/create to a folder by name (supports globs)
- `--folder-id <uuid>`: scope project find/create to a folder by UUID
- `--create-folder`: find-or-create `--folder` if it doesn't exist
- `--parent-folder <name>`: parent folder name when creating (defaults to root)
- `--parent-folder-id <uuid>`: parent folder UUID when creating (defaults to root)
- `--project-id <uuid>`: skip project find/create
- `--version-id <uuid>`: skip version creation, upload to this version ID directly

### Upload third-party results

```sh
fs-cli third-party <file> --name <project-name> --type <tool>
```

The `--type` flag is required (e.g., `snyk`, `coverity`, `checkmarx`).

Key flags:
- `--name` / `--project` (required): project name
- `--folder <name>`: scope project find/create to a folder by name (supports globs)
- `--folder-id <uuid>`: scope project find/create to a folder by UUID
- `--create-folder`: find-or-create `--folder` if it doesn't exist
- `--parent-folder <name>`: parent folder name when creating (defaults to root)
- `--parent-folder-id <uuid>`: parent folder UUID when creating (defaults to root)
- `--project-id <uuid>`: skip project find/create
- `--version-id <uuid>`: skip version creation, upload to this version ID directly

### Deliver a scan file (airgap workflow)

```sh
fs-cli deliver <file> --endpoint <endpoint> --token <token>
```

Key flags:
- `--verify-key <path>`: PEM-encoded Ed25519 public key to verify signed envelopes
- `--folder <name>`: scope project find/create to a folder by name (supports globs)
- `--folder-id <uuid>`: scope project find/create to a folder by UUID
- `--create-folder`: find-or-create `--folder` if it doesn't exist
- `--parent-folder <name>`: parent folder name when creating (defaults to root)
- `--parent-folder-id <uuid>`: parent folder UUID when creating (defaults to root)
- `--project-id <uuid>`: skip project find/create
- `--version-id <uuid>`: skip version creation, upload to this version ID directly
- `--timeout <minutes>`: timeout (default: 5)

### Query scan status / finding gate (CI gating)

```sh
fs-cli query --type scan    --name <project> --version <version> [--wait]
fs-cli query --type project --name <project> --version <version> --fail-on-severity critical --reachable
fs-cli query --type project --name <project> --version <version> --fail-on-severity high --vulns-in-kev
```

Read-only query of the platform for build-pipeline gating — the **process exit code is the gate**.

- `--type scan`: reports scan completion across **all scan types** for the version (SCA, CONFIG, binary SAST, vulnerability/reachability analysis, …) — a finished SCA scan can't mask a still-running reachability/SAST scan. Exits non-zero when any scan failed. `--wait` polls until every scan settles (`--poll-timeout`, default 30 min); `--fail-on-scan-incomplete` also fails when any scan is still running (or none found).
- `--type project`: prints findings-by-severity counts, then applies a gate. The gate conditions are **AND-combined per finding** — exits non-zero if ≥1 finding matches *all* set conditions; no conditions = print counts, exit zero.
- Conditions: `--fail-on-severity <critical|high|medium|low>` (finding severity is at this level **or higher** — gates on the named level plus every more-severe level, so `medium` gates on medium/high/critical, `critical` gates on critical only, `low` gates on everything), `--vulns-in-kev` (CISA KEV), `--vulns-in-vc-kev` (VulnCheck KEV), `--reachable` (vulnerable code reachable), `--exploit-maturity <not-defined|unreported|proof-of-concept|attacked>` (CVSS Exploit Code Maturity >= level; aliases `none`/`poc`; *attacked* = CISA KEV or weaponized/botnet/commercial/threat-actor/ransomware; useful values are `proof-of-concept` and `attacked`), `--max-epss <0-100>` (EPSS score exceeds the integer threshold). e.g. `--fail-on-severity critical --reachable` fails only on a finding that is *both* critical and reachable, not all criticals plus all reachables.
- `--finding-scope` (default `cve`, comma-separated `cve|bsast|config|all`) limits which categories are fetched/evaluated for performance: `cve`=CVE/SCA (incl. third-party/SBOM-imported CVEs), `bsast`=Binary SAST, `config`=config issues+credentials+crypto material, `all`=everything. The gate and severity breakdown only see the chosen scope; widen (e.g. `all`) to gate on non-CVE findings. (No third-party scope: those are SBOM-imported CVEs, already under `cve`.)
- No-scans check (always on, no flag): a `--type project` query verifies the version has a terminally-successful (`COMPLETED`/`NOT_APPLICABLE`) scan before fetching findings and **fails fast if not** — a never-scanned version has an empty/stale findings list, so a gate would otherwise pass vacuously.

Shared flags: `--name`/`--project` + `--version` to resolve the version (`--version` matches the platform's `name` *or* `version` field, like scan/upload), or `--project-id`/`--version-id` to skip lookups; `--folder`/`--folder-id` to disambiguate; `--format table|json`; `--timeout <minutes>` (default 10).

### Update

```sh
fs-cli update
```

Self-updates the binary in place. On Windows, renames the old binary to `.old` and cleans it up on the next run.

### Version

```sh
fs-cli version
```

## Configuration

Credentials are resolved in order: CLI flags > environment variables > credential file > defaults.

**Environment variables:**
- `FS_TOKEN` (or `FINITE_STATE_AUTH_TOKEN`): API token
- `FS_ENDPOINT` (or `FINITE_STATE_DOMAIN`): API endpoint
- `FS_PROJECT_NAME`: default project name
- `FS_FOLDER`: folder name for project scoping (resolved to UUID, supports globs)
- `FS_FOLDER_ID`: folder UUID for project scoping
- `FS_CREATE_FOLDER`: set to `true` to find-or-create `FS_FOLDER` if it doesn't exist
- `FS_PARENT_FOLDER`: parent folder name when creating (defaults to root)
- `FS_PARENT_FOLDER_ID`: parent folder UUID when creating (defaults to root)
- `FS_PROJECT_ID`: project UUID (skips project find/create)
- `FS_VERSION_ID`: version UUID (skips version creation)
- `FS_RELEASE`: enable release mode (equivalent to `--release`)
- `FS_RELEASE_SYNCHRONOUS`: enable synchronous release mode (equivalent to `--release-synchronous`; implies `FS_RELEASE`)
- `FS_NO_UPDATE_CHECK=1`: disable update notifications

**Credential file** at `~/.finitestate/credential`:
```
endpoint=app.finitestate.io
token=your-api-token
```
One key=value pair per line. Lines starting with `#` are comments. The legacy keys `finite_state_domain` and `finite_state_auth_token` are also accepted for backward compatibility with the Java CLI.

**Endpoint normalization:** Bare domain names are automatically prefixed with `https://` and trailing slashes are stripped. `app.finitestate.io`, `https://app.finitestate.io`, and `https://app.finitestate.io/` are all equivalent.

**Git auto-detection:** When run inside a Git repository, fs-cli automatically detects the branch name, commit hash, and remote URL. Override with `--branch` and `--version`.

## Global flags

- `--debug`: structured debug logging
- `--quiet`: minimal output
- `--no-update-check`: suppress update notification

## Output adapters

Select with `--output`:

| Adapter | Description |
|---|---|
| `platform` | **(default)** Generates a CycloneDX SBOM and uploads to the Finite State platform API. Creates the project and version automatically if they don't exist. |
| `legacy` | Transforms results into the legacy wire format (JSON, gzipped, base64-encoded) and POSTs to `/api/m/profileVulns`. For older Finite State deployments. |
| `file` | Writes scan results as indented JSON to a local file. Requires `--output-file`. Does not need API credentials. Supports optional Ed25519 signing via `--sign-key` for airgapped delivery. |

## Supported ecosystems

### Build tool execution (tool must be on PATH)

| Ecosystem | Command | What it provides |
|---|---|---|
| Maven | `mvn dependency:tree` | Full transitive tree with scopes (compile/runtime/test/provided) |
| Gradle | `gradle dependencies` | Configuration-aware resolution, multi-module, conflict resolution |
| sbt | `sbt dependencyTree` | Full Scala dependency tree |
| Go | `go list -m -json all` | Module-resolved transitive deps with indirect flag |

### Lock file parsing (no build tool required)

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
| Conan | conan.lock | Yes | No |
| SPM | Package.resolved | No | No |
| Conda | environment.yml | No | No |
| Docker | Dockerfile | No | No |

**Scope**: whether the scanner distinguishes runtime vs. dev/test dependencies.
**DependsOn**: whether the output includes a dependency graph (which packages depend on which).

## CI/CD usage

```yaml
# GitHub Actions example
- name: Install fs-cli
  run: curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh

- name: Scan and gate the build
  env:
    FS_TOKEN: ${{ secrets.FS_TOKEN }}
    FS_ENDPOINT: app.finitestate.io
  run: |
    NAME="${{ github.event.repository.name }}"
    VER="${{ github.sha }}"
    fs-cli scan  --name "$NAME" --version "$VER" --release .
    fs-cli query --type scan    --name "$NAME" --version "$VER" --wait
    fs-cli query --type project --name "$NAME" --version "$VER" --fail-on-severity high
```

The two `query` steps fail the job (non-zero exit) if the scan errored or a finding matches the gate — here, any critical or high finding. Set `FS_NO_UPDATE_CHECK=1` in CI to suppress update notifications.

## Airgap workflow

For environments without network access, scan locally, shuttle the file, then deliver from a connected system:

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

## Migrating from the Java CLI

fs-cli is a drop-in replacement for `finitestate.jar`. Existing CI scripts work without changes:

**camelCase flags** are automatically normalized to kebab-case: `--pipFile` -> `--pip-file`, `--toolOptions` -> `--tool-options`, `--includeOnly` -> `--include-only`, `--scanTimeout` -> `--scan-timeout`, etc.

**Legacy mode flags** are accepted and delegated to the appropriate subcommand with a deprecation warning:

| Legacy invocation | Modern equivalent |
|---|---|
| `fs-cli --scan --name=foo .` | `fs-cli scan --name=foo .` |
| `fs-cli --binary myfile.bin --name=foo` | `fs-cli upload myfile.bin --name=foo` |
| `fs-cli --upload myfile.bin --name=foo` | `fs-cli upload myfile.bin --name=foo` |
| `fs-cli --upload=sca,sast myfile.bin --name=foo` | `fs-cli upload myfile.bin --name=foo --type=sca,sast` |
| `fs-cli --import sbom.json --name=foo` | `fs-cli import sbom.json --name=foo` |
| `fs-cli --thirdParty=snyk results.json --name=foo` | `fs-cli third-party results.json --name=foo --type=snyk` |

## Common patterns

When the user wants to:

- **Test scanning without uploading**: use `--test` flag
- **Save results locally**: use `--output file --output-file results.json`
- **Deliver from airgapped environment**: scan with `--output file`, shuttle the file, then `fs-cli deliver <file>`
- **Scan a monorepo**: use `--all` flag
- **Include dev dependencies**: use `--scope all`
- **Debug scan issues**: use `--debug` flag
- **Fail CI on scan errors**: use `--strict` flag
- **Scope project to a folder**: use `--folder <name>` or `--folder-id <uuid>` (all commands)
- **Skip project lookup**: use `--project-id <uuid>` to go straight to version creation
- **Skip version creation**: use `--version-id <uuid>` to upload to an existing version directly
- **Create a clean release snapshot (fast, default)**: `--version <name> --release` — archives the previous version as a checkpoint *before* upload and the CLI exits as soon as the upload completes. Best for CI/CD. If the version does not exist yet, creates it normally.
- **Create a clean release snapshot (synchronous)**: `--version <name> --release-synchronous` — waits for the backend scan to finish, auto-rolls back on scan failure. Use when you want atomic swap semantics. Implies `--release`.
- **Recover from a failed scan under fast release mode**: the current version now contains the failed scan and the checkpoint holds the previous good scan. Swap them back manually in the platform UI; re-running with `--release-synchronous` does *not* fix it (it would just layer another checkpoint).

## Error guidance

- "no ecosystems detected": check directory path, ensure lock/manifest files exist, use `--all` for monorepos
- "token is required": set credentials via `--token`, `FS_TOKEN`, or `~/.finitestate/credential`
- Build tool not found: install Maven/Gradle/sbt/Go and ensure it's on PATH
- Scan timeout: increase `--scan-timeout` for large projects
