# Changelog

All notable changes to fs-cli are documented in this file.

## v2.0.17

### Changed

- **Final release of this fs-cli distribution — fs-cli now upgrades itself through the Finite State platform.** Before each work command (`scan`, `upload`, `import`, `third-party`, `deliver`), fs-cli asks your Finite State platform whether a newer release is available. When one is, it downloads the release, verifies its SHA-256 checksum and Ed25519 signature, replaces itself in place, and restarts to run your command on the new version. Once your platform is upgraded, this upgrades fs-cli to the **next-generation Finite State CLI (v2.3.x)** — same `fs-cli` binary name, compatible commands and flags. On platforms that have not been upgraded yet, the check logs an informational "auto-update service is temporarily unavailable" message and the command continues normally. The next-generation CLI can also be downloaded directly from the platform UI (see the [CLI documentation](https://docs.finitestate.io/docs/command-line-interface/v2/)).
- `fs-cli update` now updates through the Finite State platform and requires a configured endpoint and token (via `--endpoint`/`--token` flags, environment variables, or the credential file). On platforms that do not offer the update service yet it reports that and exits zero. The post-command "a new version is available" notification is gone — updates apply automatically instead.
- New opt-outs: `FS_SKIP_UPDATE=1` disables the automatic update check (alongside the existing `FS_NO_UPDATE_CHECK=1` and `--no-update-check`).
- The CI wrapper scripts (`run-fs-cli.sh` / `run-fs-cli.ps1`) no longer suppress the built-in update check or re-download fs-cli every run — the binary keeps itself up to date from the platform instead. The wrapper downloads only when no cached binary exists, or once to bring a cached binary older than v2.0.17 (which cannot update itself) up to the final published release.

## v2.0.16

### Added

- `fs-cli query` — read-only query of the platform for CI/build-pipeline gating; **the process exit code is the gate** (non-zero on failure). Two modes:
  - **`--type scan`** reports scan completion **across all scan types** for a project version (SCA, CONFIG, binary SAST, vulnerability/reachability analysis, …), so a finished SCA scan can't mask a still-running reachability or binary-SAST scan. Exits non-zero when any scan failed. With `--wait` it polls until every scan has settled (`--poll-timeout`, default 30 min, bounded independently of `--timeout`); `--fail-on-scan-incomplete` makes a still-running (or missing) scan a failure in the non-wait snapshot.
  - **`--type project`** prints the version's findings-by-severity counts and then applies an opt-in **per-finding gate**: conditions are AND-combined, so the run exits non-zero when at least one finding satisfies *every* configured condition (with none set it just prints the counts).
  - Gate conditions (AND-combined per finding — a finding trips the gate only when it matches *every* set condition; e.g. `--fail-on-severity critical --reachable` fails only on a finding that is *both* critical and reachable):
    - `--fail-on-severity <critical|high|medium|low>` — severity at the named level *or higher* (`medium` → medium/high/critical; `low` → everything; `critical` → critical only)
    - `--vulns-in-kev` — finding is listed in the CISA Known Exploited Vulnerabilities catalog
    - `--vulns-in-vc-kev` — finding is listed in the VulnCheck KEV catalog
    - `--reachable` — vulnerable code path is reachable in the scanned binary
    - `--exploit-maturity <level>` — CVSS Exploit Code Maturity is at or above the given level (`not-defined` / `unreported` / `proof-of-concept` / `attacked`; `none` and `poc` accepted as aliases)
    - `--max-epss <0-100>` — EPSS percentile score exceeds the given integer threshold
  - `--finding-scope` (default `cve`, comma-separated `cve`/`bsast`/`config`/`all`) limits which finding categories are fetched and evaluated — `cve` (CVE/SCA, including third-party/SBOM-imported CVEs), `bsast` (Binary SAST), `config` (config issues + credentials + crypto material), or `all` — so the gate stays cheap and, by default, scoped to CVEs (widen it to gate on non-CVE findings).
  - A `--type project` query always exits non-zero if the version has no terminally-successful (`COMPLETED`/`NOT_APPLICABLE`) scan — checked before any findings are fetched — so a gate can't pass vacuously against a version that was never scanned (where the findings list is empty or stale).
  - The project version is resolved from `--name` + `--version`, with `--project-id` / `--version-id` to skip the lookups and `--folder` / `--folder-id` to disambiguate a project name that repeats across folders. Supports `--format table` (default) and `--format json`.
  - **Planned:** structured exit codes to distinguish failure modes (gate failure vs. scan error vs. API/auth error) are targeted for a future release. The current gate uses a single non-zero exit code for all failure modes.

## v2.0.15

### Added

- `fs-cli rbac-report` — read-only audit of user and/or group access on the Finite State platform. Resolves one-or-many emails (via `--users`) and/or group names/ids (via `--groups`) and reports each subject's group memberships, member emails, and folder access (direct + via group) with `read` / `write` / `admin` roles and `orgRoles`. Supports `--format table` (default), `--format csv` (one row per subject × access), and `--format json` (structured single-document). User lookup tries `email==` first, then `username==` (the platform's `userId` is often an IDP handle, not the email). Inputs with RSQL-structural characters are rejected at parse time; multi-match lookups are reported as `AMBIGUOUS` rather than guessed. At least one of `--users` / `--groups` is required; both may be combined in a single run. Group-only runs skip the org-wide membership fan-out (`--groups` without `--users` is materially cheaper on large tenants). Per-folder and per-group API calls run in parallel — tune with `--workers` (default 3).

## v2.0.14

### Added

- Work subcommands (`scan`, `upload`, `import`, `third-party`, `deliver`) now emit an opening `fs-cli starting` and closing `fs-cli finished` info logline on stderr that includes the CLI version, the subcommand being run, and the total elapsed time. Metadata commands (`version`, `update`, `completion`, `help`) and the bare `fs-cli` invocation are unchanged. Use `--quiet` to suppress.
- `--create-folder`, `--parent-folder`, and `--parent-folder-id` flags on `scan`, `upload`, `import`, `third-party`, and `deliver` (env: `FS_CREATE_FOLDER`, `FS_PARENT_FOLDER`, `FS_PARENT_FOLDER_ID`). When `--create-folder` is set, fs-cli find-or-creates the destination folder named by `--folder` under the chosen parent (or root) before resolving the project. The operation is idempotent — an existing folder of the same name under the parent is reused. `--parent-folder` and `--parent-folder-id` are mutually exclusive. If the folder name already exists elsewhere on the platform (folder names are globally unique), the CLI fails with a precise error naming the actual parent and suggesting how to recover, instead of a misleading retry message.

### Changed

- Uploads from `--scan` are now classified as source-code SCA scans on the Finite State platform, distinct from generic SBOM imports. `--import` uploads continue to be classified as SBOM imports.

## v2.0.13

### Changed — BREAKING

- `--release` now uses a fast, CI-friendly flow by default: the existing version is renamed to `{name}-checkpoint-{YYYY-MM-DD}` **before** the upload, a fresh version is created with the target name, the upload runs, and the CLI exits. Scan status is no longer tracked by the CLI, so backend scan queue time does not extend the job. If the backend scan later fails, the empty/failed version remains "current" until manually recovered via the platform UI.
- New flag `--release-synchronous` (env: `FS_RELEASE_SYNCHRONOUS`) — performs the same rename-before-upload sequence as `--release`, then polls until the backend scan reaches a terminal state. On scan failure or timeout: if a prior version was swapped out, automatically rolls back (delete new version, rename checkpoint back); on a first-time release (no prior version), returns the error without rollback, leaving the failed/partial version in place for the operator to inspect. Passing `--release-synchronous` alone is sufficient; it implies `--release`.
- Synchronous release mode also changed: the previous "upload to a temporary `{name}-release-{timestamp}` version, then swap on scan completion" flow has been replaced by the rename-before-upload sequence above. Net effect during the scan window: the version named `{name}` on the platform transiently points at the new, still-scanning build rather than at the previous known-good version. The final state is unchanged — on scan success the new build is current; on scan failure the rollback restores the previous version under its original name.

If your CI depends on the CLI blocking until scan completion (e.g. to fail the job on scan failure), switch to `--release-synchronous`. If you depended on the previous known-good version remaining queryable under its original name throughout the scan window, do not use release mode at all — create a separate version instead.

## v2.0.12

### Added

- `python` upload scan type (`--type python`) that triggers a Bandit security scan on uploaded Python source code.
- `--release` now works when the version or project does not yet exist — falls back to normal create-and-upload flow, making it safe for first-run CI/CD pipelines.
- Windows self-update support: `fs-cli update` now works on Windows by renaming the running binary instead of deleting it, with cleanup on next invocation.

### Fixed

- Maven and Gradle scanners now fall back to the system-installed build tool (`mvn`/`gradle`) when the project wrapper (`mvnw`/`gradlew`) fails (e.g., due to network issues downloading the wrapper distribution).

## Previous releases

### Add folder-scoped projects and project-id shortcut

- `--folder-id` flag on all commands (`scan`, `upload`, `import`, `deliver`, `third-party`) to scope project find/create to a specific folder. Environment variable: `FS_FOLDER_ID`.
- `--project-id` flag on all commands to skip project find/create entirely and use a known project UUID directly. Environment variable: `FS_PROJECT_ID`.
- Root folder auto-discovery: when no `--folder-id` is specified, the CLI looks up the root folder via `GET /api/public/v0/folders` and scopes project search to it, preventing cross-folder name collisions.

### Fix --tool-options passthrough and RSQL filter quoting

- Fixed `--tool-options` flag not being passed through to build tools.
- Fixed RSQL filter quoting for project names containing special characters.

### Add deliver command for airgap workflow

- New `deliver` command to upload a previously saved scan output file to the platform.
- Supports signed envelopes with Ed25519 signature verification.

### Add version check, self-update command, and customer-facing docs

- `fs-cli update` command for self-updating.
- Post-command version check with update notifications.
- User guide and skill documentation.

### Add cross-platform build and install script

- Automated installer script with checksum verification.
- Cross-platform binary builds (Linux, macOS, Windows; x86_64, ARM64).

### Add Java CLT backward compatibility

- Flag normalization (camelCase to kebab-case).
- Legacy flag support (`--scan`, `--binary`, `--upload`, `--import`, `--thirdParty`).

### Add .NET solution file support and JS ecosystem priority rules

- .NET `.sln` file scanning.
- JavaScript ecosystem detection priority rules.

### Add support for advanced ecosystem layouts

- Cargo workspaces.
- Poetry projects using PEP 621.
- Multi-module Gradle builds.
- NPM lockfile v3.
