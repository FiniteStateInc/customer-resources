# Changelog

All notable changes to fs-cli are documented in this file.

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
