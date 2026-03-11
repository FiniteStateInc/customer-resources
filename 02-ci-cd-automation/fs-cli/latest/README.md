# fs-cli

**Finite State CLI** -- scan your project dependencies and upload SBOM-grade package inventories to the Finite State platform.

Single binary, no runtime dependencies. Supports 19 package ecosystems with transitive dependency resolution.

## Installation

### Automated (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
```

This detects your OS and architecture, downloads the correct binary, verifies its SHA-256 checksum, and installs to `/usr/local/bin` (or `~/.local/bin` if `/usr/local/bin` is not writable).

To install to a custom directory:

```sh
curl -fsSL .../install.sh | INSTALL_DIR=/opt/tools sh
```

### Manual

Download the binary for your platform from the `latest/` directory in this repository:

| Platform       | Binary                      |
|----------------|-----------------------------|
| Linux x86_64   | `fs-cli-linux-amd64`        |
| Linux ARM64    | `fs-cli-linux-arm64`        |
| macOS x86_64   | `fs-cli-darwin-amd64`       |
| macOS ARM64    | `fs-cli-darwin-arm64`       |
| Windows x86_64 | `fs-cli-windows-amd64.exe`  |

Verify the checksum against `checksums.txt`, then make it executable:

```sh
chmod +x fs-cli-*
mv fs-cli-* /usr/local/bin/fs-cli
```

## Quick Start

### 1. Configure credentials

Set your API token and endpoint. You can use environment variables:

```sh
export FS_TOKEN="your-api-token"
export FS_ENDPOINT="app.finitestate.io"
```

Or create a credential file at `~/.finitestate/credential`:

```
endpoint=app.finitestate.io
token=your-api-token
```

### 2. Scan a project

```sh
fs-cli scan --name myproject .
```

This detects package ecosystems in the current directory, resolves dependencies, and uploads results to the Finite State platform.

### 3. Try a dry run first

To see what would be uploaded without sending anything:

```sh
fs-cli scan --name myproject --test .
```

## Common Commands

```sh
# Scan a project directory
fs-cli scan --name myproject .

# Recursive monorepo scan
fs-cli scan --name myproject --all .

# Upload a binary artifact
fs-cli upload myfile.bin --name myproject

# Import an existing SBOM
fs-cli import sbom.json --name myproject

# Upload third-party tool results
fs-cli third-party results.json --name myproject --type snyk

# Deliver a scan file from an airgapped environment
fs-cli deliver scan.json --endpoint app.finitestate.io --token $FS_TOKEN

# Check version
fs-cli version

# Update to latest version
fs-cli update
```

## Project Organization

fs-cli organizes uploads into a three-level hierarchy: **Folders > Projects > Versions**.

### Folders (`--folder` / `--folder-id`)

Folders group related projects on the platform. Use `--folder <name>` to look up a folder by name, or `--folder-id <uuid>` if you already have the UUID. If neither is provided, fs-cli uses the root folder.

`--folder` supports glob patterns (`*`, `?`, `[...]`) for matching folder names. If multiple folders match, the CLI prints all matches with their IDs so you can switch to `--folder-id`.

Set the `FS_FOLDER` environment variable as an alternative to `--folder`.

### Projects (`--name` / `--project`)

A project represents a single software component or repository. `--name` and `--project` are interchangeable.

- **By name** (default): fs-cli finds an existing project with that name, or creates one if it doesn't exist.
- **By ID** (`--project-id <uuid>`): skips the search and uploads directly to a known project.

### Versions (`--version` / `--version-id`)

A version is a point-in-time snapshot of a project — typically a release, build, or scan run.

| Flags | Behavior |
|---|---|
| *(neither)* | Auto-generates a date-based name (`2026-03-06`). On conflict, increments: `.1`, `.2`, etc. Each run creates a new version. |
| `--version <name>` | Finds an existing version with that name, or creates it. Repeated runs with the same value upload to the **same** version. |
| `--version-id <uuid>` | Uploads directly to a known version UUID. No lookup, no creation. |

### Common Patterns

```sh
# CI/CD daily builds — auto-generated version per run
fs-cli scan --name "$REPO_NAME" .

# Release builds — pin version so all artifacts land together
fs-cli scan --name my-app --version "$RELEASE_TAG" .
fs-cli upload firmware.bin --name my-app --version "$RELEASE_TAG"

# Multi-team org — use folders by name
fs-cli scan --name my-app --folder "IoT Cloud" .

# Or by UUID
fs-cli scan --name my-app --folder-id "$TEAM_FOLDER_ID" .

# Multiple scan types on one version — --version reuses by name
fs-cli upload firmware.bin --name my-device --version v3.0.0
fs-cli third-party coverity.json --name my-device --type coverity --version v3.0.0
fs-cli import sbom.cdx.json --name my-device --version v3.0.0
```

## Updating

fs-cli checks for new versions after each command and will notify you when an update is available. To update in place:

```sh
fs-cli update
```

To disable update notifications, set `FS_NO_UPDATE_CHECK=1` or use `--no-update-check`.

## Supported Ecosystems

Bundler, Cargo, CocoaPods, Composer, Conan, Conda, Docker, .NET, Go modules, Gradle, Maven, npm, pip, pnpm, Poetry, sbt, Swift Package Manager, uv, and Yarn.

## More Information

See `USER_GUIDE.md` in this directory for the full user guide, including all flags, configuration options, ecosystem details, CI/CD integration, and troubleshooting.
