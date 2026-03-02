# fs-cli

**Finite State CLI** -- scan your project dependencies and upload SBOM-grade package inventories to the Finite State platform.

Single binary, no runtime dependencies. Supports 18 package ecosystems with transitive dependency resolution.

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

## Updating

fs-cli checks for new versions after each command and will notify you when an update is available. To update in place:

```sh
fs-cli update
```

To disable update notifications, set `FS_NO_UPDATE_CHECK=1` or use `--no-update-check`.

## Supported Ecosystems

Bundler, Cargo, CocoaPods, Composer, Conda, Docker, .NET, Go modules, Gradle, Maven, npm, pip, pnpm, Poetry, sbt, Swift Package Manager, uv, and Yarn.

## More Information

See `USER_GUIDE.md` in this directory for the full user guide, including all flags, configuration options, ecosystem details, CI/CD integration, and troubleshooting.
