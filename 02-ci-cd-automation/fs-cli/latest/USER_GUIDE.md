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

fs-cli is a software composition analysis tool that scans project dependencies and uploads SBOM-grade package inventories to the Finite State platform. It ships as a single binary with no runtime dependencies and supports 18 package ecosystems with transitive dependency resolution.

---

## Installation

### Automated install

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
```

The installer:
- Detects your OS (Linux, macOS, Windows) and architecture (x86_64, ARM64)
- Downloads the correct binary
- Verifies its SHA-256 checksum
- Installs to `/usr/local/bin` (or `~/.local/bin` if `/usr/local/bin` is not writable)

Custom install directory:

```sh
curl -fsSL .../install.sh | INSTALL_DIR=/opt/tools sh
```

### Manual install

Download the binary for your platform, verify the checksum, and place it on your PATH:

```sh
# Example for Linux x86_64
curl -fsSL -o fs-cli https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/latest/fs-cli-linux-amd64
chmod +x fs-cli
sudo mv fs-cli /usr/local/bin/
```

### Self-update

Once installed, fs-cli can update itself in place:

```sh
fs-cli update
```

fs-cli also checks for new versions after each command and prints a notification to stderr when an update is available.

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
| `FS_DEBUG` | | Enable debug logging |
| `FS_NO_UPDATE_CHECK` | | Set to `1` to disable update notifications |

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
| `--name` | (required) | Project name |
| `--branch` | (auto-detect) | Git branch |
| `--version` | | Version string |
| `--all`, `--deep` | `false` | Recursive monorepo scan — find all ecosystems in subdirectories |
| `--scope` | `runtime` | Dependency scope: `runtime` excludes dev/test deps, `all` includes everything |
| `--output` | `platform` | Output adapter: `platform`, `legacy`, `helix`, `file` |
| `--output-file` | | Output file path (required when `--output=file`) |
| `--sign-key` | | PEM-encoded Ed25519 private key for signing file output |
| `--strict` | `false` | Fail immediately on any scanner error instead of continuing |
| `--tool-options` | | Pass-through options for build tools (Maven, Gradle, etc.) |
| `--include-only` | | Gradle subproject include filter |
| `--exclude` | | Gradle subproject exclusion filter |
| `--configuration` | | Gradle configuration name |
| `--pip-file` | | Custom path to requirements.txt |
| `--timeout` | `30` | Overall timeout in minutes |
| `--scan-timeout` | `5` | Per-ecosystem scan timeout in minutes |
| `--test` | `false` | Dry run: print JSON to stdout, do not upload |
| `--concurrency` | CPU count | Maximum number of parallel ecosystem scans |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |

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
```

---

### upload

Upload a binary artifact for analysis.

```
fs-cli upload <file> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--name` | (required) | Project name |
| `--version` | today's date | Version string |
| `--type` | `sca` | Scan types, comma-separated: `sca`, `sast`, `config`, `vulnerability_analysis` |
| `--timeout` | `30` | Overall timeout in minutes |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |

#### Examples

```sh
# Upload a firmware image
fs-cli upload firmware.bin --name my-device

# Upload with multiple scan types
fs-cli upload app.bin --name myapp --type sca,sast

# Upload with explicit version
fs-cli upload release.bin --name myapp --version 2.1.0
```

---

### import

Import an existing SBOM file (CycloneDX or SPDX) to the platform.

```
fs-cli import <sbom-file> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--name` | (required) | Project name |
| `--version` | (auto-generated) | Version string |
| `--format` | (auto-detect) | SBOM format: `cyclonedx`, `cdx`, or `spdx` |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |

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
| `--name` | (required) | Project name |
| `--type` | (required) | Third-party tool type (e.g., `snyk`, `coverity`, `checkmarx`) |
| `--version` | (auto-generated) | Version string |
| `--timeout` | `30` | Overall timeout in minutes |
| `--endpoint` | | Finite State API endpoint |
| `--token` | | Finite State API token |

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

### update

Update fs-cli to the latest version.

```
fs-cli update
```

Downloads the latest binary for your platform, verifies its SHA-256 checksum, and atomically replaces the running binary. No arguments or flags required.

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
| `--no-update-check` | Disable the post-command update notification |

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
- Set `FS_NO_UPDATE_CHECK=1` in CI to suppress update notifications.

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
- **Self-updating.** Run `fs-cli update` instead of re-downloading the JAR.
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

`fs-cli update` needs write access to the directory containing the binary. If installed to `/usr/local/bin`, you may need to run the update with appropriate permissions.

### Debug logging

Use `--debug` to see detailed structured logs, including which ecosystems were detected, which scanners ran, and what was sent to the API:

```sh
fs-cli scan --name myproject --debug .
```
