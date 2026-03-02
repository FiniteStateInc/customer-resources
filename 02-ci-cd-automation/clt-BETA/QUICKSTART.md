# Quick Start Guide

This guide walks you through running your first scan and uploading results
using the standalone scanner binary.

---

## 1. Get the Binary for Your Platform

Pre-built standalone binaries are available for the following platforms:


| Platform              | Binary name             |
| --------------------- | ----------------------- |
| macOS (Apple Silicon) | `cli_mac_arm64`         |
| macOS (Intel)         | `cli_mac_amd64`         |
| Linux (x86_64)        | `cli_linux_amd64`       |
| Linux (ARM64)         | `cli_linux_arm64`       |
| Windows (x86_64)      | `cli_windows_amd64.exe` |
| Windows (ARM64)       | `cli_windows_arm64.exe` |


Each binary also has a corresponding `.sig` (signature) and `.pem`
(certificate) file in the release, along with a `cli_checksums.txt` file
containing SHA-256 hashes of all binaries. See
[Verifying the Binary](#2-verify-the-binary-optional) below.

Download the binary for your platform, rename it to `cli` (or `cli.exe` on
Windows), and make it executable:

```bash
mv cli_mac_arm64 cli
chmod +x cli
```

**macOS users:** Because the binary is not Apple-signed, macOS Gatekeeper will
block it the first time you try to run it. Remove the quarantine attribute to
fix this:

```bash
xattr -d com.apple.quarantine ./cli
```

Alternatively, right-click the file in Finder, choose **Open**, and confirm the
security prompt. You only need to do this once.

The standalone binary is fully self-contained — all detection rules and default
configuration are embedded. No additional files or dependencies are required.

> **Tip:** You can verify the binary works by checking its version:
>
> ```bash
> ./cli --version
> ```

---

## 2. Verify the Binary (Optional)

Every release binary is signed using [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/)
with keyless signing. This means there is no static public key to manage — the
signature is tied to the GitHub Actions identity that built the release.

Each binary in the release has two companion files:


| File                | Purpose                                          |
| ------------------- | ------------------------------------------------ |
| `cli_mac_arm64.sig` | Cosign signature for the binary                  |
| `cli_mac_arm64.pem` | Signing certificate (contains the OIDC identity) |


There is also a `cli_checksums.txt` (with its own `.sig` and `.pem`) that
contains SHA-256 hashes of all binaries.

### Verify a binary with Cosign

Install [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/),
then run:

```bash
cosign verify-blob \
  --signature cli_mac_arm64.sig \
  --certificate cli_mac_arm64.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/FiniteStateInc/" \
  cli_mac_arm64
```

Replace the filenames with the ones matching your platform. A successful
check prints `Verified OK`.

### Verify checksums

You can also verify the checksum file first, then check your binary against
it:

```bash
# 1. Verify the checksum file's signature
cosign verify-blob \
  --signature cli_checksums.txt.sig \
  --certificate cli_checksums.txt.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/FiniteStateInc/" \
  cli_checksums.txt

# 2. Check your binary against the verified checksums
sha256sum -c cli_checksums.txt --ignore-missing
```

---

## 3. Run Your First Scan

Point the scanner at any directory you want to analyze:

```bash
./cli --dir /path/to/project
```

When no output file or format is specified, the scanner automatically generates
a CycloneDX JSON SBOM with a timestamped filename (e.g.
`myproject-20260220-143012.cdx.json`). This file can be imported into Finite
State or any other tool that supports the CycloneDX format.

You can also upload results directly to Finite State as part of the scan — see
[Uploading Results](#5-uploading-results-to-finite-state) for setup
details.

To write to a specific filename:

```bash
./cli --dir /path/to/project --output bom.cdx.json
```

### Other output formats

Additional formats are available for debugging or manual analysis:

- **HTML** — a visual report you can open in a browser. Useful for reviewing
  results by hand.
  ```bash
  ./cli --dir /path/to/project --format html
  ```
- **JSON** (`simple`) — raw JSON to stdout. Useful for scripting or piping
  into tools like `jq`.
  ```bash
  ./cli --dir /path/to/project --format simple
  ```

---

## 4. Available Scanners

The tool combines five independent detection methods into a single scan. Each
one targets a different class of software component. All five run automatically
— there is nothing extra to configure.

### Manifest Parser (Package Manager Detection)

Identifies components declared through standard package managers such as npm,
pip, Maven, Go modules, Cargo, NuGet, APK, dpkg, RPM, and many more. This is
the broadest detector and covers most managed dependencies.

### Git (Repository Identity)

Reads `.git` metadata from the scanned directory to identify the repository
URL, current branch, and commit. This information is included in reports to
tie a scan result back to its source.

### Ocean Rules (C/C++ Component Detection)

A library of 670+ YAML-based rules that detect unmanaged C and C++ components
by looking for characteristic source files, headers, and version strings. This
is particularly valuable for embedded and firmware projects where libraries are
vendored directly into the source tree without a package manager.

### Build System Detection

Parses build-system manifests from OpenWrt, Buildroot, Yocto, Autotools,
CMake, Meson, Bazel, Visual Studio, and others. Extracts component names and
versions from the build configuration itself, catching dependencies that
package-manager scanners miss.

### AUTOSAR Detection

Extracts module metadata from AUTOSAR manifest files, identifying components
in automotive software stacks that follow the AUTOSAR standard.

---

## 5. Uploading Results to Finite State

You can upload the generated CycloneDX SBOM directly to Finite State. This
requires three pieces of information and an API token.

### 5a. Get your API token

Obtain an API token from your Finite State account. You can provide it in one
of two ways:

**Option A — Environment variable (recommended):**

```bash
export FINITE_STATE_AUTH_TOKEN="your-api-token-here"
```

**Option B — CLI flag:**

```bash
./cli ... --api-token "your-api-token-here"
```

The environment variable is recommended so the token does not appear in your
shell history.

### 5b. Set the domain (optional)

If your environment already has `FINITE_STATE_DOMAIN` set (e.g. by other
Finite State tools), the scanner will automatically derive the API URL from it.
The variable should contain the bare domain without a scheme or path:

```bash
export FINITE_STATE_DOMAIN="customer.finitestate.io"
```

This is equivalent to passing `--api-url https://customer.finitestate.io/api`.
If both `--api-url` and `FINITE_STATE_DOMAIN` are set, the explicit flag wins.

### 5c. Run the scan with upload

Pass the API URL (or set `FINITE_STATE_DOMAIN`), project name, and project
version alongside the token:

```bash
export FINITE_STATE_AUTH_TOKEN="your-api-token-here"

./cli \
  --dir /path/to/project \
  --api-url https://platform.finitestate.io/api \
  --project-name "My Project" \
  --project-version "1.0.0"
```

Or, if you already have both `FINITE_STATE_DOMAIN` and `FINITE_STATE_AUTH_TOKEN`
in your environment:

```bash
./cli \
  --dir /path/to/project \
  --project-name "My Project" \
  --project-version "1.0.0"
```

That's it. The scanner will:

1. Scan the directory using all five detectors.
2. Generate a CycloneDX SBOM for upload (CycloneDX is always used for uploads).
3. Create the project and version in Finite State if they don't already exist.
4. Upload the SBOM.

You can combine upload with local output by adding `--output`. The local output
format is inferred from the filename when `--format` is not set:

- `.cdx.json` => CycloneDX JSON
- `.html` / `.htm` => HTML report
- `.json` => simple JSON (debug)

Uploads still send CycloneDX regardless of the local output format.

```bash
./cli \
  --dir /path/to/project \
  --api-url https://platform.finitestate.io/api \
  --project-name "My Project" \
  --project-version "1.0.0" \
  --output bom.cdx.json
```

This saves the CycloneDX file locally **and** uploads it.

To upload while also saving an HTML report locally:

```bash
./cli \
  --dir /path/to/project \
  --api-url https://platform.finitestate.io/api \
  --project-name "My Project" \
  --project-version "1.0.0" \
  --output report.html
```

---

## 6. Excluding Files from a Scan

If the scanner picks up directories you want to ignore (vendored copies,
test fixtures, etc.), create a `.fsignore` file in the root of the directory
being scanned. It uses the same syntax as `.gitignore`:

```
# Ignore vendored third-party code
vendor/
third_party/

# Ignore test data
**/testdata/**
```

The embedded default configuration already excludes `node_modules/`,
`vendor/`, and `.git/` from the Ocean and build-system file walk. The
`.fsignore` file lets you add project-specific exclusions on top of those
defaults.

---

## 7. Customizing the Configuration

The standalone binary ships with a sensible default configuration embedded
inside it. You don't need a config file to run a scan, but you can export,
edit, and use a custom one if you need to change behavior.

### Export the embedded config

Dump the built-in configuration to a file so you have a starting point:

```bash
./cli --dump-embedded-config config.yaml
```

Use `-` instead of a filename to print it to stdout:

```bash
./cli --dump-embedded-config -
```

### What you can change

The config file is YAML. The key sections are:

```yaml
# Package types to exclude entirely from output
exclude_types:
  - github-action
  - github-action-workflow

# Package types to categorize as "infrastructure" (shown separately in HTML)
infrastructure_types:
  - github-action
  - github-action-workflow
  - binary

# Output settings
output:
  format: ""            # Empty = auto-save CycloneDX to timestamped file; or set cyclonedx, simple, full, html
  include_git_info: true

# Glob patterns excluded from the Ocean and build-system file walk
exclude_paths:
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/.git/**"

# Enable or disable individual detectors
detectors:
  manifest_parser:
    enabled: true
  git:
    enabled: true
  ocean:
    enabled: true
    rules_dir: ../ocean/rules   # Path to rules (ignored in standalone builds)
    top_level_only: false        # Suppress nested detections when top-level matches
  autosar:
    enabled: true
  build_system:
    enabled: true
```

Common modifications:

- **Disable a detector** — set `enabled: false` under the detector you want to
  skip (e.g., disable AUTOSAR if you're not scanning automotive software).
- **Exclude additional paths** — add glob patterns to `exclude_paths` to skip
  directories from the Ocean and build-system file walk.
- **Exclude package types** — add types to `exclude_types` to drop them from
  output entirely (e.g., `binary` if you don't want binary detections).
- **Change the default output format** — set `output.format` to `cyclonedx`,
  `simple`, `full`, or `html`. When left empty, the scanner writes a
  CycloneDX file with a timestamped name automatically.

### Top-level-only mode

When scanning large codebases — especially embedded or firmware projects — it's
common to have a top-level component (e.g., an RTOS like ThreadX, or an OS
like FreeBSD) that contains many smaller libraries within it. By default the
scanner reports every component it finds, which can mean the top-level project
and all of its internal sub-libraries appear as separate items.

Setting `top_level_only: true` under the Ocean detector changes this behavior.
When a rule marked `top_level: true` matches a directory, all other detections
at or below that directory are suppressed — only the top-level component is
reported. Detections outside that directory are unaffected.

The quickest way to enable it is with the `--top-level` CLI flag:

```bash
./cli --dir /path/to/project --top-level --output bom.cdx.json
```

Or set it permanently in your config file:

```yaml
detectors:
  ocean:
    enabled: true
    top_level_only: true
```

**When to enable it:**

- You're scanning a firmware image or OS tree and want the SBOM to reflect
  high-level components rather than every vendored sub-library.
- You're seeing a lot of noise from internal libraries that are part of a
  larger project you've already identified.

**When to leave it off (the default):**

- You need full visibility into every individual library, even those nested
  inside larger projects.
- You're doing vulnerability analysis and need to know about every component
  regardless of how it's organized on disk.

### Using external rules

You can point the scanner at your own rules directory with `--rules`:

```bash
./cli --dir /path/to/project --rules /path/to/rules
```

All YAML files in the directory must be valid. If any rule file is corrupt or
contains invalid YAML, the scan will fail with an error rather than silently
skipping the bad file. This ensures you always get consistent results.

### Use your custom config

Pass the edited file with `--config`:

```bash
./cli --dir /path/to/project --config my-config.yaml
```

When `--config` is provided, the scanner uses your file instead of the embedded
defaults. Any setting you omit from your file falls back to the built-in
default.

---

## 8. Providing Feedback on Scan Results

If you notice that the scanner missed a component or identified something
incorrectly, you can use the `--feedback` option to generate a structured
feedback report. This helps us improve detection accuracy and expand our
rule coverage.

### Running a feedback session

Add `--feedback` to your normal scan command (CycloneDX format is selected automatically):

```bash
./cli --dir /path/to/project --feedback --output project.cdx.json
```

After the scan completes your default browser opens with an interactive
review of the scanned directory tree. From there you can:

- **Mark missed packages** — right-click a directory or file and select
  *Mark missed* to tell us a component was not detected.
- **Flag incorrect detections** — right-click a detection card and select
  *Mark incorrect* to report a false positive, wrong version, or
  misidentified component.
- **Add notes** — right-click and select *Add/edit note…* to provide
  additional context (e.g. "this is vendored libfoo 2.1").
- **Undo** — click *Remove* next to any item in the feedback list.

### Git-only detections

The scanner automatically detects git repositories within the scanned
directory. When a git repository is found that no other detector (Ocean
rules, manifest parser, build system) has covered, it is included in the
feedback list as a **git** entry by default. These entries show us which
subprojects need new or expanded detection rules, so please leave them in
the feedback bundle.

### Generating the feedback file

When you are done reviewing, click **Generate feedback**. A timestamped JSON
file (e.g. `myproject-feedback-20260224-143012.json`) is written to the
current working directory. Send this file back to us along with any other
context that might help.

The feedback server shuts down automatically once the file is generated.

---

## 9. Quick Reference


| What you want to do               | Command                                                                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Quick scan (auto-saves CycloneDX) | `./cli --dir /path`                                                                                                             |
| CycloneDX SBOM to specific file   | `./cli --dir /path --output bom.cdx.json`                                                                                       |
| Top-level components only         | `./cli --dir /path --top-level --output bom.cdx.json`                                                                           |
| Upload to Finite State            | `./cli --dir /path --api-url URL --project-name NAME --project-version VER`                                                     |
| Upload via env vars               | `export FINITE_STATE_DOMAIN=... FINITE_STATE_AUTH_TOKEN=...` then `./cli --dir /path --project-name NAME --project-version VER` |
| Upload + save locally             | `... --api-url URL --project-name NAME --project-version VER --output bom.cdx.json`                                             |
| Export embedded config            | `./cli --dump-embedded-config config.yaml`                                                                                      |
| Use a custom config               | `./cli --dir /path --config my-config.yaml`                                                                                     |
| Use external rules directory      | `./cli --dir /path --rules /path/to/rules`                                                                                      |
| Feedback on scan results          | `./cli --dir /path --feedback --output bom.cdx.json`                                                                            |
| HTML report (debug)               | `./cli --dir /path --format html`                                                                                               |
| JSON to stdout (debug)            | `./cli --dir /path --format simple`                                                                                             |
| See all options                   | `./cli --help`                                                                                                                  |


