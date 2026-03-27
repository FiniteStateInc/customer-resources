# 02 - CI/CD Automation

This section covers integrating scanning into your CI/CD pipelines and automating security checks as part of your development workflow.

## Available Tools

### Finite State CLI 2.0 (`fs-cli`)

`fs-cli` scans your repo's dependencies (SCA/SBOM-grade inventory) and uploads results to the Finite State platform. It's a **single binary** with **no runtime dependencies**.

- **Current bundled version**: see `./fs-cli/latest/VERSION`

#### Install (persistent)

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
```

The installer detects your OS and architecture, downloads the correct binary, verifies its SHA-256 checksum, and installs to `/usr/local/bin` (or `~/.local/bin`). Override with `INSTALL_DIR`:

```sh
curl -fsSL .../install.sh | INSTALL_DIR=/opt/tools sh
```

#### Run without installing (CI wrapper)

For **Jenkins, Bamboo**, and other CI agents that need a zero-install, single-command approach:

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/run-fs-cli.sh \
  | sh -s -- scan --name myproject .
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/run-fs-cli.ps1 -OutFile run-fs-cli.ps1
.\run-fs-cli.ps1 scan --name myproject .
```

The wrapper scripts auto-detect the platform, download and cache the binary in `.fs-cli/`, verify checksums, and forward all arguments to `fs-cli`. On subsequent runs they reuse the cached binary and auto-update when a new version is available.

**Environment variables for the wrapper:**

| Variable | Description |
|----------|-------------|
| `FS_CLI_DIR` | Cache directory (default: `.fs-cli` in working dir) |
| `FS_CLI_PATH` | Skip download and use this binary path directly |

#### Configure credentials

Set these environment variables (either style works):

```sh
export FS_TOKEN="your-api-token"
export FS_ENDPOINT="your-domain.finitestate.io"
# or (compat)
export FINITE_STATE_AUTH_TOKEN="your-api-token"
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"
```

#### CI scan examples

```sh
# Dry run (prints JSON, doesn't upload)
fs-cli scan --name myproject --test .

# Upload dependency inventory for a single project
fs-cli scan --name myproject .

# Monorepo scan (recursive ecosystem detection)
fs-cli scan --name myproject --all .

# Pin to a specific version string
fs-cli scan --name myproject --version "1.2.3" .

# Upload a binary artifact
fs-cli upload --name myproject --version "1.2.3" firmware.bin

# Import an existing SBOM
fs-cli import --name myproject --version "1.2.3" sbom.cdx.json
```

#### Self-update

Once installed, `fs-cli` can update itself:

```sh
fs-cli update
```

It also checks for new versions after each command and prints a notification when an update is available. Suppress with `FS_NO_UPDATE_CHECK=1`.

See `./fs-cli/latest/README.md` and `./fs-cli/latest/USER_GUIDE.md` for the full flag reference and CI/CD guidance.

---

### BETA: C/C++ Scanner (`fs-scan`, from `syft-mod`)

This section includes the **BETA unmanaged C/C++ component scanner** packaged as standalone binaries under `./fs-scan BETA/`.

- **Current bundled version**: `syft-mod v1.0.28` (see `./fs-scan BETA/syft-mod_v1.0.28_RELEASE_NOTES.md`)

- **Binaries** (pick the one matching your runner OS/arch):
  - **macOS**: `fs-scan BETA/fs-scan_mac_arm64`, `fs-scan BETA/fs-scan_mac_amd64`
  - **Linux**: `fs-scan BETA/fs-scan_linux_arm64`, `fs-scan BETA/fs-scan_linux_amd64`
  - **Windows**: `fs-scan BETA/fs-scan_windows_arm64.exe`, `fs-scan BETA/fs-scan_windows_amd64.exe`

- **Recommended usage in CI**: copy/rename the platform binary to `./fs-scan` (or `fs-scan.exe`) and run it from your job workspace.

```sh
cp "fs-scan BETA/fs-scan_linux_amd64" ./fs-scan
chmod +x ./fs-scan
./fs-scan --version
```

- **Example scan to a CycloneDX SBOM file**:

```sh
./fs-scan --dir . --output sbom.cdx.json
```

- **Example scan + upload to Finite State** (requires project name/version):

```sh
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"
export FINITE_STATE_AUTH_TOKEN="your-api-token"

./fs-scan \
  --dir . \
  --project-name "myproject" \
  --project-version "1.0.0" \
  --output sbom.cdx.json
```

The `fs-scan BETA/Unmanaged.C.and.C++.projects.csv` file is included as a companion dataset for unmanaged C/C++ component identification workflows.

For complete instructions (including signature verification, output formats, and upload options), see:
- `./fs-scan BETA/README.md`
- `./fs-scan BETA/QUICKSTART.md`
