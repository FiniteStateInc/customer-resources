# 02 - CI/CD Automation

This section covers integrating scanning into your CI/CD pipelines and automating security checks as part of your development workflow.

## Available Tools

### Finite State CLI 2.0 (`fs-cli`)

`fs-cli` scans your repo’s dependencies (SCA/SBOM-grade inventory) and uploads results to the Finite State platform. It’s a **single binary** with **no runtime dependencies**.

- **Install (recommended)**:

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
```

- **Configure credentials** (either style works):

```sh
export FS_TOKEN="your-api-token"
export FS_ENDPOINT="your-domain.finitestate.io"
# or (compat)
export FINITE_STATE_AUTH_TOKEN="your-api-token"
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"
```

- **CI-friendly scan examples**:

```sh
# Dry run (prints what would be uploaded)
fs-cli scan --name myproject --test .

# Upload dependency inventory for a repo (monorepo-friendly)
fs-cli scan --name myproject --all .
```

See `./fs-cli/latest/README.md` and `./fs-cli/latest/USER_GUIDE.md` for full usage, flags, and CI/CD guidance.

### BETA: C/C++ Scanner (syft-mod CLI)

This is the **BETA C/C++ component scanner** (from `FiniteStateInc/syft-mod` release `v1.0.24`) packaged as platform-specific binaries in `./BETA/`, along with checksums and signatures.

- **Binaries** (pick the one matching your runner OS/arch):
  - **macOS**: `BETA/cli_mac_arm64`, `BETA/cli_mac_amd64`
  - **Linux**: `BETA/cli_linux_arm64`, `BETA/cli_linux_amd64`
  - **Windows**: `BETA/cli_windows_arm64.exe`, `BETA/cli_windows_amd64.exe`

- **Common flags** (run `--help` for the full list):

```sh
./BETA/cli_mac_arm64 --help
```

- **Example scan to CycloneDX SBOM file**:

```sh
./BETA/cli_mac_arm64 --dir . --format cyclonedx --output sbom.cdx.json
```

- **Example scan + upload to Finite State**:

```sh
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"
export FINITE_STATE_AUTH_TOKEN="your-api-token"

./BETA/cli_mac_arm64 \
  --dir . \
  --api-url "https://$FINITE_STATE_DOMAIN/api" \
  --project-name "myproject" \
  --project-version "1.0.0" \
  --format cyclonedx \
  --output sbom.cdx.json
```

The `BETA/Unmanaged.C.and.C++.projects.csv` file is included as a companion dataset for unmanaged C/C++ component identification workflows.

