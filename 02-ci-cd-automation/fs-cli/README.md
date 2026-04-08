# fs-cli

Finite State CLI — scans project dependencies across 19 ecosystems and uploads SBOM-grade package inventories to the Finite State platform.

For full usage, flags, and CI/CD integration guidance, see:

- **[User Guide](./latest/USER_GUIDE.md)**
- **[README](./latest/README.md)**

## Quick Start

**Install (macOS / Linux):**

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
```

**Install (Windows PowerShell):**

```powershell
irm https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.ps1 | iex
```

**Or run directly in CI (no install needed):**

```sh
curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/run-fs-cli.sh \
  | sh -s -- scan --name myproject .
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/run-fs-cli.ps1 -OutFile run-fs-cli.ps1
.\run-fs-cli.ps1 scan --name myproject .
```

## Contents

| File | Description |
|------|-------------|
| `install.sh` | One-line installer for macOS/Linux (detects OS/arch, verifies checksum) |
| `install.ps1` | One-line installer for Windows (PowerShell, verifies checksum) |
| `run-fs-cli.sh` | CI wrapper for Linux/macOS (downloads, caches, and runs fs-cli) |
| `run-fs-cli.ps1` | CI wrapper for Windows (PowerShell equivalent) |
| `latest/` | Current release binaries, checksums, and documentation |
