# fs-cli

Finite State CLI — scans project dependencies across 19 ecosystems and uploads SBOM-grade package inventories to the Finite State platform.

> **⚠️ Final release — fs-cli now upgrades itself through the Finite State platform**
>
> v2.0.17 is the final release published to this directory. From now on, fs-cli receives updates directly from the Finite State platform: the first time it runs against an upgraded platform, it automatically upgrades itself to the next-generation Finite State CLI (v2.3.x) — same `fs-cli` binary name, compatible commands and flags — and continues your command. If your platform has not been upgraded yet, fs-cli keeps working as before (you may see an informational "auto-update service is temporarily unavailable" log line, which is safe to ignore).
>
> You can also download the next-generation CLI directly from the Finite State platform UI — see the [CLI documentation](https://docs.finitestate.io/docs/command-line-interface/v2/).
>
> To opt out of automatic updates, set `FS_SKIP_UPDATE=1` or pass `--no-update-check`.

For full usage, flags, and CI/CD integration guidance, see:

- **[User Guide](./latest/USER_GUIDE.md)**
- **[README](./latest/README.md)**
- **[Changelog](./latest/CHANGELOG.md)**

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
| `run-fs-cli.sh` | CI wrapper for Linux/macOS (bootstraps fs-cli, upgrades pre-v2.0.17 caches once, then reuses the cached self-updating binary) |
| `run-fs-cli.ps1` | CI wrapper for Windows (PowerShell equivalent) |
| `latest/` | Current release binaries, checksums, changelog, and documentation |
