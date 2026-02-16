# Finite State Report Kit — Setup Script (PowerShell)
#
# Installs fs-report via pipx and configures domain + API token.
#
# Usage:
#   irm https://raw.githubusercontent.com/.../setup.ps1 | iex
#   .\setup.ps1                    # from a local clone
#   .\setup.ps1 -FromSource        # install from current directory

param (
    [switch]$FromSource
)

$ErrorActionPreference = "Stop"

function Write-Info  ($msg) { Write-Host $msg -ForegroundColor Cyan }
function Write-Ok    ($msg) { Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn  ($msg) { Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Fail  ($msg) { Write-Host "✗ $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Info "=== Finite State Report Kit Setup ==="
Write-Host ""

# ── 1. Check Python >= 3.11 ─────────────────────────────────────────

$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1 | Select-String -Pattern '(\d+)\.(\d+)'
        if ($ver.Matches) {
            $major = [int]$ver.Matches[0].Groups[1].Value
            $minor = [int]$ver.Matches[0].Groups[2].Value
            if ($major -ge 3 -and $minor -ge 11) {
                $python = $cmd
                break
            }
        }
    }
    catch { }
}

if (-not $python) {
    Write-Fail "Python 3.11+ is required but not found. Install from https://python.org"
}
Write-Ok "Python found: $(& $python --version)"

# ── 2. Check / install pipx ─────────────────────────────────────────

$hasPipx = Get-Command pipx -ErrorAction SilentlyContinue
if (-not $hasPipx) {
    Write-Warn "pipx not found. Installing..."
    & $python -m pip install --user pipx
    & $python -m pipx ensurepath 2>$null
    $env:PATH = "$env:USERPROFILE\.local\bin;$env:PATH"
}

$hasPipx = Get-Command pipx -ErrorAction SilentlyContinue
if (-not $hasPipx) {
    Write-Fail "pipx installation failed. Install manually: https://pipx.pypa.io"
}
Write-Ok "pipx found: $(pipx --version)"

# ── 3. Install fs-report ────────────────────────────────────────────

Write-Info "Installing fs-report..."
if ($FromSource -or (Test-Path "pyproject.toml")) {
    pipx install . --force
}
else {
    try {
        pipx install fs-report --force
    }
    catch {
        pipx install "git+https://github.com/FiniteStateInc/fs-report.git" --force
    }
}
Write-Ok "fs-report installed"

# ── 4. Prompt for domain ────────────────────────────────────────────

Write-Host ""
$domain = Read-Host "Finite State domain (e.g., customer.finitestate.io)"

# ── 5. Prompt for API token ─────────────────────────────────────────

Write-Host ""
Write-Host "The API token will be stored as a persistent user environment variable." -ForegroundColor DarkGray
Write-Host "Tokens should be rotated periodically per your organization's policy." -ForegroundColor DarkGray
$secureToken = Read-Host "API token" -AsSecureString
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
)

if ($token) {
    [Environment]::SetEnvironmentVariable("FINITE_STATE_AUTH_TOKEN", $token, "User")
    Write-Ok "Token stored as persistent user environment variable"
}

# ── 6. Generate config file ─────────────────────────────────────────

$configDir = Join-Path $HOME ".fs-report"
$configFile = Join-Path $configDir "config.yaml"

if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

$configContent = @"
# Finite State Report Kit configuration
# CLI flags override these values; env vars override config file.
domain: $domain
output_dir: ./output
finding_types: cve
current_version_only: true
request_delay: 0.5
batch_size: 5
"@

Set-Content -Path $configFile -Value $configContent -Encoding UTF8
Write-Ok "Config written to $configFile"

# ── 7. Verify ────────────────────────────────────────────────────────

Write-Host ""
Write-Info "Verifying installation..."
$fsReport = Get-Command fs-report -ErrorAction SilentlyContinue
if ($fsReport) {
    fs-report --version
    Write-Ok "Installation verified"
}
else {
    Write-Warn "fs-report not found in PATH. Restart your terminal to pick up PATH changes."
}

# ── 8. Summary ───────────────────────────────────────────────────────

Write-Host ""
Write-Info "Setup complete!"
Write-Host ""
Write-Host "  Run reports:      fs-report run --recipe `"Executive Summary`""
Write-Host "  Interactive TUI:  fs-report"
Write-Host "  See all commands: fs-report --help"
Write-Host ""
Write-Host "Restart your terminal for environment variable changes to take effect." -ForegroundColor DarkGray
