# fs-cli installer for Windows
# Usage:
#   irm https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.ps1 | iex
#   $env:INSTALL_DIR = "C:\tools"; irm .../install.ps1 | iex

$ErrorActionPreference = "Stop"

$BASE_URL = "https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/latest"

function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

function Detect-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Write-Err "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Main {
    $os = "windows"
    $arch = Detect-Arch

    $binary = "fs-cli-${os}-${arch}.exe"
    Write-Info "Detected platform: ${os}/${arch}"

    # Determine install directory
    $installDir = $env:INSTALL_DIR
    if (-not $installDir) {
        $installDir = Join-Path $env:LOCALAPPDATA "fs-cli"
    }
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        Write-Info "Downloading ${binary}..."
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri "${BASE_URL}/${binary}" -OutFile (Join-Path $tmpDir $binary) -UseBasicParsing
        Invoke-WebRequest -Uri "${BASE_URL}/checksums.txt" -OutFile (Join-Path $tmpDir "checksums.txt") -UseBasicParsing

        # Verify checksum
        Write-Info "Verifying checksum..."
        $checksums = Get-Content (Join-Path $tmpDir "checksums.txt")
        $line = $checksums | Where-Object { $_ -match $binary }
        if (-not $line) {
            Write-Warn "No checksum found for ${binary}, skipping verification"
        } else {
            $expected = ($line -split '\s+')[0]
            $actual = (Get-FileHash (Join-Path $tmpDir $binary) -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expected) {
                Write-Err "Checksum mismatch! Expected ${expected}, got ${actual}"
            }
            Write-Info "Checksum verified"
        }

        # Install
        $dest = Join-Path $installDir "fs-cli.exe"
        Move-Item -Force (Join-Path $tmpDir $binary) $dest

        Write-Info "Installed fs-cli to ${dest}"

        # Add to PATH if not already present
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$installDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
            $env:Path = "$env:Path;$installDir"
            Write-Info "Added ${installDir} to user PATH (restart your terminal for it to take effect)"
        }

        # Print version
        try {
            $version = & $dest version 2>$null
            Write-Info "Version: $version"
        } catch {
            Write-Info "Version: unknown"
        }
    } finally {
        Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    }
}

Main
