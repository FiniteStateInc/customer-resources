# fs-cli CI wrapper for Windows
# Bootstraps fs-cli on first run (downloads the correct platform binary),
# then reuses the cached binary. fs-cli 2.0.17+ keeps itself up to date from
# the Finite State platform, so the wrapper never re-downloads a current
# binary; a cached binary older than the published release (which cannot
# self-update) is upgraded once.
# All arguments are forwarded to fs-cli.
#
# Usage:
#   irm https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/run-fs-cli.ps1 | iex
#   .\run-fs-cli.ps1 scan --token $env:FS_TOKEN --project-name my-project
#
# Environment variables:
#   FS_CLI_DIR    Directory to cache the binary (default: .fs-cli in working dir)
#   FS_CLI_PATH   Skip download entirely and use this binary path

$ErrorActionPreference = "Stop"

$BaseUrl = "https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/latest"

function Write-Info($msg)  { Write-Host "[fs-cli] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[fs-cli] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "[fs-cli] $msg" -ForegroundColor Red; exit 1 }

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64"  { return "amd64" }
        "ARM64"  { return "arm64" }
        default  { Write-Err "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Get-RemoteFile($url, $dest) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    } catch {
        Write-Err "Download failed: $url`n$_"
    }
}

# Returns $true when release $a is numerically older than release $b.
# Accepts values like "v2.0.16" or "2.3.19-dev+abc" (leading v and any -/+
# suffix are ignored). Returns $false on anything unparseable so the caller
# prefers the cached binary rather than looping on downloads.
function Test-VersionOlder($a, $b) {
    try {
        $pa = [version](($a -replace '^v', '') -replace '[-+].*$', '')
        $pb = [version](($b -replace '^v', '') -replace '[-+].*$', '')
        return $pa -lt $pb
    } catch {
        return $false
    }
}

function Test-Checksum($filePath, $binaryName, $checksumsPath) {
    $checksums = Get-Content $checksumsPath
    $line = $checksums | Where-Object { $_ -match $binaryName }
    if (-not $line) {
        Write-Warn "No checksum found for $binaryName, skipping verification"
        return
    }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        Write-Err "Checksum mismatch! Expected $expected, got $actual"
    }
}

function Ensure-Binary {
    $arch = Get-Arch
    $binaryName = "fs-cli-windows-${arch}.exe"
    $cacheDir = if ($env:FS_CLI_DIR) { $env:FS_CLI_DIR } else { ".fs-cli" }
    $cachedBin = Join-Path $cacheDir "fs-cli.exe"

    # Use the cached binary if present. fs-cli 2.0.17+ updates itself from
    # the Finite State platform, so the wrapper never re-downloads a current
    # binary — but older cached versions cannot self-update, so upgrade them
    # once to the published release.
    if (Test-Path $cachedBin) {
        $localVersion = ((& $cachedBin version 2>$null) -split '\s+')[1]
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $remoteVersion = (Invoke-WebRequest -Uri "$BaseUrl/VERSION" -UseBasicParsing).Content.Trim()
            if (Test-VersionOlder $localVersion $remoteVersion) {
                Write-Info "Cached fs-cli $localVersion predates $remoteVersion; upgrading"
            } else {
                return $cachedBin
            }
        } catch {
            Write-Info "Using cached binary (offline)"
            return $cachedBin
        }
    }

    # Download
    if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir | Out-Null }
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tmpDir | Out-Null

    try {
        Write-Info "Downloading $binaryName..."
        Get-RemoteFile "$BaseUrl/$binaryName" (Join-Path $tmpDir $binaryName)
        Get-RemoteFile "$BaseUrl/checksums.txt" (Join-Path $tmpDir "checksums.txt")

        Write-Info "Verifying checksum..."
        Test-Checksum (Join-Path $tmpDir $binaryName) $binaryName (Join-Path $tmpDir "checksums.txt")

        Move-Item (Join-Path $tmpDir $binaryName) $cachedBin -Force
    } finally {
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    $version = & $cachedBin version 2>$null
    if (-not $version) { $version = "unknown" }
    Write-Info "Ready ($version)"

    return $cachedBin
}

# Main
if ($env:FS_CLI_PATH) {
    if (-not (Test-Path $env:FS_CLI_PATH)) {
        Write-Err "FS_CLI_PATH is set to '$($env:FS_CLI_PATH)' but file does not exist"
    }
    $bin = $env:FS_CLI_PATH
} else {
    $bin = Ensure-Binary
}

& $bin @args
exit $LASTEXITCODE
