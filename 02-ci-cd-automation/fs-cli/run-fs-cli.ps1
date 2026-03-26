# fs-cli CI wrapper for Windows
# Downloads (if needed) and runs fs-cli with the correct platform binary.
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

    # Check cached binary and version
    if (Test-Path $cachedBin) {
        $tmpVer = [System.IO.Path]::GetTempFileName()
        try {
            Get-RemoteFile "$BaseUrl/VERSION" $tmpVer 2>$null
            $remoteVersion = (Get-Content $tmpVer).Trim()
            $localVersion = & $cachedBin version 2>$null
            Remove-Item $tmpVer -ErrorAction SilentlyContinue
            if ($remoteVersion -and ($localVersion -eq $remoteVersion)) {
                return $cachedBin
            }
            Write-Info "Update available ($localVersion -> $remoteVersion)"
        } catch {
            Remove-Item $tmpVer -ErrorAction SilentlyContinue
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

$env:FS_NO_UPDATE_CHECK = "1"
& $bin @args
exit $LASTEXITCODE
