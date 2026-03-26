#!/bin/sh
set -e

# fs-cli CI wrapper
# Downloads (if needed) and runs fs-cli with the correct platform binary.
# All arguments are forwarded to fs-cli.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/run-fs-cli.sh | sh -s -- scan --token "$TOKEN"
#
# Or download once and invoke directly:
#   ./run-fs-cli.sh scan --token "$TOKEN" --project-name my-project
#
# Environment variables:
#   FS_CLI_DIR    Directory to cache the binary (default: .fs-cli in working dir)
#   FS_CLI_PATH   Skip download entirely and use this binary path

BASE_URL="https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/latest"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf "${GREEN}[fs-cli]${NC} %s\n" "$1" >&2; }
warn()  { printf "${YELLOW}[fs-cli]${NC} %s\n" "$1" >&2; }
error() { printf "${RED}[fs-cli]${NC} %s\n" "$1" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) error "Unsupported operating system: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
}

download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        error "Neither curl nor wget found. Please install one and retry."
    fi
}

verify_checksum() {
    binary_path="$1"
    binary_name="$2"
    checksums_path="$3"

    expected="$(grep "${binary_name}" "${checksums_path}" | awk '{print $1}')"
    if [ -z "$expected" ]; then
        warn "No checksum found for ${binary_name}, skipping verification"
        return 0
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "${binary_path}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "${binary_path}" | awk '{print $1}')"
    else
        warn "No checksum tool found, skipping verification"
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        error "Checksum mismatch! Expected ${expected}, got ${actual}"
    fi
}

ensure_binary() {
    os="$(detect_os)"
    arch="$(detect_arch)"

    ext=""
    if [ "$os" = "windows" ]; then
        ext=".exe"
    fi

    binary_name="fs-cli-${os}-${arch}${ext}"
    cache_dir="${FS_CLI_DIR:-.fs-cli}"
    cached_bin="${cache_dir}/fs-cli${ext}"

    # Check if cached binary exists and matches the latest version
    if [ -x "$cached_bin" ]; then
        # Fetch remote version to see if we need to update
        tmpver="$(mktemp)"
        trap_cleanup="rm -f \"$tmpver\""
        if download "${BASE_URL}/VERSION" "$tmpver" 2>/dev/null; then
            remote_version="$(cat "$tmpver")"
            local_version="$("$cached_bin" version 2>/dev/null || echo "")"
            rm -f "$tmpver"
            if [ -n "$remote_version" ] && [ "$local_version" = "$remote_version" ]; then
                FS_CLI_BIN="$cached_bin"
                return 0
            fi
            info "Update available (${local_version:-unknown} -> ${remote_version})"
        else
            rm -f "$tmpver"
            # Can't reach remote; use cached binary
            info "Using cached binary (offline)"
            FS_CLI_BIN="$cached_bin"
            return 0
        fi
    fi

    # Download binary
    mkdir -p "$cache_dir"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"$tmpdir\"" EXIT

    info "Downloading ${binary_name}..."
    download "${BASE_URL}/${binary_name}" "${tmpdir}/${binary_name}"
    download "${BASE_URL}/checksums.txt" "${tmpdir}/checksums.txt"

    info "Verifying checksum..."
    verify_checksum "${tmpdir}/${binary_name}" "$binary_name" "${tmpdir}/checksums.txt"

    mv "${tmpdir}/${binary_name}" "$cached_bin"
    chmod +x "$cached_bin"

    version="$("$cached_bin" version 2>/dev/null || echo "unknown")"
    info "Ready (${version})"

    FS_CLI_BIN="$cached_bin"
}

main() {
    # If FS_CLI_PATH is set, use that binary directly
    if [ -n "${FS_CLI_PATH:-}" ]; then
        if [ ! -x "$FS_CLI_PATH" ]; then
            error "FS_CLI_PATH is set to '${FS_CLI_PATH}' but it is not executable"
        fi
        FS_CLI_BIN="$FS_CLI_PATH"
    else
        ensure_binary
    fi

    # Suppress the built-in update check since we handle it ourselves
    export FS_NO_UPDATE_CHECK=1

    exec "$FS_CLI_BIN" "$@"
}

main "$@"
