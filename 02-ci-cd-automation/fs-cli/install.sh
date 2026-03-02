#!/bin/sh
set -e

# fs-cli installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/install.sh | sh
#   curl -fsSL .../install.sh | INSTALL_DIR=/tmp sh

BASE_URL="https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/02-ci-cd-automation/fs-cli/latest"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; exit 1; }

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

# Use curl if available, fall back to wget
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

main() {
    os="$(detect_os)"
    arch="$(detect_arch)"

    ext=""
    if [ "$os" = "windows" ]; then
        ext=".exe"
    fi

    binary="fs-cli-${os}-${arch}${ext}"
    info "Detected platform: ${os}/${arch}"

    # Determine install directory
    install_dir="${INSTALL_DIR:-}"
    if [ -z "$install_dir" ]; then
        if [ -w /usr/local/bin ]; then
            install_dir="/usr/local/bin"
        else
            install_dir="$HOME/.local/bin"
            mkdir -p "$install_dir"
        fi
    fi

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    info "Downloading ${binary}..."
    download "${BASE_URL}/${binary}" "${tmpdir}/${binary}"
    download "${BASE_URL}/checksums.txt" "${tmpdir}/checksums.txt"

    # Verify checksum
    info "Verifying checksum..."
    expected="$(grep "${binary}" "${tmpdir}/checksums.txt" | awk '{print $1}')"
    if [ -z "$expected" ]; then
        warn "No checksum found for ${binary}, skipping verification"
    else
        if command -v sha256sum >/dev/null 2>&1; then
            actual="$(sha256sum "${tmpdir}/${binary}" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            actual="$(shasum -a 256 "${tmpdir}/${binary}" | awk '{print $1}')"
        else
            warn "Neither sha256sum nor shasum found, skipping verification"
            actual="$expected"
        fi

        if [ "$actual" != "$expected" ]; then
            error "Checksum mismatch! Expected ${expected}, got ${actual}"
        fi
        info "Checksum verified"
    fi

    # Install
    dest="${install_dir}/fs-cli${ext}"
    mv "${tmpdir}/${binary}" "$dest"
    chmod +x "$dest"

    info "Installed fs-cli to ${dest}"
    info "Version: $(${dest} version 2>/dev/null || echo 'unknown')"
}

main
