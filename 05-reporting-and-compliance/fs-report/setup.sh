#!/usr/bin/env bash
# Finite State Report Kit — Setup Script
#
# Installs fs-report via pipx and configures domain + API token.
#
# Usage:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/FiniteStateInc/customer-resources/main/05-reporting-and-compliance/fs-report/setup.sh)"
#   ./setup.sh                    # from a local clone
#   ./setup.sh --from-source      # install from current directory
#   ./setup.sh --from-source --yes # non-interactive (uses env vars)
set -euo pipefail

# When piped from curl, stdin is the pipe — redirect interactive reads to /dev/tty
if [ ! -t 0 ] && [ -e /dev/tty ]; then
    exec < /dev/tty
fi

BOLD='\033[1m'
CYAN='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
DIM='\033[2m'
RESET='\033[0m'

info()  { echo -e "${CYAN}${BOLD}$*${RESET}"; }
ok()    { echo -e "${GREEN}✓ $*${RESET}"; }
warn()  { echo -e "${YELLOW}⚠ $*${RESET}"; }
fail()  { echo -e "${RED}✗ $*${RESET}"; exit 1; }

FROM_SOURCE=false
YES_MODE=false
for arg in "$@"; do
    case "$arg" in
        --from-source) FROM_SOURCE=true ;;
        --yes|-y)      YES_MODE=true ;;
    esac
done

echo ""
info "=== Finite State Report Kit Setup ==="
echo ""

# ── 1. Check Python ≥ 3.11 ──────────────────────────────────────────

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python 3.11+ is required but not found. Install from https://python.org"
fi
ok "Python found: $($PYTHON --version)"

# ── 2. Check / install pipx ─────────────────────────────────────────

if ! command -v pipx &>/dev/null; then
    warn "pipx not found. Installing..."
    if command -v brew &>/dev/null; then
        brew install pipx
    else
        "$PYTHON" -m pip install --user pipx
    fi
    "$PYTHON" -m pipx ensurepath 2>/dev/null || true
    export PATH="$HOME/.local/bin:$PATH"
fi

if ! command -v pipx &>/dev/null; then
    fail "pipx installation failed. Install manually: https://pipx.pypa.io"
fi
ok "pipx found: $(pipx --version)"

# ── 3. Install fs-report ────────────────────────────────────────────

info "Installing fs-report..."
if [ "$FROM_SOURCE" = true ]; then
    pipx install . --force
elif [ -f "pyproject.toml" ] && grep -q 'name = "fs-report"' pyproject.toml 2>/dev/null; then
    pipx install . --force
else
    pipx install fs-report --force 2>/dev/null || \
        pipx install git+https://github.com/FiniteStateInc/customer-resources.git#subdirectory=05-reporting-and-compliance/fs-report --force
fi
ok "fs-report installed"

# ── 4. Detect shell rc and existing values ─────────────────────────

SHELL_RC=""
if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.bash_profile" ]; then
    SHELL_RC="$HOME/.bash_profile"
fi

_existing_domain="${FINITE_STATE_DOMAIN:-}"
_existing_token="${FINITE_STATE_AUTH_TOKEN:-}"

# ── 5. Prompt for domain ────────────────────────────────────────────

echo ""
if [ "$YES_MODE" = true ]; then
    domain="${_existing_domain}"
    if [ -z "$domain" ]; then
        fail "FINITE_STATE_DOMAIN must be set in --yes mode"
    fi
    ok "Domain: $domain (from environment)"
elif [ -n "$_existing_domain" ]; then
    read -rp "$(echo -e "${CYAN}Finite State domain${RESET} [${BOLD}$_existing_domain${RESET}]: ")" domain
    domain="${domain:-$_existing_domain}"
else
    read -rp "$(echo -e "${CYAN}Finite State domain${RESET} (e.g., customer.finitestate.io): ")" domain
fi

# ── 6. Prompt for API token ─────────────────────────────────────────

echo ""
if [ "$YES_MODE" = true ]; then
    token="${_existing_token}"
    if [ -z "$token" ]; then
        fail "FINITE_STATE_AUTH_TOKEN must be set in --yes mode"
    fi
    ok "Token: from environment (****${token: -4})"
elif [ -n "$_existing_token" ]; then
    _masked="****${_existing_token: -4}"
    echo -e "${DIM}Current token ends in ${_masked}. Press Enter to keep it.${RESET}"
    read -rsp "$(echo -e "${CYAN}API token${RESET} [${BOLD}keep existing${RESET}]: ")" token
    echo ""
    token="${token:-$_existing_token}"
else
    echo -e "${DIM}The API token will be stored in your shell profile as an environment variable.${RESET}"
    echo -e "${DIM}Tokens should be rotated periodically per your organization's policy.${RESET}"
    read -rsp "$(echo -e "${CYAN}API token${RESET}: ")" token
    echo ""
fi

if [ -n "$token" ] && [ -n "$SHELL_RC" ]; then
    if [ "$token" = "$_existing_token" ]; then
        ok "Token unchanged"
    else
        if grep -q "FINITE_STATE_AUTH_TOKEN" "$SHELL_RC" 2>/dev/null; then
            sed -i.bak '/FINITE_STATE_AUTH_TOKEN/d' "$SHELL_RC"
        fi
        echo "export FINITE_STATE_AUTH_TOKEN=\"$token\"  # Finite State API — rotate periodically" >> "$SHELL_RC"
        ok "Token saved to $SHELL_RC"
    fi
elif [ -n "$token" ]; then
    warn "Could not find shell profile. Set FINITE_STATE_AUTH_TOKEN manually."
fi

# ── 7. Generate config file ─────────────────────────────────────────

CONFIG_DIR="$HOME/.fs-report"
CONFIG_FILE="$CONFIG_DIR/config.yaml"

mkdir -p "$CONFIG_DIR"
_write_config=true
if [ -f "$CONFIG_FILE" ]; then
    if [ "$YES_MODE" = true ]; then
        ok "Overwriting existing config (--yes)"
    else
        echo ""
        echo -e "${YELLOW}Config file already exists: $CONFIG_FILE${RESET}"
        read -rp "Overwrite? [y/N] " _confirm
        if [[ ! "$_confirm" =~ ^[Yy]$ ]]; then
            _write_config=false
            ok "Kept existing config"
        fi
    fi
fi
if [ "$_write_config" = true ]; then
    cat > "$CONFIG_FILE" << EOF
# Finite State Report Kit configuration
# CLI flags override these values; env vars override config file.
domain: ${domain}
output_dir: ./output
finding_types: cve
current_version_only: true
request_delay: 0.5
batch_size: 5
EOF
    chmod 600 "$CONFIG_FILE"
    ok "Config written to $CONFIG_FILE"
fi

# ── 8. Verify ────────────────────────────────────────────────────────

echo ""
info "Verifying installation..."
if command -v fs-report &>/dev/null; then
    fs-report --help &>/dev/null && ok "Installation verified" \
        || warn "fs-report is on PATH but did not run cleanly"
else
    warn "fs-report not found in PATH yet. You may need to restart your terminal."
    echo -e "${DIM}Or run: source ${SHELL_RC:-~/.zshrc}${RESET}"
fi

# ── 9. Summary ───────────────────────────────────────────────────────

echo ""
info "Setup complete!"
echo ""
echo -e "  ${BOLD}Run reports:${RESET}      fs-report run --recipe \"Executive Summary\""
echo -e "  ${BOLD}Interactive TUI:${RESET}  fs-report"
echo -e "  ${BOLD}See all commands:${RESET} fs-report --help"
echo ""
if [ -n "${SHELL_RC:-}" ]; then
    echo -e "${DIM}Remember to run: source $SHELL_RC${RESET}"
fi
