#!/bin/sh
#
# NETRA_CLI One-Line Installer
# Installs netra to ~/.local/bin/netra without requiring root privileges.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/404Avinash/Netra_cli/main/install.sh | sh
#   or: curl -sSL https://raw.githubusercontent.com/404Avinash/Netra_cli/main/install.sh | bash
#   or from a local clone: ./install.sh
#

set -eu

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# 1. Detect Python 3.10+
PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    printf "%b\n" "${RED}Error: NETRA_CLI requires Python 3.10 or higher.${NC}" >&2
    if command -v python3 >/dev/null 2>&1; then
        CURRENT_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>/dev/null || echo "unknown")
        printf "%b\n" "Found python3 version ${CURRENT_VER}. Please upgrade to Python 3.10+." >&2
    else
        printf "%b\n" "Neither 'python3' nor 'python' was found in your PATH." >&2
    fi
    exit 1
fi

# 2. Setup ~/.local/bin destination
INSTALL_DIR="${HOME}/.local/bin"
TARGET_BIN="${INSTALL_DIR}/netra"
mkdir -p "${INSTALL_DIR}"

# 3. Obtain netra.py (local repo or GitHub raw download)
SCRIPT_DIR=""
if [ -f "$0" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"
fi

if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/netra.py" ]; then
    cp "${SCRIPT_DIR}/netra.py" "${TARGET_BIN}"
elif [ -f "./netra.py" ]; then
    cp "./netra.py" "${TARGET_BIN}"
else
    REPO_RAW_URL="https://raw.githubusercontent.com/404Avinash/Netra_cli/main/netra.py"
    printf "%b\n" "${BLUE}Downloading netra from ${REPO_RAW_URL}...${NC}"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${REPO_RAW_URL}" -o "${TARGET_BIN}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${TARGET_BIN}" "${REPO_RAW_URL}"
    else
        printf "%b\n" "${RED}Error: Neither 'curl' nor 'wget' found. Cannot download netra.${NC}" >&2
        exit 1
    fi
fi

# 4. Set executable permission
chmod +x "${TARGET_BIN}"

# 5. Check and configure PATH
PATH_CONFIGURED=false
case ":$PATH:" in
    *":${INSTALL_DIR}:"*)
        PATH_CONFIGURED=true
        ;;
esac

RC_UPDATED=false
EXPORT_CMD="export PATH=\"\$HOME/.local/bin:\$PATH\""

if [ "$PATH_CONFIGURED" = false ]; then
    for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
        if [ -f "$rc" ] && ! grep -q '\.local/bin' "$rc"; then
            printf "\n# NETRA_CLI path\n%s\n" "$EXPORT_CMD" >> "$rc"
            RC_UPDATED=true
        fi
    done
fi

# 6. Friendly Completion Banner
printf "%b\n" "${BLUE}${BOLD}"
cat << 'EOF'
  _   _ _____ _____ ____      _       ____ _     ___ 
 | \ | | ____|_   _|  _ \    / \     / ___| |   |_ _|
 |  \| |  _|   | | | |_) |  / _ \   | |   | |    | | 
 | |\  | |___  | | |  _ <  / ___ \  | |___| |___ | | 
 |_| \_|_____| |_| |_| \_\/_/   \_\  \____|_____|___|
      Network & Endpoint Threat & Resilience Assessor
EOF
printf "%b\n" "${NC}"

printf "%b\n\n" "${GREEN}✔ NETRA_CLI successfully installed to ${BOLD}${TARGET_BIN}${NC}"

if [ "$PATH_CONFIGURED" = false ]; then
    if [ "$RC_UPDATED" = true ]; then
        printf "%b\n" "${BOLD}Note:${NC} Added ~/.local/bin to your shell config. To use 'netra' in this terminal:"
        printf "%b\n\n" "  ${BOLD}${EXPORT_CMD}${NC} (or restart your shell)"
    else
        printf "%b\n" "${BOLD}Note:${NC} ~/.local/bin is not yet in your PATH. Add it with:"
        printf "%b\n\n" "  ${BOLD}${EXPORT_CMD}${NC}"
    fi
fi

printf "%b\n" "Try it now:"
printf "%b\n" "  ${BOLD}netra example.com${NC}          # Nmap-style instant security audit"
printf "%b\n" "  ${BOLD}netra top example.com${NC}      # Live interactive dashboard"
printf "%b\n" "  ${BOLD}netra --help${NC}               # View all subcommands and options"
