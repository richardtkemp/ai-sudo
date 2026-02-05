#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/aisudo.toml"
INSTALL_PAM=false

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --pam) INSTALL_PAM=true ;;
        *) echo "Unknown option: $arg"; echo "Usage: $0 [--pam]"; exit 1 ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }

# ── Pre-flight checks ────────────────────────────────────────────────

if [[ ! -f "$CONFIG_FILE" ]]; then
    error "aisudo.toml not found at $CONFIG_FILE"
    error "Copy aisudo.toml.example to aisudo.toml and fill in your settings before running setup."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo $0)"
    exit 1
fi

# Check for cargo
if ! command -v cargo &>/dev/null; then
    error "Rust toolchain not found. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────

info "Building ai-sudo (release)..."
cd "$SCRIPT_DIR"
cargo build --release 2>&1 | tail -5

DAEMON_BIN="$SCRIPT_DIR/target/release/aisudo-daemon"
CLI_BIN="$SCRIPT_DIR/target/release/aisudo"

if [[ ! -f "$DAEMON_BIN" ]]; then
    error "Daemon binary not found at $DAEMON_BIN — build failed?"
    exit 1
fi

if [[ ! -f "$CLI_BIN" ]]; then
    error "CLI binary not found at $CLI_BIN — build failed?"
    exit 1
fi

# ── Stop running daemon ──────────────────────────────────────────────

if systemctl is-active --quiet aisudo-daemon 2>/dev/null; then
    info "Stopping running aisudo-daemon..."
    systemctl stop aisudo-daemon
fi

# ── Install daemon ────────────────────────────────────────────────────

info "Installing daemon binary to /usr/local/bin/aisudo-daemon..."
cp "$DAEMON_BIN" /usr/local/bin/aisudo-daemon
chmod 755 /usr/local/bin/aisudo-daemon

# ── Install CLI wrapper ──────────────────────────────────────────────

info "Installing CLI wrapper to /usr/local/bin/aisudo..."
cp "$CLI_BIN" /usr/local/bin/aisudo
chmod 755 /usr/local/bin/aisudo

# ── Install config ────────────────────────────────────────────────────

info "Installing config to /etc/aisudo/aisudo.toml..."
mkdir -p /etc/aisudo
cp "$CONFIG_FILE" /etc/aisudo/aisudo.toml
chmod 600 /etc/aisudo/aisudo.toml

# ── Create service group ─────────────────────────────────────────────

if ! getent group aisudo &>/dev/null; then
    info "Creating aisudo service group..."
    /usr/sbin/groupadd --system aisudo
else
    info "aisudo group already exists"
fi

# ── Create directories ────────────────────────────────────────────────

info "Creating runtime directories..."
mkdir -p /var/run/aisudo
chown root:aisudo /var/run/aisudo
chmod 775 /var/run/aisudo

mkdir -p /var/lib/aisudo
chmod 750 /var/lib/aisudo

# ── Install systemd service ──────────────────────────────────────────

info "Installing systemd service..."
cp "$SCRIPT_DIR/aisudo-daemon.service" /etc/systemd/system/aisudo-daemon.service
systemctl daemon-reload

# ── Optionally install PAM module ─────────────────────────────────────

if [[ "$INSTALL_PAM" == true ]]; then
    PAM_LIB="$SCRIPT_DIR/target/release/libpam_aisudo.so"

    if [[ ! -f "$PAM_LIB" ]]; then
        error "PAM module not found at $PAM_LIB — build failed?"
        exit 1
    fi

    PAM_DIR="/usr/lib/security"
    if [[ ! -d "$PAM_DIR" ]]; then
        for candidate in /lib/x86_64-linux-gnu/security /lib/security /usr/lib/x86_64-linux-gnu/security; do
            if [[ -d "$candidate" ]]; then
                PAM_DIR="$candidate"
                break
            fi
        done
        mkdir -p "$PAM_DIR"
    fi

    info "Installing PAM module to $PAM_DIR/pam_aisudo.so..."
    cp "$PAM_LIB" "$PAM_DIR/pam_aisudo.so"
    chmod 755 "$PAM_DIR/pam_aisudo.so"

    # Configure PAM
    PAM_SUDO="/etc/pam.d/sudo"
    PAM_LINE="auth    sufficient    pam_aisudo.so"

    if [[ -f "$PAM_SUDO" ]]; then
        if grep -q "pam_aisudo" "$PAM_SUDO"; then
            info "PAM already configured for ai-sudo"
        else
            info "Adding ai-sudo to PAM sudo config..."
            cp "$PAM_SUDO" "$PAM_SUDO.bak.$(date +%s)"
            sed -i "0,/^auth/s/^auth/$PAM_LINE\nauth/" "$PAM_SUDO"
            info "PAM configured. Backup saved as $PAM_SUDO.bak.*"
        fi
    else
        warn "/etc/pam.d/sudo not found — you'll need to configure PAM manually"
        warn "Add this line to your PAM sudo config: $PAM_LINE"
    fi
fi

# ── Start service ─────────────────────────────────────────────────────

info "Enabling and starting aisudo-daemon..."
systemctl enable aisudo-daemon
systemctl restart aisudo-daemon

# Give it a moment
sleep 2

if systemctl is-active --quiet aisudo-daemon; then
    info "aisudo-daemon is running!"
else
    error "aisudo-daemon failed to start. Check: journalctl -u aisudo-daemon -n 20"
    exit 1
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════"
echo -e "${GREEN}  ai-sudo setup complete!${NC}"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Config:    /etc/aisudo/aisudo.toml"
echo "  Daemon:    /usr/local/bin/aisudo-daemon"
echo "  CLI:       /usr/local/bin/aisudo"
echo "  Service:   aisudo-daemon.service"
echo "  Database:  /var/lib/aisudo/aisudo.db"
echo "  Socket:    /var/run/aisudo/aisudo.sock"
echo "  Logs:      journalctl -u aisudo-daemon -f"
echo ""
echo "  Test it:   aisudo whoami"
if [[ "$INSTALL_PAM" == true ]]; then
    echo "  PAM test:  sudo echo hello"
    echo ""
    warn "If sudo breaks, recover with: pkexec sed -i '/pam_aisudo/d' /etc/pam.d/sudo"
else
    echo ""
    echo "  To also install PAM mode (intercepts all sudo):"
    echo "    sudo $0 --pam"
fi
echo ""
