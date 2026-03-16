#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/aisudo.toml"
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

# ── Rust toolchain discovery ─────────────────────────────────────────
# When running under sudo/aisudo, root may not have a Rust toolchain.
# Use SUDO_USER's standard ~/.rustup and ~/.cargo unless RUSTUP_HOME
# or CARGO_HOME are already set in the environment.

if [[ -z "${RUSTUP_HOME:-}" || -z "${CARGO_HOME:-}" ]]; then
    # Resolve the invoking user's home directory
    if [[ -n "${SUDO_USER:-}" ]]; then
        SUDO_USER_HOME=$(eval echo "~$SUDO_USER")
    else
        SUDO_USER_HOME="$HOME"
    fi
    export RUSTUP_HOME="${RUSTUP_HOME:-$SUDO_USER_HOME/.rustup}"
    export CARGO_HOME="${CARGO_HOME:-$SUDO_USER_HOME/.cargo}"
fi

# Check for cargo
if ! command -v cargo &>/dev/null; then
    if [[ -x "$CARGO_HOME/bin/cargo" ]]; then
        export PATH="$CARGO_HOME/bin:$PATH"
    else
        error "Rust toolchain not found. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
fi

# Set LD_LIBRARY_PATH so rustc can find librustc_driver when cargo invokes
# it directly by absolute path (bypassing the rustup proxy).
TC_DIR=$(ls -1d "$RUSTUP_HOME"/toolchains/*/lib 2>/dev/null | head -1)
if [[ -n "$TC_DIR" ]]; then
    export LD_LIBRARY_PATH="${TC_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
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

# Fork installation into a transient systemd service so it survives daemon restart.
# setsid alone isn't enough — systemd's KillMode=control-group kills all processes
# in the daemon's cgroup. systemd-run creates a new transient unit in a separate
# cgroup, so stopping aisudo-daemon won't kill the install process.
info "Launching install as transient systemd service..."

# Write the install script to a temp file (avoids quoting issues with systemd-run)
INSTALL_SCRIPT=$(mktemp /tmp/aisudo-install-XXXXXX.sh)
cat > "$INSTALL_SCRIPT" <<INSTALL_EOF
#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/aisudo-setup.log"
exec >"\$LOG_FILE" 2>&1
echo "=== aisudo setup started at \$(date) ==="

info()  { echo -e "\033[0;32m[✓]\033[0m \$*"; }
warn()  { echo -e "\033[1;33m[!]\033[0m \$*"; }
error() { echo -e "\033[0;31m[✗]\033[0m \$*"; }

if systemctl is-active --quiet aisudo-daemon 2>/dev/null; then
    info "Stopping running aisudo-daemon..."
    systemctl stop aisudo-daemon
fi

info "Installing daemon binary to /usr/local/bin/aisudo-daemon..."
cp "$DAEMON_BIN" /usr/local/bin/aisudo-daemon
chmod 755 /usr/local/bin/aisudo-daemon

info "Installing CLI wrapper to /usr/local/bin/aisudo..."
cp "$CLI_BIN" /usr/local/bin/aisudo
chmod 755 /usr/local/bin/aisudo

info "Installing config to /etc/aisudo/aisudo.toml..."
mkdir -p /etc/aisudo
cp "$CONFIG_FILE" /etc/aisudo/aisudo.toml
chmod 600 /etc/aisudo/aisudo.toml

if ! getent group aisudo &>/dev/null; then
    info "Creating aisudo service group..."
    /usr/sbin/groupadd --system aisudo
else
    info "aisudo group already exists"
fi

info "Creating runtime directories..."
mkdir -p /var/run/aisudo
chown root:aisudo /var/run/aisudo
chmod 775 /var/run/aisudo

mkdir -p /var/lib/aisudo
chmod 750 /var/lib/aisudo

info "Installing systemd service..."
cp "$SCRIPT_DIR/aisudo-daemon.service" /etc/systemd/system/aisudo-daemon.service
systemctl daemon-reload

info "Enabling and starting aisudo-daemon..."
systemctl enable aisudo-daemon
systemctl restart aisudo-daemon

sleep 2

if systemctl is-active --quiet aisudo-daemon; then
    info "aisudo-daemon is running!"
    echo ""
    echo "=== aisudo setup completed at \$(date) ==="
    echo "View this log: cat /var/log/aisudo-setup.log"
else
    error "aisudo-daemon failed to start. Check: journalctl -u aisudo-daemon -n 20"
    echo ""
    echo "=== aisudo setup FAILED at \$(date) ==="
fi

rm -f "\$0"  # clean up temp script
INSTALL_EOF
chmod 755 "$INSTALL_SCRIPT"

systemd-run --unit=aisudo-install --description="aisudo install" \
    --slice=system.slice bash "$INSTALL_SCRIPT"

echo ""
echo "Installation launched as transient service (aisudo-install.service)."
echo "Monitor progress: tail -f /var/log/aisudo-setup.log"
echo "                  systemctl status aisudo-install"
echo ""
exit 0

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
echo ""
