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

# The build must NOT run as root: cargo executes every dependency's build.rs and
# proc-macros, and we don't want that running with root privileges. Require sudo
# from a normal user so we can drop to it for the build.
if [[ -z "${SUDO_USER:-}" || "$SUDO_USER" == "root" ]]; then
    error "Run this with sudo from your normal user account (e.g. 'sudo ./setup.sh')."
    error "The build must run unprivileged — refusing to compile as root."
    exit 1
fi
BUILD_USER="$SUDO_USER"
USER_HOME=$(getent passwd "$BUILD_USER" | cut -d: -f6)
if [[ -z "$USER_HOME" || ! -d "$USER_HOME" ]]; then
    error "Could not resolve a home directory for build user '$BUILD_USER'."
    exit 1
fi

# Refuse to build/install from a world-writable source tree: a world-writable
# file could be tampered with before it is compiled into the root daemon.
# Group-writable is allowed (the group is trusted). target/ and .git/ are excluded
# (target is rebuilt below; .git is not compiled).
WORLD_WRITABLE=$(find "$SCRIPT_DIR" \
    \( -path "$SCRIPT_DIR/target" -o -path "$SCRIPT_DIR/.git" \) -prune -o \
    -perm -0002 -print 2>/dev/null | head -5)
if [[ -n "$WORLD_WRITABLE" ]]; then
    error "Refusing to build/install: world-writable files in the source tree:"
    echo "$WORLD_WRITABLE" | sed 's/^/    /'
    error "A world-writable source tree could be tampered with before being compiled into the root daemon."
    error "Fix with: chmod -R o-w '$SCRIPT_DIR'"
    exit 1
fi

# ── Rust toolchain discovery (build user's toolchain) ────────────────

RUSTUP_HOME="${RUSTUP_HOME:-$USER_HOME/.rustup}"
CARGO_HOME="${CARGO_HOME:-$USER_HOME/.cargo}"

if [[ ! -x "$CARGO_HOME/bin/cargo" ]] && ! sudo -u "$BUILD_USER" command -v cargo &>/dev/null; then
    error "Rust toolchain not found for $BUILD_USER."
    error "Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# ── Build (as the unprivileged invoking user) ────────────────────────

info "Building ai-sudo (release) as $BUILD_USER..."
sudo -u "$BUILD_USER" env \
    HOME="$USER_HOME" \
    RUSTUP_HOME="$RUSTUP_HOME" \
    CARGO_HOME="$CARGO_HOME" \
    PATH="$CARGO_HOME/bin:/usr/local/bin:/usr/bin:/bin" \
    bash -c "cd '$SCRIPT_DIR' && cargo build --release --locked" 2>&1 | tail -8

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

# ── Install (root, in a transient unit so it survives the daemon restart) ──

# Fork installation into a transient systemd service so it survives the daemon
# restart below. systemd's KillMode=control-group would otherwise kill this
# process when aisudo-daemon stops; systemd-run runs it in a separate cgroup.
info "Launching install as transient systemd service..."

# Temp install script (avoids quoting issues with systemd-run). It only contains
# install commands and paths — no secrets — but keep it root-only anyway.
INSTALL_SCRIPT=$(mktemp /tmp/aisudo-install-XXXXXX.sh)
chmod 700 "$INSTALL_SCRIPT"
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

# Create the service group first so install ownership can reference it.
if ! getent group aisudo &>/dev/null; then
    info "Creating aisudo service group..."
    /usr/sbin/groupadd --system aisudo
else
    info "aisudo group already exists"
fi

# Install binaries root-owned and not group/world-writable (atomic mode set —
# no world-readable/writable window). Non-root must not be able to swap the
# root daemon binary.
info "Installing daemon + CLI binaries to /usr/local/bin..."
install -o root -g root -m 755 "$DAEMON_BIN" /usr/local/bin/aisudo-daemon
install -o root -g root -m 755 "$CLI_BIN" /usr/local/bin/aisudo

# Config carries the Telegram token — create it 0600 atomically.
info "Installing config to /etc/aisudo/aisudo.toml..."
install -d -o root -g root -m 755 /etc/aisudo
install -o root -g root -m 600 "$CONFIG_FILE" /etc/aisudo/aisudo.toml

# Socket dir: group-traversable (x) but NOT group-writable, so aisudo members can
# reach the socket but cannot unlink/replace it. (systemd's RuntimeDirectory
# recreates this as 0755 root:root at start; this covers non-systemd starts.)
info "Creating runtime + state directories..."
install -d -o root -g aisudo -m 750 /var/run/aisudo
# State dir holds the DB (and transient credentials) — root only. The daemon also
# enforces 0700 on this dir and 0600 on the DB file.
install -d -o root -g root -m 700 /var/lib/aisudo

info "Installing systemd service..."
install -o root -g root -m 644 "$SCRIPT_DIR/aisudo-daemon.service" /etc/systemd/system/aisudo-daemon.service
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

systemd-run --unit=aisudo-install --description="aisudo install" \
    --slice=system.slice bash "$INSTALL_SCRIPT"

echo ""
echo "Installation launched as transient service (aisudo-install.service)."
echo "Monitor progress: tail -f /var/log/aisudo-setup.log"
echo "                  systemctl status aisudo-install"
echo ""
