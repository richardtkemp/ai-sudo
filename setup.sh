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

# ── Arguments ────────────────────────────────────────────────────────
# --gid N   Pin the aisudo group's GID. Useful for cross-machine
#           consistency (e.g. shared/NFS storage owned by the group).
#           Only applied when the group is CREATED — pre-existing groups
#           keep their current GID. Default: 6000 on macOS; unset on
#           Linux (groupadd --system auto-assigns from the system range).
AISUDO_GID=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --gid)   AISUDO_GID="${2:?--gid requires a numeric value}"; shift 2 ;;
        --gid=*) AISUDO_GID="${1#*=}"; shift ;;
        -h|--help)
            echo "Usage: sudo $0 [--gid N]"
            echo "  --gid N   Pin the aisudo group GID on first creation (default 6000 on macOS)."
            exit 0 ;;
        *) error "Unknown argument: $1 (see --help)"; exit 1 ;;
    esac
done
if [[ -n "$AISUDO_GID" && ! "$AISUDO_GID" =~ ^[0-9]+$ ]]; then
    error "--gid must be a non-negative integer, got: '$AISUDO_GID'"
    exit 1
fi

# =====================================================================
# Platform-specific install functions
# =====================================================================
# Defined before the dispatch below — bash does not hoist function
# definitions, so they must exist at the point of the call.

# ---------------------------------------------------------------------
# Linux install path
# ---------------------------------------------------------------------
# Forked into a transient systemd service so the install survives the
# daemon restart below. systemd's KillMode=control-group would otherwise
# kill this process when aisudo-daemon stops; systemd-run runs it in a
# separate cgroup.
install_linux() {
    info "Launching install as transient systemd service..."

    # GID flag baked into the install script below. --system auto-assigns from
    # the system range unless --gid pins an explicit value (only applied on a
    # fresh create; groupadd errors on an existing group but that branch is
    # guarded by the getent existence check).
    local groupadd_gid_flag="--system"
    if [[ -n "$AISUDO_GID" ]]; then
        groupadd_gid_flag="--gid $AISUDO_GID"
    fi

    # Temp install script (avoids quoting issues with systemd-run). It only
    # contains install commands and paths — no secrets — but keep it root-only.
    local INSTALL_SCRIPT
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
    /usr/sbin/groupadd ${groupadd_gid_flag} aisudo
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
install -d -o root -g root -m 755 /etc/aisudo
if [[ -f "$CONFIG_FILE" ]]; then
    info "Installing config to /etc/aisudo/aisudo.toml..."
    install -o root -g root -m 600 "$CONFIG_FILE" /etc/aisudo/aisudo.toml
else
    info "No local aisudo.toml; keeping existing /etc/aisudo/aisudo.toml"
fi

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
}

# ---------------------------------------------------------------------
# macOS install path
# ---------------------------------------------------------------------
# No systemd-run analogue needed — launchctl bootstrap doesn't share cgroup
# kill semantics with the daemon, so we install inline. Logs go to a flat
# file (rotated by newsyslog) instead of journald.
install_macos() {
    # Stop the running daemon if present (bootout is idempotent — fails
    # harmlessly if not loaded).
    if launchctl print system/ai.sudo.daemon &>/dev/null; then
        info "Stopping running aisudo-daemon..."
        launchctl bootout system /Library/LaunchDaemons/ai.sudo.daemon.plist 2>/dev/null || true
    fi

    # Create the service group if it doesn't already exist.
    # `-o read` is the existence check (exit 0 iff the group exists); `-o check`
    # is NOT a valid operation and `-n` means "directory node", so the old
    # `-o check -n aisudo` always failed and re-ran create — which errors on an
    # existing group and, under `set -e`, aborted every reinstall.
    # Pin the GID (-i) so it's deterministic across machines; only applies on a
    # fresh create, so pre-existing installs keep their current GID. Override
    # with `--gid N`; default 6000 is well clear of macOS's system (<500) and
    # staff/admin ranges. Change it if it ever collides.
    local gid="${AISUDO_GID:-6000}"
    if ! dseditgroup -o read aisudo &>/dev/null; then
        info "Creating aisudo service group (gid $gid)..."
        dseditgroup -o create -i "$gid" -r "ai-sudo approval group" aisudo
    else
        info "aisudo group already exists"
    fi

    info "Installing daemon + CLI binaries to /usr/local/bin..."
    install -o root -g wheel -m 755 "$DAEMON_BIN" /usr/local/bin/aisudo-daemon
    install -o root -g wheel -m 755 "$CLI_BIN" /usr/local/bin/aisudo

    install -d -o root -g wheel -m 755 /etc/aisudo
    if [[ -f "$CONFIG_FILE" ]]; then
        info "Installing config to /etc/aisudo/aisudo.toml..."
        install -o root -g wheel -m 600 "$CONFIG_FILE" /etc/aisudo/aisudo.toml
    else
        info "No local aisudo.toml; keeping existing /etc/aisudo/aisudo.toml"
    fi

    # Socket dir: group-traversable (x) but NOT group-writable, so aisudo
    # members can reach the socket but cannot unlink/replace it. /private/var/run
    # is wiped on every boot; the daemon recreates this dir at startup with the
    # same mode (see socket.rs cfg(target_os = "macos") block).
    info "Creating runtime + state directories..."
    install -d -o root -g aisudo -m 750 /var/run/aisudo
    # State dir holds the DB (and transient credentials) — root only. The
    # daemon also enforces 0700 on this dir and 0600 on the DB file. macOS
    # convention: /var/db (NOT /var/lib, which does not exist by default).
    install -d -o root -g wheel -m 700 /var/db/aisudo

    # Log file (launchd StandardOutPath / StandardErrorPath target). Group-readable
    # so aisudo members can read their own audit trail; newsyslog rotates it.
    info "Creating log file and newsyslog drop-in..."
    touch /var/log/aisudo.log
    chown root:aisudo /var/log/aisudo.log
    chmod 640 /var/log/aisudo.log
    # newsyslog format: owner:group mode count size when flags
    # 7 archived copies, rotate at ~1000 KB, no time-based schedule (J = compress).
    cat > /etc/newsyslog.d/aisudo.conf <<NEWSYSLOG_EOF
# logfilename          owner:group   mode  count  size   when  flags
/var/log/aisudo.log    root:aisudo   640   7      1000   *     J
NEWSYSLOG_EOF
    chown root:wheel /etc/newsyslog.d/aisudo.conf
    chmod 644 /etc/newsyslog.d/aisudo.conf

    info "Installing launchd plist..."
    install -o root -g wheel -m 644 \
        "$SCRIPT_DIR/ai.sudo.daemon.plist" \
        /Library/LaunchDaemons/ai.sudo.daemon.plist

    info "Loading and starting aisudo-daemon..."
    launchctl bootstrap system /Library/LaunchDaemons/ai.sudo.daemon.plist

    sleep 2

    if launchctl print system/ai.sudo.daemon &>/dev/null; then
        info "aisudo-daemon is running!"
        echo ""
        echo "Next steps:"
        echo "  Add your user to the aisudo group:"
        echo "    sudo dseditgroup -o edit -a $BUILD_USER -t user aisudo"
        echo "  (new group membership needs a fresh login shell or 'sg aisudo -l')"
        echo ""
        echo "  Status:   sudo launchctl print system/ai.sudo.daemon"
        echo "  Logs:     tail -f /var/log/aisudo.log"
        echo "  Restart:  sudo launchctl kickstart -k system/ai.sudo.daemon"
    else
        error "aisudo-daemon failed to start. Check: tail -50 /var/log/aisudo.log"
        error "Also: sudo launchctl print system/ai.sudo.daemon"
        exit 1
    fi
}

# =====================================================================
# Pre-flight checks
# =====================================================================

if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -f /etc/aisudo/aisudo.toml ]]; then
        info "No local aisudo.toml; keeping existing config at /etc/aisudo/aisudo.toml"
    else
        error "aisudo.toml not found at $CONFIG_FILE"
        error "Copy aisudo.toml.example to aisudo.toml and fill in your settings before running setup."
        exit 1
    fi
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

# Resolve the build user's home directory. getent is Linux-only; macOS uses dscl.
case "$(uname -s)" in
    Linux)
        USER_HOME=$(getent passwd "$BUILD_USER" | cut -d: -f6)
        ;;
    Darwin)
        USER_HOME=$(dscl . -read "/Users/$BUILD_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
        ;;
    *)
        error "Unsupported OS: $(uname -s)"
        exit 1
        ;;
esac
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

# ── Build (as the unprivileged invoking user) ────────────────────────
# Run through the user's LOGIN shell (`bash -lc`) so we use whatever cargo/rustup
# setup they actually have (system rustup in /usr/bin, ~/.cargo/bin, Homebrew on
# macOS, a custom CARGO_HOME in their profile, etc.) rather than guessing paths.

if ! sudo -u "$BUILD_USER" bash -lc 'command -v cargo' &>/dev/null; then
    error "Rust toolchain ('cargo') not found in ${BUILD_USER}'s login PATH."
    error "Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    error "On macOS you also need Xcode Command Line Tools: xcode-select --install"
    exit 1
fi

info "Building ai-sudo (release) as $BUILD_USER..."
sudo -u "$BUILD_USER" bash -lc "cd '$SCRIPT_DIR' && cargo build --release --locked" 2>&1 | tail -8

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

# ── Install (platform-specific) ──────────────────────────────────────

case "$(uname -s)" in
    Linux)  install_linux ;;
    Darwin) install_macos ;;
esac
