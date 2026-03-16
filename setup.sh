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

# ── Shared Rust build cache ───────────────────────────────────────────
# Root has no Rust toolchain by default. Use /var/cache paths (like Go)
# so both root and the invoking user can share toolchains and build cache.
# Honour an existing RUSTUP_HOME/CARGO_HOME if already set in the environment.

RUSTUP_HOME="${RUSTUP_HOME:-/var/cache/rustup}"
CARGO_HOME="${CARGO_HOME:-/var/cache/cargo}"
export RUSTUP_HOME CARGO_HOME

# find_user_rustup: locate an existing rustup installation to bootstrap from.
# Checks SUDO_USER's home first, then scans /home/*/.rustup.
find_user_rustup() {
    # Try SUDO_USER if set
    if [[ -n "${SUDO_USER:-}" ]]; then
        local h
        h=$(eval echo "~$SUDO_USER")
        if [[ -d "$h/.rustup/toolchains" ]] && [[ -n "$(ls -A "$h/.rustup/toolchains" 2>/dev/null)" ]]; then
            echo "$h/.rustup"
            return
        fi
    fi
    # Scan /home for any user with a populated rustup
    for d in /home/*/.rustup/toolchains; do
        if [[ -d "$d" ]] && [[ -n "$(ls -A "$d" 2>/dev/null)" ]]; then
            echo "${d%/toolchains}"
            return
        fi
    done
    return 1
}

# Bootstrap from a user's toolchain if the shared one is empty
if [[ ! -d "$RUSTUP_HOME/toolchains" ]] || [[ -z "$(ls -A "$RUSTUP_HOME/toolchains" 2>/dev/null)" ]]; then
    SRC_RUSTUP=$(find_user_rustup) || {
        error "No Rust toolchain found in any /home/*/.rustup. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    }
    info "Bootstrapping shared Rust toolchain from $SRC_RUSTUP..."
    mkdir -p "$RUSTUP_HOME"
    cp -a "$SRC_RUSTUP/toolchains" "$RUSTUP_HOME/"
    cp -a "$SRC_RUSTUP/update-hashes" "$RUSTUP_HOME/" 2>/dev/null || true
    cp -a "$SRC_RUSTUP/settings.toml" "$RUSTUP_HOME/" 2>/dev/null || true
fi

# Ensure a default toolchain is configured — rustup will refuse to run without one.
if [[ ! -f "$RUSTUP_HOME/settings.toml" ]] || ! grep -q 'default_toolchain' "$RUSTUP_HOME/settings.toml" 2>/dev/null; then
    # Pick the first installed toolchain as the default
    default_tc=$(ls -1 "$RUSTUP_HOME/toolchains" 2>/dev/null | head -1)
    if [[ -n "$default_tc" ]]; then
        info "Setting default toolchain: $default_tc"
        cat > "$RUSTUP_HOME/settings.toml" <<TOML
default_toolchain = "$default_tc"
profile = "default"
version = "12"

[overrides]
TOML
    else
        error "No toolchains found in $RUSTUP_HOME/toolchains"
        exit 1
    fi
fi

# Check for cargo — look in the shared cache, SUDO_USER's home, then /home/*/
if ! command -v cargo &>/dev/null; then
    if [[ -x "$CARGO_HOME/bin/cargo" ]]; then
        export PATH="$CARGO_HOME/bin:$PATH"
    else
        found_cargo=""
        if [[ -n "${SUDO_USER:-}" ]]; then
            h=$(eval echo "~$SUDO_USER")
            [[ -x "$h/.cargo/bin/cargo" ]] && found_cargo="$h/.cargo/bin"
        fi
        if [[ -z "$found_cargo" ]]; then
            for c in /home/*/.cargo/bin/cargo; do
                [[ -x "$c" ]] && found_cargo="${c%/cargo}" && break
            done
        fi
        if [[ -n "$found_cargo" ]]; then
            export PATH="$found_cargo:$PATH"
        else
            error "Rust toolchain not found. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            exit 1
        fi
    fi
fi

# Ensure shared cache dirs exist with group-writable setgid (matches /var/cache/go)
for d in "$RUSTUP_HOME" "$CARGO_HOME"; do
    mkdir -p "$d"
    chown root:rich-readers "$d"
    chmod 2775 "$d"
done

# Strip setgid from *files* — the dynamic linker ignores RUNPATH ($ORIGIN/../lib)
# on setgid binaries as a security measure, which breaks rustc's library loading.
# Directories keep setgid (for group inheritance); only files lose it.
find "$RUSTUP_HOME" "$CARGO_HOME" -type f -perm /2000 -exec chmod g-s {} +

# Set LD_LIBRARY_PATH so rustc can find librustc_driver even if the rustup proxy
# isn't in the call chain (e.g. cargo invokes rustc directly by absolute path).
TC_DIR=$(ls -1d "$RUSTUP_HOME"/toolchains/*/lib 2>/dev/null | head -1)
if [[ -n "$TC_DIR" ]]; then
    export LD_LIBRARY_PATH="${TC_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

# Make sure cargo binary is on PATH
if [[ -d "$CARGO_HOME/bin" ]] && [[ -x "$CARGO_HOME/bin/cargo" ]]; then
    export PATH="$CARGO_HOME/bin:$PATH"
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

# Fork daemon-stopping and installation into background process so it survives
# when the daemon is stopped (script may be running as child of the daemon)
info "Forking installation to survive daemon stop..."
setsid bash -c '
    LOG_FILE="/var/log/aisudo-setup.log"
    exec >"$LOG_FILE" 2>&1
    echo "=== aisudo setup started at $(date) ==="
    
    SCRIPT_DIR="'"$SCRIPT_DIR"'"
    CONFIG_FILE="'"$CONFIG_FILE"'"
    DAEMON_BIN="'"$DAEMON_BIN"'"
    CLI_BIN="'"$CLI_BIN"'"
    
    info()  { echo -e "\033[0;32m[✓]\033[0m $*"; }
    warn()  { echo -e "\033[1;33m[!]\033[0m $*"; }
    error() { echo -e "\033[0;31m[✗]\033[0m $*"; }
    
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
        echo "=== aisudo setup completed at $(date) ==="
        echo "View this log: cat /var/log/aisudo-setup.log"
    else
        error "aisudo-daemon failed to start. Check: journalctl -u aisudo-daemon -n 20"
        echo ""
        echo "=== aisudo setup FAILED at $(date) ==="
    fi
' </dev/null &

echo ""
echo "Installation forked to background process."
echo "Monitor progress: tail -f /var/log/aisudo-setup.log"
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
