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
# Install rollback
# =====================================================================
# The install stops the daemon and overwrites the live binaries, config and
# service unit IN PLACE. If what replaces them is broken, every agent on the
# box loses privileged operations until a human intervenes by hand — and the
# way that gets discovered is an agent failing, not the installer saying so.
# (A human still has real /usr/bin/sudo, which this daemon does not mediate,
# so it is recoverable; it is just silent.)
#
# So: snapshot the files the install is about to overwrite, arm a trap, and put
# them back unless we reach a VERIFIED-HEALTHY daemon.
#
# WHY A TRAP AND NOT AN `else` AFTER THE HEALTH CHECK. Both install paths run
# under `set -euo pipefail`. A failing `install`, `groupadd` or `daemon-reload`
# aborts the script immediately and never reaches code placed after it — and by
# then the daemon is stopped and the binaries may be half-swapped. The old
# "daemon failed to start" branch was unreachable for every one of those
# failures. Only a trap fires on that path.
#
# Every backed-up path is a plain FILE, deliberately. Restoring never needs a
# recursive delete, so this code contains no `rm -rf` of anything it did not
# itself create.

AISUDO_PLATFORM="$(uname -s)"
AISUDO_BACKUP_ROOT="/var/backups/aisudo"
AISUDO_BACKUP_KEEP=5
AISUDO_BACKUP_DIR=""
AISUDO_LOG_HINT=""

# Snapshot the given live paths into a timestamped dir, mirroring their real
# layout, with a MANIFEST listing what was taken. Paths that do not exist are
# skipped — that is how a first install correctly ends up with nothing to roll
# back to, rather than a rollback that restores emptiness over a good install.
aisudo_backup() {
    AISUDO_BACKUP_DIR="$AISUDO_BACKUP_ROOT/$(date +%Y%m%d-%H%M%S).$$"
    install -d -o root -g root -m 700 "$AISUDO_BACKUP_ROOT"
    install -d -o root -g root -m 700 "$AISUDO_BACKUP_DIR"

    local p found=0
    for p in "$@"; do
        [[ -f "$p" ]] || continue
        install -d -o root -g root -m 700 "$AISUDO_BACKUP_DIR$(dirname "$p")"
        cp -p "$p" "$AISUDO_BACKUP_DIR$p"
        printf '%s\n' "$p" >>"$AISUDO_BACKUP_DIR/MANIFEST"
        found=$((found + 1))
    done

    if [[ $found -eq 0 ]]; then
        rmdir "$AISUDO_BACKUP_DIR" 2>/dev/null || true
        AISUDO_BACKUP_DIR=""
        info "Nothing installed yet — no rollback point (first install)"
        return 0
    fi

    info "Backed up $found file(s) to $AISUDO_BACKUP_DIR"
    aisudo_prune_backups
}

# Keep the last AISUDO_BACKUP_KEEP snapshots. `ls -t` rather than `find -printf`
# because the latter is GNU-only and this runs on macOS too.
aisudo_prune_backups() {
    local old
    # shellcheck disable=SC2012  # need mtime ordering; backup dirs are our own timestamped names, never arbitrary
    while IFS= read -r old; do
        # Belt and braces: only ever delete something under the backup root.
        [[ -n "$old" && "$old" == "$AISUDO_BACKUP_ROOT"/* ]] || continue
        rm -rf -- "$old"
    done < <(ls -1dt "$AISUDO_BACKUP_ROOT"/*/ 2>/dev/null | tail -n +$((AISUDO_BACKUP_KEEP + 1)) || true)
}

aisudo_restart_daemon() {
    case "$AISUDO_PLATFORM" in
        Linux)
            systemctl restart aisudo-daemon
            ;;
        Darwin)
            launchctl bootout system /Library/LaunchDaemons/ai.sudo.daemon.plist 2>/dev/null || true
            launchctl bootstrap system /Library/LaunchDaemons/ai.sudo.daemon.plist
            ;;
    esac
}

# The gate that decides whether the install keeps its changes.
#
# `systemctl is-active` / `launchctl print` only prove the process launched. A
# daemon that starts and is THEN broken — cannot open its DB, fails to bind the
# socket, panics on the first request — passes both and still leaves every agent
# unable to escalate. So the check is an end-to-end round trip: `aisudo --status`
# connects to the socket, sends a Status message and parses the reply, exiting
# non-zero on any failure along the way. It notifies nobody, so it is safe to run
# unattended.
#
# Ten one-second attempts rather than one `sleep 2`: the daemon may still be
# opening its socket, and a health gate that is merely impatient would roll back
# a perfectly good install.
aisudo_health_check() {
    local _
    for _ in $(seq 1 10); do
        if /usr/local/bin/aisudo --status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Trap handler. Restores the snapshot, restarts, and reports which of the two
# bad outcomes happened: rolled back and healthy, or rolled back and still dead.
aisudo_rollback() {
    local rc=$?
    trap - ERR EXIT

    if [[ -z "$AISUDO_BACKUP_DIR" || ! -f "$AISUDO_BACKUP_DIR/MANIFEST" ]]; then
        error "Install failed (status $rc) and there is no previous install to restore."
        error "Expected on a first install. Fix the cause and re-run: $AISUDO_LOG_HINT"
        exit "$rc"
    fi

    error "Install failed (status $rc) — restoring the previous install"
    error "  from $AISUDO_BACKUP_DIR"
    local p
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        if cp -p "$AISUDO_BACKUP_DIR$p" "$p"; then
            info "  restored $p"
        else
            error "  FAILED to restore $p — copy it back by hand from $AISUDO_BACKUP_DIR"
        fi
    done <"$AISUDO_BACKUP_DIR/MANIFEST"

    aisudo_restart_daemon || true

    if aisudo_health_check; then
        info "Rolled back. The previous daemon is answering on its socket again."
        info "The new build is still at $DAEMON_BIN if you want to debug it."
    else
        error "ROLLED BACK, BUT THE RESTORED DAEMON IS NOT ANSWERING."
        error "  backup: $AISUDO_BACKUP_DIR"
        error "  logs:   $AISUDO_LOG_HINT"
        error "  Recover with real /usr/bin/sudo, which this daemon does not mediate."
    fi
    exit "$rc"
}

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
INSTALL_EOF

    # The rollback library goes in via `declare -f`, not a heredoc. The heredoc
    # around it MUST stay unquoted (it interpolates $groupadd_gid_flag,
    # $DAEMON_BIN, $SCRIPT_DIR...), and an unquoted heredoc would eat every
    # $1/$@/$? inside those function bodies. `declare -f` writes them verbatim,
    # so Linux and macOS share ONE definition instead of a copy that drifts.
    # shellcheck disable=SC2129  # separate appends on purpose: the quoted/unquoted heredoc split above is the point
    cat >> "$INSTALL_SCRIPT" <<VARS_EOF
AISUDO_PLATFORM="Linux"
AISUDO_BACKUP_ROOT="$AISUDO_BACKUP_ROOT"
AISUDO_BACKUP_KEEP=$AISUDO_BACKUP_KEEP
AISUDO_BACKUP_DIR=""
AISUDO_LOG_HINT="journalctl -u aisudo-daemon -n 50"
DAEMON_BIN="$DAEMON_BIN"
CLI_BIN="$CLI_BIN"
VARS_EOF
    declare -f aisudo_backup aisudo_prune_backups aisudo_restart_daemon \
               aisudo_health_check aisudo_rollback >> "$INSTALL_SCRIPT"

    cat >> "$INSTALL_SCRIPT" <<INSTALL_EOF

# Snapshot every file below overwrites, THEN arm the trap — both before the
# daemon is stopped, so any failure from here on has something to restore.
aisudo_backup /usr/local/bin/aisudo-daemon /usr/local/bin/aisudo \\
              /etc/aisudo/aisudo.toml /etc/systemd/system/aisudo-daemon.service
trap aisudo_rollback ERR EXIT

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

# Verified-answering, not merely is-active — see aisudo_health_check.
if aisudo_health_check; then
    trap - ERR EXIT   # the install stands; nothing left to roll back to
    info "aisudo-daemon is running and answering on its socket!"
    echo ""
    if id -nG "$BUILD_USER" | tr ' ' '\n' | grep -qx aisudo; then
        info "$BUILD_USER is already a member of the aisudo group"
    else
        echo "Next steps:"
        echo "  Add your user to the aisudo group:"
        echo "    sudo usermod -aG aisudo $BUILD_USER"
        echo "  (new group membership needs a fresh login shell or 'newgrp aisudo')"
        echo ""
    fi
    echo "=== aisudo setup completed at \$(date) ==="
    echo "View this log: cat /var/log/aisudo-setup.log"
else
    error "aisudo-daemon is not answering on its socket after the install."
    error "Check: journalctl -u aisudo-daemon -n 50"
    echo ""
    echo "=== aisudo setup FAILED at \$(date) ==="
    # Falls through to the EXIT trap, which restores the previous install.
    exit 1
fi

# Only reached on success — the failure branch exits above and the trap handles
# it, keeping this script on disk so a post-mortem has more than the log.
rm -f "\$0"
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
    AISUDO_LOG_HINT="tail -50 /var/log/aisudo.log"
    # Snapshot every file below overwrites, THEN arm the trap — both before the
    # daemon is stopped, so any failure from here on has something to restore.
    aisudo_backup /usr/local/bin/aisudo-daemon /usr/local/bin/aisudo \
                  /etc/aisudo/aisudo.toml /etc/newsyslog.d/aisudo.conf \
                  /Library/LaunchDaemons/ai.sudo.daemon.plist
    trap aisudo_rollback ERR EXIT

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

    # Verified-answering, not merely loaded — see aisudo_health_check.
    if aisudo_health_check; then
        trap - ERR EXIT   # the install stands; nothing left to roll back to
        info "aisudo-daemon is running and answering on its socket!"
        echo ""
        if dseditgroup -o checkmember -m "$BUILD_USER" aisudo &>/dev/null; then
            info "$BUILD_USER is already a member of the aisudo group"
        else
            echo "Next steps:"
            echo "  Add your user to the aisudo group:"
            echo "    sudo dseditgroup -o edit -a $BUILD_USER -t user aisudo"
            echo "  (new group membership needs a fresh login shell or 'sg aisudo -l')"
            echo ""
        fi
        echo "  Status:   sudo launchctl print system/ai.sudo.daemon"
        echo "  Logs:     tail -f /var/log/aisudo.log"
        echo "  Restart:  sudo launchctl kickstart -k system/ai.sudo.daemon"
    else
        error "aisudo-daemon is not answering on its socket after the install."
        error "Check: tail -50 /var/log/aisudo.log"
        error "Also: sudo launchctl print system/ai.sudo.daemon"
        # Falls through to the EXIT trap, which restores the previous install.
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
    # shellcheck disable=SC2001  # multi-line prefix; ${var//} cannot anchor per line
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
