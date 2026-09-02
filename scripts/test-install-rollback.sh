#!/usr/bin/env bash
# Tests setup.sh's install-rollback library.
#
# WHY THIS EXISTS: the rollback only ever runs when an install has already gone
# wrong, i.e. on the path nobody exercises. A rollback that has never been shown
# to fire is decoration. So this drives the real functions through both failure
# shapes AND a success control, proving it fires when it should and stays out of
# the way when it should not.
#
# It sources the functions OUT OF setup.sh rather than keeping a copy, so it
# cannot pass against code that is no longer what ships.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB=$(mktemp); trap 'rm -f "$LIB"' EXIT
awk '/^# Install rollback$/{on=1} /^# Platform-specific install functions$/{on=0} on' \
    "$REPO/setup.sh" >"$LIB"
for fn in aisudo_backup aisudo_prune_backups aisudo_restart_daemon aisudo_rollback; do
    grep -q "^$fn() {" "$LIB" || { echo "FAIL: could not extract $fn from setup.sh"; exit 2; }
done

T=$(mktemp -d); trap 'rm -f "$LIB"; rm -rf "$T"' EXIT
mkdir -p "$T/root/usr/local/bin" "$T/root/etc/aisudo"
info()  { echo "[i] $*"; }
warn()  { echo "[w] $*"; }
error() { echo "[e] $*"; }

# --- substitutions, and only these ---
# install(1): drop -o/-g, which need root. Nothing under test depends on ownership.
install() { local a=(); while [[ $# -gt 0 ]]; do case "$1" in -o|-g) shift 2;; *) a+=("$1"); shift;; esac; done; command install "${a[@]}"; }
systemctl() { :; }
# shellcheck disable=SC1090
source "$LIB"
AISUDO_PLATFORM=Linux
AISUDO_BACKUP_ROOT="$T/backups"
DAEMON_BIN="$T/newbuild/aisudo-daemon"
# The real check shells out to /usr/local/bin/aisudo against the live socket.
aisudo_health_check() { [[ "${FAKE_HEALTHY:-1}" == 1 ]]; }
# --- end substitutions ---

D="$T/root/usr/local/bin/aisudo-daemon"; C="$T/root/etc/aisudo/aisudo.toml"
fail() { echo "FAIL: $*"; exit 1; }

# HARNESS SHAPE, and it matters: each arm is a bare `( set -e; ... )` subshell run
# as a PLAIN command with the harness's own -e off. Putting the subshell on the
# left of `||` would suppress set -e INSIDE it -- bash exempts any command in an
# &&/|| list -- so the simulated failure would not abort and the arm would
# silently assert nothing while looking green. That happened while writing this.

echo "== arm 1: a command fails mid-install (the set -e abort path) =="
echo OLD-DAEMON >"$D"; echo OLD-CONFIG >"$C"
set +e
( set -e
  aisudo_backup "$D" "$C"
  trap aisudo_rollback ERR EXIT
  echo NEW-DAEMON >"$D"; echo NEW-CONFIG >"$C"
  false                    # stands in for a failing install/groupadd/daemon-reload
  echo "REACHED CODE AFTER THE FAILURE - BUG"
  trap - ERR EXIT ) >/dev/null 2>&1
rc=$?; set -e
[[ $rc -ne 0 ]]                   || fail "arm 1 reported success"
[[ "$(cat "$D")" == OLD-DAEMON ]] || fail "daemon not restored: $(cat "$D")"
[[ "$(cat "$C")" == OLD-CONFIG ]] || fail "config not restored: $(cat "$C")"
echo "   ok: trap fired, both files restored, code after the failure never ran"

echo "== arm 2: daemon starts but does not answer (health check fails) =="
echo OLD2-DAEMON >"$D"
set +e
( set -e
  aisudo_backup "$D"
  trap aisudo_rollback ERR EXIT
  echo BROKEN-DAEMON >"$D"
  if FAKE_HEALTHY=0 aisudo_health_check; then trap - ERR EXIT; else exit 1; fi ) >/dev/null 2>&1
rc=$?; set -e
[[ $rc -ne 0 ]]                    || fail "arm 2 reported success"
[[ "$(cat "$D")" == OLD2-DAEMON ]] || fail "not restored: $(cat "$D")"
echo "   ok: an unhealthy daemon rolls back even though no command errored"

echo "== control: a clean install keeps its changes =="
set +e
( set -e
  aisudo_backup "$D"
  trap aisudo_rollback ERR EXIT
  echo GOOD-DAEMON >"$D"
  if aisudo_health_check; then trap - ERR EXIT; else exit 1; fi ) >/dev/null 2>&1
rc=$?; set -e
[[ $rc -eq 0 ]]                    || fail "control reported failure"
[[ "$(cat "$D")" == GOOD-DAEMON ]] || fail "control rolled back a good install: $(cat "$D")"
echo "   ok: the trap does not fire on success"

echo "== prune keeps the last 5 snapshots =="
# Pre-made dirs with distinct, backdated mtimes -- `ls -t` orders on mtime, and
# faking it beats sleeping a second per snapshot.
mkdir -p "$AISUDO_BACKUP_ROOT"
for i in $(seq 1 8); do
    d="$AISUDO_BACKUP_ROOT/fake-$i"; mkdir -p "$d"; touch -d "@$((1600000000 + i))" "$d"
done
aisudo_backup "$D" >/dev/null
n=$(find "$AISUDO_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | wc -l)
[[ $n -eq 5 ]] || fail "expected 5 retained snapshots, got $n"
echo "   ok: retained $n"

echo "== first install: nothing to back up, and no bogus restore =="
set +e
( set -e
  aisudo_backup "$T/root/does-not-exist"
  trap aisudo_rollback ERR EXIT
  false ) >/dev/null 2>&1
rc=$?; set -e
[[ $rc -ne 0 ]] || fail "first-install arm reported success"
echo "   ok: fails loudly with no restore to attempt"

echo "== setup.sh actually WIRES the library in, in the right order =="
# The arms above prove the library works. They arm the trap themselves, so they
# say nothing about whether setup.sh does. This generates the real Linux install
# script and checks the order the install commands will run in.
GEN="$T/generated-install.sh"
(
  set -e
  SCRIPT_DIR="$REPO"; CONFIG_FILE="$SCRIPT_DIR/aisudo.toml"
  DAEMON_BIN="$SCRIPT_DIR/target/release/aisudo-daemon"
  CLI_BIN="$SCRIPT_DIR/target/release/aisudo"
  AISUDO_GID=""; BUILD_USER="${SUDO_USER:-$USER}"
  # Intercept the launch: capture the generated script instead of running it.
  systemd-run() { cp "$INSTALL_SCRIPT" "$GEN"; rm -f "$INSTALL_SCRIPT"; }
  eval "$(awk '/^install_linux\(\) \{$/{on=1} on; /^\}$/{if(on)exit}' "$REPO/setup.sh")"
  install_linux >/dev/null 2>&1
)
[[ -f "$GEN" ]] || fail "setup.sh did not generate an install script"
bash -n "$GEN"  || fail "the generated install script does not parse"
# Verbatim, not heredoc-expanded: an unquoted heredoc would have eaten these.
grep -q 'local rc=\$?' "$GEN" || fail "rollback body was mangled on the way into the generated script"
grep -q 'for p in "\$@"' "$GEN" || fail "backup body was mangled on the way into the generated script"
# The disarm pattern carries its trailing comment on purpose: without it the
# `trap - ERR EXIT;` INSIDE the rollback function body matches too, and the arm
# counts six landmarks instead of five.
order=$(grep -n 'aisudo_backup /usr/local/bin\|^trap aisudo_rollback\|^    systemctl stop\|^if aisudo_health_check\|^    trap - ERR EXIT   #' "$GEN" | cut -d: -f1 | tr '\n' ' ')
set -- $order
[[ $# -eq 5 ]] || fail "expected 5 wiring landmarks in the generated script, found $#: $order"
[[ $1 -lt $2 && $2 -lt $3 && $3 -lt $4 && $4 -lt $5 ]] \
  || fail "wiring out of order (backup, trap, stop, health, disarm) = $order"
echo "   ok: backup -> arm trap -> stop daemon -> health check -> disarm ($order)"

echo "install-rollback: all arms passed"
