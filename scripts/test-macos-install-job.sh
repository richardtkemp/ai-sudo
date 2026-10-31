#!/usr/bin/env bash
# Tests setup.sh's macOS launcher, install_macos (#2652).
#
# WHY THIS EXISTS: on macOS the normal agent path runs setup.sh as a child of
# aisudo-daemon. `launchctl bootout` of the daemon sends SIGTERM to the
# daemon's whole process group, so an install that stops the daemon INLINE
# kills itself at that step. install_macos must therefore never touch the
# daemon itself: it writes a one-shot launchd job and bootstraps it, and the
# job does the install. This checks that contract with launchctl stubbed, so
# it runs on Linux too. The real launchd behaviour is proved on a Mac (see the
# ticket); this guards against a refactor moving the bootout back inline.
#
# It sources the functions OUT OF setup.sh rather than keeping a copy.
#
# Usage: scripts/test-macos-install-job.sh   (no arguments; -h prints this)
# shellcheck disable=SC2317  # the stubs are called by the sourced setup.sh code, which shellcheck cannot see
set -euo pipefail
[[ "${1:-}" == -h || "${1:-}" == --help ]] && { sed -n '2,15p' "$0"; exit 0; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
LIB="$T/lib.sh"
awk '/^# Install rollback$/{on=1} /^# Pre-flight checks$/{on=0} on' "$REPO/setup.sh" >"$LIB"
grep -q '^install_macos() {' "$LIB" || { echo "FAIL: could not extract install_macos from setup.sh"; exit 2; }

fail() { echo "FAIL: $*"; exit 1; }
CALLS="$T/calls"

# One arm = one subshell that sources setup.sh's functions with every
# root-only command stubbed to a recorder, then runs install_macos.
# $1 is what the stubbed `launchctl print system/ai.sudo.install` reports:
# "absent", "stopped" or "running".
run_arm() {
    local install_job="$1"
    : >"$CALLS"
    mkdir -p "$T/jobs"
    set +e
    (
        set -euo pipefail
        info()  { :; }; warn() { :; }; error() { echo "[e] $*" >>"$CALLS"; }
        # shellcheck disable=SC1090
        source "$LIB"
        launchctl() {
            echo "launchctl $*" >>"$CALLS"
            if [[ "$1" == print && "$2" == system/ai.sudo.install ]]; then
                case "$install_job" in
                    absent)  return 113 ;;
                    stopped) echo "	state = not running" ;;
                    running) echo "	state = running" ;;
                esac
            fi
            return 0
        }
        # Root-only tools. Recorded, never run: the OLD inline code calls these,
        # and this test must be safe to run red against it.
        install()      { echo "install $*" >>"$CALLS"; }
        dseditgroup()  { echo "dseditgroup $*" >>"$CALLS"; }
        chown()        { echo "chown $*" >>"$CALLS"; }
        touch()        { echo "touch $*" >>"$CALLS"; }
        aisudo_backup() { echo "aisudo_backup $*" >>"$CALLS"; }
        aisudo_health_check() { return 0; }
        # shellcheck disable=SC2034  # read by the sourced setup.sh functions
        {
            RED=r; GREEN=g; YELLOW=y; NC=n  # defined above the extracted section
            SCRIPT_DIR="$REPO"; CONFIG_FILE="$T/none.toml"; AISUDO_GID=""
            AISUDO_PLATFORM=Darwin; AISUDO_BACKUP_ROOT="$T/backups"
            DAEMON_BIN="$T/aisudo-daemon"; CLI_BIN="$T/aisudo"; BUILD_USER=nobody
            AISUDO_SETUP_LOG="$T/setup.log"; AISUDO_JOB_DIR_BASE="$T/jobs"
        }
        install_macos
    ) >"$T/out" 2>&1
    RC=$?
    set -e
}

echo "== arm 1: the launcher leaves the daemon alone and bootstraps a one-shot job =="
run_arm absent
if grep -E '^launchctl (bootout|kickstart|kill|stop|remove).*ai\.sudo\.daemon' "$CALLS"; then
    fail "install_macos stopped the daemon from the launching process (it would SIGTERM itself)"
fi
grep -qE '^(install|dseditgroup|chown|touch|aisudo_backup) ' "$CALLS" \
    && fail "install_macos ran install steps itself instead of in the job: $(grep -E '^(install|dseditgroup|chown|touch|aisudo_backup) ' "$CALLS" | head -3)"
[[ $RC -eq 0 ]] || { cat "$T/out"; fail "install_macos exited $RC"; }
boot=$(grep '^launchctl bootstrap system ' "$CALLS") || fail "no launchctl bootstrap of a job: $(cat "$CALLS")"
plist=${boot#launchctl bootstrap system }
[[ -f "$plist" ]] || fail "bootstrapped plist $plist does not exist"
echo "   ok: no daemon bootout, no inline install steps, one job bootstrapped"

echo "== arm 2: the job's plist and script are well formed =="
python3 - "$plist" <<'PY' || fail "plist check failed"
import plistlib, sys
p = plistlib.load(open(sys.argv[1], "rb"))
assert p["Label"] == "ai.sudo.install", p["Label"]
assert p["RunAtLoad"] is True
assert "KeepAlive" not in p, "a one-shot job must not be kept alive"
assert p["StandardOutPath"] == p["StandardErrorPath"]
assert len(p["ProgramArguments"]) == 2

PY
script=$(python3 -c 'import plistlib,sys; print(plistlib.load(open(sys.argv[1],"rb"))["ProgramArguments"][1])' "$plist")
[[ -x "$script" ]] || fail "job script $script is missing or not executable"
bash -n "$script" || fail "job script does not parse"
grep -q '^aisudo_install_macos_job () *$' "$script" || fail "job script lacks the install function"
grep -q '^aisudo_rollback () *$' "$script" || fail "job script lacks the rollback function"
grep -qx 'aisudo_install_macos_job' "$script" || fail "job script never calls the install"
# declare -f must carry the newsyslog heredoc through intact.
grep -q '/var/log/aisudo.log    root:aisudo' "$script" || fail "newsyslog heredoc lost in the job script"
echo "   ok: one-shot plist, script parses and carries install + rollback"

echo "== arm 3: a stale stopped job from an earlier install is removed first =="
run_arm stopped
[[ $RC -eq 0 ]] || { cat "$T/out"; fail "exited $RC"; }
grep -n '' "$CALLS" | grep -E 'launchctl (bootout system/ai.sudo.install|bootstrap system)' >"$T/order"
[[ $(wc -l <"$T/order") -eq 2 && $(head -1 "$T/order") == *"bootout system/ai.sudo.install"* ]] \
    || fail "stale job not booted out before the bootstrap: $(cat "$CALLS")"
echo "   ok: stale job booted out, then the new one bootstrapped"

echo "== arm 4: a RUNNING install refuses a second one =="
run_arm running
[[ $RC -ne 0 ]] || fail "a second install started beside a running one"
grep -q '^launchctl bootstrap' "$CALLS" && fail "bootstrapped despite a running install"
grep -q '^launchctl bootout' "$CALLS" && fail "booted out the running install"
echo "   ok: refused, nothing booted out or started"

echo "PASS"
