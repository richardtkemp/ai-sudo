#!/usr/bin/env bash
# Tests setup.sh's target/ ownership pre-build check (#1647).
#
# Usage: scripts/test-target-ownership.sh   (no arguments; -h prints this)
#
# The check exists to turn a misleading cargo failure into a clear one, so it
# only earns its place if it actually fires. Making files owned by another user
# needs root, so this inverts the setup instead: files owned by the CURRENT user,
# checked against a DIFFERENT build user, is the same split seen from the other
# side. A same-user control and a missing-dir control prove it stays quiet when
# it should.
#
# It extracts the function OUT OF setup.sh rather than keeping a copy, so it
# cannot pass against code that is no longer what ships.
set -euo pipefail

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
sed -n '/^aisudo_check_target_ownership() {$/,/^}$/p' "$REPO/setup.sh" >"$T/lib.sh"
grep -q '^aisudo_check_target_ownership() {' "$T/lib.sh" \
    || { echo "FAIL: could not extract aisudo_check_target_ownership from setup.sh"; exit 2; }
error() { echo "[e] $*"; }
unset -f aisudo_check_target_ownership
# shellcheck disable=SC1091
source "$T/lib.sh"

fail() { echo "FAIL: $*"; exit 1; }
me=$(id -un)
# Any existing user other than me; root always exists.
other=root
[[ "$me" != "$other" ]] || other=nobody

mkdir -p "$T/target/release/build"
touch "$T/target/release/aisudo" "$T/target/release/build/bindings.rs"

echo "== arm: files owned by someone other than the build user =="
set +e
out=$(aisudo_check_target_ownership "$T/target" "$other" 2>&1)
rc=$?
set -e
[[ $rc -ne 0 ]]                          || fail "check passed despite foreign-owned files"
[[ "$out" == *"not owned by the build user '$other'"* ]] || fail "message does not name the build user: $out"
# target/, release/, build/ and two files: 5 paths owned by $me.
[[ "$out" == *"5 $me"* ]]                || fail "per-owner count missing or wrong: $out"
[[ "$out" == *"chown -R '$other'"* ]]    || fail "no chown remedy offered: $out"
echo "   ok: refused, named the owner split and the remedy"

echo "== control: everything owned by the build user =="
aisudo_check_target_ownership "$T/target" "$me" >/dev/null 2>&1 || fail "check fired on a clean tree"
echo "   ok: silent on a single-owner tree"

echo "== control: no target/ yet (fresh clone) =="
aisudo_check_target_ownership "$T/nope" "$other" >/dev/null 2>&1 || fail "check fired on a missing dir"
echo "   ok: silent when there is nothing to check"

echo "PASS"
