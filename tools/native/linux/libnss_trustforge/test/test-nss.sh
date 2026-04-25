#!/usr/bin/env bash
# test-nss.sh — end-to-end smoke test for libnss_trustforge.so.2
#
# Prereqs:
#   1. Module built and installed:    make && sudo make install
#   2. nsswitch.conf has `trustforge` on the passwd: line (see
#      nsswitch.conf.example).
#   3. Mock daemon running:           python3 test/mock-daemon.py &
#
# What it checks:
#   - getent passwd alice    -> succeeds, uid is in TF range (>=100000)
#   - getent passwd agent01  -> succeeds
#   - getent passwd nonexistent -> miss (so other NSS modules still get a
#     chance — proves we don't hijack the lookup chain).

set -u

PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
note()  { printf '  %s\n' "$*"; }

expect_hit() {
    local name="$1"
    local row
    row="$(getent passwd "$name" 2>/dev/null)"
    if [[ -z "$row" ]]; then
        red   "FAIL: getent passwd $name -> no row"
        FAIL=$((FAIL+1))
        return 1
    fi
    # passwd row format: name:x:uid:gid:gecos:home:shell
    local uid
    uid=$(printf '%s' "$row" | awk -F: '{print $3}')
    if (( uid < 100000 )); then
        red   "FAIL: getent passwd $name -> uid $uid is below TF range"
        FAIL=$((FAIL+1))
        return 1
    fi
    green "PASS: $name resolves -> $row"
    PASS=$((PASS+1))
    return 0
}

expect_miss() {
    local name="$1"
    if getent passwd "$name" >/dev/null 2>&1; then
        red   "FAIL: getent passwd $name unexpectedly returned a row"
        FAIL=$((FAIL+1))
        return 1
    fi
    green "PASS: $name correctly falls through (not found)"
    PASS=$((PASS+1))
    return 0
}

note "Sanity: confirm libnss_trustforge.so.2 is on the loader path..."
if ! ldconfig -p 2>/dev/null | grep -q libnss_trustforge.so.2; then
    note "WARN: ldconfig does not see libnss_trustforge.so.2 — install first:"
    note "      sudo make install && sudo ldconfig"
fi

note "Sanity: confirm the mock daemon socket exists..."
if [[ ! -S "${HOME}/.trustforge/decide.sock" ]]; then
    red   "FAIL: ${HOME}/.trustforge/decide.sock not present"
    note  "      start it with:  python3 test/mock-daemon.py &"
    exit 1
fi

note "Sanity: confirm /etc/nsswitch.conf lists trustforge for passwd..."
if ! grep -E '^passwd:.*\btrustforge\b' /etc/nsswitch.conf >/dev/null 2>&1; then
    red   "FAIL: /etc/nsswitch.conf does not include trustforge on passwd: line"
    note  "      see nsswitch.conf.example"
    exit 1
fi

echo
expect_hit  "alice"
expect_hit  "agent01"
expect_miss "nonexistent"
expect_miss "nope-$$"

echo
if (( FAIL == 0 )); then
    green "All ${PASS} checks passed."
    exit 0
else
    red   "${FAIL} failed, ${PASS} passed."
    exit 1
fi
