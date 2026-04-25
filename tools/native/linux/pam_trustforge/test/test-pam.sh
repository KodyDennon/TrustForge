#!/usr/bin/env bash
#
# test-pam.sh — exercise pam_trustforge.so end-to-end via pamtester.
#
# Requires:
#   - pamtester (apt install pamtester / dnf install pamtester)
#   - python3
#   - sudo (or run as root) — pamtester typically needs to read /etc/pam.d
#     and pam_trustforge.so must already be installed in $PAMDIR. To avoid
#     installing system-wide for tests, we drop a service config that
#     points at the freshly-built .so via an absolute path using
#     pam_permit-style wrapping is not possible, so we DO install the
#     module to a temporary copy of $PAMDIR. The script will warn if it
#     can't.
#
# Strategy:
#   1. Start mock-daemon.py with --decision allow.
#   2. Run `pamtester trustforge-test "$USER" authenticate` — expect success.
#   3. Stop mock; restart with --decision deny.
#   4. Run pamtester again — expect failure.
#
# Exit code 0 = both assertions passed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOD_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SO_PATH="$MOD_DIR/pam_trustforge.so"
SERVICE="trustforge-test"
PAMD_FILE="/etc/pam.d/$SERVICE"
SOCK_PATH="${HOME}/.trustforge/decide.sock"
MOCK="$SCRIPT_DIR/mock-daemon.py"

err() { printf 'error: %s\n' "$*" >&2; }
info() { printf '[test] %s\n' "$*" >&2; }

cleanup() {
    if [[ -n "${MOCK_PID:-}" ]] && kill -0 "$MOCK_PID" 2>/dev/null; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    rm -f "$SOCK_PATH" 2>/dev/null || true
}
trap cleanup EXIT

# --- preflight ---------------------------------------------------------

if ! command -v pamtester >/dev/null 2>&1; then
    err "pamtester not found — install it (apt install pamtester / dnf install pamtester)"
    exit 2
fi

if [[ ! -f "$SO_PATH" ]]; then
    err "pam_trustforge.so not built — run 'make' in $MOD_DIR first"
    exit 2
fi

if [[ ! -r "$PAMD_FILE" ]]; then
    err "missing $PAMD_FILE — create it with the following contents (run as root):"
    cat <<EOF >&2

  cat <<'CONF' | sudo tee $PAMD_FILE
  auth     required   pam_trustforge.so
  account  required   pam_trustforge.so
  session  required   pam_trustforge.so
  CONF

and ensure pam_trustforge.so is installed under your distro's PAM module
directory (typically /lib/security or /lib/x86_64-linux-gnu/security).
EOF
    exit 2
fi

mkdir -p "$(dirname "$SOCK_PATH")"

# --- helper: spawn mock daemon ----------------------------------------

start_mock() {
    local decision="$1"
    rm -f "$SOCK_PATH"
    python3 "$MOCK" --socket "$SOCK_PATH" --decision "$decision" >/tmp/tf-mock.log 2>&1 &
    MOCK_PID=$!
    # Wait up to 2s for socket to appear
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [[ -S "$SOCK_PATH" ]]; then return 0; fi
        sleep 0.2
    done
    err "mock daemon did not create $SOCK_PATH"
    cat /tmp/tf-mock.log >&2 || true
    return 1
}

stop_mock() {
    if [[ -n "${MOCK_PID:-}" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
        unset MOCK_PID
    fi
}

# --- tests ------------------------------------------------------------

PASS=0
FAIL=0

assert_allow() {
    info "case: decision=allow — expecting authenticate to SUCCEED"
    start_mock allow
    if pamtester "$SERVICE" "$USER" authenticate </dev/null >/tmp/tf-pamtester.log 2>&1; then
        info "  PASS"
        PASS=$((PASS + 1))
    else
        err "  FAIL — pamtester returned non-zero on allow"
        cat /tmp/tf-pamtester.log >&2 || true
        FAIL=$((FAIL + 1))
    fi
    stop_mock
}

assert_deny() {
    info "case: decision=deny — expecting authenticate to FAIL"
    start_mock deny
    if pamtester "$SERVICE" "$USER" authenticate </dev/null >/tmp/tf-pamtester.log 2>&1; then
        err "  FAIL — pamtester returned success on deny"
        FAIL=$((FAIL + 1))
    else
        info "  PASS"
        PASS=$((PASS + 1))
    fi
    stop_mock
}

assert_allow
assert_deny

info "results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
