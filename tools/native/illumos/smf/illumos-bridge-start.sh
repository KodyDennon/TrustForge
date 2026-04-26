#!/usr/bin/bash
#
# illumos-bridge-start.sh — SMF start method for trustforge/illumos-bridge.
#
# Reads SMF properties via svcprop(1) and execs the Go bridge with the
# corresponding flags. Installed at /usr/lib/trustforge/.

set -euo pipefail

SVC="svc:/trustforge/illumos-bridge:default"

prop() {
    /usr/bin/svcprop -p "$1" "$SVC" 2>/dev/null || echo ""
}

DTRACE_PATH="$(prop config/dtrace_path)"
SCRIPT="$(prop config/script)"
DAEMON_URL="$(prop config/daemon_url)"
AUDIT_FILE="$(prop config/audit_file)"
TIMEOUT_MS="$(prop config/timeout_ms)"
VERBOSE="$(prop config/verbose)"

: "${DTRACE_PATH:=/usr/sbin/dtrace}"
: "${SCRIPT:=/usr/lib/trustforge/trustforge.d}"
: "${DAEMON_URL:=http://127.0.0.1:8787/v1/decide}"
: "${TIMEOUT_MS:=200}"

ARGS=(
    --dtrace="$DTRACE_PATH"
    --script="$SCRIPT"
    --daemon="$DAEMON_URL"
    --timeout="$TIMEOUT_MS"
)
if [[ -n "$AUDIT_FILE" ]]; then
    ARGS+=(--audit="$AUDIT_FILE")
fi
if [[ "$VERBOSE" == "true" ]]; then
    ARGS+=(-v)
fi

exec /usr/lib/trustforge/tf-illumos-bridge "${ARGS[@]}"
