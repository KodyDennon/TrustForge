#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# pre-gravity-trustforge.sh — Pi-hole gravity hook.
#
# Run me from /opt/pihole/gravity.sh's pre-update phase (or via cron a
# few minutes before the gravity refresh) to pull the current
# TrustForge allow/deny list and merge it with Pi-hole's gravity DB.
#
# How it works:
#
#   1. POST a tiny request to the local tf-daemon's /v1/decide endpoint
#      asking, in effect, "give me the allow/deny tuples that apply to
#      this Pi-hole's resolver actor". The daemon returns a small JSON
#      object with two arrays, `allow` and `deny`, each containing
#      hostnames.
#   2. Translate those arrays into Pi-hole's whitelist / blacklist
#      shape using the supported `pihole -w` and `pihole -b` commands
#      (or the `gravity.db` SQLite schema for batch mode).
#   3. Touch a sentinel file the gravity-update timer reads so it
#      doesn't double-run.
#
# The script fails closed: if the daemon is unreachable, we *do not*
# remove the existing block list. We log the failure and exit 0 so a
# transient daemon outage does not mass-unblock domains.
#
# Status: Draft (Phase 0). Reference example only.

set -u

DAEMON_URL="${TF_DAEMON_URL:-http://127.0.0.1:8787}"
ACTOR="${TF_PIHOLE_ACTOR:-tf:actor:device:pihole/$(hostname -s)}"
SENTINEL="${TF_PIHOLE_SENTINEL:-/run/trustforge/pihole-pre-gravity.done}"
LOG_TAG="trustforge-pre-gravity"
TIMEOUT="${TF_PIHOLE_TIMEOUT:-5}"

# Path to the pihole CLI; let users override for tests.
PIHOLE="${PIHOLE_BIN:-/usr/local/bin/pihole}"

log() { logger -t "$LOG_TAG" -- "$*"; printf '%s\n' "$*" >&2; }

mkdir -p "$(dirname "$SENTINEL")" 2>/dev/null || true

# Build the decide-request body. We use a single decide call that
# returns the full tuple set rather than one call per domain because
# Pi-hole gravity batches happen rarely and need O(thousands) of
# domains in one shot.
read -r -d '' BODY <<EOF || true
{"actor":"$ACTOR","action":"pihole.gravity.refresh","target":"resolver"}
EOF

RESP="$(mktemp)"
trap 'rm -f "$RESP"' EXIT

http_code=$(
    curl --silent --show-error --output "$RESP" \
         --write-out '%{http_code}' \
         --max-time "$TIMEOUT" \
         --header 'content-type: application/json' \
         --request POST \
         --data "$BODY" \
         "$DAEMON_URL/v1/decide" 2>/dev/null \
    || echo "000"
)

if [ "$http_code" != "200" ]; then
    log "daemon $DAEMON_URL returned $http_code; leaving gravity untouched (fail-closed)"
    exit 0
fi

# Pi-hole gravity DB lives under /etc/pihole/gravity.db (older
# releases used flat files under /etc/pihole/*.list). We let the
# `pihole -w` / `pihole -b` CLI handle whichever schema is on-disk.

# Extract the allow / deny arrays without pulling in jq (Pi-hole
# images don't always ship it). This is intentionally permissive: the
# daemon's allow/deny arrays are flat string arrays of hostnames.
extract_array() {
    local key=$1
    sed -n "s/.*\"$key\":\s*\[\([^]]*\)\].*/\1/p" "$RESP" \
        | tr ',' '\n' \
        | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//'
}

ALLOW="$(extract_array allow)"
DENY="$(extract_array deny)"

allow_count=0
deny_count=0

if [ -n "$ALLOW" ]; then
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        if "$PIHOLE" -w "$host" --quiet >/dev/null 2>&1; then
            allow_count=$((allow_count + 1))
        else
            log "warn: failed to whitelist $host"
        fi
    done <<<"$ALLOW"
fi

if [ -n "$DENY" ]; then
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        if "$PIHOLE" -b "$host" --quiet >/dev/null 2>&1; then
            deny_count=$((deny_count + 1))
        else
            log "warn: failed to blacklist $host"
        fi
    done <<<"$DENY"
fi

date -u +%FT%TZ > "$SENTINEL"

log "merged TrustForge tuples: $allow_count allowed, $deny_count denied"
exit 0
