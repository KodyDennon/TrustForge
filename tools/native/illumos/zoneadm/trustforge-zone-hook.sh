#!/usr/bin/bash
#
# trustforge-zone-hook.sh — illumos zone {create,boot,halt} hook for
# TrustForge.
#
# Registers each zone with the local TrustForge daemon so the daemon
# can attach a per-zone identity, policy, and audit profile. The hook
# is meant to be invoked from the SMF service or from a wrapper around
# zoneadm(1M):
#
#     /usr/lib/trustforge/trustforge-zone-hook.sh boot   <zonename>
#     /usr/lib/trustforge/trustforge-zone-hook.sh halt   <zonename>
#     /usr/lib/trustforge/trustforge-zone-hook.sh create <zonename>
#
# A simple zoneadm-aware operator can register the hook with:
#
#     # /etc/zones/index.d/trustforge.sh:
#     /usr/lib/trustforge/trustforge-zone-hook.sh "$1" "$2"
#
# This script intentionally has no dependencies beyond curl and jq;
# it is safe to run before user-level Go binaries are available.

set -euo pipefail

DAEMON_URL="${TF_DAEMON_URL:-http://127.0.0.1:8787/v1/zones}"
HOOK_LOG="${TF_HOOK_LOG:-/var/log/trustforge/zone-hook.log}"

usage() {
    echo "usage: $0 {create|boot|halt|reboot|destroy} <zonename>" >&2
    exit 2
}

if [[ $# -lt 2 ]]; then
    usage
fi

ACTION="$1"
ZONE="$2"

case "$ACTION" in
    create|boot|halt|reboot|destroy) ;;
    *) usage ;;
esac

mkdir -p "$(dirname "$HOOK_LOG")"
exec >>"$HOOK_LOG" 2>&1
printf '[%s] action=%s zone=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ACTION" "$ZONE"

# Best-effort gather zone metadata from zoneadm/zonecfg.
ZONE_STATE="$(zoneadm -z "$ZONE" list -p 2>/dev/null | awk -F: '{print $3}' || true)"
ZONE_BRAND="$(zoneadm -z "$ZONE" list -p 2>/dev/null | awk -F: '{print $7}' || true)"
ZONE_PATH="$(zoneadm -z "$ZONE" list -p 2>/dev/null | awk -F: '{print $4}' || true)"
ZONE_UUID="$(zoneadm -z "$ZONE" list -p 2>/dev/null | awk -F: '{print $5}' || true)"

PAYLOAD=$(printf '{"action":"%s","zone":"%s","state":"%s","brand":"%s","path":"%s","uuid":"%s","platform":"illumos"}' \
    "$ACTION" "$ZONE" "$ZONE_STATE" "$ZONE_BRAND" "$ZONE_PATH" "$ZONE_UUID")

# Fire-and-forget POST. If curl is missing or the daemon is down,
# log and continue — zone operations must not be blocked by hook
# failures.
if command -v curl >/dev/null 2>&1; then
    curl --silent --show-error --fail \
         --max-time 2 \
         -H 'Content-Type: application/json' \
         -d "$PAYLOAD" \
         "$DAEMON_URL" \
         || printf '[%s] WARN tf-daemon notify failed for zone=%s action=%s\n' \
             "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ZONE" "$ACTION"
else
    printf '[%s] WARN curl(1) missing; cannot notify daemon\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

exit 0
