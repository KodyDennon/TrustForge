# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# trustforge-firewall.rsc — example RouterOS firewall integration.
#
# Pattern:
#   1. /ip firewall filter rules mark suspicious flows with
#      packet-mark=trustforge-pending (configured ahead of time).
#   2. This script runs every N seconds via /system scheduler.
#   3. For each pending mark in /ip firewall connection it asks
#      tf-daemon (via trustforge-decide.rsc) whether to permit the
#      flow, then either:
#         - adds a stateless "drop" rule for the src/dst pair (deny),
#         - adds an explicit "accept" rule (allow), or
#         - logs and leaves it in pending (ask / fail-closed).
#
# Limitations:
#   - RouterOS firewall rules are append-only here; we don't reconcile
#     with prior decisions. A companion cleanup script
#     (`trustforge-firewall-gc.rsc`, not provided) is expected to age
#     out rules tagged with the trustforge comment prefix.
#   - The connection-tracking table is bounded; this script only looks
#     at the first 64 pending entries per run to keep CPU low.
#   - Mikrotik's /ip firewall uses comments (max 255 chars) as our
#     identity tag. We prefix every rule we author with
#     "tf-managed:" so a human or GC pass can tell what we did.
#
# Status: Draft (Phase 0). Reference example only.

:global tfDecide;

:if ([:typeof $tfDecide] != "code") do={
    /system script run trustforge-decide;
}

:local pendingMark "trustforge-pending";
:local commentPrefix "tf-managed:";
:local maxPerRun 64;

:local count 0;
:local pending [/ip firewall connection find packet-mark=$pendingMark];

:foreach c in=$pending do={
    :if ($count >= $maxPerRun) do={ :return; }
    :set count ($count + 1);

    :local src [/ip firewall connection get $c src-address];
    :local dst [/ip firewall connection get $c dst-address];
    :local proto [/ip firewall connection get $c protocol];

    # Strip the :port suffix RouterOS includes in src-address/dst-address.
    :local srcIp $src;
    :local dstIp $dst;
    :local colonSrc [:find $src ":"];
    :if ($colonSrc >= 0) do={ :set srcIp [:pick $src 0 $colonSrc]; }
    :local colonDst [:find $dst ":"];
    :if ($colonDst >= 0) do={ :set dstIp [:pick $dst 0 $colonDst]; }

    :local actor ("tf:actor:host:" . $srcIp);
    :local action ("network." . $proto . ".connect");
    :local target $dstIp;

    :local verdict [$tfDecide $actor $action $target];

    :local cmt ($commentPrefix . " " . $actor . " -> " . $target . " (" . $verdict . ")");

    :if ($verdict = "allow") do={
        # Idempotency: skip if we already authored an allow rule for
        # this src/dst pair.
        :local existing [/ip firewall filter find comment~("^" . $commentPrefix . ".*" . $srcIp . ".*" . $dstIp)];
        :if ([:len $existing] = 0) do={
            /ip firewall filter add chain=forward action=accept \
                src-address=$srcIp dst-address=$dstIp \
                comment=$cmt;
            :log info ("trustforge-firewall: ALLOW " . $srcIp . " -> " . $dstIp);
        }
    }
    :if ($verdict = "deny") do={
        :local existing [/ip firewall filter find comment~("^" . $commentPrefix . ".*" . $srcIp . ".*" . $dstIp)];
        :if ([:len $existing] = 0) do={
            # Insert at top of the chain so it short-circuits. The
            # `place-before=0` form prepends in RouterOS 7.x.
            /ip firewall filter add chain=forward action=drop \
                src-address=$srcIp dst-address=$dstIp \
                comment=$cmt \
                place-before=0;
            :log warning ("trustforge-firewall: DENY " . $srcIp . " -> " . $dstIp);
        }
    }
    :if ($verdict = "ask") do={
        :log info ("trustforge-firewall: ASK pending operator for " . $srcIp . " -> " . $dstIp);
    }
    :if ($verdict = "error") do={
        :log error ("trustforge-firewall: fail-closed on " . $srcIp . " -> " . $dstIp);
    }
}
