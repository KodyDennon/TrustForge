# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# trustforge-decide.rsc — RouterOS scripting helper that asks the local
# tf-daemon whether an (actor, action, target) tuple should be allowed.
#
# The daemon is expected to be reachable at http://127.0.0.1:8787 by
# default (the standard tf-daemon HTTP-bridge listener). On most
# Mikrotik deployments tf-daemon will not run on-box (RouterOS is a
# closed appliance OS); instead this script targets a sidecar host
# reachable on the management LAN. Override :daemonUrl below.
#
# Usage from another script or scheduler:
#
#   /system script run trustforge-decide \
#     [:tostr [$tfDecide \
#         actor="tf:actor:device:mikrotik/edge-01" \
#         action="firewall.input" \
#         target="203.0.113.7"]]
#
# Returns one of:
#   "allow"  — daemon returned decision=allow
#   "deny"   — daemon returned decision=deny
#   "ask"    — daemon returned decision=ask (caller decides fallback)
#   "error"  — fail-closed on transport / parse error
#
# RouterOS has no JSON parser; we use :find on a small response body.
# tf-daemon's /v1/decide returns minimal JSON of the shape
# {"decision":"allow","reason":"..."}.
#
# Status: Draft (Phase 0). Untested on RouterOS hardware. Syntax-checked
# only by the upstream lint harness (regex).

:global tfDaemonUrl;
:global tfDecideTimeoutSec;
:global tfDecideOnError;

# Defaults; override before invoking by setting the globals from the
# scheduler or from /system script environment.
:if ([:typeof $tfDaemonUrl] = "nothing") do={
    :set tfDaemonUrl "http://127.0.0.1:8787";
}
:if ([:typeof $tfDecideTimeoutSec] = "nothing") do={
    :set tfDecideTimeoutSec 2;
}
:if ([:typeof $tfDecideOnError] = "nothing") do={
    # On transport / parse error: "deny" = fail closed (recommended);
    # "allow" = fail open (only for non-security gating). Default deny.
    :set tfDecideOnError "deny";
}

:global tfDecide do={
    :local actor   $1;
    :local action  $2;
    :local target  $3;

    :global tfDaemonUrl;
    :global tfDecideTimeoutSec;
    :global tfDecideOnError;

    :if ([:len $actor] = 0 or [:len $action] = 0 or [:len $target] = 0) do={
        :log error "tfDecide: actor/action/target required";
        :return "error";
    }

    # Build the JSON body inline. RouterOS lacks string escape, so we
    # reject any caller arg that contains `"` or `\` — those would break
    # the daemon's JSON parser anyway.
    :foreach v in={$actor; $action; $target} do={
        :if ([:find $v "\""] >= 0 or [:find $v "\\"] >= 0) do={
            :log error "tfDecide: arg contains illegal char";
            :return "error";
        }
    }

    :local body ("{\"actor\":\"" . $actor . "\",\"action\":\"" . $action . "\",\"target\":\"" . $target . "\"}");
    :local url ($tfDaemonUrl . "/v1/decide");
    :local tmp ("trustforge-decide-resp-" . [:pick [/system clock get time] 0 8] . ".tmp");

    :do {
        /tool fetch \
            url=$url \
            http-method=post \
            http-header-field="Content-Type: application/json" \
            http-data=$body \
            mode=http \
            keep-result=yes \
            dst-path=$tmp \
            output=file \
            check-certificate=no \
            timeout=($tfDecideTimeoutSec . "s");
    } on-error={
        :log warning ("tfDecide: fetch failed url=" . $url);
        /file remove [find name=$tmp] || nothing;
        :return $tfDecideOnError;
    }

    # Read response body into a string. RouterOS's :file/get content
    # returns the text payload; for very large responses this is
    # truncated, but /v1/decide bodies are always small.
    :local raw "";
    :do {
        :set raw [/file get $tmp contents];
    } on-error={
        :log warning "tfDecide: cannot read response file";
        /file remove [find name=$tmp] || nothing;
        :return $tfDecideOnError;
    }
    /file remove [find name=$tmp];

    # Crude JSON probe — look for the literal "decision":"<value>".
    :if ([:find $raw "\"decision\":\"allow\""] >= 0) do={ :return "allow"; }
    :if ([:find $raw "\"decision\":\"deny\""]  >= 0) do={ :return "deny"; }
    :if ([:find $raw "\"decision\":\"ask\""]   >= 0) do={ :return "ask"; }

    :log warning ("tfDecide: unparseable response: " . $raw);
    :return $tfDecideOnError;
}

# Convenience: a simple log-only call so the script can be sourced and
# smoke-tested from /system script run trustforge-decide.
:local result [$tfDecide \
    "tf:actor:device:mikrotik/self" \
    "firewall.test" \
    "0.0.0.0"];
:log info ("trustforge-decide self-test: " . $result);
