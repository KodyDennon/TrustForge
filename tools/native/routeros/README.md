# TrustForge RouterOS (Mikrotik) integration

This directory contains RouterOS scripting-language helpers that let a
Mikrotik device consult a local-LAN `tf-daemon` for authorization
decisions and translate the verdicts into `/ip firewall` rules.

## Status

**Phase 0 / pre-release.** Untested on RouterOS hardware. The scripts
in `scripts/` have been syntax-checked by the upstream lint harness
only — Mikrotik does not publish a standalone offline script
validator, so authoritative testing requires a CHR (Cloud Hosted
Router) VM or a physical board.

> **Heads-up.** RouterOS is a closed appliance OS. There is no way to
> install native binaries (and therefore `tf-daemon` itself) on the
> device. This integration assumes `tf-daemon` runs on a *sidecar
> host* on the management LAN — typically a tiny Linux box, a NAS
> jail, or another router that *can* run binaries (OpenWRT, VyOS).

## Layout

```
scripts/trustforge-decide.rsc      decide-helper script (sourced)
scripts/trustforge-firewall.rsc    example firewall integration
examples/router-policy.yaml        sample tf-daemon policy
```

## Install

On the Mikrotik shell (Winbox terminal, SSH, or Webfig):

```
# 1. Pull the helper scripts onto the device. Replace the URL with
#    your release / mirror path.
:tool fetch \
    url=https://example.com/trustforge/routeros/trustforge-decide.rsc \
    dst-path=trustforge-decide.rsc

:tool fetch \
    url=https://example.com/trustforge/routeros/trustforge-firewall.rsc \
    dst-path=trustforge-firewall.rsc

# 2. Import them into /system script.
/system script add name=trustforge-decide   source=[/file get trustforge-decide.rsc   contents]
/system script add name=trustforge-firewall source=[/file get trustforge-firewall.rsc contents]

# 3. Point the helper at your sidecar tf-daemon.
/system script environment set [find name=tfDaemonUrl]       value="http://10.10.0.42:8787"
/system script environment set [find name=tfDecideTimeoutSec] value=2
/system script environment set [find name=tfDecideOnError]    value="deny"

# 4. Sanity-check the helper.
/system script run trustforge-decide
/log print where topics~"script" and message~"trustforge-decide self-test"

# 5. Mark candidate flows for inspection. Example: every new
#    forward-chain TCP connection from the IoT VLAN.
/ip firewall mangle add chain=prerouting \
    in-interface=vlan40 connection-state=new protocol=tcp \
    action=mark-packet new-packet-mark=trustforge-pending passthrough=yes \
    comment="tf-pending: candidates for trustforge-firewall.rsc"

# 6. Schedule the firewall reconciler.
/system scheduler add name=trustforge-firewall \
    interval=10s on-event="/system script run trustforge-firewall" \
    comment="TrustForge firewall reconciler"
```

## Packaging into an `.npk`

Mikrotik signs `.npk` packages with a vendor-only key. Third parties
**cannot** produce an `.npk` that the router will load without
disabling code signing (which RouterOS does not allow). The supported
distribution paths for third-party scripts are therefore:

- raw `.rsc` files fetched onto the device with `/tool fetch`,
- a `/system script add` payload baked into a backup file, or
- `container` packages (RouterOS 7.x ARM/64 only) when the asset is
  *itself* a Linux container — not applicable to plain scripts.

If a vendor partnership is in place, the `.npk` build flow is:

```
# These tools are vendor-internal and not publicly distributed.
mkpkg-tool --name trustforge-routeros \
           --version 0.1.0 \
           --arch all \
           --include scripts/ \
           --sign-with mikrotik-partner.key \
           --out trustforge-routeros-0.1.0.npk
```

The TrustForge project does **not** ship a pre-built `.npk` and has
no plans to do so without an upstream partnership.

## Configure

`scripts/trustforge-decide.rsc` reads three globals that you can set
either via `/system script environment` (persistent) or by `:set` at
the top of a calling script:

| Global               | Default                  | Purpose                              |
| -------------------- | ------------------------ | ------------------------------------ |
| `tfDaemonUrl`        | `http://127.0.0.1:8787`  | Base URL of the sidecar tf-daemon.   |
| `tfDecideTimeoutSec` | `2`                      | `/tool fetch` timeout, in seconds.   |
| `tfDecideOnError`    | `deny`                   | Verdict on transport / parse error.  |

The companion `examples/router-policy.yaml` is the **daemon-side**
policy. Drop it on your sidecar host as
`/etc/trustforge/policy.yaml` and reload `tf-daemon`.

## Test

```
# 1. Self-test the decide helper (logs to /log).
/system script run trustforge-decide

# 2. Watch the firewall reconciler create/drop rules in real time.
/log print follow where topics~"script" and message~"trustforge-firewall"

# 3. Inspect the rules it wrote.
/ip firewall filter print where comment~"^tf-managed:"

# 4. Force a deny on the daemon side and confirm a drop rule appears
#    within one scheduler tick.
```

## Troubleshooting

- `/tool fetch` returns `failure: dns-server failure` — RouterOS uses
  the system DNS settings; make sure `/ip dns` has servers configured
  *and* that the sidecar IP doesn't require name resolution. The
  helper defaults to a literal IP for that reason.
- `expected end of command (line N column M)` on import — that's the
  RouterOS parser; it is unforgiving of comments mid-expression. The
  scripts here have been split to keep `:if` / `:foreach` blocks
  comment-free internally.
- `tfDecide returns "error"` on every call — `/tool fetch` on
  RouterOS 6.x predates HTTP/1.1 keep-alive negotiation against some
  daemons; upgrade to 7.x or front the daemon with a tiny reverse
  proxy.
- The reconciler keeps adding duplicate rules — your idempotency
  comment doesn't match. Check that the comment prefix in
  `trustforge-firewall.rsc` matches what your earlier rules used.

## Hard rules carried over from the spec

- No custom cryptography on the device; verdicts are obtained from a
  daemon that itself composes only reviewed primitives.
- Fail-closed by default. Do not change `tfDecideOnError` to `allow`
  unless the action class is non-security (e.g. metric collection).
- Nothing here is production-ready. Treat the scripts as experimental
  drafts until reviewed against your topology.
