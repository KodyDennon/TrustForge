# TrustForge Tailscale integration

This directory contains a Go sidecar (`tf-tailscale-sync`) that gates
Tailscale tailnet activity on TrustForge verdicts, plus example
artefacts showing how to wire the sidecar into Tailscale SSH and into
a Tailscale-ACL → TrustForge-policy translation.

## Status

**Phase 0 / pre-release.** Not production-ready. The reference
`tf-daemon` exists as a working reference; this sidecar remains useful primarily for
conformance testing against a mock daemon.

## What it does

The sidecar speaks two interfaces:

1. **Local API watcher.** It opens
   `/var/run/tailscale/tailscaled.sock` (the documented local API
   socket used by `tailscale.com/client/tailscale`), subscribes to
   `/localapi/v0/watch-ipn-bus`, and on every peer-update event
   queries `/v1/decide` on the local `tf-daemon`. On `decision: deny`
   it logs the deny and produces a proof event; on `allow` it does
   nothing (Tailscale's default is to accept the peer once Tailnet
   Lock has signed it).

2. **SSH auth-hook listener.** Tailscale SSH supports an external
   auth-request URL. The sidecar listens at
   `http://127.0.0.1:8789/trustforge/ssh/auth` and answers
   `{"allow": bool, "reason": "..."}` for each incoming SSH session
   request, after consulting the daemon.

## Why we don't import `tailscale.com/client/tailscale`

The upstream Go package is the canonical wrapper around the local
API. We hand-roll a thin client instead because:

- Pulling `tailscale.com` brings ~80 MB of transitive deps
  (Wireguard, BoringTun, magicsock, …) which is outsized for a thin
  sidecar.
- The TrustForge build is offline-first; CI does not have
  module-proxy access during integration tests.

The wire shape we use matches `tailscale.com/client/tailscale`'s
public methods (`Status`, `WatchIPNBus`); if the local API ever
changes shape, both the upstream package and this sidecar will need
updates in lockstep.

## Tailnet Lock interaction

Tailscale's [Tailnet
Lock](https://tailscale.com/kb/1226/tailnet-lock) signs new node
keys with a tailnet-owner key before peers will accept them. This
sidecar runs **alongside** Tailnet Lock, not instead of it:

- Tailnet Lock answers "is this a real peer in our tailnet?"
- TrustForge answers "should this peer be allowed to talk to this
  host *right now* under our policy?"

A deployment that wants strong identity should run both. The sidecar
treats `peer.online == true` as the trigger, which already implies
Tailnet Lock has accepted the peer.

## Layout

```
cmd/tf-tailscale-sync/
  go.mod
  main.go                 entry, flags, local-API client
  sync.go                 reconcile + SSH listener
  sync_test.go            unit + integration tests

examples/
  acl-translation.yaml    Tailscale ACL ↔ TrustForge capability map
  sshconfig.example       Tailscale-SSH external-auth wiring
```

## Install

```sh
# 1. Build.
cd cmd/tf-tailscale-sync
go build -o tf-tailscale-sync .
sudo install -m 0755 tf-tailscale-sync /usr/local/bin/tf-tailscale-sync

# 2. Run as a sidecar to tailscaled. The user must be in the
#    tailscale group (or root) to read the local-API socket.
sudo tee /etc/systemd/system/tf-tailscale-sync.service >/dev/null <<'EOF'
[Unit]
Description=TrustForge Tailscale sidecar
After=tailscaled.service network-online.target
Requires=tailscaled.service

[Service]
Environment=TF_DAEMON_URL=http://127.0.0.1:8787
Environment=TF_TAILSCALE_SSH_ADDR=127.0.0.1:8789
ExecStart=/usr/local/bin/tf-tailscale-sync \
    --daemon-url http://127.0.0.1:8787 \
    --ssh-addr  127.0.0.1:8789 \
    --fail-closed
Restart=on-failure
SupplementaryGroups=tailscale

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now tf-tailscale-sync
```

## Tailscale SSH wiring

See `examples/sshconfig.example` for three approaches:

1. **ACL `extAuth` block** — speculative; works once Tailscale
   exposes external auth hooks in the public ACL grammar.
2. **`tailscale up --advertise-ssh-extauth` CLI flag** — works on
   recent Tailscale builds; flag may move or be renamed.
3. **OpenSSH `ForceCommand` wrapper** — a portable fallback that
   works against a stock OpenSSH server when Tailscale SSH is not in
   use.

## Client API authentication

The Tailscale local API is **not** authenticated by network
credentials — it relies on Unix-socket peer credentials. The
`tailscale` group on the tailscaled host may read it. The sidecar's
systemd unit grants itself that group via `SupplementaryGroups`.

For the *Tailscale admin API* (the public API at `api.tailscale.com`,
used for ACL pushes and node provisioning), use a tailnet API key
or an OAuth client. The sidecar **does not** call the admin API —
it never pushes ACL changes back. ACL synthesis from a TrustForge
policy is a separate offline tool (see `examples/acl-translation.yaml`).

## Test

```sh
cd cmd/tf-tailscale-sync
go vet ./...
go test ./...
```

## Troubleshooting

- `local-api: dial unix /var/run/tailscale/tailscaled.sock: permission
  denied` — the user the sidecar runs as is not in the `tailscale`
  group. Add it: `sudo usermod -aG tailscale trustforge`. Restart
  the service.
- `local-api: dial unix /var/run/tailscale/tailscaled.sock: no such
  file or directory` — tailscaled isn't running, or it's running
  with a non-standard `--socket` path. Pass `--tailscale-socket` to
  match.
- `watch-ipn-bus: 426 Upgrade Required` — old tailscaled (pre-1.40)
  used a different streaming shape. Upgrade tailscaled.
- `SSH listener returns 503` even with `--fail-closed=false` — the
  HTTP listener returns 503 on *transport* error to the daemon
  (different from a deny). `--fail-closed=false` makes the auth
  hook return `allow: true` on transport error; the HTTP status is
  still 200 in that case. If you need a strict allow-on-transport-
  error path, edit `runSSHAuthListener` to override.
- Decisions arrive after the connection is already open — Tailscale
  does not gate established peer flows once the wireguard tunnel is
  up. The sidecar enforces on connection events; for in-flow
  enforcement you need a separate netfilter integration on each
  host (see `tools/native/linux/`).

## Hard rules carried over from the spec

- No custom cryptography in the sidecar; verdicts are obtained from
  a daemon that itself composes only reviewed primitives.
- Fail-closed by default. The sidecar denies on daemon-transport
  errors unless `--fail-closed=false` is set.
- Nothing here is production-ready. Treat this binary as an
  experimental draft until reviewed.
