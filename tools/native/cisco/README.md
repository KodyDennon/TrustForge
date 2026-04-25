# TrustForge Cisco IOX / Guest Shell package

This directory is the upstream source for the `trustforge` IOX
package targeted at Cisco Catalyst, IOS-XE, and IOS-XR devices that
support Guest Shell.

## Status

**Phase 0 / pre-release.** The IOX package references a `tf-daemon`
binary built for `x86_64-unknown-linux-musl` that does not exist
yet. It is produced by upstream CI when `v0.1.0` is tagged.

## When to use this

- The site already runs Cisco edge gear and you want TrustForge
  enforcement co-located with the device rather than as a separate
  appliance.
- You want AAA decisions for SSH / enable mode / config commits to
  flow through TrustForge via the TACACS+ bridge.
- You need on-box decide+proof for routing-plane actions in air-gapped
  or LoRa-relay topologies (Packet Mode, see TF-0001).

## Layout

```
iox/package.yaml          IOX package descriptor (ioxclient)
iox/start.sh              Container entrypoint
iox/scripts/install.py    NX-API helper to push + activate the package
examples/router-policy.yaml  TACACS+ <-> TF bridge example policy
```

## Install

Build the IOX package on a workstation that has `ioxclient` from the
Cisco IOX SDK:

```sh
# 1. Build the package.
ioxclient package iox/package.yaml
# -> produces trustforge-0.1.0.tar

# 2. Push and activate. Replace user/host/password.
export CISCO_PASSWORD='...'
python3 iox/scripts/install.py \
    --host  10.0.0.1 \
    --user  admin \
    --package trustforge-0.1.0.tar
```

Or do it manually from the device CLI:

```
device# copy scp:trustforge-0.1.0.tar bootflash:
device# app-hosting install appid trustforge package bootflash:trustforge-0.1.0.tar
device# app-hosting activate appid trustforge
device# app-hosting start    appid trustforge
device# show app-hosting list
```

## Configure

Copy a policy into the running container and point tf-daemon at it:

```
device# copy scp:router-policy.yaml bootflash:
device# app-hosting data appid trustforge copy bootflash:router-policy.yaml /data/etc/policy.yaml
device# app-hosting reload appid trustforge
```

Wire AAA so that SSH login flows through tf-daemon:

```
device(config)# aaa group server tacacs+ trustforge
device(config-sg)#  server-private 127.0.0.1 single-connection key 0 trustforge-bridge
device(config-sg)#  exit
device(config)# aaa authentication login default group trustforge local
```

The `examples/router-policy.yaml` shows how to map TF risk classes
(R0-R5) to TACACS+ privilege levels and how to apply a negative
capability so nobody enters enable mode without an approval ticket.

## Test

```
# Daemon liveness from the host's Guest Shell.
device# guestshell run curl -s http://127.0.0.1:8642/v1/health

# Force a deny: try to log in as a non-admin from an off-policy subnet.
ssh untrusted@10.0.0.1
# Expected: "TrustForge denied: source_subnet not in 10.0.0.0/8"

# Inspect proof events.
device# guestshell run tail -n 50 /data/log/proof.log
```

## Troubleshooting

- `app-hosting activate` fails with `Resources unavailable` — the
  package descriptor's `cpu` / `memory` exceed the platform's IOX
  budget. Switch `resources.profile` to `c1.tiny` in
  `iox/package.yaml` and rebuild.
- TACACS+ bridge times out and AAA falls back to `local` — confirm the
  daemon is listening on 127.0.0.1:49 inside the container and that
  the host's `tacacs-server` config points at the loopback. Set
  `bridges.tacacs_plus.on_timeout: deny` in the policy if you want a
  fail-closed posture.
- Proof events missing after a reload — `/data` is mapped to NVRAM /
  bootflash; ensure the IOX package's `resources-disk.tf-data` survives
  reboots on your platform (some Cisco models clear scratch volumes).
- NX-API install script returns 401 — IOS-XE requires the `nxapi`
  feature enabled and a privileged user. Check `show feature | inc
  nxapi`.

## Hard rules carried over from the spec

- No custom cryptography. Compose reviewed primitives only.
- The TACACS+ bridge speaks the existing protocol; do not invent a
  TF-flavored TACACS+ wire format.
- Hybrid / post-quantum readiness must be possible without changing
  the bridge contract; classical suites are fine for the v0.1
  reference impl.
- Nothing is production-ready. Treat the binaries as experimental
  drafts until the upstream review gate clears.
