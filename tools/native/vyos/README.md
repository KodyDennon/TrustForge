# TrustForge VyOS Salt formula

This directory is the upstream source for the `trustforge` Salt
formula targeted at VyOS 1.4+ routers. It installs `tf-daemon`,
writes a generated config, and rewrites the firewall so that gated
traffic flows through `tf-proxy` before leaving the router.

## Status

**Phase 0 / pre-release.** The formula pulls a release tarball from

```
https://github.com/trustforge/trustforge/releases/download/v0.1.0/tf-daemon-<arch>.tar.gz
```

Those tarballs do not exist yet. They are produced by upstream CI when
`v0.1.0` is tagged. Until then the formula is intended for review and
salt-system testing only — `state.apply trustforge` will fail at the
download step.

## When to use this

Use this when the gateway router itself runs VyOS and you want
TrustForge enforcement co-located with the routing data plane (rather
than as an off-path appliance). Typical topologies:

- Edge router for a small office / homelab where VyOS already terminates
  WAN and serves DHCP. tf-daemon provides per-flow decide+proof for
  outbound traffic.
- VyOS-on-VM in a cloud VPC acting as the egress gateway. TrustForge
  gates exfil from workloads behind the VPC.

## Layout

```
salt/trustforge/init.sls            Salt state file
salt/trustforge/files/config.yaml.j2  tf-daemon config template
salt/trustforge/files/firewall.j2     VyOS firewall rules template
pillar/trustforge.sls                 sample pillar data
```

## Install

On a VyOS box with `salt-minion` (or salt-call --local):

```sh
# 1. Place the formula on the salt master (or locally).
sudo mkdir -p /srv/salt /srv/pillar
sudo cp -r salt/trustforge   /srv/salt/
sudo cp    pillar/trustforge.sls /srv/pillar/

# 2. Add to top.sls.
sudo tee /srv/salt/top.sls > /dev/null <<'EOF'
base:
  '*':
    - trustforge
EOF
sudo tee /srv/pillar/top.sls > /dev/null <<'EOF'
base:
  '*':
    - trustforge
EOF

# 3. Apply.
sudo salt-call --local state.apply trustforge
```

## Configure

Edit `/srv/pillar/trustforge.sls` (or the host-scoped pillar). The
sample includes:

- `version` / `arch` — which release tarball to pull.
- `profile` — TrustForge deployment profile, defaults to
  `tf-home-compatible`.
- `gated_interfaces` — list of VyOS interface names whose new flows
  must clear tf-proxy.
- `bridges` — which compatibility bridges (WebAuthn, OAuth/GNAP, TLS,
  …) to enable.

After editing the pillar, re-run `state.apply trustforge`.

## Test

```sh
# 1. Daemon liveness.
sudo systemctl status trustforge

# 2. Decide endpoint.
curl --unix-socket /var/run/trustforge/decide.sock \
     http://localhost/v1/health

# 3. Firewall ruleset present.
show firewall name TRUSTFORGE-GATE
show firewall name TRUSTFORGE-DECIDE

# 4. Generate a deny and confirm the proof event lands.
curl -s --unix-socket /var/run/trustforge/decide.sock \
     -X POST -H 'content-type: application/json' \
     -d '{"actor":"tf:actor:test","action":"egress","target":"203.0.113.7"}' \
     http://localhost/v1/decide
sudo tail -n 20 /var/log/trustforge/proof.log
```

## Troubleshooting

- `state.apply` fails at `archive.extracted: trustforge_binary` — the
  v0.1.0 release tarball does not exist yet (Phase 0). Use a locally
  built tarball and pin `source` to a `file://` URL while testing.
- Firewall script applied but rules missing — VyOS needs the script to
  run inside `vbash` with `script-template`. Confirm:
  `sudo /config/scripts/trustforge-firewall.sh` runs cleanly.
- `tf-daemon` starts but cannot bind the control socket — ensure
  `/var/run/trustforge` exists and is owned `trustforge:trustforge`. A
  reboot wipes `/var/run`; the systemd unit recreates it but stale
  ACLs from manual edits can persist.
- `commit` fails with "configuration changed by another user" — VyOS
  serializes config edits. Stop concurrent `vbash` sessions and retry.

## Hard rules carried over from the spec

- No custom cryptography. `tf-daemon` composes reviewed primitives.
- Hybrid / post-quantum readiness from day one; classical suite is
  fine for the v0.1 reference impl, but the config schema must allow
  switching without protocol breakage.
- Nothing is production-ready. Treat the published binaries as
  experimental drafts until the upstream review gate clears.
