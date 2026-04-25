# systemd-trustforge

Native systemd integration for TrustForge on Linux.

> Status: **Phase 0 / Draft.** `tf-daemon` itself is not yet implemented; these
> units describe how it will run once it exists. Path and identity choices
> here are normative for future packaging — keep them in sync with
> `docs/specs/TF-0001-core-architecture.md` and the `tools/tf-daemon/` crate
> when that crate lands.

## What's in this directory

| File | Install path | Purpose |
| --- | --- | --- |
| `tf-daemon.service` | `/etc/systemd/system/tf-daemon.service` | Main daemon unit (sandboxed, watchdog, socket-activated). |
| `tf-daemon.socket` | `/etc/systemd/system/tf-daemon.socket` | Creates `/run/trustforge/decide.sock` for `/v1/decide` callers. |
| `tf-daemon@.service` | `/etc/systemd/system/tf-daemon@.service` | Per-user / per-instance template (`tf-daemon@alice`). |
| `99-trustforge-journal.conf` | `/etc/systemd/journald.conf.d/99-trustforge-journal.conf` | Journal sizing + tagging for proof events. |
| `tmpfiles.d/trustforge.conf` | `/etc/tmpfiles.d/trustforge.conf` | Creates `/var/lib/trustforge`, `/etc/trustforge`, `/run/trustforge`, etc. on boot. |
| `sysusers.d/trustforge.conf` | `/etc/sysusers.d/trustforge.conf` | Allocates the `trustforge` system user/group. |
| `unit-generator/tf-daemon-generator` | `/usr/lib/systemd/system-generators/tf-daemon-generator` | Auto-creates instance units from `/etc/trustforge/instances/*.tf-daemon`. |

## Filesystem layout

| Path | Owner | Mode | Notes |
| --- | --- | --- | --- |
| `/etc/trustforge/` | `trustforge:trustforge` | `0750` | `config.yaml`, `policy.yaml`, `agent-contract.yaml`. |
| `/etc/trustforge/instances/` | `trustforge:trustforge` | `0750` | Per-instance configs picked up by `tf-daemon-generator`. |
| `/var/lib/trustforge/` | `trustforge:trustforge` | `0750` | Persistent state, key material, proof archive. |
| `/var/lib/trustforge/keys/` | `trustforge:trustforge` | `0700` | Long-lived signing material. |
| `/run/trustforge/` | `trustforge:trustforge` | `0750` | Runtime sockets including `decide.sock`. |
| `/var/log/trustforge/` | `trustforge:trustforge` | `0750` | Logs that supplement the journal. |

## Install

From the repo:

```sh
# 1. System user/group and directories.
sudo cp sysusers.d/trustforge.conf       /etc/sysusers.d/trustforge.conf
sudo cp tmpfiles.d/trustforge.conf       /etc/tmpfiles.d/trustforge.conf
sudo systemd-sysusers
sudo systemd-tmpfiles --create

# 2. Service + socket + per-user template.
sudo cp tf-daemon.service tf-daemon.socket tf-daemon@.service \
        /etc/systemd/system/

# 3. Journal tuning for proof events.
sudo install -d /etc/systemd/journald.conf.d
sudo cp 99-trustforge-journal.conf /etc/systemd/journald.conf.d/

# 4. Instance generator.
sudo install -d /usr/lib/systemd/system-generators
sudo install -m 0755 unit-generator/tf-daemon-generator \
        /usr/lib/systemd/system-generators/tf-daemon-generator

# 5. Reload + enable.
sudo systemctl daemon-reload
sudo systemctl restart systemd-journald
sudo systemctl enable --now tf-daemon.socket tf-daemon.service
```

A tarball/distro package will eventually do this; for now treat the above
as the canonical reference.

## Verify

```sh
# Syntax-check the units.
systemd-analyze verify /etc/systemd/system/tf-daemon.service
systemd-analyze verify /etc/systemd/system/tf-daemon.socket
systemd-analyze verify /etc/systemd/system/tf-daemon@.service

# Sandbox audit (lower score = tighter).
systemd-analyze security tf-daemon.service

# Confirm the socket is listening.
ss -lx | grep /run/trustforge/decide.sock
sudo systemctl status tf-daemon.socket
```

## Per-user and named instances

Two ways to spin up additional daemons:

1. **Per Linux user** — direct template invocation:

   ```sh
   sudo systemctl enable --now tf-daemon@alice.service
   ```

2. **Named instance via dropped config** — preferred for fleet management:

   ```sh
   sudo install -m 0640 -o trustforge -g trustforge \
        my-edge-node.tf-daemon /etc/trustforge/instances/my-edge-node.tf-daemon
   sudo systemctl daemon-reload   # triggers tf-daemon-generator
   sudo systemctl start tf-daemon@my-edge-node.service
   ```

   The generator wires the new instance into `multi-user.target.wants` and
   writes an `ExecStart=` drop-in pointing at the dropped config.

## Journal queries

`tf-daemon` emits two `SYSLOG_IDENTIFIER` streams:

* `tf-daemon` — operational logs (startup, errors, watchdog).
* `tf-proof`  — cryptographically-anchored proof events (decisions,
  capability grants, capability revocations, session attestations).

```sh
# Live tail of operational logs.
journalctl -u tf-daemon -f

# Just proof events, JSON format, ready to ship to a SIEM.
journalctl -t tf-proof -o json --no-pager

# Proof events from a specific instance, last 24h.
journalctl -u tf-daemon@my-edge-node -t tf-proof --since "24 hours ago"

# Decisions only (filter by structured field, once tf-daemon emits it).
journalctl -t tf-proof TF_EVENT=decision -o json-pretty

# Errors from any TrustForge unit since last boot.
journalctl -b -p err -u 'tf-daemon*'
```

If you ship logs to a central collector, prefer `journalctl -o json` over
the legacy text format — the JSON includes the `tf-proof` identifier and
all structured fields, which is what auditors will want.

## Security notes

* `tf-daemon.service` and `tf-daemon@.service` use the same hardening
  profile: `NoNewPrivileges`, `ProtectSystem=strict`, syscall filter,
  `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
  Do not weaken these without an ADR.
* Per `SECURITY.md` and the manifesto: **no custom crypto.** All signing
  primitives must come from reviewed libraries.
* The `decide.sock` is the daemon's only inbound API surface from local
  callers. Anything connecting to it must already have filesystem-level
  authority (the `trustforge` group).

## See also

* `docs/specs/TF-0001-core-architecture.md`
* `docs/profiles/` (deployment profiles)
* `tools/native/linux/pam_trustforge/`, `polkit_trustforge/`,
  `sudo_trustforge/`, `apparmor/`, `selinux/` — sibling Linux integrations.
