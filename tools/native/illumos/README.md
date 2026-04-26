# tf-illumos — TrustForge illumos / SmartOS / OmniOS integration

illumos does not have an LSM-style kernel security framework. The
tools that exist for *observation* are excellent (DTrace), and zones
provide strong isolation, but there is no in-kernel hook that can
synchronously block a syscall and consult userspace.

This directory therefore ships a **monitoring + advisory** integration:

1. A DTrace script (`dtrace/trustforge.d`) emits structured events
   for `open*`, `exec*`, and TCP `connect-request` probes.
2. A Go bridge (`cmd/tf-illumos-bridge/`) reads those events,
   asks the local TrustForge daemon (`/v1/decide`) for an allow /
   deny verdict, and writes the decision to an optional audit log.
3. A zone hook (`zoneadm/trustforge-zone-hook.sh`) registers each
   zone with the daemon on `boot` / `halt` so the daemon can attach
   per-zone identity and policy.
4. SMF service definitions (`smf/manifest.xml`) install the bridge as
   a managed service.

> Status: **experimental**, monitoring-only. Not production-ready.

## Important: this is advisory, not enforcement

DTrace cannot block syscalls by default on illumos. The bridge logs
denials and reports them to the daemon, but the kernel proceeds with
the operation. To convert this to true enforcement is **future work**;
the two known paths are:

- **`kvmrw` / hot-patching kernel pointers** to redirect a syscall
  through a TrustForge-controlled wrapper that returns `EACCES` when
  policy denies. This requires either a custom kernel build or
  exclusive use of `kvmrw`-capable diagnostic interfaces — both are
  fragile and are explicitly *not* recommended in production today.
- **SUID kernel-binary modification** to embed a static check before
  syscall dispatch. Requires the operator to maintain a custom
  illumos build.

We document these for completeness only. Do not deploy them.

## Layout

| Path                                        | Purpose                                    |
|---------------------------------------------|--------------------------------------------|
| `dtrace/trustforge.d`                       | DTrace script: open, exec, TCP connect     |
| `cmd/tf-illumos-bridge/main.go`             | Go bridge entry point                      |
| `cmd/tf-illumos-bridge/bridge.go`           | DTrace stream parser + decider client      |
| `cmd/tf-illumos-bridge/bridge_test.go`      | Unit + end-to-end tests                    |
| `zoneadm/trustforge-zone-hook.sh`           | Zone create/boot/halt registration         |
| `smf/manifest.xml`                          | SMF service definition for the bridge      |
| `smf/illumos-bridge-start.sh`               | SMF start method                           |

## Building

```sh
cd cmd/tf-illumos-bridge
go vet ./...
go test ./...
go build -o tf-illumos-bridge .
```

The binary compiles on any host. The `dtrace` binary is illumos-only;
use `--stdin` (or the test fixture in `bridge_test.go`) on developer
machines.

## Installation

```sh
pfexec install -d /usr/lib/trustforge /var/log/trustforge
pfexec install -m 0755 cmd/tf-illumos-bridge/tf-illumos-bridge \
    /usr/lib/trustforge/
pfexec install -m 0755 dtrace/trustforge.d /usr/lib/trustforge/
pfexec install -m 0755 zoneadm/trustforge-zone-hook.sh /usr/lib/trustforge/
pfexec install -m 0755 smf/illumos-bridge-start.sh /usr/lib/trustforge/

pfexec svccfg import smf/manifest.xml
pfexec svcadm enable trustforge/illumos-bridge
```

Verify:

```sh
svcs -p trustforge/illumos-bridge
tail -f /var/log/trustforge/audit.jsonl
```

## Configuration

SMF properties (`svcprop -p config trustforge/illumos-bridge`):

| Property            | Default                              | Meaning                                   |
|---------------------|--------------------------------------|-------------------------------------------|
| `config/dtrace_path`| `/usr/sbin/dtrace`                   | DTrace binary                             |
| `config/script`     | `/usr/lib/trustforge/trustforge.d`   | Script invoked by `dtrace -qs`            |
| `config/daemon_url` | `http://127.0.0.1:8787/v1/decide`    | tf-daemon decision endpoint               |
| `config/audit_file` | `/var/log/trustforge/audit.jsonl`    | JSONL audit log (advisory)                |
| `config/timeout_ms` | 200                                  | Per-decision deadline                     |
| `config/verbose`    | false                                | Verbose stderr logging                    |

Change a property and refresh:

```sh
pfexec svccfg -s trustforge/illumos-bridge:default \
    setprop config/timeout_ms = count: 500
pfexec svcadm refresh trustforge/illumos-bridge
pfexec svcadm restart trustforge/illumos-bridge
```

## Wire format

Each DTrace event is emitted as a single tab-separated text line:

```
TFEV<TAB>kind=<name><TAB>k=v<TAB>k=v...
```

| Key      | Always present | Meaning                                  |
|----------|----------------|------------------------------------------|
| `kind`   | yes            | `vnode_open`, `vnode_exec`, `socket_connect` |
| `ts`     | yes            | nanoseconds since boot                   |
| `pid`    | yes            | process id                               |
| `uid`    | yes            | real uid                                 |
| `zone`   | yes            | zone id (0 == global)                    |
| `exec`   | yes            | `execname`                               |
| `path`   | open / exec    | argv0 / opened path                      |
| `family` | connect        | 2 = AF_INET, 10 = AF_INET6               |
| `addr`   | connect        | textual peer address                     |
| `port`   | connect        | TCP destination port                     |

The bridge re-frames each event as JSON for the daemon's
`/v1/decide` endpoint and also writes a JSONL record per event to
the audit file.

## Zone integration

The hook script accepts the zoneadm action and zone name:

```sh
/usr/lib/trustforge/trustforge-zone-hook.sh boot myzone
/usr/lib/trustforge/trustforge-zone-hook.sh halt myzone
```

It POSTs a small JSON document (`zone`, `state`, `brand`, `path`,
`uuid`, `action`) to `/v1/zones`. Failures are logged but do not
block the zone operation.

To wire it into zoneadm proper, drop a wrapper into
`/etc/zones/index.d/` or invoke the script from a brand-specific
hook (e.g. `/usr/lib/brand/lipkg/postboot`).

## Limitations

- **Advisory only** as noted above.
- The TCP `connect-request` probe is the canonical illumos
  TCP-layer probe; on very old kernels lacking the `tcp` provider
  the script can be wired through `socket:::` instead.
- The bridge keeps the dtrace child running for the lifetime of the
  service. If dtrace exits unexpectedly the SMF method exits and
  SMF will re-run it according to the contract restart policy.
- Zone-id resolution from DTrace context is best-effort; the
  `zonename`/`curthread->t_procp->p_zone->zone_id` chain works on
  illumos-gate as of mid-2024 but is technically a private detail
  of the kernel ABI.

## See also

- `tools/native/linux/lsm_trustforge/` — Linux LSM port (true
  enforcement).
- `tools/native/freebsd/mac_trustforge/` — FreeBSD MAC port (true
  enforcement).
- `tools/native/openbsd/pledge-trustforge/` — OpenBSD supervisor
  (cooperative enforcement).
- `docs/specs/TF-0009-enforcement-and-quarantine.md` — enforcement
  model the daemon implements.
