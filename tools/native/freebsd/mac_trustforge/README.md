# mac_trustforge — TrustForge FreeBSD MAC policy module

Phase M reference module. Hooks four FreeBSD MAC framework events
(`mpo_vnode_check_open`, `mpo_vnode_check_exec`,
`mpo_socket_check_connect`, `mpo_proc_check_signal`), forwards each
event to a userspace bridge daemon over `/dev/mac_trustforge`, and
waits up to a configurable timeout for an allow / deny verdict.

If the daemon does not respond in time the hook **fails open** by
default — the kernel does not block the operation. This matches the
TrustForge "availability over correctness for unanchored events" rule
for early profiles. Set `security.mac.trustforge.fail_open=0` for
strict deployments.

> Status: **experimental**. Not production-ready. No custom
> cryptography is performed in-kernel; verdicts are computed by
> userspace, where TrustForge keys live.

## Layout

| Path                                                  | Purpose                                      |
|-------------------------------------------------------|----------------------------------------------|
| `kernel/mac_trustforge.c`                             | MAC policy module: hooks + cdev transport    |
| `kernel/Makefile`                                     | `bsd.kmod.mk` build glue                     |
| `userspace/tf-mac-bridge/main.go`                     | Go bridge daemon entry point                 |
| `userspace/tf-mac-bridge/bridge.go`                   | Shared bridge logic + decision client        |
| `userspace/tf-mac-bridge/cdev_freebsd.go`             | `/dev/mac_trustforge` driver (FreeBSD only)  |
| `userspace/tf-mac-bridge/cdev_other.go`               | Stub driver for non-FreeBSD developer hosts  |
| `userspace/tf-mac-bridge/bridge_test.go`              | Unit + end-to-end tests (host-portable)      |
| `etc/mac.conf.d/trustforge.conf`                      | Operator notes for sysctl tunables           |
| `etc/rc.d/tf-mac-bridge`                              | rc.d script for the bridge daemon            |

## Compatibility

| FreeBSD release | MAC framework                         | Status         |
|-----------------|---------------------------------------|----------------|
| 12.x            | Yes                                   | Untested       |
| **13.x**        | Yes (default)                         | **Supported**  |
| 14.x            | Yes                                   | Supported      |

The kernel must include `options MAC` (default in `GENERIC` since
FreeBSD 13). No custom kernel build is required.

## Building the kernel module

The kernel module **cannot be cross-compiled on macOS**. The bridge
build (Go, in `userspace/`) compiles on any host; only the kernel C
needs a FreeBSD build environment with `/usr/src` (or world headers)
present.

On a real FreeBSD host:

```sh
cd kernel
make
sudo make install        # copies mac_trustforge.ko to /boot/modules
sudo kldload mac_trustforge
```

To unload:

```sh
sudo kldunload mac_trustforge
```

To enable at boot, add to `/boot/loader.conf`:

```
mac_trustforge_load="YES"
```

## Building the userspace bridge

This compiles cleanly on FreeBSD, Linux, and macOS:

```sh
cd userspace/tf-mac-bridge
go vet ./...
go test ./...
go build -o tf-mac-bridge .
```

On non-FreeBSD hosts the stub `cdev_other.go` is built in; `Open()` of
`/dev/mac_trustforge` is a no-op so unit tests can run, but the binary
cannot do real work off FreeBSD.

## Running

After loading the module:

```sh
sudo /usr/local/sbin/tf-mac-bridge \
    --device=/dev/mac_trustforge \
    --daemon=http://127.0.0.1:8787/v1/decide \
    --timeout=100 \
    --fail-open=true \
    -v
```

Or via rc.d:

```sh
sudo cp etc/rc.d/tf-mac-bridge /usr/local/etc/rc.d/
sudo sysrc tf_mac_bridge_enable=YES
sudo service tf_mac_bridge start
```

## Tunables (sysctl)

| sysctl                                | Default | Meaning                                      |
|---------------------------------------|---------|----------------------------------------------|
| `security.mac.trustforge.enabled`     | 1       | 1 = enforce, 0 = bypass                      |
| `security.mac.trustforge.fail_open`   | 1       | 1 = allow on timeout, 0 = deny on timeout    |
| `security.mac.trustforge.timeout_ms`  | 100     | Userspace decision deadline (ms)             |
| `security.mac.trustforge.have_reader` | r/o     | 1 when bridge has `/dev/mac_trustforge` open |

## Wire format

Both kernel and userspace use the packed structures in
`kernel/mac_trustforge.c`:

```c
struct tf_event   { magic='TFEV', version, cookie, kind, pid, uid, gid,
                    mask, target_pid, target_sig, path_len, path[512] };
struct tf_verdict { magic='TFVD', version, cookie, result, _ };
```

Records are little-endian (only LE FreeBSD targets are supported:
amd64, arm64). The bridge serialises each event to the daemon as JSON
and reads back `{"result":<int>}` (0 = allow, positive errno = deny).

## Hook coverage

The four MAC hooks installed map onto the same TrustForge enforcement
events as the Linux LSM port:

| MAC hook                        | TF kind         | Notes                          |
|---------------------------------|-----------------|--------------------------------|
| `mpo_vnode_check_open`          | `vnode_open`    | Open with `accmode_t` mask     |
| `mpo_vnode_check_exec`          | `vnode_exec`    | Per-execve image check         |
| `mpo_socket_check_connect`      | `socket_connect`| AF_INET/AF_INET6 sockaddr      |
| `mpo_proc_check_signal`         | `proc_signal`   | Carries target pid + signum    |

The MAC framework does not currently expose a `socket_create`-style
hook in the same shape as Linux's; we ship `connect` because that's
the higher-value enforcement point. Adding more hooks is one
`mac_policy_ops` field at a time.

## Limitations / future work

- The cdev only allows a single reader at a time (the bridge daemon).
  If the bridge crashes, all in-flight requests fail-open per the
  default.
- `vn_fullpath()` is best-effort — if the kernel cannot resolve a
  vnode to a path the event's `path` field is empty and the daemon
  must decide based on uid/pid alone.
- IPv6 connect events carry only the port, not the address, in the
  current `path` formatting; this is a `snprintf` simplification, not
  a protocol limitation.
- The module does not (yet) bind labels onto vnodes/sockets/processes;
  it is a pure decision-broker. Adding labels is the work to compose
  with `mac_biba`/`mac_mls` in a stacked-MAC profile.

## See also

- `tools/native/linux/lsm_trustforge/` — the Linux LSM port this
  module mirrors.
- `tools/native/openbsd/pledge-trustforge/` — the OpenBSD supervisor
  approach (no LSM-style framework).
- `tools/native/illumos/` — DTrace-based monitoring on illumos.
- `docs/specs/TF-0009-enforcement-and-quarantine.md` — enforcement
  model the daemon implements.
- `docs/specs/TF-0006-policy.md` — policy language used to compute
  verdicts.
