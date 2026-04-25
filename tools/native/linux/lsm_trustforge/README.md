# trustforge_lsm — TrustForge Linux Security Module

Phase M1 reference module. Hooks five LSM events
(`inode_permission`, `file_permission`, `socket_create`,
`socket_connect`, `bprm_set_creds`), forwards each event to a
userspace daemon over `NETLINK_USERSOCK` (multicast group 29), and
waits up to a configurable timeout for an allow / deny verdict.

If the daemon does not respond in time the hook **fails open** by
default — the kernel does not block the operation and an error is
written to `dmesg`. This matches the TrustForge "availability over
correctness for unanchored events" rule for early profiles. Set the
module parameter `fail_open=0` for strict deployments.

> Status: **experimental**. Not production-ready. No custom
> cryptography is performed in-kernel; verdicts are the responsibility
> of userspace, which is where TrustForge keys live.

## Files

| File | Purpose |
|------|---------|
| `trustforge_lsm.c`              | Kernel module: hooks + netlink transport |
| `Kbuild`                        | In-kernel-tree build descriptor |
| `Makefile`                      | Out-of-tree build, DKMS, bridge build, test |
| `dkms.conf`                     | DKMS package descriptor |
| `userspace/tf-lsm-bridge.c`     | Userspace netlink ↔ Unix-socket bridge |
| `tests/test-load-unload.sh`     | Sanity test: build, insmod, rmmod |

## Compatibility matrix

| Kernel        | LSM stacking? | Status                  |
|---------------|---------------|-------------------------|
| < 5.7         | No            | Not supported           |
| 5.7 – 5.14    | Yes (early)   | Build, but unsupported  |
| **>= 5.15**   | Yes           | **Supported target**    |
| 6.x           | Yes           | Supported (CI target)   |

The module uses `security_add_hooks()` and `DEFINE_LSM(...)`. It
requires `CONFIG_SECURITY=y` and `CONFIG_SECURITY_NETWORK=y`. It does
**not** require BPF LSM — that is the M2/M3/M4 path.

## Build

You need kernel headers/build tools matching the running kernel. On
Debian/Ubuntu:

```sh
sudo apt-get install build-essential linux-headers-$(uname -r)
```

On Fedora:

```sh
sudo dnf install kernel-devel kernel-headers gcc make
```

Then:

```sh
make            # builds trustforge_lsm.ko + userspace/tf-lsm-bridge
make KDIR=/usr/src/linux-headers-6.6.0
```

> This build host (the macOS machine running TrustForge development)
> does **not** have a Linux kernel build tree. Cross-building the
> module here is not supported; build on a Linux host or in a
> container with matching kernel headers.

## Install

### Manual

```sh
sudo make install
sudo modprobe trustforge_lsm timeout_ms=100 fail_open=1
sudo /usr/sbin/tf-lsm-bridge --daemon /run/trustforge/decide.sock
```

### Via DKMS

```sh
sudo make dkms        # adds + builds + installs for current kernel
sudo modprobe trustforge_lsm
```

To uninstall: `sudo make uninstall`.

## Module parameters

| Param          | Default | Meaning |
|----------------|---------|---------|
| `timeout_ms`   | 100     | Max time to wait for userspace verdict |
| `enabled`      | 1       | Globally enable enforcement (0 = bypass) |
| `fail_open`    | 1       | On timeout: 1 = allow, 0 = deny (`-EACCES`) |

Set at load time (`modprobe trustforge_lsm timeout_ms=50 fail_open=0`)
or at runtime via `/sys/module/trustforge_lsm/parameters/*`.

## Wire format

Both the in-kernel and userspace sides use the packed structures
defined in `trustforge_lsm.c` and `tf-lsm-bridge.c`. The bridge
serialises each event as one line of JSON to the local TrustForge
daemon's Unix socket, and reads back one line of JSON containing
`{"result": <int>}` (0 = allow, negative errno = deny).

## Debugging

```sh
dmesg | grep trustforge          # init / errors / load events
journalctl -u tf-lsm-bridge      # bridge log if run via systemd
sudo ./userspace/tf-lsm-bridge -v   # foreground, stderr logging
```

Common failure modes:

- **`netlink_kernel_create` returns NULL** — another module has
  already claimed `NETLINK_USERSOCK` group 29. Choose a different
  group via a future module parameter.
- **Hooks fire but verdict never arrives** — bridge isn't running,
  or the daemon socket path is wrong. The hook will fail open after
  `timeout_ms`.
- **`insmod` fails with "Invalid module format"** — kernel headers
  don't match the running kernel. Run `uname -r` and check
  `/lib/modules/$(uname -r)/build` exists.

## Performance notes

- The pending-decision hash table is keyed by a 64-bit cookie and
  uses a single spinlock; this is fine for moderate hook rates
  (thousands per second). Heavier workloads should switch to a
  per-CPU table or RCU.
- `wait_event_interruptible_timeout` is used so signals can wake
  blocked hooks; this prevents the module from converting a daemon
  hang into an unkillable D-state process.
- Path resolution (`dentry_path_raw`) is best-effort; some
  callsites pass an inode without a hashed dentry, in which case the
  event carries an empty path. Userspace must tolerate this.

## Testing

```sh
sudo bash tests/test-load-unload.sh           # default kernel
sudo bash tests/test-load-unload.sh /path/to/kernel/build
```

The test only proves the module loads, surfaces in `lsmod`, prints
its init banner, and unloads cleanly. Functional / decision tests
require the daemon and live in `crates/tf-conformance` (planned).

## See also

- `tools/native/linux/ebpf/` — the eBPF LSM alternative (M2-M4),
  which is preferable on kernels with `CONFIG_BPF_LSM=y` because it
  doesn't require a kernel module build.
- `docs/specs/TF-0009-enforcement-and-quarantine.md` — enforcement
  model the daemon implements.
- `docs/specs/TF-0006-policy.md` — policy language used to compute
  verdicts.
