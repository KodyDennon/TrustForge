# libnss_trustforge

A glibc Name Service Switch (NSS) module that resolves TrustForge actors as
POSIX users and groups so that tools like `ssh`, `sudo`, `ls -l`, `id`, and
`getent` can see actor names alongside `/etc/passwd` entries.

> **Status: Phase 0 / Draft.** The TrustForge daemon exists as a working
> reference and `/v1/import-credential` is bearer-gated. This module is
> mock-tested and still fails closed to `NOTFOUND` when
> `/run/trustforge/decide.sock` is unavailable.

## What it does

When something on the system calls `getpwnam("alice")` and `alice` is not in
`/etc/passwd`, glibc walks the modules listed in `/etc/nsswitch.conf`. With
TrustForge enabled, glibc loads `libnss_trustforge.so.2`, which talks to the
local TrustForge daemon over a Unix-domain socket and asks "do you know an
actor named `alice`?". If yes, the module synthesises a `struct passwd`
whose `pw_uid`/`pw_gid` are derived from a stable hash of the actor id
(above 100000 so they cannot collide with system or LDAP accounts).

Supported entry points:

| NSS function                       | Purpose                               |
|------------------------------------|---------------------------------------|
| `_nss_trustforge_getpwnam_r`       | name -> passwd                        |
| `_nss_trustforge_getpwuid_r`       | uid -> passwd (TF range only)         |
| `_nss_trustforge_getgrnam_r`       | name -> group                         |
| `_nss_trustforge_getgrgid_r`       | gid -> group (TF range only)          |
| `_nss_trustforge_setpwent`         | start enumeration                     |
| `_nss_trustforge_getpwent_r`       | next entry                            |
| `_nss_trustforge_endpwent`         | finish enumeration                    |

## Build

Requires glibc headers (for `nss.h`, `pwd.h`, `grp.h`) and a C99 compiler.

Debian / Ubuntu:

```sh
sudo apt install libc6-dev gcc make
make
```

Fedora / RHEL:

```sh
sudo dnf install glibc-headers glibc-devel gcc make
make
```

The Makefile target `check-headers` will tell you if the required headers
are missing:

```sh
make check-headers
```

The output artifact is `libnss_trustforge.so.2`. The trailing `.2` is the
glibc NSS ABI version and is **not optional** — `nsswitch.conf` looks up
exactly this filename.

> **macOS / BSD note**: this module targets glibc only. macOS uses
> Open Directory, not NSS, and is handled by the planned
> `tools/native/macos/` directory. The Makefile will fail to compile on
> macOS because `nss.h` does not exist there; that's expected.

## Install

```sh
sudo make install                       # drops .so.2 into /lib/x86_64-linux-gnu/
sudo cp nsswitch.conf.example /tmp/     # review first — do not blindly overwrite
sudoedit /etc/nsswitch.conf             # add `trustforge` after `files`
```

The minimal change to `/etc/nsswitch.conf` is two lines:

```
passwd: files trustforge
group:  files trustforge
```

After editing nsswitch.conf, no daemon restart is required — every new
process picks up the change at first NSS lookup. Existing long-lived
processes (sshd, etc.) keep their old config until restart.

You can confirm with:

```sh
getent passwd <some-trustforge-actor-name>
id    <some-trustforge-actor-name>
```

## Uninstall

```sh
sudo make uninstall
sudoedit /etc/nsswitch.conf             # remove `trustforge` from passwd/group
```

## Security caveats — please read

NSS modules are **loaded into every process that performs a name lookup**.
That includes `init`, `sshd`, `sudo`, `login`, `cron`, `systemd-logind`, and
any normal binary that calls `getpwnam()` or `getgrnam()`. A bug or hang in
this module becomes a bug or hang in the entire authentication path. With
that in mind:

- The module deliberately uses **no third-party libraries** — only POSIX
  syscalls and stdlib. No libcurl, no JSON parser, no TLS stack.
- Connection to the daemon is short, over the system local AF_UNIX
  socket. Filesystem ownership, group membership, service-manager policy,
  and daemon endpoint auth form the trust boundary.
- The module **fails closed-but-quiet**: any error returns
  `NSS_STATUS_NOTFOUND` (or `TRYAGAIN` on transient socket failure). It
  must never crash, hang indefinitely, or grant access on its own.
- UID/GID hashes use FNV-1a, which is **not cryptographic**. The hash is
  used purely for namespace-local POSIX id derivation; authentication and
  authority decisions are made by the daemon, not by the hash.
- The module never reads or writes `/etc/shadow`. Authentication of a
  TrustForge actor is handled by the PAM module (`pam_trustforge`) and
  the TrustForge daemon, not by NSS.
- Consider keeping enumeration disabled in production by configuring the
  daemon to refuse `/v1/list-actors`. Bulk enumeration of actors is
  rarely what you want and leaks principal names.

## How `getpwuid_r` resolves UID -> actor

The module reserves the range `[100000, 0x3FFFFFFF]` for TrustForge
actors. Any uid outside that range short-circuits to `NSS_STATUS_NOTFOUND`
without contacting the daemon, so `ls -l` on a system file does not pay a
socket round-trip. Inside the range, the module asks the daemon
`POST /v1/lookup-uid {"uid": <n>}` and trusts the daemon's answer; if two
actors hash to the same uid (extremely unlikely at this hash width), the
daemon resolves the collision authoritatively.

## Testing

A mock daemon is provided under `test/`:

```sh
python3 test/mock-daemon.py &           # listens on a test Unix socket
make
sudo make install
test/test-nss.sh                        # runs `getent passwd ...` checks
```

The test script verifies both a hit (returns a row with a TF-range uid) and
a miss (`getent passwd nonexistent` falls through to other modules).

## Files

| File                       | Purpose                                |
|----------------------------|----------------------------------------|
| `Makefile`                 | builds and installs the .so.2          |
| `libnss_trustforge.c`      | the module                             |
| `nsswitch.conf.example`    | reference nsswitch.conf snippet        |
| `test/mock-daemon.py`      | stub daemon for local testing          |
| `test/test-nss.sh`         | end-to-end `getent` test               |

## Related

- `tools/native/linux/pam_trustforge/` — PAM auth for the same actors
- `tools/native/linux/polkit_trustforge/` — polkit authority bridge
- `docs/specs/TF-0001-core-architecture.md` — the actor / instance model
- `docs/bridges/` — credential and identity bridges
