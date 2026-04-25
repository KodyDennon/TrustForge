# sudo_trustforge

A sudo **policy plugin** that delegates every `sudo <command>` decision to
the local TrustForge daemon. The plugin is a pure transport shim: it
extracts the wrapped command and argv, calls
`POST /v1/decide` over the daemon's UNIX socket
(`~/.trustforge/decide.sock`), and allows the command iff the daemon
returns `decision: "allow"`. Anything else -- denial, malformed JSON,
unreachable daemon -- is treated as deny. **Fail-closed.**

> Status: **Draft / experimental.** Per `SECURITY.md`, no TrustForge
> component is production-ready until reviewed.

## Wire contract

```http
POST /v1/decide HTTP/1.0
Content-Type: application/json
Content-Length: ...

{
  "actor": null,
  "host_token": "<value of $SUDO_USER>",
  "host_token_kind": "session-cookie",
  "action": "shell.exec",
  "target": "<argv[0]>",
  "context": { "argv": "<space-joined argv>" }
}
```

The plugin is intentionally minimal -- it does **no** crypto, runs no
policy logic locally, and ships no embedded JSON parser. The daemon is
the single decision point. See `TF-0001-core-architecture.md` and
`DECISIONS.md` for why.

## Build

```sh
make
```

### Header dependency

`sudo_plugin.h` is required. It is provided by:

| Distribution    | Package        |
|-----------------|----------------|
| Debian/Ubuntu   | `libsudo-dev`  |
| Fedora/RHEL     | `sudo-devel`   |
| Alpine          | `sudo-dev`     |
| Arch            | `sudo` (header ships with the main package) |

If the build host does not have it, install the relevant package or
vendor the header from the upstream sudo source tarball and pass
`make INCLUDES=-I./vendor/sudo`.

## Install

```sh
sudo make install
```

This places `sudo_trustforge.so` in the distribution's sudo plugin
directory (one of `/usr/libexec/sudo`, `/usr/lib/sudo`,
`/usr/lib64/sudo`). The Makefile installs the file root-owned, mode
0644, which is what sudo requires -- sudo refuses to load plugins that
are group- or world-writable, or owned by a non-root user.

Then register it. Copy `sudo.conf.example` to `/etc/sudo.conf` (or merge
its `Plugin` lines into your existing `/etc/sudo.conf`):

```
Plugin sudoers_policy sudo_trustforge.so
Plugin sudoers_io     sudoers.so
```

Keep a root shell open while you edit `/etc/sudo.conf`. A typo here
removes your ability to escalate.

## Caveats

- **Plugin file must be root-owned.** sudo enforces this; non-root
  ownership or group/world write permissions will cause sudo to refuse
  to load the plugin and fall back to its compiled-in default (which is
  almost certainly `sudoers`, not this plugin).
- **`sudo` strips most of the environment by default.** The plugin
  reads `HOME` to locate the daemon socket and `SUDO_USER` to populate
  the `host_token` field. Modern sudo preserves `SUDO_USER`; `HOME`
  must be in `env_keep` (or the operator must set
  `TRUSTFORGE_SOCKET=/path/to/decide.sock` somewhere the plugin can
  see). The plugin reads the override env var first.
- **The daemon runs in the user's session, not as root.** TrustForge
  decisions are made by the user-context daemon. If the daemon is not
  running, every sudo call is denied. This is by design.
- **No I/O logging is performed by this plugin.** Pair it with
  `sudoers_io` (or another I/O plugin) if you want sudo's standard
  audit trail; the TrustForge daemon emits its own append-only proof
  log via TF-0006 / TF-0008.
- **`policy_check` returns 1 (allow) / 0 (deny).** The signature mirrors
  sudo's documented semantics; see `man sudo_plugin`.
- **Performance.** Each sudo call adds one round trip over a UNIX
  socket plus the daemon's own decision time. This is acceptable for
  interactive sudo; pipelines that sudo thousands of times will feel
  it.

## Test

A mock daemon is provided for integration testing:

```sh
# Terminal A: run the mock
python3 test/mock-daemon.py /tmp/tf-mock.sock allow

# Terminal B: run the test driver
TRUSTFORGE_SOCKET=/tmp/tf-mock.sock ./test/test-sudo.sh
```

The test exercises the plugin's request-format and decision-handling
paths against the mock; it does not require a real sudo install (the
test harness invokes the plugin's exported symbol via a tiny C
loader).

## Files

| File                       | Purpose                                       |
|----------------------------|-----------------------------------------------|
| `Makefile`                 | Build/install/test rules                      |
| `sudo_trustforge.c`        | Plugin source                                 |
| `sudo.conf.example`        | Drop-in for `/etc/sudo.conf`                  |
| `test/mock-daemon.py`      | Trivial UNIX-socket HTTP daemon for testing   |
| `test/test-sudo.sh`        | Integration test driver                       |
