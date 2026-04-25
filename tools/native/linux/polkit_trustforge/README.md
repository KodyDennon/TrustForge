# polkit_trustforge

A small helper binary plus a polkit-1 JS rule that delegate every gated
polkit authorization decision to the local TrustForge daemon.

```
+-----------+        spawn         +---------------------------+
|  polkitd  |  --(action.id, user)-> | polkit-trustforge-helper |
|  (mozjs)  |  <----- "yes" -------- |   POST /v1/decide        |
+-----------+                        +-------------|------------+
                                                   v
                                       ~/.trustforge/decide.sock
                                            (TrustForge daemon)
```

> Status: **Draft / experimental.** Per `SECURITY.md`, no TrustForge
> component is production-ready until reviewed.

## Why a helper, not a JS port?

polkit's rule engine is Mozilla's mozjs (SpiderMonkey). We could in
principle implement TrustForge inside JS, but:

* Embedding a full daemon-IPC client in mozjs is awkward and unsafe.
* Linking libpolkit into a TrustForge binary would couple the daemon
  to a specific polkit ABI version.
* `polkit.spawn()` is documented and stable; a one-line rule that
  shells out to a small native helper is the conservative path.

So we ship a tiny helper binary and a JS rule (`49-trustforge.rules`)
that calls it.

## Wire contract (helper -> daemon)

```http
POST /v1/decide HTTP/1.0
Content-Type: application/json
Content-Length: ...

{
  "actor": "<subject.user>",
  "host_token": "<subject.user>",
  "host_token_kind": "session-cookie",
  "action": "<TrustForge action name>",
  "target": "<polkit action.id>",
  "context": {}
}
```

The helper maps a few common polkit action namespaces to TrustForge
action names (see `tf_action_for_polkit` in
`polkit-trustforge-helper.c`); anything else falls through to
`polkit.<action.id>`. Refine the map as the TF action vocabulary
stabilises.

## Build

```sh
make
```

### Header / runtime dependencies

The helper itself does **not** link libpolkit; it is a plain UNIX-socket
client. Therefore polkit dev headers are **not** a build dependency.

You do need polkitd at runtime to load the JS rule:

| Distribution    | Package          |
|-----------------|------------------|
| Debian/Ubuntu   | `policykit-1`    |
| Fedora/RHEL     | `polkit`         |
| Alpine          | `polkit`         |
| Arch            | `polkit`         |

If you later extend the helper to call libpolkit-gobject-1 directly,
install the matching `-dev` / `-devel` package and add
`pkg-config --cflags --libs polkit-gobject-1` to the Makefile.

## Install

```sh
sudo make install
```

This installs:

* `/usr/libexec/polkit-trustforge-helper` (mode 0755, root:root)
* `/etc/polkit-1/rules.d/49-trustforge.rules` (mode 0644, root:root)

polkitd picks up rule changes automatically on most distros; if not,
`systemctl restart polkit`.

## Security notes

- **Helper must be root-owned and not writable by non-root users.**
  polkit spawns it as the polkitd UID (root); a writable helper is
  root-equivalent.
- **polkit.spawn() blocks the caller.** Every gated action will wait
  on the helper's round trip to the daemon. Keep the daemon's
  /v1/decide endpoint fast; consider a hard timeout in a future
  revision (the current helper does not impose one).
- **HOME inside polkitd is not the user's HOME.** The default socket
  path `~/.trustforge/decide.sock` resolves against polkitd's HOME,
  which is typically empty or `/var/lib/polkit-1`. To make the helper
  reach the user-context daemon you must either:
    1. Set `TRUSTFORGE_SOCKET` system-wide (e.g. via a polkitd
       systemd drop-in), or
    2. Run a TrustForge system-level socket bridge that forwards into
       the appropriate user session.
  This README documents the constraint; the daemon-side bridge is
  out of scope.
- **The helper fails closed: any error -> "no" on stdout.** The JS
  rule, however, returns `NOT_HANDLED` on spawn failure so that other
  polkit rules can still run. If you want strict fail-closed at the
  polkit layer, change the `catch` branch in the rule to
  `return polkit.Result.NO;`.
- **No cryptography in the helper.** All decisions, signing, and
  proof-emission happen in the daemon. See `TF-0001`.

## Test

```sh
./test/mock-helper-test.sh
```

This runs the helper directly against a Python UNIX-socket mock daemon
and asserts allow/deny/unreachable behaviour. It does not require
polkitd or a real polkit install.

## Files

| File                                              | Purpose                                       |
|---------------------------------------------------|-----------------------------------------------|
| `Makefile`                                        | Build/install/test rules                      |
| `polkit-trustforge-helper.c`                      | Helper source                                 |
| `etc-polkit-1-rules.d/49-trustforge.rules`        | Drop-in for `/etc/polkit-1/rules.d/`          |
| `test/mock-helper-test.sh`                        | Integration test driver                       |
