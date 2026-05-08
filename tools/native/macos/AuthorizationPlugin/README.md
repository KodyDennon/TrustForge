# TrustForge.bundle - macOS Authorization plugin

A macOS Authorization Services plugin (a CFBundle loaded by SecurityAgent)
that consults the local TrustForge daemon before granting one of the named
authorization rights (sudo via GUI, `task_for_pid`, System Settings panes,
etc.).

**Status:** Draft - Phase 0. Experimental, not production-ready. The
the reference TrustForge daemon exists, but this bundle remains
useful primarily for integration testing against a mock daemon listening on
`/var/run/trustforge/decide.sock`.

## What it does

Each time a process calls `AuthorizationCopyRights` (or any API layered on
it) for a right whose authorizationdb rule names
`com.trustforge.AuthPlugin:gate`, SecurityAgent loads this bundle and invokes
its `gate` mechanism. The mechanism:

1. Reads the requesting username (`kAuthorizationEnvironmentUsername`) from
   the auth context, falling back to the hint dictionary, then to the real
   uid of the calling SecurityAgent worker.
2. Reads the right name from the `right` hint, falling back to the
   `AuthorizationMechanismId` we were created under.
3. Connects to `/var/run/trustforge/decide.sock` (`AF_UNIX`) and POSTs:

   ```json
   {
     "actor": null,
     "host_token": null,
     "host_token_kind": "macos-authorization",
     "action": "<right name, e.g. system.privilege.taskport>",
     "target": "<service hint, defaults to macos-authorization>",
     "username": "<resolved user>"
   }
   ```

4. Calls `SetResult(kAuthorizationResultAllow)` only if the JSON response
   contains `"decision": "allow"`. **Anything else - timeout, missing
   socket, non-2xx HTTP, parse error, deny - sets
   `kAuthorizationResultDeny`.**

`MechanismDeactivate`, `MechanismDestroy`, and `PluginDestroy` perform only
the minimal cleanup required by the contract (free per-mechanism state and
acknowledge deactivation).

## Build

```sh
make
```

This invokes `clang -bundle -framework Security -framework Foundation`,
producing `TrustForge.bundle/Contents/MacOS/TrustForge`. The Makefile also
drops `Info.plist` into `TrustForge.bundle/Contents/`.

### SDK requirement

The "full" build expects the `AuthorizationPlugin.h` header that ships inside
`Security.framework` on every recent macOS SDK:

```sh
ls "$(xcrun --show-sdk-path)/System/Library/Frameworks/Security.framework/Headers/AuthorizationPlugin.h"
```

If that path does not exist (very old SDKs / minimal Command Line Tools),
the Makefile fails with a clear error. To build a no-op stub that still
loads (useful to verify your authorizationdb wiring):

```sh
make stub
```

The stub is compiled against only `<Security/Authorization.h>` (which has
shipped since macOS 10.0) and intentionally fails closed. Once you have an
SDK with the plugin header, `make clean && make`.

The Makefile also detects whether the SDK exposes `AuthorizationPlugin` as a
*standalone* framework (it does on a small subset of SDKs); if so it adds
`-framework AuthorizationPlugin` to the link line. In every other case the
symbols come from `Security.framework`, so the build still succeeds.

## Install

```sh
sudo make install
```

This copies `TrustForge.bundle/` to `/Library/Security/SecurityAgentPlugins/`
- the canonical location SecurityAgent searches at startup.

### Code signing (required on modern macOS)

SecurityAgent will refuse to load an unsigned bundle on macOS 11+. For local
development, ad-hoc sign:

```sh
sudo make codesign                   # ad-hoc (identity "-")
sudo make codesign CODESIGN_IDENT="Developer ID Application: Your Co."
sudo make verify
```

For production builds, sign with a Developer ID identity and notarize the
bundle (`xcrun notarytool submit ...`).

### Register the plugin against a right

See `TrustForge.bundle.example.authorizationdb` for full examples. The
minimum to gate `task_for_pid` is:

```sh
sudo security authorizationdb write system.privilege.taskport \
    allow,com.trustforge.AuthPlugin:gate
```

To revert, take a backup of the rule first:

```sh
sudo security authorizationdb read system.privilege.taskport \
    > taskport.before.plist
# ... change ...
sudo security authorizationdb write system.privilege.taskport \
    < taskport.before.plist
```

## Security caveats

- **Fail-closed.** A missing socket, hung daemon, malformed reply, or any
  HTTP non-2xx returns `kAuthorizationResultDeny`. This will block real user
  workflows (sudo, debugger attach, System Settings) if the daemon is down.
  Roll out behind a launchd-supervised daemon.
- **No password handling.** The plugin never reads passwords or
  `kAuthorizationEnvironmentPassword`. Authentication mechanisms (the
  built-in `builtin:authenticate` and friends) must run before us in the
  rule's mechanism list if you want a password prompt; we only **authorize**
  on top of an existing authenticated identity.
- **No custom crypto.** Per project rule: signing/verifying lives in the
  daemon, not here. We forward the request opaquely.
- **System-wide socket.** `/var/run/trustforge/decide.sock` is created by
  the launchd plist (`com.trustforge.daemon.plist`) under `_trustforge`.
  Any user who can connect to it can ask for decisions about themselves;
  the daemon must enforce per-actor policy.
- **Logs are sensitive.** The plugin emits `LOG_INFO`/`LOG_NOTICE` lines
  containing usernames and right names via `syslog(3)`. They appear in the
  unified log under `process: SecurityAgent` /
  `subsystem: TrustForgeAuthPlugin`.
- **Bundle code-signing is enforced.** An unsigned or wrongly-signed
  bundle silently fails to load; symptoms are "right denied" with no plugin
  log entries.

## Troubleshooting

Live-tail the unified log filtered to SecurityAgent and our subsystem:

```sh
log stream --predicate 'subsystem == "TrustForgeAuthPlugin" OR process == "SecurityAgent"'
```

Or, in `Console.app`:

1. Open Console.app.
2. In the search bar, enter `subsystem:TrustForgeAuthPlugin`.
3. Reproduce the auth prompt (e.g. `sudo -k && sudo true`, or click an
   admin lock in System Settings).

| Symptom | Likely cause |
|---|---|
| Right always denied, no plugin log lines | Bundle unsigned or wrong CFBundleIdentifier; check `codesign -dv TrustForge.bundle`. |
| `connect(/var/run/trustforge/decide.sock): No such file or directory` | tf-daemon not running; check `sudo launchctl print system/com.trustforge.daemon`. |
| `connect timeout` / `recv timeout` | Daemon hung. Plugin fails closed after 2s. |
| `malformed HTTP response` | Daemon spoke something other than HTTP/1.1. |
| `response missing 'decision' field` | Daemon returned 200 OK but no `"decision"` key. |
| `decide HTTP status 4xx/5xx` | Daemon rejected the request - check daemon log. |
| `MechanismCreate id=…` log line, then no `Invoke` | The mechanism is registered but the right's rule short-circuited before reaching us; inspect `security authorizationdb read <right>`. |

## Files

| File | Purpose |
|---|---|
| `Makefile` | clang -bundle, install, codesign, verify, clean |
| `TrustForgePlugin.m` | Full plugin against `<Security/AuthorizationPlugin.h>` |
| `TrustForgePlugin_stub.m` | Stub fallback when `AuthorizationPlugin.h` is unavailable |
| `Info.plist` | Bundle metadata (`CFBundleIdentifier=com.trustforge.AuthPlugin`) |
| `TrustForge.bundle.example.authorizationdb` | Sample `security authorizationdb write` commands |

## References

- `man 8 authorization`, `man 1 security`
- Apple's deprecated but still-current SecurityAgent plugin docs:
  Technote 2228, Technical Q&A 1277.
- `docs/specs/TF-0001-core-architecture.md` for the actor/right/decision
  vocabulary.
- `../com.trustforge.daemon.plist` for the launchd job that owns the
  decision socket.
