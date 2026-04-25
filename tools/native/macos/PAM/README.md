# pam_trustforge (macOS / OpenPAM)

A macOS PAM module that consults the local TrustForge daemon for an
authorization decision before allowing authentication, account access, or
session opening. macOS port of `tools/native/linux/pam_trustforge`, built
against Apple's OpenPAM (the BSD-derived PAM that ships with every macOS
install).

**Status:** Draft - Phase 0. Experimental, not production-ready. The
reference TrustForge daemon is not yet shipped; until it is, this module is
useful primarily for integration testing against a mock daemon listening on
`/var/run/trustforge/decide.sock`.

## What it does

For the `auth`, `account`, and `session` (open) PAM phases, the module:

1. Resolves the target user via `pam_get_user` (canonicalised through
   `getpwnam_r(3)` if available — OpenPAM has no `pam_modutil_*` helpers).
2. Connects to `/var/run/trustforge/decide.sock` (the launchd-managed
   socket from `../com.trustforge.daemon.plist`).
3. POSTs `/v1/decide` with a small JSON body:

   ```json
   {
     "actor": null,
     "host_token": "<PAM_AUTHTOK if available>",
     "host_token_kind": "session-cookie",
     "action": "login" | "account.access" | "session.open",
     "target": "<PAM service name, e.g. sudo, sshd, login>",
     "username": "<canonical login name>"
   }
   ```

4. Returns `PAM_SUCCESS` only if the JSON response contains
   `"decision": "allow"`. **Anything else - timeout, missing socket,
   non-2xx status, parse error, deny - fails closed with `PAM_AUTH_ERR`.**

`pam_sm_close_session`, `pam_sm_setcred`, and `pam_sm_chauthtok` are
implemented as `PAM_IGNORE` so the module composes cleanly with the rest
of the stack (`pam_opendirectory`, `pam_smartcard`, etc.).

## Differences from the Linux build

| Concern | Linux | macOS |
|---|---|---|
| PAM flavour | Linux-PAM | OpenPAM |
| User lookup | `pam_modutil_getpwnam` | `getpwnam_r(3)` directly |
| Logging | `pam_vsyslog` | `vsyslog` (OpenPAM's `openpam_log` is a `__func__` macro) |
| Socket path | `~/.trustforge/decide.sock` (per-user) | `/var/run/trustforge/decide.sock` (system, owned by `_trustforge`) |
| Module path | `/lib/security/` | `/usr/local/lib/pam/` (SIP — see below) |

## Build

```sh
make
```

This calls `clang -bundle -lpam` against the OpenPAM headers in the macOS
SDK (`/usr/include/security/pam_modules.h`, `pam_appl.h`, `openpam.h` —
all unconditionally present). The output `pam_trustforge.so` is a Mach-O
bundle with both `arm64` and `x86_64` slices.

```sh
make verify        # confirms the .so exports pam_sm_authenticate et al.
```

## Install

```sh
sudo make install
```

Default install path is `/usr/local/lib/pam/pam_trustforge.so`. Override
with `PAMDIR` if you have disabled SIP and want the canonical location:

```sh
sudo make install PAMDIR=/usr/lib/pam
```

### macOS SIP caveat

System Integrity Protection (SIP) protects `/usr/lib/pam`, the directory
where macOS's own PAM modules live. **You cannot copy a custom module
there on a stock system.** Two options:

1. **Recommended:** install under `/usr/local/lib/pam/` and reference the
   module by absolute path in `/etc/pam.d/<service>`:

   ```
   auth required /usr/local/lib/pam/pam_trustforge.so
   ```

   This works because OpenPAM resolves a name with a leading `/` as a
   filesystem path rather than a relative-to-`PAM_MODULES_DIR` lookup.

2. **Discouraged:** disable SIP for filesystem protections so you can write
   to `/usr/lib/pam`:

   ```sh
   # Boot into Recovery (hold Power on Apple Silicon, Cmd+R on Intel)
   csrutil enable --without fs            # leaves all other SIP guards on
   # Reboot, then:
   sudo make install PAMDIR=/usr/lib/pam
   # When done re-enable:
   csrutil enable
   ```

   Lowering SIP is a security-policy decision; do not do this on a
   production host. The TrustForge project recommends option 1.

## Wire it into a service

See `pam.d/trustforge` for a self-contained service. The most common
real-world target is `sudo`. Apple's recommended pattern is to edit
`/etc/pam.d/sudo_local` (which `/etc/pam.d/sudo` includes and which
survives macOS updates) rather than `/etc/pam.d/sudo` directly:

```sh
# /etc/pam.d/sudo_local — append before the existing required modules
auth required /usr/local/lib/pam/pam_trustforge.so
```

Other services worth gating: `login`, `sshd`, `screensaver`, `passwd`,
`su`. Inspect their stacks under `/etc/pam.d/` and add the line in the
**`auth`** block, *after* the module that proves identity
(`pam_opendirectory.so` on macOS).

## Testing

There is no included mock daemon yet on the macOS side; until one lands,
copy `tools/native/linux/pam_trustforge/test/mock-daemon.py` and run it
pointing at `/var/run/trustforge/decide.sock` (you'll need root or a
writable parent dir). Then drive the stack with `pamtester` (Homebrew):

```sh
brew install pamtester
sudo pamtester sudo $USER authenticate
```

Watch the output via:

```sh
log stream --predicate 'eventMessage contains "trustforge"'
```

## Security caveats

- **Fail-closed by design.** A missing socket or hung daemon will block
  logins, sudo, screen-unlock — anything in the stack. For a production
  rollout, deploy the daemon under launchd with `KeepAlive=true` (already
  in `com.trustforge.daemon.plist`) and consider `auth sufficient` instead
  of `auth required` during initial cutover.
- **No password handling.** This module never reads passwords. It runs
  *after* whichever `pam_opendirectory.so` / `pam_smartcard.so` proves the
  identity; it only authorizes the already-authenticated principal.
- **System-scope socket.** `/var/run/trustforge/decide.sock` is owned by
  the `_trustforge` service user. The socket mode is `0660` per the
  launchd plist; you must be in the `_trustforge` group, or the daemon
  must explicitly accept the calling uid, for the connect to succeed.
- **Logs are sensitive.** Module log output goes to `LOG_AUTHPRIV` and
  ends up in the unified log:

  ```sh
  log show --last 5m --predicate 'category == "AUTH"'
  ```

  It contains usernames, action names, and PAM service names. Treat the
  auth log as PII.
- **No custom crypto.** Per project rule: signing/verifying lives in the
  daemon, not here.
- **OpenPAM differences.** OpenPAM's `pam_modutil_*` family does not exist
  on macOS; this module uses `getpwnam_r(3)` directly. If you port other
  Linux PAM modules to macOS, expect to do the same.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `connect(/var/run/trustforge/decide.sock): No such file or directory` | tf-daemon not running; check `sudo launchctl print system/com.trustforge.daemon`. |
| `connect timeout` / `recv timeout` | Daemon hung. Module fails closed after 2s. |
| `connect: Permission denied` | Calling user not in the `_trustforge` group. |
| `malformed HTTP response` | Daemon spoke something other than HTTP/1.1. |
| `response missing 'decision' field` | Daemon returned 200 OK but no `"decision"` key. |
| `decide HTTP status 4xx/5xx` | Daemon rejected the request. |
| Module never invoked | Path in `/etc/pam.d/<service>` wrong. macOS pam.d requires absolute paths for non-`/usr/lib/pam` modules. |
| `pam_get_user failed` | Service didn't supply a user (rare; usually a service config bug). |

## Files

| File | Purpose |
|---|---|
| `Makefile` | clang -bundle build, install (`/usr/local/lib/pam/`), verify, clean |
| `pam_trustforge.c` | The OpenPAM-flavoured module source |
| `pam.d/trustforge` | Sample `/etc/pam.d/` snippet (standalone service) |

## References

- `man 3 openpam`, `man 5 pam.conf`
- Apple's `/etc/pam.d/sudo_local` convention (Sonoma and newer).
- `tools/native/linux/pam_trustforge/` for the Linux equivalent and the
  shared design notes.
- `docs/specs/TF-0001-core-architecture.md` for the actor/decision
  vocabulary the daemon enforces.
- `../com.trustforge.daemon.plist` for the launchd job that owns the
  decision socket.
