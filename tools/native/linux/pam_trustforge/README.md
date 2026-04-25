# pam_trustforge

A Linux PAM module that consults the local TrustForge daemon for an authorization
decision before allowing authentication, account access, or session opening.

**Status:** Draft — Phase 0. Experimental, not production-ready. The reference
TrustForge daemon is not yet shipped; until it is, this module is useful primarily
for integration testing against the included mock daemon.

## What it does

For the `auth`, `account`, and `session` (open) PAM phases, the module:

1. Resolves the target user's home directory.
2. Connects to `~/.trustforge/decide.sock` (a `AF_UNIX` socket).
3. Sends `POST /v1/decide` with a small JSON body:

   ```json
   {
     "actor": null,
     "host_token": "<PAM_AUTHTOK if available>",
     "host_token_kind": "session-cookie",
     "action": "login" | "account.access" | "session.open",
     "target": "<PAM service name, e.g. sshd>"
   }
   ```

4. Returns `PAM_SUCCESS` only if the JSON response contains
   `"decision": "allow"`. **Anything else — timeout, missing socket, non-2xx
   status, parse error, deny — fails closed with `PAM_AUTH_ERR`.**

`pam_sm_close_session`, `pam_sm_setcred`, and `pam_sm_chauthtok` are implemented
as `PAM_IGNORE` so the module composes cleanly with the rest of the stack.

## Build

```sh
make
```

### Header dependency

You need PAM development headers installed:

| Distro       | Command                          |
|--------------|----------------------------------|
| Debian/Ubuntu| `sudo apt install libpam0g-dev`  |
| Fedora/RHEL  | `sudo dnf install pam-devel`     |
| Alpine       | `sudo apk add linux-pam-dev`     |
| Arch         | `sudo pacman -S pam`             |

If `<security/pam_modules.h>` is missing, `make` will fail with a clear compile
error — install the package above and retry.

## Install

```sh
sudo make install
```

The default install path is `/lib/security/`, with fallbacks to
`/lib/x86_64-linux-gnu/security/` and `/usr/lib/security/`. Override with
`PAMDIR` if your distro differs:

```sh
sudo make install PAMDIR=/usr/lib64/security
```

## Wire it into a service

See `pam-trustforge.example.conf`. For example, to gate `sshd`:

```
# /etc/pam.d/sshd
auth    required   pam_trustforge.so
account required   pam_trustforge.so
session optional   pam_trustforge.so
```

`session optional` is recommended on first deployment so a daemon outage cannot
lock you out of an already-authenticated host. Once you trust the policy and
the daemon, promote it to `session required`.

## Testing

A mock daemon is included so you can exercise the module without the real
TrustForge daemon:

```sh
# Terminal 1 — start mock daemon answering "allow"
python3 test/mock-daemon.py --decision allow

# Terminal 2 — run the test driver (requires pamtester and a built .so)
sudo apt install pamtester
sudo make install
./test/test-pam.sh
```

`test-pam.sh` will start the mock daemon in `allow` and `deny` modes in turn
and use `pamtester` to verify the module returns success and failure
respectively.

## Troubleshooting

All log output goes through `pam_syslog` and ends up in the PAM/auth log
(`/var/log/auth.log` on Debian-family, `journalctl _COMM=sshd` on systemd
distros).

| Symptom | Likely cause |
|---|---|
| `connect(...): No such file or directory` | Daemon not running, or wrong user's home dir. Check `~/.trustforge/decide.sock`. |
| `connect timeout` / `recv timeout` | Daemon hung. Module fails closed after 2s. |
| `malformed HTTP response` | Daemon spoke something other than HTTP/1.1 — check daemon version. |
| `response missing 'decision' field` | Daemon returned 200 but no JSON `decision`. |
| `decide HTTP status 4xx/5xx` | Daemon rejected the request. |
| Always denies | Likely host token / actor binding issue. Set log level to debug on the daemon. |

To temporarily disable while keeping the module installed, comment out the
corresponding lines in `/etc/pam.d/<service>`. **Do not remove `pam_unix.so`
from the stack** — pam_trustforge does not authenticate passwords; it only
authorizes.

## Security caveats

- **Fail-closed by design.** A missing socket or hung daemon will block
  logins. For high-availability hosts, deploy the daemon under a supervisor
  (systemd, runit) and consider `auth sufficient` rather than `required`
  during rollout. (`sufficient` is *not* recommended long-term — it lets
  attackers bypass the policy if they can DoS the daemon.)
- **Per-user socket path.** The module connects to the *target* user's
  home directory. A user cannot make decisions for another user's logins
  unless the daemon is running for that user. For system-wide enforcement,
  point the daemon at a shared socket and patch `TF_SOCK_RELATIVE_PATH` /
  resolution logic; this is intentional Phase 0 simplicity.
- **No replay protection in this bridge.** The host_token is forwarded
  opaquely to the daemon. Replay protection, nonce checks, and Trust-level
  enforcement live in the daemon, not here. See
  `docs/specs/TF-0001-core-architecture.md` and
  `docs/bridges/` for the boundary.
- **No custom crypto.** Per project rule: this module performs no crypto
  itself. All signing/verifying happens in the daemon.
- **Logs may contain principal names.** `pam_syslog` output includes the
  user, action, and service. Treat the auth log as sensitive.

## Files

| File | Purpose |
|---|---|
| `Makefile` | Build / install / clean / uninstall |
| `pam_trustforge.c` | The PAM module source |
| `pam-trustforge.example.conf` | Sample `/etc/pam.d/sshd` snippet |
| `test/mock-daemon.py` | Stand-alone mock decide endpoint over `AF_UNIX` |
| `test/test-pam.sh` | End-to-end test using `pamtester` |
