# TrustForge OpenWRT package

This directory is the upstream source for the `trustforge` and
`luci-app-trustforge` OpenWRT packages. The expected feed path is:

```
feeds/packages/utils/trustforge/Makefile
feeds/luci/applications/luci-app-trustforge/...
```

## Status

**Phase 0 / pre-release.** The Makefile pulls release tarballs from

```
https://github.com/trustforge/trustforge/releases/download/v0.1.0/tf-daemon-<arch>.tar.gz
```

These tarballs **do not exist yet**. They are produced by upstream CI
when `v0.1.0` is tagged. Until then, the package is intended for
review and packaging-system testing only — `make package/trustforge/compile`
will fail at the download step.

## Targets supported

| OpenWRT `ARCH` | Rust target triple                  |
| -------------- | ----------------------------------- |
| `mipsel`       | `mipsel-unknown-linux-musl`         |
| `mips`         | `mips-unknown-linux-musl`           |
| `aarch64`      | `aarch64-unknown-linux-musl`        |
| `arm`          | `armv7-unknown-linux-musleabihf`    |
| `x86_64`       | `x86_64-unknown-linux-musl`         |

Other targets are unsupported until upstream CI publishes binaries.

## Install

Once published to a feed:

```sh
opkg update
opkg install trustforge
opkg install luci-app-trustforge   # optional web UI
```

The package creates the `trustforge` system user (uid 915), installs
`tf-daemon` to `/usr/bin`, and seeds `/etc/config/trustforge` plus
`/etc/trustforge/config.yaml` on first boot via the `99-trustforge`
uci-defaults script.

## Configure

All persistent configuration lives in UCI:

```sh
uci show trustforge
uci set trustforge.main.profile='tf-home-compatible'
uci set trustforge.main.listen='127.0.0.1:8642'
uci add_list trustforge.@bridge[0].issuer_match='https://login.microsoftonline.com'
uci commit trustforge
/etc/init.d/trustforge reload
```

Build-time feature gates (set in `make menuconfig` under
*Utilities → trustforge → Configuration*):

- `--enable-tls` — enable the TLS / X.509 compatibility bridge.
- `--enable-relay` — let this device forward packets for other actors.
- `--enable-dashboard` — embed the lightweight tf-dashboard. Prefer
  `luci-app-trustforge` instead on devices that already run LuCI.

## LuCI app

`luci-app-trustforge` adds a *Services → TrustForge* page showing:

- daemon liveness and pid,
- a 5-minute decision histogram (allow / deny / ask),
- a tail of recent proof events.

The view polls the controller every 5 s; the controller speaks
line-delimited JSON to `/var/run/trustforge/decide.sock`.

## Troubleshooting

```sh
# Is the daemon up?
/etc/init.d/trustforge status
logread -e trustforge | tail -n 50

# Is procd respawning it on every boot?
pgrep -af tf-daemon

# Check the control socket.
ls -l /var/run/trustforge/decide.sock

# Reset to defaults (destructive).
/etc/init.d/trustforge stop
rm -rf /etc/trustforge /var/run/trustforge
opkg remove --force-removal-of-dependent-packages trustforge
opkg install trustforge
```

If the daemon refuses to start with `permission denied` on the socket
path, confirm `/var/run/trustforge` is owned by `trustforge:trustforge`.
The `99-trustforge` uci-defaults script sets this on first boot but a
manual `rm -rf` of `/var/run` clears it.

## Hard rules carried over from the spec

- No custom cryptography in this package; `tf-daemon` composes reviewed
  primitives (see `SECURITY.md` upstream).
- Nothing is production-ready yet. Treat the published binaries as
  experimental drafts until the upstream review gate clears.
