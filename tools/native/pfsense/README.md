# TrustForge pfSense package

This directory is the upstream source for the
`pfSense-pkg-trustforge` FreeBSD port / pfSense package. It bundles
the `tf-daemon` binary, an rc.d service script, a Bootstrap-styled web
UI under *Services → TrustForge*, and the XML descriptor pfSense uses
to wire it all together.

## Status

**Phase 0 / pre-release.** The Makefile pulls a release tarball from

```
https://github.com/trustforge/trustforge/releases/download/v0.1.0/tf-daemon-amd64-pfsense.tar.gz
```

This tarball **does not exist yet** — it will be produced by upstream
CI when `v0.1.0` is tagged. Until then, building this port will fail
at the `fetch` stage. The package layout, plist, and XML descriptor
are nonetheless reviewable as-is.

## Caveats

- **pfSense Plus only.** The XML descriptor declares
  `pfSense Plus 23.05 or later` as a requirement. The community
  edition (pfSense CE / 2.x) lacks the `service` integration points
  this package leans on. CE support is tracked separately and is not
  promised for v0.1.0.
- **amd64 only.** pfSense Plus appliances are amd64. ARM Netgate
  appliances are out of scope until upstream CI publishes an
  `aarch64-unknown-freebsd` artifact.
- **No HA sync yet.** `<custom_php_resync_config_command>` is wired
  into the XML for symmetry, but `trustforge_resync()` is currently a
  stub. CARP HA pairs will copy the YAML config but not yet the
  generated proof-event store.

## Install (once upstream publishes the .pkg)

```sh
# On the pfSense Plus shell:
pkg-static add https://example.com/pfSense-pkg-trustforge-0.1.0.pkg

# Or via the System > Package Manager UI once the package is in the
# pfSense Plus catalogue.
```

After install:

1. Navigate to *Services → TrustForge*.
2. Save your YAML config under the **Configuration** tab.
3. Toggle the service on under *Status → Services*.
4. Watch decisions tick in under the **Status** tab.

## Files installed

See `pkg-plist` for the authoritative list. Summary:

| Path                                          | Purpose                          |
| --------------------------------------------- | -------------------------------- |
| `/usr/local/bin/tf-daemon`                    | The Rust daemon (static)         |
| `/usr/local/etc/rc.d/trustforge.sh`           | rc.subr service script           |
| `/usr/local/etc/trustforge/config.yaml.sample`| Editable config template         |
| `/usr/local/pkg/trustforge.xml`               | pfSense package descriptor       |
| `/usr/local/www/trustforge.php`               | Web UI page                      |
| `/var/run/trustforge/`                        | Runtime dir (sockets, pidfile)   |
| `/var/log/trustforge/`                        | Log dir                          |

## Troubleshooting

```sh
# rc.subr status (used by Status > Services).
service trustforge status

# Live tail.
tail -F /var/log/trustforge/trustforge.log

# Reload after manual config edit.
service trustforge reload

# Confirm the package is registered.
pkg info pfSense-pkg-trustforge
```

If the web UI shows "Stopped" but the process is running, check that
the pidfile under `/var/run/trustforge/trustforge.pid` matches the
live pid — pfSense reboots wipe `/var/run`, so the
`trustforge_prestart` hook re-creates the directory on each start.

## Hard rules carried over from the spec

- No custom cryptography in this package; `tf-daemon` composes reviewed
  primitives.
- Nothing is production-ready. Treat published binaries as experimental
  drafts until upstream review clears.
