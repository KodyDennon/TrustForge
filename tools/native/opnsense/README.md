# TrustForge OPNsense plugin

This directory is the upstream source for the `os-trustforge` OPNsense
plugin. The on-disk layout matches the OPNsense plugin convention so
the tree can be lifted directly into
[`opnsense/plugins`](https://github.com/opnsense/plugins) under
`security/os-trustforge/`.

## Status

**Phase 0 / pre-release.** The packaging definition pulls a release
tarball from

```
https://github.com/trustforge/trustforge/releases/download/v0.1.0/tf-daemon-amd64-freebsd.tar.gz
```

This tarball **does not exist yet** — it will be produced by upstream
CI when `v0.1.0` is tagged. Until then, builds will fail at the
`fetch` step. The plugin source layout, REST controller, model XML,
and Volt template are nonetheless reviewable and lintable as-is.

## Layout

```
+POST_INSTALL                                   # post-install hook
pkg-plist                                       # file manifest
src/etc/inc/plugins.inc.d/trustforge.inc        # plugin backend
src/opnsense/mvc/app/controllers/OPNsense/Trustforge/
    IndexController.php                         # UI controller
    Api/SettingsController.php                  # REST controller
src/opnsense/mvc/app/models/OPNsense/Trustforge/
    Trustforge.php                              # model class
    Trustforge.xml                              # schema
src/opnsense/mvc/app/views/OPNsense/Trustforge/
    index.volt                                  # UI template
```

## Install (once upstream publishes the .pkg)

On the OPNsense shell:

```sh
pkg install os-trustforge
```

Or via the UI: *System → Firmware → Plugins → install os-trustforge*.

After install, the plugin appears under *Services → TrustForge*. The
`+POST_INSTALL` hook seeds `/usr/local/etc/trustforge/config.yaml`
from the sample, registers the rc.d service, and starts it.

## REST API

| Method | Endpoint                                       | Purpose                       |
| ------ | ---------------------------------------------- | ----------------------------- |
| GET    | `/api/trustforge/settings/get`                 | Fetch settings                |
| POST   | `/api/trustforge/settings/set`                 | Replace settings (validated)  |
| POST   | `/api/trustforge/settings/reconfigure`         | Render YAML + reload daemon   |
| GET    | `/api/trustforge/settings/status`              | Liveness + decision histogram |

All endpoints follow OPNsense's standard CSRF + auth conventions and
require the `page-services-trustforge` ACL.

## Caveats

- **amd64 / FreeBSD only.** OPNsense is x86_64-only at present.
- **No HA proof-store sync yet.** XMLRPC sync (`trustforge_xmlrpc_sync`)
  pushes the YAML config to a peer but does not yet replicate the
  proof-event store. Failover is therefore safe for new sessions but
  loses prior local proof state.
- **configd templates not bundled here.** The hooks shell out to
  `configctl trustforge {start,stop,restart,status,histogram,info}`;
  the matching `/usr/local/opnsense/service/conf/actions.d/`
  templates ship with the binary tarball, not this source tree.

## Hard rules carried over from the spec

- No custom cryptography in this plugin; `tf-daemon` composes reviewed
  primitives.
- Nothing is production-ready. Treat published binaries as experimental
  drafts until upstream review clears.
