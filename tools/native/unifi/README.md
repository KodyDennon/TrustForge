# TrustForge UniFi (Ubiquiti) integration

This directory bundles three pieces that together gate UniFi-managed
networks on TrustForge verdicts:

1. **`controller-plugin/`** — a Node.js plugin loaded by the UniFi
   Network Application. Listens for client-connect, port-block,
   firewall-rule, and voucher events on the controller's event bus
   and consults `tf-daemon /v1/decide` before letting them stand.
2. **`cmd/tf-unifi-sync/`** — a Go reconciler binary that polls the
   controller's REST API, asks the daemon for a verdict on every
   client/device it sees, and emits `.tf/clients/<mac>.yaml` and
   `.tf/devices/<mac>.yaml` actor manifests.
3. **`examples/`** — a sample `site-policy.yaml` for the daemon and a
   `voucher-hotspot.json` showing how a captive portal can call
   `/v1/decide` before issuing a guest voucher.

## Status

**Phase 0 / pre-release.** Not production-ready. The reference
`tf-daemon` exists as a working reference; both the plugin and the reconciler
are useful primarily for conformance testing against a mock daemon.

## Compatibility

| Controller                                             | Plugin path                                              |
| ------------------------------------------------------ | -------------------------------------------------------- |
| UniFi Network Application 8.0+ on a self-hosted Linux  | `~/.unifi/plugins/trustforge/`                           |
| UniFi OS 4.0+ (UDM Pro / UDM SE / Cloud Key G2 Plus)   | Sidecar required — see "Webhook fallback" below          |
| UniFi Network Application 7.x and earlier              | Unsupported. The event-bus shape changed in 8.x.         |

> **Heads-up.** Ubiquiti has never published a stable, public plugin
> SDK. The "plugins" directory used by self-hosted Network
> Application installs is community-discovered, undocumented, and can
> break between point releases. UniFi OS appliances reject unsigned
> plugins outright. For those, use the **webhook fallback**: run the
> Go reconciler (`tf-unifi-sync`) plus a small webhook script that
> calls the controller's REST API with admin credentials.

## Layout

```
controller-plugin/
  package.json            Node.js metadata
  manifest.json           plugin metadata for the controller loader
  src/index.js            event handler + decide bridge
  test/index.test.js      pure-function unit tests (node --test)

cmd/tf-unifi-sync/
  go.mod
  main.go                 entry point + flags + main loop
  sync.go                 reconcile() and YAML manifest renderers
  sync_test.go            full-path tests with mock controller + daemon

examples/
  site-policy.yaml        sample daemon policy
  voucher-hotspot.json    captive-portal voucher hook
```

## Install — controller plugin (self-hosted Network Application 8.x)

```sh
# 1. Drop the plugin into the controller's plugin directory.
sudo mkdir -p /usr/lib/unifi/plugins/trustforge
sudo cp -r controller-plugin/* /usr/lib/unifi/plugins/trustforge/

# 2. Restart the controller so it loads the plugin.
sudo systemctl restart unifi

# 3. Confirm it loaded.
sudo journalctl -u unifi --since "5 min ago" | grep -i trustforge
```

The plugin reads its config from the controller UI's plugin pane (or
from `~/.unifi/plugins/trustforge/config.json` for headless setups);
see the `config_schema` block in `controller-plugin/manifest.json`
for the supported keys.

## Install — webhook fallback (UniFi OS appliances)

UniFi OS does not load third-party plugins. Run the Go reconciler on
any Linux box that can reach the controller and `tf-daemon`:

```sh
# 1. Build.
cd cmd/tf-unifi-sync
go build -o tf-unifi-sync .

# 2. Run as a long-lived service.
sudo install -m 0755 tf-unifi-sync /usr/local/bin/tf-unifi-sync
sudo tee /etc/systemd/system/tf-unifi-sync.service >/dev/null <<'EOF'
[Unit]
Description=TrustForge UniFi reconciler
After=network-online.target

[Service]
Environment=UNIFI_URL=https://unifi.lan
Environment=UNIFI_USERNAME=trustforge-readonly
Environment=UNIFI_PASSWORD=replace-me
Environment=TF_DAEMON_URL=http://127.0.0.1:8787
ExecStart=/usr/local/bin/tf-unifi-sync \
    --site default \
    --interval 30s \
    --out-dir /var/lib/trustforge/unifi
Restart=on-failure
User=trustforge

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now tf-unifi-sync
```

The reconciler does **not** push enforcement back into the
controller — it produces actor manifests. To act on `decision: deny`
you still need either (a) the controller plugin (self-hosted only),
or (b) a separate "UniFi API browser" script that calls the REST API
with admin credentials, driven by the daemon's webhook fanout.

## Test

### Plugin unit tests

```sh
cd controller-plugin
node --test test/
```

### Reconciler unit + integration tests

```sh
cd cmd/tf-unifi-sync
go vet ./...
go test ./...
```

### End-to-end smoke

```sh
# Run a fake controller (returns one client) and a fake daemon
# (always allows). Confirm the reconciler emits a manifest.
TF_DAEMON_URL=http://127.0.0.1:8787 \
UNIFI_URL=https://unifi.lan UNIFI_USERNAME=u UNIFI_PASSWORD=p \
go run . --interval 5s --out-dir /tmp/tf-unifi-test
ls /tmp/tf-unifi-test/clients/
```

## Troubleshooting

- `controller restart loops with "plugin failed to load"` — the plugin
  loader on Network Application 8.x is strict about `manifest.json`
  shape. Check `journalctl -u unifi` for the parse error and confirm
  `manifest.json` matches the schema in this directory.
- `tf-unifi-sync exits with "login failed"` — the controller's login
  endpoint changes between Network Application (`/api/login`) and
  UniFi OS (`/api/auth/login`). The reconciler tries both; if both
  fail, your credentials or TLS chain is the issue. Pass `--insecure`
  to skip TLS verification only for local self-signed setups.
- `manifests not appearing in --out-dir` — the reconciler writes
  atomically via `<file>.tmp` then `os.Rename`. If the destination is
  on a different filesystem from the temp file, the rename will fail;
  set `--out-dir` to a path on the same filesystem as the parent dir.
- `voucher-hotspot.json fields don't match my portal` — that file is
  a *template* showing the field names the plugin substitutes. The
  actual portal config lives in the controller's hotspot settings;
  point its post-auth webhook at the plugin instead of editing JSON.

## Hard rules carried over from the spec

- No custom cryptography in either component; both speak HTTP to a
  daemon that itself composes only reviewed primitives.
- Fail-closed by default. The plugin's `fail_closed: true` is the
  intended setting for any deployment that gates joins/admissions.
- Nothing here is production-ready. Treat both binaries as
  experimental drafts until reviewed.
