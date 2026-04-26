# TrustForge Pi-hole integration

This directory turns a Pi-hole DNS sinkhole into a TrustForge policy
enforcement point. Three components cooperate:

1. **`gravity/pre-gravity-trustforge.sh`** — pre-gravity hook that
   pulls the current allow/deny table from `tf-daemon` and merges it
   into Pi-hole's gravity DB before each gravity refresh.
2. **`cmd/tf-pihole-policy/`** — Go HTTP sidecar that fronts the
   Pi-hole admin pane. lighttpd proxies admin requests to it and the
   sidecar gates them on a `/v1/decide` call.
3. **`dnsmasq.d/05-trustforge.conf`** — dnsmasq snippet for the
   blocklist integration (addn-hosts + NXDOMAIN policy).

The supporting `lighttpd/external.conf` wires the Pi-hole admin pane
through the sidecar.

## Status

**Phase 0 / pre-release.** Not production-ready. The reference
`tf-daemon` is not yet shipped; the sidecar and gravity hook are
useful primarily for conformance testing against a mock daemon.

## Pi-hole compatibility

| Pi-hole              | Status                                                 |
| -------------------- | ------------------------------------------------------ |
| **Pi-hole v5.x**     | Supported. Gravity DB at `/etc/pihole/gravity.db`.     |
| **Pi-hole v6.x**     | Supported (Pi-hole v6 changed the dnsmasq runtime path; the snippet still drops at `/etc/dnsmasq.d/`). |
| **Pi-hole v4.x**     | Not supported — flat-file gravity is gone from v5+ and the sidecar assumes v5+ admin endpoint URLs. |

Pi-hole v6 refactored the admin webserver away from lighttpd. If you
are on v6 with the new built-in webserver, the lighttpd snippet here
will not load; instead point the v6 webserver's reverse-proxy block
at `tf-pihole-policy` directly. See "Troubleshooting" below.

## Layout

```
gravity/
  pre-gravity-trustforge.sh    bash hook (run from gravity.sh)

lighttpd/
  external.conf                 lighttpd reverse-proxy snippet

cmd/tf-pihole-policy/
  go.mod
  main.go                       sidecar HTTP entry point
  main_test.go                  unit + integration tests

dnsmasq.d/
  05-trustforge.conf            dnsmasq snippet (addn-hosts, NXDOMAIN)
```

## Install

```sh
# 1. Install the sidecar.
cd cmd/tf-pihole-policy
go build -o tf-pihole-policy .
sudo install -m 0755 tf-pihole-policy /usr/local/bin/tf-pihole-policy

sudo tee /etc/systemd/system/tf-pihole-policy.service >/dev/null <<'EOF'
[Unit]
Description=TrustForge Pi-hole sidecar
After=network-online.target

[Service]
Environment=TF_DAEMON_URL=http://127.0.0.1:8787
Environment=PIHOLE_BACKEND=http://127.0.0.1:80
Environment=TF_PIHOLE_ACTOR=tf:actor:device:pihole/$(hostname -s)
ExecStart=/usr/local/bin/tf-pihole-policy --addr 127.0.0.1:8788
Restart=on-failure
User=trustforge

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now tf-pihole-policy

# 2. Wire lighttpd through the sidecar.
sudo cp lighttpd/external.conf /etc/lighttpd/conf-available/15-trustforge.conf
sudo lighttpd-enable-mod trustforge
sudo systemctl reload lighttpd

# 3. Install the gravity hook.
sudo install -m 0755 gravity/pre-gravity-trustforge.sh \
    /etc/pihole/scripts/pre-gravity-trustforge.sh

# Pi-hole v5+ does not expose a formal pre-gravity hook; the
# documented pattern is to schedule the hook a few minutes before
# the gravity timer fires.
sudo tee /etc/cron.d/trustforge-pihole >/dev/null <<'EOF'
# Run TrustForge sync 5 minutes before Pi-hole's gravity refresh
# (which Pi-hole schedules at 03:30 by default).
25 3 * * 7 root /etc/pihole/scripts/pre-gravity-trustforge.sh
EOF

# 4. Install the dnsmasq snippet.
sudo cp dnsmasq.d/05-trustforge.conf /etc/dnsmasq.d/05-trustforge.conf
sudo touch /run/trustforge/pihole-hosts /run/trustforge/pihole-nxdomain.conf

# 5. Restart in the right order. Sidecar first, then lighttpd, then DNS.
sudo systemctl restart tf-pihole-policy
sudo systemctl restart lighttpd
sudo pihole restartdns
```

### Restart sequence (important)

The order **matters**. If you restart Pi-hole's DNS before the
sidecar is up, the dnsmasq snippet's `addn-hosts` paths point at
files that haven't been written yet and dnsmasq will refuse to
start. Either:

- Restart in the order shown above, or
- Pre-create empty files at `/run/trustforge/pihole-hosts` and
  `/run/trustforge/pihole-nxdomain.conf` so dnsmasq is happy on
  boot before the sidecar paints them.

## Test

```sh
# Sidecar unit tests.
cd cmd/tf-pihole-policy
go vet ./...
go test ./...

# Gravity hook smoke (against a fake daemon).
TF_DAEMON_URL=http://127.0.0.1:8787 \
TF_PIHOLE_ACTOR=tf:actor:device:pihole/test \
PIHOLE_BIN=/bin/true \
gravity/pre-gravity-trustforge.sh
echo "exit=$?"
```

Shellcheck the bash script if you have shellcheck installed:

```sh
shellcheck gravity/pre-gravity-trustforge.sh
```

## Troubleshooting

- `lighttpd refuses to load 15-trustforge.conf` — Pi-hole v6 ships
  its own webserver, not lighttpd. Use the v6 reverse-proxy directive
  pointing at the same sidecar address (`127.0.0.1:8788`) instead.
- `dnsmasq: failed to load /run/trustforge/pihole-hosts: No such file`
  — pre-create empty files (see "Restart sequence" above) or set
  `tf-pihole-policy` to start before dnsmasq via systemd ordering.
- `pre-gravity-trustforge.sh exits 0 but nothing changed` — the hook
  fails closed on daemon timeout. Check `journalctl -t trustforge-pre-gravity`.
- `pihole -w` / `pihole -b` exit 1 — the gravity hook ignores
  individual failures (logged as warnings) so a single bad domain
  doesn't abort the whole batch. Check the warnings.

## Hard rules carried over from the spec

- No custom cryptography in any of these components; the sidecar
  speaks plain HTTP to a daemon that itself composes only reviewed
  primitives.
- Fail-closed by default. The gravity hook leaves the existing block
  list intact on daemon outage; the sidecar returns HTTP 503 (not
  HTTP 200) when the daemon is unreachable.
- Nothing here is production-ready. Treat both binaries and the
  shell hook as experimental drafts until reviewed.
