# Installation

How to install TrustForge on each supported target. The reference
implementation is dual-language: TypeScript (Bun) and Rust. Most
operators install both because the conformance suite uses both;
production deployments typically run one or the other and pin the
other for testing.

This page documents the source-first install path. Pre-built binaries,
deb/rpm packages, and signed OS installers are v0.2+ release work.

## Supported targets

| Target | Daemon | CLI | Embedded crates |
|---|---|---|---|
| Linux x86_64 / aarch64 | working reference (Bun) | working reference | n/a |
| macOS x86_64 / aarch64 | working reference (Bun) | working reference | n/a |
| Windows x86_64 | experimental; WSL2 recommended | working reference | n/a |
| Linux container | planned image path | yes | n/a |
| Cortex-M / RISC-V (Rust no_std) | n/a | n/a | yes |

## Prerequisites

For all desktop targets:

- **Bun** ≥ 1.1 (https://bun.sh) — runs the TS daemon, CLI,
  conformance runner.
- **Rust** ≥ 1.78 (via `rustup`) with the `stable` toolchain — builds
  every crate in `crates/`.
- **Git** for cloning; **OpenSSL CLI** for one-off random tokens.
- **A POSIX shell** for the example commands; PowerShell works on
  Windows but the examples here use `bash`.

For embedded targets, additionally:

- The matching Rust target installed via
  `rustup target add thumbv7em-none-eabihf` (and friends, see each
  embedded crate's README).
- `probe-rs` or `cargo-flash` to flash the device.

## Linux native

```bash
git clone https://github.com/trustforge-dev/trustforge.git
cd trustforge

# Install JS deps with Bun.
bun install

# Build every Rust crate (stops you finding type errors at runtime).
cargo build --workspace

# Sanity check.
bun test
cargo test --workspace
```

Recommended layout for a real install:

```
/opt/trustforge/
  bin/                   # symlinks or locally built binaries
  etc/
    daemon.yaml
    policy.yaml
    profile.yaml
  var/
    vault.tfvault
    log/
```

Run the daemon under a dedicated `trustforge` system user, with
the vault and ledger files owned by that user (`0600` for the
vault, `0640` for the ledger). systemd unit example:

```ini
[Unit]
Description=TrustForge daemon
After=network-online.target

[Service]
User=trustforge
EnvironmentFile=/opt/trustforge/etc/env
ExecStart=/opt/trustforge/bin/tf-daemon run --config /opt/trustforge/etc/daemon.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The `EnvironmentFile` should hold `TF_VAULT_PASS` and
`TF_ADMIN_TOKEN` (or use a secret store integration; see
[`configuration.md`](configuration.md)).

## macOS native

Same as Linux native. Pay attention to:

- `launchd` instead of `systemd` for the supervisor. A draft
  `LaunchDaemon` example lives in `tools/native/macos/`.
- macOS 14+ flags TCP listeners as needing approval; bind the
  admin endpoint to loopback or a UDS to avoid the firewall
  prompt.

## Windows native

WSL2 with Ubuntu is the path most operators take; the Linux native
instructions apply.

For native Win32:

- Bun has Windows support since 1.1; works out of the box.
- Rust on Windows is best with the MSVC toolchain (`rustup default
  stable-x86_64-pc-windows-msvc`).
- Long file paths can bite cargo; enable long paths in Group Policy
  or use a short cargo target dir.

The daemon binds to loopback by default; the Windows firewall does
not prompt unless you change that.

## Container

The container path is not a published release artifact yet. Minimum
source-build shape:

```dockerfile
FROM oven/bun:1.1 AS bunbuild
WORKDIR /app
COPY . .
RUN bun install --frozen-lockfile

FROM rust:1.78 AS rustbuild
WORKDIR /app
COPY . .
RUN cargo build --release --bin tf-daemon

FROM gcr.io/distroless/cc-debian12
COPY --from=bunbuild /app /app
COPY --from=rustbuild /app/target/release/tf-daemon /usr/local/bin/tf-daemon
USER 65532
ENTRYPOINT ["/usr/local/bin/tf-daemon", "run"]
```

Mount the vault, ledger, and config as volumes; never bake the
vault into the image.

A Helm chart and a Kustomize overlay are on the v0.2 roadmap. Today,
write a `Deployment` plus `Secret` (vault passphrase) plus
`PersistentVolumeClaim` (vault) by hand.

## Embedded

Each embedded crate under `crates/embedded/` has its own README.
Common ground:

- They all consume `crates/tf-core-no-std` rather than `tf-types`.
- They flash via `cargo flash` or `probe-rs`.
- They write their long-term key into a designated flash region
  on first boot.

A typical flow for a LoRa node:

```bash
cd crates/embedded/tf-stm32wl-lora
cargo build --release --target thumbv7em-none-eabihf
cargo flash --chip STM32WLE5JC --release
# First boot mints a key; capture the printed actor URI for
# federation later.
```

## Verifying the install

```bash
# 1. Generate a daemon vault.
TF_VAULT_PASS=dev-pw \
    bun run tools/tf-cli/src/cli.ts actor create \
    --type service --name tf-daemon --domain example.com

# 2. Boot the daemon.
TF_VAULT_PASS=dev-pw TF_ADMIN_TOKEN=$(openssl rand -hex 16) \
    bun run tools/tf-daemon/src/cli.ts run --config .tf/daemon.yaml &

# 3. Validate the config in CI or before restarts.
bun run tools/tf-daemon/src/cli.ts run --config .tf/daemon.yaml --dry-run

# 4. Make a local decision over TCP with bearer auth.
curl -s http://127.0.0.1:8642/v1/decide \
    -H "Authorization: Bearer $TF_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"actor":"tf:actor:agent:example.com/demo","action":"fs.read","target":null,"context":{},"trace_id":"install-check"}' | jq .

# 5. Run the conformance suite.
bun run tools/tf-conformance/src/cli.ts run
```

A successful dry run, a local decision response, and a green
`tf-conformance run` indicate the source install is healthy.

## Uninstall

```bash
# Stop the daemon.
systemctl stop trustforge   # or pkill tf-daemon

# Remove files.
rm -rf /opt/trustforge

# (Optional) revoke the daemon's actor identity from federation.
tf actor revoke --actor tf:actor:service:example.com/tf-daemon
```

If you skip the revocation step, federated peers will continue
trusting the daemon's keys until they expire or are manually
removed. For long-lived deployments, always revoke before tearing
down.

## Troubleshooting

- **`Argon2 parameters refused`** — your vault was created with
  parameters incompatible with the running daemon. Recreate the
  vault, or pin to the matching daemon version. See
  [`upgrade.md`](upgrade.md).
- **`profile MUST not satisfied`** — the asserted profile in
  `profile.yaml` requires features your config does not provide.
  Read the error message carefully; it names the missing MUST.
- **`Address already in use`** — pick a different port in
  `daemon.yaml` or stop the conflicting process. The default
  ports are 8787 (admin), 8788 (session), 8443 (binary path),
  9090 (metrics).
- **Embedded `flash failed`** — usually the device is not in
  bootloader mode or `probe-rs` lacks permission. Check the
  per-crate README.
