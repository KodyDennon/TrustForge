# 01 — Getting started

Goal: install TrustForge from source, mint your first actor
identity, boot a daemon, sign a packet, and verify it. About 20
minutes.

By the end you will have:

- A daemon running on `127.0.0.1:8787`.
- A vault under `.tf/vault.tfvault`.
- A signed `.tfpkt` packet you can verify offline.
- A proof event in your local ledger.

## Prerequisites

- Bun ≥ 1.1.
- Rust ≥ 1.78 with `stable` toolchain.
- Git.
- OpenSSL CLI (for one-off random tokens).

## Step 1 — Clone and build

```bash
git clone https://github.com/trustforge-dev/trustforge.git
cd trustforge

bun install
cargo build --workspace
```

Expected: both succeed. Errors here are environment problems, not
TrustForge problems; see
[`../ops/installation.md`](../ops/installation.md) for the
full prerequisites list.

## Step 2 — Mint a daemon identity

```bash
TF_VAULT_PASS=dev-pw \
    bun run tools/tf-cli/src/cli.ts actor create \
    --type service \
    --name tf-daemon \
    --domain example.com
```

Expected output (formatting may vary):

```
actor minted:
  uri: tf:actor:service:example.com/tf-daemon
  pubkey (ed25519): <base64>
  pubkey (ml-dsa-44): <base64>
  vault: .tf/vault.tfvault
  proof event: pe.actor.minted (chain index 1)
```

What just happened:

- A new ed25519 keypair was generated (with a paired ml-dsa-44
  keypair for hybrid post-quantum signatures).
- Both private keys were sealed in `.tf/vault.tfvault` using
  Argon2id-stretched ChaCha20-Poly1305 (vault passphrase:
  `dev-pw`).
- A `pe.actor.minted` proof event was appended to the local
  ledger.

Everything from now on signs as
`tf:actor:service:example.com/tf-daemon`.

## Step 3 — Write a minimal `.tf/daemon.yaml`

```yaml
# .tf/daemon.yaml
listen:
  admin: "127.0.0.1:8787"
  session: "127.0.0.1:8788"
  metrics: "127.0.0.1:9090"
profile: "tf-home-compatible"
vault:
  path: ".tf/vault.tfvault"
ledger:
  backend: "sqlite"
  path: ".tf/ledger.db"
logging:
  level: "info"
  format: "text"
```

For every flag and the full schema, see
[`../ops/configuration.md`](../ops/configuration.md).

## Step 4 — Boot the daemon

In a new terminal:

```bash
TF_VAULT_PASS=dev-pw \
TF_ADMIN_TOKEN=$(openssl rand -hex 16) \
    bun run tools/tf-daemon/src/cli.ts run --config .tf/daemon.yaml
```

Save the admin token in your shell environment so other commands
can use it:

```bash
export TF_ADMIN_TOKEN=…  # from the daemon's startup log
```

Expected output:

```
[info] vault unlocked
[info] profile asserted: tf-home-compatible (all MUSTs satisfied)
[info] admin endpoint listening on 127.0.0.1:8787
[info] session listener listening on 127.0.0.1:8788
[info] metrics listening on 127.0.0.1:9090
[info] daemon ready
```

## Step 5 — Confirm health

In your original terminal:

```bash
curl -s http://127.0.0.1:8787/v1/health | jq .
```

Expected:

```json
{ "status": "ok", "version": "0.1.0" }
```

Then the readiness endpoint, which requires the admin token:

```bash
curl -s http://127.0.0.1:8787/v1/health/ready \
    -H "Authorization: Bearer $TF_ADMIN_TOKEN" | jq .
```

Expected: `"ready": true`, plus the asserted profile and the list
of satisfied MUSTs.

## Step 6 — Sign your first packet

We will create a "hello" packet from our daemon to itself (just
to demonstrate; in real deployments the recipient is a different
actor).

```bash
echo '{"hello":"world"}' > /tmp/payload.json

TF_VAULT_PASS=dev-pw \
    bun run tools/tf-cli/src/cli.ts packet sign \
    --from tf:instance:service:example.com/tf-daemon/local/dev \
    --to   tf:actor:service:example.com/tf-daemon \
    --payload /tmp/payload.json \
    --out /tmp/hello.tfpkt
```

Expected:

```
packet signed:
  out: /tmp/hello.tfpkt
  size: <N> bytes
  nonce: <base64>
  signature (ed25519): <base64>
```

The `.tfpkt` file is the binary container format: magic `"TFPK"`,
u32 BE length, CBOR-encoded `Packet`. See
[`../topologies/offline-and-air-gapped.md`](../topologies/offline-and-air-gapped.md)
for the full description.

## Step 7 — Verify the packet

```bash
bun run tools/tf-cli/src/cli.ts packet verify --in /tmp/hello.tfpkt
```

Expected:

```
packet valid:
  from:    tf:instance:service:example.com/tf-daemon/local/dev
  to:      tf:actor:service:example.com/tf-daemon
  ts:      2026-04-26T10:00:00Z
  payload: 18 bytes
  signature: ok (ed25519)
  hybrid:    ok (ml-dsa-44)
  nonce:     fresh (no replay)
```

All six checks (signature, hybrid signature, fresh nonce,
in-window timestamp, recipient match, payload integrity) must
pass for the packet to be accepted. If any fails, verify exits
non-zero and names the failing check.

## Step 8 — Inspect the proof events

```bash
curl -s http://127.0.0.1:8787/v1/events?limit=5 \
    -H "Authorization: Bearer $TF_ADMIN_TOKEN" | jq .
```

You should see:

- `pe.actor.minted` (from step 2).
- `pe.daemon.started` (from step 4).
- `pe.packet.signed` (from step 6).
- `pe.packet.received` (from step 7, if you ran verify against
  the daemon).

Each event is hash-chained: every event's `prev_chain_hash`
matches the `chain_hash` of the previous event.

## Step 9 — Run the conformance suite

To convince yourself the install is healthy end-to-end:

```bash
bun run tools/tf-conformance/src/cli.ts run
```

Expected: a green run across schema, signature, guard,
trust-overlay, bridge, interop, fuzz, profile, security
regression, AI-implementation, and compatibility-label
categories.

## What you have learned

- TrustForge identities are minted, not registered. The vault is
  authoritative for "I am this actor".
- Every meaningful operation emits a proof event. The chain is
  the audit trail.
- Live mode and packet mode are equally first-class. We did not
  open a session in this tutorial; we signed a packet.

## What to read next

- [02 Protect an app](02-protect-an-app.md) — wire an Express
  app to a daemon.
- [03 Rust server](03-rust-server.md) — wire an Axum server to a
  daemon.
- [04 Policy authoring](04-policy-authoring.md) — write the
  policies the daemon evaluates.

## Cleanup

```bash
# Stop the daemon (Ctrl-C in its terminal).
# Remove generated files if you want a clean slate:
rm -rf .tf/vault.tfvault .tf/ledger.db /tmp/hello.tfpkt /tmp/payload.json
```

This will erase the daemon identity and the local ledger; only
do this on a development machine.
