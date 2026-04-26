# 08 — Evidence assembly and verification

Goal: assemble a sealed, anchored evidence bundle (a
`.tfbundle`) covering proof events from a time window, then
verify it on a separate machine. About 30 minutes.

By the end you will have:

- A sealed `.tfbundle` you can hand to an auditor.
- A verified bundle reproducing the same events on the auditor's
  side.
- An understanding of how RFC 3161 / RFC 6962 anchoring lifts the
  proof level from L3 to L4 / L5.

This tutorial assumes you have completed
[01 Getting started](01-getting-started.md). It is most
illustrative if you have run [05 Federation](05-federation.md)
or [07 Bridges](07-bridges.md) first so your ledger has more
than just startup events; otherwise, you can use the tutorial 01
ledger.

## Pre-requisite: the compliance evidence profile

Evidence assembly works under any profile but is the **purpose**
of the `tf-compliance-evidence-compatible` profile (TF-0012).
That profile asserts:

- Hash-chained ledger (every profile).
- ed25519 signature on every event (every profile).
- AEAD-sealed bundle to recipient X25519 keys (L4 floor).
- RFC 3161 anchored Merkle root and/or RFC 6962 inclusion proof
  (L5 floor).
- Redaction policy applied before sealing.
- Replayable narrative reconstruction.

For this tutorial, switch to the compliance profile in
`.tf/daemon.yaml`:

```yaml
profile: "tf-compliance-evidence-compatible"
anchors:
  rfc3161:
    enabled: true
    tsa_url: "http://127.0.0.1:4321/tsa"   # mock TSA for the tutorial
```

A mock RFC 3161 timestamp authority is provided under
`tools/native/mock-tsa/`. Start it:

```bash
bun run tools/native/mock-tsa/cli.ts --port 4321
```

Restart the daemon. It will attempt to anchor each batch of
events against the mock TSA; expect `tf_anchor_inclusions_total{anchor="rfc3161"}`
to start incrementing.

## Step 1 — Generate some events

If your ledger is sparse, generate a handful of decisions:

```bash
for i in $(seq 1 5); do
  curl -s http://127.0.0.1:8787/v1/decide \
      -H "Authorization: Bearer $TF_ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"actor\":  \"tf:actor:human:example.com/alice\",
        \"action\": \"doc.read\",
        \"target\": \"doc:welcome-${i}\"
      }" >/dev/null
done
```

(Re-create alice from tutorial 04 if she is not in the ledger.)

## Step 2 — Mint a recipient X25519 key

The auditor needs a key the bundle can be sealed to. For the
tutorial, mint one locally; in production, the auditor sends
their public key to you:

```bash
TF_VAULT_PASS=dev-pw \
    bun run tools/tf-cli/src/cli.ts actor create \
    --type human --name auditor --domain audit.example \
    --x25519
```

Capture the auditor's X25519 public key from the output.

## Step 3 — Assemble the bundle

```bash
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ONE_HOUR_AGO=$(date -u -d '1 hour ago' +"%Y-%m-%dT%H:%M:%SZ" \
    || date -u -v-1H +"%Y-%m-%dT%H:%M:%SZ")  # GNU vs BSD date

bun run tools/tf-cli/src/cli.ts evidence assemble \
    --from "$ONE_HOUR_AGO" \
    --to   "$NOW" \
    --recipient $AUDITOR_X25519_PK \
    --redact-pii \
    --out /tmp/evidence-$(date -u +%F).tfbundle
```

Output:

```
evidence assembled:
  events: 17
  merkle root: <base64>
  rfc3161 timestamp: ok
  redactions applied: 3 (per redaction policy)
  sealed to: 1 recipient
  out: /tmp/evidence-2026-04-26.tfbundle
  size: 8421 bytes
```

The bundle:

- Captured every event in the time window.
- Computed a Merkle tree over the events.
- Anchored the root with RFC 3161 (timestamp token attached).
- Redacted any field tagged `pii` per the redaction policy.
- AEAD-sealed the bundle to the auditor's X25519 public key.
- Wrote a `.tfbundle` (magic + u32 BE length + CBOR-encoded
  `ProofBundleEncrypted` + signature trailer).

## Step 4 — Inspect (optional, before sealing)

If you want to inspect a bundle before sealing, run with
`--inspect-cleartext`:

```bash
bun run tools/tf-cli/src/cli.ts evidence assemble \
    --from "$ONE_HOUR_AGO" \
    --to "$NOW" \
    --inspect-cleartext \
    --out /tmp/evidence-cleartext.tfbundle
```

Then:

```bash
bun run tools/tf-cli/src/cli.ts evidence inspect \
    --in /tmp/evidence-cleartext.tfbundle | jq .
```

This is for development only; production bundles should always
be sealed.

## Step 5 — Hand the bundle to the auditor

In real life, this is a courier, an SFTP transfer, or a
write-once optical disc (see
[`../topologies/offline-and-air-gapped.md`](../topologies/offline-and-air-gapped.md)).
For the tutorial, copy the file to a different directory to
simulate the boundary:

```bash
mkdir -p ~/auditor-sandbox
cp /tmp/evidence-$(date -u +%F).tfbundle ~/auditor-sandbox/
cd ~/auditor-sandbox
```

## Step 6 — Verify the bundle

The auditor verifies:

```bash
TF_VAULT_PASS=dev-pw \
    bun run /path/to/trustforge/tools/tf-cli/src/cli.ts \
    evidence verify --in evidence-2026-04-26.tfbundle
```

Output:

```
evidence verified:
  events: 17
  signature on each event: ok (ed25519)
  hybrid signature on each event: ok (ml-dsa-44)
  chain integrity: ok
  merkle root: ok
  rfc3161 inclusion: ok (TSA: http://127.0.0.1:4321/tsa)
  redactions consistent: ok
  level: L4 (sealed) | L5 (with anchor)
```

Each line is a separate cryptographic check. All must pass for
the bundle to be accepted.

## Step 7 — Replay the bundle

A `replay` produces a human-readable narrative timeline:

```bash
bun run /path/to/trustforge/tools/tf-cli/src/cli.ts \
    evidence replay --in evidence-2026-04-26.tfbundle
```

Output is a sequence like:

```
2026-04-26T10:00:00Z  pe.daemon.started      tf:actor:service:example.com/tf-daemon
2026-04-26T10:01:23Z  pe.actor.minted        tf:actor:human:example.com/alice
2026-04-26T10:01:42Z  pe.action.allowed      alice → doc.read → doc:welcome-1
2026-04-26T10:01:43Z  pe.action.allowed      alice → doc.read → doc:welcome-2
…
```

This is the narrative an auditor reads to reconstruct what
happened. Redacted fields appear as `<redacted: pii>` so the
narrative is intelligible without exposing the redacted data.

## Step 8 — Demonstrate non-repudiation

Modify the bundle (simulate tampering):

```bash
# Don't actually do this in a real environment; for demo only.
xxd evidence-2026-04-26.tfbundle | sed '5s/00/01/' | xxd -r > tampered.tfbundle

bun run /path/to/trustforge/tools/tf-cli/src/cli.ts \
    evidence verify --in tampered.tfbundle
# evidence verification FAILED:
#   chain integrity: FAIL (chain hash mismatch at event 4)
# exit code: 1
```

Tampering is detected at the chain hash stage. The TSA
inclusion proof would also fail because the modified bundle has
a different Merkle root than the one timestamped.

## Step 9 — Bundles for federation

Cross-domain evidence works the same way. The recipient is the
peer domain's recipient X25519 key (which you exchanged at
federation time). The peer verifies the bundle the same way the
auditor did in step 6.

This is the substrate for cross-domain audit: each domain emits
its own ledger, and bundles are the cross-domain transfer
medium. See
[`../architecture/data-flows.md`](../architecture/data-flows.md)
flow G.

## Step 10 — Operational considerations

- **Bundle size**: scale linearly with the number of events.
  For high-throughput deployments, assemble per hour or per
  day.
- **Anchor latency**: RFC 3161 is sub-second under normal load;
  RFC 6962 inclusion takes a CT log batch interval (often
  minutes). Accept that L5 events are not instantly available.
- **Redaction policy**: configured in `.tf/redaction.yaml`
  alongside the policy bundle. Common redactions: PII fields
  in payload bodies, IP addresses, email addresses.
- **Replay determinism**: same input produces same output. The
  conformance suite tests this; run `tf-conformance run --suite
  evidence` to confirm.

## What you have learned

- Evidence bundles are the cross-domain audit primitive.
- L4 = sealed; L5 = sealed + anchored. The proof level is a
  property of how the bundle was assembled, not a separate
  format.
- Tampering is detected by chain hash + Merkle root + anchor
  inclusion, in that order. Multiple lines of defence.
- Replay produces a narrative auditors can read; redactions are
  visible without exposing redacted data.

## What to read next

- [`../profiles/compliance-evidence-profile.md`](../profiles/compliance-evidence-profile.md)
  — every MUST and SHOULD for L4/L5.
- [`../specs/TF-0012-compliance-evidence-profile.md`](../specs/TF-0012-compliance-evidence-profile.md)
  — normative spec.
- [`../specs/TF-0005-proof-events-ledgers.md`](../specs/TF-0005-proof-events-ledgers.md)
  — proof event format and anchoring contract.

## End of the tutorial track

You have walked through every major TrustForge surface:
identity, sessions, packets, policy, federation, embedded,
bridges, and evidence. From here, your reading is the spec
series in [`../specs/`](../specs/) and the architecture deep
dives in [`../architecture/`](../architecture/).

If you found a step that did not match the running code, file
an issue. The tutorials are draft and live with the
implementation.
