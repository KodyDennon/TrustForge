# Constrained Profile

## Status

Draft.

## Purpose

The `tf-constrained-compatible` profile targets deployments where TrustForge runs over low-bandwidth, intermittently-connected, or fully air-gapped transports: LoRa radios, BLE/Bluetooth Mesh, serial cables, sneakernet USB drops, satellite store-and-forward, and embedded edge nodes. The defining constraint is that **a live WebSocket session cannot be assumed**. Every protocol exchange must survive being framed into a self-contained packet, fragmented, queued, hand-carried, and reassembled hours or days later.

## MUST features

| Feature id | Spec |
|---|---|
| `packet-mode` | TF-0011 |
| `fragment-reassembly` | TF-0011 |
| `offline-revocation-list` | TF-0011 |
| `emergency-authority` | TF-0004 |

## MUST NOT features

| Feature id | Reason |
|---|---|
| `transport.websocket-only` | A WebSocket-only daemon cannot serve clients reachable only by LoRa or sneakernet. |
| `transparency-anchor.always-online` | An anchor that requires synchronous CT submission breaks when the link is offline. |

## SHOULD features

| Feature id | Spec |
|---|---|
| `cbor-encoding` | TF-0011 |
| `deflate-compression` | TF-0011 |

## Enforcement floor

`min_enforcement_level: E3` — escalations must surface; the operator may not be reachable but the local guard still refuses unauthorized actions and queues a deny event for later replay.

## Proof level floor

`min_proof_level: L1` — every action emits a signed event. Transparency anchoring is explicitly NOT required because the link cannot be assumed to be online; anchors that work asynchronously (RFC 3161 batches, CT log catch-up on reconnect) are permitted but not mandatory.

## Packet-mode requirements

Constrained deployments rely on `tf-packet` framing exclusively for cross-actor exchange:

- **Self-contained packets.** Every packet carries its own envelope, signature, and proof entries. No assumption of a session-level handshake.
- **Fragmentation.** A single logical packet MAY be split across MTU-sized fragments and reassembled by the receiver after deduplication and out-of-order arrival.
- **Replay protection.** Receivers maintain a sliding-window nonce cache so a captured packet replayed days later is rejected.
- **Offline revocation.** Revocation lists ship as signed bundles that can be diff-merged on reconnection; an isolated node can still refuse a revoked actor with last-known-good data.
- **Emergency authority.** A pre-signed offline approval MAY authorize a high-risk action when the normal quorum collector cannot be reached, subject to the action's `risk_class` and the contract's `emergency_actors` list.

## What this profile does NOT promise

- It does not promise live RPC. Clients that need synchronous replies should use `tf-home-compatible` or `tf-enterprise-compatible`.
- It does not by itself satisfy `tf-compliance-evidence-compatible` — compliance requires online RFC 3161 anchoring on a strict cadence.
- It does not require federation, although federated trust bundles MAY ship as part of the offline revocation/trust packet stream.

## Related specs

- [TF-0001 — Core Architecture](../specs/TF-0001-core-architecture.md)
- [TF-0004 — Capabilities and Policy](../specs/TF-0004-capabilities-policy.md)
- [TF-0011 — Packet Mode and Constrained Networks](../specs/TF-0011-packet-mode-constrained.md)
- [TF-0010 — Conformance and Governance](../specs/TF-0010-conformance-governance.md)
